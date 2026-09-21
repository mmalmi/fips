//! Incomplete HTTP upgrades remain transport-owned until timeout or shutdown.
use super::*;
use std::future::{Future, poll_fn};
use std::task::Poll;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const REQUEST_PREFIX: &[u8] = b"GET /fips HTTP/1.1\r\nHost: localhost\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n";

async fn listener(connect_timeout_ms: u64) -> WebSocketTransport {
    let identity = Identity::generate();
    let (packet_tx, _packet_rx) = packet_channel(8);
    let mut transport = WebSocketTransport::new(
        TransportId::new(1),
        None,
        WebSocketConfig {
            bind_addr: Some("127.0.0.1:0".into()),
            max_connections: Some(1),
            max_inbound_connections: Some(1),
            connect_timeout_ms: Some(connect_timeout_ms),
            ping_interval_secs: Some(0),
            idle_timeout_secs: Some(0),
            ..Default::default()
        },
        packet_tx,
        &identity,
    );
    transport.start_async().await.unwrap();
    transport
}

fn slots(transport: &WebSocketTransport) -> (usize, usize) {
    (
        transport.runtime.total_slots.available_permits(),
        transport.runtime.inbound_slots.available_permits(),
    )
}

async fn wait_slots(
    transport: &WebSocketTransport,
    expected: (usize, usize),
    budget: Duration,
) -> bool {
    tokio::time::timeout(budget, async {
        while slots(transport) != expected {
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    })
    .await
    .is_ok()
}

async fn stalled_upgrade(transport: &WebSocketTransport) -> TcpStream {
    let mut client = TcpStream::connect(transport.local_addr().unwrap())
        .await
        .unwrap();
    client.write_all(REQUEST_PREFIX).await.unwrap();
    assert!(
        wait_slots(transport, (0, 0), Duration::from_secs(1)).await,
        "the actual accepted HTTP upgrade must own both permits before testing its lifetime"
    );
    assert_eq!(transport.stats().connections_opened, 0);
    assert!(transport.runtime.pool.lock().await.is_empty());
    client
}

async fn tcp_closed(client: &mut TcpStream) -> bool {
    let mut byte = [0];
    matches!(
        tokio::time::timeout(Duration::from_millis(500), client.read(&mut byte)).await,
        Ok(Ok(0) | Err(_))
    )
}

async fn finish_old_upgrade(client: &mut TcpStream) -> bool {
    if client.write_all(b"\r\n").await.is_err() {
        return false;
    }
    tokio::time::timeout(Duration::from_millis(500), async {
        let mut response = Vec::new();
        let mut bytes = [0; 256];
        while response.len() < 1024 {
            match client.read(&mut bytes).await {
                Ok(0) | Err(_) => return false,
                Ok(len) => response.extend_from_slice(&bytes[..len]),
            }
            if response.windows(4).any(|window| window == b"\r\n\r\n") {
                return response.starts_with(b"HTTP/1.1 101 ");
            }
        }
        false
    })
    .await
    .unwrap_or(false)
}

async fn fresh_connection(transport: &WebSocketTransport) -> Option<WebSocketStream<TcpStream>> {
    tokio::time::timeout(Duration::from_secs(2), async {
        let socket = transport.local_addr().unwrap();
        let stream = TcpStream::connect(socket).await.ok()?;
        let (mut client, response) =
            tokio_tungstenite::client_async(format!("ws://{socket}/fips"), stream)
                .await
                .ok()?;
        if response.status().as_u16() != 101 {
            return None;
        }
        // Exercise the production connection loop, not just a TCP connect or
        // HTTP response. This hint is transport discovery, not Noise proof.
        let nonce = 317;
        client
            .send(Message::Binary(
                LocalKeyHint::Request { nonce }.encode().into(),
            ))
            .await
            .ok()?;
        loop {
            match client.next().await? {
                Ok(Message::Binary(bytes)) => {
                    return (LocalKeyHint::decode(&bytes)
                        == Some(LocalKeyHint::Response {
                            nonce,
                            pubkey: transport.runtime.local_pubkey,
                        }))
                    .then_some(client);
                }
                Ok(Message::Ping(_) | Message::Pong(_)) => {}
                _ => return None,
            }
        }
    })
    .await
    .ok()
    .flatten()
}

async fn websocket_closed(client: &mut WebSocketStream<TcpStream>) -> bool {
    tokio::time::timeout(Duration::from_millis(500), async {
        loop {
            match client.next().await {
                None | Some(Err(_) | Ok(Message::Close(_))) => return true,
                Some(Ok(Message::Ping(_) | Message::Pong(_))) => {}
                _ => return false,
            }
        }
    })
    .await
    .unwrap_or(false)
}

async fn stop(transport: &mut WebSocketTransport) {
    tokio::time::timeout(Duration::from_secs(2), transport.stop_async())
        .await
        .expect("transport stop must join owned workers within the test deadline")
        .unwrap();
}

#[tokio::test]
async fn incomplete_http_upgrade_times_out_and_restores_both_connection_permits() {
    const CONNECT_MS: u64 = 150;
    let mut server = listener(CONNECT_MS).await;
    let mut stalled = stalled_upgrade(&server).await;
    // Allow scheduling slack beyond the configured upgrade budget; ownership
    // is observed directly rather than inferred from an elapsed sleep.
    let restored = wait_slots(&server, (1, 1), Duration::from_millis(CONNECT_MS + 500)).await;
    let expired_stats = server.stats();
    let after_timeout = slots(&server);
    let old_closed = tcp_closed(&mut stalled).await;
    let mut healthy = fresh_connection(&server).await;
    let healthy_connected = healthy.is_some();
    let opened = server.stats().connections_opened;

    // Even an accepted connection stays open here: stop must own that worker
    // too and return only after its physical socket and permits are released.
    stop(&mut server).await;
    let stopped_stats = server.stats();
    let after_stop = slots(&server);
    let healthy_closed = if let Some(client) = healthy.as_mut() {
        websocket_closed(client).await
    } else {
        true
    };
    drop((stalled, healthy));
    assert!(wait_slots(&server, (1, 1), Duration::from_secs(1)).await);

    assert!(
        restored && after_timeout == (1, 1),
        "incomplete upgrade retained permits after connect timeout: {after_timeout:?}; old_closed={old_closed}, fresh_connected={healthy_connected}"
    );
    assert!(old_closed, "timed-out HTTP client must observe EOF/reset");
    assert_eq!(
        (
            expired_stats.connections_opened,
            expired_stats.connections_closed
        ),
        (0, 0),
        "an expired HTTP upgrade never becomes an opened or closed WebSocket"
    );
    assert!(
        healthy_connected,
        "a fresh WebSocket must recover after the stalled upgrade"
    );
    assert_eq!(
        opened, 1,
        "only the fresh completed upgrade enters the pool"
    );
    assert_eq!(
        after_stop,
        (1, 1),
        "stop joins the completed connection owner"
    );
    assert_eq!(stopped_stats.connections_opened, 1);
    assert_eq!(
        stopped_stats.connections_closed, stopped_stats.connections_opened,
        "stop accounts for the completed WebSocket before returning"
    );
    assert!(
        healthy_closed,
        "stop closes the fresh peer's physical socket"
    );
}

#[tokio::test]
async fn stop_joins_stalled_upgrade_before_restart_and_rejects_its_late_completion() {
    let mut server = listener(10_000).await;
    let mut stalled = stalled_upgrade(&server).await;
    // The generous upgrade budget isolates explicit stop ownership from the
    // timeout case. No client disconnect is sent before stop returns.
    stop(&mut server).await;
    let incomplete_stats = server.stats();
    let at_stop = slots(&server);
    let old_closed_at_stop = tcp_closed(&mut stalled).await;
    assert_eq!(server.state(), TransportState::Down);
    assert!(server.local_addr().is_none());

    server.start_async().await.unwrap();
    let stale_upgrade_completed = finish_old_upgrade(&mut stalled).await;
    let before_fresh_stats = server.stats();
    let stale_pool_entries = server.runtime.pool.lock().await.len();
    // Close only this test-owned old client before probing the fresh runtime,
    // retaining the observations above even on the broken implementation.
    drop(stalled);
    assert!(wait_slots(&server, (1, 1), Duration::from_secs(1)).await);
    let mut healthy = fresh_connection(&server).await;
    let healthy_connected = healthy.is_some();
    stop(&mut server).await;
    let stopped_stats = server.stats();
    let final_slots = slots(&server);
    let healthy_closed = if let Some(client) = healthy.as_mut() {
        websocket_closed(client).await
    } else {
        true
    };
    drop(healthy);
    assert!(wait_slots(&server, (1, 1), Duration::from_secs(1)).await);

    assert_eq!(
        at_stop,
        (1, 1),
        "stop returned with an unowned HTTP upgrade: old_closed={old_closed_at_stop}, late_upgrade={stale_upgrade_completed}, late_pool_entries={stale_pool_entries}"
    );
    assert!(
        old_closed_at_stop,
        "stopped upgrade must close before restart"
    );
    assert!(
        !stale_upgrade_completed,
        "old HTTP upgrade completed after restart"
    );
    assert_eq!(
        (
            incomplete_stats.connections_opened,
            incomplete_stats.connections_closed
        ),
        (0, 0),
        "aborting HTTP before upgrade must not count an established connection"
    );
    assert_eq!(
        (
            before_fresh_stats.connections_opened,
            before_fresh_stats.connections_closed
        ),
        (0, 0),
        "the late old upgrade must not affect connection accounting after restart"
    );
    assert_eq!(stale_pool_entries, 0);
    assert!(
        healthy_connected,
        "restart must admit a valid fresh WebSocket"
    );
    assert_eq!(final_slots, (1, 1));
    assert_eq!(stopped_stats.connections_opened, 1);
    assert_eq!(
        stopped_stats.connections_closed, stopped_stats.connections_opened,
        "stopping the restarted transport accounts for its fresh WebSocket"
    );
    assert!(healthy_closed);
}

#[tokio::test(flavor = "current_thread")]
async fn cancelled_stop_retains_join_ownership_until_a_later_stop_completes() {
    let mut server = listener(10_000).await;
    let mut stalled = stalled_upgrade(&server).await;
    let mut first_stop = Box::pin(server.stop_async());
    // On this current-thread runtime the aborted tasks cannot finish while we
    // hold this poll. Return immediately rather than yielding on Pending.
    let first_pending = poll_fn(|cx| Poll::Ready(first_stop.as_mut().poll(cx)))
        .await
        .is_pending();
    drop(first_stop);
    // No scheduling/yield between cancellation and the replacement stop. It
    // must retain and join the original workers, not merely clear the pool.
    let resumed = tokio::time::timeout(Duration::from_secs(2), server.stop_async()).await;
    let stopped_stats = server.stats();
    let at_return = slots(&server);
    let old_closed = tcp_closed(&mut stalled).await;
    drop(stalled);
    let cleanup_released = wait_slots(&server, (1, 1), Duration::from_secs(1)).await;

    assert!(
        first_pending,
        "first stop must suspend while owned workers remain unscheduled"
    );
    assert!(
        matches!(resumed, Ok(Ok(()))),
        "replacement stop must complete normally"
    );
    assert_eq!(
        at_return,
        (1, 1),
        "replacement stop lost the cancelled stop's pending worker ownership; client_closed={old_closed}"
    );
    assert!(
        old_closed,
        "replacement stop must close the accepted HTTP client"
    );
    assert!(cleanup_released);
    assert_eq!(
        (
            stopped_stats.connections_opened,
            stopped_stats.connections_closed
        ),
        (0, 0),
        "cancelled and resumed shutdown never established the incomplete HTTP connection"
    );
}
