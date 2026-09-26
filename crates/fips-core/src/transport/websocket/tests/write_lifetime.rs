//! A peer that stops reading must not pin a writer past timeout or local close.
use super::*;
use std::{
    future::{Future, poll_fn},
    pin::Pin,
    task::Poll,
};
use tokio::io::{AsyncReadExt, DuplexStream};
use tokio_tungstenite::tungstenite::protocol::Role;

async fn poll_pending(mut future: Pin<&mut impl Future>) {
    poll_fn(|cx| {
        assert!(future.as_mut().poll(cx).is_pending());
        Poll::Ready(())
    })
    .await;
}

async fn transport(idle_secs: u64) -> WebSocketTransport {
    let identity = Identity::generate();
    let (packet_tx, _packet_rx) = packet_channel(8);
    let mut transport = WebSocketTransport::new(
        TransportId::new(1),
        None,
        WebSocketConfig {
            max_connections: Some(1),
            max_inbound_connections: Some(1),
            key_hint_timeout_ms: Some(150),
            idle_timeout_secs: Some(idle_secs),
            ping_interval_secs: Some(0),
            ..Default::default()
        },
        packet_tx,
        &identity,
    );
    transport.start_async().await.unwrap();
    transport
}

async fn stalled(
    transport: &WebSocketTransport,
    hint: bool,
) -> (
    TransportAddr,
    DuplexStream,
    Pin<Box<impl Future<Output = Result<(), TransportError>> + use<>>>,
) {
    // Real WebSocket framing over a one-byte pipe guarantees a pending write;
    // the peer remains alive without draining or closing its read half.
    let (local, peer) = tokio::io::duplex(1);
    let websocket = WebSocketStream::from_raw_socket(local, Role::Client, None).await;
    let addr = TransportAddr::from_string("ws://127.0.0.1:1/fips");
    let mut worker = Box::pin(run_connection(
        transport.runtime.clone(),
        addr.clone(),
        websocket,
        transport.runtime.next_generation(),
        Direction::Outbound,
        hint,
        0,
    ));
    poll_pending(worker.as_mut()).await;
    if !hint {
        let record = build_msg1(
            SessionIndex::new(1),
            &[0; crate::noise::HANDSHAKE_MSG1_SIZE],
        );
        transport.send_async(&addr, &record).await.unwrap();
        poll_pending(worker.as_mut()).await;
    }
    assert_eq!(
        transport.connection_state_sync(&addr),
        ConnectionState::Connected
    );
    assert_eq!(transport.stats().frames_sent, 0);
    (addr, peer, worker)
}

async fn assert_closed(
    transport: &WebSocketTransport,
    addr: &TransportAddr,
    peer: &mut DuplexStream,
) {
    assert!(transport.runtime.connections().is_empty());
    assert_eq!(transport.connection_state_sync(addr), ConnectionState::None);
    assert_eq!(transport.stats().connections_opened, 1);
    assert_eq!(transport.stats().connections_closed, 1);
    assert_eq!(
        transport.stats().frames_sent,
        0,
        "a partial write is not a submitted frame"
    );
    let mut partial = Vec::new();
    tokio::time::timeout(Duration::from_millis(10), peer.read_to_end(&mut partial))
        .await
        .expect("closed worker must drop the physical stream")
        .unwrap();
    assert_eq!(
        partial.len(),
        1,
        "the real encoder reached the blocked underlay"
    );
}

#[tokio::test(start_paused = true)]
async fn initial_hint_write_obeys_its_exchange_deadline() {
    let mut transport = transport(0).await;
    let (addr, mut peer, mut worker) = stalled(&transport, true).await;
    tokio::time::advance(Duration::from_millis(151)).await;
    let result = tokio::time::timeout(Duration::from_millis(10), worker.as_mut())
        .await
        .expect("stalled initial key-hint write must expire");
    assert!(matches!(result, Err(TransportError::Timeout)));
    assert_closed(&transport, &addr, &mut peer).await;
    transport.stop_async().await.unwrap();
}

#[tokio::test(start_paused = true)]
async fn data_write_cannot_suspend_the_idle_deadline() {
    let mut transport = transport(1).await;
    let (addr, mut peer, mut worker) = stalled(&transport, false).await;
    tokio::time::advance(Duration::from_millis(1001)).await;
    let result = tokio::time::timeout(Duration::from_millis(10), worker.as_mut())
        .await
        .expect("stalled data write must not suspend the idle timer");
    assert!(matches!(result, Err(TransportError::Timeout)));
    assert_closed(&transport, &addr, &mut peer).await;
    transport.stop_async().await.unwrap();
}

#[tokio::test(start_paused = true)]
async fn close_and_network_change_cancel_stalled_writes_with_idle_timeout_disabled() {
    for rebind in [false, true] {
        let mut transport = transport(0).await;
        let (addr, mut peer, mut worker) = stalled(&transport, false).await;
        if rebind {
            assert!(transport.restart_after_network_change().await.unwrap());
        } else {
            transport.close_connection_async(&addr).await;
        }
        tokio::time::timeout(Duration::from_millis(10), worker.as_mut())
            .await
            .expect("local close must cancel a blocked write even without an idle timer")
            .unwrap();
        assert_closed(&transport, &addr, &mut peer).await;
        transport.stop_async().await.unwrap();
    }
}
