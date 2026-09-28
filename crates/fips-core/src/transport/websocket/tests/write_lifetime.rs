//! Bidirectional backpressure must preserve read progress and connection lifetime.
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
    transport_with_packets(idle_secs).await.0
}

async fn transport_with_packets(
    idle_secs: u64,
) -> (WebSocketTransport, crate::transport::PacketRx) {
    let identity = Identity::generate();
    let (packet_tx, packet_rx) = packet_channel(8);
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
    (transport, packet_rx)
}

#[tokio::test(start_paused = true)]
async fn simultaneous_writes_keep_reading_through_bidirectional_backpressure() {
    for hint in [false, true] {
        let (mut left, mut left_packets) = transport_with_packets(0).await;
        let (mut right, mut right_packets) = transport_with_packets(0).await;
        // Each frame exceeds the physical buffer in both directions. Neither
        // side can complete its write unless the other keeps reading.
        let (client, server) = tokio::io::duplex(1);
        let client = WebSocketStream::from_raw_socket(client, Role::Client, None).await;
        let server = WebSocketStream::from_raw_socket(server, Role::Server, None).await;
        let addr = TransportAddr::from_string("ws://127.0.0.1:1/fips");
        let mut outgoing = Box::pin(run_framing_connection(
            left.runtime.clone(),
            addr.clone(),
            client,
            left.runtime.next_generation(),
            Direction::Outbound,
            hint,
            0,
        ));
        let mut incoming = Box::pin(run_framing_connection(
            right.runtime.clone(),
            addr.clone(),
            server,
            right.runtime.next_generation(),
            Direction::Inbound,
            false,
            0,
        ));
        poll_pending(outgoing.as_mut()).await;
        poll_pending(incoming.as_mut()).await;
        let records: Vec<_> = (1..=3)
            .map(|id| {
                build_msg1(
                    SessionIndex::new(id),
                    &[id as u8; crate::noise::HANDSHAKE_MSG1_SIZE],
                )
            })
            .collect();
        for record in &records {
            left.send_async(&addr, record).await.unwrap();
            right.send_async(&addr, record).await.unwrap();
        }
        let mut received_left = Vec::new();
        let mut received_right = Vec::new();
        let delivered = tokio::time::timeout(Duration::from_millis(100), async {
            while received_left.len() < records.len() || received_right.len() < records.len() {
                tokio::select! {
                    result = outgoing.as_mut() => panic!("outbound stream ended: {result:?}"),
                    result = incoming.as_mut() => panic!("inbound stream ended: {result:?}"),
                    packet = left_packets.recv(), if received_left.len() < records.len() => {
                        received_left.push(packet.unwrap().data.as_slice().to_vec());
                    }
                    packet = right_packets.recv(), if received_right.len() < records.len() => {
                        received_right.push(packet.unwrap().data.as_slice().to_vec());
                    }
                }
            }
            poll_pending(outgoing.as_mut()).await;
            poll_pending(incoming.as_mut()).await;
        })
        .await;
        left.close_connection_async(&addr).await;
        right.close_connection_async(&addr).await;
        outgoing.await.unwrap();
        incoming.await.unwrap();
        left.stop_async().await.unwrap();
        right.stop_async().await.unwrap();
        assert!(
            delivered.is_ok(),
            "healthy bidirectional WebSocket writes must make progress"
        );
        assert_eq!(received_left, records);
        assert_eq!(received_right, records);
        for transport in [&left, &right] {
            assert_eq!(transport.stats().frames_sent, 3);
            assert_eq!(transport.stats().frames_received, 3);
            assert_eq!(transport.stats().connections_opened, 1);
            assert_eq!(transport.stats().connections_closed, 1);
        }
    }
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
    let mut worker = Box::pin(run_framing_connection(
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
async fn blocked_data_write_keeps_receiving_but_still_expires_when_idle() {
    let mut transport = transport(1).await;
    let (addr, peer, mut worker) = stalled(&transport, false).await;
    let mut peer = WebSocketStream::from_raw_socket(peer, Role::Server, None).await;
    tokio::time::advance(Duration::from_millis(750)).await;
    tokio::time::timeout(Duration::from_millis(10), async {
        tokio::select! {
            result = worker.as_mut() => panic!("blocked writer ended before incoming activity: {result:?}"),
            result = peer.send(Message::Pong(Bytes::new())) => result.unwrap(),
        }
    })
    .await
    .expect("incoming activity must progress while the peer does not read");
    poll_pending(worker.as_mut()).await;
    tokio::time::advance(Duration::from_millis(251)).await;
    poll_pending(worker.as_mut()).await;
    tokio::time::advance(Duration::from_millis(750)).await;
    let result = tokio::time::timeout(Duration::from_millis(10), worker.as_mut())
        .await
        .expect("stalled data write must not suspend the idle timer");
    assert!(matches!(result, Err(TransportError::Timeout)));
    assert_closed(&transport, &addr, peer.get_mut()).await;
    transport.stop_async().await.unwrap();
}

#[tokio::test(start_paused = true)]
async fn control_flood_cannot_queue_unbounded_replies_behind_a_blocked_write() {
    let mut transport = transport(0).await;
    let (addr, peer, mut worker) = stalled(&transport, false).await;
    let mut peer = WebSocketStream::from_raw_socket(peer, Role::Server, None).await;
    let outcome = tokio::time::timeout(Duration::from_millis(10), async {
        tokio::join!(worker.as_mut(), async {
            for nonce in 0..100 {
                if peer
                    .send(Message::Binary(
                        LocalKeyHint::Request { nonce }.encode().into(),
                    ))
                    .await
                    .is_err()
                {
                    return;
                }
            }
        })
    })
    .await
    .expect("control flood must close the stream without an idle timeout");
    assert!(matches!(outcome.0, Err(TransportError::SendFailed(_))));
    assert_closed(&transport, &addr, peer.get_mut()).await;
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
