//! Connection errors must release their address without disturbing a replacement.
use super::*;
use std::future::{Future, poll_fn};
use std::pin::Pin;
use std::task::Poll;
use tokio::io::DuplexStream;
use tokio_tungstenite::tungstenite::protocol::Role;

async fn poll_pending(future: Pin<&mut impl Future>) {
    let mut future = future;
    poll_fn(|cx| {
        assert!(future.as_mut().poll(cx).is_pending());
        Poll::Ready(())
    })
    .await;
}

async fn raw_pair() -> (WebSocketStream<DuplexStream>, WebSocketStream<DuplexStream>) {
    let (client, server) = tokio::io::duplex(4096);
    (
        WebSocketStream::from_raw_socket(client, Role::Client, None).await,
        WebSocketStream::from_raw_socket(server, Role::Server, None).await,
    )
}

fn record() -> Vec<u8> {
    build_msg1(
        SessionIndex::new(1),
        &[0; crate::noise::HANDSHAKE_MSG1_SIZE],
    )
}

async fn answer_hint<S>(websocket: &mut WebSocketStream<S>, pubkey: [u8; 32])
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let Some(Ok(Message::Binary(hint))) = websocket.next().await else {
        panic!("fresh dial must send its key-hint request");
    };
    let Some(LocalKeyHint::Request { nonce }) = LocalKeyHint::decode(&hint) else {
        panic!("fresh dial must begin with a valid request");
    };
    websocket
        .send(Message::Binary(
            LocalKeyHint::Response { nonce, pubkey }.encode().into(),
        ))
        .await
        .unwrap();
}

async fn expect_record<S>(websocket: &mut WebSocketStream<S>, expected: &[u8])
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    loop {
        match websocket.next().await {
            Some(Ok(Message::Binary(bytes))) => {
                assert_eq!(bytes.as_ref(), expected);
                return;
            }
            Some(Ok(Message::Ping(_) | Message::Pong(_))) => {}
            other => panic!("connection did not deliver the physical record: {other:?}"),
        }
    }
}

#[tokio::test]
async fn failed_initial_hint_write_releases_address_for_a_fresh_dial() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = TransportAddr::from_string(&format!("ws://{}/fips", listener.local_addr().unwrap()));
    let mut transport = test_transport(8);
    transport.start_async().await.unwrap();

    // Use the real WebSocket encoder with an underlay whose first write must
    // fail. A dropped duplex reader deterministically returns BrokenPipe.
    let (websocket, peer) = raw_pair().await;
    drop(peer);
    let error = run_framing_connection(
        transport.runtime.clone(),
        addr.clone(),
        websocket,
        transport.runtime.next_generation(),
        Direction::Outbound,
        true,
        0,
    )
    .await
    .unwrap_err();
    assert!(matches!(error, TransportError::SendFailed(_)));
    assert_eq!(transport.stats().connections_opened, 1);
    assert_eq!(transport.stats().connections_closed, 1);
    assert!(transport.discover().unwrap().is_empty());
    assert!(
        !transport.runtime.connections().contains_key(&addr),
        "failed initial hint write must not retain the address in the connection pool"
    );
    assert_eq!(
        transport.connection_state_sync(&addr),
        ConnectionState::None
    );

    let remote_pubkey = Identity::generate().pubkey().serialize();
    let expected = record();
    let server = async {
        let (stream, _) = listener.accept().await.unwrap();
        let mut websocket = tokio_tungstenite::accept_async(stream).await.unwrap();
        answer_hint(&mut websocket, remote_pubkey).await;
        expect_record(&mut websocket, &expected).await;
    };
    let client = async {
        transport.connect_async(&addr).await.unwrap();
        loop {
            let peers = transport.discover().unwrap();
            if !peers.is_empty() {
                assert_eq!(peers.len(), 1);
                assert_eq!(peers[0].addr, addr);
                assert_eq!(peers[0].pubkey_hint.unwrap().serialize(), remote_pubkey);
                break;
            }
            tokio::task::yield_now().await;
        }
        assert_eq!(
            transport.connection_state_sync(&addr),
            ConnectionState::Connected
        );
        transport.send_async(&addr, &expected).await.unwrap();
    };
    tokio::time::timeout(Duration::from_secs(3), async {
        tokio::join!(server, client);
    })
    .await
    .expect("same-address dial must complete discovery and deliver a fresh physical record");
    transport.stop_async().await.unwrap();
    assert_eq!(transport.stats().connections_opened, 2);
    assert_eq!(transport.stats().connections_closed, 2);
}

#[tokio::test]
async fn old_connection_completion_preserves_the_replacement_state_and_writer() {
    let mut transport = test_transport(8);
    transport.start_async().await.unwrap();
    let addr = TransportAddr::from_string("ws://127.0.0.1:1/fips");
    let (old_socket, mut old_peer) = raw_pair().await;
    let mut old = Box::pin(run_framing_connection(
        transport.runtime.clone(),
        addr.clone(),
        old_socket,
        transport.runtime.next_generation(),
        Direction::Outbound,
        true,
        0,
    ));
    poll_pending(old.as_mut()).await;
    answer_hint(&mut old_peer, Identity::generate().pubkey().serialize()).await;
    poll_pending(old.as_mut()).await;
    transport.close_connection_async(&addr).await;

    let (replacement_socket, mut replacement_peer) = raw_pair().await;
    let generation = transport.runtime.next_generation();
    let mut replacement = Box::pin(run_framing_connection(
        transport.runtime.clone(),
        addr.clone(),
        replacement_socket,
        generation,
        Direction::Outbound,
        true,
        0,
    ));
    poll_pending(replacement.as_mut()).await;
    let replacement_pubkey = Identity::generate().pubkey().serialize();
    answer_hint(&mut replacement_peer, replacement_pubkey).await;
    poll_pending(replacement.as_mut()).await;

    // The old worker finishes only after the new one has registered itself.
    drop(old_peer);
    let _ = old.await;
    let hints = transport.discover().unwrap();
    assert_eq!(hints.len(), 1);
    assert_eq!(
        hints[0].pubkey_hint.unwrap().serialize(),
        replacement_pubkey
    );
    {
        let pool = transport.runtime.connections();
        assert_eq!(pool.get(&addr).unwrap().generation, generation);
        // Holding the pool guard exercises the synchronous state fallback.
        assert_eq!(
            transport.connection_state_sync(&addr),
            ConnectionState::Connected
        );
    }

    let expected = record();
    transport.send_async(&addr, &expected).await.unwrap();
    tokio::time::timeout(Duration::from_secs(1), async {
        loop {
            tokio::select! {
                result = replacement.as_mut() => panic!("replacement ended early: {result:?}"),
                message = replacement_peer.next() => match message {
                    Some(Ok(Message::Binary(bytes))) => {
                        assert_eq!(bytes.as_ref(), expected.as_slice());
                        break;
                    }
                    Some(Ok(Message::Ping(_) | Message::Pong(_))) => {}
                    other => panic!("replacement did not deliver the physical record: {other:?}"),
                }
            }
        }
    })
    .await
    .expect("replacement must still forward after old connection cleanup");
    transport.close_connection_async(&addr).await;
    replacement.await.unwrap();
    assert_eq!(
        transport.connection_state_sync(&addr),
        ConnectionState::None
    );
    assert_eq!(transport.stats().connections_opened, 2);
    assert_eq!(transport.stats().connections_closed, 2);
    transport.stop_async().await.unwrap();
}

#[tokio::test]
async fn late_dial_completion_preserves_pending_and_established_replacement() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = TransportAddr::from_string(&format!("ws://{}/fips", listener.local_addr().unwrap()));
    let mut transport = test_transport(8);
    transport.start_async().await.unwrap();
    let attempt = transport.runtime.prepare_dial(&addr).unwrap();
    let mut old = Box::pin(run_one_shot_dial(
        transport.runtime.clone(),
        addr.clone(),
        attempt,
    ));
    let (old_stream, _) = tokio::time::timeout(Duration::from_secs(2), async {
        tokio::select! {
            _ = old.as_mut() => panic!("old dial ended before reaching HTTP upgrade"),
            accepted = listener.accept() => accepted.unwrap(),
        }
    })
    .await
    .unwrap();

    // A physical close permits a new dial while the old HTTP upgrade is pending.
    transport.close_connection_async(&addr).await;
    transport.connect_async(&addr).await.unwrap();
    let (replacement_stream, _) = tokio::time::timeout(Duration::from_secs(2), listener.accept())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        transport.connection_state_sync(&addr),
        ConnectionState::Connecting
    );

    // Tungstenite fixes the callback's HTTP error type.
    #[allow(clippy::result_large_err)]
    fn reject_upgrade(_request: &Request, _response: Response) -> Result<Response, ErrorResponse> {
        let mut response = ErrorResponse::new(Some("retry later".into()));
        *response.status_mut() =
            tokio_tungstenite::tungstenite::http::StatusCode::SERVICE_UNAVAILABLE;
        Err(response)
    }
    let rejection = tokio_tungstenite::accept_hdr_async(old_stream, reject_upgrade);
    let (_, rejected) = tokio::time::timeout(Duration::from_secs(2), async {
        tokio::join!(old, rejection)
    })
    .await
    .expect("retired dial must finish without changing the pending replacement");
    assert!(rejected.is_err());
    assert_eq!(
        transport.connection_state_sync(&addr),
        ConnectionState::Connecting
    );
    let mut replacement_peer = tokio_tungstenite::accept_async(replacement_stream)
        .await
        .unwrap();
    answer_hint(
        &mut replacement_peer,
        Identity::generate().pubkey().serialize(),
    )
    .await;
    wait_for_connection(&transport, &addr).await;
    let generation = transport
        .runtime
        .connections()
        .get(&addr)
        .unwrap()
        .generation;
    {
        let pool = transport.runtime.connections();
        assert_eq!(pool.get(&addr).unwrap().generation, generation);
        assert_eq!(
            transport.connection_state_sync(&addr),
            ConnectionState::Connected,
            "a late failed dial must not replace the active connection's status"
        );
    }
    let expected = record();
    transport.send_async(&addr, &expected).await.unwrap();
    tokio::time::timeout(
        Duration::from_secs(1),
        expect_record(&mut replacement_peer, &expected),
    )
    .await
    .unwrap();
    transport.stop_async().await.unwrap();
    assert_eq!(transport.stats().connections_opened, 1);
    assert_eq!(transport.stats().connections_closed, 1);
}

#[tokio::test]
async fn detached_close_cannot_remove_a_replacement() {
    use futures::FutureExt;
    for had_original in [true, false] {
        let mut transport = test_transport(8);
        transport.start_async().await.unwrap();
        let addr = TransportAddr::from_string("ws://127.0.0.1:1/fips");
        if had_original {
            let (socket, peer) = raw_pair().await;
            let mut old = Box::pin(run_framing_connection(
                transport.runtime.clone(),
                addr.clone(),
                socket,
                transport.runtime.next_generation(),
                Direction::Outbound,
                false,
                0,
            ));
            poll_pending(old.as_mut()).await;
            transport.close_connection_detached(&addr);
            drop(peer);
            // Complete the old worker without yielding to the scheduled close.
            let _ = old
                .as_mut()
                .now_or_never()
                .expect("closed underlay must finish immediately");
        } else {
            transport.close_connection_detached(&addr);
        }
        let (socket, mut peer) = raw_pair().await;
        let generation = transport.runtime.next_generation();
        let mut replacement = Box::pin(run_framing_connection(
            transport.runtime.clone(),
            addr.clone(),
            socket,
            generation,
            Direction::Outbound,
            false,
            0,
        ));
        poll_pending(replacement.as_mut()).await;
        // This current-thread test has not yielded. Any detached cleanup now
        // runs after the replacement registered at the same seed URL.
        let tasks = std::mem::take(&mut *transport.runtime.tasks.lock().unwrap());
        for task in tasks {
            task.await.unwrap();
        }
        assert_eq!(
            transport.connection_state_sync(&addr),
            ConnectionState::Connected,
            "a delayed close must leave the replacement connected"
        );
        let expected = record();
        transport.send_async(&addr, &expected).await.unwrap();
        tokio::time::timeout(Duration::from_secs(1), async {
            tokio::select! {
                result = replacement.as_mut() => panic!("replacement ended early: {result:?}"),
                _ = expect_record(&mut peer, &expected) => {}
            }
        })
        .await
        .expect("replacement must deliver after detached cleanup");
        transport.close_connection_async(&addr).await;
        replacement.await.unwrap();
        assert_eq!(
            transport.stats().connections_opened,
            1 + u64::from(had_original)
        );
        assert_eq!(
            transport.stats().connections_closed,
            1 + u64::from(had_original)
        );
        transport.stop_async().await.unwrap();
    }
}

#[tokio::test]
async fn unconsumed_seed_hints_retire_with_their_physical_connection() {
    for retirement in ["remote-close", "peer-removal", "network-change", "stop"] {
        let mut transport = test_transport(8);
        let addr = TransportAddr::from_string("ws://127.0.0.1:1/fips");
        for keep_live in [false, true] {
            if !transport.state.is_operational() {
                transport.start_async().await.unwrap();
            }
            let pubkey = Identity::generate().pubkey().serialize();
            let (socket, mut peer) = raw_pair().await;
            let mut connection = Box::pin(run_framing_connection(
                transport.runtime.clone(),
                addr.clone(),
                socket,
                transport.runtime.next_generation(),
                Direction::Outbound,
                true,
                *transport.runtime.network_rebind_generation.borrow(),
            ));
            poll_pending(connection.as_mut()).await;
            answer_hint(&mut peer, pubkey).await;
            poll_pending(connection.as_mut()).await;

            if keep_live {
                // A new connection at the same URL still announces its own
                // key exactly once after the previous connection retires.
                let hints = transport.discover().unwrap();
                assert_eq!(hints.len(), 1, "fresh discovery after {retirement}");
                assert_eq!(hints[0].addr, addr);
                assert_eq!(hints[0].pubkey_hint.unwrap().serialize(), pubkey);
                assert!(transport.discover().unwrap().is_empty());
                transport.close_connection_detached(&addr);
            } else {
                match retirement {
                    "remote-close" => peer.close(None).await.unwrap(),
                    "peer-removal" => transport.close_connection_detached(&addr),
                    "network-change" => {
                        assert!(transport.restart_after_network_change().await.unwrap());
                    }
                    "stop" => transport.stop_async().await.unwrap(),
                    _ => unreachable!(),
                }
            }
            tokio::time::timeout(Duration::from_secs(1), connection)
                .await
                .expect("retired physical connection must finish")
                .unwrap();
            assert!(
                transport.discover().unwrap().is_empty(),
                "retired WebSocket connection must not leave a discovery hint: {retirement}"
            );
        }
        assert_eq!(transport.stats().connections_opened, 2);
        assert_eq!(transport.stats().connections_closed, 2);
        transport.stop_async().await.unwrap();
    }
}

#[tokio::test]
async fn cancelled_outbound_upgrade_cannot_register_or_hold_the_connection_slot() {
    for (seeded, detached) in [(false, false), (false, true), (true, false), (true, true)] {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr =
            TransportAddr::from_string(&format!("ws://{}/fips", listener.local_addr().unwrap()));
        let identity = Identity::generate();
        let (tx, _rx) = packet_channel(8);
        let mut client = WebSocketTransport::new(
            TransportId::new(1),
            None,
            WebSocketConfig {
                seed_urls: if seeded {
                    vec![addr.to_string()]
                } else {
                    Vec::new()
                },
                max_connections: Some(1),
                max_inbound_connections: Some(1),
                connect_timeout_ms: Some(10_000),
                key_hint_timeout_ms: Some(10_000),
                reconnect_initial_ms: Some(5_000),
                reconnect_max_ms: Some(5_000),
                ping_interval_secs: Some(0),
                idle_timeout_secs: Some(0),
                ..Default::default()
            },
            tx,
            &identity,
        );
        client.start_async().await.unwrap();
        if !seeded {
            client.connect_async(&addr).await.unwrap();
        }
        let (stream, _) = tokio::time::timeout(Duration::from_secs(1), listener.accept())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(client.runtime.total_slots.available_permits(), 0);
        assert_eq!(
            client.connection_state_sync(&addr),
            ConnectionState::Connecting
        );
        assert_eq!(client.stats().connections_opened, 0);

        if detached {
            client.close_connection_detached(&addr);
        } else {
            client.close_connection_async(&addr).await;
        }
        // Finish the old server handshake only after cancellation. Its reply
        // must not promote an abandoned dial, even if the HTTP write succeeds.
        let late = tokio::time::timeout(
            Duration::from_secs(1),
            tokio_tungstenite::accept_async(stream),
        )
        .await
        .ok()
        .and_then(Result::ok);
        let released = tokio::time::timeout(Duration::from_millis(500), async {
            while client.runtime.total_slots.available_permits() != 1 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .is_ok();
        let stale_state = client.connection_state_sync(&addr);
        let stale_opened = client.stats().connections_opened;
        drop(late);
        if !released {
            client.stop_async().await.unwrap();
        }
        assert!(
            released,
            "cancelled outbound upgrade retained its connection slot: seeded={seeded} detached={detached} state={stale_state:?} opened={stale_opened}"
        );
        assert_eq!(stale_state, ConnectionState::None);
        assert_eq!(stale_opened, 0);
        assert!(client.discover().unwrap().is_empty());

        // Reuse the same URL and sole connection slot without stopping the
        // transport or waiting for the configured seed's five-second backoff.
        client.connect_async(&addr).await.unwrap();
        let (stream, _) = tokio::time::timeout(Duration::from_secs(1), listener.accept())
            .await
            .unwrap()
            .unwrap();
        let mut replacement = tokio_tungstenite::accept_async(stream).await.unwrap();
        let pubkey = Identity::generate().pubkey().serialize();
        answer_hint(&mut replacement, pubkey).await;
        tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                let hints = client.discover().unwrap();
                if !hints.is_empty() {
                    assert_eq!(hints.len(), 1);
                    assert_eq!(hints[0].pubkey_hint.unwrap().serialize(), pubkey);
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("the replacement must complete fresh discovery");
        let expected = record();
        client.send_async(&addr, &expected).await.unwrap();
        tokio::time::timeout(
            Duration::from_secs(1),
            expect_record(&mut replacement, &expected),
        )
        .await
        .unwrap();
        client.stop_async().await.unwrap();
        assert_eq!(client.runtime.total_slots.available_permits(), 1);
        assert_eq!(client.stats().connections_opened, 1);
        assert_eq!(client.stats().connections_closed, 1);
    }
}

#[tokio::test(flavor = "current_thread")]
async fn outbound_dial_limit_is_reserved_before_workers_run() {
    let mut client = test_transport(8);
    client.start_async().await.unwrap();
    let limit = client.config.max_connections();
    let first = TransportAddr::from_string("ws://127.0.0.1:1/0");
    for index in 0..limit {
        let addr = TransportAddr::from_string(&format!("ws://127.0.0.1:1/{index}"));
        client.connect_async(&addr).await.unwrap();
    }
    // No pending worker has been polled on this current-thread runtime.
    assert_eq!(client.runtime.total_slots.available_permits(), 0);
    assert_eq!(client.runtime.statuses().len(), limit);
    client.connect_async(&first).await.unwrap();
    let extra = TransportAddr::from_string("ws://127.0.0.1:1/excess");
    assert!(matches!(
        client.connect_async(&extra).await,
        Err(TransportError::ConnectionRefused)
    ));
    assert_eq!(client.connection_state_sync(&extra), ConnectionState::None);
    assert_eq!(client.runtime.statuses().len(), limit);
    assert_eq!(client.stats().connections_opened, 0);
    client.stop_async().await.unwrap();
    assert_eq!(client.runtime.total_slots.available_permits(), limit);
    assert!(client.runtime.statuses().is_empty());
}
