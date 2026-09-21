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
    let error = run_connection(
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
        !transport.runtime.pool.lock().await.contains_key(&addr),
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
    let (old_socket, old_peer) = raw_pair().await;
    let mut old = Box::pin(run_connection(
        transport.runtime.clone(),
        addr.clone(),
        old_socket,
        transport.runtime.next_generation(),
        Direction::Outbound,
        false,
        0,
    ));
    poll_pending(old.as_mut()).await;
    transport.close_connection_async(&addr).await;

    let (replacement_socket, mut replacement_peer) = raw_pair().await;
    let generation = transport.runtime.next_generation();
    let mut replacement = Box::pin(run_connection(
        transport.runtime.clone(),
        addr.clone(),
        replacement_socket,
        generation,
        Direction::Outbound,
        false,
        0,
    ));
    poll_pending(replacement.as_mut()).await;

    // The old worker finishes only after the new one has registered itself.
    drop(old_peer);
    let _ = old.await;
    {
        let pool = transport.runtime.pool.lock().await;
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
async fn late_dial_failure_does_not_overwrite_an_established_replacement() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = TransportAddr::from_string(&format!("ws://{}/fips", listener.local_addr().unwrap()));
    let mut transport = test_transport(8);
    transport.start_async().await.unwrap();
    transport
        .runtime
        .set_state(&addr, ConnectionState::Connecting);
    let mut old = Box::pin(run_one_shot_dial(transport.runtime.clone(), addr.clone()));
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
    let mut replacement_peer = tokio::time::timeout(Duration::from_secs(2), async {
        let (stream, _) = listener.accept().await.unwrap();
        let mut peer = tokio_tungstenite::accept_async(stream).await.unwrap();
        answer_hint(&mut peer, Identity::generate().pubkey().serialize()).await;
        peer
    })
    .await
    .unwrap();
    wait_for_connection(&transport, &addr).await;
    let generation = transport
        .runtime
        .pool
        .lock()
        .await
        .get(&addr)
        .unwrap()
        .generation;

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
    .expect("old dial must publish its failed HTTP upgrade result");
    assert!(rejected.is_err());
    {
        let pool = transport.runtime.pool.lock().await;
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
