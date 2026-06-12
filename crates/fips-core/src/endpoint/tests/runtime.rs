use super::*;

#[tokio::test]
async fn endpoint_starts_without_system_tun() {
    let endpoint = FipsEndpoint::builder()
        .without_system_tun()
        .bind()
        .await
        .expect("endpoint should bind");

    assert!(!endpoint.npub().is_empty());
    assert!(endpoint.discovery_scope().is_none());
    endpoint.shutdown().await.expect("shutdown should succeed");
}

#[tokio::test]
async fn loopback_endpoint_data_roundtrips() {
    let endpoint = FipsEndpoint::builder()
        .without_system_tun()
        .bind()
        .await
        .expect("endpoint should bind");

    endpoint
        .send(endpoint.npub().to_string(), b"ping".to_vec())
        .await
        .expect("loopback send should succeed");
    let message = tokio::time::timeout(Duration::from_secs(1), endpoint.recv())
        .await
        .expect("recv should not time out")
        .expect("message should arrive");
    assert_eq!(*message.source_node_addr(), *endpoint.node_addr());
    assert_eq!(message.source_npub(), endpoint.npub());
    assert_eq!(message.data, b"ping");
    assert!(endpoint.discovery_scope().is_none());

    endpoint.shutdown().await.expect("shutdown should succeed");
}

#[tokio::test]
async fn send_to_peer_loopback_endpoint_data_roundtrips() {
    let endpoint = FipsEndpoint::builder()
        .without_system_tun()
        .bind()
        .await
        .expect("endpoint should bind");

    let local = PeerIdentity::from_npub(endpoint.npub()).expect("local peer identity");
    endpoint
        .send_to_peer(local, b"ping".to_vec())
        .await
        .expect("loopback send should succeed");
    let message = tokio::time::timeout(Duration::from_secs(1), endpoint.recv())
        .await
        .expect("recv should not time out")
        .expect("message should arrive");
    assert_eq!(*message.source_node_addr(), *endpoint.node_addr());
    assert_eq!(message.source_npub(), endpoint.npub());
    assert_eq!(message.data, b"ping");

    endpoint.shutdown().await.expect("shutdown should succeed");
}

#[tokio::test]
async fn send_batch_to_peer_loopback_endpoint_data_roundtrips() {
    let endpoint = FipsEndpoint::builder()
        .without_system_tun()
        .bind()
        .await
        .expect("endpoint should bind");

    let local = PeerIdentity::from_npub(endpoint.npub()).expect("local peer identity");
    endpoint
        .send_batch_to_peer(local, vec![b"ping".to_vec(), b"pong".to_vec()])
        .await
        .expect("loopback batch send should succeed");

    let first = tokio::time::timeout(Duration::from_secs(1), endpoint.recv())
        .await
        .expect("first recv should not time out")
        .expect("first message should arrive");
    let second = tokio::time::timeout(Duration::from_secs(1), endpoint.recv())
        .await
        .expect("second recv should not time out")
        .expect("second message should arrive");
    assert_eq!(*first.source_node_addr(), *endpoint.node_addr());
    assert_eq!(first.source_npub(), endpoint.npub());
    assert_eq!(first.data, b"ping");
    assert_eq!(*second.source_node_addr(), *endpoint.node_addr());
    assert_eq!(second.source_npub(), endpoint.npub());
    assert_eq!(second.data, b"pong");

    endpoint.shutdown().await.expect("shutdown should succeed");
}

#[tokio::test]
async fn recv_batch_drains_ready_loopback_endpoint_data() {
    let endpoint = FipsEndpoint::builder()
        .without_system_tun()
        .bind()
        .await
        .expect("endpoint should bind");

    let local = PeerIdentity::from_npub(endpoint.npub()).expect("local peer identity");
    endpoint
        .send_batch_to_peer(
            local,
            vec![b"first".to_vec(), b"second".to_vec(), b"third".to_vec()],
        )
        .await
        .expect("loopback batch send should succeed");

    let messages = tokio::time::timeout(Duration::from_secs(1), endpoint.recv_batch(2))
        .await
        .expect("recv batch should not time out")
        .expect("messages should arrive");
    assert_eq!(messages.len(), 2);
    assert!(
        messages
            .iter()
            .all(|message| *message.source_node_addr() == *endpoint.node_addr())
    );
    assert_eq!(messages[0].data, b"first");
    assert_eq!(messages[1].data, b"second");

    let message = tokio::time::timeout(Duration::from_secs(1), endpoint.recv())
        .await
        .expect("recv should not time out")
        .expect("message should arrive");
    assert_eq!(message.data, b"third");

    endpoint.shutdown().await.expect("shutdown should succeed");
}

#[tokio::test]
async fn recv_batch_into_reuses_caller_buffer_and_respects_limit() {
    let endpoint = FipsEndpoint::builder()
        .without_system_tun()
        .bind()
        .await
        .expect("endpoint should bind");

    let local = PeerIdentity::from_npub(endpoint.npub()).expect("local peer identity");
    endpoint
        .send_batch_to_peer(
            local,
            vec![b"first".to_vec(), b"second".to_vec(), b"third".to_vec()],
        )
        .await
        .expect("loopback batch send should succeed");

    let mut messages = Vec::with_capacity(8);
    let capacity = messages.capacity();
    let received = tokio::time::timeout(
        Duration::from_secs(1),
        endpoint.recv_batch_into(&mut messages, 2),
    )
    .await
    .expect("recv batch should not time out")
    .expect("messages should arrive");
    assert_eq!(received, 2);
    assert_eq!(messages.capacity(), capacity);
    assert_eq!(messages[0].data, b"first");
    assert_eq!(messages[1].data, b"second");

    let received = tokio::time::timeout(
        Duration::from_secs(1),
        endpoint.recv_batch_into(&mut messages, 8),
    )
    .await
    .expect("recv batch should not time out")
    .expect("message should arrive");
    assert_eq!(received, 1);
    assert_eq!(messages.capacity(), capacity);
    assert_eq!(messages[0].data, b"third");

    endpoint.shutdown().await.expect("shutdown should succeed");
}

#[tokio::test]
async fn recv_batch_into_splits_internal_endpoint_batches_without_reordering() {
    let endpoint = FipsEndpoint::builder()
        .without_system_tun()
        .bind()
        .await
        .expect("endpoint should bind");
    let local = PeerIdentity::from_npub(endpoint.npub()).expect("local peer identity");

    endpoint
        .inbound_endpoint_tx
        .send(NodeEndpointEvent::DataBatch {
            messages: vec![
                EndpointDataDelivery::new(local, b"first".to_vec()),
                EndpointDataDelivery::new(local, b"second".to_vec()),
                EndpointDataDelivery::new(local, b"third".to_vec()),
            ],
            queued_at: crate::perf_profile::stamp(),
        })
        .expect("inject internal batch");
    endpoint
        .inbound_endpoint_tx
        .send(NodeEndpointEvent::Data {
            source_peer: local,
            payload: b"fourth".to_vec(),
            queued_at: crate::perf_profile::stamp(),
        })
        .expect("inject follow-on message");

    let mut messages = Vec::with_capacity(8);
    let received = tokio::time::timeout(
        Duration::from_secs(1),
        endpoint.recv_batch_into(&mut messages, 2),
    )
    .await
    .expect("recv batch should not time out")
    .expect("messages should arrive");
    assert_eq!(received, 2);
    assert_eq!(messages[0].data, b"first");
    assert_eq!(messages[1].data, b"second");

    let received = tokio::time::timeout(
        Duration::from_secs(1),
        endpoint.recv_batch_into(&mut messages, 8),
    )
    .await
    .expect("recv batch should not time out")
    .expect("messages should arrive");
    assert_eq!(received, 2);
    assert_eq!(messages[0].data, b"third");
    assert_eq!(messages[1].data, b"fourth");

    endpoint.shutdown().await.expect("shutdown should succeed");
}

#[tokio::test]
async fn recv_batch_into_priority_overtakes_pending_bulk_batch_tail() {
    let endpoint = FipsEndpoint::builder()
        .without_system_tun()
        .bind()
        .await
        .expect("endpoint should bind");
    let local = PeerIdentity::from_npub(endpoint.npub()).expect("local peer identity");

    endpoint
        .inbound_endpoint_tx
        .send(NodeEndpointEvent::DataBatch {
            messages: vec![
                EndpointDataDelivery::new(local, vec![0xaa; ENDPOINT_EVENT_PRIORITY_MAX_LEN + 1]),
                EndpointDataDelivery::new(local, vec![0xbb; ENDPOINT_EVENT_PRIORITY_MAX_LEN + 2]),
            ],
            queued_at: crate::perf_profile::stamp(),
        })
        .expect("inject bulk internal batch");

    let mut messages = Vec::with_capacity(8);
    let received = tokio::time::timeout(
        Duration::from_secs(1),
        endpoint.recv_batch_into(&mut messages, 1),
    )
    .await
    .expect("recv batch should not time out")
    .expect("message should arrive");
    assert_eq!(received, 1);
    assert_eq!(messages[0].data[0], 0xaa);

    endpoint
        .inbound_endpoint_tx
        .send(NodeEndpointEvent::Data {
            source_peer: local,
            payload: vec![0x11; 32],
            queued_at: crate::perf_profile::stamp(),
        })
        .expect("inject priority follow-on");

    let received = tokio::time::timeout(
        Duration::from_secs(1),
        endpoint.recv_batch_into(&mut messages, 8),
    )
    .await
    .expect("recv batch should not time out")
    .expect("messages should arrive");
    assert_eq!(received, 2);
    assert_eq!(messages[0].data[0], 0x11);
    assert_eq!(messages[1].data[0], 0xbb);

    endpoint.shutdown().await.expect("shutdown should succeed");
}

#[tokio::test]
async fn try_recv_drains_pending_internal_endpoint_batch_tail() {
    let endpoint = FipsEndpoint::builder()
        .without_system_tun()
        .bind()
        .await
        .expect("endpoint should bind");
    let local = PeerIdentity::from_npub(endpoint.npub()).expect("local peer identity");

    endpoint
        .inbound_endpoint_tx
        .send(NodeEndpointEvent::DataBatch {
            messages: vec![
                EndpointDataDelivery::new(local, b"first".to_vec()),
                EndpointDataDelivery::new(local, b"second".to_vec()),
            ],
            queued_at: crate::perf_profile::stamp(),
        })
        .expect("inject internal batch");

    assert_eq!(endpoint.try_recv().expect("first message").data, b"first");
    assert_eq!(
        endpoint.try_recv().expect("pending message").data,
        b"second"
    );
    assert!(endpoint.try_recv().is_none());

    endpoint.shutdown().await.expect("shutdown should succeed");
}

#[tokio::test]
async fn blocking_recv_drains_pending_internal_endpoint_batch_tail() {
    let endpoint = FipsEndpoint::builder()
        .without_system_tun()
        .bind()
        .await
        .expect("endpoint should bind");
    let local = PeerIdentity::from_npub(endpoint.npub()).expect("local peer identity");

    endpoint
        .inbound_endpoint_tx
        .send(NodeEndpointEvent::DataBatch {
            messages: vec![
                EndpointDataDelivery::new(local, b"first".to_vec()),
                EndpointDataDelivery::new(local, b"second".to_vec()),
            ],
            queued_at: crate::perf_profile::stamp(),
        })
        .expect("inject internal batch");

    let endpoint = tokio::task::spawn_blocking(move || {
        let first = endpoint.blocking_recv().expect("first message");
        let second = endpoint.blocking_recv().expect("pending message");
        assert_eq!(first.data, b"first");
        assert_eq!(second.data, b"second");
        endpoint
    })
    .await
    .expect("blocking receiver should join");

    endpoint.shutdown().await.expect("shutdown should succeed");
}

#[tokio::test]
async fn blocking_recv_batch_into_priority_overtakes_pending_bulk_batch_tail() {
    let endpoint = FipsEndpoint::builder()
        .without_system_tun()
        .bind()
        .await
        .expect("endpoint should bind");
    let local = PeerIdentity::from_npub(endpoint.npub()).expect("local peer identity");

    endpoint
        .inbound_endpoint_tx
        .send(NodeEndpointEvent::DataBatch {
            messages: vec![
                EndpointDataDelivery::new(local, vec![0xaa; ENDPOINT_EVENT_PRIORITY_MAX_LEN + 1]),
                EndpointDataDelivery::new(local, vec![0xbb; ENDPOINT_EVENT_PRIORITY_MAX_LEN + 2]),
            ],
            queued_at: crate::perf_profile::stamp(),
        })
        .expect("inject bulk internal batch");

    let priority_tx = endpoint.inbound_endpoint_tx.clone();
    let endpoint = tokio::task::spawn_blocking(move || {
        let mut messages = Vec::with_capacity(8);
        let received = endpoint
            .blocking_recv_batch_into(&mut messages, 1)
            .expect("message should arrive");
        assert_eq!(received, 1);
        assert_eq!(messages[0].data[0], 0xaa);

        priority_tx
            .send(NodeEndpointEvent::Data {
                source_peer: local,
                payload: vec![0x11; 32],
                queued_at: crate::perf_profile::stamp(),
            })
            .expect("inject priority follow-on");

        let received = endpoint
            .blocking_recv_batch_into(&mut messages, 8)
            .expect("messages should arrive");
        assert_eq!(received, 2);
        assert_eq!(messages[0].data[0], 0x11);
        assert_eq!(messages[1].data[0], 0xbb);
        endpoint
    })
    .await
    .expect("blocking receiver should join");

    endpoint.shutdown().await.expect("shutdown should succeed");
}

#[tokio::test]
async fn blocking_recv_batch_into_reuses_caller_buffer_and_respects_limit() {
    let endpoint = FipsEndpoint::builder()
        .without_system_tun()
        .bind()
        .await
        .expect("endpoint should bind");

    let local = PeerIdentity::from_npub(endpoint.npub()).expect("local peer identity");
    endpoint
        .send_batch_to_peer(
            local,
            vec![b"first".to_vec(), b"second".to_vec(), b"third".to_vec()],
        )
        .await
        .expect("loopback batch send should succeed");

    let (endpoint, capacity) = tokio::task::spawn_blocking(move || {
        let mut messages = Vec::with_capacity(8);
        let capacity = messages.capacity();
        let received = endpoint
            .blocking_recv_batch_into(&mut messages, 2)
            .expect("messages should arrive");
        assert_eq!(received, 2);
        assert_eq!(messages.capacity(), capacity);
        assert_eq!(messages[0].data, b"first");
        assert_eq!(messages[1].data, b"second");

        let received = endpoint
            .blocking_recv_batch_into(&mut messages, 8)
            .expect("message should arrive");
        assert_eq!(received, 1);
        assert_eq!(messages.capacity(), capacity);
        assert_eq!(messages[0].data, b"third");

        (endpoint, capacity)
    })
    .await
    .expect("blocking receiver should join");
    assert_eq!(capacity, 8);

    endpoint.shutdown().await.expect("shutdown should succeed");
}

#[tokio::test]
async fn blocking_recv_batch_for_each_respects_limit_without_message_vec_staging() {
    let endpoint = FipsEndpoint::builder()
        .without_system_tun()
        .bind()
        .await
        .expect("endpoint should bind");

    let local = PeerIdentity::from_npub(endpoint.npub()).expect("local peer identity");
    endpoint
        .send_batch_to_peer(
            local,
            vec![b"first".to_vec(), b"second".to_vec(), b"third".to_vec()],
        )
        .await
        .expect("loopback batch send should succeed");

    let endpoint = tokio::task::spawn_blocking(move || {
        let mut messages = Vec::with_capacity(3);
        let received = endpoint
            .blocking_recv_batch_for_each(2, |message| {
                messages.push(message.data);
                true
            })
            .expect("messages should arrive");
        assert_eq!(received, 2);
        assert_eq!(messages, vec![b"first".to_vec(), b"second".to_vec()]);

        let received = endpoint
            .blocking_recv_batch_for_each(8, |message| {
                messages.push(message.data);
                true
            })
            .expect("message should arrive");
        assert_eq!(received, 1);
        assert_eq!(
            messages,
            vec![b"first".to_vec(), b"second".to_vec(), b"third".to_vec()]
        );
        endpoint
    })
    .await
    .expect("blocking receiver should join");

    endpoint.shutdown().await.expect("shutdown should succeed");
}

#[tokio::test]
async fn blocking_recv_batch_for_each_preserves_unhandled_internal_batch_tail() {
    let endpoint = FipsEndpoint::builder()
        .without_system_tun()
        .bind()
        .await
        .expect("endpoint should bind");
    let local = PeerIdentity::from_npub(endpoint.npub()).expect("local peer identity");

    endpoint
        .inbound_endpoint_tx
        .send(NodeEndpointEvent::DataBatch {
            messages: vec![
                EndpointDataDelivery::new(local, b"first".to_vec()),
                EndpointDataDelivery::new(local, b"second".to_vec()),
                EndpointDataDelivery::new(local, b"third".to_vec()),
            ],
            queued_at: crate::perf_profile::stamp(),
        })
        .expect("inject internal batch");

    let endpoint = tokio::task::spawn_blocking(move || {
        let mut messages = Vec::with_capacity(3);
        let received = endpoint
            .blocking_recv_batch_for_each(8, |message| {
                messages.push(message.data);
                false
            })
            .expect("message should arrive");
        assert_eq!(received, 1);
        assert_eq!(messages, vec![b"first".to_vec()]);

        let received = endpoint
            .blocking_recv_batch_for_each(8, |message| {
                messages.push(message.data);
                true
            })
            .expect("pending messages should arrive");
        assert_eq!(received, 2);
        assert_eq!(
            messages,
            vec![b"first".to_vec(), b"second".to_vec(), b"third".to_vec()]
        );
        endpoint
    })
    .await
    .expect("blocking receiver should join");

    endpoint.shutdown().await.expect("shutdown should succeed");
}

#[tokio::test]
async fn blocking_recv_batch_into_splits_internal_endpoint_batches_without_reordering() {
    let endpoint = FipsEndpoint::builder()
        .without_system_tun()
        .bind()
        .await
        .expect("endpoint should bind");
    let local = PeerIdentity::from_npub(endpoint.npub()).expect("local peer identity");

    endpoint
        .inbound_endpoint_tx
        .send(NodeEndpointEvent::DataBatch {
            messages: vec![
                EndpointDataDelivery::new(local, b"first".to_vec()),
                EndpointDataDelivery::new(local, b"second".to_vec()),
                EndpointDataDelivery::new(local, b"third".to_vec()),
            ],
            queued_at: crate::perf_profile::stamp(),
        })
        .expect("inject internal batch");
    endpoint
        .inbound_endpoint_tx
        .send(NodeEndpointEvent::Data {
            source_peer: local,
            payload: b"fourth".to_vec(),
            queued_at: crate::perf_profile::stamp(),
        })
        .expect("inject follow-on message");

    let endpoint = tokio::task::spawn_blocking(move || {
        let mut messages = Vec::with_capacity(8);
        let received = endpoint
            .blocking_recv_batch_into(&mut messages, 2)
            .expect("messages should arrive");
        assert_eq!(received, 2);
        assert_eq!(messages[0].data, b"first");
        assert_eq!(messages[1].data, b"second");

        let received = endpoint
            .blocking_recv_batch_into(&mut messages, 8)
            .expect("messages should arrive");
        assert_eq!(received, 2);
        assert_eq!(messages[0].data, b"third");
        assert_eq!(messages[1].data, b"fourth");

        endpoint
    })
    .await
    .expect("blocking receiver should join");

    endpoint.shutdown().await.expect("shutdown should succeed");
}

#[tokio::test]
async fn blocking_send_to_peer_loopback_endpoint_data_roundtrips() {
    let endpoint = FipsEndpoint::builder()
        .without_system_tun()
        .bind()
        .await
        .expect("endpoint should bind");

    let local = PeerIdentity::from_npub(endpoint.npub()).expect("local peer identity");
    endpoint
        .blocking_send_to_peer(local, b"ping".to_vec())
        .expect("loopback send should succeed");
    let message = tokio::time::timeout(Duration::from_secs(1), endpoint.recv())
        .await
        .expect("recv should not time out")
        .expect("message should arrive");
    assert_eq!(*message.source_node_addr(), *endpoint.node_addr());
    assert_eq!(message.source_npub(), endpoint.npub());
    assert_eq!(message.data, b"ping");

    endpoint.shutdown().await.expect("shutdown should succeed");
}
