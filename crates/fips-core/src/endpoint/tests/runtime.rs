use super::*;
use std::time::Duration;

fn endpoint_delivery(source: PeerIdentity, payload: Vec<u8>) -> EndpointDataDelivery {
    EndpointDataDelivery::new(source, crate::transport::PacketBuffer::new(payload))
}

fn one_message_endpoint_event(source: PeerIdentity, payload: Vec<u8>) -> NodeEndpointEvent {
    NodeEndpointEvent {
        messages: vec![endpoint_delivery(source, payload)],
        queued_at: crate::perf_profile::stamp(),
    }
}

async fn recv_endpoint_batch(
    endpoint: &FipsEndpoint,
    max: usize,
    expected: &str,
) -> Vec<FipsEndpointMessage> {
    let mut messages = Vec::with_capacity(max);
    tokio::time::timeout(
        Duration::from_secs(1),
        endpoint.recv_batch_into(&mut messages, max),
    )
    .await
    .expect("recv batch should not time out")
    .unwrap_or_else(|| panic!("{expected}"));
    messages
}

async fn recv_service_batch(
    endpoint: &FipsEndpoint,
    max: usize,
    expected: &str,
) -> Vec<FipsEndpointServiceDatagram> {
    let mut datagrams = Vec::with_capacity(max);
    tokio::time::timeout(
        Duration::from_secs(1),
        endpoint.recv_service_datagram_batch_into(&mut datagrams, max),
    )
    .await
    .expect("service receive should not time out")
    .unwrap_or_else(|| panic!("{expected}"));
    datagrams
}

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

#[tokio::test(start_paused = true)]
async fn endpoint_control_times_out_for_wedged_node() {
    let mut endpoint = FipsEndpoint::builder()
        .without_system_tun()
        .bind()
        .await
        .expect("endpoint should bind");
    let (control_tx, mut control_rx) = mpsc::channel(1);
    endpoint.endpoint_control_tx = control_tx;
    let wedged_node = tokio::spawn(async move {
        let _command = control_rx.recv().await.expect("control command");
        std::future::pending::<()>().await;
    });

    let endpoint = Arc::new(endpoint);
    let call = {
        let endpoint = Arc::clone(&endpoint);
        tokio::spawn(async move { endpoint.peers().await })
    };
    tokio::task::yield_now().await;
    tokio::time::advance(ENDPOINT_OPERATION_TIMEOUT).await;
    let error = call
        .await
        .expect("control call task")
        .expect_err("wedged control response should time out");
    assert!(matches!(
        error,
        FipsEndpointError::Timeout {
            operation: "peer snapshot"
        }
    ));

    wedged_node.abort();
    let _ = wedged_node.await;
    endpoint.shutdown().await.expect("shutdown should succeed");
}

#[tokio::test(start_paused = true)]
async fn endpoint_shutdown_aborts_wedged_node_after_graceful_budget() {
    let endpoint = FipsEndpoint::builder()
        .without_system_tun()
        .bind()
        .await
        .expect("endpoint should bind");
    let (task_drop_tx, task_drop_rx) = oneshot::channel::<()>();
    let wedged_task = tokio::spawn(async move {
        let _task_drop_tx = task_drop_tx;
        std::future::pending::<()>().await;
        Ok(())
    });
    let node_task = endpoint
        .task
        .lock()
        .expect("endpoint task lock")
        .replace(wedged_task)
        .expect("running node task");
    node_task.abort();
    let _ = node_task.await;

    let endpoint = Arc::new(endpoint);
    let shutdown = {
        let endpoint = Arc::clone(&endpoint);
        tokio::spawn(async move { endpoint.shutdown().await })
    };
    tokio::task::yield_now().await;
    tokio::time::advance(ENDPOINT_OPERATION_TIMEOUT).await;
    let error = shutdown
        .await
        .expect("shutdown call task")
        .expect_err("wedged node shutdown should time out");
    assert!(matches!(
        error,
        FipsEndpointError::Timeout {
            operation: "shutdown"
        }
    ));
    assert!(task_drop_rx.await.is_err(), "wedged task should be aborted");
}

#[tokio::test]
async fn endpoint_drop_detaches_its_task_after_signaling_graceful_shutdown() {
    let endpoint = FipsEndpoint::builder()
        .without_system_tun()
        .bind()
        .await
        .expect("endpoint should bind");
    let original = endpoint
        .task
        .lock()
        .expect("endpoint task lock")
        .take()
        .expect("running node task");
    original.abort();
    let _ = original.await;
    drop(
        endpoint
            .shutdown_tx
            .lock()
            .expect("endpoint shutdown lock")
            .take(),
    );

    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    let (stopped_tx, stopped_rx) = oneshot::channel();
    *endpoint.shutdown_tx.lock().expect("endpoint shutdown lock") = Some(shutdown_tx);
    *endpoint.task.lock().expect("endpoint task lock") = Some(tokio::spawn(async move {
        let _ = shutdown_rx.await;
        let _ = stopped_tx.send(());
        Ok(())
    }));

    drop(endpoint);
    tokio::time::timeout(Duration::from_secs(1), stopped_rx)
        .await
        .expect("detached node task receives graceful shutdown")
        .expect("detached node task reports stop");
}

#[tokio::test]
async fn endpoint_rejects_external_nostr_event_when_discovery_is_disabled() {
    let endpoint = FipsEndpoint::builder()
        .without_system_tun()
        .bind()
        .await
        .expect("endpoint should bind");
    let event = nostr::EventBuilder::text_note("not a discovery event")
        .sign_with_keys(&nostr::Keys::generate())
        .expect("signed event");

    assert!(
        !endpoint
            .ingest_nostr_discovery_event(event)
            .await
            .expect("ingest command should complete")
    );
    endpoint.shutdown().await.expect("shutdown should succeed");
}

#[tokio::test]
async fn external_peerfinding_endpoint_starts_without_advert_relays() {
    let mut config = Config::new();
    config.node.discovery.nostr.enabled = true;
    config.node.discovery.nostr.peerfinding_source =
        crate::config::NostrPeerfindingSource::External;
    config.node.discovery.nostr.advert_relays.clear();
    let endpoint = FipsEndpoint::builder()
        .config(config)
        .without_system_tun()
        .bind()
        .await
        .expect("external peerfinding endpoint should not need relay sockets");

    assert!(
        endpoint
            .local_nostr_discovery_advert_event()
            .await
            .expect("local advert snapshot")
            .is_none()
    );
    assert!(
        endpoint
            .relay_statuses()
            .await
            .expect("relay snapshot")
            .is_empty()
    );
    endpoint.shutdown().await.expect("endpoint shutdown");
}

#[tokio::test]
async fn external_peerfinding_endpoint_exports_signal_without_existing_route() {
    use nostr::nips::nip19::ToBech32;
    use nostr::{EventBuilder, Kind, Tag, TagKind, Timestamp};

    let local = nostr::Keys::generate();
    let remote = nostr::Keys::generate();
    let remote_npub = remote.public_key().to_bech32().expect("remote npub");
    let mut config = Config::new();
    config.node.discovery.nostr.enabled = true;
    config.node.discovery.nostr.advertise = false;
    config.node.discovery.nostr.peerfinding_source =
        crate::config::NostrPeerfindingSource::External;
    config.node.discovery.nostr.share_local_candidates = true;
    config.node.discovery.nostr.stun_servers = vec!["stun:127.0.0.1:9".to_string()];
    config.node.discovery.nostr.signal_ttl_secs = 5;
    config.node.discovery.nostr.attempt_timeout_secs = 5;
    config.transports.udp = crate::config::TransportInstances::Single(crate::config::UdpConfig {
        bind_addr: Some("0.0.0.0:0".to_string()),
        accept_connections: Some(true),
        ..Default::default()
    });
    config
        .peers
        .push(crate::config::PeerConfig::new(&remote_npub, "udp", "nat"));
    let endpoint = FipsEndpoint::builder()
        .config(config)
        .identity_nsec(local.secret_key().to_bech32().expect("local nsec"))
        .without_system_tun()
        .bind()
        .await
        .expect("bind external peerfinding endpoint");
    let advert = EventBuilder::new(
        Kind::Custom(crate::discovery::nostr::ADVERT_KIND),
        serde_json::json!({
            "identifier": "fips-overlay-v1",
            "version": 1,
            "endpoints": [{"transport": "udp", "addr": "nat"}],
            "stunServers": ["stun:127.0.0.1:9"],
        })
        .to_string(),
    )
    .tags([
        Tag::identifier("fips-overlay-v1"),
        Tag::custom(TagKind::custom("protocol"), ["fips-overlay-v1".to_string()]),
        Tag::custom(TagKind::custom("version"), ["1".to_string()]),
        Tag::expiration(Timestamp::from(
            Timestamp::now().as_secs().saturating_add(3_600),
        )),
    ])
    .sign_with_keys(&remote)
    .expect("signed remote advert");
    assert!(
        endpoint
            .ingest_nostr_discovery_event(advert)
            .await
            .expect("ingest remote advert")
    );

    let remote_identity = PeerIdentity::from_npub(&remote_npub).expect("remote identity");
    tokio::time::timeout(Duration::from_secs(8), async {
        loop {
            let _ = endpoint
                .refresh_peer_paths(vec![remote_identity])
                .await
                .expect("refresh remote path");
            let events = endpoint
                .drain_nostr_traversal_signal_events()
                .await
                .expect("drain signals");
            if events.iter().any(|event| {
                event.kind == Kind::Custom(crate::discovery::nostr::SIGNAL_KIND)
                    && event
                        .tags
                        .public_keys()
                        .any(|pubkey| *pubkey == remote.public_key())
            }) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await
    .expect("external traversal offer is exported without a FIPS route");

    endpoint.shutdown().await.expect("endpoint shutdown");
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

    let messages = recv_endpoint_batch(&endpoint, 2, "messages should arrive").await;
    assert_eq!(messages.len(), 2);
    let first = &messages[0];
    let second = &messages[1];
    assert_eq!(first.source_peer.node_addr(), endpoint.node_addr());
    assert_eq!(first.source_peer.npub(), endpoint.npub());
    assert_eq!(first.data.as_slice(), &b"ping"[..]);
    assert_eq!(second.source_peer.node_addr(), endpoint.node_addr());
    assert_eq!(second.source_peer.npub(), endpoint.npub());
    assert_eq!(second.data.as_slice(), &b"pong"[..]);

    endpoint.shutdown().await.expect("shutdown should succeed");
}

#[tokio::test]
async fn registered_service_loopback_request_reply_preserves_ports_and_endpoint_data() {
    const SERVICE_PORT: u16 = 7368;
    let endpoint = FipsEndpoint::builder()
        .without_system_tun()
        .bind()
        .await
        .expect("endpoint should bind");
    endpoint
        .register_service(SERVICE_PORT)
        .await
        .expect("service should register");

    let duplicate = endpoint
        .register_service(SERVICE_PORT)
        .await
        .expect_err("duplicate registration should fail");
    assert!(matches!(
        duplicate,
        FipsEndpointError::ServicePortAlreadyRegistered { port: SERVICE_PORT }
    ));
    let reserved = endpoint
        .register_service(crate::node::session_wire::FSP_PORT_IPV6_SHIM)
        .await
        .expect_err("IPv6 shim port should stay reserved");
    assert!(matches!(
        reserved,
        FipsEndpointError::ServicePortReserved {
            port: crate::node::session_wire::FSP_PORT_IPV6_SHIM
        }
    ));

    let local = PeerIdentity::from_npub(endpoint.npub()).expect("local peer identity");
    endpoint
        .send_datagram(local, 41_000, SERVICE_PORT, b"REQ".to_vec())
        .await
        .expect("service request should send");
    let request = recv_service_batch(&endpoint, 8, "request should arrive").await;
    assert_eq!(request.len(), 1);
    assert_eq!(request[0].source_peer.node_addr(), local.node_addr());
    assert_eq!(request[0].source_peer.npub(), local.npub());
    assert_eq!(request[0].source_port, 41_000);
    assert_eq!(request[0].destination_port, SERVICE_PORT);
    assert_eq!(request[0].data.as_slice(), b"REQ");

    endpoint
        .send_datagram(
            local,
            SERVICE_PORT,
            request[0].source_port,
            b"EVENT".to_vec(),
        )
        .await
        .expect("service reply should send");
    endpoint
        .register_service(41_000)
        .await
        .expect("request source port should register");
    endpoint
        .send_datagram_batch_to_peer(
            local,
            vec![
                FipsEndpointOutboundDatagram::new(SERVICE_PORT, 41_000, b"EVENT-1".to_vec()),
                FipsEndpointOutboundDatagram::new(SERVICE_PORT, 41_000, b"EVENT-2".to_vec()),
            ],
        )
        .await
        .expect("registered reply batch should send");
    let reply = recv_service_batch(&endpoint, 1, "first reply should arrive").await;
    assert_eq!(reply.len(), 1);
    assert_eq!(reply[0].source_peer.node_addr(), local.node_addr());
    assert_eq!(reply[0].source_peer.npub(), local.npub());
    assert_eq!(reply[0].source_port, SERVICE_PORT);
    assert_eq!(reply[0].destination_port, 41_000);
    assert_eq!(reply[0].data.as_slice(), b"EVENT-1");
    let reply_tail = recv_service_batch(&endpoint, 8, "second reply should arrive").await;
    assert_eq!(reply_tail.len(), 1);
    assert_eq!(reply_tail[0].data.as_slice(), b"EVENT-2");

    endpoint
        .send_batch_to_peer(local, vec![b"legacy-endpoint".to_vec()])
        .await
        .expect("legacy endpoint data should still send");
    let endpoint_messages = recv_endpoint_batch(&endpoint, 1, "endpoint data should arrive").await;
    assert_eq!(endpoint_messages[0].data.as_slice(), b"legacy-endpoint");

    endpoint.shutdown().await.expect("shutdown should succeed");
}

#[tokio::test]
async fn registered_service_receivers_isolate_destination_ports() {
    const JOIN_PORT: u16 = 7368;
    const MESH_PORT: u16 = 7369;
    let endpoint = FipsEndpoint::builder()
        .without_system_tun()
        .bind()
        .await
        .expect("endpoint should bind");
    let join_receiver = endpoint
        .register_service_receiver(JOIN_PORT)
        .await
        .expect("join service should register");
    let mesh_receiver = endpoint
        .register_service_receiver(MESH_PORT)
        .await
        .expect("mesh service should register");

    let local = PeerIdentity::from_npub(endpoint.npub()).expect("local peer identity");
    endpoint
        .send_datagram_batch_to_peer(
            local,
            vec![
                FipsEndpointOutboundDatagram::new(41_000, MESH_PORT, b"mesh".to_vec()),
                FipsEndpointOutboundDatagram::new(41_001, JOIN_PORT, b"join".to_vec()),
            ],
        )
        .await
        .expect("interleaved services should send");

    let mut join = Vec::new();
    tokio::time::timeout(
        Duration::from_secs(1),
        join_receiver.recv_batch_into(&mut join, 8),
    )
    .await
    .expect("join receive should not time out")
    .expect("join datagram should arrive");
    assert_eq!(join.len(), 1);
    assert_eq!(join[0].destination_port, JOIN_PORT);
    assert_eq!(join[0].data.as_slice(), b"join");

    let mut mesh = Vec::new();
    tokio::time::timeout(
        Duration::from_secs(1),
        mesh_receiver.recv_batch_into(&mut mesh, 8),
    )
    .await
    .expect("mesh receive should not time out")
    .expect("mesh datagram should arrive");
    assert_eq!(mesh.len(), 1);
    assert_eq!(mesh[0].destination_port, MESH_PORT);
    assert_eq!(mesh[0].data.as_slice(), b"mesh");

    endpoint.shutdown().await.expect("shutdown should succeed");
}

#[tokio::test]
async fn endpoint_send_batch_rejects_oversize_payload() {
    let endpoint = FipsEndpoint::builder()
        .without_system_tun()
        .bind()
        .await
        .expect("endpoint should bind");

    let local = PeerIdentity::from_npub(endpoint.npub()).expect("local peer identity");
    let max = crate::node::session_wire::fsp_endpoint_data_max_body_len();
    let error = endpoint
        .send_batch_to_peer(local, vec![b"ok".to_vec(), vec![0; max + 1]])
        .await
        .expect_err("oversize endpoint payload should fail explicitly");
    assert!(matches!(
        error,
        FipsEndpointError::EndpointDataTooLarge { len, max: error_max }
            if len == max + 1 && error_max == max
    ));

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

    let mut messages = Vec::new();
    let received = tokio::time::timeout(
        Duration::from_secs(1),
        endpoint.recv_batch_into(&mut messages, 2),
    )
    .await
    .expect("recv batch should not time out")
    .expect("messages should arrive");
    assert_eq!(received, 2);
    assert_eq!(messages.len(), 2);
    assert!(
        messages
            .iter()
            .all(|message| message.source_peer.node_addr() == endpoint.node_addr())
    );
    assert_eq!(messages[0].data.as_slice(), &b"first"[..]);
    assert_eq!(messages[1].data.as_slice(), &b"second"[..]);

    let messages = recv_endpoint_batch(&endpoint, 8, "message should arrive").await;
    assert_eq!(messages.len(), 1);
    assert_eq!(messages[0].data.as_slice(), &b"third"[..]);

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
    assert_eq!(messages[0].data.as_slice(), &b"first"[..]);
    assert_eq!(messages[1].data.as_slice(), &b"second"[..]);

    let received = tokio::time::timeout(
        Duration::from_secs(1),
        endpoint.recv_batch_into(&mut messages, 8),
    )
    .await
    .expect("recv batch should not time out")
    .expect("message should arrive");
    assert_eq!(received, 1);
    assert_eq!(messages.capacity(), capacity);
    assert_eq!(messages[0].data.as_slice(), &b"third"[..]);

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
        .send(NodeEndpointEvent {
            messages: vec![
                endpoint_delivery(local, b"first".to_vec()),
                endpoint_delivery(local, b"second".to_vec()),
                endpoint_delivery(local, b"third".to_vec()),
            ],
            queued_at: crate::perf_profile::stamp(),
        })
        .expect("inject internal batch");
    endpoint
        .inbound_endpoint_tx
        .send(one_message_endpoint_event(local, b"fourth".to_vec()))
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
    assert_eq!(messages[0].data.as_slice(), &b"first"[..]);
    assert_eq!(messages[1].data.as_slice(), &b"second"[..]);

    let received = tokio::time::timeout(
        Duration::from_secs(1),
        endpoint.recv_batch_into(&mut messages, 8),
    )
    .await
    .expect("recv batch should not time out")
    .expect("messages should arrive");
    assert_eq!(received, 2);
    assert_eq!(messages[0].data.as_slice(), &b"third"[..]);
    assert_eq!(messages[1].data.as_slice(), &b"fourth"[..]);

    endpoint.shutdown().await.expect("shutdown should succeed");
}

#[tokio::test]
async fn recv_batch_into_preserves_pending_batch_tail_fifo() {
    let endpoint = FipsEndpoint::builder()
        .without_system_tun()
        .bind()
        .await
        .expect("endpoint should bind");
    let local = PeerIdentity::from_npub(endpoint.npub()).expect("local peer identity");

    endpoint
        .inbound_endpoint_tx
        .send(NodeEndpointEvent {
            messages: vec![
                endpoint_delivery(local, vec![0xaa; ENDPOINT_EVENT_TEST_PAYLOAD_LEN + 1]),
                endpoint_delivery(local, vec![0xbb; ENDPOINT_EVENT_TEST_PAYLOAD_LEN + 2]),
            ],
            queued_at: crate::perf_profile::stamp(),
        })
        .expect("inject internal batch");

    let mut messages = Vec::with_capacity(8);
    let received = tokio::time::timeout(
        Duration::from_secs(1),
        endpoint.recv_batch_into(&mut messages, 1),
    )
    .await
    .expect("recv batch should not time out")
    .expect("message should arrive");
    assert_eq!(received, 1);
    assert_eq!(messages[0].data.as_slice()[0], 0xaa);

    endpoint
        .inbound_endpoint_tx
        .send(one_message_endpoint_event(local, vec![0x11; 32]))
        .expect("inject small follow-on");

    let received = tokio::time::timeout(
        Duration::from_secs(1),
        endpoint.recv_batch_into(&mut messages, 8),
    )
    .await
    .expect("recv batch should not time out")
    .expect("messages should arrive");
    assert_eq!(received, 2);
    assert_eq!(messages[0].data.as_slice()[0], 0xbb);
    assert_eq!(messages[1].data.as_slice()[0], 0x11);

    endpoint.shutdown().await.expect("shutdown should succeed");
}

#[tokio::test]
async fn recv_batch_into_releases_endpoint_event_credit_per_public_message() {
    let endpoint = FipsEndpoint::builder()
        .without_system_tun()
        .bind()
        .await
        .expect("endpoint should bind");
    let local = PeerIdentity::from_npub(endpoint.npub()).expect("local peer identity");

    endpoint
        .inbound_endpoint_tx
        .send(NodeEndpointEvent {
            messages: vec![
                endpoint_delivery(local, b"first".to_vec()),
                endpoint_delivery(local, b"second".to_vec()),
                endpoint_delivery(local, b"third".to_vec()),
            ],
            queued_at: crate::perf_profile::stamp(),
        })
        .expect("inject internal batch");
    assert_eq!(endpoint.inbound_endpoint_tx.queued_messages(), 3);

    let mut messages = Vec::with_capacity(8);
    let received = tokio::time::timeout(
        Duration::from_secs(1),
        endpoint.recv_batch_into(&mut messages, 1),
    )
    .await
    .expect("recv batch should not time out")
    .expect("message should arrive");
    assert_eq!(received, 1);
    assert_eq!(messages[0].data.as_slice(), &b"first"[..]);
    assert_eq!(endpoint.inbound_endpoint_tx.queued_messages(), 2);

    let received = tokio::time::timeout(
        Duration::from_secs(1),
        endpoint.recv_batch_into(&mut messages, 8),
    )
    .await
    .expect("recv batch should not time out")
    .expect("pending messages should arrive");
    assert_eq!(received, 2);
    assert_eq!(messages[0].data.as_slice(), &b"second"[..]);
    assert_eq!(messages[1].data.as_slice(), &b"third"[..]);
    assert_eq!(endpoint.inbound_endpoint_tx.queued_messages(), 0);

    endpoint.shutdown().await.expect("shutdown should succeed");
}

#[tokio::test]
async fn blocking_recv_batch_into_preserves_pending_batch_tail_fifo() {
    let endpoint = FipsEndpoint::builder()
        .without_system_tun()
        .bind()
        .await
        .expect("endpoint should bind");
    let local = PeerIdentity::from_npub(endpoint.npub()).expect("local peer identity");

    endpoint
        .inbound_endpoint_tx
        .send(NodeEndpointEvent {
            messages: vec![
                endpoint_delivery(local, vec![0xaa; ENDPOINT_EVENT_TEST_PAYLOAD_LEN + 1]),
                endpoint_delivery(local, vec![0xbb; ENDPOINT_EVENT_TEST_PAYLOAD_LEN + 2]),
            ],
            queued_at: crate::perf_profile::stamp(),
        })
        .expect("inject internal batch");

    let event_tx = endpoint.inbound_endpoint_tx.clone();
    let endpoint = tokio::task::spawn_blocking(move || {
        let mut messages = Vec::with_capacity(8);
        let received = endpoint
            .blocking_recv_batch_into(&mut messages, 1)
            .expect("message should arrive");
        assert_eq!(received, 1);
        assert_eq!(messages[0].data.as_slice()[0], 0xaa);

        event_tx
            .send(one_message_endpoint_event(local, vec![0x11; 32]))
            .expect("inject small follow-on");

        let received = endpoint
            .blocking_recv_batch_into(&mut messages, 8)
            .expect("messages should arrive");
        assert_eq!(received, 2);
        assert_eq!(messages[0].data.as_slice()[0], 0xbb);
        assert_eq!(messages[1].data.as_slice()[0], 0x11);
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
        assert_eq!(messages[0].data.as_slice(), &b"first"[..]);
        assert_eq!(messages[1].data.as_slice(), &b"second"[..]);

        let received = endpoint
            .blocking_recv_batch_into(&mut messages, 8)
            .expect("message should arrive");
        assert_eq!(received, 1);
        assert_eq!(messages.capacity(), capacity);
        assert_eq!(messages[0].data.as_slice(), &b"third"[..]);

        (endpoint, capacity)
    })
    .await
    .expect("blocking receiver should join");
    assert_eq!(capacity, 8);

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
        .send(NodeEndpointEvent {
            messages: vec![
                endpoint_delivery(local, b"first".to_vec()),
                endpoint_delivery(local, b"second".to_vec()),
                endpoint_delivery(local, b"third".to_vec()),
            ],
            queued_at: crate::perf_profile::stamp(),
        })
        .expect("inject internal batch");
    endpoint
        .inbound_endpoint_tx
        .send(one_message_endpoint_event(local, b"fourth".to_vec()))
        .expect("inject follow-on message");

    let endpoint = tokio::task::spawn_blocking(move || {
        let mut messages = Vec::with_capacity(8);
        let received = endpoint
            .blocking_recv_batch_into(&mut messages, 2)
            .expect("messages should arrive");
        assert_eq!(received, 2);
        assert_eq!(messages[0].data.as_slice(), &b"first"[..]);
        assert_eq!(messages[1].data.as_slice(), &b"second"[..]);

        let received = endpoint
            .blocking_recv_batch_into(&mut messages, 8)
            .expect("messages should arrive");
        assert_eq!(received, 2);
        assert_eq!(messages[0].data.as_slice(), &b"third"[..]);
        assert_eq!(messages[1].data.as_slice(), &b"fourth"[..]);

        endpoint
    })
    .await
    .expect("blocking receiver should join");

    endpoint.shutdown().await.expect("shutdown should succeed");
}

#[tokio::test]
async fn blocking_send_batch_to_peer_loopback_endpoint_data_roundtrips() {
    let endpoint = FipsEndpoint::builder()
        .without_system_tun()
        .bind()
        .await
        .expect("endpoint should bind");

    let local = PeerIdentity::from_npub(endpoint.npub()).expect("local peer identity");
    endpoint
        .blocking_send_batch_to_peer(local, vec![b"ping".to_vec()])
        .expect("loopback send should succeed");
    let messages = recv_endpoint_batch(&endpoint, 1, "message should arrive").await;
    assert_eq!(messages[0].source_peer.node_addr(), endpoint.node_addr());
    assert_eq!(messages[0].source_peer.npub(), endpoint.npub());
    assert_eq!(messages[0].data.as_slice(), &b"ping"[..]);

    endpoint.shutdown().await.expect("shutdown should succeed");
}

#[tokio::test]
async fn local_capability_snapshot_connects_across_product_scopes() {
    const SERVICE_PORT: u16 = 39_018;
    let rendezvous_socket =
        std::net::UdpSocket::bind("127.0.0.1:0").expect("reserve local rendezvous address");
    let std::net::SocketAddr::V4(rendezvous_addr) = rendezvous_socket
        .local_addr()
        .expect("reserved local rendezvous address")
    else {
        panic!("reserved rendezvous address should be IPv4");
    };
    drop(rendezvous_socket);

    let mut config = Config::new();
    config.transports.udp = crate::config::TransportInstances::Single(UdpConfig {
        bind_addr: Some("127.0.0.1:0".to_string()),
        advertise_on_nostr: Some(false),
        ..UdpConfig::default()
    });
    config.node.discovery.nostr.enabled = true;
    config.node.discovery.nostr.peerfinding_source =
        crate::config::NostrPeerfindingSource::External;
    config.node.discovery.nostr.advert_relays.clear();
    config.node.discovery.lan.enabled = false;
    config.node.discovery.local.rendezvous_addr = rendezvous_addr;
    config.node.discovery.local.retry_interval_ms = 10;
    assert_eq!(
        config.node.discovery.nostr.policy,
        crate::config::NostrDiscoveryPolicy::ConfiguredOnly
    );

    let provider = FipsEndpoint::builder()
        .config(config.clone())
        .discovery_scope("iris-chat-device-sync-v1:account-a")
        .local_rendezvous()
        .without_system_tun()
        .bind()
        .await
        .expect("provider should bind");
    let provider_npub = provider.npub().to_string();
    let service = provider
        .register_service_receiver_with_capability(
            crate::discovery::local::LocalInstanceCapability::service(
                "hashtree.blob/1",
                SERVICE_PORT,
            ),
        )
        .await
        .expect("provider service should register");

    let mut consumer_config = config;
    let crate::config::TransportInstances::Single(consumer_udp) =
        &mut consumer_config.transports.udp
    else {
        panic!("single consumer UDP config");
    };
    consumer_udp.outbound_only = Some(true);
    consumer_udp.accept_connections = Some(false);
    let consumer = FipsEndpoint::builder()
        .local_rendezvous()
        .config(consumer_config)
        .discovery_scope("nostr-vpn:private-network")
        .without_system_tun()
        .bind()
        .await
        .expect("consumer should bind");

    let selected = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let provider_connected = consumer
                .peers()
                .await
                .expect("peer snapshot")
                .iter()
                .any(|peer| peer.npub == provider_npub && peer.connected);
            let adverts = consumer
                .local_instance_advertisements()
                .expect("local capability snapshot");
            if provider_connected
                && let Some(selected) =
                    crate::discovery::local::select_capability_provider(&adverts, "hashtree.blob/1")
            {
                break selected.clone();
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("same-host endpoints should connect without public open discovery");

    assert_eq!(selected.npub, provider_npub);
    assert_eq!(
        selected
            .capability("hashtree.blob/1")
            .and_then(|capability| capability.fsp_port),
        Some(SERVICE_PORT)
    );

    consumer
        .send_datagram(
            PeerIdentity::from_npub(&provider_npub).expect("provider identity"),
            40_000,
            SERVICE_PORT,
            b"GET".to_vec(),
        )
        .await
        .expect("same-host service request should send");
    let mut datagrams = Vec::new();
    tokio::time::timeout(
        Duration::from_secs(5),
        service.recv_batch_into(&mut datagrams, 8),
    )
    .await
    .expect("same-host service receive should not time out")
    .expect("same-host service receiver should stay open");
    assert_eq!(datagrams[0].source_peer.npub(), consumer.npub());
    assert_eq!(datagrams[0].data.as_slice(), b"GET");

    consumer.shutdown().await.expect("consumer shutdown");
    provider.shutdown().await.expect("provider shutdown");
}
