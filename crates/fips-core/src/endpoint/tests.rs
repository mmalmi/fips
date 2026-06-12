use super::*;
use crate::node::{EndpointDataDelivery, NodeEndpointPeer};
use std::time::Duration;

fn ipv6_tcp_packet(flags: u8, tcp_payload_len: usize) -> Vec<u8> {
    let tcp_len = 20 + tcp_payload_len;
    let mut packet = vec![0u8; 40 + tcp_len];
    packet[0] = 0x60;
    packet[4..6].copy_from_slice(&(tcp_len as u16).to_be_bytes());
    packet[6] = 6;
    packet[40 + 12] = 5 << 4;
    packet[40 + 13] = flags;
    packet
}

fn ipv4_icmp_echo_packet() -> Vec<u8> {
    let mut packet = vec![0u8; 28];
    packet[0] = 0x45;
    packet[2..4].copy_from_slice(&28u16.to_be_bytes());
    packet[9] = 1;
    packet[20] = 8;
    packet
}

#[test]
fn endpoint_peer_conversion_preserves_rekey_state() {
    let peer = FipsEndpointPeer::from(NodeEndpointPeer {
        npub: "npub1peer".to_string(),
        node_addr: NodeAddr::from_bytes([7; 16]),
        connected: true,
        transport_addr: Some("127.0.0.1:9000".to_string()),
        transport_type: Some("udp".to_string()),
        link_id: 7,
        srtt_ms: Some(12),
        srtt_age_ms: Some(34),
        packets_sent: 3,
        packets_recv: 4,
        bytes_sent: 120,
        bytes_recv: 240,
        rekey_in_progress: true,
        rekey_draining: true,
        current_k_bit: Some(true),
        direct_probe_pending: false,
        direct_probe_after_ms: None,
        direct_probe_retry_count: 0,
        direct_probe_auto_reconnect: false,
        direct_probe_expires_at_ms: None,
        nostr_traversal_consecutive_failures: 2,
        nostr_traversal_in_cooldown: true,
        nostr_traversal_cooldown_until_ms: Some(1_234),
        nostr_traversal_last_observed_skew_ms: Some(-42),
    });

    assert!(peer.rekey_in_progress);
    assert!(peer.rekey_draining);
    assert_eq!(peer.current_k_bit, Some(true));
    assert_eq!(peer.srtt_ms, Some(12));
    assert_eq!(peer.srtt_age_ms, Some(34));
    assert_eq!(peer.nostr_traversal_consecutive_failures, 2);
    assert!(peer.nostr_traversal_in_cooldown);
    assert_eq!(peer.nostr_traversal_cooldown_until_ms, Some(1_234));
    assert_eq!(peer.nostr_traversal_last_observed_skew_ms, Some(-42));
}

#[test]
fn endpoint_command_tx_helper_classifies_priority_and_bulk_payloads() {
    let (priority_tx, _priority_rx) = mpsc::channel(1);
    let (bulk_tx, _bulk_rx) = mpsc::channel(1);
    let remote = PeerIdentity::from_pubkey_full(crate::Identity::generate().pubkey_full());

    let tcp_ack = ipv6_tcp_packet(0x10, 0);
    let tcp_ack = NodeEndpointCommand::send_oneway(remote, tcp_ack, None);
    assert!(std::ptr::eq(
        endpoint_command_tx_for_command(&tcp_ack, &priority_tx, &bulk_tx),
        &priority_tx,
    ));

    let icmpv4_ping = ipv4_icmp_echo_packet();
    let icmpv4_ping = NodeEndpointCommand::send_oneway(remote, icmpv4_ping, None);
    assert!(std::ptr::eq(
        endpoint_command_tx_for_command(&icmpv4_ping, &priority_tx, &bulk_tx),
        &priority_tx,
    ));

    let bulk_tcp_data = ipv6_tcp_packet(0x18, 512);
    let bulk_tcp_data = NodeEndpointCommand::send_oneway(remote, bulk_tcp_data, None);
    assert!(std::ptr::eq(
        endpoint_command_tx_for_command(&bulk_tcp_data, &priority_tx, &bulk_tx),
        &bulk_tx,
    ));
}

#[test]
fn endpoint_command_owns_lane_selected_at_construction() {
    let (priority_tx, _priority_rx) = mpsc::channel(1);
    let (bulk_tx, _bulk_rx) = mpsc::channel(1);
    let remote = PeerIdentity::from_pubkey_full(crate::Identity::generate().pubkey_full());

    let tcp_ack = ipv6_tcp_packet(0x10, 0);
    let priority_command = NodeEndpointCommand::send_oneway(remote, tcp_ack, None);
    assert_eq!(priority_command.lane(), EndpointCommandLane::Priority);
    assert!(std::ptr::eq(
        endpoint_command_tx_for_command(&priority_command, &priority_tx, &bulk_tx),
        &priority_tx,
    ));

    let bulk_tcp_data = ipv6_tcp_packet(0x18, 512);
    let bulk_command = NodeEndpointCommand::send_oneway(remote, bulk_tcp_data, None);
    assert_eq!(bulk_command.lane(), EndpointCommandLane::Bulk);
    assert!(std::ptr::eq(
        endpoint_command_tx_for_command(&bulk_command, &priority_tx, &bulk_tx),
        &bulk_tx,
    ));

    let batch_payload = crate::node::EndpointDataPayload::new(ipv6_tcp_packet(0x18, 512));
    let batch_command = NodeEndpointCommand::send_batch_oneway(
        remote,
        vec![batch_payload],
        None,
        EndpointCommandLane::Bulk,
    )
    .expect("non-empty batch command");
    assert_eq!(batch_command.lane(), EndpointCommandLane::Bulk);
    assert!(std::ptr::eq(
        endpoint_command_tx_for_command(&batch_command, &priority_tx, &bulk_tx),
        &bulk_tx,
    ));
}

#[test]
fn endpoint_command_owns_discard_policy_selected_at_construction() {
    let remote = PeerIdentity::from_pubkey_full(crate::Identity::generate().pubkey_full());

    let priority_command = NodeEndpointCommand::send_oneway(remote, ipv6_tcp_packet(0x10, 0), None);
    assert_eq!(priority_command.lane(), EndpointCommandLane::Priority);
    assert!(!priority_command.drop_on_backpressure());

    let reliable_bulk = NodeEndpointCommand::send_oneway(remote, ipv6_tcp_packet(0x18, 512), None);
    assert_eq!(reliable_bulk.lane(), EndpointCommandLane::Bulk);
    assert!(!reliable_bulk.drop_on_backpressure());

    let discardable_bulk = NodeEndpointCommand::send_oneway(remote, vec![0, 1, 2, 3], None);
    assert_eq!(discardable_bulk.lane(), EndpointCommandLane::Bulk);
    assert!(discardable_bulk.drop_on_backpressure());

    let reliable_batch = NodeEndpointCommand::send_batch_oneway(
        remote,
        vec![
            crate::node::EndpointDataPayload::new(ipv6_tcp_packet(0x18, 512)),
            crate::node::EndpointDataPayload::new(vec![0, 1, 2, 3]),
        ],
        None,
        EndpointCommandLane::Bulk,
    )
    .expect("mixed bulk batch command");
    assert_eq!(reliable_batch.lane(), EndpointCommandLane::Bulk);
    assert!(!reliable_batch.drop_on_backpressure());

    let discardable_batch = NodeEndpointCommand::send_batch_oneway(
        remote,
        vec![
            crate::node::EndpointDataPayload::new(vec![0, 1, 2, 3]),
            crate::node::EndpointDataPayload::new(vec![4, 5, 6, 7]),
        ],
        None,
        EndpointCommandLane::Bulk,
    )
    .expect("discardable bulk batch command");
    assert_eq!(discardable_batch.lane(), EndpointCommandLane::Bulk);
    assert!(discardable_batch.drop_on_backpressure());
}

#[tokio::test]
async fn endpoint_command_enqueue_drops_only_discardable_bulk_when_full() {
    let (priority_tx, _priority_rx) = mpsc::channel(1);
    let (bulk_tx, mut bulk_rx) = mpsc::channel(1);
    let remote = PeerIdentity::from_pubkey_full(crate::Identity::generate().pubkey_full());

    let queued_discardable = NodeEndpointCommand::send_oneway(remote, vec![0, 1, 2, 3], None);
    assert!(queued_discardable.drop_on_backpressure());
    bulk_tx
        .try_send(queued_discardable)
        .expect("bulk queue should accept the first command");

    let dropped_discardable = NodeEndpointCommand::send_oneway(remote, vec![4, 5, 6, 7], None);
    assert!(dropped_discardable.drop_on_backpressure());
    send_endpoint_command(dropped_discardable, &priority_tx, &bulk_tx)
        .await
        .expect("discardable bulk should be accepted as dropped");

    let first = bulk_rx
        .try_recv()
        .expect("only the first command should remain queued");
    assert!(first.drop_on_backpressure());
    assert!(matches!(
        bulk_rx.try_recv(),
        Err(mpsc::error::TryRecvError::Empty)
    ));

    let queued_reliable =
        NodeEndpointCommand::send_oneway(remote, ipv6_tcp_packet(0x18, 512), None);
    assert!(!queued_reliable.drop_on_backpressure());
    bulk_tx
        .try_send(queued_reliable)
        .expect("bulk queue should accept the reliable fill command");

    let waiting_reliable =
        NodeEndpointCommand::send_oneway(remote, ipv6_tcp_packet(0x18, 512), None);
    assert!(!waiting_reliable.drop_on_backpressure());
    let send_fut = send_endpoint_command(waiting_reliable, &priority_tx, &bulk_tx);
    tokio::pin!(send_fut);

    tokio::select! {
        result = &mut send_fut => panic!("reliable bulk must not be dropped: {result:?}"),
        _ = tokio::time::sleep(Duration::from_millis(20)) => {}
    }

    let first = bulk_rx
        .try_recv()
        .expect("free one bulk slot for the waiting reliable command");
    assert!(!first.drop_on_backpressure());

    tokio::time::timeout(Duration::from_secs(1), send_fut)
        .await
        .expect("reliable bulk send should complete once space is available")
        .expect("reliable bulk enqueue should succeed");

    let second = bulk_rx
        .try_recv()
        .expect("reliable command should enqueue after space is available");
    assert!(!second.drop_on_backpressure());
}

#[test]
fn endpoint_send_command_owns_payload_lane_and_queue_stamp() {
    let remote = PeerIdentity::from_pubkey_full(crate::Identity::generate().pubkey_full());
    let payload = ipv6_tcp_packet(0x18, 512);
    let queued_at = Some(crate::perf_profile::test_stamp());

    let command = crate::node::EndpointSendCommand::new(remote, payload.clone(), queued_at);
    assert_eq!(command.lane(), EndpointCommandLane::Bulk);

    let (owned_send, owned_queued_at) = command.into_parts();
    assert_eq!(owned_send.dest_addr(), *remote.node_addr());
    assert_eq!(owned_send.dest_pubkey(), remote.pubkey_full());
    assert_eq!(owned_send.payload().as_slice(), payload.as_slice());
    assert_eq!(owned_send.payload().lane(), EndpointCommandLane::Bulk);
    assert_eq!(owned_queued_at, queued_at);
}

#[test]
fn endpoint_data_payload_owns_drop_policy_selected_at_construction() {
    let tcp_ack = crate::node::EndpointDataPayload::new(ipv6_tcp_packet(0x10, 0));
    assert_eq!(tcp_ack.lane(), EndpointCommandLane::Priority);
    assert!(!tcp_ack.drop_on_backpressure());

    let tcp_bulk = crate::node::EndpointDataPayload::new(ipv6_tcp_packet(0x18, 512));
    assert_eq!(tcp_bulk.lane(), EndpointCommandLane::Bulk);
    assert!(!tcp_bulk.drop_on_backpressure());

    let opaque_bulk = crate::node::EndpointDataPayload::new(vec![0, 1, 2, 3]);
    assert_eq!(opaque_bulk.lane(), EndpointCommandLane::Bulk);
    assert!(opaque_bulk.drop_on_backpressure());
}

#[test]
fn endpoint_payload_lane_batches_keep_same_lane_runs_single() {
    let bulk_tcp = ipv6_tcp_packet(0x18, 512);
    let opaque_bulk = vec![0, 1, 2, 3];
    match endpoint_payload_lane_batches(
        vec![bulk_tcp.clone(), opaque_bulk.clone()]
            .into_iter()
            .map(FipsEndpointPayload::new)
            .collect(),
    ) {
        EndpointPayloadLaneBatches::Single { lane, payloads } => {
            assert_eq!(lane, EndpointCommandLane::Bulk);
            assert_eq!(payloads.len(), 2);
            assert_eq!(payloads[0].as_slice(), bulk_tcp.as_slice());
            assert_eq!(payloads[1].as_slice(), opaque_bulk.as_slice());
        }
        other => panic!("expected a single bulk run, got {other:?}"),
    }

    let tcp_ack = ipv6_tcp_packet(0x10, 0);
    let icmp_ping = ipv4_icmp_echo_packet();
    match endpoint_payload_lane_batches(
        vec![tcp_ack.clone(), icmp_ping.clone()]
            .into_iter()
            .map(FipsEndpointPayload::new)
            .collect(),
    ) {
        EndpointPayloadLaneBatches::Single { lane, payloads } => {
            assert_eq!(lane, EndpointCommandLane::Priority);
            assert_eq!(payloads.len(), 2);
            assert_eq!(payloads[0].as_slice(), tcp_ack.as_slice());
            assert_eq!(payloads[1].as_slice(), icmp_ping.as_slice());
        }
        other => panic!("expected a single priority run, got {other:?}"),
    }
}

#[test]
fn endpoint_payload_lane_batches_split_mixed_payloads_by_lane() {
    let bulk_first = ipv6_tcp_packet(0x18, 512);
    let priority_first = ipv6_tcp_packet(0x10, 0);
    let bulk_second = vec![0, 1, 2, 3];
    let priority_second = ipv4_icmp_echo_packet();

    match endpoint_payload_lane_batches(
        vec![
            bulk_first.clone(),
            priority_first.clone(),
            bulk_second.clone(),
            priority_second.clone(),
        ]
        .into_iter()
        .map(FipsEndpointPayload::new)
        .collect(),
    ) {
        EndpointPayloadLaneBatches::Split {
            priority_payloads,
            bulk_payloads,
        } => {
            assert_eq!(priority_payloads.len(), 2);
            assert_eq!(priority_payloads[0].as_slice(), priority_first.as_slice());
            assert_eq!(priority_payloads[1].as_slice(), priority_second.as_slice());
            assert_eq!(bulk_payloads.len(), 2);
            assert_eq!(bulk_payloads[0].as_slice(), bulk_first.as_slice());
            assert_eq!(bulk_payloads[1].as_slice(), bulk_second.as_slice());
        }
        other => panic!("expected split priority/bulk runs, got {other:?}"),
    }
}

#[test]
fn endpoint_payload_lane_batches_accept_empty_batches() {
    match endpoint_payload_lane_batches(Vec::new()) {
        EndpointPayloadLaneBatches::Empty => {}
        other => panic!("expected empty batch, got {other:?}"),
    }
}

#[test]
fn classified_endpoint_payload_preserves_supplied_class() {
    let priority_class = crate::node::classify_endpoint_payload(&ipv6_tcp_packet(0x10, 0));
    let opaque_bytes = vec![0, 1, 2, 3];
    let payload = FipsEndpointPayload::from_classified(opaque_bytes.clone(), priority_class);
    let endpoint_payload = EndpointDataPayload::from(payload.clone());

    assert_eq!(payload.as_slice(), opaque_bytes.as_slice());
    assert_eq!(endpoint_payload.lane(), EndpointCommandLane::Priority);
    assert!(!endpoint_payload.drop_on_backpressure());
}

#[test]
fn endpoint_data_send_owns_remote_identity_and_payload_policy() {
    let remote = PeerIdentity::from_pubkey_full(crate::Identity::generate().pubkey_full());
    let payload = crate::node::EndpointDataPayload::new(ipv6_tcp_packet(0x18, 512));

    let send = crate::node::EndpointDataSend::new(remote, payload.clone());
    assert_eq!(send.dest_addr(), *remote.node_addr());
    assert_eq!(send.dest_pubkey(), remote.pubkey_full());
    assert_eq!(send.payload().lane(), EndpointCommandLane::Bulk);
    assert!(!send.payload().drop_on_backpressure());
    assert_eq!(send.payload().as_slice(), payload.as_slice());
}

mod runtime;

#[test]
fn discovery_scope_enables_default_scoped_udp_discovery() {
    let config = FipsEndpoint::builder()
        .discovery_scope("nostr-vpn:test")
        .prepared_config();

    assert!(!config.tun.enabled);
    assert!(!config.dns.enabled);
    assert!(!config.node.system_files_enabled);
    assert!(config.node.discovery.nostr.enabled);
    assert!(config.node.discovery.nostr.advertise);
    assert_eq!(
        config.node.discovery.nostr.policy,
        NostrDiscoveryPolicy::Open
    );
    assert!(config.node.discovery.nostr.share_local_candidates);
    assert_eq!(config.node.discovery.nostr.app, "nostr-vpn:test");
    assert_eq!(
        config.node.discovery.lan.scope.as_deref(),
        Some("nostr-vpn:test")
    );
    assert!(config.node.discovery.local.enabled);

    let udp = match config.transports.udp {
        TransportInstances::Single(udp) => udp,
        TransportInstances::Named(_) => panic!("expected a default UDP transport"),
    };
    assert_eq!(udp.bind_addr(), "0.0.0.0:0");
    assert!(udp.advertise_on_nostr());
    assert!(!udp.is_public());
    assert!(!udp.outbound_only());
    assert!(udp.accept_connections());
}

#[test]
fn local_ethernet_adds_scoped_discovery_transport() {
    let config = FipsEndpoint::builder()
        .discovery_scope("iris-chat:host")
        .local_ethernet("fips-app0")
        .prepared_config();

    assert!(config.node.discovery.nostr.enabled);
    assert_eq!(
        config.node.discovery.lan.scope.as_deref(),
        Some("iris-chat:host")
    );

    let eth = match config.transports.ethernet {
        TransportInstances::Single(eth) => eth,
        TransportInstances::Named(_) => panic!("expected a single Ethernet transport"),
    };
    assert_eq!(eth.interface, "fips-app0");
    assert!(eth.discovery());
    assert!(eth.announce());
    assert!(eth.auto_connect());
    assert!(eth.accept_connections());
    assert_eq!(eth.discovery_scope(), Some("iris-chat:host"));
}

#[test]
fn local_ethernet_preserves_existing_ethernet_config() {
    let mut explicit = Config::new();
    explicit.transports.ethernet = TransportInstances::Single(EthernetConfig {
        interface: "br-existing".to_string(),
        announce: Some(false),
        ..EthernetConfig::default()
    });

    let config = FipsEndpoint::builder()
        .config(explicit)
        .local_ethernet("fips-app0")
        .prepared_config();

    let TransportInstances::Named(map) = config.transports.ethernet else {
        panic!("expected named Ethernet transports");
    };
    assert!(map.contains_key("default"));
    let local = map
        .get("local-ethernet-fips-app0")
        .expect("local endpoint Ethernet transport");
    assert_eq!(local.interface, "fips-app0");
    assert!(local.announce());
    assert!(local.auto_connect());
    assert!(local.accept_connections());
}

#[test]
fn discovery_scope_preserves_explicit_connectivity_config() {
    let mut explicit = Config::new();
    explicit.node.discovery.nostr.enabled = true;
    explicit.node.discovery.nostr.app = "custom-app".to_string();
    explicit.node.discovery.nostr.policy = NostrDiscoveryPolicy::ConfiguredOnly;
    explicit.node.discovery.nostr.share_local_candidates = false;
    explicit.transports.udp = TransportInstances::Single(UdpConfig {
        bind_addr: Some("127.0.0.1:34567".to_string()),
        advertise_on_nostr: Some(false),
        outbound_only: Some(true),
        ..UdpConfig::default()
    });

    let config = FipsEndpoint::builder()
        .config(explicit)
        .discovery_scope("nostr-vpn:test")
        .prepared_config();

    assert_eq!(config.node.discovery.nostr.app, "custom-app");
    assert_eq!(
        config.node.discovery.nostr.policy,
        NostrDiscoveryPolicy::ConfiguredOnly
    );
    assert!(!config.node.discovery.nostr.share_local_candidates);
    assert_eq!(
        config.node.discovery.lan.scope.as_deref(),
        Some("nostr-vpn:test")
    );
    assert!(config.node.discovery.local.enabled);
    let udp = match config.transports.udp {
        TransportInstances::Single(udp) => udp,
        TransportInstances::Named(_) => panic!("expected explicit UDP transport"),
    };
    assert_eq!(udp.bind_addr.as_deref(), Some("127.0.0.1:34567"));
    assert_eq!(udp.bind_addr(), "0.0.0.0:0");
    assert!(!udp.advertise_on_nostr());
    assert!(udp.outbound_only());
}

#[tokio::test]
async fn invalid_remote_npub_is_rejected() {
    let endpoint = FipsEndpoint::builder()
        .without_system_tun()
        .bind()
        .await
        .expect("endpoint should bind");

    let error = endpoint
        .send("not-an-npub", b"hello".to_vec())
        .await
        .expect_err("invalid npub should fail");
    assert!(matches!(error, FipsEndpointError::InvalidRemoteNpub { .. }));

    endpoint.shutdown().await.expect("shutdown should succeed");
}

#[tokio::test]
async fn endpoint_peer_snapshot_starts_empty() {
    let endpoint = FipsEndpoint::builder()
        .without_system_tun()
        .bind()
        .await
        .expect("endpoint should bind");

    let peers = endpoint.peers().await.expect("peer snapshot");
    assert!(peers.is_empty());

    endpoint.shutdown().await.expect("shutdown should succeed");
}
