use super::*;
use crate::node::{
    EndpointDataDelivery, EndpointDataPayload, NodeEndpointDataBatch, NodeEndpointPeer,
};

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

fn endpoint_payload(payload: Vec<u8>) -> EndpointDataPayload {
    EndpointDataPayload::from_packet_payload(payload)
        .expect("test endpoint payload should fit FSP endpoint data")
}

fn endpoint_payloads(payloads: Vec<Vec<u8>>) -> Vec<EndpointDataPayload> {
    payloads.into_iter().map(endpoint_payload).collect()
}

fn endpoint_batch(remote: PeerIdentity, payloads: Vec<Vec<u8>>) -> NodeEndpointDataBatch {
    NodeEndpointDataBatch::from_payloads(remote, endpoint_payloads(payloads), None)
        .expect("non-empty endpoint data batch")
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
        last_outbound_route: Some("direct".to_string()),
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
    assert_eq!(peer.last_outbound_route.as_deref(), Some("direct"));
    assert_eq!(peer.srtt_ms, Some(12));
    assert_eq!(peer.srtt_age_ms, Some(34));
    assert_eq!(peer.nostr_traversal_consecutive_failures, 2);
    assert!(peer.nostr_traversal_in_cooldown);
    assert_eq!(peer.nostr_traversal_cooldown_until_ms, Some(1_234));
    assert_eq!(peer.nostr_traversal_last_observed_skew_ms, Some(-42));
}

#[test]
fn endpoint_data_batches_charge_drain_budget_by_small_packet_groups() {
    let remote = PeerIdentity::from_pubkey_full(crate::Identity::generate().pubkey_full());
    let bulk_payload = || ipv6_tcp_packet(0x18, 512);
    let payloads = |count: usize| (0..count).map(|_| bulk_payload()).collect::<Vec<_>>();

    let single = endpoint_batch(remote, vec![ipv6_tcp_packet(0x18, 512)]);
    assert_eq!(single.drain_cost(), 1);

    let batch_1 = endpoint_batch(remote, payloads(1));
    assert_eq!(batch_1.drain_cost(), 1);

    let batch_8 = endpoint_batch(remote, payloads(8));
    assert_eq!(batch_8.drain_cost(), 1);

    let batch_9 = endpoint_batch(remote, payloads(9));
    assert_eq!(batch_9.drain_cost(), 2);

    let full_batch = endpoint_batch(remote, payloads(ENDPOINT_DATA_BATCH_MAX));
    assert_eq!(ENDPOINT_DATA_BATCH_MAX, 128);
    assert_eq!(full_batch.drain_cost(), 16);
}

#[test]
fn endpoint_data_drop_accounting_counts_packets_not_drain_quanta() {
    let remote = PeerIdentity::from_pubkey_full(crate::Identity::generate().pubkey_full());
    let discardable_payload = || vec![0, 1, 2, 3];
    let payloads = (0..ENDPOINT_DATA_BATCH_MAX)
        .map(|_| discardable_payload())
        .collect::<Vec<_>>();
    let full_batch = endpoint_batch(remote, payloads);

    assert_eq!(full_batch.drain_cost(), 16);
    assert_eq!(full_batch.packet_count(), ENDPOINT_DATA_BATCH_MAX);
}

#[tokio::test]
async fn endpoint_data_batch_enqueue_drops_when_full() {
    let (batch_tx, mut batch_rx) = crate::node::endpoint_data_batch_channel(1);
    let remote = PeerIdentity::from_pubkey_full(crate::Identity::generate().pubkey_full());

    let queued_data = endpoint_batch(remote, vec![vec![0, 1, 2, 3]]);
    batch_tx
        .send_or_drop(queued_data)
        .map_err(|_| FipsEndpointError::Closed)
        .expect("first endpoint data batch should enqueue");

    let dropped_tcp = endpoint_batch(remote, vec![ipv6_tcp_packet(0x18, 512)]);
    batch_tx
        .send_or_drop(dropped_tcp)
        .map_err(|_| FipsEndpointError::Closed)
        .expect("endpoint data batch should be accepted as dropped");

    let first = batch_rx
        .try_recv()
        .expect("only the first batch should remain queued");
    assert!(matches!(
        batch_rx.try_recv(),
        Err(mpsc::error::TryRecvError::Empty)
    ));
    assert_eq!(first.packet_count(), 1);
}

#[tokio::test]
async fn endpoint_data_batch_lane_charges_batches_by_drain_cost() {
    let (batch_tx, mut batch_rx) = crate::node::endpoint_data_batch_channel(2);
    let remote = PeerIdentity::from_pubkey_full(crate::Identity::generate().pubkey_full());
    let payloads = (0..9)
        .map(|_| ipv6_tcp_packet(0x18, 512))
        .collect::<Vec<_>>();
    let batch = endpoint_batch(remote, payloads);
    assert_eq!(batch.drain_cost(), 2);

    batch_tx
        .send_or_drop(batch)
        .map_err(|_| FipsEndpointError::Closed)
        .expect("nine-packet batch should fill the two-quanta lane");
    batch_tx
        .send_or_drop(endpoint_batch(remote, vec![vec![8, 9, 10, 11]]))
        .map_err(|_| FipsEndpointError::Closed)
        .expect("overflowing endpoint data batch should be accepted as dropped");

    let first = batch_rx
        .try_recv()
        .expect("the two-quanta batch should remain queued");
    assert_eq!(first.packet_count(), 9);
    assert!(matches!(
        batch_rx.try_recv(),
        Err(mpsc::error::TryRecvError::Empty)
    ));
}

#[test]
fn endpoint_data_batch_owns_payload_bytes_and_queue_stamp() {
    let remote = PeerIdentity::from_pubkey_full(crate::Identity::generate().pubkey_full());
    let payload = ipv6_tcp_packet(0x18, 512);
    let queued_at = Some(crate::perf_profile::test_stamp());
    let enqueued_at_ms = 1_234;

    let batch = crate::node::NodeEndpointDataBatch::from_payloads_with_enqueued_at_ms(
        remote,
        vec![endpoint_payload(payload.clone())],
        queued_at,
        enqueued_at_ms,
    )
    .expect("one-packet endpoint data batch");

    let (owned_remote, owned_payloads, owned_queued_at, owned_enqueued_at_ms) = batch.into_parts();
    assert_eq!(owned_remote, remote);
    let owned_payloads = owned_payloads
        .into_iter()
        .map(|payload| payload.into_body().into_vec())
        .collect::<Vec<_>>();
    assert_eq!(owned_payloads, vec![payload]);
    assert_eq!(owned_queued_at, queued_at);
    assert_eq!(owned_enqueued_at_ms, enqueued_at_ms);
}

mod local_rendezvous;
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
fn local_rendezvous_enables_fixed_loopback_without_adding_transports() {
    let config = FipsEndpoint::builder().local_rendezvous().prepared_config();

    assert!(config.node.discovery.local.enabled);
    assert_eq!(
        config.node.discovery.local.rendezvous_addr,
        crate::discovery::local::DEFAULT_LOCAL_RENDEZVOUS_ADDR
    );
    assert!(config.transports.is_empty());
}

#[test]
fn discovery_scope_preserves_explicit_connectivity_config() {
    let mut explicit = Config::new();
    explicit.node.discovery.nostr.enabled = true;
    explicit.node.discovery.nostr.app = "custom-app".to_string();
    explicit.node.discovery.nostr.policy = NostrDiscoveryPolicy::ConfiguredOnly;
    explicit.node.discovery.nostr.share_local_candidates = false;
    explicit.node.discovery.lan.scope = Some("iris-local-v1".to_string());
    explicit.transports.udp = TransportInstances::Single(UdpConfig {
        bind_addr: Some("127.0.0.1:34567".to_string()),
        advertise_on_nostr: Some(false),
        outbound_only: Some(true),
        ..UdpConfig::default()
    });

    let config = FipsEndpoint::builder()
        .config(explicit.clone())
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
        Some("iris-local-v1")
    );
    assert!(!config.node.discovery.local.enabled);
    let TransportInstances::Single(udp) = config.transports.udp else {
        panic!("expected the explicit UDP transport");
    };
    assert_eq!(udp.bind_addr.as_deref(), Some("127.0.0.1:34567"));
    assert_eq!(udp.advertise_on_nostr, Some(false));
    assert_eq!(udp.outbound_only, Some(true));

    let local = FipsEndpoint::builder()
        .config(explicit)
        .discovery_scope("nostr-vpn:test")
        .local_rendezvous()
        .prepared_config();
    assert!(local.node.discovery.local.enabled);
    let TransportInstances::Single(udp) = local.transports.udp else {
        panic!("expected the explicit UDP transport");
    };
    assert_eq!(udp.bind_addr.as_deref(), Some("127.0.0.1:34567"));
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

#[tokio::test]
async fn endpoint_exposes_signed_machine_rating_events() {
    let endpoint = FipsEndpoint::builder()
        .without_system_tun()
        .bind()
        .await
        .expect("endpoint should bind");

    let events = endpoint
        .peer_rating_events("fips.peer")
        .await
        .expect("peer rating snapshot");
    assert!(events.is_empty());

    endpoint.shutdown().await.expect("shutdown should succeed");
}
