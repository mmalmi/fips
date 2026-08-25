use super::*;
use crate::protocol::{CoordsRequired, PathBroken};

fn routing_signal_body(encoded: &[u8]) -> &[u8] {
    &encoded[FSP_COMMON_PREFIX_SIZE + 1..]
}

fn prove_outbound_path(node: &mut Node, dest: NodeAddr, next_hop: NodeAddr) {
    seed_dataplane_fsp_data_sent_for_test(node, dest, next_hop, Node::now_ms());
}

#[tokio::test]
async fn test_unbound_coords_required_is_ignored_before_any_side_effect() {
    let mut node = Node::new(Config::new()).expect("node");
    let dest = NodeAddr::from_bytes([0xCC; 16]);
    let previous_hop = NodeAddr::from_bytes([0xBB; 16]);
    let encoded = CoordsRequired::new(dest, previous_hop).encode();

    node.handle_coords_required(&previous_hop, routing_signal_body(&encoded))
        .await;

    assert_eq!(node.stats().errors.coords_required, 1);
    assert_eq!(node.stats().errors.coords_required_unbound, 1);
    assert!(!node.pending_lookups.contains_key(&dest));
}

#[tokio::test]
async fn test_unbound_path_broken_cannot_invalidate_coordinates() {
    let mut node = Node::new(Config::new()).expect("node");
    let dest = NodeAddr::from_bytes([0xCC; 16]);
    let previous_hop = NodeAddr::from_bytes([0xBB; 16]);
    let coords = TreeCoordinate::root(dest);
    node.coord_cache_mut().insert(dest, coords, Node::now_ms());
    let encoded = PathBroken::new(dest, previous_hop).encode();

    node.handle_path_broken(&previous_hop, routing_signal_body(&encoded))
        .await;

    assert_eq!(node.stats().errors.path_broken, 1);
    assert_eq!(node.stats().errors.path_broken_unbound, 1);
    assert!(node.coord_cache().contains(&dest, Node::now_ms()));
}

#[tokio::test]
async fn test_structurally_forged_routing_signal_is_counted_separately() {
    let mut node = Node::new(Config::new()).expect("node");
    let local = *node.node_addr();
    let previous_hop = NodeAddr::from_bytes([0xBB; 16]);
    let encoded = CoordsRequired::new(local, previous_hop).encode();

    node.handle_coords_required(&previous_hop, routing_signal_body(&encoded))
        .await;

    assert_eq!(node.stats().errors.coords_required_unbound, 1);
    assert_eq!(node.stats().errors.routing_signal_forged, 1);
}

#[tokio::test]
async fn test_half_open_responder_does_not_bind_routing_signal_destination() {
    let mut node = Node::new(Config::new()).expect("node");
    let claimed = NodeAddr::from_bytes([0xCC; 16]);
    let previous_hop = NodeAddr::from_bytes([0xBB; 16]);
    let handshake = crate::noise::HandshakeState::new_responder(node.identity().keypair());
    let placeholder = node.identity().pubkey_full();
    node.sessions.insert(
        claimed,
        crate::node::session::SessionEntry::new(
            claimed,
            placeholder,
            EndToEndState::AwaitingMsg3(handshake),
            1_000,
            false,
        ),
    );
    let encoded = PathBroken::new(claimed, previous_hop).encode();

    node.handle_path_broken(&previous_hop, routing_signal_body(&encoded))
        .await;

    assert_eq!(node.stats().errors.path_broken_unbound, 1);
}

#[tokio::test]
async fn default_tree_coords_required_requires_proven_ingress_path() {
    let mut node = Node::new(Config::new()).expect("node");
    let remote = Identity::generate();
    let dest = *remote.node_addr();
    let proven_hop = NodeAddr::from_bytes([0xAA; 16]);
    let forged_hop = NodeAddr::from_bytes([0xBB; 16]);
    install_established_session_with_mmp(&mut node, &remote);
    prove_outbound_path(&mut node, dest, proven_hop);

    let forged = CoordsRequired::new(dest, forged_hop).encode();
    node.handle_coords_required(&forged_hop, routing_signal_body(&forged))
        .await;
    assert_eq!(
        node.coords_response_rate_limiter.len(),
        0,
        "an unrelated authenticated Tree neighbor must not trigger recovery work"
    );

    let valid = CoordsRequired::new(dest, proven_hop).encode();
    node.handle_coords_required(&proven_hop, routing_signal_body(&valid))
        .await;
    assert_eq!(
        node.coords_response_rate_limiter.len(),
        1,
        "feedback returning over the proven outbound branch remains actionable"
    );
}

#[tokio::test]
async fn default_tree_path_broken_requires_proven_ingress_path() {
    let mut node = Node::new(Config::new()).expect("node");
    let remote = Identity::generate();
    let dest = *remote.node_addr();
    let proven_hop = NodeAddr::from_bytes([0xAA; 16]);
    let forged_hop = NodeAddr::from_bytes([0xBB; 16]);
    let coords = TreeCoordinate::root(dest);
    install_established_session_with_mmp(&mut node, &remote);
    prove_outbound_path(&mut node, dest, proven_hop);
    node.coord_cache_mut().insert(dest, coords, Node::now_ms());

    let forged = PathBroken::new(dest, forged_hop).encode();
    node.handle_path_broken(&forged_hop, routing_signal_body(&forged))
        .await;
    assert!(
        node.coord_cache().contains(&dest, Node::now_ms()),
        "an unrelated authenticated Tree neighbor must not invalidate coordinates"
    );

    let valid = PathBroken::new(dest, proven_hop).encode();
    node.handle_path_broken(&proven_hop, routing_signal_body(&valid))
        .await;
    assert!(
        !node.coord_cache().contains(&dest, Node::now_ms()),
        "feedback returning over the proven outbound branch remains actionable"
    );
}

#[tokio::test]
async fn default_tree_mtu_exceeded_requires_proven_ingress_path() {
    let mut node = Node::new(Config::new()).expect("node");
    let remote = Identity::generate();
    let dest = *remote.node_addr();
    let proven_hop = NodeAddr::from_bytes([0xAA; 16]);
    let forged_hop = NodeAddr::from_bytes([0xBB; 16]);
    let dest_fips = crate::FipsAddress::from_node_addr(&dest);
    install_established_session_with_mmp(&mut node, &remote);
    prove_outbound_path(&mut node, dest, proven_hop);
    note_sent_wire_len(&mut node, dest, 1400);

    let forged = build_mtu_exceeded_inner(&dest, &forged_hop, 1280);
    node.handle_mtu_exceeded(&forged_hop, &forged).await;

    assert_eq!(node.path_mtu_lookup_get(&dest_fips), None);
    assert_eq!(node.stats().errors.mtu_exceeded_stale_path, 1);
}

#[tokio::test]
async fn test_handle_mtu_exceeded_writes_path_mtu_lookup_when_empty() {
    use crate::node::tests::spanning_tree::make_test_node;

    let mut tn = make_test_node().await;

    let remote = Identity::generate();
    let dest = *remote.node_addr();
    let reporter = NodeAddr::from_bytes([0xBB; 16]);
    let dest_fips = crate::FipsAddress::from_node_addr(&dest);
    install_established_session_with_mmp(&mut tn.node, &remote);
    prove_outbound_path(&mut tn.node, dest, reporter);
    note_sent_wire_len(&mut tn.node, dest, 1400);

    assert!(
        tn.node.path_mtu_lookup_get(&dest_fips).is_none(),
        "lookup should start empty for this destination"
    );

    let inner = build_mtu_exceeded_inner(&dest, &reporter, 1280);
    tn.node.handle_mtu_exceeded(&reporter, &inner).await;

    assert_eq!(
        tn.node.path_mtu_lookup_get(&dest_fips),
        Some(1280),
        "MtuExceeded should populate path_mtu_lookup with the bottleneck MTU"
    );
}

#[tokio::test]
async fn test_handle_mtu_exceeded_tightens_existing_path_mtu_lookup() {
    use crate::node::tests::spanning_tree::make_test_node;

    let mut tn = make_test_node().await;

    let remote = Identity::generate();
    let dest = *remote.node_addr();
    let reporter = NodeAddr::from_bytes([0xBB; 16]);
    let dest_fips = crate::FipsAddress::from_node_addr(&dest);
    install_established_session_with_mmp(&mut tn.node, &remote);
    prove_outbound_path(&mut tn.node, dest, reporter);
    note_sent_wire_len(&mut tn.node, dest, 1400);

    // Pre-seed with a generous value (e.g., from a discovery reverse-path
    // response that didn't reflect the forward-path bottleneck).
    tn.node.path_mtu_lookup_insert(dest_fips, 1500);

    let inner = build_mtu_exceeded_inner(&dest, &reporter, 1280);
    tn.node.handle_mtu_exceeded(&reporter, &inner).await;

    assert_eq!(
        tn.node.path_mtu_lookup_get(&dest_fips),
        Some(1280),
        "MtuExceeded with smaller bottleneck must tighten the lookup"
    );
}

#[tokio::test]
async fn test_handle_mtu_exceeded_keeps_tighter_existing_path_mtu_lookup() {
    use crate::node::tests::spanning_tree::make_test_node;

    let mut tn = make_test_node().await;

    let remote = Identity::generate();
    let dest = *remote.node_addr();
    let reporter = NodeAddr::from_bytes([0xBB; 16]);
    let dest_fips = crate::FipsAddress::from_node_addr(&dest);
    install_established_session_with_mmp(&mut tn.node, &remote);
    prove_outbound_path(&mut tn.node, dest, reporter);
    note_sent_wire_len(&mut tn.node, dest, 1600);

    // Pre-seed with a tighter value than the incoming signal (e.g., from
    // a prior reactive event on a narrower hop). The clamp must never
    // loosen — keep the existing value.
    tn.node.path_mtu_lookup_insert(dest_fips, 1280);

    let inner = build_mtu_exceeded_inner(&dest, &reporter, 1500);
    tn.node.handle_mtu_exceeded(&reporter, &inner).await;

    assert_eq!(
        tn.node.path_mtu_lookup_get(&dest_fips),
        Some(1280),
        "MtuExceeded with looser bottleneck must not loosen a tighter existing value"
    );
}

#[tokio::test]
async fn test_handle_mtu_exceeded_ignores_unbound_destination() {
    use crate::node::tests::spanning_tree::make_test_node;

    let mut tn = make_test_node().await;
    let dest = NodeAddr::from_bytes([0xCC; 16]);
    let reporter = NodeAddr::from_bytes([0xBB; 16]);
    let dest_fips = crate::FipsAddress::from_node_addr(&dest);

    let inner = build_mtu_exceeded_inner(&dest, &reporter, 1280);
    tn.node.handle_mtu_exceeded(&reporter, &inner).await;

    assert_eq!(tn.node.path_mtu_lookup_get(&dest_fips), None);
    assert_eq!(tn.node.stats().errors.mtu_exceeded_unbound, 1);
}

#[tokio::test]
async fn test_handle_mtu_exceeded_ignores_sub_floor_value() {
    use crate::node::tests::spanning_tree::make_test_node;

    let mut tn = make_test_node().await;
    let remote = Identity::generate();
    let dest = *remote.node_addr();
    let reporter = NodeAddr::from_bytes([0xBB; 16]);
    let dest_fips = crate::FipsAddress::from_node_addr(&dest);
    install_established_session_with_mmp(&mut tn.node, &remote);
    prove_outbound_path(&mut tn.node, dest, reporter);
    note_sent_wire_len(&mut tn.node, dest, 1400);

    let inner = build_mtu_exceeded_inner(&dest, &reporter, 128);
    tn.node.handle_mtu_exceeded(&reporter, &inner).await;

    assert_eq!(tn.node.path_mtu_lookup_get(&dest_fips), None);
    assert_eq!(tn.node.stats().errors.mtu_exceeded_below_floor, 1);
}

#[tokio::test]
async fn test_handle_mtu_exceeded_requires_fresh_sent_size_evidence() {
    use crate::node::tests::spanning_tree::make_test_node;

    let mut tn = make_test_node().await;
    let remote = Identity::generate();
    let dest = *remote.node_addr();
    let reporter = NodeAddr::from_bytes([0xBB; 16]);
    let dest_fips = crate::FipsAddress::from_node_addr(&dest);
    install_established_session_with_mmp(&mut tn.node, &remote);
    prove_outbound_path(&mut tn.node, dest, reporter);
    let inner = build_mtu_exceeded_inner(&dest, &reporter, 1280);

    tn.node.handle_mtu_exceeded(&reporter, &inner).await;
    assert_eq!(tn.node.path_mtu_lookup_get(&dest_fips), None);
    assert_eq!(tn.node.stats().errors.mtu_exceeded_uncorroborated, 1);

    note_sent_wire_len(&mut tn.node, dest, 1400);
    tn.node.handle_mtu_exceeded(&reporter, &inner).await;
    assert_eq!(tn.node.path_mtu_lookup_get(&dest_fips), Some(1280));

    tn.node.handle_mtu_exceeded(&reporter, &inner).await;
    assert_eq!(tn.node.stats().errors.mtu_exceeded_uncorroborated, 2);
}

// ============================================================================
// Proactive PathMtuNotification → path_mtu_lookup focused unit tests
//
// These exercise the receive-side write path that mirrors the proactive
// end-to-end echo into `path_mtu_lookup`. Without this mirror, new TCP
// flows opened on a path the proactive notification has tightened keep
// getting clamped by the staler discovery-time value until a reactive
// MtuExceeded fires for those flows — long-lived stable paths can sit
// in the gap indefinitely.
// ============================================================================
