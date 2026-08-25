use super::*;

#[tokio::test]
async fn test_handle_mtu_exceeded_writes_path_mtu_lookup_when_empty() {
    use crate::node::tests::spanning_tree::make_test_node;

    let mut tn = make_test_node().await;

    let remote = Identity::generate();
    let dest = *remote.node_addr();
    let reporter = NodeAddr::from_bytes([0xBB; 16]);
    let dest_fips = crate::FipsAddress::from_node_addr(&dest);
    install_established_session_with_mmp(&mut tn.node, &remote);
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
