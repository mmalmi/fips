use super::*;

#[test]
fn test_handle_path_mtu_notification_writes_path_mtu_lookup_when_empty() {
    let mut node = make_node();
    let remote = Identity::generate();
    let remote_addr = *remote.node_addr();
    let remote_fips = crate::FipsAddress::from_node_addr(&remote_addr);

    install_established_session_with_mmp(&mut node, &remote);

    assert!(
        node.path_mtu_lookup_get(&remote_fips).is_none(),
        "lookup should start empty for this destination"
    );

    let body = build_path_mtu_notification_body(1280);
    node.handle_session_path_mtu_notification(&remote_addr, &body);

    assert_eq!(
        node.path_mtu_lookup_get(&remote_fips),
        Some(1280),
        "PathMtuNotification should populate path_mtu_lookup with the reported MTU"
    );
}

#[test]
fn test_handle_path_mtu_notification_tightens_existing_path_mtu_lookup() {
    let mut node = make_node();
    let remote = Identity::generate();
    let remote_addr = *remote.node_addr();
    let remote_fips = crate::FipsAddress::from_node_addr(&remote_addr);

    install_established_session_with_mmp(&mut node, &remote);

    // Pre-seed with a generous value (e.g., from the discovery seed at link
    // promotion time, before the destination's proactive echo arrived).
    node.path_mtu_lookup_insert(remote_fips, 1500);

    let body = build_path_mtu_notification_body(1280);
    node.handle_session_path_mtu_notification(&remote_addr, &body);

    assert_eq!(
        node.path_mtu_lookup_get(&remote_fips),
        Some(1280),
        "PathMtuNotification with smaller MTU must tighten the lookup"
    );
}

#[test]
fn test_handle_path_mtu_notification_keeps_tighter_existing_path_mtu_lookup() {
    let mut node = make_node();
    let remote = Identity::generate();
    let remote_addr = *remote.node_addr();
    let remote_fips = crate::FipsAddress::from_node_addr(&remote_addr);

    install_established_session_with_mmp(&mut node, &remote);

    // Pre-seed with a tighter value than what the proactive notification
    // reports (e.g., from a prior reactive MtuExceeded on a narrower hop).
    // The mirror must never loosen the clamp.
    node.path_mtu_lookup_insert(remote_fips, 1200);

    let body = build_path_mtu_notification_body(1400);
    node.handle_session_path_mtu_notification(&remote_addr, &body);

    assert_eq!(
        node.path_mtu_lookup_get(&remote_fips),
        Some(1200),
        "PathMtuNotification with looser MTU must not loosen a tighter existing value"
    );
}

#[test]
fn test_handle_path_mtu_notification_no_session_no_op() {
    let mut node = make_node();
    let remote = Identity::generate();
    let remote_addr = *remote.node_addr();
    let remote_fips = crate::FipsAddress::from_node_addr(&remote_addr);

    // No session installed. The handler should drop the notification entirely.
    let body = build_path_mtu_notification_body(1280);
    node.handle_session_path_mtu_notification(&remote_addr, &body);

    assert!(
        node.path_mtu_lookup_get(&remote_fips).is_none(),
        "PathMtuNotification with no session must not touch path_mtu_lookup"
    );
}
