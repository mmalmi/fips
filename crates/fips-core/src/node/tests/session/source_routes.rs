use super::*;

fn add_peer(node: &mut Node, index: u64) -> PeerIdentity {
    let link = LinkId::new(index);
    let (connection, peer) = make_completed_connection(node, link, TransportId::new(1), 1_000);
    node.add_connection(connection).unwrap();
    node.promote_connection(link, peer, 2_000).unwrap();
    assert!(node.sync_dataplane_fmp_owner(peer.node_addr()));
    peer
}

#[test]
fn source_binding_is_bounded_and_does_not_override_transit() {
    let mut node = make_node();
    let destination = add_peer(&mut node, 1);
    let selected = add_peer(&mut node, 2);
    let local = PeerIdentity::from_pubkey_full(node.identity().pubkey_full());
    let unknown = PeerIdentity::from_pubkey_full(Identity::generate().pubkey_full());
    assert!(
        node.set_endpoint_source_route(local, Some(selected))
            .is_err()
    );
    assert!(
        node.set_endpoint_source_route(destination, Some(unknown))
            .is_err()
    );
    node.set_endpoint_source_route(destination, Some(selected))
        .unwrap();
    assert_eq!(
        node.find_next_hop(destination.node_addr())
            .unwrap()
            .node_addr(),
        selected.node_addr()
    );
    assert_eq!(
        node.find_transit_next_hop(destination.node_addr(), selected.node_addr()),
        Some(*destination.node_addr())
    );
    for _ in 1..64 {
        let other = PeerIdentity::from_pubkey_full(Identity::generate().pubkey_full());
        node.set_endpoint_source_route(other, Some(selected))
            .unwrap();
    }
    assert!(
        node.set_endpoint_source_route(unknown, Some(selected))
            .is_err()
    );
    // Updates and removals must still work when the table is full.
    node.set_endpoint_source_route(destination, Some(destination))
        .unwrap();
    node.set_endpoint_source_route(destination, None).unwrap();
    assert_eq!(
        node.find_next_hop(destination.node_addr())
            .unwrap()
            .node_addr(),
        destination.node_addr()
    );
    node.set_endpoint_source_route(unknown, Some(selected))
        .unwrap();
    node.peers
        .get_mut(selected.node_addr())
        .unwrap()
        .mark_disconnected();
    assert!(node.find_next_hop(unknown.node_addr()).is_none());
}

#[test]
fn source_binding_replaces_cached_carrier_and_fails_closed() {
    let mut node = make_node();
    let old = add_peer(&mut node, 1);
    let selected = add_peer(&mut node, 2);
    let remote = Identity::generate();
    let destination = PeerIdentity::from_pubkey_full(remote.pubkey_full());
    let dest = *destination.node_addr();
    node.learn_reverse_route(dest, *old.node_addr());
    install_established_session_with_mmp(&mut node, &remote);
    assert!(node.sync_dataplane_fsp_owner_from_current_session_via(
        &dest,
        Some(*old.node_addr()),
        0
    ));
    assert_eq!(
        node.dataplane.fsp_owner_next_hop(&dest),
        Some(*old.node_addr())
    );
    node.set_endpoint_source_route(destination, Some(selected))
        .unwrap();
    assert_eq!(
        node.dataplane.fsp_owner_next_hop(&dest),
        Some(*selected.node_addr())
    );
    // A preferred handshake/recovery ingress must not override the binding.
    node.refresh_dataplane_fsp_owner_routes_via(&dest, Some(*old.node_addr()));
    assert_eq!(
        node.dataplane.fsp_owner_next_hop(&dest),
        Some(*selected.node_addr())
    );
    node.peers
        .get_mut(selected.node_addr())
        .unwrap()
        .mark_disconnected();
    node.refresh_dataplane_fsp_owner_routes_retaining_current(&dest);
    assert!(node.find_next_hop(&dest).is_none());
    assert_eq!(
        node.dataplane.fsp_owner_next_hop(&dest),
        None,
        "unusable bound peer must clear the cached output even while its owner remains"
    );
    node.peers
        .get_mut(selected.node_addr())
        .unwrap()
        .mark_connected(Node::now_ms());
    node.refresh_dataplane_fsp_owner_routes(&dest);
    assert_eq!(
        node.dataplane.fsp_owner_next_hop(&dest),
        Some(*selected.node_addr())
    );
}

#[test]
fn source_quality_keeps_an_unanswered_burst_failed_and_rebinding_invalidates_it() {
    let mut node = make_node();
    let selected = add_peer(&mut node, 1);
    let remote = Identity::generate();
    let destination = PeerIdentity::from_pubkey_full(remote.pubkey_full());
    let dest = *destination.node_addr();
    install_established_session_with_mmp(&mut node, &remote);
    node.set_endpoint_source_route(destination, Some(selected))
        .unwrap();
    let unknown = node.endpoint_source_route_quality(dest, 1_000);
    assert_eq!(unknown.next_hop, None);
    assert!(!unknown.has_recent_delivery_feedback);
    assert!(!unknown.delivery_feedback_timed_out);
    seed_dataplane_fsp_data_sent_for_test(
        &mut node,
        dest,
        *selected.node_addr(),
        Node::now_ms() - 10_000,
    );
    let failed = node.endpoint_source_route_quality(dest, 1_000);
    assert_eq!(failed.next_hop, Some(*selected.node_addr()));
    assert!(failed.delivery_feedback_timed_out);
    assert!(!failed.has_recent_delivery_feedback);
    assert!(failed.rtt_ms.is_none() && failed.loss_rate.is_none() && failed.goodput_bps.is_none());
    assert_eq!(failed.sent_packets, 1);
    node.set_endpoint_source_route(destination, Some(selected))
        .unwrap();
    let reset = node.endpoint_source_route_quality(dest, 1_000);
    assert_eq!(reset.next_hop, None);
    assert!(!reset.delivery_feedback_timed_out);
    assert_eq!(
        reset.sent_packets, 1,
        "rebinding must not reset session traffic counters"
    );
}
