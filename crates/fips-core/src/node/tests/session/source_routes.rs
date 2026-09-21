use super::*;

mod queued_retry;

#[test]
fn unknown_destination_coordinates_preserve_bootstrap_identity() {
    let node = make_node();
    let destination = *Identity::generate().node_addr();
    let coords = node.get_dest_coords(&destination);
    let setup = SessionSetup::new(node.tree_state.my_coords().clone(), coords)
        .with_handshake(vec![0; crate::noise::XK_HANDSHAKE_MSG1_SIZE])
        .encode();
    assert_eq!(
        crate::protocol::SessionHandshake::classify(&setup, *node.node_addr(), destination),
        Some(crate::protocol::SessionHandshake::Setup),
        "an uncached destination must remain eligible for bounded bootstrap"
    );
}

fn add_peer(node: &mut Node, index: u64) -> PeerIdentity {
    let link = LinkId::new(index);
    let (connection, peer) = make_completed_connection(node, link, TransportId::new(1), 1_000);
    node.add_connection(connection).unwrap();
    node.promote_connection(link, peer, 2_000).unwrap();
    assert!(node.sync_dataplane_fmp_owner(peer.node_addr()));
    peer
}

#[tokio::test]
async fn local_control_allowance_denial_does_not_quarantine_its_carrier() {
    #[derive(Debug)]
    struct Denied;
    impl crate::node::OriginatedSessionObserver for Denied {
        fn prepare(
            &self,
            _: &crate::node::OriginatedSessionIntent,
        ) -> crate::node::OriginatedSessionAdmission {
            crate::node::OriginatedSessionAdmission::Reject
        }
        fn observe(&self, _: &crate::node::OriginatedSessionRequest<'_>) -> Option<u64> {
            panic!("denied before sealing")
        }
        fn complete(&self, _: u64, _: crate::node::ForwardingOutcome) {
            panic!("no reservation")
        }
    }
    let mut nodes = run_tree_test(2, &[(0, 1)], false).await;
    let selected = PeerIdentity::from_pubkey_full(nodes[1].node.identity().pubkey_full());
    let node = &mut nodes[0].node;
    node.config.node.routing.mode = RoutingMode::ReplyLearned;
    assert!(node.sync_dataplane_fmp_owner(selected.node_addr()));
    let remote = Identity::generate();
    let dest = *remote.node_addr();
    node.learn_reverse_route(dest, *selected.node_addr());
    install_established_session_with_mmp(node, &remote);
    node.set_endpoint_source_route(
        PeerIdentity::from_pubkey_full(remote.pubkey_full()),
        Some(selected),
    )
    .unwrap();
    assert!(node.sync_dataplane_fsp_owner_from_current_session_via(
        &dest,
        Some(*selected.node_addr()),
        0
    ));
    node.set_originated_session_observer(Some(std::sync::Arc::new(Denied)));
    let error = node
        .send_session_msg(
            &dest,
            crate::protocol::SessionMessageType::SenderReport.to_byte(),
            &[0; 46],
        )
        .await
        .unwrap_err();
    assert!(error.to_string().contains("SourcePolicy"), "{error}");
    let snapshot = node.learned_route_table_snapshot(Node::now_ms());
    assert!(
        snapshot
            .destinations
            .iter()
            .flat_map(|d| &d.routes)
            .all(|r| r.failures == 0),
        "local budget is not a route failure: {snapshot:?}"
    );
    cleanup_nodes(&mut nodes).await;
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
    node.config.node.routing.mode = RoutingMode::ReplyLearned;
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

fn source_loss_report(
    highest_counter: u64,
    cumulative_packets_recv: u64,
    age: u64,
) -> SessionReceiverReport {
    SessionReceiverReport {
        highest_counter,
        cumulative_packets_recv,
        cumulative_bytes_recv: cumulative_packets_recv * 100,
        timestamp_echo: session_timestamp_echo_for(age.try_into().unwrap()),
        dwell_time: 0,
        max_burst_loss: 0,
        mean_burst_loss: 0,
        jitter: 0,
        ecn_ce_count: 0,
        owd_trend: 0,
        burst_loss_count: 0,
        cumulative_reorder_count: 0,
        interval_packets_recv: 0,
        interval_bytes_recv: 0,
    }
}

#[tokio::test]
async fn source_forward_loss_survives_late_receipt_after_carrier_switch() {
    let mut node = make_node();
    let old = add_peer(&mut node, 1);
    let next = add_peer(&mut node, 2);
    let remote = Identity::generate();
    let destination = PeerIdentity::from_pubkey_full(remote.pubkey_full());
    let dest = *destination.node_addr();
    install_established_session_with_mmp(&mut node, &remote);
    let report = |highest, packets, age| source_loss_report(highest, packets, age).encode();
    node.set_endpoint_source_route(destination, Some(old))
        .unwrap();
    seed_dataplane_fsp_data_sent_for_test(&mut node, dest, *old.node_addr(), Node::now_ms() - 100);
    node.handle_session_receiver_report(&dest, &report(100, 100, 50))
        .await;
    node.handle_session_receiver_report(&dest, &report(116, 116, 50))
        .await;
    assert_eq!(
        node.endpoint_source_route_quality(dest, 1_000).loss_rate,
        Some(0.0)
    );

    node.set_endpoint_source_route(destination, Some(next))
        .unwrap();
    seed_dataplane_fsp_data_sent_for_test(&mut node, dest, *next.node_addr(), Node::now_ms() - 100);
    node.handle_session_receiver_report(&dest, &report(120, 118, 200))
        .await;
    let old_echo = node.endpoint_source_route_quality(dest, 1_000);
    assert!(!old_echo.has_recent_delivery_feedback);
    assert_eq!(old_echo.loss_rate, None);
    node.handle_session_receiver_report(&dest, &report(120, 118, 50))
        .await;
    let baseline = node.endpoint_source_route_quality(dest, 1_000);
    assert!(baseline.has_recent_delivery_feedback && baseline.rtt_ms.is_some());
    assert_eq!(
        baseline.loss_rate, None,
        "RTT alone must not imply zero loss"
    );
    node.handle_session_receiver_report(&dest, &report(136, 133, 50))
        .await;
    assert_eq!(
        node.endpoint_source_route_quality(dest, 1_000).loss_rate,
        Some(1.0 / 16.0)
    );
    node.handle_session_receiver_report(&dest, &report(136, 134, 50))
        .await;
    let corrected = node.endpoint_source_route_quality(dest, 1_000);
    assert_eq!(corrected.next_hop, Some(*next.node_addr()));
    assert!(corrected.has_recent_delivery_feedback && corrected.goodput_bps.unwrap() > 0.0);
    assert_eq!(corrected.loss_rate, Some(0.0));
}

#[test]
fn source_forward_loss_expires_despite_fresh_late_delivery_feedback() {
    let mut node = make_node();
    let next = add_peer(&mut node, 1);
    let remote = Identity::generate();
    let destination = PeerIdentity::from_pubkey_full(remote.pubkey_full());
    let dest = *destination.node_addr();
    install_established_session_with_mmp(&mut node, &remote);
    node.set_endpoint_source_route(destination, Some(next))
        .unwrap();
    let now = std::time::Instant::now();
    let now_ms = Node::now_ms();
    for (highest, packets, age) in [(100, 90, 3_000), (116, 105, 2_000), (116, 106, 0)] {
        seed_dataplane_fsp_data_sent_for_test(
            &mut node,
            dest,
            *next.node_addr(),
            now_ms - age - 100,
        );
        let report = source_loss_report(highest, packets, age + 50);
        node.dataplane
            .process_fsp_mmp_receiver_report(
                dest,
                &crate::mmp::report::ReceiverReport::from(&report),
                Some(*next.node_addr()),
                now_ms - age,
                now - std::time::Duration::from_millis(age),
                16,
            )
            .unwrap();
    }
    let expired = node.endpoint_source_route_quality(dest, 1_000);
    assert!(expired.has_recent_delivery_feedback && expired.rtt_ms.is_some());
    assert!(expired.goodput_bps.unwrap() > 0.0);
    assert_eq!(
        expired.loss_rate, None,
        "late delivery cannot renew positive-span evidence"
    );
    assert_eq!(
        node.endpoint_source_route_quality(dest, 10_000).loss_rate,
        Some(0.0)
    );
}

#[test]
fn metadata_refresh_preserves_an_authenticated_reply_carrier() {
    let mut node = make_node();
    node.config.node.routing.mode = RoutingMode::ReplyLearned;
    let proven = add_peer(&mut node, 1);
    let alternate = add_peer(&mut node, 2);
    let remote = Identity::generate();
    let dest = *remote.node_addr();
    node.learn_reverse_route(dest, *alternate.node_addr());
    install_established_session_with_mmp(&mut node, &remote);
    assert!(node.sync_dataplane_fsp_owner_from_current_session_via(
        &dest,
        Some(*proven.node_addr()),
        0,
    ));
    assert_eq!(
        node.dataplane.fsp_owner_next_hop(&dest),
        Some(*proven.node_addr())
    );
    assert!(node.refresh_dataplane_fsp_owner_routes_with_coords_warmup(&dest, 3));
    assert_eq!(
        node.dataplane.fsp_owner_next_hop(&dest),
        Some(*proven.node_addr()),
        "new coordinates must not displace the authenticated carrier of replies"
    );
    assert!(matches!(
        node.apply_dataplane_fsp_path_mtu_signal(&dest, 1000, std::time::Instant::now()),
        Ok(crate::dataplane::DataplaneFspPathMtuApplyResult::Changed(_))
    ));
    assert_eq!(
        node.dataplane.fsp_owner_next_hop(&dest),
        Some(*proven.node_addr()),
        "a size update must not displace the authenticated carrier of replies"
    );
    node.peers
        .get_mut(proven.node_addr())
        .unwrap()
        .mark_disconnected();
    assert!(node.refresh_dataplane_fsp_owner_routes_with_coords_warmup(&dest, 3));
    assert_eq!(
        node.dataplane.fsp_owner_next_hop(&dest),
        Some(*alternate.node_addr()),
        "a disconnected carrier must still yield to a usable route"
    );
}

#[tokio::test]
async fn tree_payload_route_does_not_follow_a_nonprogressing_handshake_ingress() {
    let mut node = make_node();
    assert_eq!(node.config.node.routing.mode, RoutingMode::Tree);
    let forward = *add_peer(&mut node, 1).node_addr();
    let incoming = *add_peer(&mut node, 2).node_addr();
    let root = *node.node_addr();
    for peer in [forward, incoming] {
        node.tree_state_mut().update_peer(
            ParentDeclaration::new(peer, root, 1, Node::now_ms()),
            TreeCoordinate::from_addrs(vec![peer, root]).unwrap(),
        );
    }
    let remote = Identity::generate();
    let dest = *remote.node_addr();
    node.coord_cache_mut().insert(
        dest,
        TreeCoordinate::from_addrs(vec![dest, forward, root]).unwrap(),
        Node::now_ms(),
    );
    assert_eq!(
        node.find_next_hop(&dest).map(|peer| *peer.node_addr()),
        Some(forward)
    );
    install_established_session_with_mmp(&mut node, &remote);
    // A reply may arrive on an asymmetric path. In tree mode that does not
    // prove the incoming neighbor can forward payload away from this root.
    node.remove_dataplane_fsp_owner(&dest);
    assert!(node.sync_dataplane_fsp_owner_from_current_session_via(&dest, Some(incoming), 0));
    assert_eq!(node.dataplane.fsp_owner_next_hop(&dest), Some(forward));
    assert!(node.refresh_dataplane_fsp_owner_routes_with_coords_warmup(&dest, 3));
    assert_eq!(node.dataplane.fsp_owner_next_hop(&dest), Some(forward));
    // Established return affinity is distinct from the initial handshake:
    // owner resync/rekey must preserve it, including earned paid return paths.
    assert!(node.refresh_dataplane_fsp_owner_routes_via(&dest, Some(incoming)));
    assert_eq!(node.dataplane.fsp_owner_next_hop(&dest), Some(incoming));
    assert!(node.sync_dataplane_fsp_owner_from_current_session_via(&dest, Some(forward), 0));
    assert_eq!(node.dataplane.fsp_owner_next_hop(&dest), Some(incoming));
    seed_dataplane_fsp_data_sent_for_test(&mut node, dest, incoming, Node::now_ms());
    let error = crate::protocol::PathBroken::new(dest, incoming).encode();
    node.handle_session_payload(LocalSessionPayload::new(incoming, incoming, &error))
        .await;
    assert_eq!(
        node.dataplane.fsp_owner_next_hop(&dest),
        Some(forward),
        "an explicit path failure must release broken reply affinity in tree mode too"
    );
}
