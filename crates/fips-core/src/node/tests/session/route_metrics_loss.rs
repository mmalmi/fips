#[tokio::test]
async fn test_session_receiver_loss_replaces_active_fallback_route() {
    let mut node = make_reply_learned_node_with_tree_peer();
    let failed_fallback = *node.peer_ids().next().expect("failed fallback peer");
    assert!(node.sync_dataplane_fmp_owner(&failed_fallback));

    let transport_id = TransportId::new(1);
    let replacement_link = LinkId::new(2);
    let (replacement_conn, replacement_identity) =
        make_completed_connection(&mut node, replacement_link, transport_id, 1_000);
    let replacement_fallback = *replacement_identity.node_addr();
    node.add_connection(replacement_conn).unwrap();
    node.promote_connection(replacement_link, replacement_identity, 2_000)
        .unwrap();
    assert!(node.sync_dataplane_fmp_owner(&replacement_fallback));

    let remote = Identity::generate();
    let remote_addr = *remote.node_addr();
    install_established_session_with_mmp(&mut node, &remote);
    node.learn_reverse_route(remote_addr, failed_fallback);
    node.learn_reverse_route(remote_addr, replacement_fallback);
    assert!(node.sync_dataplane_fsp_owner_from_current_session_via(
        &remote_addr,
        Some(failed_fallback),
        0,
    ));
    seed_dataplane_fsp_data_sent_for_test(&mut node, remote_addr, failed_fallback, Node::now_ms());

    let baseline = SessionReceiverReport {
        highest_counter: 100,
        cumulative_packets_recv: 100,
        cumulative_bytes_recv: 10_000,
        timestamp_echo: 0,
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
    .encode();
    node.handle_session_receiver_report(&remote_addr, &baseline)
        .await;

    let lossy = SessionReceiverReport {
        highest_counter: 120,
        cumulative_packets_recv: 118,
        cumulative_bytes_recv: 11_800,
        timestamp_echo: session_timestamp_echo_for(50),
        dwell_time: 0,
        max_burst_loss: 0,
        mean_burst_loss: 0,
        jitter: 0,
        ecn_ce_count: 0,
        owd_trend: 0,
        burst_loss_count: 0,
        cumulative_reorder_count: 0,
        interval_packets_recv: 12,
        interval_bytes_recv: 1_200,
    }
    .encode();
    node.handle_session_receiver_report(&remote_addr, &lossy)
        .await;

    let sustained_loss = SessionReceiverReport {
        highest_counter: 140,
        cumulative_packets_recv: 136,
        cumulative_bytes_recv: 13_600,
        timestamp_echo: session_timestamp_echo_for(50),
        dwell_time: 0,
        max_burst_loss: 0,
        mean_burst_loss: 0,
        jitter: 0,
        ecn_ce_count: 0,
        owd_trend: 0,
        burst_loss_count: 0,
        cumulative_reorder_count: 0,
        interval_packets_recv: 18,
        interval_bytes_recv: 1_800,
    }
    .encode();
    node.handle_session_receiver_report(&remote_addr, &sustained_loss)
        .await;

    assert_eq!(
        node.dataplane.fsp_owner_next_hop(&remote_addr),
        Some(replacement_fallback),
        "valid end-to-end loss must demote the active learned branch and repin the established session"
    );
    assert!(
        node.pending_lookups.contains_key(&remote_addr),
        "route-quality failure should also refresh discovery while the replacement carries traffic"
    );
    assert!(
        !node.session_direct_path_is_degraded(&remote_addr, Node::now_ms()),
        "loss on a learned fallback must not poison the independent direct-path state"
    );
}
