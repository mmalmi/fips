use super::*;

// Mirror of `restarted_initiator_reestablishes_with_surviving_responder`:
// here the SURVIVOR is the session INITIATOR and still retains its initial
// msg3 (no authenticated inbound data has confirmed the epoch yet), and the
// RESPONDER restarts and then opens a fresh session.
#[test]
fn test_restarted_responder_reestablishes_with_surviving_initiator() {
    run_large_stack_async_test("fips-session-surviving-initiator", || async {
        surviving_initiator_scenario(true).await;
    });
}

// Inside the settle window a SessionSetup from the same peer can still be a
// late simultaneous msg1, so the surviving initiator keeps dropping it.
#[test]
fn test_surviving_initiator_drops_setup_inside_settle_window() {
    run_large_stack_async_test("fips-session-surviving-initiator-window", || async {
        surviving_initiator_scenario(false).await;
    });
}

async fn surviving_initiator_scenario(past_settle_window: bool) {
    let _guard = lock_large_network_test().await;
    let mut nodes = run_tree_test(2, &[(0, 1)], false).await;
    verify_tree_convergence(&nodes);
    populate_all_coord_caches(&mut nodes);

    let survivor_addr = *nodes[0].node.node_addr();
    let restarted_addr = *nodes[1].node.node_addr();
    let restarted_identity = PeerIdentity::from_pubkey_full(nodes[1].node.identity().pubkey_full());
    let survivor_identity = PeerIdentity::from_pubkey_full(nodes[0].node.identity().pubkey_full());

    // Survivor (node 0) initiates; node 1 responds.
    nodes[0]
        .node
        .initiate_session(restarted_addr, restarted_identity.pubkey_full())
        .await
        .expect("initial session should start");
    wait_for_session_established(
        &mut nodes,
        0,
        &restarted_addr,
        Duration::from_secs(10),
        "survivor initial session",
    )
    .await;
    wait_for_session_established(
        &mut nodes,
        1,
        &survivor_addr,
        Duration::from_secs(10),
        "responder initial session",
    )
    .await;

    let survivor_session = nodes[0].node.get_session(&restarted_addr).unwrap();
    assert!(survivor_session.is_initiator());
    assert!(
        survivor_session.handshake_payload().is_some(),
        "precondition: surviving initiator still retains its initial msg3"
    );

    if past_settle_window {
        // Age the survivor's session past handshake_timeout_secs.
        let window_ms = nodes[0].node.config.node.rate_limit.handshake_timeout_secs * 1000;
        let started = Node::now_ms() - window_ms - 1_000;
        nodes[0]
            .node
            .sessions
            .get_mut(&restarted_addr)
            .unwrap()
            .mark_established(started);
    }

    // The responder restarts (loses its session) before sending any data.
    nodes[1].node.remove_dataplane_fsp_owner(&survivor_addr);
    assert!(nodes[1].node.remove_session(&survivor_addr).is_some());
    nodes[1].node.startup_epoch[0] ^= 0xff;

    // Restarted peer opens a fresh session to the survivor.
    nodes[1]
        .node
        .initiate_session(survivor_addr, survivor_identity.pubkey_full())
        .await
        .expect("restarted peer should start a fresh session");
    assert!(wait_process_packets_for_node(&mut nodes, 0).await > 0);

    let survivor = nodes[0].node.get_session(&restarted_addr).unwrap();
    let answered = survivor.has_rekey_in_progress() || survivor.pending_new_session().is_some();
    eprintln!(
        "SURVIVING-INITIATOR past_window={past_settle_window}: rekey_in_progress={} pending_new_session={} retains_msg3={}",
        survivor.has_rekey_in_progress(),
        survivor.pending_new_session().is_some(),
        survivor.handshake_payload().is_some()
    );

    if past_settle_window {
        assert!(
            answered,
            "surviving initiator must answer a restarted peer's fresh setup after the settle window"
        );
        assert!(
            !survivor.is_rekey_initiator(),
            "survivor answers as responder, it does not start its own rekey"
        );
        wait_for_session_established(
            &mut nodes,
            1,
            &survivor_addr,
            Duration::from_secs(10),
            "restarted responder fresh session",
        )
        .await;
        for _ in 0..20 {
            if process_available_packets(&mut nodes).await == 0 {
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        }
        let restarted_epoch = nodes[1].node.startup_epoch;
        let survivor = nodes[0].node.get_session(&restarted_addr).unwrap();
        assert!(
            survivor.established_remote_epoch_matches(Some(restarted_epoch)),
            "survivor must end on the restarted peer's new session, not the stale one"
        );
        assert!(!survivor.has_rekey_in_progress());
    } else {
        assert!(
            !answered,
            "inside the settle window a setup from the same peer is treated as a late simultaneous msg1"
        );
        assert!(survivor.handshake_payload().is_some());
    }
    cleanup_nodes(&mut nodes).await;
}
