use super::*;

#[test]
fn sparse_request_recovers_a_stale_session_while_link_heartbeats_succeed() {
    run_large_stack_async_test("fips-sparse-session-recovery", || async {
        sparse_session_recovery(true).await;
    });
}

#[test]
fn acknowledged_sparse_request_does_not_rekey_an_idle_session() {
    run_large_stack_async_test("fips-sparse-session-idle", || async {
        sparse_session_recovery(false).await;
    });
}

async fn sparse_session_recovery(lose_remote_session: bool) {
    let mut nodes = run_tree_test(2, &[(0, 1)], false).await;
    populate_all_coord_caches(&mut nodes);
    let identities = nodes
        .iter()
        .map(|node| PeerIdentity::from_pubkey_full(node.node.identity().pubkey_full()))
        .collect::<Vec<_>>();
    let mut endpoints = nodes
        .iter_mut()
        .map(|node| node.node.attach_endpoint_data_io(8).unwrap())
        .collect::<Vec<_>>();
    for node in &mut nodes {
        node.node.config.node.heartbeat_interval_secs = 1;
        node.node.config.node.rekey.after_secs = u64::MAX;
        node.node.config.node.rekey.after_messages = u64::MAX;
    }
    nodes[0]
        .node
        .initiate_session(*identities[1].node_addr(), identities[1].pubkey_full())
        .await
        .unwrap();
    for (index, other) in [(0, 1), (1, 0)] {
        wait_for_session_established(
            &mut nodes,
            index,
            identities[other].node_addr(),
            Duration::from_secs(5),
            "sparse recovery baseline",
        )
        .await;
    }
    settle_session_handshake_retransmits(
        &mut nodes,
        0,
        identities[1].node_addr(),
        1,
        identities[0].node_addr(),
    );
    for (source, destination) in [(0, 1), (1, 0)] {
        send_endpoint_data_via_dataplane(
            &mut nodes[source].node,
            identities[destination],
            b"baseline".to_vec(),
        )
        .await
        .unwrap();
        let event = recv_endpoint_event_while_draining(
            &mut nodes,
            &mut endpoints[destination].event_rx,
            Duration::from_secs(5),
            "baseline delivery",
        )
        .await;
        assert_eq!(
            expect_single_endpoint_data_event(event).payload.as_slice(),
            b"baseline"
        );
    }
    drain_to_quiescence(&mut nodes).await;
    let original_hash = *nodes[0]
        .node
        .get_session(identities[1].node_addr())
        .unwrap()
        .handshake_hash()
        .unwrap();

    // Lose only the recipient's end-to-end state. The authenticated UDP
    // link remains in place and continues replying to link heartbeats.
    if lose_remote_session {
        nodes[1]
            .node
            .remove_dataplane_fsp_owner(identities[0].node_addr());
        nodes[1]
            .node
            .remove_session(identities[0].node_addr())
            .unwrap();
    }
    send_endpoint_data_via_dataplane(&mut nodes[0].node, identities[1], b"one request".to_vec())
        .await
        .unwrap();
    let recovered = tokio::time::timeout(Duration::from_secs(16), async {
        loop {
            process_available_packets(&mut nodes).await;
            run_session_retransmit_work(&mut nodes).await;
            for node in &mut nodes {
                node.node.check_link_heartbeats().await;
                node.node.check_session_mmp_reports().await;
                node.node.check_session_rekey().await;
            }
            if nodes[0]
                .node
                .get_session(identities[1].node_addr())
                .and_then(|entry| entry.handshake_hash())
                .is_some_and(|hash| hash != &original_hash)
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await;
    let link_survived = nodes[0]
        .node
        .get_peer(identities[1].node_addr())
        .is_some_and(|peer| peer.is_healthy());
    if recovered.is_ok() {
        for (source, destination) in [(0, 1), (1, 0)] {
            send_endpoint_data_via_dataplane(
                &mut nodes[source].node,
                identities[destination],
                b"recovered".to_vec(),
            )
            .await
            .unwrap();
            let event = recv_endpoint_event_while_draining(
                &mut nodes,
                &mut endpoints[destination].event_rx,
                Duration::from_secs(5),
                "automatic sparse-session recovery",
            )
            .await;
            assert_eq!(
                expect_single_endpoint_data_event(event).payload.as_slice(),
                b"recovered"
            );
        }
    }
    cleanup_nodes(&mut nodes).await;
    assert!(
        link_survived,
        "link heartbeats must remain healthy during the stall"
    );
    assert!(
        recovered.is_ok() == lose_remote_session,
        "recover unanswered traffic without a restart, but preserve acknowledged idle sessions"
    );
}
