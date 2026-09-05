use super::*;

#[test]
fn routine_rekey_rotates_routed_sessions_while_a_direct_probe_is_pending() {
    run_large_stack_async_test("fips-routed-rekey", || async {
        let mut nodes = run_tree_test(3, &[(0, 1), (1, 2)], false).await;
        verify_tree_convergence(&nodes);
        populate_all_coord_caches(&mut nodes);
        let identities = nodes
            .iter()
            .map(|n| PeerIdentity::from_pubkey_full(n.node.identity().pubkey_full()))
            .collect::<Vec<_>>();
        let mut endpoints = nodes
            .iter_mut()
            .map(|n| n.node.attach_endpoint_data_io(8).unwrap())
            .collect::<Vec<_>>();
        let source_addr = *identities[0].node_addr();
        let direct_addr = *identities[1].node_addr();
        let routed_addr = *identities[2].node_addr();
        for target in [1, 2] {
            let remote_addr = *identities[target].node_addr();
            nodes[0]
                .node
                .initiate_session(remote_addr, identities[target].pubkey_full())
                .await
                .unwrap();
            wait_for_session_established(
                &mut nodes,
                0,
                &remote_addr,
                Duration::from_secs(10),
                "counter rekey initiator",
            )
            .await;
            wait_for_session_established(
                &mut nodes,
                target,
                &source_addr,
                Duration::from_secs(10),
                "counter rekey responder",
            )
            .await;
            settle_session_handshake_retransmits(&mut nodes, 0, &remote_addr, target, &source_addr);
            // Authenticated routed return creates the normal fallback-affinity
            // marker, without test-only direct degradation seeding.
            send_endpoint_data_via_dataplane(&mut nodes[target].node, identities[0], vec![9])
                .await
                .unwrap();
            let _ = recv_endpoint_event_while_draining(
                &mut nodes,
                &mut endpoints[0].event_rx,
                Duration::from_secs(5),
                "routed return",
            )
            .await;
            for counter in 0..3 {
                send_endpoint_data_via_dataplane(
                    &mut nodes[0].node,
                    identities[target],
                    vec![counter],
                )
                .await
                .unwrap();
                let event = recv_endpoint_event_while_draining(
                    &mut nodes,
                    &mut endpoints[target].event_rx,
                    Duration::from_secs(5),
                    "counter-bearing payload",
                )
                .await;
                assert_eq!(
                    expect_single_endpoint_data_event(event).payload.as_slice(),
                    vec![counter]
                );
            }
            assert!(
                nodes[0]
                    .node
                    .dataplane
                    .fsp_owner_activity(&remote_addr)
                    .unwrap()
                    .send_counter()
                    > 1
            );
        }
        assert!(
            nodes[0]
                .node
                .session_direct_degradation
                .has_pending_validation(&routed_addr)
        );
        assert_eq!(
            nodes[0].node.dataplane.fsp_owner_next_hop(&routed_addr),
            Some(direct_addr)
        );

        nodes[0]
            .node
            .restart_session_direct_path_validation(direct_addr, Node::now_ms());
        assert!(
            nodes[0]
                .node
                .refresh_dataplane_fsp_owner_routes_via(&direct_addr, Some(direct_addr))
        );
        nodes[0].node.config.node.rekey.after_secs = u64::MAX;
        nodes[0].node.config.node.rekey.after_messages = 1;
        nodes[0].node.check_session_rekey().await;
        let routed_rotating = nodes[0]
            .node
            .get_session(&routed_addr)
            .unwrap()
            .has_rekey_in_progress();
        let direct_rotating = nodes[0]
            .node
            .get_session(&direct_addr)
            .unwrap()
            .has_rekey_in_progress();
        cleanup_nodes(&mut nodes).await;
        assert!(
            !direct_rotating,
            "the staged direct validation must retain its current epoch"
        );
        assert!(
            routed_rotating,
            "healthy routed traffic must rotate despite its persistent fallback-affinity marker"
        );
    });
}
