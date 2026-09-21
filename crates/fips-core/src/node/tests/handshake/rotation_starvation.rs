use super::*;

async fn assert_response(socket: &tokio::net::UdpSocket, expected: &[u8]) {
    let mut response = [0; 512];
    let length = tokio::time::timeout(Duration::from_secs(1), socket.recv(&mut response))
        .await
        .expect("candidate Msg2 response")
        .unwrap();
    assert_eq!(&response[..length], expected);
}

#[test]
fn unconfirmed_restarts_cannot_renew_the_full_roster_candidate_slot() {
    super::super::super::super::session::run_large_stack_async_test(
        "rotation-unconfirmed-restarts",
        || async {
            let mut node = make_test_node().await;
            let old = make_node();
            let active = make_node();
            let attacker = make_node();
            let newcomer = make_node();
            let (_old_socket, old_source) = local_path().await;
            let (_active_socket, active_source) = local_path().await;
            let (attack_socket, attack_source) = local_path().await;
            let (_other_socket, other_source) = local_path().await;
            let (_new_socket, new_source) = local_path().await;
            let old_owner = incumbent(&mut node, &old, &old_source, 110, 60_000).await;
            let mut active_owner = incumbent(&mut node, &active, &active_source, 111, 50_000).await;
            let active_generation = node
                .node
                .get_peer(active.node_addr())
                .unwrap()
                .session_generation();
            enable(&mut node, 2);
            node.node
                .config
                .node
                .neighbor_rotation
                .as_mut()
                .unwrap()
                .interval_secs = 1;
            node.node.config.node.rate_limit.handshake_timeout_secs = 3;

            // Keep the real Noise response, but withhold its encrypted confirmation.
            let mut candidate = connect(&mut node, &attacker, &attack_source, 112).await;
            let conn = node.node.get_connection(&candidate.link).unwrap();
            let original_activity = conn.last_activity();
            let mut msg1 = conn.handshake_msg1().unwrap().to_vec();
            let mut msg2 = conn.handshake_msg2().unwrap().to_vec();
            let started = tokio::time::Instant::now();
            assert_response(&attack_socket, &msg2).await;
            assert_eq!(resources(&node), (2, 1, 3, 3));

            for round in 1..=2 {
                tokio::time::sleep_until(started + Duration::from_millis(1_050 * round)).await;
                // Lost Msg2 must remain recoverable, without granting more time.
                node.node
                    .handle_msg1(packet(&node, &attack_source, msg1.clone()))
                    .await;
                assert_response(&attack_socket, &msg2).await;

                let _other_path = request(&mut node, &attacker, &other_source, 119).await;
                assert_eq!(resources(&node), (2, 1, 3, 3));
                assert!(node.node.get_connection(&candidate.link).is_some());

                // A fresh sender index and ephemeral key from the same identity
                // can recover within this attempt, without granting more time.
                let old_link = candidate.link;
                let old_index = candidate.index;
                let stale_proof = candidate.frame(
                    node.transport_id,
                    &[crate::protocol::LinkMessageType::Heartbeat.to_byte()],
                );
                candidate = connect(&mut node, &attacker, &attack_source, 120 + round as u32).await;
                assert_ne!(candidate.link, old_link);
                assert!(node.node.get_connection(&old_link).is_none());
                assert!(!node.node.index_allocator.is_allocated(old_index));
                let retained = node.node.get_connection(&candidate.link).unwrap();
                assert_eq!(retained.last_activity(), original_activity);
                msg1 = retained.handshake_msg1().unwrap().to_vec();
                msg2 = retained.handshake_msg2().unwrap().to_vec();
                assert_response(&attack_socket, &msg2).await;
                assert!(!node.node.confirm_inbound_handshake(stale_proof).await);
                assert!(node.node.get_peer(attacker.node_addr()).is_none());

                // Different authenticated identities cannot take the pending slot,
                // whether they reuse its source address or arrive on another path.
                for index in 0..16 {
                    let stranger = make_node();
                    let source = if index % 2 == 0 {
                        &attack_source
                    } else {
                        &other_source
                    };
                    let _request = request(&mut node, &stranger, source, 200 + index).await;
                    assert_eq!(resources(&node), (2, 1, 3, 3));
                    assert!(node.node.get_peer(stranger.node_addr()).is_none());
                    assert!(node.node.get_connection(&candidate.link).is_some());
                }
                assert_eq!(
                    heartbeat(&mut node, &active, &mut active_owner).await,
                    round + 1
                );
                let retained = node.node.get_peer(active.node_addr()).unwrap();
                assert_eq!(retained.link_id(), active_owner.link);
                assert_eq!(retained.session_generation(), active_generation);
                assert_eq!(retained.remote_epoch(), Some(active.startup_epoch));
                assert_eq!(
                    node.node.get_peer(old.node_addr()).unwrap().our_index(),
                    Some(old_owner.index)
                );
            }

            // Use the production timeout, not a fabricated failed state or age.
            tokio::time::sleep_until(started + Duration::from_millis(3_250)).await;
            node.node.check_timeouts().await;
            assert_eq!(resources(&node), (2, 0, 2, 2));
            assert!(!node.node.index_allocator.is_allocated(candidate.index));
            assert!(node.node.pending_outbound.is_empty());

            let mut admitted = connect(&mut node, &newcomer, &new_source, 130).await;
            let proof = admitted.frame(
                node.transport_id,
                &[crate::protocol::LinkMessageType::Heartbeat.to_byte()],
            );
            assert!(node.node.confirm_inbound_handshake(proof).await);
            process_available_packets(std::slice::from_mut(&mut node)).await;
            assert_eq!(resources(&node), (2, 0, 2, 2));
            assert!(node.node.get_peer(attacker.node_addr()).is_none());
            assert!(node.node.get_peer(old.node_addr()).is_none());
            assert!(node.node.get_peer(newcomer.node_addr()).is_some());
            assert_eq!(heartbeat(&mut node, &active, &mut active_owner).await, 4);
            assert_eq!(heartbeat(&mut node, &newcomer, &mut admitted).await, 2);
            cleanup_nodes(std::slice::from_mut(&mut node)).await;
        },
    );
}

#[test]
fn fresh_inbound_can_confirm_before_the_original_deadline() {
    super::super::super::super::session::run_large_stack_async_test(
        "rotation-restarted-confirmation",
        || async {
            let mut node = make_test_node().await;
            let old = make_node();
            let newcomer = make_node();
            let (_old_socket, old_source) = local_path().await;
            let (_new_socket, new_source) = local_path().await;
            incumbent(&mut node, &old, &old_source, 150, 60_000).await;
            enable(&mut node, 1);
            node.node
                .config
                .node
                .neighbor_rotation
                .as_mut()
                .unwrap()
                .interval_secs = 1;
            node.node.config.node.rate_limit.handshake_timeout_secs = 3;
            let mut abandoned = connect(&mut node, &newcomer, &new_source, 151).await;
            let original_activity = node
                .node
                .get_connection(&abandoned.link)
                .unwrap()
                .last_activity();
            let stale = abandoned.frame(
                node.transport_id,
                &[crate::protocol::LinkMessageType::Heartbeat.to_byte()],
            );
            // Respect the normal retry cadence while retaining the first
            // connection deadline for this replacement Noise exchange.
            tokio::time::sleep(Duration::from_millis(1_050)).await;
            let mut restarted = connect(&mut node, &newcomer, &new_source, 152).await;
            assert_ne!(restarted.link, abandoned.link);
            assert_eq!(
                node.node
                    .get_connection(&restarted.link)
                    .unwrap()
                    .last_activity(),
                original_activity,
            );
            assert_eq!(resources(&node), (1, 1, 2, 2));
            assert!(!node.node.confirm_inbound_handshake(stale).await);
            assert!(node.node.get_peer(old.node_addr()).is_some());
            let proof = restarted.frame(
                node.transport_id,
                &[crate::protocol::LinkMessageType::Heartbeat.to_byte()],
            );
            assert!(node.node.confirm_inbound_handshake(proof).await);
            process_available_packets(std::slice::from_mut(&mut node)).await;
            assert_eq!(resources(&node), (1, 0, 1, 1));
            assert!(node.node.get_peer(old.node_addr()).is_none());
            assert!(node.node.get_peer(newcomer.node_addr()).is_some());
            assert_eq!(heartbeat(&mut node, &newcomer, &mut restarted).await, 2);
            cleanup_nodes(std::slice::from_mut(&mut node)).await;
        },
    );
}
