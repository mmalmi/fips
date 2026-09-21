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

#[test]
fn same_identity_retry_inside_cooldown_keeps_original_candidate_deadline() {
    super::super::super::super::session::run_large_stack_async_test(
        "rotation-restart-inside-cooldown",
        || async {
            use futures::FutureExt;
            use std::panic::AssertUnwindSafe;

            let mut node = make_test_node().await;
            let outcome = AssertUnwindSafe(retry_inside_cooldown(&mut node))
                .catch_unwind()
                .await;
            cleanup_nodes(std::slice::from_mut(&mut node)).await;
            if let Err(panic) = outcome {
                std::panic::resume_unwind(panic);
            }
        },
    );
}

async fn retry_inside_cooldown(node: &mut TestNode) {
    let old = make_node();
    let newcomer = make_node();
    let (_old_socket, old_source) = local_path().await;
    let (new_socket, new_source) = local_path().await;
    // Establish and age the incumbent through actual elapsed time. Neither
    // received timestamps nor the pending attempt's deadline are rewritten.
    let mut old_owner = connect(node, &old, &old_source, 310).await;
    assert_eq!(heartbeat(node, &old, &mut old_owner).await, 1);
    let old_generation = node
        .node
        .get_peer(old.node_addr())
        .unwrap()
        .session_generation();
    enable(node, 1);
    node.node
        .config
        .node
        .neighbor_rotation
        .as_mut()
        .unwrap()
        .interval_secs = 2;
    node.node.config.node.rate_limit.handshake_timeout_secs = 4;
    tokio::time::sleep(Duration::from_millis(1_050)).await;
    assert!(
        node.node
            .discovery_rotation_victim(Node::now_ms())
            .is_some()
    );

    let started = tokio::time::Instant::now();
    let mut candidate = connect(node, &newcomer, &new_source, 311).await;
    let original_activity = node
        .node
        .get_connection(&candidate.link)
        .unwrap()
        .last_activity();
    let original_attempt = node
        .node
        .neighbor_rotation_started_at(newcomer.node_addr())
        .unwrap();
    let response = node
        .node
        .get_connection(&candidate.link)
        .unwrap()
        .handshake_msg2()
        .unwrap()
        .to_vec();
    assert_response(&new_socket, &response).await;
    assert_eq!(resources(node), (1, 1, 2, 2));

    tokio::time::sleep_until(started + Duration::from_millis(500)).await;
    assert!(Node::now_ms().saturating_sub(original_attempt) < 2_000);
    let mut retry = request(node, &newcomer, &new_source, 312).await;
    assert_eq!(
        resources(node),
        (1, 1, 2, 2),
        "a same-identity fresh request inside cooldown must not delete the only pending owner"
    );
    let retained = node.node.peers.connection_values().next().unwrap();
    assert_eq!(
        retained.expected_identity().unwrap().node_addr(),
        newcomer.node_addr()
    );
    assert_eq!(retained.last_activity(), original_activity);
    assert_eq!(
        node.node.neighbor_rotation_started_at(newcomer.node_addr()),
        Some(original_attempt)
    );
    let retained_link = retained.link_id();
    let retained_index = retained.our_index().unwrap();
    assert!(node.node.index_allocator.is_allocated(retained_index));
    assert_eq!(
        node.node.links.lookup_addr(node.transport_id, &new_source),
        Some(retained_link)
    );
    if retained_link == candidate.link {
        // A conservative implementation may reject this request, retaining the
        // exact old candidate rather than creating a replacement during cooldown.
        assert_eq!(retained_index, candidate.index);
        assert_eq!(retained.handshake_msg2(), Some(response.as_slice()));
    } else {
        // Accepting a replacement is also safe when the original authority and
        // deadline survive and the prior index can no longer confirm anything.
        let reply = retained.handshake_msg2().unwrap().to_vec();
        let header = Msg2Header::parse(&reply).unwrap();
        assert_eq!(header.receiver_idx, SessionIndex::new(312));
        retry.read_message_2(header.noise_msg2(&reply)).unwrap();
        assert_response(&new_socket, &reply).await;
        assert!(!node.node.index_allocator.is_allocated(candidate.index));
        let stale = candidate.frame(
            node.transport_id,
            &[crate::protocol::LinkMessageType::Heartbeat.to_byte()],
        );
        assert!(!node.node.confirm_inbound_handshake(stale).await);
        candidate = Candidate {
            link: retained_link,
            index: retained_index,
            session: retry.into_session().unwrap(),
            source: new_source.clone(),
        };
    }
    let incumbent = node.node.get_peer(old.node_addr()).unwrap();
    assert_eq!(
        (
            incumbent.link_id(),
            incumbent.our_index(),
            incumbent.session_generation()
        ),
        (old_owner.link, Some(old_owner.index), old_generation)
    );
    assert!(node.node.index_allocator.is_allocated(old_owner.index));
    assert!(node.node.get_peer(newcomer.node_addr()).is_none());
    assert!(node.node.pending_outbound.is_empty());

    // A later fresh retry is permitted, but it must not turn the failed early
    // retry into a new four-second admission window.
    tokio::time::sleep_until(started + Duration::from_millis(2_100)).await;
    let stale = candidate.frame(
        node.transport_id,
        &[crate::protocol::LinkMessageType::Heartbeat.to_byte()],
    );
    let mut later = connect(node, &newcomer, &new_source, 313).await;
    assert_ne!(later.link, candidate.link);
    assert!(!node.node.index_allocator.is_allocated(candidate.index));
    let retained = node.node.get_connection(&later.link).unwrap();
    assert_eq!(retained.last_activity(), original_activity);
    assert_eq!(
        node.node.neighbor_rotation_started_at(newcomer.node_addr()),
        Some(original_attempt)
    );
    let response = retained.handshake_msg2().unwrap().to_vec();
    assert_response(&new_socket, &response).await;
    assert!(!node.node.confirm_inbound_handshake(stale).await);
    assert_eq!(resources(node), (1, 1, 2, 2));
    assert!(node.node.index_allocator.is_allocated(later.index));
    let proof = later.frame(
        node.transport_id,
        &[crate::protocol::LinkMessageType::Heartbeat.to_byte()],
    );

    tokio::time::sleep_until(started + Duration::from_millis(4_250)).await;
    node.node.check_timeouts().await;
    assert_eq!(
        resources(node),
        (1, 0, 1, 1),
        "the original deadline releases the slot"
    );
    assert!(!node.node.index_allocator.is_allocated(later.index));
    assert!(!node.node.links.contains_key(&later.link));
    assert!(!node.node.confirm_inbound_handshake(proof).await);
    let incumbent = node.node.get_peer(old.node_addr()).unwrap();
    assert_eq!(
        (
            incumbent.link_id(),
            incumbent.our_index(),
            incumbent.session_generation()
        ),
        (old_owner.link, Some(old_owner.index), old_generation)
    );
    assert!(node.node.index_allocator.is_allocated(old_owner.index));
    assert!(node.node.pending_outbound.is_empty());

    // Release is usable: a new bounded admission can prove its fresh Msg2 and
    // replace the idle incumbent through the ordinary promotion path.
    let mut fresh = connect(node, &newcomer, &new_source, 314).await;
    let proof = fresh.frame(
        node.transport_id,
        &[crate::protocol::LinkMessageType::Heartbeat.to_byte()],
    );
    assert!(node.node.confirm_inbound_handshake(proof).await);
    process_available_packets(std::slice::from_mut(node)).await;
    assert_eq!(resources(node), (1, 0, 1, 1));
    assert!(node.node.get_peer(old.node_addr()).is_none());
    assert!(node.node.get_peer(newcomer.node_addr()).is_some());
    assert!(!node.node.index_allocator.is_allocated(old_owner.index));
    assert!(node.node.index_allocator.is_allocated(fresh.index));
    assert_eq!(heartbeat(node, &newcomer, &mut fresh).await, 2);
}
