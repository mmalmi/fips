//! Failed or canceled local completion must consume the scheduled retry budget.
use super::*;
use std::future::Future;

#[test]
fn local_send_errors_exhaust_session_rekey_budget() {
    run_large_stack_async_test("session-rekey-send-errors", || {
        check_budget(false, Phase::Setup)
    });
}

#[test]
fn canceled_sends_exhaust_session_rekey_budget() {
    run_large_stack_async_test("session-rekey-canceled-sends", || {
        check_budget(true, Phase::Setup)
    });
}

#[test]
fn local_send_errors_exhaust_final_message_budget() {
    run_large_stack_async_test("session-finish-send-errors", || {
        check_budget(false, Phase::Finish)
    });
}

#[test]
fn canceled_sends_exhaust_final_message_budget() {
    run_large_stack_async_test("session-finish-canceled-sends", || {
        check_budget(true, Phase::Finish)
    });
}

#[derive(Clone, Copy)]
enum Phase {
    Setup,
    Finish,
}

impl Phase {
    fn retry_state(self, entry: &SessionEntry) -> (u32, u64) {
        match self {
            Self::Setup => (entry.resend_count(), entry.next_resend_at_ms()),
            Self::Finish => (
                entry.rekey_msg3_resend_count(),
                entry.rekey_msg3_next_resend_ms(),
            ),
        }
    }

    async fn resend(self, node: &mut Node, now: u64) {
        match self {
            Self::Setup => node.resend_pending_session_handshakes(now).await,
            Self::Finish => node.resend_pending_session_msg3(now).await,
        }
    }

    fn retained(self, entry: &SessionEntry) -> bool {
        match self {
            Self::Setup => entry.has_rekey_in_progress(),
            Self::Finish => entry.rekey_msg3_payload().is_some(),
        }
    }
}

async fn check_budget(cancel: bool, phase: Phase) {
    let _guard = lock_large_network_test().await;
    let mut nodes = run_tree_test(2, &[(0, 1)], false).await;
    populate_all_coord_caches(&mut nodes);
    let network = if cancel {
        Some(sim_harness::replace_session_100_node_carriers(&mut nodes, &[(0, 1)]).await)
    } else {
        None
    };
    let local = *nodes[0].node.node_addr();
    let remote = *nodes[1].node.node_addr();
    let identity = PeerIdentity::from_pubkey_full(nodes[1].node.identity().pubkey_full());
    nodes[0]
        .node
        .initiate_session(remote, identity.pubkey_full())
        .await
        .unwrap();
    for (index, peer) in [(0, remote), (1, local)] {
        wait_for_session_established(
            &mut nodes,
            index,
            &peer,
            Duration::from_secs(10),
            "retry budget initial session",
        )
        .await;
    }
    drain_to_quiescence(&mut nodes).await;
    settle_session_handshake_retransmits(&mut nodes, 0, &remote, 1, &local);
    nodes[0]
        .node
        .config
        .node
        .rate_limit
        .handshake_resend_interval_ms = 1_000;
    nodes[0]
        .node
        .config
        .node
        .rate_limit
        .handshake_resend_backoff = 2.0;
    nodes[0].node.config.node.rate_limit.handshake_max_resends = 5;
    assert!(nodes[0].node.initiate_session_rekey(&remote).await);
    if matches!(phase, Phase::Finish) {
        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                for index in [1, 0] {
                    process_available_packets_for_node(&mut nodes[index]).await;
                }
                // Unrelated link packets do not prove that the ACK arrived.
                // Stop before the responder can consume the final message.
                if nodes[0]
                    .node
                    .get_session(&remote)
                    .unwrap()
                    .pending_new_session()
                    .is_some()
                {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("the rekey acknowledgement installs a pending session");
    }
    assert!(wait_drop_queued_packets_for_node(&mut nodes[1]).await > 0);
    let original_k = nodes[0].node.get_session(&remote).unwrap().current_k_bit();

    // Only the retry clock is controlled. Establishment, encryption and sends
    // use production code over UDP or the existing delayed-completion carrier.
    let start = phase
        .retry_state(nodes[0].node.get_session(&remote).unwrap())
        .1
        - 1_000;
    let source = nodes[0].addr.as_str().unwrap().to_string();
    if let Some(network) = &network {
        network.set_node_send_completion_delay(&source, 60_000);
    } else {
        let transport_id = nodes[0].transport_id;
        nodes[0]
            .node
            .transports
            .get_mut(&transport_id)
            .unwrap()
            .stop()
            .await
            .unwrap();
    }
    for (index, offset) in [1_000, 3_000, 7_000, 15_000, 31_000]
        .into_iter()
        .enumerate()
    {
        let due = start + offset;
        phase.resend(&mut nodes[0].node, due - 1).await;
        assert_eq!(
            phase
                .retry_state(nodes[0].node.get_session(&remote).unwrap())
                .0,
            index as u32
        );
        if let Some(network) = &network {
            cancel_after_delivery(network, phase.resend(&mut nodes[0].node, due)).await;
        } else {
            phase.resend(&mut nodes[0].node, due).await;
        }
        let entry = nodes[0].node.get_session(&remote).unwrap();
        assert_eq!(
            phase.retry_state(entry).0,
            index as u32 + 1,
            "each due local attempt consumes its budget"
        );
        assert_eq!(phase.retry_state(entry).1, due + (1_000 << (index + 1)));
        assert!(phase.retained(entry));
        assert_eq!(entry.current_k_bit(), original_k);
    }
    phase.resend(&mut nodes[0].node, start + 62_999).await;
    assert!(phase.retained(nodes[0].node.get_session(&remote).unwrap()));
    phase.resend(&mut nodes[0].node, start + 63_000).await;
    let entry = nodes[0].node.get_session(&remote).unwrap();
    assert!(entry.is_established());
    assert!(!entry.has_rekey_in_progress());
    assert!(entry.handshake_payload().is_none());
    assert!(entry.rekey_msg3_payload().is_none());
    assert_eq!(
        entry.pending_new_session().is_some(),
        matches!(phase, Phase::Finish)
    );
    assert_eq!(entry.current_k_bit(), original_k);

    if let Some(network) = &network {
        network.set_node_send_completion_delay(&source, 0);
        if matches!(phase, Phase::Setup) {
            assert!(wait_drop_queued_packets_for_node(&mut nodes[1]).await > 0);
            assert!(nodes[0].node.initiate_session_rekey(&remote).await);
        }
        tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                process_available_packets(&mut nodes).await;
                for node in &mut nodes {
                    node.node.check_session_rekey().await;
                }
                nodes[1].node.send_coords_warmup(&local).await.unwrap();
                if nodes[0].node.get_session(&remote).unwrap().current_k_bit() != original_k
                    && nodes[1].node.get_session(&local).unwrap().current_k_bit() != original_k
                {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("retained replacement epoch must authenticate and cut over");
        let mut destination = nodes[1].node.attach_endpoint_data_io(16).unwrap();
        send_endpoint_data_via_dataplane(&mut nodes[0].node, identity, b"after-budget".to_vec())
            .await
            .unwrap();
        let event = recv_endpoint_event_while_draining(
            &mut nodes,
            &mut destination.event_rx,
            Duration::from_secs(10),
            "fresh traffic after bounded local failures",
        )
        .await;
        assert_eq!(
            expect_single_endpoint_data_event(event).payload.as_slice(),
            b"after-budget"
        );
    }
    cleanup_nodes(&mut nodes).await;
    if network.is_some() {
        crate::unregister_sim_network(sim_harness::SESSION_100_NODE_NETWORK);
    }
}

async fn cancel_after_delivery<F: Future>(network: &crate::SimNetwork, operation: F) {
    let before = network.stats().packets_sent;
    tokio::pin!(operation);
    tokio::time::timeout(Duration::from_secs(5), async {
        tokio::select! {
            _ = &mut operation => panic!("send must still await its delayed completion"),
            _ = async {
                while network.stats().packets_delivered <= before {
                    tokio::time::sleep(Duration::from_millis(1)).await;
                }
            } => {}
        }
    })
    .await
    .expect("handshake must reach the real simulated transport");
    // Dropping the incomplete operation models the RX maintenance deadline.
}
