//! Cancel local completion after a real encrypted handshake packet is delivered.
use super::*;
use std::future::Future;

#[path = "handshake_retention_ready.rs"]
mod ready;

#[derive(Clone, Copy, Debug)]
enum Stage {
    Setup,
    Ack,
    Msg3,
    DuplicateAck,
}

async fn cancel_after_delivery<F: Future>(
    receiver: &mut TestNode,
    source: &NodeAddr,
    stage: Stage,
    operation: F,
) -> ready::Delivery {
    tokio::pin!(operation);
    tokio::time::timeout(Duration::from_secs(5), async {
        tokio::select! {
            _ = &mut operation => panic!("send must still await its delayed completion"),
            delivered = ready::capture(receiver, source, stage) => delivered,
        }
    })
    .await
    .expect("selected handshake must reach the real simulated transport")
    // Dropping the incomplete operation models the RX maintenance deadline.
}

async fn run_case(stage: Stage, rekey: bool, cancel: bool) {
    let _guard = lock_large_network_test().await;
    let mut nodes = run_tree_test(2, &[(0, 1)], false).await;
    populate_all_coord_caches(&mut nodes);
    let network = sim_harness::replace_session_100_node_carriers(&mut nodes, &[(0, 1)]).await;
    let remote = *nodes[1].node.node_addr();
    let local = *nodes[0].node.node_addr();
    let identity = PeerIdentity::from_pubkey_full(nodes[1].node.identity().pubkey_full());
    let mut destination = nodes[1].node.attach_endpoint_data_io(16).unwrap();

    if rekey {
        nodes[0]
            .node
            .initiate_session(remote, identity.pubkey_full())
            .await
            .unwrap();
        wait_for_session_established(
            &mut nodes,
            0,
            &remote,
            Duration::from_secs(10),
            "initial initiator",
        )
        .await;
        wait_for_session_established(
            &mut nodes,
            1,
            &local,
            Duration::from_secs(10),
            "initial responder",
        )
        .await;
        settle_session_handshake_retransmits(&mut nodes, 0, &remote, 1, &local);
        drain_to_quiescence(&mut nodes).await;
    }
    if !matches!(stage, Stage::Setup) {
        begin(&mut nodes[0].node, identity, rekey).await;
    }
    if matches!(stage, Stage::Msg3 | Stage::DuplicateAck) {
        ready::wait_for_sent(&mut nodes[1], &local, Stage::Ack, rekey).await;
    }
    let duplicate_ack = if matches!(stage, Stage::DuplicateAck) {
        assert!(!rekey);
        let payload = nodes[1]
            .node
            .sessions
            .get(&local)
            .unwrap()
            .handshake_payload()
            .unwrap()
            .to_vec();
        ready::wait_for_sent(&mut nodes[0], &remote, Stage::Msg3, false).await;
        Some(payload)
    } else {
        None
    };
    let sender = if matches!(stage, Stage::Ack) { 1 } else { 0 };
    let source = nodes[sender].addr.as_str().unwrap().to_string();
    if cancel {
        network.set_node_send_completion_delay(&source, 60_000);
        let (left, right) = nodes.split_at_mut(1);
        let (source_node, receiver) = if sender == 0 {
            (&mut left[0], &mut right[0])
        } else {
            (&mut right[0], &mut left[0])
        };
        let source_id = *source_node.node.node_addr();
        let destination = *receiver.node.node_addr();
        let delivered = match stage {
            Stage::Setup => {
                cancel_after_delivery(
                    receiver,
                    &source_id,
                    stage,
                    begin(&mut source_node.node, identity, rekey),
                )
                .await
            }
            Stage::Ack | Stage::Msg3 => {
                cancel_after_delivery(
                    receiver,
                    &source_id,
                    stage,
                    ready::drive(source_node, &destination, stage, rekey),
                )
                .await
            }
            Stage::DuplicateAck => {
                cancel_after_delivery(
                    receiver,
                    &source_id,
                    stage,
                    source_node
                        .node
                        .handle_session_payload(LocalSessionPayload::new(
                            remote,
                            remote,
                            duplicate_ack.as_ref().unwrap(),
                        )),
                )
                .await
            }
        };
        network.set_node_send_completion_delay(&source, 0);
        delivered.assert_retained(&source_node.node, &destination, stage, rekey);
        delivered.release(receiver).await;
    } else {
        assert!(matches!(stage, Stage::Setup));
        begin(&mut nodes[0].node, identity, rekey).await;
    }

    let peer = if sender == 0 { remote } else { local };
    let entry = nodes[sender]
        .node
        .sessions
        .get(&peer)
        .unwrap_or_else(|| panic!("{stage:?}: canceled send discarded live handshake state"));
    if rekey {
        assert!(
            entry.is_established(),
            "cancellation must preserve the current epoch"
        );
        match stage {
            Stage::Setup | Stage::Ack => {
                assert!(
                    entry.has_rekey_in_progress(),
                    "{stage:?}: retain the rekey generation"
                );
                assert!(entry.handshake_payload().is_some());
                assert_eq!(
                    entry.is_rekey_handshake_initiator(),
                    matches!(stage, Stage::Setup)
                );
            }
            Stage::DuplicateAck => unreachable!("initial handshake replay only"),
            Stage::Msg3 => {
                assert!(entry.pending_new_session().is_some());
                assert!(entry.rekey_msg3_payload().is_some());
            }
        }
        tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                process_available_packets(&mut nodes).await;
                run_session_retransmit_work(&mut nodes).await;
                for node in &mut nodes {
                    node.node.check_session_rekey().await;
                }
                nodes[1].node.send_coords_warmup(&local).await.unwrap();
                if nodes[0].node.sessions.get(&remote).unwrap().current_k_bit()
                    && nodes[1].node.sessions.get(&local).unwrap().current_k_bit()
                {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("both peers must authenticate and promote the retained rekey");
    } else {
        assert!(
            entry.handshake_payload().is_some(),
            "retry keeps the same Noise generation"
        );
        match stage {
            Stage::Setup => assert!(entry.is_initiating()),
            Stage::Ack => assert!(entry.is_awaiting_msg3()),
            Stage::Msg3 | Stage::DuplicateAck => assert!(entry.is_established()),
        }
    }
    send_endpoint_data_via_dataplane(
        &mut nodes[0].node,
        identity,
        b"after-canceled-send".to_vec(),
    )
    .await
    .unwrap();
    let event = recv_endpoint_event_while_draining(
        &mut nodes,
        &mut destination.event_rx,
        Duration::from_secs(10),
        "handshake recovery after canceled send",
    )
    .await;
    assert_eq!(
        expect_single_endpoint_data_event(event).payload.as_slice(),
        b"after-canceled-send"
    );
    assert!(
        nodes[0]
            .node
            .sessions
            .get(&remote)
            .unwrap()
            .is_established()
    );
    assert!(nodes[1].node.sessions.get(&local).unwrap().is_established());
    cleanup_nodes(&mut nodes).await;
    crate::unregister_sim_network(sim_harness::SESSION_100_NODE_NETWORK);
}

#[test]
fn canceled_setup_retains_state_and_completes_the_same_handshake() {
    run_large_stack_async_test("canceled-setup", || run(Stage::Setup, false));
}
#[test]
fn canceled_ack_retains_state_and_completes_the_same_handshake() {
    run_large_stack_async_test("canceled-ack", || run(Stage::Ack, false));
}
#[test]
fn canceled_msg3_retains_state_and_completes_the_same_handshake() {
    run_large_stack_async_test("canceled-msg3", || run(Stage::Msg3, false));
}

async fn begin(node: &mut Node, remote: PeerIdentity, rekey: bool) {
    if rekey {
        assert!(node.initiate_session_rekey(remote.node_addr()).await);
    } else {
        node.initiate_session(*remote.node_addr(), remote.pubkey_full())
            .await
            .unwrap();
    }
}

#[test]
fn canceled_rekey_setup_retains_both_epochs_and_delivers_after_cutover() {
    run_large_stack_async_test("canceled-rekey-setup", || run(Stage::Setup, true));
}
#[test]
fn canceled_rekey_ack_retains_both_epochs_and_delivers_after_cutover() {
    run_large_stack_async_test("canceled-rekey-ack", || run(Stage::Ack, true));
}
#[test]
fn canceled_rekey_msg3_retains_both_epochs_and_delivers_after_cutover() {
    run_large_stack_async_test("canceled-rekey-msg3", || run(Stage::Msg3, true));
}

#[test]
fn canceled_duplicate_ack_reply_preserves_the_established_session() {
    run_large_stack_async_test("canceled-duplicate-ack", || run(Stage::DuplicateAck, false));
}

async fn run(stage: Stage, rekey: bool) {
    run_case(stage, rekey, true).await;
}

#[test]
fn undelayed_rekey_completes_on_the_same_simulated_carrier() {
    run_large_stack_async_test("undelayed-rekey", || run_case(Stage::Setup, true, false));
}
