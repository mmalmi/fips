//! Cached replies must bypass the bounded queue read by the same Node actor.
use super::*;
use crate::SessionMessageType;
use crate::dataplane::{DataplaneLiveNodeTurn, DataplaneLiveTurnFirsts};
use crate::discovery::nostr::{
    MeshTraversalSignal, NostrDiscovery, TraversalAnswer, TraversalOffer,
};
use crate::node::tests::spanning_tree::process_node_packets;
use futures::FutureExt;
use std::panic::AssertUnwindSafe;
use std::sync::Arc;

#[test]
fn cached_mesh_answer_crosses_encrypted_session_while_signal_queue_stays_full() {
    run_large_stack_async_test("cached-mesh-answer", || async {
        let mut nodes = run_tree_test(2, &[(0, 1)], false).await;
        let result = AssertUnwindSafe(exercise(&mut nodes)).catch_unwind().await;
        cleanup_nodes(&mut nodes).await;
        if let Err(panic) = result {
            std::panic::resume_unwind(panic);
        }
    });
}

async fn exercise(nodes: &mut [TestNode]) {
    populate_all_coord_caches(nodes);
    let receiver = PeerIdentity::from_pubkey_full(nodes[1].node.identity().pubkey_full());
    let sender = *nodes[0].node.node_addr();
    let _sender_endpoint = nodes[0].node.attach_endpoint_data_io(8).unwrap();
    let mut receiver_endpoint = nodes[1].node.attach_endpoint_data_io(8).unwrap();
    send_endpoint_data_via_dataplane(&mut nodes[0].node, receiver, b"warm-session".to_vec())
        .await
        .unwrap();
    let _ = recv_endpoint_event_while_draining(
        nodes,
        &mut receiver_endpoint.event_rx,
        Duration::from_secs(5),
        "real encrypted session before cached offer",
    )
    .await;
    drain_to_quiescence(nodes).await;
    let discovery = Arc::new(NostrDiscovery::new_for_test_with_identity(
        nodes[1].node.identity(),
    ));
    let now = Node::now_ms();
    let offer = TraversalOffer {
        message_type: "offer".into(),
        session_id: "cached-inline-session".into(),
        issued_at: now,
        expires_at: now + 60_000,
        nonce: "cached-inline-offer".into(),
        sender_npub: nodes[0].node.identity().npub(),
        recipient_npub: receiver.npub(),
        reflexive_address: None,
        local_addresses: Vec::new(),
        stun_server: None,
    };
    let answer = TraversalAnswer {
        message_type: "answer".into(),
        session_id: offer.session_id.clone(),
        issued_at: now,
        expires_at: now + 60_000,
        nonce: "cached-inline-answer".into(),
        sender_npub: receiver.npub(),
        recipient_npub: offer.sender_npub.clone(),
        in_reply_to: offer.nonce.clone(),
        accepted: false,
        reflexive_address: None,
        local_addresses: Vec::new(),
        stun_server: None,
        punch: None,
        reason: Some("test".into()),
        offer_received_at: Some(now),
    };
    discovery.cache_mesh_answer_for_test(&offer, &answer).await;
    let mut sentinel = answer.clone();
    sentinel.session_id = "already-queued-sentinel".into();
    let queued_signal = MeshTraversalSignal::Answer {
        peer_npub: offer.sender_npub.clone(),
        answer: sentinel.clone(),
    };
    let mut queued = 0;
    while discovery.push_mesh_signal_for_test(queued_signal.clone()) {
        queued += 1;
    }
    assert!(queued > 0);
    nodes[1].node.nostr_discovery = Some(discovery.clone());
    nodes[0]
        .node
        .send_session_msg(
            receiver.node_addr(),
            SessionMessageType::TraversalOffer.to_byte(),
            &serde_json::to_vec(&offer).unwrap(),
        )
        .await
        .unwrap();
    // Only drive authenticated ingress; the actor's discovery queue reader
    // cannot run until this handler completes, so never drain it concurrently.
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            let node = &mut nodes[1];
            process_node_packets(&mut node.node, &mut node.packet_rx).await;
            if discovery.received_mesh_offer_count_for_test() == 1 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    })
    .await
    .expect("inline Node receive returns despite full mesh signal queue");
    assert!(!discovery.push_mesh_signal_for_test(queued_signal.clone()));
    let received = tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            let mut turn = native_turn(&mut nodes[0]).await;
            assert!(turn.raw_ingress_drops().is_empty());
            assert!(turn.drops().is_empty(), "response must authenticate");
            let (_, _, sessions) = turn.take_fsp_authenticated_ingress().into_parts();
            for ingress in sessions {
                let (source, peer, _, _, _, _, kind, _, plaintext) = ingress.into_parts();
                if kind == SessionMessageType::TraversalAnswer.to_byte() {
                    assert_eq!(source, *receiver.node_addr());
                    assert_eq!(*peer.node_addr(), *receiver.node_addr());
                    let (_, parsed_kind, _, body) =
                        crate::node::session_wire::fsp_strip_inner_header(plaintext.as_slice())
                            .expect("authenticated session header");
                    assert_eq!(parsed_kind, kind);
                    return serde_json::from_slice::<TraversalAnswer>(body).unwrap();
                }
            }
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    })
    .await
    .expect("cached answer travels through real FSP encryption and UDP");
    assert_eq!(received, answer);
    assert_ne!(sender, *receiver.node_addr());
    assert!(!discovery.push_mesh_signal_for_test(queued_signal));
    let retained = discovery.drain_mesh_signals().await;
    assert_eq!(
        retained.len(),
        queued,
        "no queued signal was consumed or lost"
    );
    for signal in retained {
        assert!(matches!(signal, MeshTraversalSignal::Answer { answer, .. } if answer == sentinel));
    }
}

async fn native_turn(node: &mut TestNode) -> DataplaneLiveNodeTurn {
    let mut endpoint_rx = node.node.endpoint_data_rx.take().unwrap();
    let mut tun_rx = node.node.tun_outbound_rx.take().unwrap();
    let (_fast_tx, mut fast_rx) = tokio::sync::mpsc::channel(1);
    let endpoint_tx = node.node.endpoint_events.sender().unwrap();
    let mut io = crate::node::handlers::rx_loop_dataplane_io(
        &mut node.packet_rx,
        &mut fast_rx,
        &mut endpoint_rx,
        &mut tun_rx,
        &endpoint_tx,
    );
    let turn = Box::pin(node.node.drain_dataplane_turn_with_firsts(
        &mut io,
        DataplaneLiveTurnFirsts::default(),
        crate::node::handlers::RxLoopDataplaneTurnLimits::new(64, 0, 0, 64),
    ))
    .await;
    node.node.endpoint_data_rx = Some(endpoint_rx);
    node.node.tun_outbound_rx = Some(tun_rx);
    turn
}
