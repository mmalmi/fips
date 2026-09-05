use super::super::spanning_tree::{cleanup_nodes, process_available_packets, run_tree_test};
use super::*;

#[test]
fn authenticated_fmp_peers_can_rotate_before_the_initial_cross_connection_window() {
    super::super::session::run_large_stack_async_test("fmp-early-rekey", || async {
        // Exercise both address-order winners. Neither side has a pending
        // initial handshake after exchanging authenticated TreeAnnounces.
        for initiator in 0..2 {
            let mut nodes = run_tree_test(2, &[(0, 1)], false).await;
            nodes.sort_by_key(|node| *node.node.node_addr());
            let addresses = [*nodes[0].node.node_addr(), *nodes[1].node.node_addr()];
            for i in 0..2 {
                let peer = nodes[i].node.get_peer(&addresses[1 - i]).unwrap();
                assert!(peer.session_established_at().elapsed() < Duration::from_secs(30));
                assert!(
                    nodes[i]
                        .node
                        .dataplane_fmp_link_metrics(&addresses[1 - i], std::time::Instant::now(),)
                        .unwrap()
                        .rx_packets
                        > 0
                );
            }
            nodes[initiator].node.config.node.rekey.after_secs = 0;
            nodes[initiator]
                .node
                .get_peer_mut(&addresses[1 - initiator])
                .unwrap()
                .set_rekey_jitter_secs_for_test(0);
            nodes[initiator].node.check_rekey().await;
            assert!(
                nodes[initiator]
                    .node
                    .get_peer(&addresses[1 - initiator])
                    .unwrap()
                    .rekey_in_progress()
            );

            complete_rekey(&mut nodes).await;
            cleanup_nodes(&mut nodes).await;
        }
    });
}

async fn complete_rekey(nodes: &mut [super::super::spanning_tree::TestNode]) {
    let addresses = [*nodes[0].node.node_addr(), *nodes[1].node.node_addr()];
    let indices = [
        nodes[0].node.get_peer(&addresses[1]).unwrap().our_index(),
        nodes[1].node.get_peer(&addresses[0]).unwrap().our_index(),
    ];
    tokio::time::timeout(Duration::from_secs(1), async {
        loop {
            process_available_packets(nodes).await;
            if (0..2).all(|i| {
                nodes[i]
                    .node
                    .get_peer(&addresses[1 - i])
                    .unwrap()
                    .pending_new_session()
                    .is_some()
            }) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    })
    .await
    .expect("both peers must own the same pending rekey before cutover");
    for i in 0..2 {
        assert_eq!(
            nodes[i]
                .node
                .get_peer(&addresses[1 - i])
                .unwrap()
                .our_index(),
            indices[i]
        );
    }

    tokio::time::timeout(Duration::from_secs(1), async {
        loop {
            for i in 0..2 {
                nodes[i].node.check_rekey().await;
                nodes[i]
                    .node
                    .send_dataplane_fmp_link_plaintext(
                        &addresses[1 - i],
                        &[crate::protocol::LinkMessageType::Heartbeat.to_byte()],
                        false,
                    )
                    .await
                    .unwrap();
            }
            process_available_packets(nodes).await;
            if (0..2).all(|i| {
                nodes[i]
                    .node
                    .get_peer(&addresses[1 - i])
                    .unwrap()
                    .current_k_bit()
            }) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("authenticated rekey traffic must complete both K-bit cutovers");
}

/// A simultaneous static dial can arrive in the asymmetric production order:
/// the smaller node completes its winning outbound handshake before the
/// larger node's Msg1 reaches it. Endpoint payload trust may already have
/// expired while the late Msg1 was in flight. The late
/// inbound half must still lose the deterministic cross-connection decision;
/// otherwise both endpoints retain responder sessions with unrelated Noise
/// keys and receiver indices.
#[tokio::test]
async fn degraded_late_msg1_keeps_complementary_cross_connection_owner() {
    use crate::node::tests::spanning_tree::{cleanup_nodes, initiate_handshake, make_test_node};
    use crate::node::wire::{Msg1Header, Msg2Header};
    use tokio::time::{Duration, timeout};

    let mut nodes = vec![make_test_node().await, make_test_node().await];
    nodes.sort_by_key(|test_node| *test_node.node.node_addr());

    let smaller_addr = *nodes[0].node.node_addr();
    let larger_addr = *nodes[1].node.node_addr();

    initiate_handshake(&mut nodes, 0, 1).await;
    initiate_handshake(&mut nodes, 1, 0).await;

    let msg1_at_larger = timeout(Duration::from_secs(1), async {
        loop {
            let packet = nodes[1]
                .packet_rx
                .recv()
                .await
                .expect("larger node packet channel open");
            if Msg1Header::parse(packet.data.as_slice()).is_some() {
                break packet;
            }
        }
    })
    .await
    .expect("larger node should receive smaller node Msg1");
    nodes[1].node.handle_msg1(msg1_at_larger).await;

    let mut late_msg1_at_smaller = None;
    let msg2_at_smaller = timeout(Duration::from_secs(1), async {
        loop {
            let packet = nodes[0]
                .packet_rx
                .recv()
                .await
                .expect("smaller node packet channel open");
            if Msg1Header::parse(packet.data.as_slice()).is_some() {
                late_msg1_at_smaller = Some(packet);
                continue;
            }
            if Msg2Header::parse(packet.data.as_slice()).is_some() {
                break packet;
            }
        }
    })
    .await
    .expect("smaller node should complete its outbound handshake first");
    nodes[0].node.handle_msg2(msg2_at_smaller).await;

    // UDP can deliver authenticated current-epoch traffic before a delayed
    // crossed Msg1. Retain complementary ownership in this ordering too.
    timeout(Duration::from_secs(1), async {
        loop {
            crate::node::tests::spanning_tree::process_available_packets(&mut nodes).await;
            if nodes.iter().all(|node| {
                let remote = if node.node.node_addr() == &smaller_addr {
                    larger_addr
                } else {
                    smaller_addr
                };
                node.node
                    .dataplane_fmp_link_metrics(&remote, std::time::Instant::now())
                    .is_some_and(|metrics| metrics.current_epoch_authenticated)
            }) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    })
    .await
    .expect("current epoch must authenticate before the delayed crossed Msg1");

    assert!(
        nodes[0]
            .node
            .get_peer(&larger_addr)
            .is_some_and(|peer| peer.fmp_mmp_is_initiator()),
        "smaller node should initially own its winning outbound session"
    );

    let degraded_at_ms = Node::now_ms();
    crate::node::tests::seed_dataplane_fsp_unreturned_data_for_test(
        &mut nodes[0].node,
        larger_addr,
        larger_addr,
        degraded_at_ms,
    );
    let mut late_msg1_at_smaller = late_msg1_at_smaller.expect("larger node Msg1 retained");
    // The kernel can hold the peer's Msg1 until after endpoint liveness has
    // degraded the newly completed carrier. Preserve that production order
    // rather than the earlier channel-receipt timestamp from this fixture.
    late_msg1_at_smaller.timestamp_ms = degraded_at_ms.saturating_add(1);
    assert!(nodes[0].node.session_direct_path_exclusive_trust_expired(
        &larger_addr,
        late_msg1_at_smaller.timestamp_ms,
    ));
    assert!(
        !nodes[0]
            .node
            .session_direct_degradation
            .has_pending_validation(&larger_addr),
        "exclusive-trust expiry must exercise direct-path recovery, not the rekey branch"
    );
    nodes[0].node.handle_msg1(late_msg1_at_smaller).await;
    let responder = nodes[0].node.get_peer(&larger_addr).unwrap();
    let pending_index = responder
        .pending_our_index()
        .expect("ambiguous Msg1 staged as pending");
    let completed = responder.pending_rekey_completed_at_for_test().unwrap();
    let late_msg2 = responder.handshake_msg2().unwrap().to_vec();
    tokio::time::sleep(Duration::from_millis(1)).await;
    crate::node::tests::spanning_tree::process_available_packets(&mut nodes).await;

    let larger_on_smaller = nodes[0]
        .node
        .get_peer(&larger_addr)
        .expect("smaller node should retain larger peer");
    let smaller_on_larger = nodes[1]
        .node
        .get_peer(&smaller_addr)
        .expect("larger node should retain smaller peer");
    assert!(
        larger_on_smaller.fmp_mmp_is_initiator(),
        "degraded payload state must not replace the smaller node's winning outbound owner"
    );
    assert!(
        !smaller_on_larger.fmp_mmp_is_initiator(),
        "larger node should retain the complementary inbound owner"
    );
    assert_eq!(
        larger_on_smaller.their_index(),
        smaller_on_larger.our_index(),
        "smaller sender index must match the larger receiver owner"
    );
    assert_eq!(
        smaller_on_larger.their_index(),
        larger_on_smaller.our_index(),
        "larger sender index must match the smaller receiver owner"
    );

    let transport_id = nodes[0].transport_id;
    let timeout = Duration::from_secs(nodes[0].node.config.node.rate_limit.handshake_timeout_secs);
    nodes[0]
        .node
        .expire_unconfirmed_fmp_rekeys(completed + timeout - Duration::from_millis(1));
    assert_eq!(
        nodes[0]
            .node
            .get_peer(&larger_addr)
            .unwrap()
            .pending_our_index(),
        Some(pending_index)
    );
    nodes[0]
        .node
        .expire_unconfirmed_fmp_rekeys(completed + timeout);
    assert!(
        nodes[0]
            .node
            .get_peer(&larger_addr)
            .unwrap()
            .pending_new_session()
            .is_none()
    );
    assert!(
        !nodes[0]
            .node
            .peers
            .contains_session_index(&(transport_id, pending_index.as_u32()))
    );
    assert!(nodes[0].node.get_peer(&larger_addr).unwrap().has_session());

    // An already answered initial dial cannot reinstall its old Msg2 after
    // the ambiguous responder epoch expires.
    let indices = [
        nodes[0].node.get_peer(&larger_addr).unwrap().our_index(),
        nodes[1].node.get_peer(&smaller_addr).unwrap().our_index(),
    ];
    let packet = crate::ReceivedPacket::with_timestamp(
        nodes[1].transport_id,
        nodes[0].addr.clone(),
        crate::transport::PacketBuffer::new(late_msg2),
        Node::now_ms(),
    );
    nodes[1].node.handle_msg2(packet).await;
    assert_eq!(
        nodes[0].node.get_peer(&larger_addr).unwrap().our_index(),
        indices[0]
    );
    assert_eq!(
        nodes[1].node.get_peer(&smaller_addr).unwrap().our_index(),
        indices[1]
    );
    assert!(nodes[0].node.initiate_rekey(&larger_addr).await);
    complete_rekey(&mut nodes).await;
    cleanup_nodes(&mut nodes).await;
}
