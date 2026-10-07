use super::*;
use crate::node::tests::spanning_tree::{
    process_dataplane_completions, process_dataplane_packet_once,
};
use std::collections::HashSet;

const PACKETS: usize = 10_080;
const RATE: u32 = 140;
const EDGES: [(usize, usize); 4] = [(0, 1), (1, 0), (1, 2), (2, 1)];

#[test]
#[ignore = "72-second real UDP loss/rekey qualification"]
fn repeated_rekeys_keep_lossy_routed_neighbors_live() {
    run_large_stack_async_test("sustained-loss-rekey", || async {
        let _guard = lock_large_network_test().await;
        let mut nodes = vec![
            make_test_node().await,
            make_test_node().await,
            make_test_node().await,
        ];
        nodes.sort_by_key(|node| std::cmp::Reverse(*node.node.node_addr()));
        let result = AssertUnwindSafe(exercise_loss(&mut nodes))
            .catch_unwind()
            .await;
        cleanup_nodes(&mut nodes).await;
        if let Err(panic) = result {
            std::panic::resume_unwind(panic);
        }
    });
}

async fn exercise_loss(nodes: &mut [TestNode]) {
    setup(nodes).await;
    let identities: Vec<_> = nodes
        .iter()
        .map(|n| PeerIdentity::from_pubkey_full(n.node.identity().pubkey_full()))
        .collect();
    let mut endpoints: Vec<_> = nodes
        .iter_mut()
        .map(|n| n.node.attach_endpoint_data_io(256).unwrap())
        .collect();
    for (source, destination) in [(0, 2), (2, 0)] {
        nodes[source]
            .node
            .set_endpoint_source_route(identities[destination], Some(identities[1]))
            .unwrap();
    }
    round(nodes, &mut endpoints, &identities, 0).await;
    drain_to_quiescence(nodes).await;
    let links: Vec<_> = EDGES
        .iter()
        .map(|&(a, b)| {
            nodes[a]
                .node
                .get_peer(identities[b].node_addr())
                .unwrap()
                .link_id()
        })
        .collect();
    let mut epochs: Vec<HashSet<_>> = EDGES
        .iter()
        .map(|&(a, b)| {
            HashSet::from([nodes[a]
                .node
                .get_peer(identities[b].node_addr())
                .unwrap()
                .our_index()])
        })
        .collect();
    let mut session_epochs = [HashSet::new(), HashSet::new()];
    for n in nodes.iter_mut() {
        // Exercise repeated real cutovers without shortening the production
        // drain or dampening windows. Liveness retains its normal timeout.
        n.node.config.node.rekey.after_secs = 2;
        n.node.config.node.rekey.after_messages = 512;
    }
    let start = Instant::now();
    let mut tick = start;
    let mut sent = 0;
    let mut frames = [0usize; 3];
    let mut dropped = [0usize; 3];
    let mut received = [vec![false; PACKETS], vec![false; PACKETS]];
    let mut last_delivery = [start; 2];
    let finish = start + Duration::from_secs(72 + 3);
    while Instant::now() < finish {
        // Limit catch-up bursts so a delayed host cannot silently change the
        // intended stream into a queue-overflow test.
        for _ in 0..4 {
            if sent == PACKETS
                || start.elapsed() < Duration::from_secs_f64(sent as f64 / f64::from(RATE))
            {
                break;
            }
            for (source, destination) in [(0, 2), (2, 0)] {
                let mut payload = vec![source as u8; 1_000];
                payload[..4].copy_from_slice(&(sent as u32).to_be_bytes());
                send_endpoint_data_via_dataplane(
                    &mut nodes[source].node,
                    identities[destination],
                    payload,
                )
                .await
                .unwrap();
            }
            sent += 1;
        }
        let middle = nodes[1].addr.clone();
        for (index, n) in nodes.iter_mut().enumerate() {
            for _ in 0..64 {
                let Ok(packet) = n.packet_rx.try_recv() else {
                    break;
                };
                // Match the physical fixture: every twentieth carrier frame
                // from the middle is lost, including handshake/control frames.
                if index != 1 && packet.remote_addr == middle {
                    frames[index] += 1;
                    if frames[index].is_multiple_of(20) {
                        dropped[index] += 1;
                        continue;
                    }
                }
                process_dataplane_packet_once(&mut n.node, packet).await;
            }
            process_dataplane_completions(&mut n.node).await;
        }
        for (direction, destination) in [2, 0].into_iter().enumerate() {
            let endpoint = &mut endpoints[destination];
            while let Ok(event) = endpoint.event_rx.try_recv() {
                let count = event.message_count();
                for message in event.messages {
                    let payload = message.payload.as_slice();
                    assert_eq!(message.source_peer, identities[2 - destination]);
                    assert_eq!(payload.len(), 1_000);
                    let sequence = u32::from_be_bytes(payload[..4].try_into().unwrap()) as usize;
                    assert!(sequence < sent);
                    assert!(
                        payload[4..]
                            .iter()
                            .all(|b| usize::from(*b) == 2 - destination)
                    );
                    assert!(
                        !std::mem::replace(&mut received[direction][sequence], true),
                        "duplicate payload"
                    );
                    last_delivery[direction] = Instant::now();
                }
                endpoint.event_rx.release_messages(count);
            }
            if sent < PACKETS {
                assert!(
                    last_delivery[direction].elapsed() < Duration::from_secs(5),
                    "direction {direction} stopped delivering during key rotation"
                );
            }
            session_epochs[direction].insert(
                nodes[2 - destination]
                    .node
                    .get_session(identities[destination].node_addr())
                    .unwrap()
                    .session_start_ms(),
            );
        }
        if Instant::now() >= tick {
            tick += Duration::from_secs(1);
            // Preserve the production order of liveness, retries, reports and
            // key changes. The ordinary fixture supplies the routing upkeep.
            for n in nodes.iter_mut() {
                let now = Node::now_ms();
                n.node.check_timeouts().await;
                n.node.check_link_heartbeats().await;
                n.node.resend_pending_handshakes(now).await;
                n.node.resend_pending_rekeys(now).await;
                n.node.resend_pending_session_handshakes(now).await;
                n.node.resend_pending_session_msg3(now).await;
                n.node.retry_pending_session_traffic().await;
                n.node.check_mmp_reports().await;
                n.node.check_session_mmp_reports().await;
                n.node.check_rekey().await;
                n.node.check_session_rekey().await;
                n.node.send_pending_tree_announces().await;
                n.node.check_bloom_state().await;
                n.node.check_pending_lookups(now).await;
            }
        }
        for (edge, &(local, remote)) in EDGES.iter().enumerate() {
            let peer = nodes[local]
                .node
                .get_peer(identities[remote].node_addr())
                .expect("a continuously delivering neighbor must remain present");
            assert!(peer.can_send(), "healthy neighbor became unsendable");
            assert_eq!(peer.link_id(), links[edge], "healthy link was replaced");
            epochs[edge].insert(peer.our_index());
        }
        tokio::time::sleep(Duration::from_millis(1)).await;
    }
    assert_eq!(sent, PACKETS, "host failed to sustain the requested rate");
    let delivered: Vec<_> = received
        .iter()
        .map(|seen| seen.iter().filter(|b| **b).count())
        .collect();
    eprintln!(
        "sustained rekey: sent={sent} each, delivered={delivered:?}, dropped={dropped:?}, link_epochs={:?}, session_epochs={:?}",
        epochs.iter().map(HashSet::len).collect::<Vec<_>>(),
        session_epochs.iter().map(HashSet::len).collect::<Vec<_>>()
    );
    for (direction, destination) in [2, 0].into_iter().enumerate() {
        assert!(delivered[direction] >= PACKETS * 9 / 10);
        assert!(
            PACKETS - delivered[direction] <= dropped[destination],
            "loss exceeded actual injected carrier drops"
        );
        assert!(
            session_epochs[direction].len() >= 3,
            "two real FSP cutovers required"
        );
    }
    assert!(
        epochs.iter().all(|seen| seen.len() >= 3),
        "two real FMP cutovers on every edge required"
    );
    // Loss is off: fresh direct and routed payloads must all arrive exactly once.
    round(nodes, &mut endpoints, &identities, 1).await;
}
