use super::*;
use crate::node::session::{EndToEndState, SessionEntry};

fn snapshot_node(peer_count: usize) -> (Node, Vec<NodeAddr>) {
    let mut node = Node::new(Config::new()).expect("node");
    let mut addrs = Vec::new();
    for i in 0..peer_count {
        let remote = Identity::generate();
        let addr = *remote.node_addr();
        let peer = PeerIdentity::from_pubkey_full(remote.pubkey_full());
        node.peers
            .insert(addr, ActivePeer::new(peer, LinkId::new(i as u64 + 1), 0));
        let session = make_test_fmp_session(&node.identity, &remote, [1; 8], [2; 8]);
        node.sessions.insert(
            addr,
            SessionEntry::new(
                addr,
                remote.pubkey_full(),
                EndToEndState::Established(session),
                1_000,
                true,
            ),
        );
        addrs.push(addr);
        match i % 4 {
            0 => seed_dataplane_fsp_data_sent_for_test(&mut node, addr, addr, 1_000),
            1 => seed_dataplane_fsp_data_sent_for_test(&mut node, addr, addrs[0], 1_000),
            2 => ensure_dataplane_fsp_owner_for_test(&mut node, addr),
            _ => {}
        }
    }
    (node, addrs)
}

async fn snapshot(node: &mut Node) -> Vec<crate::node::NodeEndpointPeer> {
    let (response_tx, response_rx) = tokio::sync::oneshot::channel();
    node.handle_endpoint_control(crate::node::NodeEndpointControlCommand::PeerSnapshot {
        response_tx,
    })
    .await;
    response_rx.await.expect("peer snapshot response")
}

#[tokio::test]
async fn endpoint_peer_snapshot_preserves_route_selection_and_missing_activity() {
    let (mut node, addrs) = snapshot_node(8);
    // Multiple sessions can use one carrier. Preserve the existing first-session
    // selection, including its preference when both direct and routed traffic exist.
    let first = node
        .sessions
        .iter()
        .find(|(dest, _)| **dest == addrs[0] || **dest == addrs[1] || **dest == addrs[5])
        .unwrap()
        .0;
    let shared_route = if *first == addrs[0] {
        "direct"
    } else {
        "fallback"
    };
    let result = snapshot(&mut node).await;
    assert_eq!(result.len(), 8);
    for peer in result {
        let expected = if peer.node_addr == addrs[0] {
            Some(shared_route)
        } else if peer.node_addr == addrs[4] {
            Some("direct")
        } else {
            None
        };
        assert_eq!(peer.last_outbound_route.as_deref(), expected);
    }

    // A dataplane owner can outlive its session; it must not leak into status.
    for addr in [addrs[0], addrs[1], addrs[5]] {
        node.sessions.remove(&addr);
    }
    let result = snapshot(&mut node).await;
    assert!(
        result
            .iter()
            .find(|peer| peer.node_addr == addrs[0])
            .unwrap()
            .last_outbound_route
            .is_none()
    );
}

#[tokio::test]
#[ignore = "bounded production-handler benchmark; run separately from timing-sensitive tests"]
async fn endpoint_peer_snapshot_425_peer_benchmark() {
    let (mut node, _) = snapshot_node(425);
    for _ in 0..5 {
        std::hint::black_box(snapshot(&mut node).await);
    }
    let mut samples = Vec::new();
    for _ in 0..7 {
        let start = std::time::Instant::now();
        for _ in 0..20 {
            let peers = snapshot(&mut node).await;
            assert_eq!(peers.len(), 425);
            std::hint::black_box(peers);
        }
        samples.push(start.elapsed().as_nanos() / 20);
    }
    samples.sort_unstable();
    println!(
        "peer_snapshot_benchmark peers=425 sessions=425 samples_ns={samples:?} median_ns={}",
        samples[3]
    );
}
