//! Retention observes admission, independently of normal cryptographic renewal.
use super::*;

#[test]
fn useful_neighbor_retention_accepts_rekey_and_detects_same_process_rejoin() {
    run_large_stack_async_test("rotation-adjacency-retention", || async {
        let _guard = lock_large_network_test().await;
        let name = format!("rotation-retention-{}", std::process::id());
        let network = SimNetwork::new(197);
        network.set_default_link(SimLink {
            up: false,
            ..Default::default()
        });
        for (a, b) in [(0, 2), (1, 3)] {
            network.set_link(ADDRESSES[a], ADDRESSES[b], SimLink::default());
        }
        register_sim_network(name.clone(), network);
        let mut nodes = Vec::new();
        for (i, address) in ADDRESSES[..6].iter().enumerate() {
            nodes.push(make_node(&name, address, i < 2).await);
        }
        let result = AssertUnwindSafe(exercise_retention(&mut nodes))
            .catch_unwind()
            .await;
        cleanup_nodes(&mut nodes).await;
        unregister_sim_network(&name);
        if let Err(panic) = result {
            std::panic::resume_unwind(panic);
        }
    });
}

async fn connected(nodes: &mut [TestNode], ids: &[PeerIdentity]) {
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            turn(nodes).await;
            if [(0, 2), (1, 3)].into_iter().all(|(a, b)| {
                nodes[a]
                    .node
                    .get_peer(ids[b].node_addr())
                    .is_some_and(|peer| {
                        nodes[b]
                            .node
                            .get_peer(ids[a].node_addr())
                            .is_some_and(|other| {
                                peer.our_index() == other.their_index()
                                    && peer.their_index() == other.our_index()
                            })
                    })
                    && nodes[a].node.connection_count() == 0
                    && nodes[b].node.connection_count() == 0
            }) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("real reciprocal handshakes finish");
}

async fn exercise_retention(nodes: &mut [TestNode]) {
    let ids = identities(nodes);
    for (a, b) in [(0, 2), (1, 3)] {
        dial(nodes, a, b).await;
    }
    connected(nodes, &ids).await;
    let mut endpoints: Vec<_> = nodes
        .iter_mut()
        .map(|n| n.node.attach_endpoint_data_io(16).unwrap())
        .collect();
    local_round(nodes, &mut endpoints, &ids, 1, &LOCAL_FLOWS).await;
    let original: Vec<_> = (0..2).map(|i| original_owner(nodes, &ids, i)).collect();
    let old_indices: Vec<_> = (0..2)
        .map(|i| {
            nodes[i]
                .node
                .get_peer(ids[i + 2].node_addr())
                .unwrap()
                .our_index()
        })
        .collect();
    for (a, b) in [(0, 2), (1, 3)] {
        assert!(nodes[a].node.initiate_rekey(ids[b].node_addr()).await);
    }
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            for node in nodes.iter_mut() {
                node.node.check_rekey().await;
            }
            for (a, b) in LOCAL_FLOWS {
                nodes[a]
                    .node
                    .send_dataplane_fmp_link_plaintext(
                        ids[b].node_addr(),
                        &[crate::protocol::LinkMessageType::Heartbeat.to_byte()],
                        false,
                    )
                    .await
                    .unwrap();
            }
            turn(nodes).await;
            if (0..2).all(|i| {
                nodes[i]
                    .node
                    .get_peer(ids[i + 2].node_addr())
                    .unwrap()
                    .our_index()
                    != old_indices[i]
                    && [i, i + 2].into_iter().all(|at| {
                        let remote = if at == i { i + 2 } else { i };
                        nodes[at]
                            .node
                            .dataplane_fmp_link_metrics(ids[remote].node_addr(), Instant::now())
                            .is_some_and(|metrics| metrics.current_epoch_authenticated)
                    })
            }) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("both real rekeys authenticate new keys at both ends");
    local_round(nodes, &mut endpoints, &ids, 2, &LOCAL_FLOWS).await;
    useful_retained(nodes, &ids, &original);
    caps(nodes);

    // Same identity and startup epoch, but a genuine authenticated departure
    // followed by a new handshake must not count as retaining the old neighbor.
    let epoch = nodes[2].node.startup_epoch;
    let disconnect = crate::protocol::Disconnect::new(crate::protocol::DisconnectReason::Shutdown);
    for (a, b) in [(0, 2), (2, 0)] {
        nodes[a]
            .node
            .send_dataplane_fmp_link_plaintext(ids[b].node_addr(), &disconnect.encode(), false)
            .await
            .unwrap();
    }
    tokio::time::timeout(Duration::from_secs(1), async {
        while nodes[0].node.get_peer(ids[2].node_addr()).is_some()
            || nodes[2].node.get_peer(ids[0].node_addr()).is_some()
        {
            turn(nodes).await;
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("real encrypted Disconnects retire both admissions");
    caps(nodes);
    dial(nodes, 0, 2).await;
    connected(nodes, &ids).await;
    assert_eq!(nodes[2].node.startup_epoch, epoch);
    assert_ne!(
        original_owner(nodes, &ids, 0),
        original[0],
        "same-process rejoin is a new admission, not retention"
    );
    assert_eq!(original_owner(nodes, &ids, 1), original[1]);
    local_round(nodes, &mut endpoints, &ids, 3, &LOCAL_FLOWS).await;
    caps(nodes);
}
