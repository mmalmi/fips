use super::*;
use crate::node::tests::spanning_tree::{initiate_handshake, make_test_node};

/// Advance real UDP/MMP/announcement work, without seeding link measurements or
/// injecting coordinates. Each known neighbor must also know our current path.
async fn converge(nodes: &mut [TestNode], root: NodeAddr, members: usize) -> bool {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    loop {
        process_available_packets(nodes).await;
        for node in nodes.iter_mut() {
            node.node.check_mmp_reports().await;
            node.node.send_pending_tree_announces().await;
            node.node.check_bloom_state().await;
        }
        process_available_packets(nodes).await;
        let converged = nodes[..members].iter().all(|node| {
            *node.node.tree_state().root() == root
                && nodes[..members].iter().all(|other| {
                    node.node.get_peer(other.node.node_addr()).is_none()
                        || other.node.tree_state().peer_coords(node.node.node_addr())
                            == Some(node.node.tree_state().my_coords())
                })
        });
        if converged || tokio::time::Instant::now() >= deadline {
            return converged;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

/// These manually driven nodes have no RX-loop maintenance task. Honor normal
/// Bloom debounce and lookup deadlines without resubmitting application data.
async fn discovery_turn(nodes: &mut [TestNode]) {
    process_available_packets(nodes).await;
    for node in nodes.iter_mut() {
        node.node.check_bloom_state().await;
        node.node.check_pending_lookups(Node::now_ms()).await;
    }
    process_available_packets(nodes).await;
}

fn discovery_diagnostics(nodes: &[TestNode], destination: &NodeAddr) -> Vec<String> {
    nodes.iter().enumerate().map(|(index, node)| {
        let stats = &node.node.stats().discovery;
        let pending = node.node.pending_lookups.contains_key(destination);
        let reachable = node.node.peers.values().filter(|peer| peer.may_reach(destination)).count();
        format!(
            "node={index} pending={pending} bloom_peers={reachable} initiated={} bloom_miss={} received={} forwarded={} no_peer={} target={} sign_limited={} forward_limited={} responses={} accepted={} identity_miss={} proof_failed={} unsolicited={} timeout={}",
            stats.req_initiated, stats.req_bloom_miss, stats.req_received,
            stats.req_forwarded, stats.req_no_tree_peer, stats.req_target_is_us,
            stats.req_sign_rate_limited, stats.req_forward_rate_limited,
            stats.resp_received, stats.resp_accepted, stats.resp_identity_miss,
            stats.resp_proof_failed, stats.resp_unsolicited, stats.resp_timed_out,
        )
    }).collect()
}

#[test]
fn bound_established_payload_waits_for_coordinates_after_root_change() {
    run_large_stack_async_test("fips-bound-coordinate-recovery", || async {
        root_change_recovery(Traffic::Endpoint).await;
    });
}

#[test]
fn bound_established_tun_waits_for_coordinates_after_root_change() {
    run_large_stack_async_test("fips-bound-tun-coordinate-recovery", || async {
        root_change_recovery(Traffic::Tun).await;
    });
}

#[test]
fn reply_learned_payload_keeps_its_carrier_after_root_change() {
    run_large_stack_async_test("fips-reply-learned-coordinate-control", || async {
        root_change_recovery(Traffic::ReplyLearned).await;
    });
}

#[test]
fn direct_payload_needs_no_destination_coordinates_after_root_change() {
    run_large_stack_async_test("fips-direct-coordinate-control", || async {
        root_change_recovery(Traffic::Direct).await;
    });
}

#[derive(Clone, Copy, Debug, PartialEq)]
enum Traffic {
    Endpoint,
    Tun,
    ReplyLearned,
    Direct,
}

fn collect_deliveries(
    traffic: Traffic,
    endpoint: &mut EndpointEventReceiver,
    tun: &crate::upper::tun::TunRx,
    delivered: &mut Vec<Vec<u8>>,
    wrong_path: &mut usize,
) {
    while let Ok(packet) = tun.try_recv_packet() {
        if traffic == Traffic::Tun {
            delivered.push(packet.as_slice().to_vec());
        } else {
            *wrong_path += 1;
        }
    }
    while let Ok(event) = endpoint.try_recv() {
        if traffic == Traffic::Tun {
            *wrong_path += event.messages.len();
        } else {
            delivered.extend(
                event
                    .messages
                    .into_iter()
                    .map(|m| m.payload.as_slice().to_vec()),
            );
        }
    }
}

async fn root_change_recovery(traffic: Traffic) {
    let _guard = lock_large_network_test().await;
    let mut nodes = Vec::new();
    for _ in 0..5 {
        nodes.push(make_test_node().await);
    }
    if traffic == Traffic::ReplyLearned {
        for node in &mut nodes {
            node.node.config.node.routing.mode = RoutingMode::ReplyLearned;
        }
    }
    // The last, initially isolated node will become the new root. The old
    // component is a four-node line so its first transit needs dest coords.
    nodes.sort_by_key(|node| std::cmp::Reverse(*node.node.node_addr()));
    let identities: Vec<_> = nodes
        .iter()
        .map(|node| PeerIdentity::from_pubkey_full(node.node.identity().pubkey_full()))
        .collect();
    for edge in 0..3 {
        initiate_handshake(&mut nodes, edge, edge + 1).await;
    }
    let old_converged = converge(&mut nodes, *identities[3].node_addr(), 4).await;
    if !old_converged {
        cleanup_nodes(&mut nodes).await;
        panic!("real measured old component did not converge");
    }
    let destination_index = if traffic == Traffic::Direct { 1 } else { 3 };
    let source = *identities[0].node_addr();
    let remote = identities[destination_index];
    let destination = *remote.node_addr();
    let source_endpoint = nodes[0].node.attach_endpoint_data_io(8).unwrap();
    let mut destination_endpoint = nodes[destination_index]
        .node
        .attach_endpoint_data_io(8)
        .unwrap();
    let (tun_tx, tun_rx) = crate::upper::tun::write_channel();
    nodes[destination_index].node.tun_tx = Some(tun_tx);
    nodes[0]
        .node
        .set_endpoint_source_route(remote, Some(identities[1]))
        .unwrap();

    // This explicit route query keeps the normal bounded lookup ladder while
    // debounced Bloom announcements catch up with tree convergence.
    nodes[0]
        .node
        .register_identity(destination, remote.pubkey_full());
    nodes[0]
        .node
        .maybe_initiate_route_query_lookup(&destination)
        .await;
    let discovered = tokio::time::timeout(Duration::from_secs(5), async {
        while nodes[0]
            .node
            .coord_cache
            .get(&destination, Node::now_ms())
            .is_none()
        {
            discovery_turn(&mut nodes).await;
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await;
    if discovered.is_err() {
        let discovery = discovery_diagnostics(&nodes, &destination);
        cleanup_nodes(&mut nodes).await;
        panic!("initial authenticated discovery did not complete: {discovery:?}");
    }
    send_endpoint_data_via_dataplane(&mut nodes[0].node, remote, vec![1])
        .await
        .unwrap();
    let first = recv_endpoint_event_while_draining(
        &mut nodes,
        &mut destination_endpoint.event_rx,
        Duration::from_secs(5),
        "establish bound session",
    )
    .await;
    assert_eq!(
        expect_single_endpoint_data_event(first).payload.as_slice(),
        &[1]
    );
    settle_session_handshake_retransmits(&mut nodes, 0, &destination, destination_index, &source);
    for _ in 0..nodes[0].node.config.node.session.coords_warmup_packets {
        send_endpoint_data_via_dataplane(&mut nodes[0].node, remote, vec![2])
            .await
            .unwrap();
        let event = recv_endpoint_event_while_draining(
            &mut nodes,
            &mut destination_endpoint.event_rx,
            Duration::from_secs(5),
            "consume ordinary coordinate warmup",
        )
        .await;
        assert_eq!(
            expect_single_endpoint_data_event(event).payload.as_slice(),
            &[2]
        );
    }
    drain_to_quiescence(&mut nodes).await;
    if traffic != Traffic::Direct {
        assert_eq!(
            nodes[0]
                .node
                .dataplane
                .fsp_coords_warmup_remaining_for_test(&destination),
            0
        );
    }
    let epochs = [
        nodes[0]
            .node
            .get_session(&destination)
            .unwrap()
            .session_start_ms(),
        nodes[destination_index]
            .node
            .get_session(&source)
            .unwrap()
            .session_start_ms(),
    ];

    initiate_handshake(&mut nodes, 3, 4).await;
    let joined = converge(&mut nodes, *identities[4].node_addr(), 5).await;
    let empty_coords = [0, 1].into_iter().all(|index| {
        nodes[index]
            .node
            .coord_cache
            .get(&destination, Node::now_ms())
            .is_none()
    });
    if !joined || !empty_coords {
        cleanup_nodes(&mut nodes).await;
        assert!(joined, "real smaller-root contact did not converge");
        assert!(
            empty_coords,
            "root transition must invalidate source and transit coordinates"
        );
        return;
    }
    let before_lookup = nodes[0].node.stats().discovery.req_initiated;
    let before_error = nodes[0].node.stats().errors.coords_required;
    let before_drop = nodes[1].node.stats().forwarding.drop_no_route_packets;
    let payload = if traffic == Traffic::Tun {
        build_ipv6_packet(
            &crate::FipsAddress::from_node_addr(&source),
            &crate::FipsAddress::from_node_addr(&destination),
            b"first TUN packet after real root change",
        )
    } else {
        b"first payload after real root change".to_vec()
    };
    if traffic == Traffic::Tun {
        nodes[0].tun_outbound_tx.try_send(payload.clone()).unwrap();
    } else {
        source_endpoint
            .data_batch_tx
            .send_or_drop(
                crate::node::NodeEndpointDataBatch::from_payloads(
                    remote,
                    vec![
                        crate::node::EndpointDataPayload::from_packet_payload(payload.clone())
                            .unwrap(),
                    ],
                    None,
                )
                .unwrap(),
            )
            .unwrap();
    }
    // Only advance the source: a new lookup cannot yet have completed.
    process_available_packets(&mut nodes[..1]).await;
    let queued = if traffic == Traffic::Tun {
        nodes[0]
            .node
            .pending_session_traffic
            .tun_packets_for(&destination)
            .map_or(0, |queue| queue.len())
    } else {
        nodes[0]
            .node
            .pending_session_traffic
            .endpoint_data_for(&destination)
            .map_or(0, |queue| queue.len())
    };
    let lookup_pending = nodes[0].node.pending_lookups.contains_key(&destination);
    let lookup_count = nodes[0].node.stats().discovery.req_initiated - before_lookup;

    // Submit exactly once. Ordinary signed discovery must flush that same
    // queued payload, without a replay after a transit routing error.
    let mut delivered = Vec::new();
    let mut wrong_path = 0;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        discovery_turn(&mut nodes).await;
        collect_deliveries(
            traffic,
            &mut destination_endpoint.event_rx,
            &tun_rx,
            &mut delivered,
            &mut wrong_path,
        );
        if !delivered.is_empty() || tokio::time::Instant::now() >= deadline {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    drain_to_quiescence(&mut nodes).await;
    collect_deliveries(
        traffic,
        &mut destination_endpoint.event_rx,
        &tun_rx,
        &mut delivered,
        &mut wrong_path,
    );
    let errors = nodes[0].node.stats().errors.coords_required - before_error;
    let drops = nodes[1].node.stats().forwarding.drop_no_route_packets - before_drop;
    let verified = nodes[0]
        .node
        .coord_cache
        .get_entry(&destination)
        .is_some_and(|entry| entry.is_verified(Node::now_ms()));
    let final_epochs = [
        nodes[0]
            .node
            .get_session(&destination)
            .unwrap()
            .session_start_ms(),
        nodes[destination_index]
            .node
            .get_session(&source)
            .unwrap()
            .session_start_ms(),
    ];
    let binding = nodes[0].node.source_routes.get(&destination).copied();
    let requires_coordinates = matches!(traffic, Traffic::Endpoint | Traffic::Tun);
    if delivered != [payload.clone()] || (requires_coordinates && !verified) {
        eprintln!(
            "incomplete {traffic:?} recovery: {:?}",
            discovery_diagnostics(&nodes, &destination)
        );
    }
    cleanup_nodes(&mut nodes).await;
    eprintln!(
        "bound coord recovery {traffic:?}: queued={queued}, lookup_pending={lookup_pending}, lookup_count={lookup_count}, delivered={}, errors={errors}, drops={drops}, verified={verified}",
        delivered.len()
    );
    if requires_coordinates {
        assert_eq!(
            queued, 1,
            "missing current-tree coordinates must defer the original payload"
        );
        assert!(
            lookup_pending,
            "existing bounded discovery must start before application dispatch"
        );
        assert_eq!(lookup_count, 1);
        assert!(
            verified,
            "flush must follow authenticated destination discovery"
        );
    } else {
        assert_eq!(
            queued, 0,
            "this retained carrier does not require tree coordinates"
        );
        assert!(!lookup_pending);
        assert_eq!(
            lookup_count, 0,
            "working direct/learned routes must not trigger discovery"
        );
    }
    assert_eq!(
        delivered,
        vec![payload],
        "the original payload must arrive exactly once"
    );
    assert_eq!(
        wrong_path, 0,
        "TUN and endpoint delivery must retain their distinct output paths"
    );
    assert_eq!(
        (errors, drops),
        (0, 0),
        "first application packet must not pay for coordinate repair"
    );
    assert_eq!(
        final_epochs, epochs,
        "coordinate repair must retain the session"
    );
    assert_eq!(
        binding,
        Some(*identities[1].node_addr()),
        "discovery must retain the chosen carrier"
    );
}
