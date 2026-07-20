use super::*;

pub(super) const SESSION_100_NODE_NETWORK: &str = "fips-session-100-nodes";

async fn drain_synthetic_dataplane_activity(nodes: &mut [TestNode]) -> usize {
    let mut activity = process_available_packets(nodes).await;
    for node in nodes {
        activity =
            activity.saturating_add(node.node.drain_deferred_dataplane_control_turns().await);
    }
    activity
}

async fn quiesce_synthetic_dataplanes(nodes: &mut [TestNode]) -> usize {
    use futures::StreamExt;

    const MAX_TURNS: usize = 64;
    const COMPLETION_QUIET: Duration = Duration::from_secs(1);

    if nodes.is_empty() {
        return 0;
    }

    let mut total = 0usize;
    for _ in 0..MAX_TURNS {
        let activity = drain_synthetic_dataplane_activity(nodes).await;
        total = total.saturating_add(activity);

        if activity > 0
            || nodes
                .iter()
                .any(|node| node.node.dataplane.has_runnable_work())
        {
            continue;
        }

        let mut completions = futures::stream::FuturesUnordered::new();
        for node in nodes.iter() {
            let notify = node.node.dataplane.readiness_notify();
            completions.push(async move { notify.notified().await });
        }
        if tokio::time::timeout(COMPLETION_QUIET, completions.next())
            .await
            .is_ok()
        {
            continue;
        }

        let final_activity = drain_synthetic_dataplane_activity(nodes).await;
        total = total.saturating_add(final_activity);
        if final_activity == 0
            && !nodes
                .iter()
                .any(|node| node.node.dataplane.has_runnable_work())
        {
            return total;
        }
    }

    let runnable = nodes
        .iter()
        .enumerate()
        .filter_map(|(index, node)| node.node.dataplane.has_runnable_work().then_some(index))
        .collect::<Vec<_>>();
    panic!("synthetic dataplanes did not quiesce; runnable nodes: {runnable:?}");
}

pub(super) async fn replace_session_100_node_carriers(
    nodes: &mut [TestNode],
    edges: &[(usize, usize)],
) -> crate::SimNetwork {
    quiesce_synthetic_dataplanes(nodes).await;

    let sim_addresses = (0..nodes.len())
        .map(|index| TransportAddr::from_string(&format!("session-node-{index}")))
        .collect::<Vec<_>>();
    let address_by_node = nodes
        .iter()
        .zip(&sim_addresses)
        .map(|(node, addr)| (*node.node.node_addr(), addr.clone()))
        .collect::<std::collections::HashMap<_, _>>();

    let network = crate::SimNetwork::new(42);
    network.set_default_link(crate::SimLink {
        up: false,
        ..Default::default()
    });
    for &(left, right) in edges {
        network.set_link(
            sim_addresses[left].as_str().expect("sim address"),
            sim_addresses[right].as_str().expect("sim address"),
            crate::SimLink::default(),
        );
    }
    crate::register_sim_network(SESSION_100_NODE_NETWORK, network.clone());

    for (index, node) in nodes.iter_mut().enumerate() {
        let mut old_transport = node
            .node
            .transports
            .remove(&node.transport_id)
            .expect("UDP test transport should exist");
        old_transport
            .stop()
            .await
            .expect("UDP test transport should stop");

        let peer_addrs = node.node.peers.keys().copied().collect::<Vec<_>>();
        for peer_addr in peer_addrs {
            let remote_addr = address_by_node
                .get(&peer_addr)
                .expect("topology peer has a Sim address")
                .clone();
            let link_id = node
                .node
                .get_peer(&peer_addr)
                .expect("topology peer retained")
                .link_id();
            let old_link = node
                .node
                .links
                .remove(&link_id)
                .expect("topology peer link retained");
            let mut new_link = Link::new_with_timestamp(
                link_id,
                node.transport_id,
                remote_addr.clone(),
                old_link.direction(),
                old_link.base_rtt(),
                old_link.created_at(),
            );
            *new_link.stats_mut() = old_link.stats().clone();
            match old_link.state() {
                crate::transport::LinkState::Connected => new_link.set_connected(),
                crate::transport::LinkState::Disconnected => new_link.set_disconnected(),
                crate::transport::LinkState::Failed => new_link.set_failed(),
                crate::transport::LinkState::Connecting => {}
            }
            node.node.links.insert(link_id, new_link);
            let peer = node.node.get_peer_mut(&peer_addr).expect("topology peer");
            peer.set_current_addr(node.transport_id, &remote_addr);
            peer.clear_preferred_send_addr();
        }

        node.addr = sim_addresses[index].clone();

        let (packet_tx, packet_rx) = crate::packet_channel(256);
        let config = crate::SimTransportConfig {
            network: Some(SESSION_100_NODE_NETWORK.to_string()),
            addr: Some(node.addr.as_str().expect("sim address").to_string()),
            mtu: Some(1280),
            ..Default::default()
        };
        let mut transport = crate::SimTransport::new(node.transport_id, None, config, packet_tx);
        transport.start_async().await.expect("sim transport start");
        node.packet_rx = packet_rx;
        node.node
            .transports
            .insert(node.transport_id, crate::TransportHandle::Sim(transport));
        for peer_addr in node.node.peers.keys().copied().collect::<Vec<_>>() {
            assert!(
                node.node.sync_dataplane_fmp_owner(&peer_addr),
                "retargeted Sim peer owner should install"
            );
        }
    }

    network
}

#[tokio::test]
async fn carrier_boundary_drains_leftover_dataplane_work() {
    const PACKETS: usize = 300;

    let mut nodes = run_tree_test(2, &[(0, 1)], false).await;
    let peer = *nodes[1].node.node_addr();
    let heartbeat = [crate::protocol::LinkMessageType::Heartbeat.to_byte()];
    let outbound = (0..PACKETS)
        .map(|_| {
            nodes[0]
                .node
                .prepare_dataplane_fmp_link_outbound(
                    peer,
                    crate::transport::PacketBuffer::new(heartbeat.to_vec()),
                    false,
                    crate::dataplane::ActivityTick::new(Node::now_ms()),
                )
                .expect("prepare synthetic leftover")
                .0
        })
        .collect();
    let first = nodes[0]
        .node
        .pump_dataplane_pending_outbound_firsts(
            crate::dataplane::DataplaneLiveOutboundFirsts {
                initial_outbound_batch: outbound,
                ..Default::default()
            },
            0,
            0,
            1,
        )
        .await;
    assert_eq!(first.summary().outbound_admitted(), PACKETS);
    assert!(nodes[0].node.dataplane.has_runnable_work());

    let drained = quiesce_synthetic_dataplanes(&mut nodes).await;

    assert!(drained > 0);
    assert!(
        !nodes
            .iter()
            .any(|node| node.node.dataplane.has_runnable_work())
    );
    assert_eq!(process_available_packets(&mut nodes).await, 0);
    cleanup_nodes(&mut nodes).await;
}

#[tokio::test]
async fn discovery_control_send_survives_existing_priority_backlog() {
    // This deliberately exceeds both the two-turn fast-send budget and the
    // former eight-turn special-case handshake-response budget.
    const BACKLOG_PACKETS: usize = 12;

    let mut nodes = run_tree_test(2, &[(0, 1)], false).await;
    let peer = *nodes[1].node.node_addr();
    let heartbeat = [crate::protocol::LinkMessageType::Heartbeat.to_byte()];
    let outbound = (0..BACKLOG_PACKETS)
        .map(|_| {
            nodes[0]
                .node
                .prepare_dataplane_fmp_link_outbound(
                    peer,
                    crate::transport::PacketBuffer::new(heartbeat.to_vec()),
                    false,
                    crate::dataplane::ActivityTick::new(Node::now_ms()),
                )
                .expect("prepare synthetic priority backlog")
                .0
        })
        .collect();
    let first = nodes[0]
        .node
        .pump_dataplane_pending_outbound_firsts(
            crate::dataplane::DataplaneLiveOutboundFirsts {
                initial_outbound_batch: outbound,
                ..Default::default()
            },
            0,
            0,
            1,
        )
        .await;
    assert_eq!(first.summary().outbound_admitted(), BACKLOG_PACKETS);
    assert!(nodes[0].node.dataplane.has_runnable_work());

    nodes[0]
        .node
        .send_dataplane_fmp_link_plaintext(
            &peer,
            &[crate::protocol::LinkMessageType::LookupRequest.to_byte()],
            false,
        )
        .await
        .expect("discovery control must not fail behind admitted liveness traffic");

    quiesce_synthetic_dataplanes(&mut nodes).await;
    cleanup_nodes(&mut nodes).await;
}
#[tokio::test]
async fn queued_routed_endpoint_data_survives_existing_priority_backlog() {
    const BACKLOG_PACKETS: usize = 12;

    let mut nodes = run_tree_test(3, &[(0, 1), (1, 2)], false).await;
    populate_all_coord_caches(&mut nodes);

    let next_hop = *nodes[1].node.node_addr();
    let destination = *nodes[2].node.node_addr();
    let destination_pubkey = nodes[2].node.identity().pubkey_full();
    let mut destination_endpoint = nodes[2]
        .node
        .attach_endpoint_data_io(8)
        .expect("destination endpoint data I/O should attach");

    nodes[0]
        .node
        .initiate_session(destination, destination_pubkey)
        .await
        .expect("routed session initiation should succeed");
    wait_for_session_established(
        &mut nodes,
        0,
        &destination,
        Duration::from_secs(10),
        "routed endpoint backlog fixture",
    )
    .await;

    nodes[0]
        .node
        .pending_session_traffic
        .push_endpoint_data_batch_with_enqueued_at_ms(
            destination,
            vec![
                crate::node::EndpointDataPayload::from_packet_payload(b"queued-routed".to_vec())
                    .expect("test endpoint payload"),
            ],
            usize::MAX,
            usize::MAX,
            Node::now_ms(),
        );

    let heartbeat = [crate::protocol::LinkMessageType::Heartbeat.to_byte()];
    let outbound = (0..BACKLOG_PACKETS)
        .map(|_| {
            nodes[0]
                .node
                .prepare_dataplane_fmp_link_outbound(
                    next_hop,
                    crate::transport::PacketBuffer::new(heartbeat.to_vec()),
                    false,
                    crate::dataplane::ActivityTick::new(Node::now_ms()),
                )
                .expect("prepare synthetic priority backlog")
                .0
        })
        .collect();
    let first = nodes[0]
        .node
        .pump_dataplane_pending_outbound_firsts(
            crate::dataplane::DataplaneLiveOutboundFirsts {
                initial_outbound_batch: outbound,
                ..Default::default()
            },
            0,
            0,
            1,
        )
        .await;
    assert_eq!(first.summary().outbound_admitted(), BACKLOG_PACKETS);
    assert!(nodes[0].node.dataplane.has_runnable_work());

    nodes[0].node.flush_pending_packets(&destination).await;
    assert!(
        !nodes[0]
            .node
            .pending_session_traffic
            .has_traffic_for(&destination),
        "queued routed endpoint data must not be stranded behind valid dataplane work"
    );

    let event = recv_endpoint_event_while_draining(
        &mut nodes,
        &mut destination_endpoint.event_rx,
        Duration::from_secs(10),
        "queued routed endpoint data behind backlog",
    )
    .await;
    let delivered = expect_single_endpoint_data_event(event);
    assert_eq!(
        delivered.source_peer,
        PeerIdentity::from_pubkey_full(nodes[0].node.identity().pubkey_full())
    );
    assert_eq!(delivered.payload.as_slice(), b"queued-routed");

    quiesce_synthetic_dataplanes(&mut nodes).await;
    cleanup_nodes(&mut nodes).await;
}
