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

    let network = crate::SimNetwork::new(42);
    network.set_default_link(crate::SimLink {
        up: false,
        ..Default::default()
    });
    for &(left, right) in edges {
        network.set_link(
            nodes[left].addr.as_str().expect("sim address"),
            nodes[right].addr.as_str().expect("sim address"),
            crate::SimLink::default(),
        );
    }
    crate::register_sim_network(SESSION_100_NODE_NETWORK, network.clone());

    for node in nodes {
        let mut old_transport = node
            .node
            .transports
            .remove(&node.transport_id)
            .expect("UDP test transport should exist");
        old_transport
            .stop()
            .await
            .expect("UDP test transport should stop");

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
