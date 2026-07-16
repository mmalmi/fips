use super::*;

pub(super) const SESSION_100_NODE_NETWORK: &str = "fips-session-100-nodes";

pub(super) async fn replace_session_100_node_carriers(
    nodes: &mut [TestNode],
    edges: &[(usize, usize)],
) -> crate::SimNetwork {
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
