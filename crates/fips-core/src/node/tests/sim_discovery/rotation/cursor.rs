use super::*;
use crate::node::wire::{Msg2Header, build_msg1};
use crate::noise::HandshakeState;
use crate::utils::index::SessionIndex;

async fn send_to_local(nodes: &mut [TestNode], source: usize, wire: &[u8]) {
    nodes[source].node.transports[&nodes[source].transport_id]
        .send(&nodes[0].addr, wire)
        .await
        .unwrap();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(1);
    loop {
        let packet = tokio::time::timeout_at(deadline, nodes[0].packet_rx.recv())
            .await
            .expect("simulated handshake packet arrival")
            .unwrap();
        let matches = packet.data.as_slice() == wire;
        if matches {
            assert_eq!(packet.remote_addr, nodes[source].addr);
        }
        spanning_tree::process_dataplane_packet(&mut nodes[0], packet).await;
        if matches {
            break;
        }
    }
}

async fn confirm_incoming(nodes: &mut [TestNode], source: usize, sender_index: u32) {
    let mut handshake = HandshakeState::new_initiator(
        nodes[source].node.identity.keypair(),
        nodes[0].node.identity.pubkey_full(),
    );
    handshake.set_local_epoch(nodes[source].node.startup_epoch);
    let index = SessionIndex::new(sender_index);
    let msg1 = build_msg1(index, &handshake.write_message_1().unwrap());
    send_to_local(nodes, source, &msg1).await;
    assert_eq!(nodes[0].node.connection_count(), 1);
    assert!(
        nodes[0]
            .node
            .get_peer(nodes[source].node.node_addr())
            .is_none()
    );
    assert_caps(nodes);

    // Read the real responder's Msg2 from the Sim carrier. The remote Noise
    // initiator stays local to this helper, so a later fresh incoming attempt
    // does not depend on an unrelated stale remote Node's refresh policy.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(1);
    let header = loop {
        let packet = tokio::time::timeout_at(deadline, nodes[source].packet_rx.recv())
            .await
            .expect("simulated Msg2 arrival")
            .unwrap();
        let Some(header) = Msg2Header::parse(packet.data.as_slice()) else {
            continue;
        };
        if header.receiver_idx == index {
            assert_eq!(packet.remote_addr, nodes[0].addr);
            handshake
                .read_message_2(header.noise_msg2(packet.data.as_slice()))
                .unwrap();
            break header;
        }
    };
    let mut session = handshake.into_session().unwrap();
    let mut plaintext = 1u32.to_le_bytes().to_vec();
    plaintext.push(crate::protocol::LinkMessageType::Heartbeat.to_byte());
    let header = crate::dataplane::build_fmp_established_header(
        header.sender_idx.as_u32(),
        session.current_send_counter(),
        0,
        plaintext.len() as u16,
    );
    let mut confirmation = header.to_vec();
    confirmation.extend(session.encrypt_with_aad(&plaintext, &header).unwrap());
    send_to_local(nodes, source, &confirmation).await;
    assert!(
        nodes[0]
            .node
            .get_peer(nodes[source].node.node_addr())
            .is_some()
    );
    assert_eq!(nodes[0].node.connection_count(), 0);
    assert_eq!(nodes[0].node.link_count(), 1);
    assert_caps(nodes);
}

#[tokio::test]
async fn incoming_rotation_does_not_rewind_local_discovery_progress() {
    let name = format!("node-sim-rotation-cursor-{}", std::process::id());
    let network = SimNetwork::new(53);
    network.set_default_link(SimLink {
        up: false,
        ..Default::default()
    });
    register_sim_network(name.clone(), network.clone());
    let mut nodes = vec![
        discovering_node(&name, "local", true).await,
        discovering_node(&name, "candidate-a", false).await,
        discovering_node(&name, "candidate-b", false).await,
        discovering_node(&name, "candidate-c", false).await,
    ];
    nodes[0].node.set_max_links(2);
    nodes[0].node.config.node.neighbor_rotation = Some(NeighborRotationConfig {
        idle_secs: 1,
        interval_secs: 1,
    });
    let mut order = [1, 2, 3];
    order.sort_unstable_by_key(|index| *nodes[*index].node.node_addr());
    let [b, c, d] = order;
    let addresses = ["local", "candidate-a", "candidate-b", "candidate-c"];
    network.set_link("local", addresses[b], SimLink::default());
    nodes[0].node.poll_transport_discovery().await;
    authenticate(&mut nodes, b).await;

    // B < C < D are actual identity order, not fabricated routing state. An
    // initial incoming C may seed exploration past itself, as in the existing
    // unconfirmed-first regression. The first genuine local turn then picks D.
    tokio::time::sleep(Duration::from_millis(1_010)).await;
    for index in [c, d] {
        network.set_link("local", addresses[index], SimLink::default());
    }
    confirm_incoming(&mut nodes, c, 180).await;
    assert!(nodes[0].node.get_peer(nodes[b].node.node_addr()).is_none());
    tokio::time::sleep(Duration::from_millis(1_010)).await;
    nodes[0].node.poll_transport_discovery().await;
    let first = nodes[0].node.peers.connection_values().next().unwrap();
    assert!(first.is_outbound());
    assert_eq!(
        first.expected_identity().unwrap().node_addr(),
        nodes[d].node.node_addr(),
        "the initial incoming C must not make discovery immediately retry C"
    );
    authenticate(&mut nodes, d).await;

    // A fresh, fully confirmed C can legitimately return between maintenance
    // turns once D is idle. It must not rewind the local cursor from D to C:
    // otherwise the repeatable C -> D -> C sequence indefinitely skips B.
    tokio::time::sleep(Duration::from_millis(1_010)).await;
    confirm_incoming(&mut nodes, c, 181).await;
    assert!(nodes[0].node.get_peer(nodes[d].node.node_addr()).is_none());
    tokio::time::sleep(Duration::from_millis(1_010)).await;
    for index in [b, d] {
        assert!(nodes[0].node.can_attempt_neighbor_rotation(
            nodes[index].node.node_addr(),
            true,
            Node::now_ms(),
        ));
    }
    nodes[0].node.poll_transport_discovery().await;
    let next = nodes[0].node.peers.connection_values().next().unwrap();
    assert!(next.is_outbound());
    let chosen = *next.expected_identity().unwrap().node_addr();
    let expected = *nodes[b].node.node_addr();
    assert_caps(&nodes);
    assert!(nodes.iter().all(|node| node.node.config.peers.is_empty()));
    cleanup_nodes(&mut nodes).await;
    unregister_sim_network(&name);
    assert_eq!(
        chosen, expected,
        "incoming C between local discovery turns must not rewind D's progress and skip B"
    );
}
