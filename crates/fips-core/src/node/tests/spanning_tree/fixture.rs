use super::*;

/// A test node bundling a Node with its transport and packet channel.
pub(in crate::node::tests) struct TestNode {
    pub(in crate::node::tests) node: Node,
    pub(in crate::node::tests) transport_id: TransportId,
    pub(in crate::node::tests) packet_rx: PacketRx,
    pub(in crate::node::tests) tun_outbound_tx: crate::upper::tun::TunOutboundTx,
    pub(in crate::node::tests) addr: TransportAddr,
}

/// Create a test node with a live UDP transport on localhost.
pub(in crate::node::tests) async fn make_test_node() -> TestNode {
    make_test_node_with_mtu(1280).await
}

/// Create a test node with a specific transport MTU.
pub(in crate::node::tests) async fn make_test_node_with_mtu(mtu: u16) -> TestNode {
    use crate::config::UdpConfig;
    use crate::transport::udp::UdpTransport;

    let mut config = Config::new();
    config.node.rate_limit.handshake_burst = 1000;
    config.node.rate_limit.handshake_rate = 1000.0;
    config.node.rate_limit.handshake_resend_interval_ms = 50;
    config.node.rate_limit.handshake_resend_backoff = 1.5;
    config.node.rate_limit.handshake_max_resends = 12;
    config.node.bloom.update_debounce_ms = 50;
    let mut node = Node::new(config).unwrap();
    let transport_id = TransportId::new(1);

    let udp_config = UdpConfig {
        bind_addr: Some("127.0.0.1:0".to_string()),
        mtu: Some(mtu),
        ..Default::default()
    };

    let (packet_tx, packet_rx) = packet_channel(256);
    let (tun_outbound_tx, tun_outbound_rx) = crate::upper::tun::tun_outbound_channel(256);
    node.tun_outbound_rx = Some(tun_outbound_rx);

    let mut transport = UdpTransport::new(transport_id, None, udp_config, packet_tx);
    transport.start_async().await.unwrap();

    let addr = TransportAddr::from_string(&transport.local_addr().unwrap().to_string());
    node.transports
        .insert(transport_id, TransportHandle::Udp(transport));

    TestNode {
        node,
        transport_id,
        packet_rx,
        tun_outbound_tx,
        addr,
    }
}

/// Initiate a Noise handshake from nodes[i] to nodes[j].
///
/// Sends msg1 over UDP. The drain loop will handle msg1 processing,
/// msg2 response, and subsequent TreeAnnounce exchange.
pub(in crate::node::tests) async fn initiate_handshake(nodes: &mut [TestNode], i: usize, j: usize) {
    let wire_msg1 = prepare_outbound_msg1(nodes, i, j);
    let responder_addr = nodes[j].addr.clone();
    let transport_id = nodes[i].transport_id;

    let transport = nodes[i].node.transports.get(&transport_id).unwrap();
    transport
        .send(&responder_addr, &wire_msg1)
        .await
        .expect("Failed to send msg1");
}

fn prepare_outbound_msg1(nodes: &mut [TestNode], i: usize, j: usize) -> Vec<u8> {
    use crate::node::wire::build_msg1;

    // Extract responder info before mutably borrowing initiator
    let responder_addr = nodes[j].addr.clone();
    let responder_pubkey_full = nodes[j].node.identity().pubkey_full();
    let peer_identity = PeerIdentity::from_pubkey_full(responder_pubkey_full);

    let initiator = &mut nodes[i];
    let transport_id = initiator.transport_id;

    let link_id = initiator.node.allocate_link_id();
    let now_ms = Node::now_ms();
    let mut conn = PeerConnection::outbound(link_id, peer_identity, now_ms);

    let our_index = initiator.node.index_allocator.allocate().unwrap();
    let our_keypair = initiator.node.identity().keypair();
    let noise_msg1 = conn
        .start_handshake(our_keypair, initiator.node.startup_epoch, now_ms)
        .unwrap();
    conn.set_our_index(our_index);
    conn.set_transport_id(transport_id);
    conn.set_source_addr(responder_addr.clone());

    let wire_msg1 = build_msg1(our_index, &noise_msg1);
    let first_resend_at_ms = now_ms
        + initiator
            .node
            .config
            .node
            .rate_limit
            .handshake_resend_interval_ms;
    conn.set_handshake_msg1(wire_msg1.clone(), first_resend_at_ms);

    let link = Link::connectionless(
        link_id,
        transport_id,
        responder_addr.clone(),
        LinkDirection::Outbound,
        Duration::from_millis(100),
    );
    initiator.node.links.insert(link_id, link);
    initiator
        .node
        .links
        .insert_addr((transport_id, responder_addr.clone()), link_id);
    initiator.node.peers.insert_connection(link_id, conn);
    initiator
        .node
        .pending_outbound
        .insert((transport_id, our_index.as_u32()), link_id);

    wire_msg1
}

pub(in crate::node::tests) async fn complete_direct_handshake(
    nodes: &mut [TestNode],
    i: usize,
    j: usize,
) {
    let wire_msg1 = prepare_outbound_msg1(nodes, i, j);
    let initiator_addr = nodes[i].addr.clone();
    let responder_transport_id = nodes[j].transport_id;
    let now_ms = Node::now_ms();

    nodes[j]
        .node
        .handle_msg1(ReceivedPacket::with_timestamp(
            responder_transport_id,
            initiator_addr,
            wire_msg1,
            now_ms,
        ))
        .await;

    let initiator_node_addr = *nodes[i].node.node_addr();
    let wire_msg2 = nodes[j]
        .node
        .get_peer(&initiator_node_addr)
        .and_then(|peer| peer.handshake_msg2())
        .expect("responder should store msg2 for direct synthetic handshake")
        .to_vec();
    let responder_addr = nodes[j].addr.clone();
    let initiator_transport_id = nodes[i].transport_id;

    nodes[i]
        .node
        .handle_msg2(ReceivedPacket::with_timestamp(
            initiator_transport_id,
            responder_addr,
            wire_msg2,
            Node::now_ms(),
        ))
        .await;
}
