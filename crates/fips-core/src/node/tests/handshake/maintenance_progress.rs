use super::*;
use crate::config::TorConfig;
use crate::node::NodeEndpointControlCommand;
use crate::node::wire::build_msg1;
use crate::transport::tor::TorTransport;

#[test]
fn rx_loop_services_endpoint_control_after_liveness_send_times_out() {
    super::super::session::run_large_stack_async_test(
        "fips-maintenance-progress",
        stalled_handshake_resend,
    );
}

async fn stalled_handshake_resend() {
    // A live local proxy accepts TCP but never answers SOCKS. This exercises
    // a real transport await inside handshake maintenance, without DNS or an
    // injected delay in the event loop.
    let proxy = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mut node = make_node();
    node.config.node.discovery.lan.enabled = false;
    node.config.node.tick_interval_secs = 1;
    let transport_id = TransportId::new(1);
    let (packet_tx, packet_rx) = packet_channel(8);
    let mut transport = TorTransport::new(
        transport_id,
        None,
        TorConfig {
            socks5_addr: Some(proxy.local_addr().unwrap().to_string()),
            ..Default::default()
        },
        packet_tx,
    );
    transport.start_async().await.unwrap();
    node.transports
        .insert(transport_id, TransportHandle::Tor(transport));
    node.packet_rx = Some(packet_rx);
    node.state = NodeState::Running;

    let now_ms = Node::now_ms();
    let link_id = node.allocate_link_id();
    let mut connection = PeerConnection::outbound(link_id, make_peer_identity(), now_ms);
    let msg1 = connection
        .start_handshake(node.identity.keypair(), node.startup_epoch, now_ms)
        .unwrap();
    let index = node.index_allocator.allocate().unwrap();
    connection.set_our_index(index);
    connection.set_transport_id(transport_id);
    connection.set_source_addr(TransportAddr::from_string("127.0.0.1:51820"));
    connection.set_handshake_msg1(build_msg1(index, &msg1), now_ms);
    node.peers.insert_connection(link_id, connection);

    let (control_tx, control_rx) = tokio::sync::mpsc::channel(8);
    node.endpoint_control_rx = Some(control_rx);
    let task = tokio::spawn(async move { node.run_rx_loop().await });
    let (_stalled_socket, _) = tokio::time::timeout(Duration::from_secs(3), proxy.accept())
        .await
        .expect("maintenance must enter the real transport send")
        .unwrap();

    // Only timer behavior remains under test, so advance virtual time instead
    // of spending several seconds waiting for the maintenance budget.
    tokio::time::pause();
    let (response_tx, response_rx) = tokio::sync::oneshot::channel();
    control_tx
        .send(NodeEndpointControlCommand::PeerSnapshot { response_tx })
        .await
        .unwrap();
    let response = tokio::time::timeout(Duration::from_secs(3), response_rx).await;
    task.abort();
    let _ = task.await;
    assert!(
        response.is_ok_and(|response| response.is_ok()),
        "endpoint control must progress after the bounded maintenance send"
    );
}
