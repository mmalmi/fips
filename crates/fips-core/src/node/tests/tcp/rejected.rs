//! Rejected Noise must release its socket without disturbing an admitted owner.
use super::*;
use crate::node::wire::build_msg1;
use spanning_tree::process_dataplane_packet;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

async fn receive_invalid(node: &mut TestNode, wire: &[u8]) {
    tokio::time::timeout(Duration::from_secs(1), async {
        loop {
            let packet = node.packet_rx.recv().await.unwrap();
            let selected = packet.data.as_slice() == wire;
            process_dataplane_packet(node, packet).await;
            if selected {
                break;
            }
        }
    })
    .await
    .expect("the complete invalid Noise record must reach the real receive path");
}

#[tokio::test]
async fn rejected_msg1_releases_tcp_capacity_and_preserves_authenticated_owner() {
    let server = make_test_node_tcp_with_config(TcpConfig {
        bind_addr: Some("127.0.0.1:0".into()),
        max_inbound_connections: Some(2),
        first_frame_timeout_ms: Some(50),
        ..Default::default()
    })
    .await;
    let mut nodes = vec![server, make_test_node_tcp().await];
    initiate_handshake(&mut nodes, 1, 0).await;
    assert!(drain_all_packets(&mut nodes, false).await > 0);
    let identity = PeerIdentity::from_pubkey_full(nodes[1].node.identity().pubkey_full());
    let original = nodes[0]
        .node
        .get_peer(identity.node_addr())
        .unwrap()
        .link_id();
    let invalid = build_msg1(SessionIndex::new(77), &[0; 106]);

    // A rejected frame on an already owned carrier must not revoke that owner.
    nodes[1].node.transports[&nodes[1].transport_id]
        .send(&nodes[0].addr, &invalid)
        .await
        .unwrap();
    receive_invalid(&mut nodes[0], &invalid).await;
    assert_eq!(
        nodes[0]
            .node
            .get_peer(identity.node_addr())
            .unwrap()
            .link_id(),
        original
    );

    // Each complete frame defeats a first-frame timer. Noise rejection must
    // reclaim the only spare inbound slot even while the sender stays silent.
    for _ in 0..2 {
        let mut stranger = TcpStream::connect(nodes[0].addr.to_string()).await.unwrap();
        stranger.write_all(&invalid).await.unwrap();
        receive_invalid(&mut nodes[0], &invalid).await;
        let closed = tokio::time::timeout(Duration::from_secs(1), stranger.read(&mut [0; 1]))
            .await
            .expect("rejected Noise must not pin an inbound TCP slot indefinitely");
        assert!(matches!(closed, Ok(0)) || closed.is_err());
    }

    nodes.push(make_test_node_tcp().await);
    initiate_handshake(&mut nodes, 2, 0).await;
    assert!(drain_all_packets(&mut nodes, false).await > 0);
    let newcomer = *nodes[2].node.node_addr();
    assert!(nodes[0].node.get_peer(&newcomer).is_some());
    assert_eq!(
        nodes[0]
            .node
            .get_peer(identity.node_addr())
            .unwrap()
            .link_id(),
        original
    );
    populate_all_coord_caches(&mut nodes);
    let mut endpoint = nodes[1].node.attach_endpoint_data_io(8).unwrap();
    super::super::session::send_endpoint_data_via_dataplane(
        &mut nodes[0].node,
        identity,
        b"retained TCP owner".to_vec(),
    )
    .await
    .unwrap();
    let event = super::super::session::recv_endpoint_event_while_draining(
        &mut nodes,
        &mut endpoint.event_rx,
        Duration::from_secs(2),
        "retained owner delivery",
    )
    .await;
    assert_eq!(
        super::super::session::expect_single_endpoint_data_event(event)
            .payload
            .as_slice(),
        b"retained TCP owner"
    );
    cleanup_nodes(&mut nodes).await;
}
