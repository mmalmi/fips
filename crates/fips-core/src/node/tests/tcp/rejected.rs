//! Rejected records release sockets without disturbing current carrier owners.
use super::*;
use crate::node::wire::{build_msg1, build_msg2};
use spanning_tree::process_dataplane_packet;
use std::time::Instant;
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
    .expect("the complete rejected record must reach the real receive path");
}

#[tokio::test]
async fn rejected_msg1_releases_tcp_capacity_and_preserves_authenticated_owner() {
    assert_rejected_record(build_msg1(SessionIndex::new(77), &[0; 106]), false).await;
}

#[tokio::test]
async fn unsolicited_msg2_releases_tcp_capacity_and_preserves_authenticated_owner() {
    assert_rejected_record(
        build_msg2(SessionIndex::new(77), SessionIndex::new(u32::MAX), &[0; 57]),
        false,
    )
    .await;
}

#[tokio::test]
async fn unrouted_record_releases_tcp_capacity_and_preserves_authenticated_owner() {
    let mut record = vec![0; 32];
    record[4..8].copy_from_slice(&u32::MAX.to_le_bytes());
    assert_rejected_record(record, false).await;
}

#[tokio::test]
async fn stale_rejected_records_preserve_a_new_unowned_tcp_carrier() {
    let mut node = make_test_node_tcp().await;
    for wire in [
        build_msg2(SessionIndex::new(77), SessionIndex::new(u32::MAX), &[0; 57]),
        vec![0; 32],
    ] {
        let mut stranger = TcpStream::connect(node.addr.to_string()).await.unwrap();
        stranger.write_all(&wire).await.unwrap();
        let mut packet = tokio::time::timeout(Duration::from_secs(1), node.packet_rx.recv())
            .await
            .unwrap()
            .unwrap();
        let remote = packet.remote_addr.clone();
        // Model a record queued by the old carrier before this socket existed.
        packet.timestamp_ms = 1;
        node.node
            .transport_rebind_packet_cutoffs_ms
            .insert(node.transport_id, 1);
        process_dataplane_packet(&mut node, packet).await;
        assert_eq!(
            node.node.transports[&node.transport_id].connection_state(&remote),
            crate::transport::ConnectionState::Connected,
            "an old queued record cannot close a replacement socket",
        );
        // A current rejection of the same record must still release it.
        stranger.write_all(&wire).await.unwrap();
        receive_invalid(&mut node, &wire).await;
        let closed = tokio::time::timeout(Duration::from_secs(1), stranger.read(&mut [0; 1]))
            .await
            .expect("current rejected records must release their carrier");
        assert!(matches!(closed, Ok(0)) || closed.is_err());
    }
    cleanup_nodes(std::slice::from_mut(&mut node)).await;
}

#[tokio::test]
async fn bad_ciphertext_with_a_known_index_releases_only_its_unowned_tcp_carrier() {
    let mut record = vec![0; 32];
    record[8..16].copy_from_slice(&1_000_000_u64.to_le_bytes());
    assert_rejected_record(record, true).await;
}

#[tokio::test]
async fn replay_with_a_known_index_releases_only_its_unowned_tcp_carrier() {
    assert_rejected_record(vec![0; 32], true).await;
}

async fn assert_rejected_record(mut invalid: Vec<u8>, use_owned_index: bool) {
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

    if use_owned_index {
        // Exercise recovery accounting after the fresh-session drain grace.
        nodes[0]
            .node
            .get_peer_mut(identity.node_addr())
            .unwrap()
            .set_session_established_at_for_test(Instant::now() - Duration::from_secs(31));
        let index = nodes[0]
            .node
            .get_peer(identity.node_addr())
            .unwrap()
            .our_index()
            .unwrap();
        invalid[4..8].copy_from_slice(&index.as_u32().to_le_bytes());
    }

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
    let failures = nodes[0]
        .node
        .get_peer(identity.node_addr())
        .unwrap()
        .consecutive_decrypt_failures();
    if use_owned_index && invalid[8..16] != [0; 8] {
        assert_eq!(
            failures, 1,
            "owned bad ciphertext must still reach recovery accounting"
        );
    }

    // Each complete frame defeats a first-frame timer. Node rejection must
    // reclaim the only spare inbound slot even while the sender stays silent.
    for _ in 0..2 {
        let mut stranger = TcpStream::connect(nodes[0].addr.to_string()).await.unwrap();
        stranger.write_all(&invalid).await.unwrap();
        receive_invalid(&mut nodes[0], &invalid).await;
        let closed = tokio::time::timeout(Duration::from_secs(1), stranger.read(&mut [0; 1]))
            .await
            .expect("rejected record must not pin an inbound TCP slot indefinitely");
        assert!(matches!(closed, Ok(0)) || closed.is_err());
        assert_eq!(
            nodes[0]
                .node
                .get_peer(identity.node_addr())
                .unwrap()
                .consecutive_decrypt_failures(),
            failures,
            "a stranger knowing the session index cannot change its owner's recovery state"
        );
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
