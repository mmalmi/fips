use super::*;
use crate::config::UdpConfig;
use crate::node::tests::spanning_tree::{process_dataplane_completions, process_dataplane_packet};
use crate::transport::{Link, LinkDirection, TransportHandle, packet_channel, udp::UdpTransport};
use futures::FutureExt;
use std::panic::AssertUnwindSafe;

#[test]
fn retained_reply_on_second_udp_listener_owns_proof_and_bidirectional_payload() {
    run_large_stack_async_test("prepared-reply-second-listener", || async {
        let mut nodes = [
            make_test_node().await,
            make_test_node().await,
            make_test_node().await,
        ];
        let result = AssertUnwindSafe(exercise(&mut nodes)).catch_unwind().await;
        cleanup_nodes(&mut nodes).await;
        if let Err(panic) = result {
            std::panic::resume_unwind(panic);
        }
    });
}

async fn exercise(nodes: &mut [TestNode; 3]) {
    for node in nodes.iter_mut() {
        node.node.config.node.rekey.enabled = false;
        node.node.config.node.session.idle_timeout_secs = 0;
    }
    nodes[0].node.max_peers = 1;
    nodes[0].node.max_connections = 1;
    nodes[0].node.max_links = 2;
    nodes[0].node.config.node.neighbor_rotation = Some(NeighborRotationConfig {
        idle_secs: 2,
        interval_secs: 1,
    });
    nodes[0].node.config.node.rate_limit.handshake_timeout_secs = 8;
    let local = *nodes[0].node.node_addr();
    let remote = *nodes[1].node.node_addr();
    let old = *nodes[2].node.node_addr();
    dial(nodes, 0, 2).await;
    quiesce(nodes).await;
    let incumbent = Owner::capture(&nodes[0], &old);
    let dial_transport = nodes[0].transport_id;
    dial(nodes, 0, 1).await;
    let conn = nodes[0].node.peers.connection_values().next().unwrap();
    let link = conn.link_id();
    let index = conn.our_index().unwrap();
    let attempt = nodes[0].node.neighbor_rotation_started_at(&remote).unwrap();
    let request = next_packet(&mut nodes[1]).await;
    nodes[1].node.handle_msg1(request).await;
    let original = next_packet(&mut nodes[0]).await;
    assert!(Msg2Header::parse(original.data.as_slice()).is_some());

    // The same real authenticated response arrives on another actual local
    // UDP listener. No ReceivedPacket transport/address or Noise bytes are forged.
    let receive_transport = TransportId::new(2);
    let (tx, rx) = packet_channel(256);
    let mut udp = UdpTransport::new(
        receive_transport,
        None,
        UdpConfig {
            bind_addr: Some("127.0.0.1:0".into()),
            ..Default::default()
        },
        tx,
    );
    udp.start_async().await.unwrap();
    let receive_addr = TransportAddr::from_string(&udp.local_addr().unwrap().to_string());
    nodes[0]
        .node
        .transports
        .insert(receive_transport, TransportHandle::Udp(udp));
    let _old_listener_rx = std::mem::replace(&mut nodes[0].packet_rx, rx);
    nodes[1]
        .node
        .transports
        .get(&nodes[1].transport_id)
        .unwrap()
        .send(&receive_addr, original.data.as_slice())
        .await
        .unwrap();
    let reply = next_packet(&mut nodes[0]).await;
    assert_eq!(reply.transport_id, receive_transport);
    assert_eq!(reply.remote_addr, nodes[1].addr);
    nodes[0].node.handle_msg2(reply).await;
    let conn = nodes[0].node.get_connection(&link).unwrap();
    assert_eq!(
        conn.transport_id(),
        Some(dial_transport),
        "pending cleanup keeps its original key"
    );
    assert_eq!(conn.last_activity(), attempt);
    assert_eq!(nodes[0].node.dataplane.fmp_handshake_candidate_count(), 1);
    assert_eq!(Owner::capture(&nodes[0], &old), incumbent);

    let wait = tokio::time::Instant::now() + Duration::from_secs(3);
    while Node::now_ms() <= incumbent.authenticated_at + 2_000 {
        assert!(tokio::time::Instant::now() < wait);
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    nodes[0]
        .node
        .resend_pending_handshakes(Node::now_ms())
        .await;
    // Receiving the genuine readiness frame makes the remote observe the
    // second listener through normal authenticated roaming bookkeeping.
    let ready = next_packet(&mut nodes[1]).await;
    assert_eq!(ready.remote_addr, receive_addr);
    process_dataplane_packet(&mut nodes[1], ready).await;
    let drain = tokio::time::Instant::now() + Duration::from_secs(1);
    while nodes[1].node.get_peer(&local).unwrap().current_addr() != Some(&receive_addr) {
        assert!(
            tokio::time::Instant::now() < drain,
            "ready frame must authenticate on remote"
        );
        process_dataplane_completions(&mut nodes[1].node).await;
        tokio::task::yield_now().await;
    }
    let heartbeat = [crate::protocol::LinkMessageType::Heartbeat.to_byte()];
    nodes[1]
        .node
        .send_dataplane_fmp_link_plaintext(&local, &heartbeat, false)
        .await
        .unwrap();
    let proof = next_packet(&mut nodes[0]).await;
    assert_eq!(proof.transport_id, receive_transport);
    assert_eq!(proof.remote_addr, nodes[1].addr);
    process_dataplane_packet(&mut nodes[0], proof.clone()).await;
    let drain = tokio::time::Instant::now() + Duration::from_secs(1);
    loop {
        process_dataplane_completions(&mut nodes[0].node).await;
        if nodes[0]
            .node
            .dataplane_fmp_link_metrics(&remote, Instant::now())
            .is_some_and(|metrics| metrics.current_epoch_authenticated)
        {
            break;
        }
        assert!(
            tokio::time::Instant::now() < drain,
            "first retained proof must reenter the winning receiver route"
        );
        tokio::task::yield_now().await;
    }
    assert_eq!(
        nodes[0]
            .node
            .dataplane_fmp_link_metrics(&remote, Instant::now())
            .unwrap()
            .rx_packets,
        1
    );
    process_dataplane_packet(&mut nodes[0], proof).await;
    process_dataplane_completions(&mut nodes[0].node).await;
    assert_eq!(
        nodes[0]
            .node
            .dataplane_fmp_link_metrics(&remote, Instant::now())
            .unwrap()
            .rx_packets,
        1
    );
    let active = nodes[0].node.get_peer(&remote).unwrap();
    assert_eq!(active.transport_id(), Some(receive_transport));
    assert_eq!(active.current_addr(), Some(&nodes[1].addr));
    assert_eq!(active.our_index(), Some(index));
    assert_eq!(active.remote_epoch(), Some(nodes[1].node.startup_epoch));
    assert_eq!(
        nodes[0].node.links.get(&link).unwrap().transport_id(),
        receive_transport
    );
    assert_eq!(
        nodes[0].node.links.get(&link).unwrap().remote_addr(),
        &nodes[1].addr
    );
    assert_eq!(
        nodes[0]
            .node
            .links
            .lookup_addr(dial_transport, &nodes[1].addr),
        None
    );
    assert_eq!(
        nodes[0]
            .node
            .links
            .lookup_addr(receive_transport, &nodes[1].addr),
        Some(link)
    );
    assert_eq!(
        nodes[0]
            .node
            .peers
            .lookup_session_index((receive_transport, index.as_u32())),
        Some(remote)
    );
    assert_eq!(
        nodes[0]
            .node
            .peers
            .lookup_session_index((dial_transport, index.as_u32())),
        None
    );
    assert!(nodes[0].node.pending_outbound.is_empty());
    assert_eq!(nodes[0].node.dataplane.fmp_handshake_candidate_count(), 0);
    assert_eq!(resources(&nodes[0]), (1, 0, 1, 1));
    quiesce(nodes).await;

    let mut endpoints: Vec<_> = nodes[..2]
        .iter_mut()
        .map(|node| node.node.attach_endpoint_data_io(8).unwrap())
        .collect();
    for (source, destination, payload) in [
        (0, 1, b"second-listener-out".as_slice()),
        (1, 0, b"second-listener-back".as_slice()),
    ] {
        let peer = PeerIdentity::from_pubkey_full(nodes[destination].node.identity.pubkey_full());
        send_endpoint_data_via_dataplane(&mut nodes[source].node, peer, payload.to_vec())
            .await
            .unwrap();
        let event = recv_endpoint_event_while_draining(
            nodes,
            &mut endpoints[destination].event_rx,
            Duration::from_secs(3),
            "second-listener bidirectional payload",
        )
        .await;
        endpoints[destination]
            .event_rx
            .release_messages(event.messages.len());
        assert_eq!(
            expect_single_endpoint_data_event(event).payload.as_slice(),
            payload
        );
    }
    quiesce(nodes).await;
    for endpoint in &mut endpoints {
        assert!(matches!(
            endpoint.event_rx.try_recv(),
            Err(tokio::sync::mpsc::error::TryRecvError::Empty)
        ));
    }
}

#[test]
fn winning_link_rebind_keeps_stats_and_only_removes_owned_aliases() {
    use crate::node::LinkRegistry;
    let mut links = LinkRegistry::default();
    let id = LinkId::new(1);
    let other = LinkId::new(2);
    let old = TransportAddr::from("127.0.0.1:1001");
    let alias = TransportAddr::from("127.0.0.1:1002");
    let new = TransportAddr::from("127.0.0.1:1003");
    let mut link = Link::new_with_timestamp(
        id,
        TransportId::new(1),
        old.clone(),
        LinkDirection::Outbound,
        Duration::from_millis(4),
        1_234,
    );
    link.set_connected();
    link.stats_mut().record_sent(37);
    links.insert(id, link);
    links.insert_addr((TransportId::new(1), alias.clone()), id);
    assert!(links.rebind_path(id, TransportId::new(1), old.clone()));
    assert_eq!(
        links.lookup_addr(TransportId::new(1), &alias),
        Some(id),
        "unchanged path must preserve hostname/ordinary aliases"
    );
    links.insert_addr((TransportId::new(1), old.clone()), other);
    assert!(links.rebind_path(id, TransportId::new(2), new.clone()));
    assert_eq!(links.lookup_addr(TransportId::new(1), &old), Some(other));
    assert_eq!(links.lookup_addr(TransportId::new(1), &alias), None);
    assert_eq!(links.lookup_addr(TransportId::new(2), &new), Some(id));
    let link = links.get(&id).unwrap();
    assert!(link.is_operational());
    assert_eq!(link.created_at(), 1_234);
    assert_eq!(link.base_rtt(), Duration::from_millis(4));
    assert_eq!(link.stats().packets_sent, 1);
    assert_eq!(link.stats().bytes_sent, 37);
}
