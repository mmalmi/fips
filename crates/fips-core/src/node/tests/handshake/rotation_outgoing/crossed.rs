use super::*;
use crate::node::tests::spanning_tree::process_dataplane_packet;

#[test]
fn retained_outgoing_reply_cannot_replace_newer_authenticated_incoming_epoch() {
    run_large_stack_async_test("outgoing-prepared-newer-incoming", || crossed(true));
}

#[test]
fn retained_outgoing_reply_preserves_same_epoch_crossed_winner() {
    run_large_stack_async_test("outgoing-prepared-same-epoch-crossed", || crossed(false));
}

fn restart(remote: &mut TestNode) {
    let mut config = remote.node.config.clone();
    config.node.identity.replace_nsec(Some(crate::encode_nsec(
        &remote.node.identity().keypair().secret_key(),
    )));
    let mut fresh = Node::new(config).unwrap();
    // Only test IO survives. Every epoch, Noise owner and protocol key comes
    // from an actual new Node with the same persistent identity.
    fresh.transports = std::mem::take(&mut remote.node.transports);
    fresh.tun_outbound_rx = remote.node.tun_outbound_rx.take();
    remote.node = fresh;
}

async fn msg1(node: &mut TestNode) -> ReceivedPacket {
    tokio::time::timeout(Duration::from_secs(1), async {
        loop {
            let packet = node.packet_rx.recv().await.unwrap();
            if Msg1Header::parse(packet.data.as_slice()).is_some() {
                return packet;
            }
            process_dataplane_packet(node, packet).await;
        }
    })
    .await
    .expect("genuine incoming UDP Msg1 must arrive")
}

async fn crossed(new_epoch: bool) {
    let mut nodes = [
        make_test_node().await,
        make_test_node().await,
        make_test_node().await,
    ];
    // The smaller remote's outgoing wins the existing crossed-dial rule.
    if nodes[0].node.node_addr() < nodes[1].node.node_addr() {
        nodes.swap(0, 1);
    }
    for node in &mut nodes {
        node.node.config.node.rekey.enabled = false;
        node.node.config.node.session.idle_timeout_secs = 0;
    }
    nodes[0].node.max_peers = 1;
    nodes[0].node.max_connections = 2;
    nodes[0].node.max_links = 3;
    nodes[0].node.config.node.neighbor_rotation = Some(NeighborRotationConfig {
        idle_secs: IDLE_MS / 1000,
        interval_secs: 1,
    });
    nodes[0].node.config.node.rate_limit.handshake_timeout_secs = TIMEOUT_MS / 1000;
    let local = *nodes[0].node.node_addr();
    let remote = *nodes[1].node.node_addr();
    let old = *nodes[2].node.node_addr();
    dial(&mut nodes, 0, 2).await;
    quiesce(&mut nodes).await;
    let incumbent = Owner::capture(&nodes[0], &old);
    assert!(Node::now_ms() - incumbent.authenticated_at < IDLE_MS);
    dial(&mut nodes, 0, 1).await;
    let original = nodes[0].node.peers.connection_values().next().unwrap();
    let saved_link = original.link_id();
    let saved_index = original.our_index().unwrap();
    let saved_epoch = nodes[1].node.startup_epoch;

    // For the unchanged process, both outbound requests precede either
    // response. The restarted process instead initiates after old Msg2 is held.
    let incoming = if new_epoch {
        None
    } else {
        dial(&mut nodes, 1, 0).await;
        Some(msg1(&mut nodes[0]).await)
    };
    let request = msg1(&mut nodes[1]).await;
    nodes[1].node.handle_msg1(request).await;
    let response = next_packet(&mut nodes[0]).await;
    assert_eq!(
        Msg2Header::parse(response.data.as_slice())
            .unwrap()
            .receiver_idx,
        saved_index
    );
    nodes[0].node.handle_msg2(response).await;
    let saved = nodes[0].node.get_connection(&saved_link).unwrap();
    assert!(saved.is_complete() && saved.has_session());
    assert!(saved.completed_handshake_response().is_some());
    assert_eq!(saved.remote_epoch(), Some(saved_epoch));
    assert_eq!(Owner::capture(&nodes[0], &old), incumbent);

    let incoming = if let Some(incoming) = incoming {
        incoming
    } else {
        restart(&mut nodes[1]);
        assert_eq!(*nodes[1].node.node_addr(), remote);
        assert_ne!(nodes[1].node.startup_epoch, saved_epoch);
        dial(&mut nodes, 1, 0).await;
        msg1(&mut nodes[0]).await
    };
    let request_bytes = incoming.data.as_slice().to_vec();
    nodes[0].node.handle_msg1(incoming).await;
    assert_eq!(resources(&nodes[0]), (1, 2, 3, 3));
    assert_eq!(Owner::capture(&nodes[0], &old), incumbent);
    let incoming_link = nodes[0]
        .node
        .peers
        .connection_values()
        .find(|conn| conn.is_inbound())
        .unwrap()
        .link_id();

    // A real incumbent departure frees capacity before either timer retries
    // the old outgoing proof. The exact incoming request can then receive its
    // stored response through normal duplicate handling, without direct
    // promotion or a specially ordered partial maintenance callback.
    let disconnect = crate::protocol::Disconnect::new(crate::protocol::DisconnectReason::Shutdown);
    nodes[2]
        .node
        .send_dataplane_fmp_link_plaintext(&local, &disconnect.encode(), false)
        .await
        .unwrap();
    tokio::time::timeout(Duration::from_secs(1), async {
        while nodes[0].node.get_peer(&old).is_some() {
            process_available_packets(&mut nodes).await;
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("authenticated incumbent Disconnect frees the roster slot");
    assert!(nodes[0].node.get_peer(&remote).is_none());
    nodes[1]
        .node
        .transports
        .get(&nodes[1].transport_id)
        .unwrap()
        .send(&nodes[0].addr, &request_bytes)
        .await
        .unwrap();
    let retry = msg1(&mut nodes[0]).await;
    assert_eq!(retry.data.as_slice(), request_bytes);
    nodes[0].node.handle_msg1(retry).await;
    tokio::time::timeout(Duration::from_secs(1), async {
        while nodes[0].node.get_peer(&remote).is_none() {
            process_available_packets(&mut nodes).await;
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("fresh encrypted confirmation installs the incoming owner");
    quiesce(&mut nodes).await;
    let winner = Owner::capture(&nodes[0], &remote);
    assert_eq!(winner.link, incoming_link);
    assert_eq!(winner.epoch, Some(nodes[1].node.startup_epoch));
    let saved = nodes[0].node.get_connection(&saved_link).unwrap();
    assert_eq!(saved.remote_epoch(), Some(saved_epoch));
    assert!(saved.completed_handshake_response().is_some());
    assert_eq!(saved_epoch != nodes[1].node.startup_epoch, new_epoch);

    let mut endpoint = nodes[1].node.attach_endpoint_data_io(8).unwrap();
    let identity = PeerIdentity::from_pubkey_full(nodes[1].node.identity.pubkey_full());
    send_endpoint_data_via_dataplane(
        &mut nodes[0].node,
        identity,
        b"incoming-before-retry".to_vec(),
    )
    .await
    .unwrap();
    let event = recv_endpoint_event_while_draining(
        &mut nodes,
        &mut endpoint.event_rx,
        Duration::from_secs(2),
        "newly confirmed incoming FSP before retained reply",
    )
    .await;
    endpoint.event_rx.release_messages(event.messages.len());
    assert_eq!(
        expect_single_endpoint_data_event(event).payload.as_slice(),
        b"incoming-before-retry"
    );
    quiesce(&mut nodes).await;
    let hash = *nodes[0]
        .node
        .get_session(&remote)
        .unwrap()
        .handshake_hash()
        .unwrap();
    assert_eq!(
        nodes[1].node.get_session(&local).unwrap().handshake_hash(),
        Some(&hash)
    );

    // Normal maintenance now resumes the old, independently authenticated
    // outgoing response. It cannot roll back the newer accepted process, and
    // the same-epoch control must retain the ordinary crossed winner.
    assert!(
        !nodes[0]
            .node
            .get_connection(&saved_link)
            .unwrap()
            .is_timed_out(Node::now_ms(), TIMEOUT_MS),
        "the guard must handle a live retained reply, not pass by timeout cleanup"
    );
    nodes[0].node.check_timeouts().await;
    nodes[0]
        .node
        .resend_pending_handshakes(Node::now_ms())
        .await;
    assert_eq!(Owner::capture(&nodes[0], &remote), winner);
    assert_eq!(
        nodes[0].node.get_session(&remote).unwrap().handshake_hash(),
        Some(&hash)
    );
    assert!(nodes[0].node.dataplane_has_fsp_owner(&remote));
    assert!(nodes[0].node.get_connection(&saved_link).is_none());
    assert!(!nodes[0].node.index_allocator.is_allocated(saved_index));
    assert!(nodes[0].node.pending_outbound.is_empty());
    assert_eq!(resources(&nodes[0]), (1, 0, 1, 1));
    let a = nodes[0].node.get_peer(&remote).unwrap();
    let b = nodes[1].node.get_peer(&local).unwrap();
    assert_eq!(a.our_index(), b.their_index());
    assert_eq!(a.their_index(), b.our_index());
    for (source, target) in [(0, remote), (1, local)] {
        assert!(
            nodes[source]
                .node
                .dataplane_fmp_link_metrics(&target, Instant::now())
                .unwrap()
                .current_epoch_authenticated
        );
    }
    send_endpoint_data_via_dataplane(
        &mut nodes[0].node,
        identity,
        b"incoming-after-retry".to_vec(),
    )
    .await
    .unwrap();
    let event = recv_endpoint_event_while_draining(
        &mut nodes,
        &mut endpoint.event_rx,
        Duration::from_secs(2),
        "retained incoming FSP after old proof cleanup",
    )
    .await;
    endpoint.event_rx.release_messages(event.messages.len());
    assert_eq!(
        expect_single_endpoint_data_event(event).payload.as_slice(),
        b"incoming-after-retry"
    );
    cleanup_nodes(&mut nodes).await;
}
