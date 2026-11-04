use super::*;
use crate::protocol::{LinkMessageType, TreeAnnounce};

mod coordinates;
mod listeners;

async fn node(strict: bool) -> TestNode {
    let mut node = make_test_node().await;
    // Deserialize the opt-in as an application does. The pre-fix library
    // ignores the unknown option, so the same fixture supplies its RED.
    let mut config = serde_json::to_value(&node.node.config).unwrap();
    config["node"]["leaf_only"] = true.into();
    config["node"]["strict_client_only"] = strict.into();
    config["node"]["tree"]["announce_min_interval_ms"] = 10.into();
    node.node.config = serde_json::from_value(config).unwrap();
    node.node.refresh_client_role();
    node
}

async fn attach(node: &mut TestNode, remote: &Node) -> (tokio::net::UdpSocket, Candidate) {
    let (socket, source) = local_path().await;
    let mut handshake =
        HandshakeState::new_initiator(remote.identity.keypair(), node.node.identity.pubkey_full());
    handshake.set_local_epoch(remote.startup_epoch);
    let wire = build_msg1(
        SessionIndex::new(123),
        &handshake.write_message_1().unwrap(),
    );
    socket.send_to(&wire, node.addr.to_string()).await.unwrap();
    let packet = tokio::time::timeout(Duration::from_secs(2), node.packet_rx.recv())
        .await
        .unwrap()
        .unwrap();
    node.node.handle_msg1(packet).await;
    let mut bytes = [0; 2048];
    let n = tokio::time::timeout(Duration::from_secs(2), socket.recv(&mut bytes))
        .await
        .unwrap()
        .unwrap();
    let header = Msg2Header::parse(&bytes[..n]).unwrap();
    handshake
        .read_message_2(header.noise_msg2(&bytes[..n]))
        .unwrap();
    let candidate = Candidate {
        link: node
            .node
            .links
            .lookup_addr(node.transport_id, &source)
            .unwrap(),
        index: header.sender_idx,
        session: handshake.into_session().unwrap(),
        source,
    };
    (socket, candidate)
}

async fn send(
    node: &mut TestNode,
    socket: &tokio::net::UdpSocket,
    peer: &mut Candidate,
    body: &[u8],
) {
    let wire = peer.frame(node.transport_id, body);
    socket
        .send_to(wire.data.as_slice(), node.addr.to_string())
        .await
        .unwrap();
    let packet = tokio::time::timeout(Duration::from_secs(2), node.packet_rx.recv())
        .await
        .unwrap()
        .unwrap();
    crate::node::tests::spanning_tree::process_dataplane_packet(node, packet).await;
    process_dataplane_completions(&mut node.node).await;
}

async fn frames(socket: &tokio::net::UdpSocket, peer: &mut Candidate) -> Vec<Vec<u8>> {
    let mut frames = Vec::new();
    let mut bytes = [0; 4096];
    while let Ok(Ok(n)) =
        tokio::time::timeout(Duration::from_millis(25), socket.recv(&mut bytes)).await
    {
        let wire = &bytes[..n];
        let header = crate::dataplane::FmpWireHeader::parse_encrypted(wire).unwrap();
        let offset = usize::from(header.ciphertext_offset());
        let plaintext = peer
            .session
            .decrypt_with_replay_check_and_aad(&wire[offset..], header.counter(), &wire[..offset])
            .unwrap();
        assert!(plaintext.len() >= 5);
        frames.push(plaintext[4..].to_vec());
        assert!(frames.len() < 32, "bounded control flight");
    }
    frames
}

fn run(strict: bool, modern: bool) {
    crate::node::tests::session::run_large_stack_async_test(
        "strict-client-wire",
        move || async move {
            let mut node = node(strict).await;
            let remote = make_node();
            let (socket, mut peer) = attach(&mut node, &remote).await;
            send(
                &mut node,
                &socket,
                &mut peer,
                &[LinkMessageType::Heartbeat.to_byte()],
            )
            .await;
            let mut observed = frames(&socket, &mut peer).await;

            // The peer advertises a real, signed ancestry. A legacy peer ignores
            // ClientSupport and never sends it; the modern peer acknowledges it.
            let addr = *remote.node_addr();
            let announce = TreeAnnounce::new(
                remote.tree_state.my_declaration().clone(),
                remote.tree_state.my_coords().clone(),
            )
            .encode()
            .unwrap();
            send(&mut node, &socket, &mut peer, &announce).await;
            if modern {
                send(
                    &mut node,
                    &socket,
                    &mut peer,
                    &[LinkMessageType::ClientSupport.to_byte()],
                )
                .await;
            }
            for _ in 0..3 {
                tokio::time::sleep(Duration::from_millis(15)).await;
                node.node.send_tree_announce_to_peer(&addr).await.unwrap();
                node.node.bloom_state.mark_update_needed(addr);
                node.node.send_pending_filter_announces().await;
                observed.extend(frames(&socket, &mut peer).await);
            }
            assert!(
                observed
                    .iter()
                    .any(|body| body[0] == LinkMessageType::ClientSupport.to_byte())
            );
            if strict {
                assert!(node.node.is_leaf_only());
                assert!(
                    !observed.iter().any(|body| matches!(body[0], 0x10 | 0x20)),
                    "strict clients must not disclose tree ancestry or Bloom filters: {observed:?}"
                );
                assert_eq!(
                    observed
                        .iter()
                        .any(|body| body[0] == LinkMessageType::ClientOnly.to_byte()),
                    modern
                );
                // Restarted capabilities must fail closed until renegotiated.
                node.node.reset_peer_routing_after_restart(&addr);
                node.node.refresh_client_role();
                assert!(node.node.is_leaf_only());
                tokio::time::sleep(Duration::from_millis(15)).await;
                node.node.send_tree_announce_to_peer(&addr).await.unwrap();
                let restart = frames(&socket, &mut peer).await;
                assert!(
                    !restart
                        .iter()
                        .any(|body| matches!(body[0], 0x10 | 0x20 | 0x52))
                );
            } else {
                assert!(!node.node.is_leaf_only());
                assert!(
                    observed
                        .iter()
                        .any(|body| body[0] == LinkMessageType::TreeAnnounce.to_byte())
                );
                assert!(
                    observed
                        .iter()
                        .any(|body| body[0] == LinkMessageType::FilterAnnounce.to_byte())
                );
            }
            cleanup_nodes(&mut [node]).await;
        },
    );
}

#[test]
fn strict_client_legacy_wire_never_falls_back_to_tree_or_bloom() {
    run(true, false);
}

#[test]
fn strict_client_modern_wire_uses_only_client_role_and_survives_restart() {
    run(true, true);
}

#[test]
fn preferred_client_legacy_wire_retains_router_compatibility() {
    run(false, false);
}
