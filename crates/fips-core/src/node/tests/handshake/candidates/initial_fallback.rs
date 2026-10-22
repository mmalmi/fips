use super::*;

#[test]
fn confirmed_fallback_replaces_only_unconfirmed_initial_responder() {
    super::super::super::session::run_large_stack_async_test(
        "confirmed-initial-fallback",
        || async {
            for (established, late_heartbeat, owner_changed) in [
                (false, false, false),
                (true, false, false),
                (false, true, false),
                (false, false, true),
            ] {
                let mut node = make_test_node().await;
                let remote = make_node();
                // Generation is timestamp-derived, not a first-session counter.
                tokio::time::sleep(Duration::from_millis(5)).await;
                let (_first_socket, first) = local_path().await;
                let (_fallback_socket, fallback) = local_path().await;
                let (_newer_socket, newer_path) = local_path().await;
                let mut peer = crate::config::PeerConfig::new(
                    remote.identity.npub(),
                    "udp",
                    first.to_string(),
                );
                peer.addresses = vec![
                    crate::config::PeerAddress::with_priority("udp", first.to_string(), 10),
                    crate::config::PeerAddress::with_priority("udp", fallback.to_string(), 200),
                    crate::config::PeerAddress::with_priority("udp", newer_path.to_string(), 150),
                ];
                node.node.config.peers = vec![peer];
                node.node.configured_peers =
                    crate::node::ConfiguredPeerLookup::from_config(&node.node.config);
                let mut owner = connect(&mut node, &remote, &first, 10).await;
                assert!(
                    node.node
                        .get_peer(remote.node_addr())
                        .unwrap()
                        .session_generation()
                        > 1
                );
                if established {
                    deliver_owner_heartbeat(&mut node, &mut owner, remote.node_addr()).await;
                }
                assert_eq!(
                    node.node
                        .dataplane_fmp_link_metrics(remote.node_addr(), Instant::now())
                        .unwrap()
                        .current_epoch_authenticated,
                    established,
                );
                let mut candidate = connect(&mut node, &remote, &fallback, 20).await;
                assert!(!node.node.alternate_path_priority_allows_replace(
                    remote.node_addr(),
                    node.transport_id,
                    &fallback,
                ));
                assert_eq!(
                    node.node.get_peer(remote.node_addr()).unwrap().our_index(),
                    Some(owner.index)
                );

                // Neither a second Msg1 nor an unauthenticated confirmation
                // can displace the initial receiver, regardless of its priority.
                let heartbeat = [crate::protocol::LinkMessageType::Heartbeat.to_byte()];
                let valid = candidate.frame(node.transport_id, &heartbeat);
                let mut corrupted = valid.data.as_slice().to_vec();
                *corrupted.last_mut().unwrap() ^= 1;
                let forged = ReceivedPacket::with_timestamp(
                    node.transport_id,
                    fallback.clone(),
                    PacketBuffer::new(corrupted),
                    Node::now_ms(),
                );
                assert!(!node.node.confirm_pending_handshake(forged).await);
                assert_eq!(
                    node.node.get_peer(remote.node_addr()).unwrap().our_index(),
                    Some(owner.index)
                );
                assert!(
                    node.node
                        .get_connection(&candidate.link)
                        .unwrap()
                        .handshake_confirmation()
                        .is_none()
                );

                // The alternate receiver has already been advertised. A
                // delayed first-path heartbeat must not revoke that offer:
                // its sender can have switched to the candidate meanwhile.
                if late_heartbeat {
                    deliver_owner_heartbeat(&mut node, &mut owner, remote.node_addr()).await;
                }

                let retained_index = if owner_changed {
                    // A newer receiver on the same identity must not inherit a
                    // delayed candidate's proof for the previous owner.
                    let mut newer = connect(&mut node, &remote, &newer_path, 30).await;
                    node.node
                        .get_peer_mut(remote.node_addr())
                        .unwrap()
                        .touch(Node::now_ms());
                    assert!(
                        node.node
                            .confirm_pending_handshake(newer.frame(node.transport_id, &heartbeat))
                            .await
                    );
                    assert_eq!(
                        node.node.get_peer(remote.node_addr()).unwrap().our_index(),
                        Some(newer.index)
                    );
                    newer.index
                } else {
                    owner.index
                };

                // Keep this a fresh-path decision, not the existing quiet UDP
                // roaming exception. The proof is a real candidate-key frame.
                node.node
                    .get_peer_mut(remote.node_addr())
                    .unwrap()
                    .touch(Node::now_ms());
                let promoted = node.node.confirm_pending_handshake(valid).await;
                assert_eq!(promoted, !established && !owner_changed);
                assert_eq!(
                    node.node.get_peer(remote.node_addr()).unwrap().our_index(),
                    Some(if established || owner_changed {
                        retained_index
                    } else {
                        candidate.index
                    }),
                    "confirmed fallback only displaces an unconfirmed initial owner",
                );
                assert!(node.node.get_connection(&candidate.link).is_none());
                cleanup_nodes(std::slice::from_mut(&mut node)).await;
            }
        },
    );
}
