use super::*;

#[test]
fn inbound_paths_cannot_monopolize_candidate_capacity() {
    super::super::super::session::run_large_stack_async_test(
        "inbound-peer-candidate-cap",
        || async {
            let mut node = make_test_node().await;
            let remote = make_node();
            let (_socket, source) = local_path().await;
            let mut current = connect(&mut node, &remote, &source, 10).await;
            node.node.max_connections = 16;
            node.node.max_links = 16;
            let mut paths = Vec::new();
            let mut candidates = Vec::new();
            for index in 0..4 {
                let (socket, path) = local_path().await;
                candidates.push(connect(&mut node, &remote, &path, 20 + index).await);
                paths.push((socket, path));
            }
            let mut owners: Vec<_> = node
                .node
                .peers
                .connection_iter()
                .map(|(link, conn)| {
                    (
                        *link,
                        conn.our_index(),
                        conn.started_at(),
                        conn.last_activity(),
                    )
                })
                .collect();
            owners.sort_by_key(|row| row.0.as_u64());
            let (_extra_socket, extra_path) = local_path().await;
            request(&mut node, &remote, &extra_path, 30).await;
            assert_eq!(
                node.node.connection_count(),
                4,
                "one identity cannot fill unrelated peers' slots"
            );
            assert_eq!(node.node.link_count(), 5);
            assert_eq!(node.node.index_allocator.count(), 5);

            // Exact retries still get the retained response without moving a deadline.
            let retained = node
                .node
                .get_connection(&candidates[0].link)
                .unwrap()
                .handshake_msg1()
                .unwrap()
                .to_vec();
            node.node
                .handle_msg1(ReceivedPacket::with_timestamp(
                    node.transport_id,
                    paths[0].1.clone(),
                    PacketBuffer::new(retained),
                    Node::now_ms(),
                ))
                .await;
            let mut after: Vec<_> = node
                .node
                .peers
                .connection_iter()
                .map(|(link, conn)| {
                    (
                        *link,
                        conn.our_index(),
                        conn.started_at(),
                        conn.last_activity(),
                    )
                })
                .collect();
            after.sort_by_key(|row| row.0.as_u64());
            assert_eq!(
                owners, after,
                "rejection and replay preserve existing candidates"
            );
            assert_eq!(
                node.node.get_peer(remote.node_addr()).unwrap().our_index(),
                Some(current.index)
            );

            let newcomer = make_node();
            let (_new_socket, new_path) = local_path().await;
            connect(&mut node, &newcomer, &new_path, 40).await;
            assert_eq!(
                node.node.peer_count(),
                2,
                "an unrelated authenticated peer can still join"
            );

            let heartbeat = [crate::protocol::LinkMessageType::Heartbeat.to_byte()];
            let packet = current.frame(node.transport_id, &heartbeat);
            super::super::super::spanning_tree::process_dataplane_packet(&mut node, packet).await;
            assert_eq!(
                node.node
                    .dataplane_fmp_link_metrics(remote.node_addr(), Instant::now())
                    .unwrap()
                    .rx_packets,
                1
            );
            node.node
                .get_peer_mut(remote.node_addr())
                .unwrap()
                .touch(Node::now_ms() - 1_001);
            let packet = candidates[0].frame(node.transport_id, &heartbeat);
            super::super::super::spanning_tree::process_dataplane_packet(&mut node, packet).await;
            assert_eq!(
                node.node.get_peer(remote.node_addr()).unwrap().our_index(),
                Some(candidates[0].index),
                "an admitted alternate can still confirm and replace its owner"
            );
            cleanup_nodes(std::slice::from_mut(&mut node)).await;
        },
    );
}

#[test]
fn direct_outbound_paths_obey_the_existing_peer_candidate_budget() {
    super::super::super::session::run_large_stack_async_test(
        "outbound-peer-candidate-cap",
        || async {
            let mut node = make_test_node().await;
            let remote = make_node();
            let identity = PeerIdentity::from_pubkey_full(remote.identity.pubkey_full());
            let mut paths = Vec::new();
            node.node.max_connections = 16;
            node.node.max_links = 16;
            for _ in 0..4 {
                let (socket, path) = local_path().await;
                node.node
                    .initiate_connection(node.transport_id, path.clone(), identity)
                    .await
                    .unwrap();
                paths.push((socket, path));
            }
            let (_socket, extra_path) = local_path().await;
            let result = node
                .node
                .initiate_connection(node.transport_id, extra_path, identity)
                .await;
            assert!(
                result.is_err(),
                "direct callers cannot bypass path selection's four-candidate budget"
            );
            assert_eq!(node.node.connection_count(), 4);
            assert_eq!(node.node.link_count(), 4);
            assert_eq!(node.node.index_allocator.count(), 4);
            node.node
                .initiate_connection(node.transport_id, paths[0].1.clone(), identity)
                .await
                .unwrap();
            assert_eq!(
                node.node.connection_count(),
                4,
                "same-path requests remain idempotent"
            );
            let other = make_node();
            let (_other_socket, other_path) = local_path().await;
            node.node
                .initiate_connection(
                    node.transport_id,
                    other_path,
                    PeerIdentity::from_pubkey_full(other.identity.pubkey_full()),
                )
                .await
                .unwrap();
            assert_eq!(
                node.node.connection_count(),
                5,
                "capacity remains available to another peer"
            );
            cleanup_nodes(std::slice::from_mut(&mut node)).await;
        },
    );
}

#[test]
fn full_peer_budget_keeps_one_crossed_inbound_half() {
    super::super::super::session::run_large_stack_async_test(
        "crossed-peer-candidate-cap",
        || async {
            let mut node = make_test_node().await;
            let remote = make_node();
            let identity = PeerIdentity::from_pubkey_full(remote.identity.pubkey_full());
            let (_socket, source) = local_path().await;
            let current = connect(&mut node, &remote, &source, 10).await;
            node.node.max_connections = 16;
            node.node.max_links = 16;
            let mut paths = Vec::new();
            for _ in 0..4 {
                let (socket, path) = local_path().await;
                node.node
                    .initiate_connection(node.transport_id, path.clone(), identity)
                    .await
                    .unwrap();
                paths.push((socket, path));
            }
            let (_inbound_socket, inbound) = local_path().await;
            let candidate = connect(&mut node, &remote, &inbound, 20).await;
            assert_eq!(
                node.node.connection_count(),
                5,
                "crossed dial keeps one inbound reply slot"
            );
            let (_extra_socket, extra) = local_path().await;
            request(&mut node, &remote, &extra, 21).await;
            assert_eq!(
                node.node.connection_count(),
                5,
                "different paths cannot multiply the crossed allowance"
            );
            assert_eq!(node.node.link_count(), 6);
            assert_eq!(node.node.index_allocator.count(), 6);
            assert!(node.node.get_connection(&candidate.link).is_some());
            assert_eq!(
                node.node.get_peer(remote.node_addr()).unwrap().our_index(),
                Some(current.index)
            );
            cleanup_nodes(std::slice::from_mut(&mut node)).await;
        },
    );
}

#[test]
fn carrier_preparation_and_handshakes_share_the_peer_budget() {
    super::super::super::session::run_large_stack_async_test(
        "preparation-peer-candidate-cap",
        || async {
            let mut node = make_test_node().await;
            let remote = make_node();
            let identity = PeerIdentity::from_pubkey_full(remote.identity.pubkey_full());
            let (_socket, source) = local_path().await;
            connect(&mut node, &remote, &source, 10).await;
            let mut paths = Vec::new();
            for index in 0..2 {
                let (socket, path) = local_path().await;
                connect(&mut node, &remote, &path, 20 + index).await;
                paths.push((socket, path));
            }
            // Hostname preparation is deferred before any Noise connection exists.
            for _ in 0..2 {
                let (socket, _) = local_path().await;
                let addr = TransportAddr::from_string(&format!(
                    "localhost:{}",
                    socket.local_addr().unwrap().port()
                ));
                node.node
                    .initiate_connection(node.transport_id, addr.clone(), identity)
                    .await
                    .unwrap();
                paths.push((socket, addr));
            }
            assert_eq!(node.node.pending_connects.len(), 2);
            assert_eq!(node.node.connection_count(), 2);
            let (_extra_socket, extra) = local_path().await;
            request(&mut node, &remote, &extra, 30).await;
            assert_eq!(
                node.node.connection_count(),
                2,
                "inbound admission counts carrier preparations"
            );
            assert!(
                node.node
                    .initiate_connection(node.transport_id, extra, identity)
                    .await
                    .is_err()
            );
            let link = node.node.pending_connects[0].link_id;
            node.node.retire_connection_preparation(link).await;
            let (_new_socket, new_path) = local_path().await;
            connect(&mut node, &remote, &new_path, 31).await;
            assert_eq!(
                node.node.connection_count(),
                3,
                "retirement releases precisely one peer slot"
            );
            assert_eq!(node.node.pending_connects.len(), 1);
            cleanup_nodes(std::slice::from_mut(&mut node)).await;
        },
    );
}
