use super::*;
use crate::config::UdpConfig;
use crate::transport::udp::UdpTransport;
use crate::transport::{ReceivedPacket, packet_channel, resolve_socket_addr};

#[test]
fn pending_same_path_refresh_defers_active_peer_rekey() {
    run_large_stack_async_test("refresh-before-fmp-rekey", || async {
        let _guard = lock_large_network_test().await;
        let mut nodes = vec![
            make_test_node().await,
            make_test_node().await,
            make_test_node().await,
        ];
        nodes.sort_by_key(|node| std::cmp::Reverse(*node.node.node_addr()));
        let result = AssertUnwindSafe(reverse_order(&mut nodes))
            .catch_unwind()
            .await;
        cleanup_nodes(&mut nodes).await;
        if let Err(panic) = result {
            std::panic::resume_unwind(panic);
        }
    });
}

async fn reverse_order(nodes: &mut [TestNode]) {
    setup(nodes).await;
    let identities: Vec<_> = nodes
        .iter()
        .map(|node| PeerIdentity::from_pubkey_full(node.node.identity().pubkey_full()))
        .collect();
    let mut endpoints: Vec<_> = nodes
        .iter_mut()
        .map(|node| node.node.attach_endpoint_data_io(16).unwrap())
        .collect();
    for (source, destination) in [(0, 2), (2, 0)] {
        nodes[source]
            .node
            .set_endpoint_source_route(identities[destination], Some(identities[1]))
            .unwrap();
    }
    round(nodes, &mut endpoints, &identities, 0).await;
    drain_to_quiescence(nodes).await;
    let old = (0..2)
        .map(|local| {
            let peer = nodes[local]
                .node
                .get_peer(identities[1 - local].node_addr())
                .unwrap();
            (
                peer.link_id(),
                peer.our_index(),
                peer.their_index(),
                peer.current_k_bit(),
            )
        })
        .collect::<Vec<_>>();
    let addr = nodes[1].addr.clone();
    let source = &mut nodes[0];
    source
        .node
        .initiate_connection(source.transport_id, addr, identities[1])
        .await
        .unwrap();
    let candidate = source.node.peers.connection_values().next().unwrap();
    let candidate_index = candidate.our_index().unwrap();
    let candidate_link = candidate.link_id();
    let allocated = source.node.index_allocator.count();
    assert!(
        !source.node.initiate_rekey(identities[1].node_addr()).await,
        "an actual pending same-path Msg1 must own this handshake turn"
    );
    assert_eq!(source.node.index_allocator.count(), allocated);
    assert_eq!(source.node.peers.connection_len(), 1);
    assert_eq!(
        source
            .node
            .pending_outbound
            .get(&(source.transport_id, candidate_index.as_u32())),
        Some(&candidate_link)
    );
    assert!(
        !source
            .node
            .get_peer(identities[1].node_addr())
            .unwrap()
            .rekey_in_progress()
    );
    assert!(
        source
            .node
            .get_peer(identities[1].node_addr())
            .unwrap()
            .pending_new_session()
            .is_none()
    );
    let sender = exchange_refresh(nodes).await;
    assert_eq!(sender, candidate_index);
    drain_to_quiescence(nodes).await;
    assert!(nodes[0].node.peers.connection_is_empty());
    assert!(!nodes[0].node.links.contains_key(&candidate_link));
    assert!(!nodes[0].node.index_allocator.is_allocated(candidate_index));
    round(nodes, &mut endpoints, &identities, 1).await;
    for local in 0..2 {
        let peer = nodes[local]
            .node
            .get_peer(identities[1 - local].node_addr())
            .unwrap();
        assert_eq!(
            (
                peer.link_id(),
                peer.our_index(),
                peer.their_index(),
                peer.current_k_bit()
            ),
            old[local]
        );
        assert_eq!(
            nodes[local].node.peers.lookup_session_index((
                nodes[local].transport_id,
                peer.our_index().unwrap().as_u32()
            )),
            Some(*identities[1 - local].node_addr())
        );
    }
}

pub(super) async fn bind_localhost_family(nodes: &mut [TestNode]) {
    // Match the resolver used by production DNS preparation, including address
    // family/order; all three UDP sockets must be able to reach that result.
    let bind = resolve_socket_addr(&TransportAddr::from_string("localhost:0"))
        .await
        .unwrap();
    for node in nodes {
        node.node
            .transports
            .get_mut(&node.transport_id)
            .unwrap()
            .stop()
            .await
            .unwrap();
        let (packet_tx, packet_rx) = packet_channel(256);
        let mut transport = UdpTransport::new(
            node.transport_id,
            None,
            UdpConfig {
                bind_addr: Some(bind.to_string()),
                mtu: Some(1280),
                ..Default::default()
            },
            packet_tx,
        );
        transport.start_async().await.unwrap();
        node.addr = TransportAddr::from_string(&transport.local_addr().unwrap().to_string());
        node.packet_rx = packet_rx;
        node.node
            .transports
            .insert(node.transport_id, TransportHandle::Udp(transport));
    }
}

pub(super) async fn queue_hostname_refresh(nodes: &mut [TestNode], identities: &[PeerIdentity]) {
    let remote = nodes[1]
        .addr
        .as_str()
        .unwrap()
        .parse::<std::net::SocketAddr>()
        .unwrap();
    let hostname = TransportAddr::from_string(&format!("localhost:{}", remote.port()));
    let source = &mut nodes[0];
    source
        .node
        .initiate_connection(source.transport_id, hostname, identities[1])
        .await
        .unwrap();
    assert_eq!(source.node.pending_connects.len(), 1);
    assert!(source.node.pending_connects[0].address_resolution.is_some());
    assert!(
        source.node.peers.connection_is_empty(),
        "hostname preparation must not fabricate a Noise flight"
    );
}

pub(super) async fn resolve_during_rekey(nodes: &mut [TestNode], identities: &[PeerIdentity]) {
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        assert!(
            nodes[0]
                .node
                .get_peer(identities[1].node_addr())
                .unwrap()
                .rekey_in_progress()
        );
        poll_refresh(nodes, identities).await;
        if nodes[0].node.pending_connects.is_empty()
            || nodes[0].node.pending_connects[0]
                .address_resolution
                .is_none()
        {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "real localhost preparation must resolve"
        );
        tokio::time::sleep(Duration::from_millis(1)).await;
    }
    assert_resolved_pending(nodes, identities).await;
}

pub(super) async fn assert_resolved_pending(nodes: &mut [TestNode], identities: &[PeerIdentity]) {
    if let Some(pending) = nodes[0].node.pending_connects.first() {
        assert_eq!(pending.remote_addr, nodes[1].addr);
        assert!(pending.address_resolution.is_none());
        assert_eq!(pending.peer_identity, identities[1]);
    }
    // Safe coalescing with the existing rekey is also valid. An independent
    // Noise connection must not appear while the original rekey is pending.
    assert!(nodes[0].node.peers.connection_is_empty());
    poll_refresh(nodes, identities).await;
    assert!(nodes[0].node.peers.connection_is_empty());
}

pub(super) async fn poll_refresh(nodes: &mut [TestNode], identities: &[PeerIdentity]) {
    let Some(preparation_link) = nodes[0]
        .node
        .pending_connects
        .first()
        .map(|pending| pending.link_id)
    else {
        return;
    };
    nodes[0].node.poll_pending_connects().await;
    if nodes[0].node.pending_connects.is_empty() {
        if nodes[0].node.peers.connection_is_empty() {
            // Deduplication may retire only the temporary preparation link.
            assert!(!nodes[0].node.links.contains_key(&preparation_link));
            let source = &nodes[0];
            let peer = source.node.get_peer(identities[1].node_addr()).unwrap();
            assert_eq!(
                source
                    .node
                    .links
                    .lookup_addr(source.transport_id, &nodes[1].addr),
                Some(peer.link_id())
            );
            eprintln!("DNS rekey overlap: resolved preparation coalesced without Msg1");
        } else {
            let sender = exchange_refresh(nodes).await;
            eprintln!(
                "DNS rekey overlap: actual late Msg1/Msg2 completed, distinct_sender_index={}",
                nodes[0]
                    .node
                    .get_peer(identities[1].node_addr())
                    .unwrap()
                    .our_index()
                    != Some(sender)
            );
        }
    }
}

pub(super) async fn finish_retained_refresh(nodes: &mut [TestNode], identities: &[PeerIdentity]) {
    let deadline = Instant::now() + Duration::from_secs(2);
    while !nodes[0].node.pending_connects.is_empty() || !nodes[0].node.peers.connection_is_empty() {
        poll_refresh(nodes, identities).await;
        process_available_packets(nodes).await;
        assert!(
            Instant::now() < deadline,
            "resolved preparation must finish after the real key drain"
        );
        tokio::time::sleep(Duration::from_millis(1)).await;
    }
}

async fn next_handshake(nodes: &mut [TestNode], receiver: usize, msg1: bool) -> ReceivedPacket {
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            let packet = nodes[receiver].packet_rx.recv().await.unwrap();
            let expected = if msg1 {
                Msg1Header::parse(packet.data.as_slice()).is_some()
            } else {
                Msg2Header::parse(packet.data.as_slice()).is_some()
            };
            if packet.remote_addr == nodes[1 - receiver].addr && expected {
                break packet;
            }
            process_dataplane_packet(&mut nodes[receiver], packet).await;
        }
    })
    .await
    .expect("actual UDP handshake flight must arrive")
}

async fn exchange_refresh(nodes: &mut [TestNode]) -> crate::utils::index::SessionIndex {
    let request = next_handshake(nodes, 1, true).await;
    let index = Msg1Header::parse(request.data.as_slice())
        .unwrap()
        .sender_idx;
    process_dataplane_packet(&mut nodes[1], request).await;
    let response = next_handshake(nodes, 0, false).await;
    assert_eq!(
        Msg2Header::parse(response.data.as_slice())
            .unwrap()
            .receiver_idx,
        index
    );
    process_dataplane_packet(&mut nodes[0], response).await;
    index
}

pub(super) async fn refresh_before_confirmation(
    nodes: &mut [TestNode],
    identities: &[PeerIdentity],
) {
    let remote = nodes[1].addr.clone();
    let source = &mut nodes[0];
    let peer = source.node.get_peer(identities[1].node_addr()).unwrap();
    assert!(peer.is_draining() && peer.pending_new_session().is_none());
    assert!(
        !source
            .node
            .dataplane_fmp_link_metrics(identities[1].node_addr(), std::time::Instant::now())
            .unwrap()
            .current_epoch_authenticated
    );
    let indexes = source.node.index_allocator.count();
    let links = source.node.links.len();
    assert!(source.node.peers.connection_is_empty() && source.node.pending_connects.is_empty());
    source
        .node
        .initiate_connection(source.transport_id, remote, identities[1])
        .await
        .unwrap();
    assert!(
        source.node.peers.connection_is_empty(),
        "unconfirmed cutover still owns the same numeric path"
    );
    assert!(source.node.pending_connects.is_empty());
    assert_eq!(source.node.index_allocator.count(), indexes);
    assert_eq!(source.node.links.len(), links);
    // The caller next captures the first real carrier packet: a hidden second
    // Msg1 would fail its framing check before the routed payload is delivered.
}

pub(super) async fn refresh_after_confirmation(
    nodes: &mut [TestNode],
    endpoints: &mut [EndpointDataIo],
    identities: &[PeerIdentity],
) {
    let epochs: Vec<_> = FLOWS
        .iter()
        .map(|&(source, destination)| {
            nodes[source]
                .node
                .get_session(identities[destination].node_addr())
                .unwrap()
                .session_start_ms()
        })
        .collect();
    let owners: Vec<_> = (0..2)
        .map(|local| {
            let peer = nodes[local]
                .node
                .get_peer(identities[1 - local].node_addr())
                .unwrap();
            assert!(
                peer.is_draining(),
                "refresh eligibility must be proved before old-key expiry"
            );
            assert!(
                nodes[local]
                    .node
                    .dataplane_fmp_link_metrics(
                        identities[1 - local].node_addr(),
                        std::time::Instant::now()
                    )
                    .unwrap()
                    .current_epoch_authenticated,
                "actual new-key return traffic must supply reciprocal proof"
            );
            (
                peer.link_id(),
                peer.authenticated_at(),
                peer.our_index().unwrap(),
                peer.their_index().unwrap(),
                peer.current_k_bit(),
            )
        })
        .collect();
    let remote = nodes[1].addr.clone();
    let source = &mut nodes[0];
    source
        .node
        .initiate_connection(source.transport_id, remote, identities[1])
        .await
        .unwrap();
    assert_eq!(
        source.node.peers.connection_len(),
        1,
        "authenticated drain must not blanket-block fresh discovery"
    );
    let candidate = source.node.peers.connection_values().next().unwrap();
    let candidate_index = candidate.our_index().unwrap();
    let candidate_link = candidate.link_id();
    assert_ne!(candidate_index, owners[0].2);
    assert!(
        source
            .node
            .get_peer(identities[1].node_addr())
            .unwrap()
            .is_draining()
    );
    assert_eq!(
        exchange_refresh(nodes).await,
        candidate_index,
        "eligibility must produce an actual correlated UDP Msg1/Msg2 exchange"
    );
    assert!(nodes[0].node.peers.connection_is_empty());
    assert!(!nodes[0].node.links.contains_key(&candidate_link));
    assert!(!nodes[0].node.index_allocator.is_allocated(candidate_index));
    round(nodes, endpoints, identities, 3).await;
    for local in 0..2 {
        let peer = nodes[local]
            .node
            .get_peer(identities[1 - local].node_addr())
            .unwrap();
        assert!(
            peer.is_draining(),
            "payload progress must occur during the same drain window"
        );
        assert_eq!(
            (
                peer.link_id(),
                peer.authenticated_at(),
                peer.our_index().unwrap(),
                peer.their_index().unwrap(),
                peer.current_k_bit()
            ),
            owners[local]
        );
        assert_eq!(
            peer.their_index(),
            nodes[1 - local]
                .node
                .get_peer(identities[local].node_addr())
                .unwrap()
                .our_index()
        );
        assert_eq!(
            nodes[local].node.peers.lookup_session_index((
                nodes[local].transport_id,
                peer.our_index().unwrap().as_u32()
            )),
            Some(*identities[1 - local].node_addr())
        );
    }
    for ((source, destination), epoch) in FLOWS.into_iter().zip(epochs) {
        assert_eq!(
            nodes[source]
                .node
                .get_session(identities[destination].node_addr())
                .unwrap()
                .session_start_ms(),
            epoch
        );
    }
    for (source, destination) in [(0, 2), (2, 0)] {
        assert_eq!(
            nodes[source]
                .node
                .dataplane
                .fsp_owner_next_hop(identities[destination].node_addr()),
            Some(*identities[1].node_addr())
        );
    }
    eprintln!(
        "direct cutover refresh: pre-confirmation suppressed; authenticated drain Msg1/Msg2 dispatched; six fresh payloads delivered exactly once"
    );
}
