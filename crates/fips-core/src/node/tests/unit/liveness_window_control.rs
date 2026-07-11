#[tokio::test]
async fn fresh_control_with_unreturned_endpoint_data_keeps_direct_without_fallback_peer() {
    let local_identity = Identity::generate();
    let peer_identity = Identity::generate();
    let peer_config = crate::config::PeerConfig {
        npub: peer_identity.npub(),
        alias: None,
        addresses: vec![
            crate::config::PeerAddress::with_priority("udp", "203.0.113.9:2121", 1)
                .with_seen_at_ms(10),
        ],
        connect_policy: crate::config::ConnectPolicy::AutoConnect,
        auto_reconnect: true,
        discovery_fallback_transit: true,
    };
    let peer = PeerIdentity::from_npub(&peer_config.npub).expect("peer identity");
    let peer_addr = *peer.node_addr();

    let mut config = Config::new();
    config.node.routing.mode = crate::config::RoutingMode::ReplyLearned;
    config.peers.push(peer_config);
    let link_session = make_test_fmp_session(&local_identity, &peer_identity, [1; 8], [2; 8]);
    let endpoint_session = make_test_fmp_session(&local_identity, &peer_identity, [3; 8], [4; 8]);
    let mut node = Node::with_identity(local_identity, config).expect("node");
    node.config.node.heartbeat_interval_secs = 10;
    node.config.node.link_dead_timeout_secs = 30;
    node.config.node.fast_link_dead_timeout_secs = 5;

    let mut active = ActivePeer::with_session(
        peer,
        LinkId::new(7),
        0,
        ActivePeerSession {
            session: link_session,
            our_index: crate::utils::index::SessionIndex::new(11),
            their_index: crate::utils::index::SessionIndex::new(12),
            transport_id: TransportId::new(1),
            current_addr: crate::transport::TransportAddr::from_string("203.0.113.9:2121"),
            link_stats: crate::transport::LinkStats::new(),
            is_initiator: true,
            remote_epoch: None,
        },
    );
    active.touch(Node::now_ms());
    node.peers.insert(peer_addr, active);
    super::super::seed_dataplane_fmp_rx_for_test(&mut node, peer_addr, std::time::Duration::ZERO);

    let now_ms = Node::now_ms();
    let session = crate::node::session::SessionEntry::new(
        peer_addr,
        peer_identity.pubkey_full(),
        crate::node::session::EndToEndState::Established(endpoint_session),
        1_000,
        true,
    );
    node.sessions.insert(peer_addr, session);
    seed_dataplane_fsp_data_sent_for_test(&mut node, peer_addr, peer_addr, now_ms);
    seed_dataplane_fsp_control_rx_for_test(&mut node, peer_addr, peer_addr, now_ms);

    let discovery_initiated = node.stats().discovery.req_initiated;
    node.check_link_heartbeats().await;

    let direct = node.get_peer(&peer_addr).expect("direct peer retained");
    assert!(
        direct.is_healthy() && direct.can_send(),
        "control-fresh peer should stay connected and probeable"
    );
    assert!(
        node.session_direct_path_blocks_direct_payload(&peer_addr, Node::now_ms()),
        "the soft traversal trust signal should still be visible to fallback-capable meshes"
    );
    assert!(
        !node.pending_lookups.contains_key(&peer_addr),
        "a two-node direct path must not discover the peer through itself every maintenance tick"
    );
    assert_eq!(
        node.stats().discovery.req_initiated,
        discovery_initiated,
        "path recovery without a fallback peer should not initiate discovery"
    );
    assert_eq!(
        node.find_next_hop(&peer_addr)
            .map(|next_hop| *next_hop.node_addr()),
        Some(peer_addr),
        "with no alternate carrier, the soft-suspect direct path remains the payload route"
    );
}
