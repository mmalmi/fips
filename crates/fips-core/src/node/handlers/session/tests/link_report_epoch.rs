use crate::protocol::LinkMessageType;

struct LinkReportEpochFixture {
    node: Node,
    remote: NodeAddr,
    remote_identity: Identity,
    old_sender: NoiseSession,
    new_sender: NoiseSession,
}

impl LinkReportEpochFixture {
    fn new() -> Self {
        use crate::peer::{ActivePeer, ActivePeerSession};
        use crate::transport::{LinkId, LinkStats, TransportAddr, TransportId};
        use crate::utils::index::SessionIndex;
        let local = Identity::generate();
        let remote = Identity::generate();
        let remote_addr = *remote.node_addr();
        let (old_sender, old_receiver) = make_xk_session_pair(&remote, &local);
        let (new_sender, new_receiver) = make_xk_session_pair(&remote, &local);
        let mut node = Node::with_identity(local, crate::config::Config::new()).unwrap();
        node.config.node.mmp.mode = MmpMode::Full;
        let peer = ActivePeer::with_session(
            PeerIdentity::from_pubkey_full(remote.pubkey_full()),
            LinkId::new(1),
            Node::now_ms(),
            ActivePeerSession {
                session: old_receiver,
                our_index: SessionIndex::new(1),
                their_index: SessionIndex::new(2),
                transport_id: TransportId::new(1),
                current_addr: TransportAddr::from_string("192.0.2.1:2121"),
                link_stats: LinkStats::new(),
                is_initiator: false,
                remote_epoch: None,
            },
        );
        node.peers
            .insert_with_current_session_index(remote_addr, peer);
        assert!(node.sync_dataplane_fmp_owner(&remote_addr));
        let open = new_receiver.recv_cipher_clone().unwrap();
        node.peers
            .get_mut(&remote_addr)
            .unwrap()
            .set_pending_session(
                new_receiver,
                SessionIndex::new(3),
                SessionIndex::new(4),
                false,
            );
        assert!(node.install_dataplane_fmp_pending_receive_epoch(&remote_addr, true, open));
        // Register the pending index as the completed handshake normally does.
        assert!(node.sync_dataplane_fmp_owner(&remote_addr));
        Self {
            node,
            remote: remote_addr,
            remote_identity: remote,
            old_sender,
            new_sender,
        }
    }

    async fn receive(&mut self, current: bool, message: &[u8]) -> usize {
        use crate::dataplane::{DataplaneRawIngress, PacketProtocol};
        use crate::transport::{ReceivedPacket, TransportAddr, TransportId};
        let sender = if current {
            &mut self.new_sender
        } else {
            &mut self.old_sender
        };
        let mut plaintext = 100_u32.to_le_bytes().to_vec();
        plaintext.extend(message);
        let mut header = vec![0; crate::node::wire::ESTABLISHED_HEADER_SIZE];
        header[0] = crate::node::wire::FMP_VERSION << 4;
        header[1] = if current {
            crate::node::wire::FLAG_KEY_EPOCH
        } else {
            0
        };
        header[2..4].copy_from_slice(&u16::try_from(plaintext.len()).unwrap().to_le_bytes());
        header[4..8].copy_from_slice(&(if current { 3_u32 } else { 1 }).to_le_bytes());
        header[8..16].copy_from_slice(&sender.current_send_counter().to_le_bytes());
        let ciphertext = sender.encrypt_with_aad(&plaintext, &header).unwrap();
        header.extend(ciphertext);
        let raw = DataplaneRawIngress::from_live_received(
            PacketProtocol::Fmp,
            ReceivedPacket::with_timestamp(
                TransportId::new(1),
                TransportAddr::from_string("192.0.2.1:2121"),
                PacketBuffer::new(header),
                Node::now_ms(),
            ),
        );
        receive_epoch_wire(&mut self.node, raw).await
    }

    fn received_packets(&self) -> u64 {
        self.node
            .dataplane
            .fmp_link_metrics(&self.remote, Instant::now())
            .unwrap()
            .rx_packets
    }
}

#[tokio::test]
async fn pending_link_epoch_reports_promote_and_dispatch() {
    for (kind, size) in [
        (LinkMessageType::SenderReport, 48),
        (LinkMessageType::ReceiverReport, 68),
    ] {
        let mut fixture = LinkReportEpochFixture::new();
        let mut report = vec![0; size];
        report[0] = kind.to_byte();
        assert_eq!(fixture.receive(true, &report).await, 1);
        let peer = fixture.node.peers.get(&fixture.remote).unwrap();
        assert!(peer.current_k_bit());
        assert!(peer.pending_new_session().is_none());
        assert_eq!(fixture.received_packets(), 1);
    }
}

#[tokio::test]
async fn draining_link_epoch_reports_do_not_reach_current_handlers() {
    let mut fixture = LinkReportEpochFixture::new();
    assert_eq!(
        fixture
            .receive(true, &[LinkMessageType::Heartbeat.to_byte()])
            .await,
        1
    );
    for (kind, size) in [
        (LinkMessageType::SenderReport, 48),
        (LinkMessageType::ReceiverReport, 68),
    ] {
        let mut report = vec![0; size];
        report[0] = kind.to_byte();
        assert_eq!(
            fixture.receive(false, &report).await,
            0,
            "authenticated old-key link report must not reach current-epoch handlers"
        );
        assert_eq!(fixture.receive(true, &report).await, 1);
    }
}

#[tokio::test]
async fn draining_link_epoch_packets_do_not_enter_current_receiver_counters() {
    let mut fixture = LinkReportEpochFixture::new();
    assert_eq!(
        fixture
            .receive(false, &[LinkMessageType::Heartbeat.to_byte()])
            .await,
        1
    );
    assert_eq!(
        fixture
            .receive(true, &[LinkMessageType::Heartbeat.to_byte()])
            .await,
        1
    );
    let before = fixture.received_packets();
    assert_eq!(
        fixture
            .receive(false, &[LinkMessageType::Heartbeat.to_byte()])
            .await,
        1,
        "valid draining-epoch non-report traffic still dispatches"
    );
    assert_eq!(
        fixture.received_packets(),
        before,
        "old counters must not enter the new receiver epoch"
    );
    assert_eq!(
        fixture
            .receive(true, &[LinkMessageType::Heartbeat.to_byte()])
            .await,
        1
    );
    assert_eq!(fixture.received_packets(), before + 1);
}

#[tokio::test]
async fn draining_link_epoch_carries_late_application_data() {
    use crate::node::session_wire::build_fsp_header;
    let mut fixture = LinkReportEpochFixture::new();
    assert_eq!(
        fixture
            .receive(true, &[LinkMessageType::Heartbeat.to_byte()])
            .await,
        1
    );
    let before = fixture.received_packets();
    let application = Identity::generate();
    let source = *application.node_addr();
    let (mut sender, receiver) = make_xk_session_pair(&application, fixture.node.identity());
    fixture.node.sessions.insert(
        source,
        SessionEntry::new(
            source,
            application.pubkey_full(),
            EndToEndState::Established(receiver),
            Node::now_ms(),
            false,
        ),
    );
    assert!(
        fixture
            .node
            .sync_dataplane_fsp_owner_from_current_session(&source, 0)
    );
    let mut endpoint = fixture.node.attach_endpoint_data_io(8).unwrap();
    let payload = b"valid application data carried by the draining link";
    let plaintext =
        fsp_prepend_inner_header(100, SessionMessageType::EndpointData.to_byte(), 0, payload);
    let header = build_fsp_header(
        sender.current_send_counter(),
        0,
        plaintext.len().try_into().unwrap(),
    );
    let ciphertext = sender.encrypt_with_aad(&plaintext, &header).unwrap();
    let mut wire = header.to_vec();
    wire.extend(ciphertext);
    let datagram = SessionDatagram::new(source, *fixture.node.node_addr(), wire).encode();
    assert!(fixture.receive(false, &datagram).await > 0);
    let event = endpoint.event_rx.try_recv().unwrap();
    assert_eq!(event.messages.len(), 1);
    assert_eq!(event.messages[0].source_peer.node_addr(), &source);
    assert_eq!(event.messages[0].payload.as_slice(), payload);
    assert_eq!(
        fixture.received_packets(),
        before,
        "delivered old-key application data must not contaminate current link counters"
    );
}

#[tokio::test]
async fn client_only_role_is_bound_to_identity_epoch_and_declaration_order() {
    let mut fixture = LinkReportEpochFixture::new();
    fixture
        .receive(true, &[LinkMessageType::Heartbeat.to_byte()])
        .await;
    let mut role = vec![LinkMessageType::ClientOnly.to_byte()];
    role.extend_from_slice(&2_u64.to_le_bytes());
    assert_eq!(role, vec![0x52, 2, 0, 0, 0, 0, 0, 0, 0]);
    assert_eq!(fixture.receive(false, &role).await, 0);
    assert!(fixture.node.bloom_state.leaf_dependents().is_empty());

    // The payload cannot claim another identity or append reachability.
    let mut invalid = role.clone();
    invalid.extend(Identity::generate().node_addr().as_bytes());
    fixture.receive(true, &invalid).await;
    fixture
        .receive(true, &[LinkMessageType::ClientOnly.to_byte()])
        .await;
    assert!(fixture.node.bloom_state.leaf_dependents().is_empty());
    fixture.receive(true, &role).await;
    assert_eq!(fixture.node.bloom_state.leaf_dependents().len(), 1);
    assert!(
        fixture
            .node
            .bloom_state
            .leaf_dependents()
            .contains(&fixture.remote)
    );
    assert!(
        fixture
            .node
            .bloom_state
            .base_filter()
            .contains(&fixture.remote)
    );
    assert!(
        fixture
            .node
            .tree_state
            .peer_coords(&fixture.remote)
            .is_none()
    );

    let mut declaration = crate::tree::ParentDeclaration::self_root(fixture.remote, 3, 100);
    declaration.sign(&fixture.remote_identity).unwrap();
    let announce = crate::protocol::TreeAnnounce::new(
        declaration,
        crate::tree::TreeCoordinate::root_with_meta(fixture.remote, 3, 100),
    )
    .encode()
    .unwrap();
    assert_eq!(fixture.receive(false, &announce).await, 0);
    assert!(
        fixture
            .node
            .bloom_state
            .leaf_dependents()
            .contains(&fixture.remote)
    );
    fixture.receive(true, &announce).await;
    assert!(
        !fixture
            .node
            .bloom_state
            .leaf_dependents()
            .contains(&fixture.remote)
    );
    assert!(
        fixture
            .node
            .tree_state
            .peer_coords(&fixture.remote)
            .is_some()
    );
    // Same-epoch role messages can arrive out of order across carriers.
    fixture.receive(true, &role).await;
    assert!(!fixture.node.peers.get(&fixture.remote).unwrap().client_only);
    role[1..].copy_from_slice(&4_u64.to_le_bytes());
    fixture.receive(true, &role).await;
    assert!(
        fixture
            .node
            .tree_state
            .peer_coords(&fixture.remote)
            .is_none()
    );
    fixture.receive(true, &announce).await;
    assert!(fixture.node.peers.get(&fixture.remote).unwrap().client_only);
    assert!(
        fixture
            .node
            .tree_state
            .peer_coords(&fixture.remote)
            .is_none()
    );
    fixture.node.remove_active_peer(&fixture.remote);
    assert!(fixture.node.bloom_state.leaf_dependents().is_empty());
}

#[tokio::test]
async fn client_only_discards_unrelated_lookup_before_reverse_path_allocation() {
    let mut fixture = LinkReportEpochFixture::new();
    fixture.node.is_leaf_only = true;
    let request = crate::protocol::LookupRequest::new(
        42,
        *Identity::generate().node_addr(),
        fixture.remote,
        crate::tree::TreeCoordinate::root(fixture.remote),
        5,
        0,
    );
    fixture.receive(true, &request.encode()).await;
    assert_eq!(fixture.node.stats().discovery.req_received, 1);
    assert!(fixture.node.recent_requests.is_empty());
    assert_eq!(fixture.node.stats().discovery.req_forwarded, 0);
}

#[tokio::test]
async fn client_only_negotiation_retains_router_behavior_for_legacy_neighbors() {
    let mut fixture = LinkReportEpochFixture::new();
    fixture.node.config.node.leaf_only = true;
    fixture.node.refresh_client_role();
    assert!(!fixture.node.is_leaf_only);
    fixture
        .receive(true, &[LinkMessageType::Heartbeat.to_byte()])
        .await;
    fixture
        .receive(false, &[LinkMessageType::ClientSupport.to_byte()])
        .await;
    assert!(!fixture.node.is_leaf_only);
    fixture
        .receive(true, &[LinkMessageType::ClientSupport.to_byte(), 1])
        .await;
    assert!(!fixture.node.is_leaf_only);
    fixture
        .receive(true, &[LinkMessageType::ClientSupport.to_byte()])
        .await;
    assert!(fixture.node.is_leaf_only);

    let legacy = Identity::generate();
    let legacy_addr = *legacy.node_addr();
    let (_, receive) = make_xk_session_pair(&legacy, fixture.node.identity());
    let peer = crate::peer::ActivePeer::with_session(
        PeerIdentity::from_pubkey_full(legacy.pubkey_full()),
        crate::transport::LinkId::new(2),
        Node::now_ms(),
        crate::peer::ActivePeerSession {
            session: receive,
            our_index: crate::utils::index::SessionIndex::new(10),
            their_index: crate::utils::index::SessionIndex::new(11),
            transport_id: crate::transport::TransportId::new(1),
            current_addr: crate::transport::TransportAddr::from_string("192.0.2.2:2121"),
            link_stats: crate::transport::LinkStats::new(),
            is_initiator: false,
            remote_epoch: None,
        },
    );
    assert!(peer.can_send());
    fixture
        .node
        .peers
        .insert_with_current_session_index(legacy_addr, peer);
    fixture.node.refresh_client_role();
    assert!(!fixture.node.is_leaf_only);
    assert!(!fixture.node.bloom_state.is_leaf_only());
    fixture.node.remove_active_peer(&legacy_addr);
    assert!(fixture.node.is_leaf_only);
    assert!(fixture.node.bloom_state.is_leaf_only());
}
