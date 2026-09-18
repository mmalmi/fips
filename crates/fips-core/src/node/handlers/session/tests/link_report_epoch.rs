struct LinkReportEpochFixture {
    node: Node,
    remote: NodeAddr,
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
    for (kind, size) in [(0x01, 48), (0x02, 68)] {
        let mut fixture = LinkReportEpochFixture::new();
        let mut report = vec![0; size];
        report[0] = kind;
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
    assert_eq!(fixture.receive(true, &[0x51]).await, 1);
    for (kind, size) in [(0x01, 48), (0x02, 68)] {
        let mut report = vec![0; size];
        report[0] = kind;
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
    assert_eq!(fixture.receive(false, &[0x51]).await, 1);
    assert_eq!(fixture.receive(true, &[0x51]).await, 1);
    let before = fixture.received_packets();
    assert_eq!(
        fixture.receive(false, &[0x51]).await,
        1,
        "valid draining-epoch non-report traffic still dispatches"
    );
    assert_eq!(
        fixture.received_packets(),
        before,
        "old counters must not enter the new receiver epoch"
    );
    assert_eq!(fixture.receive(true, &[0x51]).await, 1);
    assert_eq!(fixture.received_packets(), before + 1);
}
