struct ReportEpochFixture {
    node: Node,
    remote: NodeAddr,
    old_sender: NoiseSession,
    new_sender: NoiseSession,
}

impl ReportEpochFixture {
    fn new() -> Self {
        let local = Identity::generate();
        let remote = Identity::generate();
        let remote_addr = *remote.node_addr();
        let (old_sender, old_receiver) = make_xk_session_pair(&remote, &local);
        let (new_sender, new_receiver) = make_xk_session_pair(&remote, &local);
        let mut node = Node::with_identity(local, crate::config::Config::new()).unwrap();
        node.sessions.insert(
            remote_addr,
            SessionEntry::new(
                remote_addr,
                remote.pubkey_full(),
                EndToEndState::Established(old_receiver),
                Node::now_ms(),
                false,
            ),
        );
        assert!(node.sync_dataplane_fsp_owner_from_current_session(&remote_addr, 0));
        let open = new_receiver.recv_cipher_clone().unwrap();
        let seal = new_receiver.send_cipher_clone().unwrap();
        let authority = new_receiver.send_counter_authority();
        node.sessions
            .get_mut(&remote_addr)
            .unwrap()
            .set_pending_session(new_receiver);
        assert!(node.install_dataplane_fsp_pending_epoch(
            &remote_addr,
            true,
            open,
            seal,
            authority,
        ));
        Self {
            node,
            remote: remote_addr,
            old_sender,
            new_sender,
        }
    }

    async fn receive(&mut self, current: bool, kind: SessionMessageType, body: &[u8]) -> usize {
        use crate::dataplane::{DataplaneRawIngress, PacketProtocol};
        use crate::node::session_wire::{FSP_FLAG_K, build_fsp_header};
        use crate::transport::{ReceivedPacket, TransportAddr, TransportId};

        let sender = if current {
            &mut self.new_sender
        } else {
            &mut self.old_sender
        };
        let plaintext = fsp_prepend_inner_header(100, kind.to_byte(), 0, body);
        let header = build_fsp_header(
            sender.current_send_counter(),
            if current { FSP_FLAG_K } else { 0 },
            plaintext.len().try_into().unwrap(),
        );
        let ciphertext = sender.encrypt_with_aad(&plaintext, &header).unwrap();
        let mut wire = header.to_vec();
        wire.extend(ciphertext);
        let raw = DataplaneRawIngress::from_live_received(
            PacketProtocol::Fsp,
            ReceivedPacket::with_timestamp(
                TransportId::new(1),
                TransportAddr::from_string("192.0.2.1:2121"),
                PacketBuffer::new(wire),
                Node::now_ms(),
            ),
        )
        .with_fsp_source(self.remote)
        .with_previous_hop(self.remote);
        receive_epoch_wire(&mut self.node, raw).await
    }
}

async fn receive_epoch_wire(node: &mut Node, raw: crate::dataplane::DataplaneRawIngress) -> usize {
    use crate::dataplane::{DataplaneLiveOutboundFirsts, DataplaneLiveTurnIo};
    let mut raw = std::collections::VecDeque::from([raw]);
    let (endpoint_tx, _endpoint_rx) = crate::node::EndpointEventSender::channel(1);
    let (_, mut endpoint_rx) = crate::node::endpoint_data_batch_channel(1);
    let (_, mut tun_rx) = crate::upper::tun::tun_outbound_channel(1);
    let deadline = Instant::now() + std::time::Duration::from_secs(2);
    let mut processed = 0;
    loop {
        let mut turn = node
            .dataplane
            .pump_turn_with_firsts_and_transport_batch(
                None,
                &mut raw,
                1,
                DataplaneLiveOutboundFirsts::default(),
                DataplaneLiveTurnIo {
                    endpoint_data_rx: &mut endpoint_rx,
                    endpoint_limit: 0,
                    tun_outbound_rx: &mut tun_rx,
                    tun_limit: 0,
                    endpoint_tx: &endpoint_tx,
                    transports: &node.transports,
                    crypto_limit: 8,
                    transport_send_batch_packets: 1,
                },
            )
            .await;
        assert!(
            turn.raw_ingress_drops().is_empty(),
            "encrypted packet must route"
        );
        assert!(
            turn.drops().is_empty(),
            "encrypted packet must authenticate"
        );
        let delivered =
            turn.fsp_session_ingress_count() != 0 || !turn.fmp_link_ingress().is_empty();
        processed += node.process_dataplane_control_ingress(&mut turn).await;
        if delivered {
            return processed;
        }
        assert!(
            Instant::now() < deadline,
            "encrypted packet must reach dispatch"
        );
        tokio::task::yield_now().await;
    }
}

#[tokio::test]
async fn pending_epoch_reports_promote_and_dispatch() {
    for (kind, body) in [
        (SessionMessageType::SenderReport, vec![0; 46]),
        (SessionMessageType::ReceiverReport, vec![0; 66]),
    ] {
        let mut fixture = ReportEpochFixture::new();
        assert_eq!(fixture.receive(true, kind, &body).await, 1);
        let session = fixture.node.sessions.get(&fixture.remote).unwrap();
        assert!(
            session.current_k_bit(),
            "authenticated pending report must promote"
        );
        assert!(session.pending_new_session().is_none());
    }
}

#[tokio::test]
async fn draining_epoch_reports_are_ignored_but_application_data_is_delivered() {
    let mut fixture = ReportEpochFixture::new();
    let mut endpoint = fixture.node.attach_endpoint_data_io(8).unwrap();
    assert_eq!(
        fixture
            .receive(true, SessionMessageType::SenderReport, &[0; 46])
            .await,
        1,
    );
    assert!(
        fixture
            .node
            .sessions
            .get(&fixture.remote)
            .unwrap()
            .is_draining()
    );
    for (kind, body) in [
        (SessionMessageType::SenderReport, vec![0; 46]),
        (SessionMessageType::ReceiverReport, vec![0; 66]),
    ] {
        assert_eq!(
            fixture.receive(false, kind, &body).await,
            0,
            "authenticated old-key {kind:?} must not reach current-epoch report handlers",
        );
        assert_eq!(fixture.receive(true, kind, &body).await, 1);
    }
    let payload = b"valid application packet still in flight before cutover";
    assert_eq!(
        fixture
            .receive(false, SessionMessageType::EndpointData, payload)
            .await,
        1
    );
    let event = endpoint.event_rx.try_recv().unwrap();
    assert_eq!(event.messages.len(), 1);
    assert_eq!(event.messages[0].payload.as_slice(), payload);
    assert_eq!(event.messages[0].source_peer.node_addr(), &fixture.remote);
}
