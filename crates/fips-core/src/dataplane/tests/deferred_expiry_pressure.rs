use super::*;

fn unrouted(counter: u64) -> DataplaneRawIngress {
    DataplaneRawIngress::from_live_received(
        PacketProtocol::Fsp,
        ReceivedPacket::with_timestamp(
            TransportId::new(177),
            TransportAddr::from_string("198.51.100.177:9000"),
            PacketBuffer::new(fsp_wire(
                counter,
                crate::node::session_wire::FSP_FLAG_DIRECT_TRANSPORT,
            )),
            177_000,
        ),
    )
    .with_fsp_source(NodeAddr::from_bytes([0x77; 16]))
}

/// Exercise the production live-pump admission path, not a copied queue model.
/// The expired item models data whose session owner never appeared. Fresh
/// traffic consumes every raw-ingress slot while the expired item is pending.
#[tokio::test]
async fn expired_raw_ingress_is_reclaimed_under_full_fresh_budget() {
    let mut node = crate::Node::new(crate::Config::new()).expect("node");
    let endpoint_io = node.attach_endpoint_data_io(8).expect("endpoint io");
    let (_endpoint_data_tx, mut endpoint_data_rx) = endpoint_data_batch_channel(1);
    let (_tun_outbound_tx, mut tun_outbound_rx) = crate::upper::tun::tun_outbound_channel(1);
    let transports = HashMap::<TransportId, TransportHandle>::new();
    let mut live_node = DataplaneLiveNode::new(AdmissionConfig::new(4, 8));
    let expired_at = crate::time::now_ms()
        .saturating_sub(DATAPLANE_DEFERRED_RAW_INGRESS_MAX_AGE_MS + 1);
    live_node.deferred_raw_ingress.push_back((unrouted(1), expired_at));

    for turn_id in 0..64 {
        let mut fresh: VecDeque<_> = (0..8)
            .map(|offset| unrouted(2 + turn_id * 8 + offset))
            .collect();
        let _turn = live_node
            .pump_turn_with_firsts_and_transport_batch(
                None,
                &mut fresh,
                8,
                DataplaneLiveOutboundFirsts::default(),
                DataplaneLiveTurnIo {
                    endpoint_data_rx: &mut endpoint_data_rx,
                    endpoint_limit: 0,
                    tun_outbound_rx: &mut tun_outbound_rx,
                    tun_limit: 0,
                    endpoint_tx: &endpoint_io.event_tx,
                    transports: &transports,
                    crypto_limit: 8,
                    transport_send_batch_packets: 8,
                },
            )
            .await;
        assert!(fresh.is_empty(), "the full fresh budget must be consumed");
    }
    let retained_before_idle = live_node.deferred_raw_ingress.iter()
        .filter(|(_, at)| *at == expired_at).count();
    let queued_before_idle = live_node.deferred_raw_ingress.len();

    // Positive control: the same existing expiry must work with an idle budget.
    let _turn = live_node
        .pump_completion_output_turn_with_transport_batch(
            false,
            DataplaneLiveTurnIo {
                endpoint_data_rx: &mut endpoint_data_rx,
                endpoint_limit: 0,
                tun_outbound_rx: &mut tun_outbound_rx,
                tun_limit: 0,
                endpoint_tx: &endpoint_io.event_tx,
                transports: &transports,
                crypto_limit: 8,
                transport_send_batch_packets: 8,
            },
        )
        .await;
    let retained_after_idle = live_node.deferred_raw_ingress.iter()
        .filter(|(_, at)| *at == expired_at).count();
    assert_eq!(retained_after_idle, 0, "idle expiry positive control");
    eprintln!("deferred-expiry aggregate: full_turns=64 fresh_packets=512 queued_before_idle={queued_before_idle} expired_before_idle={retained_before_idle} expired_after_idle={retained_after_idle}");
    assert_eq!(retained_before_idle, 0,
        "already-expired unrouted data must not require a fresh-ingress gap");
}

#[tokio::test]
async fn deferred_retries_preserve_zero_and_per_turn_budgets() {
    let mut node = crate::Node::new(crate::Config::new()).expect("node");
    let endpoint_io = node.attach_endpoint_data_io(8).expect("endpoint io");
    let (_endpoint_data_tx, mut endpoint_data_rx) = endpoint_data_batch_channel(1);
    let (_tun_outbound_tx, mut tun_outbound_rx) = crate::upper::tun::tun_outbound_channel(1);
    let transports = HashMap::<TransportId, TransportHandle>::new();
    let mut live_node = DataplaneLiveNode::new(AdmissionConfig::new(4, 8));
    let expired_at = crate::time::now_ms()
        .saturating_sub(DATAPLANE_DEFERRED_RAW_INGRESS_MAX_AGE_MS + 1);
    for counter in 1..=9 {
        live_node.deferred_raw_ingress.push_back((unrouted(counter), expired_at));
    }
    let mut fresh: VecDeque<_> = (10..14).map(unrouted).collect();
    for (budget, expected_old, expected_fresh, expected_drops) in [(0, 9, 4, 0), (4, 5, 0, 4)] {
        let turn = live_node
            .pump_turn_with_firsts_and_transport_batch(
                None,
                &mut fresh,
                budget,
                DataplaneLiveOutboundFirsts::default(),
                DataplaneLiveTurnIo {
                    endpoint_data_rx: &mut endpoint_data_rx,
                    endpoint_limit: 0,
                    tun_outbound_rx: &mut tun_outbound_rx,
                    tun_limit: 0,
                    endpoint_tx: &endpoint_io.event_tx,
                    transports: &transports,
                    crypto_limit: 8,
                    transport_send_batch_packets: 8,
                },
            )
            .await;
        assert_eq!(fresh.len(), expected_fresh);
        assert_eq!(turn.summary.raw_ingress_dropped(), expected_drops);
        assert_eq!(live_node.deferred_raw_ingress.iter()
            .filter(|(_, at)| *at == expired_at).count(), expected_old);
        assert_eq!(live_node.deferred_raw_ingress.len(), 9,
            "freshly deferred packets remain; only the bounded old prefix is revisited");
    }
}

#[tokio::test]
async fn later_route_delivers_deferred_ciphertexts_once_in_order_with_fresh_pressure() {
    let mut node = crate::Node::new(crate::Config::new()).expect("node");
    let endpoint_io = node.attach_endpoint_data_io(8).expect("endpoint io");
    let (_endpoint_data_tx, mut endpoint_data_rx) = endpoint_data_batch_channel(1);
    let (_tun_outbound_tx, mut tun_outbound_rx) = crate::upper::tun::tun_outbound_channel(1);
    let transports = HashMap::<TransportId, TransportHandle>::new();
    let source_peer = PeerIdentity::from_pubkey_full(crate::Identity::generate().pubkey_full());
    let source_addr = *source_peer.node_addr();
    let local_addr = NodeAddr::from_bytes([0xa1; 16]);
    let owner = OwnerId::fsp_node(source_addr);
    let key = 0xa5;
    let mut live_node = DataplaneLiveNode::new(AdmissionConfig::new(4, 8));
    let now = crate::time::now_ms();
    for counter in 1..=2 {
        let inner = crate::node::session_wire::fsp_prepend_inner_header(
            counter as u32,
            crate::protocol::SessionMessageType::EndpointData.to_byte(),
            0,
            &[counter as u8],
        );
        let raw = DataplaneRawIngress::from_live_received(
            PacketProtocol::Fsp,
            ReceivedPacket::with_timestamp(
                TransportId::new(178),
                TransportAddr::from_string("198.51.100.178:9000"),
                PacketBuffer::new(fsp_encrypted_wire(counter, 0, &inner, key)),
                now,
            ),
        ).with_fsp_source(source_addr);
        live_node.deferred_raw_ingress.push_back((raw, now));
    }
    let mut delivered = Vec::new();
    let mut admitted = 0;
    for turn_id in 0..64 {
        if turn_id == 4 {
            register_keyed_owner(&mut live_node.driver, owner,
                OwnerConfig::new(1, 8).with_source_peer(source_peer.clone()), key);
            register_fsp_session_payload_route(&mut live_node.routes, source_addr, owner, local_addr);
        }
        let mut fresh: VecDeque<_> = (0..4)
            .map(|offset| unrouted(100 + turn_id * 4 + offset)).collect();
        let mut turn = live_node.pump_turn_with_firsts_and_transport_batch(
            None, &mut fresh, 4, DataplaneLiveOutboundFirsts::default(),
            DataplaneLiveTurnIo {
                endpoint_data_rx: &mut endpoint_data_rx, endpoint_limit: 0,
                tun_outbound_rx: &mut tun_outbound_rx, tun_limit: 0,
                endpoint_tx: &endpoint_io.event_tx, transports: &transports,
                crypto_limit: 8, transport_send_batch_packets: 8,
            },
        ).await;
        assert!(fresh.is_empty(), "fresh traffic keeps its full admission turn");
        assert_eq!(turn.summary().drops(), 0, "authenticated data must not fail crypto/retirement");
        admitted += turn.summary().inbound_admitted();
        for ingress in turn.take_fsp_authenticated_ingress().sessions {
            let (source, _, _, _, _, _, _, _, plaintext) = ingress.into_parts();
            assert_eq!(source, source_addr);
            delivered.extend_from_slice(&plaintext.as_slice()[crate::node::session_wire::FSP_INNER_HEADER_SIZE..]);
        }
        if turn_id < 4 {
            assert!(delivered.is_empty());
            assert_eq!(live_node.deferred_raw_ingress.iter()
                .filter(|(raw, _)| raw.fsp_source == Some(source_addr)).count(), 2,
                "nonexpired ciphertexts survive retries before the route exists");
        }
        tokio::time::sleep(std::time::Duration::from_millis(1)).await;
    }
    assert_eq!(admitted, 2, "deferred ciphertexts admitted exactly once");
    assert_eq!(delivered, vec![1, 2], "FIFO authenticated payload delivery exactly once");
    assert!(!live_node.deferred_raw_ingress.iter().any(|(raw, _)| raw.fsp_source == Some(source_addr)));
}
