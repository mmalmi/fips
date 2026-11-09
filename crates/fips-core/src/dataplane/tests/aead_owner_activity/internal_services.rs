#[test]
fn capability_controls_confirm_keys_without_application_demand_or_route_affinity() {
    let remote = crate::Identity::generate();
    let source_peer = PeerIdentity::from_pubkey_full(remote.pubkey_full());
    let owner = OwnerId::fsp_node(*source_peer.node_addr());
    let application_hop = fmp_owner(171);
    let control_hop = fmp_owner(172);
    let mut driver = DataplaneTurnDriver::new(AdmissionConfig::new(4, 8));
    driver.register_owner(owner, OwnerConfig::new(1, 8));
    let wrap = |hop: OwnerId| {
        DataplaneFspWrapRoute::new(hop, 1, 1717, test_node_addr(1), owner.node_addr())
    };
    driver
        .owner_mut(owner)
        .unwrap()
        .set_fsp_wrap_route(Some(wrap(application_hop)));
    let mut application = Vec::new();
    application.extend_from_slice(&9001u16.to_le_bytes());
    application.extend_from_slice(&9001u16.to_le_bytes());
    application.extend_from_slice(b"application");
    driver
        .mover
        .submit_outbound_packet(
            OutboundPacket::fsp(
                owner,
                1,
                PacketClass::Bulk,
                0,
                PacketBuffer::new(application),
            )
            .with_fsp_inner_header(crate::protocol::SessionMessageType::DataPacket.to_byte(), 0)
            .with_activity_tick(ActivityTick::new(100)),
        )
        .unwrap();
    assert_eq!(dispatch_outbound_available(&mut driver.mover, 8).len(), 1);
    assert_eq!(
        driver
            .owner_fsp_activity(owner)
            .unwrap()
            .last_outbound_next_hop(),
        Some(application_hop.node_addr())
    );

    driver
        .owner_mut(owner)
        .unwrap()
        .set_fsp_wrap_route(Some(wrap(control_hop)));
    for (index, request) in [true, false].into_iter().enumerate() {
        let at = 200 + index as u64;
        let mut body = Vec::new();
        body.extend_from_slice(&257u16.to_le_bytes());
        body.extend_from_slice(&257u16.to_le_bytes());
        body.extend_from_slice(
            &crate::node::session::capabilities::SessionCapabilities::local(request).encode(),
        );
        driver
            .mover
            .submit_outbound_packet(
                OutboundPacket::fsp(
                    owner,
                    1,
                    PacketClass::Control,
                    0,
                    PacketBuffer::new(body.clone()),
                )
                .with_fsp_inner_header(crate::protocol::SessionMessageType::DataPacket.to_byte(), 0)
                .with_activity_tick(ActivityTick::new(at)),
            )
            .unwrap();
        assert_eq!(dispatch_outbound_available(&mut driver.mover, 8).len(), 1);
        let activity = driver.owner_fsp_activity(owner).unwrap();
        assert_eq!(
            activity.last_outbound_next_hop(),
            Some(application_hop.node_addr()),
            "negotiation must not repin the application route"
        );
        assert!(
            !activity.has_recent_outbound_activity(at, 50),
            "negotiation must not create application demand"
        );

        let msg_type = crate::protocol::SessionMessageType::DataPacket.to_byte();
        let plaintext = crate::node::session_wire::fsp_prepend_inner_header(0, msg_type, 0, &body);
        let ingress = DataplaneFspSessionIngress {
            source_addr: owner.node_addr(),
            source_peer,
            previous_hop_addr: control_hop.node_addr(),
            ce_flag: false,
            receive_sync: FspReceiveSync {
                counter: index as u64,
                received_k_bit: false,
                timestamp: 0,
                plaintext_len: plaintext.len(),
                ce_flag: false,
                path_mtu: u16::MAX,
                spin_bit: false,
            },
            activity_tick: Some(ActivityTick::new(at)),
            timestamp_ms: 0,
            msg_type,
            inner_flags: 0,
            plaintext: PacketBuffer::new(plaintext),
        };
        driver.record_fsp_session_ingress_activity(&ingress);
        let activity = driver.owner_fsp_activity(owner).unwrap();
        assert!(
            activity.current_epoch_confirmed(),
            "authenticated control still proves epoch possession"
        );
        assert_eq!(
            activity.last_rx_age_ms(at),
            Some(0),
            "authenticated control still proves liveness"
        );
        assert_eq!(
            activity.last_rx_data_age_ms(at),
            None,
            "control must not qualify as incoming application demand"
        );
        assert!(!activity.has_recent_data_return_from(&control_hop.node_addr(), at, 50));
    }

    for port in [256u16, 258, 9001] {
        let mut body = [0; 4];
        body[..2].copy_from_slice(&257u16.to_le_bytes());
        body[2..].copy_from_slice(&port.to_le_bytes());
        assert!(
            dataplane_fsp_message_is_application_data(
                crate::protocol::SessionMessageType::DataPacket.to_byte(),
                &body
            ),
            "IPv6 and application service destinations remain data regardless of source port"
        );
    }
}
