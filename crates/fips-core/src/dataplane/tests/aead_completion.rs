#[test]
fn endpoint_data_route_builds_endpoint_data_records() {
    let owner = fsp_owner(914);
    let route = DataplaneEndpointDataRoute::fsp(owner, 1, 0, 0);
    let route_result = route_endpoint_payloads(
        &route,
        vec![b"first".to_vec(), b"second".to_vec(), b"third".to_vec()],
    );

    assert!(route_result.dropped.is_empty());
    assert_eq!(route_result.routed.len(), 3);
    for (packet, expected) in route_result.routed.iter().zip([
        b"first".as_slice(),
        b"second".as_slice(),
        b"third".as_slice(),
    ]) {
        assert!(matches!(
            packet.payload_transform,
            OutboundPayloadTransform::FspInnerHeader {
                msg_type,
                ..
            } if msg_type == crate::protocol::SessionMessageType::EndpointData.to_byte()
        ));
        assert_eq!(packet.payload.as_slice(), expected);
    }
    let route_result =
        route_endpoint_payloads(&route, (0..49).map(|idx| vec![idx as u8]).collect());
    assert_eq!(route_result.routed.len(), 49);
    assert!(route_result.dropped.is_empty());
}

#[test]
fn direct_endpoint_data_route_keeps_direct_transport_records() {
    let owner = fsp_owner(913);
    let first = vec![0x11; 100];
    let small = vec![0x22; 10];
    let third = vec![0x33; 100];
    let route = DataplaneEndpointDataRoute::fsp(owner, 1, 0, 0).with_direct_transport();

    let route_result =
        route_endpoint_payloads(&route, vec![first.clone(), small.clone(), third.clone()]);

    assert!(route_result.dropped.is_empty());
    assert_eq!(route_result.routed.len(), 3);
    for (packet, expected) in
        route_result
            .routed
            .iter()
            .zip([first.as_slice(), small.as_slice(), third.as_slice()])
    {
        assert_eq!(packet.payload.as_slice(), expected);
        assert!(!packet.fsp_auto_coords_warmup);
    }
}

#[test]
fn compact_authenticated_ingress_preserves_retirement_order() {
    let source_peer = PeerIdentity::from_pubkey_full(crate::Identity::generate().pubkey_full());
    let source_addr = *source_peer.node_addr();
    let owner = OwnerId::fsp_node(source_addr);
    let previous_hop = test_node_addr(917);
    let local_addr = test_node_addr(918);
    let key = 0x93;
    let mut driver = DataplaneTurnDriver::new(AdmissionConfig::new(4, 8));
    driver.register_owner(owner, OwnerConfig::new(1, 8).with_source_peer(source_peer));
    driver
        .owner_mut(owner)
        .unwrap()
        .set_crypto_keys(OwnerCryptoKeys::new(test_key(key), test_key(key)));

    let endpoint_inner = crate::node::session_wire::fsp_prepend_inner_header(
        917_001,
        crate::protocol::SessionMessageType::EndpointData.to_byte(),
        0,
        b"ordered-endpoint",
    );

    let mut ipv6 = Vec::new();
    ipv6.extend_from_slice(&[0x60, 0, 0, 0]);
    ipv6.extend_from_slice(&4u16.to_be_bytes());
    ipv6.push(17);
    ipv6.push(64);
    ipv6.extend_from_slice(
        &crate::FipsAddress::from_node_addr(&source_addr)
            .to_ipv6()
            .octets(),
    );
    ipv6.extend_from_slice(
        &crate::FipsAddress::from_node_addr(&local_addr)
            .to_ipv6()
            .octets(),
    );
    ipv6.extend_from_slice(&[1, 2, 3, 4]);
    assert!(
        crate::upper::ipv6_shim::compress_ipv6_with_port_header_in_place(
            &mut ipv6,
            crate::node::session_wire::FSP_PORT_IPV6_SHIM,
            crate::node::session_wire::FSP_PORT_IPV6_SHIM,
        )
    );
    let tun_inner = crate::node::session_wire::fsp_prepend_inner_header(
        917_002,
        crate::protocol::SessionMessageType::DataPacket.to_byte(),
        0,
        &ipv6,
    );
    let report_inner = crate::node::session_wire::fsp_prepend_inner_header(
        917_003,
        crate::protocol::SessionMessageType::SenderReport.to_byte(),
        0,
        b"report",
    );

    for (idx, inner) in [endpoint_inner, tun_inner, report_inner]
        .into_iter()
        .enumerate()
    {
        driver
            .mover
            .submit_socket_packet(
                SocketPacket::new(
                    owner,
                    1,
                    917 + idx as u64,
                    FSP_HEADER_SIZE as u16,
                    PacketClass::Bulk,
                    OutputTarget::SessionPayload { local_addr },
                    PacketBuffer::new(fsp_encrypted_wire(
                        917 + idx as u64,
                        0,
                        inner.as_slice(),
                        key,
                    )),
                )
                .with_previous_hop(previous_hop)
                .with_activity_tick(ActivityTick::new(917_010 + idx as u64)),
            )
            .unwrap();
    }

    let mut router = NullIngressRouter;
    let mut deferred_raw_ingress = std::collections::VecDeque::new();
    let summary = collect_test_live_session_outputs(
        &mut driver,
        DataplaneRuntimeSummary::default(),
        &mut router,
        8,
        true,
        &mut deferred_raw_ingress,
    );

    assert_eq!(summary.outputs(), 0);
    assert_eq!(
        driver.fsp_authenticated_ingress.runs,
        vec![
            DataplaneFspAuthenticatedIngressRun::EndpointDataBatch,
            DataplaneFspAuthenticatedIngressRun::Sessions { count: 2 }
        ]
    );
}

#[test]
fn compact_endpoint_data_completion_can_join_admission_finish() {
    let source_peer = PeerIdentity::from_pubkey_full(crate::Identity::generate().pubkey_full());
    let source_addr = *source_peer.node_addr();
    let owner = OwnerId::fsp_node(source_addr);
    let previous_hop = test_node_addr(915);
    let local_addr = test_node_addr(916);
    let key = 0x91;
    let mut driver = DataplaneTurnDriver::new(AdmissionConfig::new(4, 8));
    driver.register_owner(owner, OwnerConfig::new(1, 8).with_source_peer(source_peer));
    driver
        .owner_mut(owner)
        .unwrap()
        .set_crypto_keys(OwnerCryptoKeys::new(test_key(key), test_key(key)));

    let endpoint_payloads = [
        b"compact-one".as_slice(),
        b"compact-two".as_slice(),
        b"compact-three".as_slice(),
    ];
    for (offset, payload) in endpoint_payloads.into_iter().enumerate() {
        submit_endpoint_data_payload(
            &mut driver.mover,
            EndpointDataSubmit {
                owner,
                counter: 915 + offset as u64,
                timestamp: 915_001 + offset as u32,
                key,
                previous_hop,
                local_addr,
                payload,
            },
        );
    }

    let mut prepared = capture_prepared_work(&mut driver.mover, 8);
    assert_eq!(prepared.len(), 3);
    let mut completions = prepared
        .drain(..)
        .map(execute_test_prepared_crypto_work)
        .collect::<VecDeque<_>>();
    let _summary = start_test_aead_completion_turn(&mut driver, &mut completions, 8, true);

    let endpoint_batches = driver_endpoint_batches(&driver);
    assert_eq!(endpoint_batches.len(), 1);
    assert_eq!(
        endpoint_batches
            .iter()
            .map(|bulk| bulk.len())
            .sum::<usize>(),
        3
    );
    assert_eq!(endpoint_batches[0].commit_runs().len(), 1);
    assert_eq!(endpoint_batches[0].commit_runs()[0].len(), 3);
    let mut batches = take_driver_endpoint_batches(&mut driver);
    assert_eq!(batches.len(), 1);
    let batch = batches
        .last_mut()
        .expect("direct packet batch")
        .take_direct_packet_batch();
    let mut runs = batch.into_packet_runs();
    assert_eq!(runs.len(), 1);
    assert_eq!(runs.iter().map(|run| run.len()).sum::<usize>(), 3);
    assert_eq!(runs[0].source_peer(), &source_peer);
    assert_eq!(runs[0].len(), 3);
    assert_eq!(
        runs[0].packet_bytes(),
        b"compact-one".len() + b"compact-two".len() + b"compact-three".len()
    );
    assert_eq!(runs[0].packet_slice(0), Some(b"compact-one".as_slice()));
    assert_eq!(runs[0].packet_slice(1), Some(b"compact-two".as_slice()));
    assert_eq!(runs[0].packet_slice(2), Some(b"compact-three".as_slice()));
    assert!(runs[0].packet_slice(3).is_none());
    let packets = runs[0]
        .packet_slices()
        .map(<[u8]>::to_vec)
        .collect::<Vec<_>>();
    assert_eq!(
        packets,
        vec![
            b"compact-one".to_vec(),
            b"compact-two".to_vec(),
            b"compact-three".to_vec()
        ]
    );
    runs[0].retain_packets(|index, _packet| index != 1);
    assert_eq!(runs[0].len(), 2);
    assert_eq!(
        runs[0].packet_bytes(),
        b"compact-one".len() + b"compact-three".len()
    );
    let retained = runs[0]
        .packet_slices()
        .map(<[u8]>::to_vec)
        .collect::<Vec<_>>();
    assert_eq!(
        retained,
        vec![b"compact-one".to_vec(), b"compact-three".to_vec()]
    );
    assert!(driver.outputs.is_empty());
}

#[test]
fn session_ingress_raw_handoff_defers_unrouted_fsp() {
    let source_addr = test_node_addr(918);
    let local_addr = test_node_addr(919);
    let previous_hop = test_node_addr(920);
    let fmp_owner = OwnerId::fmp_node(previous_hop);
    let fsp_wire = fsp_encrypted_wire(919, 0, b"defer-until-route", 0x94);
    let datagram = crate::protocol::SessionDatagram::new(source_addr, local_addr, fsp_wire.clone())
        .with_ttl(8)
        .with_path_mtu(1280)
        .encode();
    let mut fmp_plaintext = 919_001_u32.to_le_bytes().to_vec();
    fmp_plaintext.extend_from_slice(&datagram);
    let mut payload = fmp_wire(920, 921, crate::node::wire::FLAG_CE);
    payload.truncate(FMP_ESTABLISHED_HEADER_SIZE);
    payload.extend_from_slice(&fmp_plaintext);

    let mut driver = DataplaneTurnDriver::new(AdmissionConfig::new(4, 8));
    driver.outputs.push(PacketOutput {
        owner: fmp_owner,
        counter: 921,
        ingress_seq: 0,
        lane: Lane::Bulk,
        target: OutputTarget::SessionIngress { local_addr },
        source_path: Some(live_path(9200)),
        previous_hop: None,
        ce_flag: false,
        path_mtu: u16::MAX,
        wire_flags: 0,
        opened_payload_offset: FMP_ESTABLISHED_HEADER_SIZE as u16,
        source_peer: None,
        path: None,
        activity_tick: Some(ActivityTick::new(919_002)),
        fmp_timestamp_ms: Some(919_001),
        source_wire_len: Some(payload.len()),
        fsp_send_receipt: None,
        send_token: None,
        payload: PacketBuffer::new(payload),
    });

    let mut routes = DataplaneLiveRouteTable::default();
    let mut deferred_raw_ingress = std::collections::VecDeque::new();
    let summary = collect_test_live_session_outputs(
        &mut driver,
        DataplaneRuntimeSummary::default(),
        &mut routes,
        0,
        false,
        &mut deferred_raw_ingress,
    );

    assert_eq!(summary.raw_ingress_dropped(), 0);
    assert_eq!(summary.inbound_admitted(), 0);
    assert!(driver.raw_ingress_drops.is_empty());
    let (raw, deferred_at_ms) = deferred_raw_ingress
        .pop_front()
        .expect("unrouted sourced FSP packet should defer");
    assert!(deferred_raw_ingress.is_empty());
    assert!(deferred_at_ms > 0);
    assert_eq!(raw.protocol, PacketProtocol::Fsp);
    assert_eq!(raw.fsp_source, Some(source_addr));
    assert_eq!(raw.previous_hop, Some(previous_hop));
    assert!(raw.ce_flag);
    assert_eq!(raw.path_mtu, 1280);
    assert_eq!(raw.activity_tick, Some(ActivityTick::new(919_002)));
    assert_eq!(raw.payload.as_slice(), fsp_wire.as_slice());
}

#[test]
fn direct_endpoint_packet_batches_leave_commit_only_turn_bulk() {
    let source_peer = PeerIdentity::from_pubkey_full(crate::Identity::generate().pubkey_full());
    let source_addr = *source_peer.node_addr();
    let owner = OwnerId::fsp_node(source_addr);
    let previous_hop = test_node_addr(916);
    let local_addr = test_node_addr(917);
    let key = 0x92;
    let mut driver = DataplaneTurnDriver::new(AdmissionConfig::new(4, 8));
    driver.register_owner(owner, OwnerConfig::new(1, 8).with_source_peer(source_peer));
    driver
        .owner_mut(owner)
        .unwrap()
        .set_crypto_keys(OwnerCryptoKeys::new(test_key(key), test_key(key)));

    for (offset, payload) in [b"batch-one".as_slice(), b"batch-two".as_slice()]
        .into_iter()
        .enumerate()
    {
        submit_endpoint_data_payload(
            &mut driver.mover,
            EndpointDataSubmit {
                owner,
                counter: 916 + offset as u64,
                timestamp: 916_001 + offset as u32,
                key,
                previous_hop,
                local_addr,
                payload,
            },
        );
    }

    let mut prepared = capture_prepared_work(&mut driver.mover, 8);
    assert_eq!(prepared.len(), 2);
    let mut completions = prepared
        .drain(..)
        .map(execute_test_prepared_crypto_work)
        .collect::<VecDeque<_>>();
    let _summary = start_test_aead_completion_turn(&mut driver, &mut completions, 8, true);

    let endpoint_batches = driver_endpoint_batches(&driver);
    assert_eq!(endpoint_batches.len(), 1);
    assert_eq!(endpoint_batches[0].len(), 2);
    assert!(endpoint_batches[0].has_direct_packet_runs());

    let delivered = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let captured = std::sync::Arc::clone(&delivered);
    let direct_sink =
        EndpointDirectSink::new(move |batch: crate::FipsEndpointDirectPacketBatch| {
            let packets = batch
                .into_packet_runs()
                .into_iter()
                .flat_map(|run| run.packet_slices().map(<[u8]>::to_vec).collect::<Vec<_>>())
                .collect::<Vec<_>>();
            captured.lock().expect("direct batches lock").push(packets);
            Ok::<(), crate::FipsEndpointDirectDeliveryError>(())
        });

    driver.deliver_direct_endpoint_packet_batches(Some(&direct_sink));

    assert_eq!(
        delivered.lock().expect("direct batches lock").as_slice(),
        &[vec![b"batch-one".to_vec(), b"batch-two".to_vec()]]
    );
    let endpoint_batches = driver_endpoint_batches(&driver);
    assert_eq!(endpoint_batches.len(), 1);
    assert_eq!(endpoint_batches[0].len(), 2);
    assert_eq!(endpoint_batches[0].commit_runs().len(), 1);
    assert_eq!(endpoint_batches[0].commit_runs()[0].len(), 2);
    assert!(!endpoint_batches[0].has_direct_packet_runs());
    let mut batches = take_driver_endpoint_batches(&mut driver);
    let direct_runs = batches
        .last_mut()
        .expect("commit batch")
        .take_direct_packet_batch()
        .into_packet_runs();
    assert_eq!(direct_runs.len(), 0);
}

#[test]
fn compact_endpoint_data_completion_coalesces_adjacent_direct_runs() {
    let source_peer = PeerIdentity::from_pubkey_full(crate::Identity::generate().pubkey_full());
    let source_addr = *source_peer.node_addr();
    let owner = OwnerId::fsp_node(source_addr);
    let previous_hop = test_node_addr(917);
    let local_addr = test_node_addr(918);
    let key = 0x93;
    let mut driver = DataplaneTurnDriver::new(AdmissionConfig::new(4, 8));
    driver.register_owner(owner, OwnerConfig::new(1, 8).with_source_peer(source_peer));
    driver
        .owner_mut(owner)
        .unwrap()
        .set_crypto_keys(OwnerCryptoKeys::new(test_key(key), test_key(key)));

    let endpoint_payloads = [
        b"run-one-a".as_slice(),
        b"run-one-b".as_slice(),
        b"run-two-a".as_slice(),
        b"run-two-b".as_slice(),
        b"run-two-c".as_slice(),
    ];
    for (counter, payload) in endpoint_payloads.into_iter().enumerate() {
        submit_endpoint_data_payload(
            &mut driver.mover,
            EndpointDataSubmit {
                owner,
                counter: counter as u64,
                timestamp: 917_001 + counter as u32,
                key,
                previous_hop,
                local_addr,
                payload,
            },
        );
    }

    let prepared = capture_prepared_work(&mut driver.mover, 8);
    assert_eq!(prepared.len(), 5);
    let mut completions = prepared
        .into_iter()
        .map(execute_test_prepared_crypto_work)
        .collect::<VecDeque<_>>();
    let summary = start_test_aead_completion_turn(&mut driver, &mut completions, 8, true);

    assert_eq!(summary.completions(), 5);
    assert_eq!(summary.outputs(), 0);
    let endpoint_batches = driver_endpoint_batches(&driver);
    assert_eq!(endpoint_batches.len(), 1);
    assert_eq!(endpoint_batches[0].len(), 5);
    assert_eq!(endpoint_batches[0].commit_runs().len(), 1);
    assert_eq!(endpoint_batches[0].commit_runs()[0].len(), 5);
    assert!(endpoint_batches[0].has_direct_packet_runs());
    assert!(driver.outputs.is_empty());

    let mut batches = take_driver_endpoint_batches(&mut driver);
    assert_eq!(batches.len(), 1);
    let batch = batches
        .last_mut()
        .expect("direct packet batch")
        .take_direct_packet_batch();
    let mut runs = batch.into_packet_runs();
    assert_eq!(runs.len(), 1);
    assert_eq!(runs.iter().map(|run| run.len()).sum::<usize>(), 5);
    assert_eq!(runs[0].source_peer(), &source_peer);
    assert_eq!(runs[0].len(), 5);
    let packets = runs[0]
        .packet_slices()
        .map(<[u8]>::to_vec)
        .collect::<Vec<_>>();
    assert_eq!(
        packets,
        vec![
            b"run-one-a".to_vec(),
            b"run-one-b".to_vec(),
            b"run-two-a".to_vec(),
            b"run-two-b".to_vec(),
            b"run-two-c".to_vec(),
        ]
    );
    runs[0].retain_packets(|index, _packet| index >= 2);
    assert_eq!(runs[0].len(), 3);
    assert_eq!(
        runs[0].packet_bytes(),
        b"run-two-a".len() + b"run-two-b".len() + b"run-two-c".len()
    );
    let retained = runs[0]
        .packet_slices()
        .map(<[u8]>::to_vec)
        .collect::<Vec<_>>();
    assert_eq!(
        retained,
        vec![
            b"run-two-a".to_vec(),
            b"run-two-b".to_vec(),
            b"run-two-c".to_vec()
        ]
    );
}

#[test]
fn completion_only_turn_retires_out_of_order_completions_in_owner_order() {
    let owner = fmp_owner(81);
    let open_key = 81;
    let mut driver = DataplaneTurnDriver::new(AdmissionConfig::new(4, 8));
    driver.register_owner(owner, OwnerConfig::new(1, 8));

    let packets: [(u64, &[u8]); 3] = [(100, b"first"), (101, b"second"), (102, b"third")];
    for (counter, payload) in packets {
        driver
            .mover
            .submit_socket_packet(
                fmp_socket_packet(
                    owner,
                    1,
                    OutputTarget::Transport,
                    fmp_encrypted_wire(81, counter, 0, payload, open_key),
                )
                .unwrap(),
            )
            .unwrap();
    }

    let mut work = dispatch_available(&mut driver.mover, 8);
    assert_eq!(work.len(), 3);
    assert_eq!(driver.owner_mut(owner).unwrap().in_flight, 3);

    let mut completions = work
        .drain(..)
        .map(|work| complete_test_open_work(work, open_key))
        .collect::<Vec<_>>();
    assert_eq!(
        completions
            .iter()
            .map(|completion| completion.reservation.counter)
            .collect::<Vec<_>>(),
        vec![100, 101, 102]
    );

    let third = completions.pop().unwrap();
    let first = completions.remove(0);
    let second = completions.remove(0);

    {
        let turn = run_aead_completion_turn(&mut driver, [third], 8);
        assert_eq!(turn.summary().dispatched(), 0);
        assert_eq!(turn.summary().outputs(), 0);
        assert!(turn.outputs().is_empty());
        assert!(turn.drops().is_empty());
    }
    assert_eq!(driver.owner_mut(owner).unwrap().in_flight, 3);

    {
        let turn = run_aead_completion_turn(&mut driver, [first], 8);
        assert_eq!(turn.summary().dispatched(), 0);
        assert_eq!(turn.summary().outputs(), 1);
        assert_eq!(turn.outputs()[0].counter(), 100);
        assert_eq!(
            &turn.outputs()[0].payload()[FMP_ESTABLISHED_HEADER_SIZE..],
            b"first"
        );
        assert!(turn.drops().is_empty());
    }
    assert_eq!(driver.owner_mut(owner).unwrap().in_flight, 2);

    {
        let turn = run_aead_completion_turn(&mut driver, [second], 8);
        assert_eq!(turn.summary().dispatched(), 0);
        assert_eq!(turn.summary().outputs(), 2);
        assert_eq!(turn.outputs()[0].counter(), 101);
        assert_eq!(turn.outputs()[1].counter(), 102);
        assert_eq!(
            &turn.outputs()[0].payload()[FMP_ESTABLISHED_HEADER_SIZE..],
            b"second"
        );
        assert_eq!(
            &turn.outputs()[1].payload()[FMP_ESTABLISHED_HEADER_SIZE..],
            b"third"
        );
        assert!(turn.drops().is_empty());
    }
    assert_eq!(driver.owner_mut(owner).unwrap().in_flight, 0);
}

#[test]
fn completion_only_turn_drops_stale_generation_and_unblocks_newer_completion() {
    let owner = fmp_owner(82);
    let open_key = 82;
    let mut driver = DataplaneTurnDriver::new(AdmissionConfig::new(4, 8));
    driver.register_owner(owner, OwnerConfig::new(1, 8));

    driver
        .mover
        .submit_socket_packet(
            fmp_socket_packet(
                owner,
                1,
                OutputTarget::Transport,
                fmp_encrypted_wire(82, 100, 0, b"stale", open_key),
            )
            .unwrap(),
        )
        .unwrap();
    let mut old_work = dispatch_available(&mut driver.mover, 8);
    assert_eq!(old_work.len(), 1);

    driver.owner_mut(owner).unwrap().rekey(2);
    driver
        .mover
        .submit_socket_packet(
            fmp_socket_packet(
                owner,
                2,
                OutputTarget::Transport,
                fmp_encrypted_wire(82, 101, 0, b"new", open_key),
            )
            .unwrap(),
        )
        .unwrap();
    let mut new_work = dispatch_available(&mut driver.mover, 8);
    assert_eq!(new_work.len(), 1);
    assert_eq!(driver.owner_mut(owner).unwrap().in_flight, 2);

    let old_completion = complete_test_open_work(old_work.pop().unwrap(), open_key);
    let new_completion = complete_test_open_work(new_work.pop().unwrap(), open_key);

    {
        let turn = run_aead_completion_turn(&mut driver, [new_completion], 8);
        assert_eq!(turn.summary().dispatched(), 0);
        assert_eq!(turn.summary().outputs(), 0);
        assert_eq!(turn.summary().drops(), 0);
        assert!(turn.outputs().is_empty());
        assert!(turn.drops().is_empty());
    }
    assert_eq!(driver.owner_mut(owner).unwrap().in_flight, 2);

    {
        let turn = run_aead_completion_turn(&mut driver, [old_completion], 8);
        assert_eq!(turn.summary().dispatched(), 0);
        assert_eq!(turn.summary().outputs(), 1);
        assert_eq!(turn.summary().drops(), 1);
        assert_eq!(turn.outputs()[0].counter(), 101);
        assert_eq!(
            &turn.outputs()[0].payload()[FMP_ESTABLISHED_HEADER_SIZE..],
            b"new"
        );
        assert_eq!(turn.drops().len(), 1);
        assert_eq!(
            turn.drops()[0].reason(),
            PacketDropReason::StaleCompletionGeneration
        );
        assert_eq!(turn.drops()[0].counter(), Some(100));
    }
    assert_eq!(driver.owner_mut(owner).unwrap().in_flight, 0);
}

#[test]
fn completion_only_turn_reserves_priority_progress_after_bulk_completion() {
    let owner = fmp_owner(83);
    let seal_key = 83;
    let path = live_path(8300);
    let mut driver = DataplaneTurnDriver::new(AdmissionConfig::new(4, 8));
    driver.register_owner(owner, OwnerConfig::new(1, 3).with_next_send_counter(10));
    driver
        .owner_mut(owner)
        .unwrap()
        .set_active_path(path.clone());
    driver
        .owner_mut(owner)
        .unwrap()
        .set_crypto_keys(OwnerCryptoKeys::new(test_key(seal_key), test_key(seal_key)));

    driver
        .mover
        .submit_outbound_packet(OutboundPacket::fmp(
            owner,
            1,
            PacketClass::Bulk,
            830,
            0,
            PacketBuffer::new(b"bulk-1".to_vec()),
        ))
        .unwrap();
    let mut seal_work = dispatch_outbound_available(&mut driver.mover, 1);
    assert_eq!(seal_work.len(), 1);
    assert_eq!(driver.owner_mut(owner).unwrap().in_flight, 1);

    driver
        .mover
        .submit_outbound_packet(OutboundPacket::fmp(
            owner,
            1,
            PacketClass::Bulk,
            830,
            0,
            PacketBuffer::new(b"bulk-2".to_vec()),
        ))
        .unwrap();
    driver
        .mover
        .submit_outbound_packet(OutboundPacket::fmp(
            owner,
            1,
            PacketClass::Liveness,
            830,
            0,
            PacketBuffer::new(b"priority".to_vec()),
        ))
        .unwrap();

    let completion = complete_test_seal_work(seal_work.pop().unwrap(), seal_key);

    {
        let turn = run_aead_completion_turn(&mut driver, [completion], 1);
        assert_eq!(turn.summary().dispatched(), 1);
        assert_eq!(turn.summary().outputs(), 2);
        assert!(turn.drops().is_empty());
        assert_eq!(turn.outputs()[0].counter(), 10);
        assert_eq!(turn.outputs()[0].target(), OutputTarget::Transport);
        assert_eq!(turn.outputs()[0].path.clone(), Some(path.clone()));
        assert_eq!(open_sealed_output(&turn.outputs()[0], seal_key), b"bulk-1");
        assert_eq!(turn.outputs()[1].counter(), 11);
        assert_eq!(turn.outputs()[1].target(), OutputTarget::Transport);
        assert_eq!(turn.outputs()[1].path.clone(), Some(path));
        assert_eq!(
            open_sealed_output(&turn.outputs()[1], seal_key),
            b"priority"
        );
    }

    assert_eq!(driver.owner_mut(owner).unwrap().in_flight, 0);
}

#[test]
fn completion_only_turn_continues_owner_routed_fsp_wrap_to_fmp_output() {
    let source = NodeAddr::from_bytes([0x80; 16]);
    let dest = NodeAddr::from_bytes([0x81; 16]);
    let next_hop = NodeAddr::from_bytes([0x82; 16]);
    let fsp_owner = OwnerId::fsp_node(dest);
    let fmp_owner = OwnerId::fmp_node(next_hop);
    let fsp_key = 81;
    let fmp_key = 82;
    let fmp_path = live_path(8200);
    let mut driver = DataplaneTurnDriver::new(AdmissionConfig::new(4, 8));
    driver.register_owner(fsp_owner, OwnerConfig::new(1, 8).with_next_send_counter(50));
    driver.register_owner(fmp_owner, OwnerConfig::new(1, 8).with_next_send_counter(70));
    driver
        .owner_mut(fsp_owner)
        .unwrap()
        .set_crypto_keys(OwnerCryptoKeys::new(test_key(fsp_key), test_key(fsp_key)));
    driver
        .owner_mut(fmp_owner)
        .unwrap()
        .set_crypto_keys(OwnerCryptoKeys::new(test_key(fmp_key), test_key(fmp_key)));
    driver
        .owner_mut(fmp_owner)
        .unwrap()
        .set_active_path(fmp_path.clone());

    let wrap = DataplaneFspWrapRoute::new(fmp_owner, 1, 8282, source, dest)
        .with_ttl(42)
        .with_path_mtu(1280);
    driver
        .owner_mut(fsp_owner)
        .unwrap()
        .set_fsp_wrap_route(Some(wrap));
    let packet = OutboundPacket::fsp(
        fsp_owner,
        1,
        PacketClass::Liveness,
        0x03,
        PacketBuffer::new(b"wake-wrap".to_vec()),
    )
    .with_fsp_cleartext_prefix(empty_fsp_coords_prefix());

    driver.mover.submit_outbound_packet(packet).unwrap();
    let mut seal_work = dispatch_outbound_available(&mut driver.mover, 1);
    assert_eq!(seal_work.len(), 1);
    assert_eq!(driver.owner_mut(fsp_owner).unwrap().in_flight, 1);

    let completion = complete_test_seal_work(seal_work.pop().unwrap(), fsp_key);

    {
        let turn = run_aead_completion_turn(&mut driver, [completion], 1);
        assert_eq!(turn.summary().outbound_admitted(), 1);
        assert_eq!(turn.summary().dispatched(), 1);
        assert_eq!(turn.summary().outputs(), 1);
        assert!(turn.drops().is_empty());

        let output = &turn.outputs()[0];
        assert_eq!(output.owner(), fmp_owner);
        assert_eq!(output.counter(), 70);
        assert_eq!(output.target(), OutputTarget::Transport);
        assert_eq!(output.path.clone(), Some(fmp_path));

        let fmp_plaintext = open_sealed_output(output, fmp_key);
        assert_eq!(
            fmp_plaintext[0],
            crate::protocol::LinkMessageType::SessionDatagram.to_byte()
        );
        let datagram = crate::protocol::SessionDatagramRef::decode(&fmp_plaintext[1..])
            .expect("wrapped session datagram");
        assert_eq!(datagram.src_addr, source);
        assert_eq!(datagram.dest_addr, dest);
        assert_eq!(datagram.ttl, 42);
        assert_eq!(datagram.path_mtu, 1280);
        assert_eq!(
            open_fsp_wire_payload(datagram.payload, fsp_key),
            b"wake-wrap"
        );
    }

    assert_eq!(driver.owner_mut(fsp_owner).unwrap().in_flight, 0);
    assert_eq!(driver.owner_mut(fmp_owner).unwrap().in_flight, 0);
}
