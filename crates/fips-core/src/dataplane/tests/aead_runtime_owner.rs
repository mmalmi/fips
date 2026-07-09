    fn register_owner_with_test_keys(
        mover: &mut Dataplane,
        owner: OwnerId,
        open_key: u8,
        seal_key: u8,
    ) {
        mover.register_owner(owner, OwnerConfig::new(1, 8));
        mover
            .owner_mut(owner)
            .unwrap()
            .set_crypto_keys(OwnerCryptoKeys::new(test_key(open_key), test_key(seal_key)));
    }

    fn submit_fmp_inbound_range<I>(
        mover: &mut Dataplane,
        owner: OwnerId,
        receiver_idx: u32,
        open_key: u8,
        counters: I,
        payload: &'static [u8],
    ) where
        I: IntoIterator<Item = u64>,
    {
        for counter in counters {
            mover
                .submit_socket_packet(
                    fmp_socket_packet(
                        owner,
                        1,
                        OutputTarget::Transport,
                        fmp_encrypted_wire(receiver_idx, counter, 0, payload, open_key),
                    )
                    .unwrap(),
                )
                .unwrap();
        }
    }

    struct EndpointDataSubmit<'a> {
        owner: OwnerId,
        counter: u64,
        timestamp: u32,
        key: u8,
        previous_hop: NodeAddr,
        local_addr: NodeAddr,
        payload: &'a [u8],
    }

    fn submit_endpoint_data_payload(mover: &mut Dataplane, request: EndpointDataSubmit<'_>) {
        let EndpointDataSubmit {
            owner,
            counter,
            timestamp,
            key,
            previous_hop,
            local_addr,
            payload,
        } = request;
        let fsp_inner = crate::node::session_wire::fsp_prepend_inner_header(
            timestamp,
            crate::protocol::SessionMessageType::EndpointData.to_byte(),
            0,
            payload,
        );
        mover
            .submit_socket_packet(
                SocketPacket::new(
                    owner,
                    1,
                    counter,
                    PacketClass::Bulk,
                    OutputTarget::SessionPayload { local_addr },
                    PacketBuffer::new(fsp_encrypted_wire(counter, 0, &fsp_inner, key)),
                )
                .with_previous_hop(previous_hop)
                .with_activity_tick(ActivityTick::new(timestamp as u64)),
            )
            .unwrap();
    }

    fn run_with_worker_pool(
        mover: &mut Dataplane,
        pool: &mut DataplaneAeadWorkerPool,
    ) -> (usize, Vec<PacketOutput>, Vec<PacketDrop>) {
        run_with_worker_pool_limit(mover, pool, 8)
    }

    fn run_with_worker_pool_limit(
        mover: &mut Dataplane,
        pool: &mut DataplaneAeadWorkerPool,
        limit: usize,
    ) -> (usize, Vec<PacketOutput>, Vec<PacketDrop>) {
        let mut prepared_work = Vec::new();
        let mut completion_batches = Vec::new();
        let mut retired = Vec::new();
        let mut outbound_packets = Vec::new();
        let mut fsp_authenticated_ingress = DataplaneFspAuthenticatedIngress::default();
        let mut drops = Vec::new();
        let dispatched = mover.run_aead_available_into(
            limit,
            DataplaneAeadRunBuffers::new(
                &mut prepared_work,
                &mut completion_batches,
                &mut retired,
                &mut outbound_packets,
                &mut fsp_authenticated_ingress,
                &mut drops,
            ),
            pool,
            false,
        );
        assert!(outbound_packets.is_empty());
        assert!(fsp_authenticated_ingress.is_empty());
        (dispatched, retired, drops)
    }

    fn driver_endpoint_batches(
        driver: &DataplaneTurnDriver,
    ) -> Vec<&DataplaneEndpointDataBatch> {
        driver
            .fsp_authenticated_ingress
            .endpoint_data_batches
            .iter()
            .collect()
    }

    fn endpoint_batch_direct_packet_count(batch: &DataplaneEndpointDataBatch) -> usize {
        let mut batch = batch.clone();
        batch
            .take_direct_packet_batch()
            .into_packet_runs()
            .iter()
            .map(FipsEndpointDirectPacketRun::len)
            .sum()
    }

    fn take_driver_endpoint_batches(
        driver: &mut DataplaneTurnDriver,
    ) -> Vec<DataplaneEndpointDataBatch> {
        std::mem::take(&mut driver.fsp_authenticated_ingress).endpoint_data_batches
    }

    #[test]
    fn aead_worker_pool_returns_completion_batches() {
        let owner = fmp_owner(706);
        let open_key = 20;
        let mut mover = mover();
        register_owner_with_test_keys(&mut mover, owner, open_key, open_key);
        submit_fmp_inbound_range(&mut mover, owner, 706, open_key, 100..104, b"worker");

        let mut pool = test_aead_worker_pool(8);
        let (dispatched, retired, drops) = run_with_worker_pool(&mut mover, &mut pool);

        assert_eq!(dispatched, 4);
        assert!(retired.is_empty());
        assert!(drops.is_empty());
        assert_eq!(mover.owner_mut(owner).unwrap().in_flight, 4);

        let mut retired = Vec::new();
        let completions = drain_worker_pool_completions(&mut pool, 2);
        assert_eq!(completions.len(), 2);
        assert_eq!(pool.available_capacity(), 6);
        for completion in completions {
            retired.extend(retire_completion(&mut mover, completion));
        }

        let completions = drain_worker_pool_completions(&mut pool, 2);
        assert_eq!(completions.len(), 2);
        for completion in completions {
            retired.extend(retire_completion(&mut mover, completion));
        }
        let outputs = retired;
        assert_eq!(
            outputs
                .iter()
                .map(PacketOutput::counter)
                .collect::<Vec<_>>(),
            vec![100, 101, 102, 103]
        );
        assert_eq!(mover.owner_mut(owner).unwrap().in_flight, 0);
        assert_eq!(pool.available_capacity(), 8);
    }

    #[test]
    fn aead_worker_pool_retires_one_fsp_owner_run_across_bounded_subruns() {
        let source_addr = test_node_addr(714);
        let owner = OwnerId::fsp_node(source_addr);
        let previous_hop = test_node_addr(715);
        let local_addr = test_node_addr(716);
        let open_key = 25;
        let packet_count = DATAPLANE_AEAD_JOB_PACKETS;
        let worker_capacity = packet_count + DATAPLANE_AEAD_WORKER_FAIRNESS_PACKETS;
        let mut mover = Dataplane::new(AdmissionConfig::new(packet_count, packet_count));
        mover.register_owner(owner, OwnerConfig::new(1, packet_count + 1));
        mover
            .owner_mut(owner)
            .unwrap()
            .set_crypto_keys(OwnerCryptoKeys::new(test_key(open_key), test_key(open_key)));
        for counter in 0..packet_count {
            submit_endpoint_data_payload(
                &mut mover,
                EndpointDataSubmit {
                    owner,
                    counter: counter as u64,
                    timestamp: 714_000 + counter as u32,
                    key: open_key,
                    previous_hop,
                    local_addr,
                    payload: b"shared-owner-run",
                },
            );
        }

        let mut pool = test_aead_worker_pool(worker_capacity);
        let (dispatched, retired, drops) =
            run_with_worker_pool_limit(&mut mover, &mut pool, packet_count);

        assert_eq!(dispatched, packet_count);
        assert!(retired.is_empty());
        assert!(drops.is_empty());
        assert_eq!(mover.owner_mut(owner).unwrap().in_flight, packet_count);

        let mut batches = drain_worker_pool_completion_batches(&mut pool, packet_count);
        assert_eq!(batches.len(), 1);
        assert_eq!(batches[0].len(), packet_count);
        assert_eq!(pool.available_capacity(), worker_capacity);
        let CryptoCompletionRun::OpenOwnerRun { run, range } = &batches[0].completions else {
            panic!("FSP session payload opens must keep the shared owner-run container");
        };
        assert_eq!(range, &(0..packet_count));
        assert_eq!(
            run.shared
                .remaining_subruns
                .load(std::sync::atomic::Ordering::Acquire),
            0
        );

        mover.queue_completion_batches(&mut batches);
        let mut outputs = Vec::new();
        let mut outbound_packets = Vec::new();
        let mut fsp_authenticated_ingress = DataplaneFspAuthenticatedIngress::default();
        assert_eq!(
            mover.retire_queued_completions_into(
                5,
                &mut DataplaneRetiredOutputSink::new(
                    &mut outputs,
                    &mut outbound_packets,
                    &mut fsp_authenticated_ingress,
                ),
                false,
            ),
            5
        );
        assert_eq!(
            outputs.iter().map(PacketOutput::counter).collect::<Vec<_>>(),
            (0..5).collect::<Vec<_>>()
        );
        assert_eq!(mover.owner_mut(owner).unwrap().in_flight, packet_count - 5);

        assert_eq!(
            mover.retire_queued_completions_into(
                packet_count,
                &mut DataplaneRetiredOutputSink::new(
                    &mut outputs,
                    &mut outbound_packets,
                    &mut fsp_authenticated_ingress,
                ),
                false,
            ),
            packet_count - 5
        );
        assert_eq!(
            outputs.iter().map(PacketOutput::counter).collect::<Vec<_>>(),
            (0..packet_count as u64).collect::<Vec<_>>()
        );
        assert_eq!(mover.owner_mut(owner).unwrap().in_flight, 0);
        assert!(outbound_packets.is_empty());
        assert!(fsp_authenticated_ingress.is_empty());
        assert!(mover.drain_drops().is_empty());
    }

    #[test]
    fn aead_worker_pool_uses_shared_open_and_seal_capacity() {
        let owner = fmp_owner(710);
        let open_key = 23;
        let seal_key = 24;
        let mut mover = mover();
        mover.register_owner(owner, OwnerConfig::new(1, 8).with_next_send_counter(300));
        mover
            .owner_mut(owner)
            .unwrap()
            .set_crypto_keys(OwnerCryptoKeys::new(test_key(open_key), test_key(seal_key)));
        submit_fmp_inbound_range(&mut mover, owner, 710, open_key, 100..102, b"inbound");
        for idx in 0..2 {
            mover
                .submit_outbound_packet(OutboundPacket::fmp(
                    owner,
                    1,
                    PacketClass::Bulk,
                    710,
                    0,
                    PacketBuffer::new(format!("outbound-{idx}").into_bytes()),
                ))
                .unwrap();
        }

        let mut pool = test_aead_worker_pool(2);
        let (dispatched, retired, drops) = run_with_worker_pool_limit(&mut mover, &mut pool, 4);

        assert_eq!(dispatched, 2);
        assert!(retired.is_empty());
        assert!(drops.is_empty());
        assert_eq!(pool.available_capacity(), 0);
    }

    #[test]
    fn aead_worker_pool_reserves_priority_capacity_from_bulk() {
        let owner = fmp_owner(709);
        let open_key = 22;
        let mut mover = Dataplane::new(AdmissionConfig::new(16, 32));
        mover.register_owner(
            owner,
            OwnerConfig::new(1, DATAPLANE_AEAD_WORKER_FAIRNESS_PACKETS * 2),
        );
        mover
            .owner_mut(owner)
            .unwrap()
            .set_crypto_keys(OwnerCryptoKeys::new(test_key(open_key), test_key(open_key)));
        let mut pool = test_aead_worker_pool(DATAPLANE_AEAD_WORKER_FAIRNESS_PACKETS * 2);

        for counter in 0..(DATAPLANE_AEAD_WORKER_FAIRNESS_PACKETS * 2) as u64 {
            mover
                .submit_socket_packet(encrypted_fmp_packet(
                    owner,
                    1,
                    counter,
                    PacketClass::Bulk,
                    OutputTarget::Transport,
                    open_key,
                ))
                .unwrap();
        }

        let (dispatched, retired, drops) = run_with_worker_pool_limit(
            &mut mover,
            &mut pool,
            DATAPLANE_AEAD_WORKER_FAIRNESS_PACKETS * 2,
        );
        assert_eq!(dispatched, DATAPLANE_AEAD_WORKER_FAIRNESS_PACKETS);
        assert!(retired.is_empty());
        assert!(drops.is_empty());
        assert_eq!(pool.available_capacity_for_lane(Lane::Bulk), 0);
        assert_eq!(
            pool.available_capacity_for_lane(Lane::Priority),
            DATAPLANE_AEAD_WORKER_FAIRNESS_PACKETS
        );

        mover
            .submit_socket_packet(encrypted_fmp_packet(
                owner,
                1,
                1_000,
                PacketClass::Liveness,
                OutputTarget::Transport,
                open_key,
            ))
            .unwrap();
        let (dispatched, retired, drops) = run_with_worker_pool_limit(
            &mut mover,
            &mut pool,
            DATAPLANE_AEAD_WORKER_FAIRNESS_PACKETS * 2,
        );
        assert_eq!(dispatched, 1);
        assert!(retired.is_empty());
        assert!(drops.is_empty());
    }

    #[test]
    fn aead_worker_pool_capacity_blocks_reservation_until_completion_drain() {
        let owner = fmp_owner(707);
        let open_key = 21;
        let mut mover = mover();
        register_owner_with_test_keys(&mut mover, owner, open_key, open_key);
        submit_fmp_inbound_range(&mut mover, owner, 707, open_key, 100..104, b"worker-cap");

        let mut pool = test_aead_worker_pool(2);
        let (dispatched, retired, drops) = run_with_worker_pool(&mut mover, &mut pool);
        assert_eq!(dispatched, 2);
        assert!(retired.is_empty());
        assert!(drops.is_empty());
        assert_eq!(pool.available_capacity(), 0);
        assert_eq!(mover.owner_mut(owner).unwrap().in_flight, 2);

        let (dispatched, retired, drops) = run_with_worker_pool(&mut mover, &mut pool);
        assert_eq!(dispatched, 0);
        assert!(retired.is_empty());
        assert!(drops.is_empty());
        assert_eq!(mover.owner_mut(owner).unwrap().in_flight, 2);

        let completions = drain_worker_pool_completions(&mut pool, 2);
        assert_eq!(completions.len(), 2);
        for completion in completions {
            retire_completion(&mut mover, completion);
        }
        assert_eq!(mover.owner_mut(owner).unwrap().in_flight, 0);
        assert_eq!(pool.available_capacity(), 2);

        let (dispatched, retired, drops) = run_with_worker_pool(&mut mover, &mut pool);
        assert_eq!(dispatched, 2);
        assert!(retired.is_empty());
        assert!(drops.is_empty());
        assert_eq!(mover.owner_mut(owner).unwrap().in_flight, 2);

        let completions = drain_worker_pool_completions(&mut pool, 2);
        assert_eq!(completions.len(), 2);
        for completion in completions {
            retire_completion(&mut mover, completion);
        }
        assert_eq!(mover.owner_mut(owner).unwrap().in_flight, 0);

        let (dispatched, retired, drops) = run_with_worker_pool(&mut mover, &mut pool);
        assert_eq!(dispatched, 0);
        assert!(retired.is_empty());
        assert!(drops.is_empty());
    }

    #[test]
    fn aead_turn_runner_wraps_owner_routed_fsp_into_next_hop_fmp() {
        let source = NodeAddr::from_bytes([0x21; 16]);
        let dest = NodeAddr::from_bytes([0x22; 16]);
        let next_hop = NodeAddr::from_bytes([0x23; 16]);
        let fsp_owner = OwnerId::fsp_node(dest);
        let fmp_owner = OwnerId::fmp_node(next_hop);
        let fsp_key = 21;
        let fmp_key = 22;
        let fmp_path = live_path(2200);
        let mut driver =
            DataplaneTurnDriver::new(AdmissionConfig::new(4, 8));
        driver.register_owner(
            fsp_owner,
            OwnerConfig::new(1, 8)
                .with_next_send_counter(50)
                .with_fsp_session_start_ms(1_000),
        );
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

        let wrap = DataplaneFspWrapRoute::new(
            fmp_owner,
            1,
            4242,
            source,
            dest,
        )
        .with_fmp_flags(0x05)
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
            PacketBuffer::new(b"session-body".to_vec()),
        )
        .with_fsp_cleartext_prefix(empty_fsp_coords_prefix())
        .with_activity_tick(ActivityTick::new(1_234));
        let queued_bulk = OutboundPacket::fmp(
            fmp_owner,
            1,
            PacketClass::Bulk,
            4243,
            0,
            PacketBuffer::new(b"queued-bulk".to_vec()),
        );

        let first =
            run_aead_classified_turn(&mut driver, std::iter::empty(), [packet, queued_bulk], 1);
        assert_eq!(first.summary().outbound_admitted(), 3);
        assert_eq!(first.summary().dispatched(), 1);
        assert_eq!(first.summary().outputs(), 0);
        assert!(first.drops().is_empty());

        let second = run_aead_classified_turn(
            &mut driver,
            std::iter::empty::<SocketPacket>(),
            std::iter::empty::<OutboundPacket>(),
            1,
        );
        assert_eq!(second.summary().dispatched(), 1);
        assert_eq!(second.summary().outputs(), 1);
        assert!(second.drops().is_empty());

        let output = &second.outputs()[0];
        assert_eq!(output.owner(), fmp_owner);
        assert_eq!(output.counter(), 70);
        assert_eq!(output.target(), OutputTarget::Transport);
        assert_eq!(output.path.clone(), Some(fmp_path));
        let receipt = output.fsp_send_receipt.expect("wrapped FSP receipt");
        assert_eq!(receipt.owner, fsp_owner);
        assert_eq!(receipt.counter, 50);

        let fmp_plaintext = open_sealed_output(output, fmp_key);
        assert_eq!(
            fmp_plaintext[0],
            crate::protocol::LinkMessageType::SessionDatagram.to_byte()
        );
        let datagram = crate::protocol::SessionDatagramRef::decode(&fmp_plaintext[1..])
            .expect("wrapped session datagram");
        assert_eq!(datagram.ttl, 42);
        assert_eq!(datagram.path_mtu, 1280);
        assert_eq!(datagram.src_addr, source);
        assert_eq!(datagram.dest_addr, dest);

        let fsp_header = FspWireHeader::parse(datagram.payload).unwrap();
        assert_eq!(fsp_header.counter(), 50);
        assert_eq!(fsp_header.flags(), 0x03);
        assert_eq!(
            open_fsp_wire_payload(datagram.payload, fsp_key),
            b"session-body"
        );

        let third = run_aead_classified_turn(
            &mut driver,
            std::iter::empty::<SocketPacket>(),
            std::iter::empty::<OutboundPacket>(),
            1,
        );
        assert_eq!(third.summary().dispatched(), 1);
        assert_eq!(third.summary().outputs(), 1);
        assert!(third.drops().is_empty());

        let output = &third.outputs()[0];
        assert_eq!(output.owner(), fmp_owner);
        assert_eq!(output.counter(), 71);
        assert_eq!(open_sealed_output(output, fmp_key), b"queued-bulk");
    }

    #[test]
    fn direct_fsp_endpoint_data_seals_payloads_to_transport() {
        let owner = fsp_owner(320);
        let key = 32;
        let path = live_path(3200);
        let mut driver = DataplaneTurnDriver::new(AdmissionConfig::new(4, 8));
        driver.register_owner(
            owner,
            OwnerConfig::new(1, 8)
                .with_next_send_counter(90)
                .with_fsp_session_start_ms(2_000),
        );
        driver
            .owner_mut(owner)
            .unwrap()
            .set_crypto_keys(OwnerCryptoKeys::new(test_key(key), test_key(key)));
        driver.owner_mut(owner).unwrap().set_active_path(path.clone());

        let route = DataplaneEndpointDataRoute::fsp(owner, 1, 0, 0);
        let routed = route_endpoint_payloads(&route, vec![
            b"direct-one".to_vec(),
            b"direct-two".to_vec(),
        ]);
        assert!(routed.dropped.is_empty());
        assert_eq!(routed.routed.len(), 2);
        let routed_packets = routed
            .routed
            .into_iter()
            .map(|packet| packet.with_activity_tick(ActivityTick::new(2_345)))
            .collect::<Vec<_>>();

        let turn = run_aead_classified_turn(
            &mut driver,
            std::iter::empty(),
            routed_packets,
            8,
        );
        assert_eq!(turn.summary().outbound_admitted(), 2);
        assert_eq!(turn.summary().dispatched(), 2);
        assert_eq!(turn.summary().outputs(), 2);
        assert!(turn.drops().is_empty());

        for (idx, expected) in [b"direct-one".as_slice(), b"direct-two".as_slice()]
            .into_iter()
            .enumerate()
        {
            let output = &turn.outputs()[idx];
            assert_eq!(output.owner(), owner);
            assert_eq!(output.counter(), 90 + idx as u64);
            assert_eq!(output.target(), OutputTarget::Transport);
            assert_eq!(output.path.clone(), Some(path.clone()));
            assert!(output.fsp_send_receipt.is_none());

            let header = FspWireHeader::parse(output.payload()).unwrap();
            assert_eq!(header.counter(), 90 + idx as u64);
            assert_eq!(
                header.flags() & crate::node::session_wire::FSP_FLAG_DIRECT_TRANSPORT,
                crate::node::session_wire::FSP_FLAG_DIRECT_TRANSPORT
            );
            let plaintext = open_sealed_output(output, key);
            let (_timestamp, msg_type, _inner_flags, body) =
                crate::node::session_wire::fsp_strip_inner_header(&plaintext).unwrap();
            assert_eq!(
                msg_type,
                crate::protocol::SessionMessageType::EndpointData.to_byte()
            );
            assert_eq!(body, expected);
        }
    }

    #[test]
    fn aead_turn_runner_spends_remaining_budget_on_owner_routed_fsp_wrap() {
        let source = NodeAddr::from_bytes([0x31; 16]);
        let dest = NodeAddr::from_bytes([0x32; 16]);
        let next_hop = NodeAddr::from_bytes([0x33; 16]);
        let fsp_owner = OwnerId::fsp_node(dest);
        let fmp_owner = OwnerId::fmp_node(next_hop);
        let fsp_key = 31;
        let fmp_key = 32;
        let fmp_path = live_path(3200);
        let mut driver =
            DataplaneTurnDriver::new(AdmissionConfig::new(4, 8));
        driver.register_owner(fsp_owner, OwnerConfig::new(1, 8).with_next_send_counter(90));
        driver.register_owner(fmp_owner, OwnerConfig::new(1, 8).with_next_send_counter(100));
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

        let wrap = DataplaneFspWrapRoute::new(fmp_owner, 1, 5151, source, dest)
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
            PacketBuffer::new(b"session-priority".to_vec()),
        )
        .with_fsp_cleartext_prefix(empty_fsp_coords_prefix());

        let turn = run_aead_classified_turn(&mut driver, std::iter::empty(), [packet], 2);
        assert_eq!(turn.summary().outbound_admitted(), 2);
        assert_eq!(turn.summary().dispatched(), 2);
        assert_eq!(turn.summary().outputs(), 1);
        assert!(turn.drops().is_empty());

        let output = &turn.outputs()[0];
        assert_eq!(output.owner(), fmp_owner);
        assert_eq!(output.counter(), 100);
        assert_eq!(output.target(), OutputTarget::Transport);
        assert_eq!(output.path.clone(), Some(fmp_path));
        let fmp_plaintext = open_sealed_output(output, fmp_key);
        let datagram = crate::protocol::SessionDatagramRef::decode(&fmp_plaintext[1..])
            .expect("wrapped session datagram");
        let fsp_header = FspWireHeader::parse(datagram.payload).unwrap();
        assert_eq!(fsp_header.counter(), 90);
        assert_eq!(
            open_fsp_wire_payload(datagram.payload, fsp_key),
            b"session-priority"
        );
    }

    #[test]
    fn aead_turn_runner_drains_queued_wrap_outputs_until_budget_exhausts() {
        let source = NodeAddr::from_bytes([0x41; 16]);
        let dest = NodeAddr::from_bytes([0x42; 16]);
        let next_hop = NodeAddr::from_bytes([0x43; 16]);
        let fsp_owner = OwnerId::fsp_node(dest);
        let fmp_owner = OwnerId::fmp_node(next_hop);
        let fsp_key = 41;
        let fmp_key = 42;
        let fmp_path = live_path(4200);
        let mut driver =
            DataplaneTurnDriver::new(AdmissionConfig::new(4, 8));
        driver.register_owner(
            fsp_owner,
            OwnerConfig::new(1, 8).with_next_send_counter(10),
        );
        driver.register_owner(
            fmp_owner,
            OwnerConfig::new(1, 8).with_next_send_counter(20),
        );
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

        let wrap = DataplaneFspWrapRoute::new(fmp_owner, 1, 6000, source, dest)
            .with_ttl(42)
            .with_path_mtu(1280);
        driver
            .owner_mut(fsp_owner)
            .unwrap()
            .set_fsp_wrap_route(Some(wrap));
        let packets = (0..4).map(|idx| {
            OutboundPacket::fsp(
                fsp_owner,
                1,
                PacketClass::Bulk,
                crate::node::session_wire::FSP_FLAG_CP,
                PacketBuffer::new(format!("session-{idx}").into_bytes()),
            )
            .with_fsp_cleartext_prefix(empty_fsp_coords_prefix())
        });

        let turn = run_aead_classified_turn(&mut driver, std::iter::empty(), packets, 8);
        assert_eq!(turn.summary().outbound_admitted(), 8);
        assert_eq!(turn.summary().dispatched(), 8);
        assert_eq!(turn.summary().outputs(), 4);
        assert!(turn.drops().is_empty());

        for (idx, output) in turn.outputs().iter().enumerate() {
            assert_eq!(output.owner(), fmp_owner);
            assert_eq!(output.counter(), 20 + idx as u64);
            assert_eq!(output.target(), OutputTarget::Transport);
            assert_eq!(output.path.clone(), Some(fmp_path.clone()));
            let fmp_plaintext = open_sealed_output(output, fmp_key);
            let datagram = crate::protocol::SessionDatagramRef::decode(&fmp_plaintext[1..])
                .expect("wrapped session datagram");
            assert_eq!(
                open_fsp_wire_payload(datagram.payload, fsp_key),
                format!("session-{idx}").as_bytes()
            );
        }
    }

    #[test]
    fn aead_turn_runner_reserves_progress_for_outbound_priority_under_inbound_bulk() {
        let owner = fmp_owner(701);
        let open_key = 13;
        let seal_key = 14;
        let path = live_path(7010);
        let mut mover = mover();
        mover.register_owner(owner, OwnerConfig::new(1, 8).with_next_send_counter(900));
        mover
            .owner_mut(owner)
            .unwrap()
            .set_active_path(path.clone());
        mover
            .owner_mut(owner)
            .unwrap()
            .set_crypto_keys(OwnerCryptoKeys::new(test_key(open_key), test_key(seal_key)));

        for counter in 100..104 {
            mover
                .submit_socket_packet(
                    fmp_socket_packet(
                        owner,
                        1,
                        OutputTarget::Transport,
                        fmp_encrypted_wire(70, counter, 0, b"inbound-bulk", open_key),
                    )
                    .unwrap(),
                )
                .unwrap();
        }
        mover
            .submit_outbound_packet(OutboundPacket::fmp(
                owner,
                1,
                PacketClass::Liveness,
                701,
                0,
                PacketBuffer::new(b"outbound-liveness".to_vec()),
            ))
            .unwrap();

        let turn = run_aead_available(&mut mover, 2);

        assert_eq!(turn.dispatched(), 2);
        let outputs = turn.outputs();
        assert_eq!(outputs.len(), 2);
        assert_eq!(outputs[0].target, OutputTarget::Transport);
        assert_eq!(outputs[0].counter, 100);
        assert_eq!(outputs[1].target, OutputTarget::Transport);
        assert_eq!(outputs[1].counter, 900);
        assert_eq!(outputs[1].path.clone(), Some(path));
        assert_eq!(
            open_sealed_output(outputs[1], seal_key),
            b"outbound-liveness"
        );
    }

    #[test]
    fn aead_turn_runner_missing_keys_retires_failed_work_and_releases_in_flight() {
        let owner = fsp_owner(71);
        let mut mover = mover();
        mover.register_owner(owner, OwnerConfig::new(1, 8));
        mover
            .submit_outbound_packet(OutboundPacket::fsp(
                owner,
                1,
                PacketClass::Bulk,
                0,
                PacketBuffer::new(b"needs key".to_vec()),
            ))
            .unwrap();

        let turn = run_aead_available(&mut mover, 8);
        assert_eq!(turn.dispatched(), 1);
        assert!(turn.retired().is_empty());
        assert_eq!(turn.drops().len(), 1);
        assert_eq!(turn.drops()[0].reason, PacketDropReason::CryptoFailed);
        assert_eq!(turn.drops()[0].counter, Some(0));
        assert_eq!(mover.owner_mut(owner).unwrap().in_flight, 0);
    }

    #[test]
    fn rekey_clears_owner_crypto_keys_and_restarts_send_counter() {
        let owner = fmp_owner(72);
        let mut mover = mover();
        mover.register_owner(owner, OwnerConfig::new(1, 8).with_next_send_counter(99));
        mover
            .owner_mut(owner)
            .unwrap()
            .set_crypto_keys(OwnerCryptoKeys::new(test_key(1), test_key(1)));
        mover.owner_mut(owner).unwrap().rekey(2);
        mover
            .submit_outbound_packet(OutboundPacket::fmp(
                owner,
                2,
                PacketClass::Bulk,
                720,
                0,
                PacketBuffer::new(b"after rekey".to_vec()),
            ))
            .unwrap();

        let turn = run_aead_available(&mut mover, 8);
        assert_eq!(turn.dispatched(), 1);
        assert!(turn.retired().is_empty());
        assert_eq!(turn.drops().len(), 1);
        assert_eq!(turn.drops()[0].reason, PacketDropReason::CryptoFailed);
        assert_eq!(turn.drops()[0].counter, Some(0));
        let owner = mover.owner_mut(owner).unwrap();
        assert_eq!(owner.next_send_counter, 1);
        assert_eq!(owner.in_flight, 0);
    }

    #[test]
    fn owner_tracks_inbound_path_drift_and_uses_latest_path_for_outbound_transport() {
        let owner = fmp_owner(73);
        let open_key = 21;
        let seal_key = 22;
        let path_a = live_path(100);
        let path_b = live_path(200);
        let mut mover = mover();
        mover.register_owner(owner, OwnerConfig::new(1, 8).with_next_send_counter(500));
        mover
            .owner_mut(owner)
            .unwrap()
            .set_crypto_keys(OwnerCryptoKeys::new(test_key(open_key), test_key(seal_key)));

        let inbound_a = fmp_socket_packet(
            owner,
            1,
            OutputTarget::Transport,
            fmp_encrypted_wire(73, 1000, 0, b"in-a", open_key),
        )
        .unwrap()
        .with_source_path(path_a.clone());
        mover.submit_socket_packet(inbound_a).unwrap();
        let turn = run_aead_available(&mut mover, 8);
        assert!(turn.drops().is_empty());
        assert_eq!(turn.outputs()[0].path.clone(), None);
        assert_eq!(
            mover.owner_mut(owner).unwrap().active_path(),
            Some(path_a.clone())
        );

        mover
            .submit_outbound_packet(OutboundPacket::fmp(
                owner,
                1,
                PacketClass::Bulk,
                730,
                0,
                PacketBuffer::new(b"out-a".to_vec()),
            ))
            .unwrap();
        let turn = run_aead_available(&mut mover, 8);
        let output = turn.outputs()[0];
        assert_eq!(output.counter, 500);
        assert_eq!(output.target, OutputTarget::Transport);
        assert_eq!(output.path.clone(), Some(path_a));
        assert_eq!(open_sealed_output(output, seal_key), b"out-a");

        let inbound_b = fmp_socket_packet(
            owner,
            1,
            OutputTarget::Transport,
            fmp_encrypted_wire(73, 1001, 0, b"in-b", open_key),
        )
        .unwrap()
        .with_source_path(path_b.clone());
        mover.submit_socket_packet(inbound_b).unwrap();
        let turn = run_aead_available(&mut mover, 8);
        assert!(turn.drops().is_empty());
        assert_eq!(turn.outputs()[0].path.clone(), None);
        assert_eq!(
            mover.owner_mut(owner).unwrap().active_path(),
            Some(path_b.clone())
        );

        mover
            .submit_outbound_packet(OutboundPacket::fmp(
                owner,
                1,
                PacketClass::Bulk,
                730,
                0,
                PacketBuffer::new(b"out-b".to_vec()),
            ))
            .unwrap();
        let turn = run_aead_available(&mut mover, 8);
        let output = turn.outputs()[0];
        assert_eq!(output.counter, 501);
        assert_eq!(output.path.clone(), Some(path_b));
        assert_eq!(open_sealed_output(output, seal_key), b"out-b");
    }

    #[test]
    fn stale_generation_does_not_move_owner_path() {
        let owner = fsp_owner(74);
        let old_path = live_path(10);
        let stale_path = live_path(11);
        let mut mover = mover();
        mover.register_owner(owner, OwnerConfig::new(2, 8));
        mover
            .owner_mut(owner)
            .unwrap()
            .set_active_path(old_path.clone());
        mover
            .submit_socket_packet(
                SocketPacket::new(
                    owner,
                    1,
                    5,
                    PacketClass::Bulk,
                    OutputTarget::Transport,
                    PacketBuffer::new(b"stale".to_vec()),
                )
                .with_source_path(stale_path),
            )
            .unwrap();

        let work = dispatch_available(&mut mover, 8);
        assert!(work.is_empty());
        let drops = mover.drain_drops();
        assert_eq!(drops.len(), 1);
        assert_eq!(drops[0].reason, PacketDropReason::StaleGeneration);
        assert_eq!(
            mover.owner_mut(owner).unwrap().active_path(),
            Some(old_path)
        );
    }

    #[test]
    fn owner_tracks_inbound_activity_only_for_reserved_packets() {
        let owner = fsp_owner(75);
        let mut mover = mover();
        mover.register_owner(owner, OwnerConfig::new(1, 8));

        mover
            .submit_socket_packet(
                packet(owner, 1, 1, PacketClass::Bulk, OutputTarget::Transport)
                    .with_activity_tick(ActivityTick::new(10)),
            )
            .unwrap();
        assert_eq!(dispatch_available(&mut mover, 8).len(), 1);
        assert_eq!(
            mover.owner_mut(owner).unwrap().last_rx_activity(),
            Some(ActivityTick::new(10))
        );

        mover
            .submit_socket_packet(
                packet(owner, 1, 1, PacketClass::Bulk, OutputTarget::Transport)
                    .with_activity_tick(ActivityTick::new(20)),
            )
            .unwrap();
        assert!(dispatch_available(&mut mover, 8).is_empty());
        assert_eq!(
            mover.owner_mut(owner).unwrap().last_rx_activity(),
            Some(ActivityTick::new(10))
        );

        mover
            .submit_socket_packet(
                packet(owner, 0, 2, PacketClass::Bulk, OutputTarget::Transport)
                    .with_activity_tick(ActivityTick::new(30)),
            )
            .unwrap();
        assert!(dispatch_available(&mut mover, 8).is_empty());
        assert_eq!(
            mover.owner_mut(owner).unwrap().last_rx_activity(),
            Some(ActivityTick::new(10))
        );

        let drops = mover.drain_drops();
        assert!(
            drops
                .iter()
                .any(|drop| drop.reason == PacketDropReason::Replay && drop.counter == Some(1))
        );
        assert!(drops.iter().any(
            |drop| drop.reason == PacketDropReason::StaleGeneration && drop.counter == Some(2)
        ));
    }

    #[test]
    fn owner_tracks_outbound_activity_only_for_reserved_packets() {
        let owner = fmp_owner(76);
        let mut mover = mover();
        mover.register_owner(owner, OwnerConfig::new(1, 8).with_next_send_counter(7));

        mover
            .submit_outbound_packet(
                outbound_packet(owner, 1, PacketClass::Bulk, b"newer")
                    .with_activity_tick(ActivityTick::new(50)),
            )
            .unwrap();
        let work = dispatch_outbound_available(&mut mover, 8);
        assert_eq!(work.len(), 1);
        assert_eq!(work[0].reservation.counter, 7);
        assert_eq!(
            mover.owner_mut(owner).unwrap().last_tx_activity(),
            Some(ActivityTick::new(50))
        );

        mover
            .submit_outbound_packet(
                outbound_packet(owner, 1, PacketClass::Liveness, b"older")
                    .with_activity_tick(ActivityTick::new(40)),
            )
            .unwrap();
        assert_eq!(dispatch_outbound_available(&mut mover, 8).len(), 1);
        assert_eq!(
            mover.owner_mut(owner).unwrap().last_tx_activity(),
            Some(ActivityTick::new(50))
        );

        mover
            .submit_outbound_packet(
                outbound_packet(owner, 0, PacketClass::Liveness, b"stale")
                    .with_activity_tick(ActivityTick::new(60)),
            )
            .unwrap();
        assert!(dispatch_outbound_available(&mut mover, 8).is_empty());
        assert_eq!(
            mover.owner_mut(owner).unwrap().last_tx_activity(),
            Some(ActivityTick::new(50))
        );

        let drops = mover.drain_drops();
        assert!(
            drops
                .iter()
                .any(|drop| drop.reason == PacketDropReason::StaleGeneration
                    && drop.counter.is_none())
        );
    }

    #[test]
    fn fsp_owner_tracks_data_return_without_registry_side_channel() {
        let owner = fsp_owner(77);
        let next_hop = fmp_owner(78);
        let wrap =
            DataplaneFspWrapRoute::new(next_hop, 1, 7878, test_node_addr(1), owner.node_addr());
        let mut mover = mover();
        mover.register_owner(
            owner,
            OwnerConfig::new(1, 8).with_next_send_counter(10),
        );
        mover
            .owner_mut(owner)
            .unwrap()
            .set_fsp_wrap_route(Some(wrap));

        let outbound = OutboundPacket::fsp(owner, 1, PacketClass::Bulk, 0, PacketBuffer::new(b"payload".to_vec()))
            .with_fsp_inner_header(crate::protocol::SessionMessageType::EndpointData.to_byte(), 0)
            .with_activity_tick(ActivityTick::new(100));
        mover.submit_outbound_packet(outbound).unwrap();
        assert_eq!(dispatch_outbound_available(&mut mover, 8).len(), 1);

        let activity = mover.owner_fsp_activity(owner).unwrap();
        assert_eq!(activity.last_outbound_next_hop(), Some(next_hop.node_addr()));
        assert!(activity.has_recent_outbound_activity(105, 10));
        assert!(activity.has_recent_outbound_without_inbound(105, 10));
        assert_eq!(mover.record_fsp_decrypt_failure(owner), Some(1));
        assert_eq!(mover.record_fsp_decrypt_failure(owner), Some(2));
        let sync = |counter, body_len| FspReceiveSync {
            counter,
            received_k_bit: false,
            timestamp: 0,
            plaintext_len: FSP_INNER_HEADER_SIZE + body_len,
            ce_flag: false,
            path_mtu: u16::MAX,
            spin_bit: false,
        };

        assert!(mover
            .record_authenticated_fsp_session(
                DataplaneAuthenticatedFspSession::new(
                owner.node_addr(),
                owner.node_addr(),
                crate::protocol::SessionMessageType::EndpointData.to_byte(),
                11,
                sync(1, 11),
                Some(ActivityTick::new(110)),
                std::time::Instant::now(),
                ),
            )
            .is_some());
        let activity = mover.owner_fsp_activity(owner).unwrap();
        assert_eq!(activity.last_rx_data_age_ms(115), Some(5));
        assert!(!activity.has_recent_outbound_without_inbound(115, 20));
        assert_eq!(mover.record_fsp_decrypt_failure(owner), Some(1));

        assert!(mover
            .record_authenticated_fsp_session(
                DataplaneAuthenticatedFspSession::new(
                owner.node_addr(),
                next_hop.node_addr(),
                crate::protocol::SessionMessageType::EndpointData.to_byte(),
                13,
                sync(2, 13),
                Some(ActivityTick::new(120)),
                std::time::Instant::now(),
                ),
            )
            .is_some());
        let activity = mover.owner_fsp_activity(owner).unwrap();
        assert_eq!(activity.last_rx_age_ms(125), Some(5));
        assert_eq!(activity.last_rx_data_age_ms(125), Some(5));
        assert_eq!(
            mover.min_fsp_rx_age_for_next_hop(&next_hop.node_addr(), 125),
            Some(5),
            "authenticated FSP via the previous hop must refresh that hop's link liveness"
        );
        assert_eq!(
            mover.min_fsp_data_rx_age_for_next_hop(&next_hop.node_addr(), 125),
            Some(5),
            "endpoint data via the previous hop keeps payload trust fresh"
        );

        let other_previous_hop = test_node_addr(179);
        assert!(mover
            .record_authenticated_fsp_session(
                DataplaneAuthenticatedFspSession::new(
                owner.node_addr(),
                other_previous_hop,
                crate::protocol::SessionMessageType::SenderReport.to_byte(),
                17,
                sync(3, 17),
                Some(ActivityTick::new(130)),
                std::time::Instant::now(),
                ),
            )
            .is_some());
        let activity = mover.owner_fsp_activity(owner).unwrap();
        assert_eq!(activity.last_rx_age_ms(135), Some(5));
        assert_eq!(activity.last_rx_data_age_ms(135), Some(15));
        assert_eq!(
            mover.min_fsp_rx_age_for_next_hop(&other_previous_hop, 135),
            Some(5),
            "control/session FSP activity should still prove previous-hop liveness"
        );
        assert_eq!(
            mover.min_fsp_data_rx_age_for_next_hop(&other_previous_hop, 135),
            None,
            "control/session FSP activity must not masquerade as endpoint-data freshness"
        );
    }

    #[test]
    fn fsp_owner_owns_session_mmp_reports() {
        let owner = fsp_owner(80);
        let mut mover = mover();
        mover.register_owner(
            owner,
            OwnerConfig::new(1, 8)
                .with_fsp_session_start_ms(1_000)
                .with_fsp_send_headers(0, 0)
                .with_fsp_mmp(crate::config::SessionMmpConfig::default(), true)
                .with_next_send_counter(20),
        );
        mover
            .owner_mut(owner)
            .unwrap()
            .set_crypto_keys(OwnerCryptoKeys::new(test_key(80), test_key(81)));

        let outbound = OutboundPacket::fsp(owner, 1, PacketClass::Mmp, 0, PacketBuffer::new(b"sender".to_vec()))
            .with_fsp_inner_header(crate::protocol::SessionMessageType::SenderReport.to_byte(), 0)
            .with_activity_tick(ActivityTick::new(1_020));
        mover.submit_outbound_packet(outbound).unwrap();
        assert_eq!(dispatch_outbound_available(&mut mover, 8).len(), 1);

        let sync = FspReceiveSync {
            counter: 9,
            received_k_bit: false,
            timestamp: 7,
            plaintext_len: FSP_INNER_HEADER_SIZE + 5,
            ce_flag: false,
            path_mtu: 1234,
            spin_bit: false,
        };
        assert_eq!(
            mover.record_authenticated_fsp_session(
                DataplaneAuthenticatedFspSession::new(
                owner.node_addr(),
                owner.node_addr(),
                crate::protocol::SessionMessageType::EndpointData.to_byte(),
                5,
                sync,
                Some(ActivityTick::new(1_030)),
                std::time::Instant::now(),
                ),
            ),
            Some(true)
        );

        let batch = mover.collect_fsp_mmp_reports(std::time::Instant::now());
        assert!(
            batch.reports.iter().any(|report| {
                report.dest_addr == owner.node_addr()
                    && report.msg_type == crate::protocol::SessionMessageType::SenderReport.to_byte()
            }),
            "owner should emit session SenderReport from reserved FSP sends"
        );
        assert!(
            batch.reports.iter().any(|report| {
                report.dest_addr == owner.node_addr()
                    && report.msg_type
                        == crate::protocol::SessionMessageType::ReceiverReport.to_byte()
            }),
            "owner should emit session ReceiverReport from authenticated FSP receives"
        );
        assert!(
            batch.reports.iter().any(|report| {
                report.dest_addr == owner.node_addr()
                    && report.msg_type
                        == crate::protocol::SessionMessageType::PathMtuNotification.to_byte()
            }),
            "owner should emit path-MTU notifications from authenticated FSP receives"
        );
        assert_eq!(batch.metric_logs.len(), 1);
        assert_eq!(batch.metric_logs[0].dest_addr, owner.node_addr());
        assert_eq!(batch.metric_logs[0].send_mtu, u16::MAX);
        assert_eq!(batch.metric_logs[0].observed_mtu, 1234);
        assert_eq!(batch.metric_logs[0].tx_packets, 1);
        assert_eq!(batch.metric_logs[0].rx_packets, 1);
    }

    #[test]
    fn fsp_owner_current_epoch_confirmation_is_one_shot_per_generation() {
        let owner = fsp_owner(84);
        let mut mover = mover();
        mover.register_owner(
            owner,
            OwnerConfig::new(1, 8)
                .with_fsp_session_start_ms(1_000)
                .with_fsp_send_headers(0, 0),
        );
        let sync = FspReceiveSync {
            counter: 1,
            received_k_bit: false,
            timestamp: 10,
            plaintext_len: FSP_INNER_HEADER_SIZE,
            ce_flag: false,
            path_mtu: u16::MAX,
            spin_bit: false,
        };

        assert_eq!(
            mover.record_authenticated_fsp_session(
                DataplaneAuthenticatedFspSession::new(
                owner.node_addr(),
                owner.node_addr(),
                crate::protocol::SessionMessageType::EndpointData.to_byte(),
                0,
                sync,
                Some(ActivityTick::new(1_010)),
                std::time::Instant::now(),
                ),
            ),
            Some(true)
        );
        assert_eq!(
            mover.record_authenticated_fsp_session(
                DataplaneAuthenticatedFspSession::new(
                owner.node_addr(),
                owner.node_addr(),
                crate::protocol::SessionMessageType::EndpointData.to_byte(),
                0,
                FspReceiveSync { counter: 2, ..sync },
                Some(ActivityTick::new(1_020)),
                std::time::Instant::now(),
                ),
            ),
            Some(false)
        );

        mover.owner_mut(owner).unwrap().rekey(2);
        assert_eq!(
            mover.record_authenticated_fsp_session(
                DataplaneAuthenticatedFspSession::new(
                owner.node_addr(),
                owner.node_addr(),
                crate::protocol::SessionMessageType::EndpointData.to_byte(),
                0,
                FspReceiveSync { counter: 3, ..sync },
                Some(ActivityTick::new(1_030)),
                std::time::Instant::now(),
                ),
            ),
            Some(true)
        );
    }

    #[test]
    fn fsp_owner_keeps_previous_receive_epoch_during_rekey_drain() {
        let owner = fsp_owner(85);
        let old_key = 85;
        let new_key = 86;
        let mut mover = mover();
        mover.register_owner(
            owner,
            OwnerConfig::new(1, 8)
                .with_fsp_session_start_ms(1_000)
                .with_fsp_send_headers(0, 0)
                .with_fsp_epoch(false, None),
        );
        mover
            .owner_mut(owner)
            .unwrap()
            .set_crypto_keys(OwnerCryptoKeys::new(test_key(old_key), test_key(old_key)));

        mover
            .submit_socket_packet(SocketPacket::new(
                owner,
                1,
                10,
                PacketClass::Bulk,
                OutputTarget::Transport,
                PacketBuffer::new(fsp_encrypted_wire(10, 0, b"old-before", old_key)),
            ))
            .unwrap();
        let turn = run_aead_available(&mut mover, 8);
        assert!(turn.drops().is_empty());
        assert_eq!(
            &turn.outputs()[0].payload.as_slice()[FSP_HEADER_SIZE..],
            b"old-before"
        );

        assert!(mover.owner_mut(owner).unwrap().install_fsp_session(
            OwnerConfig::new(2, 8)
                .with_fsp_session_start_ms(2_000)
                .with_fsp_send_headers(crate::node::session_wire::FSP_FLAG_K, 0)
                .with_fsp_epoch(true, Some(false)),
            OwnerCryptoKeys::new(test_key(new_key), test_key(new_key)),
        ));

        mover
            .submit_socket_packet(SocketPacket::new(
                owner,
                2,
                11,
                PacketClass::Bulk,
                OutputTarget::Transport,
                PacketBuffer::new(fsp_encrypted_wire(11, 0, b"old-after", old_key)),
            ))
            .unwrap();
        let current_epoch_packet = SocketPacket::new(
            owner,
            2,
            1,
            PacketClass::Bulk,
            OutputTarget::Transport,
            PacketBuffer::new(fsp_encrypted_wire(
                1,
                crate::node::session_wire::FSP_FLAG_K,
                b"new-after",
                new_key,
            )),
        )
        .with_wire_flags(crate::node::session_wire::FSP_FLAG_K);
        mover
            .submit_socket_packet(current_epoch_packet)
            .unwrap();

        let turn = run_aead_available(&mut mover, 8);
        assert!(turn.drops().is_empty(), "{:?}", turn.drops());
        let outputs = turn.outputs();
        assert_eq!(outputs.len(), 2);
        assert_eq!(&outputs[0].payload.as_slice()[FSP_HEADER_SIZE..], b"old-after");
        assert_eq!(&outputs[1].payload.as_slice()[FSP_HEADER_SIZE..], b"new-after");
    }

    #[test]
    fn fsp_owner_authenticates_pending_receive_epoch_before_cutover() {
        let owner = fsp_owner(86);
        let old_key = 86;
        let new_key = 87;
        let mut mover = mover();
        mover.register_owner(
            owner,
            OwnerConfig::new(1, 8)
                .with_fsp_session_start_ms(1_000)
                .with_fsp_send_headers(0, 0)
                .with_fsp_epoch(false, None),
        );
        mover
            .owner_mut(owner)
            .unwrap()
            .set_crypto_keys(OwnerCryptoKeys::new(test_key(old_key), test_key(old_key)));
        assert!(mover
            .owner_mut(owner)
            .unwrap()
            .install_fsp_pending_receive_epoch(true, test_key(new_key)));

        mover
            .submit_socket_packet(
                SocketPacket::new(
                    owner,
                    1,
                    1,
                    PacketClass::Bulk,
                    OutputTarget::Transport,
                    PacketBuffer::new(fsp_encrypted_wire(
                        1,
                        crate::node::session_wire::FSP_FLAG_K,
                        b"pending-new",
                        new_key,
                    )),
                )
                .with_wire_flags(crate::node::session_wire::FSP_FLAG_K),
            )
            .unwrap();
        let turn = run_aead_available(&mut mover, 8);
        assert!(turn.drops().is_empty(), "{:?}", turn.drops());
        assert_eq!(
            &turn.outputs()[0].payload.as_slice()[FSP_HEADER_SIZE..],
            b"pending-new"
        );

        assert!(mover.owner_mut(owner).unwrap().install_fsp_session(
            OwnerConfig::new(2, 8)
                .with_fsp_session_start_ms(2_000)
                .with_fsp_send_headers(crate::node::session_wire::FSP_FLAG_K, 0)
                .with_fsp_epoch(true, Some(false)),
            OwnerCryptoKeys::new(test_key(new_key), test_key(new_key)),
        ));
        mover
            .submit_socket_packet(
                SocketPacket::new(
                    owner,
                    2,
                    1,
                    PacketClass::Bulk,
                    OutputTarget::Transport,
                    PacketBuffer::new(fsp_encrypted_wire(
                        1,
                        crate::node::session_wire::FSP_FLAG_K,
                        b"replay",
                        new_key,
                    )),
                )
                .with_wire_flags(crate::node::session_wire::FSP_FLAG_K),
            )
            .unwrap();
        let turn = run_aead_available(&mut mover, 8);
        assert!(turn
            .drops()
            .iter()
            .any(|drop| drop.reason == PacketDropReason::Replay && drop.counter == Some(1)));
    }

    #[test]
    fn fmp_owner_authenticates_pending_receive_epoch_before_cutover() {
        let owner = fmp_owner(96);
        let old_key = 96;
        let new_key = 97;
        let receiver_idx = 0x96;
        let mut mover = mover();
        mover.register_owner(
            owner,
            OwnerConfig::new(1, 8)
                .with_fmp_session_start_ms(1_000)
                .with_fmp_send_headers(receiver_idx, 0)
                .with_fmp_epoch(false, None),
        );
        mover
            .owner_mut(owner)
            .unwrap()
            .set_crypto_keys(OwnerCryptoKeys::new(test_key(old_key), test_key(old_key)));
        assert!(mover
            .owner_mut(owner)
            .unwrap()
            .install_fmp_pending_receive_epoch(true, test_key(new_key)));

        let pending_flags = crate::node::wire::FLAG_KEY_EPOCH;
        mover
            .submit_socket_packet(
                fmp_socket_packet(
                    owner,
                    1,
                    OutputTarget::Transport,
                    fmp_encrypted_wire(
                        receiver_idx,
                        1,
                        pending_flags,
                        b"pending-new",
                        new_key,
                    ),
                )
                .unwrap(),
            )
            .unwrap();
        let turn = run_aead_available(&mut mover, 8);
        assert!(turn.drops().is_empty(), "{:?}", turn.drops());
        assert_eq!(
            &turn.outputs()[0].payload.as_slice()[FMP_ESTABLISHED_HEADER_SIZE..],
            b"pending-new"
        );

        assert!(mover.owner_mut(owner).unwrap().install_fmp_session(
            OwnerConfig::new(2, 8)
                .with_fmp_session_start_ms(2_000)
                .with_fmp_send_headers(receiver_idx, pending_flags)
                .with_fmp_epoch(true, Some(false)),
            OwnerCryptoKeys::new(test_key(new_key), test_key(new_key)),
        ));
        mover
            .submit_socket_packet(
                fmp_socket_packet(
                    owner,
                    2,
                    OutputTarget::Transport,
                    fmp_encrypted_wire(receiver_idx, 1, pending_flags, b"replay", new_key),
                )
                .unwrap(),
            )
            .unwrap();
        let turn = run_aead_available(&mut mover, 8);
        assert!(turn
            .drops()
            .iter()
            .any(|drop| drop.reason == PacketDropReason::Replay && drop.counter == Some(1)));
    }

    #[test]
    fn fsp_owner_owns_session_receiver_reports_and_path_mtu_signals() {
        let owner = fsp_owner(81);
        let mut mover = mover();
        mover.register_owner(
            owner,
            OwnerConfig::new(1, 8)
                .with_fsp_session_start_ms(1_000)
                .with_fsp_send_headers(0, 0)
                .with_fsp_mmp(crate::config::SessionMmpConfig::default(), true),
        );

        let sync = FspReceiveSync {
            counter: 40,
            received_k_bit: false,
            timestamp: 10,
            plaintext_len: FSP_INNER_HEADER_SIZE + 1200,
            ce_flag: false,
            path_mtu: u16::MAX,
            spin_bit: false,
        };
        assert_eq!(
            mover.record_authenticated_fsp_session(
                DataplaneAuthenticatedFspSession::new(
                owner.node_addr(),
                owner.node_addr(),
                crate::protocol::SessionMessageType::EndpointData.to_byte(),
                1200,
                sync,
                Some(ActivityTick::new(1_040)),
                std::time::Instant::now(),
                ),
            ),
            Some(true)
        );

        let rr = crate::mmp::report::ReceiverReport {
            highest_counter: 100,
            cumulative_packets_recv: 100,
            cumulative_bytes_recv: 10_000,
            timestamp_echo: 50,
            dwell_time: 0,
            max_burst_loss: 0,
            mean_burst_loss: 0,
            jitter: 0,
            ecn_ce_count: 0,
            owd_trend: 0,
            burst_loss_count: 0,
            cumulative_reorder_count: 0,
            interval_packets_recv: 0,
            interval_bytes_recv: 0,
        };
        let report = mover
            .process_fsp_mmp_receiver_report(
                owner,
                &rr,
                Some(owner.node_addr()),
                1_100,
                std::time::Instant::now(),
                128,
            )
            .expect("owner should process session receiver report");
        assert!(report.used_direct_next_hop);
        assert_eq!(report.mode, crate::mmp::MmpMode::Full);

        assert_eq!(mover.seed_fsp_path_mtu(owner, 1400), Ok(()));
        assert_eq!(
            mover.owner_fsp_activity(owner).unwrap().current_path_mtu(),
            Some(1400)
        );
        assert_eq!(
            mover.apply_fsp_path_mtu_signal(owner, 1280, std::time::Instant::now()),
            Ok(DataplaneFspPathMtuApplyResult::Changed(
                DataplaneFspPathMtuChange {
                    old_mtu: 1400,
                    new_mtu: 1280
                }
            ))
        );
        assert_eq!(
            mover.owner_fsp_activity(owner).unwrap().current_path_mtu(),
            Some(1280)
        );
        assert_eq!(
            mover.apply_fsp_path_mtu_signal(owner, 1400, std::time::Instant::now()),
            Ok(DataplaneFspPathMtuApplyResult::Unchanged)
        );
    }

    #[test]
    fn runtime_turn_driver_runs_classified_inbound_and_outbound_once() {
        let owner = fmp_owner(78);
        let open_key = 31;
        let seal_key = 32;
        let path = live_path(7800);
        let mut driver = DataplaneTurnDriver::new(AdmissionConfig::new(4, 8));
        driver.register_owner(owner, OwnerConfig::new(1, 8).with_next_send_counter(300));
        driver
            .owner_mut(owner)
            .unwrap()
            .set_crypto_keys(OwnerCryptoKeys::new(test_key(open_key), test_key(seal_key)));

        let inbound = fmp_socket_packet(
            owner,
            1,
            OutputTarget::Transport,
            fmp_encrypted_wire(78, 100, 0, b"inbound", open_key),
        )
        .unwrap()
        .with_source_path(path.clone())
        .with_activity_tick(ActivityTick::new(10));
        let outbound = OutboundPacket::fmp(
            owner,
            1,
            PacketClass::Liveness,
            780,
            0,
            PacketBuffer::new(b"outbound".to_vec()),
        )
        .with_activity_tick(ActivityTick::new(11));

        let turn = run_aead_classified_turn(&mut driver, [inbound], [outbound], 8);
        assert_eq!(
            turn.summary(),
            DataplaneRuntimeSummary {
                raw_ingress_dropped: 0,
                inbound_admitted: 1,
                inbound_dropped: 0,
                outbound_admitted: 1,
                outbound_dropped: 0,
                completions: 2,
                dispatched: 2,
                outputs: 2,
                outputs_sent: 0,
                outputs_dropped: 0,
                drops: 0,
            }
        );
        assert!(turn.drops().is_empty());

        let outputs = turn.outputs();
        assert_eq!(outputs[0].target, OutputTarget::Transport);
        assert_eq!(outputs[0].counter, 100);
        assert_eq!(
            &outputs[0].payload.as_slice()[FMP_ESTABLISHED_HEADER_SIZE..],
            b"inbound"
        );
        assert_eq!(outputs[0].path.clone(), None);

        assert_eq!(outputs[1].target, OutputTarget::Transport);
        assert_eq!(outputs[1].counter, 300);
        assert_eq!(outputs[1].path.clone(), Some(path.clone()));
        assert_eq!(open_sealed_output(&outputs[1], seal_key), b"outbound");

        let owner_state = driver.owner_mut(owner).unwrap();
        assert_eq!(owner_state.active_path(), Some(path));
        assert_eq!(owner_state.last_rx_activity(), Some(ActivityTick::new(10)));
        assert_eq!(owner_state.last_tx_activity(), Some(ActivityTick::new(11)));
    }

    #[test]
    fn completion_only_turn_retires_worker_completion_without_new_dispatch() {
        let owner = fmp_owner(80);
        let open_key = 80;
        let mut driver = DataplaneTurnDriver::new(AdmissionConfig::new(4, 8));
        driver.register_owner(owner, OwnerConfig::new(1, 8));

        driver
            .mover
            .submit_socket_packet(
                fmp_socket_packet(
                    owner,
                    1,
                    OutputTarget::Transport,
                    fmp_encrypted_wire(80, 100, 0, b"completion-only", open_key),
                )
                .unwrap(),
            )
            .unwrap();

        let mut work = dispatch_available(&mut driver.mover, 8);
        assert_eq!(work.len(), 1);
        assert_eq!(driver.owner_mut(owner).unwrap().in_flight, 1);

        let completion = complete_test_open_work(work.pop().unwrap(), open_key);

        {
            let turn = run_aead_completion_turn(&mut driver, [completion], 8);
            assert_eq!(
                turn.summary(),
                DataplaneRuntimeSummary {
                    raw_ingress_dropped: 0,
                    inbound_admitted: 0,
                    inbound_dropped: 0,
                    outbound_admitted: 0,
                    outbound_dropped: 0,
                    completions: 1,
                    dispatched: 0,
                    outputs: 1,
                    outputs_sent: 0,
                    outputs_dropped: 0,
                    drops: 0,
                }
            );
            assert!(turn.drops().is_empty());
            assert_eq!(turn.outputs().len(), 1);
            assert_eq!(turn.outputs()[0].owner(), owner);
            assert_eq!(turn.outputs()[0].counter(), 100);
            assert_eq!(turn.outputs()[0].target(), OutputTarget::Transport);
            assert_eq!(
                &turn.outputs()[0].payload()[FMP_ESTABLISHED_HEADER_SIZE..],
                b"completion-only"
            );
        }

        assert_eq!(driver.owner_mut(owner).unwrap().in_flight, 0);
    }

    #[test]
    fn completion_source_pump_reports_completion_activity_before_output_is_ready() {
        let owner = fmp_owner(84);
        let open_key = 84;
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
                        fmp_encrypted_wire(84, counter, 0, payload, open_key),
                    )
                    .unwrap(),
                )
                .unwrap();
        }

        let mut work = dispatch_available(&mut driver.mover, 8);
        assert_eq!(work.len(), 3);

        let mut completions = work
            .drain(..)
            .map(|work| complete_test_open_work(work, open_key))
            .collect::<VecDeque<_>>();
        let third = completions.pop_back().unwrap();
        let first = completions.pop_front().unwrap();
        let second = completions.pop_front().unwrap();

        let mut raw_ingress = VecDeque::new();
        let mut outbound = VecDeque::new();
        let mut sink = BatchRecordingOutputSink::default();
        let mut completion_source = VecDeque::from([third]);

        {
            let turn = pump_aead_output_completion_turn(
                &mut driver,
                AeadOutputCompletionTurn {
                    completions: &mut completion_source,
                    completion_limit: 8,
                    raw_ingress: &mut raw_ingress,
                    router: &mut NullIngressRouter,
                    raw_ingress_limit: 0,
                    outbound: &mut outbound,
                    outbound_limit: 0,
                    sink: &mut sink,
                    crypto_limit: 8,
                },
            );
            assert_eq!(turn.summary().completions(), 1);
            assert_eq!(turn.summary().dispatched(), 0);
            assert_eq!(turn.summary().outputs(), 0);
            assert!(turn.summary().has_activity());
            assert!(turn.outputs().is_empty());
            assert!(turn.drops().is_empty());
        }
        assert!(completion_source.is_empty());
        assert!(sink.outputs.is_empty());
        assert_eq!(sink.batch_calls, 0);

        completion_source.extend([first, second]);
        {
            let turn = pump_aead_output_completion_turn(
                &mut driver,
                AeadOutputCompletionTurn {
                    completions: &mut completion_source,
                    completion_limit: 8,
                    raw_ingress: &mut raw_ingress,
                    router: &mut NullIngressRouter,
                    raw_ingress_limit: 0,
                    outbound: &mut outbound,
                    outbound_limit: 0,
                    sink: &mut sink,
                    crypto_limit: 8,
                },
            );
            assert_eq!(turn.summary().completions(), 2);
            assert_eq!(turn.summary().outputs(), 3);
            assert_eq!(turn.summary().outputs_sent(), 3);
            assert!(turn.outputs().is_empty());
            assert!(turn.drops().is_empty());
        }

        assert!(completion_source.is_empty());
        assert_eq!(sink.batch_calls, 1);
        assert_eq!(sink.outputs.len(), 3);
        assert_eq!(sink.outputs[0].counter(), 100);
        assert_eq!(sink.outputs[1].counter(), 101);
        assert_eq!(sink.outputs[2].counter(), 102);
        assert_eq!(
            &sink.outputs[0].payload()[FMP_ESTABLISHED_HEADER_SIZE..],
            b"first"
        );
        assert_eq!(
            &sink.outputs[1].payload()[FMP_ESTABLISHED_HEADER_SIZE..],
            b"second"
        );
        assert_eq!(
            &sink.outputs[2].payload()[FMP_ESTABLISHED_HEADER_SIZE..],
            b"third"
        );
        assert_eq!(driver.owner_mut(owner).unwrap().in_flight, 0);
    }

    #[test]
    fn endpoint_data_route_builds_endpoint_data_records() {
        let owner = fsp_owner(914);
        let route = DataplaneEndpointDataRoute::fsp(owner, 1, 0, 0);
        let route_result = route_endpoint_payloads(&route, vec![
            b"first".to_vec(),
            b"second".to_vec(),
            b"third".to_vec(),
        ]);

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
        for (packet, expected) in route_result
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
        let source_peer =
            PeerIdentity::from_pubkey_full(crate::Identity::generate().pubkey_full());
        let source_addr = *source_peer.node_addr();
        let owner = OwnerId::fsp_node(source_addr);
        let previous_hop = test_node_addr(917);
        let local_addr = test_node_addr(918);
        let key = 0x93;
        let mut driver = DataplaneTurnDriver::new(AdmissionConfig::new(4, 8));
        driver.register_owner(
            owner,
            OwnerConfig::new(1, 8).with_source_peer(source_peer),
        );
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
        assert!(crate::upper::ipv6_shim::compress_ipv6_with_port_header_in_place(
            &mut ipv6,
            crate::node::session_wire::FSP_PORT_IPV6_SHIM,
            crate::node::session_wire::FSP_PORT_IPV6_SHIM,
        ));
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

        for (idx, inner) in [endpoint_inner, tun_inner, report_inner].into_iter().enumerate() {
            driver
                .mover
                .submit_socket_packet(
                    SocketPacket::new(
                        owner,
                        1,
                        917 + idx as u64,
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
        let source_peer =
            PeerIdentity::from_pubkey_full(crate::Identity::generate().pubkey_full());
        let source_addr = *source_peer.node_addr();
        let owner = OwnerId::fsp_node(source_addr);
        let previous_hop = test_node_addr(915);
        let local_addr = test_node_addr(916);
        let key = 0x91;
        let mut driver = DataplaneTurnDriver::new(AdmissionConfig::new(4, 8));
        driver.register_owner(
            owner,
            OwnerConfig::new(1, 8).with_source_peer(source_peer),
        );
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
        let datagram = crate::protocol::SessionDatagram::new(
            source_addr,
            local_addr,
            fsp_wire.clone(),
        )
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
        let (raw, retry_count) = deferred_raw_ingress
            .pop_front()
            .expect("unrouted sourced FSP packet should defer");
        assert!(deferred_raw_ingress.is_empty());
        assert_eq!(retry_count, 2);
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
        let source_peer =
            PeerIdentity::from_pubkey_full(crate::Identity::generate().pubkey_full());
        let source_addr = *source_peer.node_addr();
        let owner = OwnerId::fsp_node(source_addr);
        let previous_hop = test_node_addr(916);
        let local_addr = test_node_addr(917);
        let key = 0x92;
        let mut driver = DataplaneTurnDriver::new(AdmissionConfig::new(4, 8));
        driver.register_owner(
            owner,
            OwnerConfig::new(1, 8).with_source_peer(source_peer),
        );
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
        assert_eq!(endpoint_batch_direct_packet_count(endpoint_batches[0]), 2);

        let delivered = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let captured = std::sync::Arc::clone(&delivered);
        let direct_sink = EndpointDirectSink::new(move |batch: crate::FipsEndpointDirectPacketBatch| {
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
        assert_eq!(endpoint_batch_direct_packet_count(endpoint_batches[0]), 0);
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
        let source_peer =
            PeerIdentity::from_pubkey_full(crate::Identity::generate().pubkey_full());
        let source_addr = *source_peer.node_addr();
        let owner = OwnerId::fsp_node(source_addr);
        let previous_hop = test_node_addr(917);
        let local_addr = test_node_addr(918);
        let key = 0x93;
        let mut driver = DataplaneTurnDriver::new(AdmissionConfig::new(4, 8));
        driver.register_owner(
            owner,
            OwnerConfig::new(1, 8).with_source_peer(source_peer),
        );
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
        assert_eq!(endpoint_batch_direct_packet_count(endpoint_batches[0]), 5);
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
    fn owner_retire_consumes_contiguous_completion_batch_without_pending_map() {
        let owner = fmp_owner(811);
        let open_key = 81;
        let mut mover = mover();
        register_owner_with_test_keys(&mut mover, owner, open_key, open_key);
        submit_fmp_inbound_range(&mut mover, owner, 811, open_key, 100..104, b"run");

        let mut completions = dispatch_available(&mut mover, 8)
            .drain(..)
            .map(|work| complete_test_open_work(work, open_key))
            .collect::<Vec<_>>();
        assert_eq!(completions.len(), 4);

        let mut batches = Vec::new();
        assert_eq!(
            CryptoCompletionBatch::drain_completion_vec_into_batches(
                &mut completions,
                &mut batches,
            ),
            4
        );
        assert_eq!(batches.len(), 1);

        let mut retired = Vec::new();
        mover.queue_completion_batches(&mut batches);
        assert_eq!(
            retire_queued_completions_to_outputs(&mut mover, 4, &mut retired),
            4
        );
        let outputs = retired;
        assert_eq!(
            outputs.iter().map(PacketOutput::counter).collect::<Vec<_>>(),
            vec![100, 101, 102, 103]
        );
        let owner_state = mover.owner_mut(owner).unwrap();
        assert!(owner_state.pending.is_empty());
        assert_eq!(owner_state.next_retire, 4);
        assert_eq!(owner_state.in_flight, 0);
    }

    #[test]
    fn owner_retire_stages_only_gap_then_releases_from_next_contiguous_batch() {
        let owner = fmp_owner(812);
        let open_key = 82;
        let mut mover = mover();
        register_owner_with_test_keys(&mut mover, owner, open_key, open_key);
        submit_fmp_inbound_range(&mut mover, owner, 812, open_key, 100..103, b"gap");

        let mut completions = dispatch_available(&mut mover, 8)
            .drain(..)
            .map(|work| complete_test_open_work(work, open_key))
            .collect::<Vec<_>>();
        assert_eq!(completions.len(), 3);
        let third = completions.pop().unwrap();

        let mut batches = vec![CryptoCompletionBatch::from_completion(third)];
        let mut retired = Vec::new();
        mover.queue_completion_batches(&mut batches);
        assert_eq!(
            retire_queued_completions_to_outputs(&mut mover, 3, &mut retired),
            1
        );
        assert!(retired.is_empty());
        {
            let owner_state = mover.owner_mut(owner).unwrap();
            assert_eq!(owner_state.pending.len(), 1);
            assert_eq!(owner_state.next_retire, 0);
            assert_eq!(owner_state.in_flight, 3);
        }

        let mut batches = Vec::new();
        assert_eq!(
            CryptoCompletionBatch::drain_completion_vec_into_batches(
                &mut completions,
                &mut batches,
            ),
            2
        );
        assert_eq!(batches.len(), 1);
        let mut retired = Vec::new();
        mover.queue_completion_batches(&mut batches);
        assert_eq!(
            retire_queued_completions_to_outputs(&mut mover, 3, &mut retired),
            2
        );
        let outputs = retired;
        assert_eq!(
            outputs.iter().map(PacketOutput::counter).collect::<Vec<_>>(),
            vec![100, 101, 102]
        );
        let owner_state = mover.owner_mut(owner).unwrap();
        assert!(owner_state.pending.is_empty());
        assert_eq!(owner_state.next_retire, 3);
        assert_eq!(owner_state.in_flight, 0);
    }

    #[test]
    fn owner_retire_stages_later_contiguous_batch_as_one_pending_run() {
        let owner = fmp_owner(813);
        let open_key = 83;
        let mut mover = mover();
        register_owner_with_test_keys(&mut mover, owner, open_key, open_key);
        submit_fmp_inbound_range(&mut mover, owner, 813, open_key, 100..106, b"pending-run");

        let completions = dispatch_available(&mut mover, 8)
            .drain(..)
            .map(|work| complete_test_open_work(work, open_key))
            .collect::<Vec<_>>();
        assert_eq!(completions.len(), 6);

        let mut later = completions[2..].to_vec();
        let mut later_batches = Vec::new();
        assert_eq!(
            CryptoCompletionBatch::drain_completion_vec_into_batches(
                &mut later,
                &mut later_batches,
            ),
            4
        );
        assert_eq!(later_batches.len(), 1);
        assert_eq!(later_batches[0].first_order(), Some(OrderToken(2)));

        let mut retired = Vec::new();
        mover.queue_completion_batches(&mut later_batches);
        assert_eq!(
            retire_queued_completions_to_outputs(&mut mover, 6, &mut retired),
            4
        );
        assert!(retired.is_empty());
        {
            let owner_state = mover.owner_mut(owner).unwrap();
            assert_eq!(owner_state.pending.len(), 1);
            assert_eq!(
                owner_state
                    .pending
                    .get(&OrderToken(2))
                    .map(CryptoCompletionBatch::len),
                Some(4)
            );
            assert_eq!(owner_state.next_retire, 0);
            assert_eq!(owner_state.in_flight, 6);
        }

        let mut earlier = completions[..2].to_vec();
        let mut earlier_batches = Vec::new();
        assert_eq!(
            CryptoCompletionBatch::drain_completion_vec_into_batches(
                &mut earlier,
                &mut earlier_batches,
            ),
            2
        );
        assert_eq!(earlier_batches.len(), 1);
        assert_eq!(earlier_batches[0].first_order(), Some(OrderToken(0)));

        let mut retired = Vec::new();
        mover.queue_completion_batches(&mut earlier_batches);
        assert_eq!(
            retire_queued_completions_to_outputs(&mut mover, 6, &mut retired),
            2
        );
        let outputs = retired;
        assert_eq!(
            outputs.iter().map(PacketOutput::counter).collect::<Vec<_>>(),
            vec![100, 101, 102, 103, 104, 105]
        );
        let owner_state = mover.owner_mut(owner).unwrap();
        assert!(owner_state.pending.is_empty());
        assert_eq!(owner_state.next_retire, 6);
        assert_eq!(owner_state.in_flight, 0);
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
        driver.register_owner(
            owner,
            OwnerConfig::new(1, 3).with_next_send_counter(10),
        );
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

    #[test]
    fn wrapped_fsp_completion_refreshes_fmp_send_context_after_rekey() {
        let source = NodeAddr::from_bytes([0x90; 16]);
        let dest = NodeAddr::from_bytes([0x91; 16]);
        let next_hop = NodeAddr::from_bytes([0x92; 16]);
        let fsp_owner = OwnerId::fsp_node(dest);
        let fmp_owner = OwnerId::fmp_node(next_hop);
        let fsp_key = 91;
        let old_fmp_key = 92;
        let new_fmp_key = 93;
        let fmp_path = live_path(9200);
        let mut driver = DataplaneTurnDriver::new(AdmissionConfig::new(4, 8));
        driver.register_owner(fsp_owner, OwnerConfig::new(1, 8).with_next_send_counter(50));
        driver.register_owner(
            fmp_owner,
            OwnerConfig::new(1, 8)
                .with_next_send_counter(70)
                .with_fmp_send_headers(8282, 0),
        );
        driver
            .owner_mut(fsp_owner)
            .unwrap()
            .set_crypto_keys(OwnerCryptoKeys::new(test_key(fsp_key), test_key(fsp_key)));
        driver
            .owner_mut(fmp_owner)
            .unwrap()
            .set_crypto_keys(OwnerCryptoKeys::new(
                test_key(old_fmp_key),
                test_key(old_fmp_key),
            ));
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

        let completion = complete_test_seal_work(seal_work.pop().unwrap(), fsp_key);

        assert!(driver.owner_mut(fmp_owner).unwrap().install_fmp_session(
            OwnerConfig::new(2, 8)
                .with_next_send_counter(90)
                .with_fmp_send_headers(9292, crate::node::wire::FLAG_KEY_EPOCH),
            OwnerCryptoKeys::new(test_key(new_fmp_key), test_key(new_fmp_key)),
        ));
        driver
            .owner_mut(fmp_owner)
            .unwrap()
            .set_active_path(fmp_path.clone());

        let turn = run_aead_completion_turn(&mut driver, [completion], 1);
        assert_eq!(turn.summary().outbound_admitted(), 1);
        assert_eq!(turn.summary().dispatched(), 1);
        assert_eq!(turn.summary().outputs(), 1);
        assert!(turn.drops().is_empty());

        let output = &turn.outputs()[0];
        assert_eq!(output.owner(), fmp_owner);
        assert_eq!(output.counter(), 0);
        assert_eq!(output.path.clone(), Some(fmp_path));
        let header = FmpWireHeader::parse(output.payload()).unwrap();
        assert_eq!(header.receiver_idx(), 9292);
        assert_eq!(header.flags(), crate::node::wire::FLAG_KEY_EPOCH);

        let fmp_plaintext = open_sealed_output(output, new_fmp_key);
        let datagram = crate::protocol::SessionDatagramRef::decode(&fmp_plaintext[1..])
            .expect("wrapped session datagram");
        assert_eq!(
            open_fsp_wire_payload(datagram.payload, fsp_key),
            b"wake-wrap"
        );
        assert_eq!(driver.owner_mut(fsp_owner).unwrap().in_flight, 0);
        assert_eq!(driver.owner_mut(fmp_owner).unwrap().in_flight, 0);
    }

    #[test]
    fn failed_owner_routed_fsp_wrap_releases_inner_owner_only() {
        let source = NodeAddr::from_bytes([0x83; 16]);
        let dest = NodeAddr::from_bytes([0x84; 16]);
        let next_hop = NodeAddr::from_bytes([0x85; 16]);
        let fsp_owner = OwnerId::fsp_node(dest);
        let fmp_owner = OwnerId::fmp_node(next_hop);
        let fmp_path = live_path(8500);
        let mut driver = DataplaneTurnDriver::new(AdmissionConfig::new(4, 8));
        driver.register_owner(fsp_owner, OwnerConfig::new(1, 8).with_next_send_counter(50));
        driver.register_owner(fmp_owner, OwnerConfig::new(1, 8).with_next_send_counter(70));
        driver
            .owner_mut(fsp_owner)
            .unwrap()
            .set_crypto_keys(OwnerCryptoKeys::new(test_key(84), test_key(84)));
        driver
            .owner_mut(fmp_owner)
            .unwrap()
            .set_active_path(fmp_path);

        let wrap = DataplaneFspWrapRoute::new(fmp_owner, 1, 8585, source, dest)
            .with_ttl(42)
            .with_path_mtu(1280);
        driver
            .owner_mut(fsp_owner)
            .unwrap()
            .set_fsp_wrap_route(Some(wrap));
        let packet = OutboundPacket::fsp(
            fsp_owner,
            1,
            PacketClass::Bulk,
            0x03,
            PacketBuffer::new(b"failed-wrap".to_vec()),
        )
        .with_fsp_cleartext_prefix(empty_fsp_coords_prefix());

        driver.mover.submit_outbound_packet(packet).unwrap();
        let mut seal_work = dispatch_outbound_available(&mut driver.mover, 1);
        assert_eq!(seal_work.len(), 1);
        let work = seal_work.pop().unwrap();
        assert_eq!(driver.owner_mut(fsp_owner).unwrap().in_flight, 1);
        assert_eq!(driver.owner_mut(fmp_owner).unwrap().in_flight, 0);

        let completion = failed_crypto_completion(work.reservation, CryptoFailureKind::Seal);
        let turn = run_aead_completion_turn(&mut driver, [completion], 1);
        assert_eq!(turn.summary().completions(), 1);
        assert_eq!(turn.summary().outputs(), 0);
        assert_eq!(turn.drops().len(), 1);
        assert!(turn
            .drops()
            .iter()
            .all(|drop| drop.reason() == PacketDropReason::CryptoFailed));
        assert_eq!(driver.owner_mut(fsp_owner).unwrap().in_flight, 0);
        assert_eq!(driver.owner_mut(fmp_owner).unwrap().in_flight, 0);
    }

    #[test]
    fn runtime_turn_driver_reports_admission_and_crypto_drops() {
        let owner = fsp_owner(79);
        let mut driver = DataplaneTurnDriver::new(AdmissionConfig::new(1, 1));
        driver.register_owner(owner, OwnerConfig::new(1, 8));

        let first = fsp_socket_packet(
            owner,
            1,
            OutputTarget::Transport,
            fsp_encrypted_wire(10, 0, b"first", 40),
        )
        .unwrap();
        let second = fsp_socket_packet(
            owner,
            1,
            OutputTarget::Transport,
            fsp_encrypted_wire(11, 0, b"second", 40),
        )
        .unwrap();

        let turn = run_aead_classified_turn(&mut driver, [first, second], std::iter::empty(), 8);
        assert_eq!(turn.summary().inbound_admitted(), 1);
        assert_eq!(turn.summary().inbound_dropped(), 1);
        assert_eq!(turn.summary().outbound_admitted(), 0);
        assert_eq!(turn.summary().outbound_dropped(), 0);
        assert_eq!(turn.summary().dispatched(), 1);
        assert_eq!(turn.summary().outputs(), 0);
        assert_eq!(turn.summary().drops(), 2);
        assert!(turn.outputs().is_empty());

        let admission_drop = turn
            .drops()
            .iter()
            .find(|drop| {
                drop.reason() == PacketDropReason::Admission(AdmissionDropReason::BulkFull)
            })
            .expect("admission drop");
        assert_eq!(admission_drop.owner(), owner);
        assert_eq!(admission_drop.counter(), Some(11));

        let crypto_drop = turn
            .drops()
            .iter()
            .find(|drop| drop.reason() == PacketDropReason::CryptoFailed)
            .expect("crypto drop");
        assert_eq!(crypto_drop.owner(), owner);
        assert_eq!(crypto_drop.counter(), Some(10));
    }

    struct FixedIngressRouter {
        route: Option<DataplaneIngressRoute>,
    }

    impl DataplaneIngressRouter for FixedIngressRouter {
        fn route(
            &mut self,
            packet: &DataplaneRawIngress,
            header: DataplaneIngressHeader,
        ) -> Option<DataplaneIngressRoute> {
            assert_eq!(packet.transport_id, TransportId::new(5));
            assert_eq!(
                packet.remote_addr,
                TransportAddr::from_string("198.51.100.9:9000")
            );
            assert_eq!(packet.path, live_path(9005));
            assert_eq!(packet.activity_tick, Some(ActivityTick::new(123_456)));
            assert_eq!(
                packet.payload.len(),
                FMP_ESTABLISHED_HEADER_SIZE + b"raw-in".len() + AEAD_TAG_SIZE
            );
            assert_eq!(packet.protocol, PacketProtocol::Fmp);
            assert!(matches!(header, DataplaneIngressHeader::Fmp(_)));
            assert_eq!(header.counter(), 1200);
            self.route
        }
    }

    struct NullIngressRouter;

    impl DataplaneIngressRouter for NullIngressRouter {
        fn route(
            &mut self,
            _packet: &DataplaneRawIngress,
            _header: DataplaneIngressHeader,
        ) -> Option<DataplaneIngressRoute> {
            None
        }
    }

    #[derive(Default)]
    struct BatchRecordingOutputSink {
        batch_calls: usize,
        outputs: Vec<PacketOutput>,
    }

    impl DataplaneOutputSink for BatchRecordingOutputSink {
        fn send_batch<I>(&mut self, outputs: I, drops: &mut Vec<DataplaneOutputDrop>) -> usize
        where
            I: IntoIterator<Item = PacketOutput>,
        {
            self.batch_calls += 1;
            let drops_before = drops.len();
            let mut sent = 0;
            for output in outputs {
                assert_eq!(output.payload_len(), output.payload().len());
                self.outputs.push(output);
                sent += 1;
            }
            assert_eq!(drops.len(), drops_before);
            sent
        }
    }

    struct SimpleIngressRouter {
        owner: OwnerId,
        generation: u64,
        class: PacketClass,
        output: OutputTarget,
    }

    impl DataplaneIngressRouter for SimpleIngressRouter {
        fn route(
            &mut self,
            _packet: &DataplaneRawIngress,
            _header: DataplaneIngressHeader,
        ) -> Option<DataplaneIngressRoute> {
            Some(
                DataplaneIngressRoute::new(self.owner, self.generation, self.output)
                    .with_class(self.class),
            )
        }
    }
