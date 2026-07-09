    use super::*;
    use crate::PeerIdentity;
    use crate::transport::{ReceivedPacket, TransportAddr, TransportId};
    use ring::aead::UnboundKey;

    fn mover() -> Dataplane {
        Dataplane::new(AdmissionConfig::new(4, 8))
    }

    fn endpoint_payloads(payloads: Vec<Vec<u8>>) -> Vec<EndpointDataPayload> {
        payloads
            .into_iter()
            .map(|payload| {
                EndpointDataPayload::from_packet_payload(payload)
                    .expect("test endpoint payload should fit FSP endpoint data")
            })
            .collect()
    }

    fn route_endpoint_payloads(
        route: &DataplaneEndpointDataRoute,
        payloads: Vec<Vec<u8>>,
    ) -> DataplaneEndpointDataBatchRoute {
        route.route_payloads(
            endpoint_payloads(payloads),
            ActivityTick::new(crate::time::now_ms()),
        )
    }

    #[derive(Clone, Debug, Default, Eq, PartialEq)]
    struct DataplaneTurn {
        dispatched: usize,
        retired: Vec<PacketOutput>,
        drops: Vec<PacketDrop>,
    }

    impl DataplaneTurn {
        fn dispatched(&self) -> usize {
            self.dispatched
        }

        fn retired(&self) -> &[PacketOutput] {
            &self.retired
        }

        fn drops(&self) -> &[PacketDrop] {
            &self.drops
        }

        fn outputs(&self) -> Vec<&PacketOutput> {
            self.retired.iter().collect()
        }
    }

    #[derive(Debug, Default)]
    struct InlineDataplaneCryptoExecutor;

    impl DataplaneCryptoExecutor for InlineDataplaneCryptoExecutor {
        fn execute_prepared_chunk(
            &mut self,
            prepared: &mut Vec<PreparedCryptoWork>,
            completions: &mut Vec<CryptoCompletion>,
        ) -> usize {
            completions.clear();
            let count = prepared.len();
            for work in prepared.drain(..) {
                completions.push(work.execute());
            }
            count
        }
    }

    #[derive(Debug, Default)]
    struct CapturingPreparedCryptoExecutor {
        prepared: Vec<PreparedCryptoWork>,
    }

    impl DataplaneCryptoExecutor for CapturingPreparedCryptoExecutor {
        fn execute_prepared_chunk(
            &mut self,
            prepared: &mut Vec<PreparedCryptoWork>,
            completions: &mut Vec<CryptoCompletion>,
        ) -> usize {
            completions.clear();
            let count = prepared.len();
            self.prepared.append(prepared);
            count
        }
    }

    fn dispatch_available(mover: &mut Dataplane, limit: usize) -> Vec<CryptoWork> {
        capture_prepared_work(mover, limit)
            .into_iter()
            .map(|prepared| match prepared {
                PreparedCryptoWork::Open { work, .. } => work,
                PreparedCryptoWork::Seal { work, .. } => {
                    panic!("unexpected outbound work while capturing inbound: {work:?}")
                }
            })
            .collect()
    }

    fn dispatch_outbound_available(
        mover: &mut Dataplane,
        limit: usize,
    ) -> Vec<OutboundCryptoWork> {
        capture_prepared_work(mover, limit)
            .into_iter()
            .map(|prepared| match prepared {
                PreparedCryptoWork::Seal { work, .. } => work,
                PreparedCryptoWork::Open { work, .. } => {
                    panic!("unexpected inbound work while capturing outbound: {work:?}")
                }
            })
            .collect()
    }

    fn capture_prepared_work(mover: &mut Dataplane, limit: usize) -> Vec<PreparedCryptoWork> {
        seed_missing_test_owner_keys(mover);
        let mut prepared_work = Vec::new();
        let mut completion_work = Vec::new();
        let mut completion_batches = Vec::new();
        let mut retired = Vec::new();
        let mut outbound_packets = Vec::new();
        let mut fsp_authenticated_ingress = DataplaneFspAuthenticatedIngress::default();
        let mut drops = Vec::new();
        let mut executor = CapturingPreparedCryptoExecutor::default();
        mover.run_aead_available_into_with_executor(
            limit,
            DataplaneAeadRunBuffers::new(
                &mut prepared_work,
                &mut completion_work,
                &mut completion_batches,
                &mut retired,
                &mut outbound_packets,
                &mut fsp_authenticated_ingress,
                &mut drops,
            ),
            &mut executor,
            false,
        );
        debug_assert!(prepared_work.is_empty());
        debug_assert!(completion_work.is_empty());
        debug_assert!(retired.is_empty());
        assert!(outbound_packets.is_empty());
        assert!(fsp_authenticated_ingress.is_empty());
        for drop in drops {
            mover.record_drop(drop);
        }
        executor.prepared
    }

    fn seed_missing_test_owner_keys(mover: &mut Dataplane) {
        let key = test_key(0);
        for shard in &mut mover.shards {
            for owner in shard.owners.values_mut() {
                if owner.crypto_keys.is_none() {
                    owner.set_crypto_keys(OwnerCryptoKeys::new(key.clone(), key.clone()));
                }
            }
        }
    }

    impl DataplaneCompletionSource for VecDeque<CryptoCompletion> {
        fn drain_completion_batches_into_sink<S>(
            &mut self,
            limit: usize,
            sink: &mut S,
        ) -> usize
        where
            S: DataplaneCompletionSink,
        {
            let mut drained = 0;
            let mut completion_batches = Vec::new();
            while drained < limit {
                let Some(completion) = self.pop_front() else {
                    break;
                };
                CryptoCompletionBatch::push_grouped(completion, &mut completion_batches);
                drained += 1;
            }
            for batch in completion_batches {
                sink.push_completion_batch(batch);
            }
            drained
        }
    }

    fn run_aead_available(mover: &mut Dataplane, limit: usize) -> DataplaneTurn {
        let mut prepared_work = Vec::new();
        let mut completion_work = Vec::new();
        let mut completion_batches = Vec::new();
        let mut retired = Vec::new();
        let mut outbound_packets = Vec::new();
        let mut fsp_authenticated_ingress = DataplaneFspAuthenticatedIngress::default();
        let mut drops = Vec::new();
        let mut executor = InlineDataplaneCryptoExecutor;
        let dispatched = mover.run_aead_available_into_with_executor(
            limit,
            DataplaneAeadRunBuffers::new(
                &mut prepared_work,
                &mut completion_work,
                &mut completion_batches,
                &mut retired,
                &mut outbound_packets,
                &mut fsp_authenticated_ingress,
                &mut drops,
            ),
            &mut executor,
            false,
        );
        assert!(outbound_packets.is_empty());
        assert!(fsp_authenticated_ingress.is_empty());

        DataplaneTurn {
            dispatched,
            retired,
            drops,
        }
    }

    fn run_aead_completion_turn<I>(
        driver: &mut DataplaneTurnDriver,
        completions: I,
        limit: usize,
    ) -> DataplaneRuntimeTurn<'_>
    where
        I: IntoIterator<Item = CryptoCompletion>,
    {
        driver.reset_turn_buffers();

        driver.completion_work.clear();
        driver.completion_work.extend(completions);
        let queued = driver.completion_work.len();
        driver.completion_batches.clear();
        CryptoCompletionBatch::drain_completion_vec_into_batches(
            &mut driver.completion_work,
            &mut driver.completion_batches,
        );
        let mut summary = DataplaneRuntimeSummary::default();
        summary.completions = summary.completions.saturating_add(queued);
        driver
            .mover
            .queue_completion_batches(&mut driver.completion_batches);
        driver.retire_queued_completed_aead_outputs(queued, false);
        let summary = driver.admit_retired_outbound_packets(summary);
        let mut executor = InlineDataplaneCryptoExecutor;
        let summary =
            driver.collect_aead_outputs_with_executor(summary, limit, &mut executor, false);

        DataplaneRuntimeTurn {
            summary,
            raw_ingress_drops: &driver.raw_ingress_drops,
            output_drops: &driver.output_drops,
            outputs: &driver.outputs,
            drops: &driver.drops,
        }
    }

    async fn wait_for_live_worker_completion(live_node: &DataplaneLiveNode) {
        let notify = live_node.completion_notify();
        tokio::time::timeout(std::time::Duration::from_secs(1), notify.notified())
            .await
            .expect("live dataplane worker completion");
    }

    fn run_aead_classified_turn<I, O>(
        driver: &mut DataplaneTurnDriver,
        inbound: I,
        outbound: O,
        limit: usize,
    ) -> DataplaneRuntimeTurn<'_>
    where
        I: IntoIterator<Item = SocketPacket>,
        O: IntoIterator<Item = OutboundPacket>,
    {
        driver.reset_turn_buffers();

        let mut summary = DataplaneRuntimeSummary::default();
        for packet in inbound {
            driver.admit_socket_packet(packet, &mut summary);
        }
        for packet in outbound {
            driver.admit_outbound_packet(packet, &mut summary);
        }

        finish_aead_turn_with_inline(driver, summary, limit)
    }

    fn run_aead_classified_output_turn<'a, I, O, S>(
        driver: &'a mut DataplaneTurnDriver,
        inbound: I,
        outbound: O,
        sink: &mut S,
        limit: usize,
    ) -> DataplaneRuntimeTurn<'a>
    where
        I: IntoIterator<Item = SocketPacket>,
        O: IntoIterator<Item = OutboundPacket>,
        S: DataplaneOutputSink,
    {
        driver.reset_turn_buffers();

        let mut summary = DataplaneRuntimeSummary::default();
        for packet in inbound {
            driver.admit_socket_packet(packet, &mut summary);
        }
        for packet in outbound {
            driver.admit_outbound_packet(packet, &mut summary);
        }

        finish_aead_output_turn_with_inline(driver, summary, sink, limit)
    }

    fn admit_test_raw_ingress_packet<R>(
        driver: &mut DataplaneTurnDriver,
        packet: DataplaneRawIngress,
        router: &mut R,
        summary: &mut DataplaneRuntimeSummary,
    ) where
        R: DataplaneIngressRouter,
    {
        let mut deferred_raw_ingress = std::collections::VecDeque::new();
        let Some(socket_packet) = DataplaneTurnDriver::raw_ingress_socket_packet(
            packet,
            router,
            summary,
            &mut driver.raw_ingress_drops,
            &mut deferred_raw_ingress,
            0,
        ) else {
            return;
        };
        driver.admit_socket_packet(socket_packet, summary);
    }

    fn run_aead_raw_ingress_turn<'a, I, O, R>(
        driver: &'a mut DataplaneTurnDriver,
        inbound: I,
        router: &mut R,
        outbound: O,
        limit: usize,
    ) -> DataplaneRuntimeTurn<'a>
    where
        I: IntoIterator<Item = DataplaneRawIngress>,
        O: IntoIterator<Item = OutboundPacket>,
        R: DataplaneIngressRouter,
    {
        driver.reset_turn_buffers();

        let mut summary = DataplaneRuntimeSummary::default();
        for packet in inbound {
            admit_test_raw_ingress_packet(driver, packet, router, &mut summary);
        }
        for packet in outbound {
            driver.admit_outbound_packet(packet, &mut summary);
        }
        finish_aead_turn_with_inline(driver, summary, limit)
    }

    struct AeadOutputCompletionTurn<'a, C, RI, R, S> {
        completions: &'a mut C,
        completion_limit: usize,
        raw_ingress: &'a mut RI,
        router: &'a mut R,
        raw_ingress_limit: usize,
        outbound: &'a mut VecDeque<OutboundPacket>,
        outbound_limit: usize,
        sink: &'a mut S,
        crypto_limit: usize,
    }

    fn pump_aead_output_completion_turn<'a, C, RI, R, S>(
        driver: &'a mut DataplaneTurnDriver,
        request: AeadOutputCompletionTurn<'_, C, RI, R, S>,
    ) -> DataplaneRuntimeTurn<'a>
    where
        C: DataplaneCompletionSource,
        RI: DataplaneRawIngressSource,
        R: DataplaneIngressRouter,
        S: DataplaneOutputSink,
    {
        let AeadOutputCompletionTurn {
            completions,
            completion_limit,
            raw_ingress,
            router,
            raw_ingress_limit,
            outbound,
            outbound_limit,
            sink,
            crypto_limit,
        } = request;
        let mut executor = InlineDataplaneCryptoExecutor;
        driver.reset_turn_buffers();

        let mut summary = DataplaneRuntimeSummary::default();
        driver.completion_batches.clear();
        let queued = completions
            .drain_completion_batches_into(completion_limit, &mut driver.completion_batches);
        summary.completions = summary.completions.saturating_add(queued);
        driver
            .mover
            .queue_completion_batches(&mut driver.completion_batches);
        driver.retire_queued_completed_aead_outputs(completion_limit, false);
        summary = driver.admit_retired_outbound_packets(summary);

        raw_ingress.drain_raw_ingress(raw_ingress_limit, |packet| {
            admit_test_raw_ingress_packet(driver, packet, router, &mut summary);
        });
        let outbound_count = outbound_limit.min(outbound.len());
        for packet in outbound.drain(..outbound_count) {
            driver.admit_outbound_packet(packet, &mut summary);
        }

        summary =
            driver.collect_aead_outputs_with_executor(summary, crypto_limit, &mut executor, false);
        driver.send_collected_outputs(summary, sink)
    }

    struct AeadLiveRouteTableTurn<'a, RI> {
        raw_ingress: &'a mut RI,
        routes: &'a mut DataplaneLiveRouteTable,
        raw_ingress_limit: usize,
        endpoint_data_rx: &'a mut EndpointDataBatchRx,
        endpoint_limit: usize,
        tun_outbound_rx: &'a mut TunOutboundRx,
        tun_limit: usize,
        deferred_endpoint_data_batches: &'a mut Vec<NodeEndpointDataBatch>,
        deferred_tun_packets: &'a mut Vec<Vec<u8>>,
        endpoint_tx: &'a EndpointEventSender,
        transports: &'a HashMap<TransportId, TransportHandle>,
        crypto_limit: usize,
    }

    async fn pump_aead_live_node_route_table_turn<RI>(
        driver: &mut DataplaneTurnDriver,
        request: AeadLiveRouteTableTurn<'_, RI>,
    ) -> DataplaneLiveNodeTurn
    where
        RI: DataplaneRawIngressSource,
    {
        let mut completions = VecDeque::<CryptoCompletion>::new();
        pump_aead_live_node_route_table_turn_with_completions(
            driver,
            AeadLiveRouteTableCompletionTurn {
                completions: &mut completions,
                completion_limit: 0,
                route: request,
            },
        )
        .await
    }

    struct AeadLiveRouteTableCompletionTurn<'a, C, RI> {
        completions: &'a mut C,
        completion_limit: usize,
        route: AeadLiveRouteTableTurn<'a, RI>,
    }

    async fn pump_aead_live_node_route_table_turn_with_completions<C, RI>(
        driver: &mut DataplaneTurnDriver,
        request: AeadLiveRouteTableCompletionTurn<'_, C, RI>,
    ) -> DataplaneLiveNodeTurn
    where
        C: DataplaneCompletionSource,
        RI: DataplaneRawIngressSource,
    {
        let AeadLiveRouteTableCompletionTurn {
            completions,
            completion_limit,
            route,
        } = request;
        let AeadLiveRouteTableTurn {
            raw_ingress,
            routes,
            raw_ingress_limit,
            endpoint_data_rx,
            endpoint_limit,
            tun_outbound_rx,
            tun_limit,
            deferred_endpoint_data_batches,
            deferred_tun_packets,
            endpoint_tx,
            transports,
            crypto_limit,
        } = route;
        let transport_send_batch_packets = 8;
        let mut executor = InlineDataplaneCryptoExecutor;
        let mut deferred_raw_ingress = std::collections::VecDeque::new();
        let summary = driver.start_aead_completion_turn(
            completions,
            completion_limit,
            endpoint_tx.direct_sink().is_some(),
        );
        driver
            .pump_aead_live_node_route_table_executor_turn_after_completion_with_firsts(
                DataplaneLivePumpRequest {
                    summary,
                    executor: &mut executor,
                    fast_ingress: None,
                    raw_ingress,
                    routes,
                    raw_ingress_limit,
                    endpoint_data_rx,
                    endpoint_limit,
                    tun_outbound_rx,
                    tun_limit,
                    outbound_firsts: DataplaneLiveOutboundFirsts::default(),
                    deferred_endpoint_data_batches,
                    deferred_tun_packets,
                    deferred_raw_ingress: &mut deferred_raw_ingress,
                    endpoint_tx,
                    transports,
                    crypto_limit,
                    transport_send_batch_packets,
                },
            )
            .await
    }

    fn finish_aead_turn_with_inline(
        driver: &mut DataplaneTurnDriver,
        summary: DataplaneRuntimeSummary,
        limit: usize,
    ) -> DataplaneRuntimeTurn<'_> {
        let mut executor = InlineDataplaneCryptoExecutor;
        let summary =
            driver.collect_aead_outputs_with_executor(summary, limit, &mut executor, false);
        DataplaneRuntimeTurn {
            summary,
            raw_ingress_drops: &driver.raw_ingress_drops,
            output_drops: &driver.output_drops,
            outputs: &driver.outputs,
            drops: &driver.drops,
        }
    }

    fn finish_aead_output_turn_with_inline<'a, S>(
        driver: &'a mut DataplaneTurnDriver,
        summary: DataplaneRuntimeSummary,
        sink: &mut S,
        limit: usize,
    ) -> DataplaneRuntimeTurn<'a>
    where
        S: DataplaneOutputSink,
    {
        let mut executor = InlineDataplaneCryptoExecutor;
        let summary =
            driver.collect_aead_outputs_with_executor(summary, limit, &mut executor, false);
        driver.send_collected_outputs(summary, sink)
    }

    fn test_node_addr(id: u64) -> NodeAddr {
        let mut bytes = [0u8; 16];
        bytes[8..16].copy_from_slice(&id.to_be_bytes());
        NodeAddr::from_bytes(bytes)
    }

    fn fmp_owner(id: u64) -> OwnerId {
        OwnerId::fmp_node(test_node_addr(id))
    }

    fn fsp_owner(id: u64) -> OwnerId {
        OwnerId::fsp_node(test_node_addr(id))
    }

    fn test_receiver_idx(owner: OwnerId) -> u32 {
        let node_addr = owner.node_addr();
        let bytes: [u8; 4] = node_addr.as_bytes()[12..16]
            .try_into()
            .expect("test owner embeds receiver index");
        u32::from_be_bytes(bytes)
    }

    fn live_path(id: u32) -> TransportPath {
        let port = 10_000 + id % 50_000;
        let remote_addr = format!("198.51.100.1:{port}");
        TransportPath::live(TransportId::new(id), TransportAddr::from_string(&remote_addr))
    }

    fn tun_ipv6_packet(dest_addr: NodeAddr, len: usize) -> Vec<u8> {
        assert!(len >= 40);
        let mut packet = vec![0u8; len];
        packet[0] = 0x60;
        packet[6] = 17;
        let dest = crate::FipsAddress::from_node_addr(&dest_addr);
        packet[24..40].copy_from_slice(dest.as_bytes());
        packet
    }

    fn packet(
        owner: OwnerId,
        generation: u64,
        counter: u64,
        class: PacketClass,
        output: OutputTarget,
    ) -> SocketPacket {
        SocketPacket::new(
            owner,
            generation,
            counter,
            class,
            output,
            PacketBuffer::new(vec![counter as u8]),
        )
    }

    fn fmp_socket_packet(
        owner: OwnerId,
        generation: u64,
        output: OutputTarget,
        payload: Vec<u8>,
    ) -> Result<SocketPacket, WirePreflightError> {
        let payload = PacketBuffer::new(payload);
        let header = FmpWireHeader::parse(payload.as_slice())?;
        Ok(SocketPacket::new(
            owner,
            generation,
            header.counter(),
            PacketClass::Bulk,
            output,
            payload,
        )
        .with_wire_flags(header.flags()))
    }

    fn fsp_socket_packet(
        owner: OwnerId,
        generation: u64,
        output: OutputTarget,
        payload: Vec<u8>,
    ) -> Result<SocketPacket, WirePreflightError> {
        let payload = PacketBuffer::new(payload);
        let header = FspWireHeader::parse(payload.as_slice())?;
        Ok(SocketPacket::new(
            owner,
            generation,
            header.counter(),
            PacketClass::Bulk,
            output,
            payload,
        )
        .with_wire_flags(header.flags()))
    }

    fn fmp_wire(receiver_idx: u32, counter: u64, flags: u8) -> Vec<u8> {
        let mut data = vec![0u8; FMP_ESTABLISHED_HEADER_SIZE + 16];
        data[0] = (FMP_VERSION << 4) | FMP_PHASE_ESTABLISHED;
        data[1] = flags;
        data[4..8].copy_from_slice(&receiver_idx.to_le_bytes());
        data[8..16].copy_from_slice(&counter.to_le_bytes());
        data
    }

    fn fsp_wire(counter: u64, flags: u8) -> Vec<u8> {
        let mut data = vec![0u8; FSP_HEADER_SIZE + 16];
        data[0] = (FSP_VERSION << 4) | FSP_PHASE_ESTABLISHED;
        data[1] = flags;
        data[4..12].copy_from_slice(&counter.to_le_bytes());
        data
    }

    fn transport_output(
        owner: OwnerId,
        counter: u64,
        ingress_seq: u64,
        transport_id: TransportId,
        remote_addr: TransportAddr,
        payload: Vec<u8>,
    ) -> PacketOutput {
        PacketOutput {
            owner,
            counter,
            ingress_seq,
            lane: Lane::Bulk,
            target: OutputTarget::Transport,
            source_path: None,
            previous_hop: None,
            ce_flag: false,
            path_mtu: u16::MAX,
            source_peer: None,
            path: Some(TransportPath::live(transport_id, remote_addr)),
            activity_tick: None,
            source_wire_len: None,
            fmp_timestamp_ms: None,
            fsp_send_receipt: None,
            send_token: None,
            payload: PacketBuffer::new(payload),
        }
    }

    fn test_cipher(byte: u8) -> LessSafeKey {
        let key = [byte; 32];
        let unbound = UnboundKey::new(&ring::aead::CHACHA20_POLY1305, &key).unwrap();
        LessSafeKey::new(unbound)
    }

    fn test_key(byte: u8) -> AeadKey {
        Arc::new(test_cipher(byte))
    }

    fn unstarted_udp_transport(transport_id: TransportId) -> TransportHandle {
        let (packet_tx, _packet_rx) = crate::transport::packet_channel(4);
        TransportHandle::Udp(crate::transport::udp::UdpTransport::new(
            transport_id,
            None,
            crate::config::UdpConfig {
                bind_addr: Some("127.0.0.1:0".to_string()),
                ..Default::default()
            },
            packet_tx,
        ))
    }

    fn fmp_encrypted_wire(
        receiver_idx: u32,
        counter: u64,
        flags: u8,
        plaintext: &[u8],
        key: u8,
    ) -> Vec<u8> {
        let mut data = fmp_wire(receiver_idx, counter, flags);
        data.truncate(FMP_ESTABLISHED_HEADER_SIZE);
        let mut ciphertext = plaintext.to_vec();
        test_cipher(key)
            .seal_in_place_append_tag(
                aead_nonce(counter),
                Aad::from(&data[..FMP_ESTABLISHED_HEADER_SIZE]),
                &mut ciphertext,
            )
            .unwrap();
        data.extend_from_slice(&ciphertext);
        data
    }

    fn fsp_encrypted_wire(counter: u64, flags: u8, plaintext: &[u8], key: u8) -> Vec<u8> {
        fsp_encrypted_wire_with_coords(
            counter,
            flags,
            plaintext,
            key,
            &empty_fsp_coords_prefix(),
        )
    }

    fn fsp_encrypted_wire_with_coords(
        counter: u64,
        flags: u8,
        plaintext: &[u8],
        key: u8,
        coords_prefix: &[u8],
    ) -> Vec<u8> {
        let mut data = fsp_wire(counter, flags);
        data.truncate(FSP_HEADER_SIZE);
        let mut ciphertext = plaintext.to_vec();
        test_cipher(key)
            .seal_in_place_append_tag(
                aead_nonce(counter),
                Aad::from(&data[..FSP_HEADER_SIZE]),
                &mut ciphertext,
            )
            .unwrap();
        if flags & crate::node::session_wire::FSP_FLAG_CP != 0 {
            data.extend_from_slice(coords_prefix);
        }
        data.extend_from_slice(&ciphertext);
        data
    }

    fn encrypted_fmp_packet(
        owner: OwnerId,
        generation: u64,
        counter: u64,
        class: PacketClass,
        output: OutputTarget,
        key: u8,
    ) -> SocketPacket {
        SocketPacket::new(
            owner,
            generation,
            counter,
            class,
            output,
            PacketBuffer::new(fmp_encrypted_wire(
                test_receiver_idx(owner),
                counter,
                0,
                &[counter as u8],
                key,
            )),
        )
    }

    fn retire_completion(
        mover: &mut Dataplane,
        completion: CryptoCompletion,
    ) -> Vec<PacketOutput> {
        let mut retired = Vec::new();
        let mut completions = vec![CryptoCompletionBatch::from_completion(completion)];
        mover.queue_completion_batches(&mut completions);
        retire_queued_completions_to_outputs(mover, 1, &mut retired);
        retired
    }

    fn retire_queued_completions_to_outputs(
        mover: &mut Dataplane,
        limit: usize,
        retired: &mut Vec<PacketOutput>,
    ) -> usize {
        let mut outbound_packets = Vec::new();
        let mut fsp_authenticated_ingress = DataplaneFspAuthenticatedIngress::default();
        let retired_count = mover.retire_queued_completions_into(
            limit,
            &mut DataplaneRetiredOutputSink::new(
                retired,
                &mut outbound_packets,
                &mut fsp_authenticated_ingress,
            ),
            false,
        );
        assert!(outbound_packets.is_empty());
        assert!(fsp_authenticated_ingress.is_empty());
        retired_count
    }

    fn empty_fsp_coords_prefix() -> Vec<u8> {
        let mut prefix = Vec::with_capacity(2 * std::mem::size_of::<u16>());
        prefix.extend_from_slice(&0u16.to_le_bytes());
        prefix.extend_from_slice(&0u16.to_le_bytes());
        prefix
    }

    fn open_sealed_output(output: &PacketOutput, key: u8) -> Vec<u8> {
        match output.owner.protocol {
            PacketProtocol::Fmp => open_fmp_wire_payload(output.payload.as_slice(), key),
            PacketProtocol::Fsp => open_fsp_wire_payload(output.payload.as_slice(), key),
        }
    }

    fn open_fmp_wire_payload(payload: &[u8], key: u8) -> Vec<u8> {
        let header = FmpWireHeader::parse(payload).unwrap();
        let aad = header.header_bytes();
        open_wire_payload(
            payload,
            key,
            header.counter(),
            &aad,
            header.ciphertext_offset(),
        )
    }

    fn open_fsp_wire_payload(payload: &[u8], key: u8) -> Vec<u8> {
        let header = FspWireHeader::parse(payload).unwrap();
        let aad = header.header_bytes();
        open_wire_payload(
            payload,
            key,
            header.counter(),
            &aad,
            header.ciphertext_offset(),
        )
    }

    fn open_wire_payload(
        payload: &[u8],
        key: u8,
        counter: u64,
        aad: &[u8],
        ciphertext_offset: usize,
    ) -> Vec<u8> {
        let mut ciphertext = payload[ciphertext_offset..].to_vec();
        let plaintext_len = test_cipher(key)
            .open_in_place(aead_nonce(counter), Aad::from(aad), &mut ciphertext)
            .unwrap()
            .len();
        ciphertext.truncate(plaintext_len);
        ciphertext
    }

    fn outbound_packet(
        owner: OwnerId,
        generation: u64,
        class: PacketClass,
        payload: &[u8],
    ) -> OutboundPacket {
        match owner.protocol {
            PacketProtocol::Fmp => OutboundPacket::fmp(
                owner,
                generation,
                class,
                test_receiver_idx(owner),
                0,
                PacketBuffer::new(payload.to_vec()),
            ),
            PacketProtocol::Fsp => {
                OutboundPacket::fsp(owner, generation, class, 0, PacketBuffer::new(payload.to_vec()))
            }
        }
    }
