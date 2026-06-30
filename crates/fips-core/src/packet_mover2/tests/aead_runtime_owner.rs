    #[test]
    fn aead_turn_runner_uses_owner_keys_for_inbound_and_outbound_work() {
        let owner = fmp_owner(70);
        let open_key = 11;
        let seal_key = 12;
        let mut mover = mover();
        mover.register_owner(owner, OwnerConfig::new(1, 8).with_next_send_counter(200));
        mover
            .owner_mut(owner)
            .unwrap()
            .set_crypto_keys(OwnerCryptoKeys::new(test_key(open_key), test_key(seal_key)));

        mover
            .submit_socket_packet(
                SocketPacket::from_fmp_established_wire(
                    owner,
                    1,
                    OutputTarget::Tun,
                    fmp_encrypted_wire(70, 100, 0, b"inbound", open_key),
                )
                .unwrap(),
            )
            .unwrap();
        mover
            .submit_outbound_packet(OutboundPacket::fmp(
                owner,
                1,
                PacketClass::Bulk,
                700,
                0,
                b"outbound".to_vec(),
            ))
            .unwrap();

        let turn = run_aead_available(&mut mover, 8);
        assert_eq!(turn.dispatched(), 2);
        assert!(turn.drops().is_empty());

        let outputs = turn.outputs();
        assert_eq!(outputs.len(), 2);
        assert_eq!(outputs[0].counter, 100);
        assert_eq!(outputs[0].target, OutputTarget::Tun);
        assert_eq!(
            &outputs[0].payload[FMP_ESTABLISHED_HEADER_SIZE..],
            b"inbound"
        );
        assert_eq!(outputs[1].counter, 200);
        assert_eq!(outputs[1].target, OutputTarget::Transport);
        let sealed_header = FmpWireHeader::parse(&outputs[1].payload).unwrap();
        assert_eq!(sealed_header.receiver_idx(), 700);
        assert_eq!(sealed_header.counter(), 200);
        assert_eq!(open_sealed_output(outputs[1], seal_key), b"outbound");
    }

    #[test]
    fn aead_dispatch_spreads_existing_budget_across_owner_shards() {
        let mut mover = PacketMover2::new(AdmissionConfig::new(16, 16));
        let shard_count = mover.shards.len();
        if shard_count < 2 {
            return;
        }

        let first = fsp_owner(10_000);
        let first_shard = packet_mover2_owner_shard_index(first, shard_count);
        let second = (10_001..20_000)
            .map(fsp_owner)
            .find(|owner| packet_mover2_owner_shard_index(*owner, shard_count) != first_shard)
            .expect("test range should contain an owner on a distinct shard");
        let key = 70;
        mover.register_owner(first, OwnerConfig::new(1, 16));
        mover.register_owner(second, OwnerConfig::new(1, 16));
        mover
            .owner_mut(first)
            .unwrap()
            .set_crypto_keys(OwnerCryptoKeys::new(test_key(key), test_key(key)));
        mover
            .owner_mut(second)
            .unwrap()
            .set_crypto_keys(OwnerCryptoKeys::new(test_key(key), test_key(key)));

        for counter in 1..=8 {
            mover
                .submit_socket_packet(encrypted_fsp_packet(
                    first,
                    1,
                    counter,
                    PacketClass::Bulk,
                    OutputTarget::Tun,
                    key,
                ))
                .unwrap();
        }
        for counter in 101..=108 {
            mover
                .submit_socket_packet(encrypted_fsp_packet(
                    second,
                    1,
                    counter,
                    PacketClass::Bulk,
                    OutputTarget::Tun,
                    key,
                ))
                .unwrap();
        }

        let work = dispatch_available(&mut mover, 8);
        let first_count = work
            .iter()
            .filter(|work| work.reservation.owner == first)
            .count();
        let second_count = work
            .iter()
            .filter(|work| work.reservation.owner == second)
            .count();
        assert_eq!(work.len(), 8);
        assert!(first_count > 0, "first shard should be fed");
        assert!(second_count > 0, "second shard should be fed");
    }

    #[test]
    fn aead_completions_return_through_owner_shard_queues() {
        let mut mover = PacketMover2::new(AdmissionConfig::new(16, 16));
        let shard_count = mover.shards.len();
        if shard_count < 2 {
            return;
        }

        let first = fsp_owner(20_000);
        let first_shard = packet_mover2_owner_shard_index(first, shard_count);
        let second = (20_001..30_000)
            .map(fsp_owner)
            .find(|owner| packet_mover2_owner_shard_index(*owner, shard_count) != first_shard)
            .expect("test range should contain an owner on a distinct shard");
        let key = 71;
        mover.register_owner(first, OwnerConfig::new(1, 16));
        mover.register_owner(second, OwnerConfig::new(1, 16));
        mover
            .owner_mut(first)
            .unwrap()
            .set_crypto_keys(OwnerCryptoKeys::new(test_key(key), test_key(key)));
        mover
            .owner_mut(second)
            .unwrap()
            .set_crypto_keys(OwnerCryptoKeys::new(test_key(key), test_key(key)));

        mover
            .submit_socket_packet(encrypted_fsp_packet(
                first,
                1,
                1,
                PacketClass::Bulk,
                OutputTarget::Tun,
                key,
            ))
            .unwrap();
        mover
            .submit_socket_packet(encrypted_fsp_packet(
                second,
                1,
                101,
                PacketClass::Bulk,
                OutputTarget::Tun,
                key,
            ))
            .unwrap();

        let mut work = dispatch_available(&mut mover, 8);
        assert_eq!(work.len(), 2);
        let second_work = work
            .iter()
            .position(|work| work.reservation.owner == second)
            .map(|pos| work.remove(pos))
            .unwrap();
        let first_work = work.pop().unwrap();
        assert_eq!(
            first_work.reservation.owner_shard,
            packet_mover2_owner_shard_index(first, shard_count)
        );
        assert_eq!(
            second_work.reservation.owner_shard,
            packet_mover2_owner_shard_index(second, shard_count)
        );

        let mut retired = Vec::new();
        mover.queue_completion(open_aead_completion(second_work, key));
        assert_eq!(mover.retire_queued_completions_into(1, &mut retired), 1);
        assert_eq!(retired.len(), 1);
        assert!(matches!(&retired[0], RetiredPacket::Output(output) if output.owner == second));

        mover.queue_completion(open_aead_completion(first_work, key));
        assert_eq!(mover.retire_queued_completions_into(1, &mut retired), 1);
        assert_eq!(retired.len(), 2);
        assert!(matches!(&retired[1], RetiredPacket::Output(output) if output.owner == first));
    }

    #[test]
    fn aead_completion_ready_queue_marks_each_owner_shard_once() {
        let owner = fsp_owner(20_500);
        let key = 72;
        let mut mover = mover();
        mover.register_owner(owner, OwnerConfig::new(1, 16));
        mover
            .owner_mut(owner)
            .unwrap()
            .set_crypto_keys(OwnerCryptoKeys::new(test_key(key), test_key(key)));

        for counter in 1..=2 {
            mover
                .submit_socket_packet(encrypted_fsp_packet(
                    owner,
                    1,
                    counter,
                    PacketClass::Bulk,
                    OutputTarget::Tun,
                    key,
                ))
                .unwrap();
        }

        let mut work = dispatch_available(&mut mover, 8);
        assert_eq!(work.len(), 2);
        let shard = work[0].reservation.owner_shard;
        let first = work.remove(0);
        let second = work.remove(0);

        mover.queue_completion(open_aead_completion(first, key));
        mover.queue_completion(open_aead_completion(second, key));
        assert_eq!(
            mover
                .completion_ready_shards
                .queue
                .iter()
                .copied()
                .collect::<Vec<_>>(),
            vec![shard]
        );
        assert!(mover.completion_ready_shards.ready[shard]);

        let mut retired = Vec::new();
        assert_eq!(mover.retire_queued_completions_into(1, &mut retired), 1);
        assert_eq!(
            mover
                .completion_ready_shards
                .queue
                .iter()
                .copied()
                .collect::<Vec<_>>(),
            vec![shard]
        );
        assert!(mover.completion_ready_shards.ready[shard]);
        assert!(matches!(&retired[0], RetiredPacket::Output(output) if output.counter == 1));

        assert_eq!(mover.retire_queued_completions_into(1, &mut retired), 1);
        assert!(mover.completion_ready_shards.is_empty());
        assert!(!mover.completion_ready_shards.ready[shard]);
        assert!(matches!(&retired[1], RetiredPacket::Output(output) if output.counter == 2));
    }

    #[test]
    fn aead_completion_ready_queue_retires_owner_shard_batch() {
        let owner = fsp_owner(20_550);
        let key = 74;
        let mut mover = mover();
        mover.register_owner(owner, OwnerConfig::new(1, 16));
        mover
            .owner_mut(owner)
            .unwrap()
            .set_crypto_keys(OwnerCryptoKeys::new(test_key(key), test_key(key)));

        for counter in 1..=3 {
            mover
                .submit_socket_packet(encrypted_fsp_packet(
                    owner,
                    1,
                    counter,
                    PacketClass::Bulk,
                    OutputTarget::Tun,
                    key,
                ))
                .unwrap();
        }

        let work = dispatch_available(&mut mover, 8);
        assert_eq!(work.len(), 3);
        let shard = work[0].reservation.owner_shard;
        for work in work {
            mover.queue_completion(open_aead_completion(work, key));
        }
        assert_eq!(
            mover
                .completion_ready_shards
                .queue
                .iter()
                .copied()
                .collect::<Vec<_>>(),
            vec![shard]
        );

        let mut retired = Vec::new();
        let retired_counters = |retired: &[RetiredPacket]| {
            retired
                .iter()
                .filter_map(|item| match item {
                    RetiredPacket::Output(output) => Some(output.counter),
                    _ => None,
                })
                .collect::<Vec<_>>()
        };
        assert_eq!(mover.retire_queued_completions_into(2, &mut retired), 2);
        assert_eq!(retired_counters(&retired), vec![1, 2]);
        assert_eq!(
            mover
                .completion_ready_shards
                .queue
                .iter()
                .copied()
                .collect::<Vec<_>>(),
            vec![shard]
        );
        assert!(mover.completion_ready_shards.ready[shard]);

        assert_eq!(mover.retire_queued_completions_into(8, &mut retired), 1);
        assert!(mover.completion_ready_shards.is_empty());
        assert_eq!(retired_counters(&retired), vec![1, 2, 3]);
    }

    #[test]
    fn admission_ready_queues_mark_each_owner_shard_lane_once() {
        let owner = fmp_owner(20_600);
        let key = 73;
        let mut inbound_mover = mover();
        inbound_mover.register_owner(owner, OwnerConfig::new(1, 16));
        inbound_mover
            .owner_mut(owner)
            .unwrap()
            .set_crypto_keys(OwnerCryptoKeys::new(test_key(key), test_key(key)));

        inbound_mover
            .submit_socket_packet(packet(
                owner,
                1,
                10,
                PacketClass::Bulk,
                OutputTarget::Tun,
            ))
            .unwrap();
        inbound_mover
            .submit_socket_packet(packet(
                owner,
                1,
                11,
                PacketClass::Bulk,
                OutputTarget::Tun,
            ))
            .unwrap();

        let shard = packet_mover2_owner_shard_index(owner, inbound_mover.shards.len());
        assert_eq!(
            inbound_mover
                .ingress_ready_shards
                .bulk
                .queue
                .iter()
                .copied()
                .collect::<Vec<_>>(),
            vec![shard]
        );

        let inbound = dispatch_available(&mut inbound_mover, 1);
        assert_eq!(inbound.len(), 1);
        assert_eq!(
            inbound_mover
                .ingress_ready_shards
                .bulk
                .queue
                .iter()
                .copied()
                .collect::<Vec<_>>(),
            vec![shard]
        );
        assert!(inbound_mover.ingress_ready_shards.bulk.ready[shard]);

        let mut outbound_mover = mover();
        outbound_mover.register_owner(owner, OwnerConfig::new(1, 16).with_next_send_counter(700));
        outbound_mover
            .owner_mut(owner)
            .unwrap()
            .set_crypto_keys(OwnerCryptoKeys::new(test_key(key), test_key(key)));
        outbound_mover
            .submit_outbound_packet(OutboundPacket::fmp(
                owner,
                1,
                PacketClass::Bulk,
                700,
                0,
                b"first".to_vec(),
            ))
            .unwrap();
        outbound_mover
            .submit_outbound_packet(OutboundPacket::fmp(
                owner,
                1,
                PacketClass::Bulk,
                700,
                0,
                b"second".to_vec(),
            ))
            .unwrap();

        assert_eq!(
            outbound_mover
                .outbound_ready_shards
                .bulk
                .queue
                .iter()
                .copied()
                .collect::<Vec<_>>(),
            vec![shard]
        );

        let outbound = dispatch_outbound_available(&mut outbound_mover, 1);
        assert_eq!(outbound.len(), 1);
        assert_eq!(
            outbound_mover
                .outbound_ready_shards
                .bulk
                .queue
                .iter()
                .copied()
                .collect::<Vec<_>>(),
            vec![shard]
        );
        assert!(outbound_mover.outbound_ready_shards.bulk.ready[shard]);
    }

    #[derive(Debug, Default)]
    struct RecordingChunkExecutor {
        inline: InlinePacketMover2CryptoExecutor,
        nonempty_chunks: Vec<usize>,
    }

    impl PacketMover2CryptoExecutor for RecordingChunkExecutor {
        fn execute_prepared_chunk(
            &mut self,
            prepared: &mut Vec<PreparedCryptoWork>,
            completions: &mut Vec<CryptoCompletion>,
        ) -> usize {
            if !prepared.is_empty() {
                self.nonempty_chunks.push(prepared.len());
            }
            self.inline.execute_prepared_chunk(prepared, completions)
        }
    }

    #[derive(Debug, Default)]
    struct DelayedChunkExecutor {
        inline: InlinePacketMover2CryptoExecutor,
        ready: VecDeque<Vec<CryptoCompletion>>,
        nonempty_chunks: Vec<usize>,
    }

    impl DelayedChunkExecutor {
        fn take_ready(&mut self) -> VecDeque<Vec<CryptoCompletion>> {
            std::mem::take(&mut self.ready)
        }
    }

    impl PacketMover2CryptoExecutor for DelayedChunkExecutor {
        fn execute_prepared_chunk(
            &mut self,
            prepared: &mut Vec<PreparedCryptoWork>,
            completions: &mut Vec<CryptoCompletion>,
        ) -> usize {
            if !prepared.is_empty() {
                self.nonempty_chunks.push(prepared.len());
            }
            let count = self.inline.execute_prepared_chunk(prepared, completions);
            if !completions.is_empty() {
                self.ready.push_back(std::mem::take(completions));
            }
            count
        }
    }

    #[derive(Debug)]
    struct BoundedDelayedChunkExecutor {
        inline: InlinePacketMover2CryptoExecutor,
        ready: VecDeque<Vec<CryptoCompletion>>,
        nonempty_chunks: Vec<usize>,
        remaining_capacity: usize,
    }

    impl BoundedDelayedChunkExecutor {
        fn new(capacity: usize) -> Self {
            Self {
                inline: InlinePacketMover2CryptoExecutor::default(),
                ready: VecDeque::new(),
                nonempty_chunks: Vec::new(),
                remaining_capacity: capacity,
            }
        }

        fn take_ready(&mut self) -> VecDeque<Vec<CryptoCompletion>> {
            std::mem::take(&mut self.ready)
        }
    }

    impl PacketMover2CryptoExecutor for BoundedDelayedChunkExecutor {
        fn available_capacity(&self) -> usize {
            self.remaining_capacity
        }

        fn execute_prepared_chunk(
            &mut self,
            prepared: &mut Vec<PreparedCryptoWork>,
            completions: &mut Vec<CryptoCompletion>,
        ) -> usize {
            assert!(
                prepared.len() <= self.remaining_capacity,
                "owner-reserved chunk exceeded executor capacity"
            );
            if !prepared.is_empty() {
                self.nonempty_chunks.push(prepared.len());
            }
            self.remaining_capacity = self.remaining_capacity.saturating_sub(prepared.len());
            let count = self.inline.execute_prepared_chunk(prepared, completions);
            if !completions.is_empty() {
                self.ready.push_back(std::mem::take(completions));
            }
            count
        }
    }

    fn register_owner_with_test_keys(
        mover: &mut PacketMover2,
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
        mover: &mut PacketMover2,
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
                    SocketPacket::from_fmp_established_wire(
                        owner,
                        1,
                        OutputTarget::Tun,
                        fmp_encrypted_wire(receiver_idx, counter, 0, payload, open_key),
                    )
                    .unwrap(),
                )
                .unwrap();
        }
    }

    fn run_with_executor<E>(
        mover: &mut PacketMover2,
        executor: &mut E,
    ) -> (usize, Vec<RetiredPacket>, Vec<PacketDrop>)
    where
        E: PacketMover2CryptoExecutor,
    {
        run_with_executor_limit(mover, executor, 8)
    }

    fn run_with_executor_limit<E>(
        mover: &mut PacketMover2,
        executor: &mut E,
        limit: usize,
    ) -> (usize, Vec<RetiredPacket>, Vec<PacketDrop>)
    where
        E: PacketMover2CryptoExecutor,
    {
        let mut prepared_work = Vec::new();
        let mut completion_work = Vec::new();
        let mut retired = Vec::new();
        let mut drops = Vec::new();
        let dispatched = mover.run_aead_available_into_with_executor(
            limit,
            &mut prepared_work,
            &mut completion_work,
            &mut retired,
            &mut drops,
            executor,
        );
        (dispatched, retired, drops)
    }

    fn drain_worker_pool_completions(
        pool: &mut PacketMover2AeadWorkerPool,
        expected: usize,
    ) -> Vec<CryptoCompletion> {
        let mut completions = Vec::new();
        for _ in 0..100 {
            pool.drain_completions_into(expected.saturating_sub(completions.len()), &mut completions);
            if completions.len() >= expected {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
        completions
    }

    #[test]
    fn aead_turn_runner_hands_executor_prepared_crypto_chunks() {
        let owner = fmp_owner(702);
        let open_key = 15;
        let seal_key = 16;
        let mut mover = mover();
        mover.register_owner(owner, OwnerConfig::new(1, 8).with_next_send_counter(300));
        mover
            .owner_mut(owner)
            .unwrap()
            .set_crypto_keys(OwnerCryptoKeys::new(test_key(open_key), test_key(seal_key)));

        for counter in 100..104 {
            mover
                .submit_socket_packet(
                    SocketPacket::from_fmp_established_wire(
                        owner,
                        1,
                        OutputTarget::Tun,
                        fmp_encrypted_wire(70, counter, 0, b"inbound", open_key),
                    )
                    .unwrap(),
                )
                .unwrap();
        }
        for idx in 0..2 {
            mover
                .submit_outbound_packet(OutboundPacket::fmp(
                    owner,
                    1,
                    PacketClass::Bulk,
                    702,
                    0,
                    format!("outbound-{idx}").into_bytes(),
                ))
                .unwrap();
        }

        let mut prepared_work = Vec::new();
        let mut completion_work = Vec::new();
        let mut retired = Vec::new();
        let mut drops = Vec::new();
        let mut executor = RecordingChunkExecutor::default();
        let dispatched = mover.run_aead_available_into_with_executor(
            6,
            &mut prepared_work,
            &mut completion_work,
            &mut retired,
            &mut drops,
            &mut executor,
        );

        assert_eq!(dispatched, 6);
        assert_eq!(executor.nonempty_chunks, vec![6]);
        assert!(drops.is_empty());
        assert!(prepared_work.is_empty());
        assert!(completion_work.is_empty());

        let outputs = outputs(retired);
        assert_eq!(outputs.len(), 6);
        assert_eq!(
            outputs
                .iter()
                .map(PacketOutput::counter)
                .collect::<Vec<_>>(),
            vec![100, 101, 102, 103, 300, 301]
        );
        assert_eq!(
            open_sealed_output(&outputs[4], seal_key),
            b"outbound-0"
        );
        assert_eq!(
            open_sealed_output(&outputs[5], seal_key),
            b"outbound-1"
        );
    }

    #[test]
    fn executor_capacity_zero_does_not_reserve_owner_work() {
        let owner = fmp_owner(704);
        let open_key = 18;
        let mut mover = mover();
        register_owner_with_test_keys(&mut mover, owner, open_key, open_key);
        submit_fmp_inbound_range(&mut mover, owner, 704, open_key, 100..102, b"queued");

        let mut bounded = BoundedDelayedChunkExecutor::new(0);
        let (dispatched, retired, drops) = run_with_executor(&mut mover, &mut bounded);

        assert_eq!(dispatched, 0);
        assert!(bounded.nonempty_chunks.is_empty());
        assert!(retired.is_empty());
        assert!(drops.is_empty());
        assert_eq!(mover.owner_mut(owner).unwrap().in_flight, 0);

        let mut inline = InlinePacketMover2CryptoExecutor::default();
        let (dispatched, retired, _) = run_with_executor(&mut mover, &mut inline);
        assert_eq!(dispatched, 2);
        assert_eq!(outputs(retired).len(), 2);
    }

    #[test]
    fn executor_capacity_bounds_owner_in_flight_reservations() {
        let owner = fmp_owner(705);
        let open_key = 19;
        let mut mover = mover();
        register_owner_with_test_keys(&mut mover, owner, open_key, open_key);
        submit_fmp_inbound_range(&mut mover, owner, 705, open_key, 100..104, b"bounded");

        let mut bounded = BoundedDelayedChunkExecutor::new(2);
        let (dispatched, retired, drops) = run_with_executor(&mut mover, &mut bounded);

        assert_eq!(dispatched, 2);
        assert_eq!(bounded.nonempty_chunks, vec![2]);
        assert!(retired.is_empty());
        assert!(drops.is_empty());
        assert_eq!(mover.owner_mut(owner).unwrap().in_flight, 2);

        let mut retired_ready = Vec::new();
        for completions in bounded.take_ready() {
            for completion in completions {
                retired_ready.extend(retire_completion(&mut mover, completion));
            }
        }
        assert_eq!(outputs(retired_ready).len(), 2);
        assert_eq!(mover.owner_mut(owner).unwrap().in_flight, 0);

        let mut inline = InlinePacketMover2CryptoExecutor::default();
        let (dispatched, retired, drops) = run_with_executor(&mut mover, &mut inline);
        assert_eq!(dispatched, 2);
        assert_eq!(outputs(retired).len(), 2);
        assert!(drops.is_empty());
    }

    #[test]
    fn aead_worker_pool_returns_completions_through_completion_source() {
        let owner = fmp_owner(706);
        let open_key = 20;
        let mut mover = mover();
        register_owner_with_test_keys(&mut mover, owner, open_key, open_key);
        submit_fmp_inbound_range(&mut mover, owner, 706, open_key, 100..104, b"worker");

        let mut pool = PacketMover2AeadWorkerPool::new(2, 8);
        let (dispatched, retired, drops) = run_with_executor(&mut mover, &mut pool);

        assert_eq!(dispatched, 4);
        assert!(retired.is_empty());
        assert!(drops.is_empty());
        assert_eq!(mover.owner_mut(owner).unwrap().in_flight, 4);

        let mut retired = Vec::new();
        let completions = drain_worker_pool_completions(&mut pool, 2);
        assert_eq!(completions.len(), 2);
        assert_eq!(pool.available_open_capacity(), 6);
        assert_eq!(pool.available_seal_capacity(), 8);
        for completion in completions {
            retired.extend(retire_completion(&mut mover, completion));
        }

        let completions = drain_worker_pool_completions(&mut pool, 2);
        assert_eq!(completions.len(), 2);
        for completion in completions {
            retired.extend(retire_completion(&mut mover, completion));
        }
        let outputs = outputs(retired);
        assert_eq!(
            outputs
                .iter()
                .map(PacketOutput::counter)
                .collect::<Vec<_>>(),
            vec![100, 101, 102, 103]
        );
        assert_eq!(mover.owner_mut(owner).unwrap().in_flight, 0);
        assert_eq!(pool.available_open_capacity(), 8);
        assert_eq!(pool.available_seal_capacity(), 8);
    }

    #[test]
    fn aead_worker_pool_has_independent_open_and_seal_capacity() {
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
                    format!("outbound-{idx}").into_bytes(),
                ))
                .unwrap();
        }

        let mut pool = PacketMover2AeadWorkerPool::new(1, 2);
        let (dispatched, retired, drops) = run_with_executor_limit(&mut mover, &mut pool, 4);

        assert_eq!(dispatched, 4);
        assert!(retired.is_empty());
        assert!(drops.is_empty());
        assert_eq!(pool.available_open_capacity(), 0);
        assert_eq!(pool.available_seal_capacity(), 0);
    }

    #[test]
    fn aead_worker_pool_reserves_priority_capacity_from_bulk() {
        let owner = fmp_owner(709);
        let open_key = 22;
        let mut mover = PacketMover2::new(AdmissionConfig::new(16, 32));
        mover.register_owner(
            owner,
            OwnerConfig::new(1, PACKET_MOVER2_AEAD_WORKER_JOB_PACKETS * 2),
        );
        mover
            .owner_mut(owner)
            .unwrap()
            .set_crypto_keys(OwnerCryptoKeys::new(test_key(open_key), test_key(open_key)));
        let mut pool = PacketMover2AeadWorkerPool::new(
            1,
            PACKET_MOVER2_AEAD_WORKER_JOB_PACKETS * 2,
        );

        for counter in 0..(PACKET_MOVER2_AEAD_WORKER_JOB_PACKETS * 2) as u64 {
            mover
                .submit_socket_packet(encrypted_fmp_packet(
                    owner,
                    1,
                    counter,
                    PacketClass::Bulk,
                    OutputTarget::Tun,
                    open_key,
                ))
                .unwrap();
        }

        let (dispatched, retired, drops) = run_with_executor_limit(
            &mut mover,
            &mut pool,
            PACKET_MOVER2_AEAD_WORKER_JOB_PACKETS * 2,
        );
        assert_eq!(dispatched, PACKET_MOVER2_AEAD_WORKER_JOB_PACKETS);
        assert!(retired.is_empty());
        assert!(drops.is_empty());
        assert_eq!(pool.available_open_capacity_for_lane(Lane::Bulk), 0);
        assert_eq!(
            pool.available_open_capacity_for_lane(Lane::Priority),
            PACKET_MOVER2_AEAD_WORKER_JOB_PACKETS
        );

        mover
            .submit_socket_packet(encrypted_fmp_packet(
                owner,
                1,
                1_000,
                PacketClass::Liveness,
                OutputTarget::Tun,
                open_key,
            ))
            .unwrap();
        let (dispatched, retired, drops) = run_with_executor_limit(
            &mut mover,
            &mut pool,
            PACKET_MOVER2_AEAD_WORKER_JOB_PACKETS * 2,
        );
        assert_eq!(dispatched, 1);
        assert!(retired.is_empty());
        assert!(drops.is_empty());
        assert_eq!(queue_lens(&mover), (0, PACKET_MOVER2_AEAD_WORKER_JOB_PACKETS));
    }

    #[test]
    fn aead_worker_jobs_split_hot_owner_burst() {
        let owner = fmp_owner(708);
        assert_eq!(packet_mover2_aead_worker_job_packets(8, 8), 1);
        assert_eq!(packet_mover2_aead_worker_job_packets(64, 8), 8);

        let work_count = PACKET_MOVER2_AEAD_WORKER_JOB_PACKETS * 2 + 3;
        let work = (0..work_count as u64)
            .map(|counter| {
                PreparedCryptoWork::Completed(CryptoCompletion {
                    reservation: OwnerReservation {
                        owner,
                        owner_shard: 0,
                        generation: 1,
                        order: OrderToken(counter),
                        ingress_seq: counter,
                        counter,
                        class: PacketClass::Bulk,
                        lane: Lane::Bulk,
                        source_path: None,
                        previous_hop: None,
                        ce_flag: false,
                        path_mtu: u16::MAX,
                        wire_flags: 0,
                        source_peer: None,
                        output_path: None,
                        activity_tick: None,
                        fmp_timestamp_ms: None,
                        fsp_timestamp_ms: None,
                    },
                    result: CryptoResult::Failed(CryptoFailureKind::Open),
                })
            })
            .collect::<Vec<_>>();

        let jobs = PreparedCryptoJobSplitter::new(work, packet_mover2_aead_worker_job_packets(work_count, 4))
            .collect::<Vec<_>>();
        assert_eq!(
            jobs.iter().map(Vec::len).collect::<Vec<_>>(),
            vec![5, 5, 5, 4]
        );
        let counters = jobs
            .into_iter()
            .flatten()
            .map(|work| match work {
                PreparedCryptoWork::Completed(completion) => completion.reservation.counter,
                PreparedCryptoWork::Open { .. } | PreparedCryptoWork::Seal { .. } => {
                    unreachable!("test constructs completed crypto work only")
                }
            })
            .collect::<Vec<_>>();
        assert_eq!(counters, (0..work_count as u64).collect::<Vec<_>>());
    }

    #[test]
    fn aead_worker_pool_capacity_blocks_reservation_until_completion_drain() {
        let owner = fmp_owner(707);
        let open_key = 21;
        let mut mover = mover();
        register_owner_with_test_keys(&mut mover, owner, open_key, open_key);
        submit_fmp_inbound_range(&mut mover, owner, 707, open_key, 100..104, b"worker-cap");

        let mut pool = PacketMover2AeadWorkerPool::new(1, 2);
        let (dispatched, retired, drops) = run_with_executor(&mut mover, &mut pool);
        assert_eq!(dispatched, 2);
        assert!(retired.is_empty());
        assert!(drops.is_empty());
        assert_eq!(pool.available_open_capacity(), 0);
        assert_eq!(pool.available_seal_capacity(), 2);
        assert_eq!(mover.owner_mut(owner).unwrap().in_flight, 2);

        let (dispatched, retired, drops) = run_with_executor(&mut mover, &mut pool);
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
        assert_eq!(pool.available_open_capacity(), 2);

        let (dispatched, retired, drops) = run_with_executor(&mut mover, &mut pool);
        assert_eq!(dispatched, 2);
        assert!(retired.is_empty());
        assert!(drops.is_empty());
    }

    #[test]
    fn executor_turn_dispatches_chunk_and_retires_delayed_completion_later() {
        let owner = fmp_owner(703);
        let seal_key = 17;
        let mut driver = PacketMover2TurnDriver::new(AdmissionConfig::new(4, 8));
        driver.register_owner(owner, OwnerConfig::new(1, 8).with_next_send_counter(500));
        driver
            .owner_mut(owner)
            .unwrap()
            .set_crypto_keys(OwnerCryptoKeys::new(test_key(seal_key), test_key(seal_key)));

        let mut raw_ingress = VecDeque::new();
        let mut outbound = VecDeque::from([OutboundPacket::fmp(
            owner,
            1,
            PacketClass::Bulk,
            703,
            0,
            b"delayed-outbound".to_vec(),
        )]);
        let mut sink = BatchRecordingOutputSink::default();
        let mut empty_completions: VecDeque<CryptoCompletion> = VecDeque::new();
        let mut executor = DelayedChunkExecutor::default();

        {
            let turn = pump_aead_output_completion_executor_turn(
                &mut empty_completions,
                8,
                &mut executor,
                &mut driver,
                &mut raw_ingress,
                &mut NullIngressRouter,
                0,
                &mut outbound,
                1,
                &mut sink,
                8,
            );
            assert_eq!(turn.summary().completions(), 0);
            assert_eq!(turn.summary().outbound_admitted(), 1);
            assert_eq!(turn.summary().dispatched(), 1);
            assert_eq!(turn.summary().outputs_sent(), 0);
            assert!(turn.outputs().is_empty());
            assert!(turn.drops().is_empty());
        }
        assert!(empty_completions.is_empty());
        assert!(outbound.is_empty());
        assert!(sink.outputs.is_empty());
        assert_eq!(executor.nonempty_chunks, vec![1]);
        assert_eq!(driver.owner_mut(owner).unwrap().in_flight, 1);

        let mut ready_completions = executor.take_ready();
        {
            let turn = pump_aead_output_completion_executor_turn(
                &mut ready_completions,
                8,
                &mut executor,
                &mut driver,
                &mut raw_ingress,
                &mut NullIngressRouter,
                0,
                &mut outbound,
                0,
                &mut sink,
                0,
            );
            assert_eq!(turn.summary().completions(), 1);
            assert_eq!(turn.summary().dispatched(), 0);
            assert_eq!(turn.summary().outputs_sent(), 1);
            assert!(turn.outputs().is_empty());
            assert!(turn.drops().is_empty());
        }

        assert!(ready_completions.is_empty());
        assert_eq!(driver.owner_mut(owner).unwrap().in_flight, 0);
        assert_eq!(sink.outputs.len(), 1);
        assert_eq!(sink.outputs[0].owner(), owner);
        assert_eq!(sink.outputs[0].counter(), 500);
        assert_eq!(sink.outputs[0].target(), OutputTarget::Transport);
        assert_eq!(
            open_sealed_output(&sink.outputs[0], seal_key),
            b"delayed-outbound"
        );
    }

    #[test]
    fn aead_turn_runner_wraps_fsp_post_seal_into_next_hop_fmp() {
        let source = NodeAddr::from_bytes([0x21; 16]);
        let dest = NodeAddr::from_bytes([0x22; 16]);
        let next_hop = NodeAddr::from_bytes([0x23; 16]);
        let fsp_owner = OwnerId::fsp_node(dest);
        let fmp_owner = OwnerId::fmp_node(next_hop);
        let fsp_key = 21;
        let fmp_key = 22;
        let fmp_path = live_path(2200);
        let mut driver =
            PacketMover2TurnDriver::new(AdmissionConfig::new(4, 8));
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

        let wrap = PacketMover2FspWrapRoute::new(
            fmp_owner,
            1,
            4242,
            source,
            dest,
        )
        .with_fmp_flags(0x05)
        .with_ttl(42)
        .with_path_mtu(1280);
        let packet = OutboundPacket::fsp(
            fsp_owner,
            1,
            PacketClass::Liveness,
            0x03,
            b"session-body".to_vec(),
        )
        .with_fsp_cleartext_prefix(empty_fsp_coords_prefix())
        .with_post_seal(OutboundPostSeal::FmpWrap(wrap))
        .with_activity_tick(ActivityTick::new(1_234));
        let queued_bulk = OutboundPacket::fmp(
            fmp_owner,
            1,
            PacketClass::Bulk,
            4243,
            0,
            b"queued-bulk".to_vec(),
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
        assert_eq!(output.path(), Some(fmp_path));
        let receipt = output.fsp_send_receipt().expect("wrapped FSP receipt");
        assert_eq!(receipt.owner(), fsp_owner);
        assert_eq!(receipt.counter(), 50);
        assert_eq!(receipt.timestamp_ms(), Some(234));

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
    fn aead_turn_runner_spends_remaining_budget_on_fsp_post_seal_wrap() {
        let source = NodeAddr::from_bytes([0x31; 16]);
        let dest = NodeAddr::from_bytes([0x32; 16]);
        let next_hop = NodeAddr::from_bytes([0x33; 16]);
        let fsp_owner = OwnerId::fsp_node(dest);
        let fmp_owner = OwnerId::fmp_node(next_hop);
        let fsp_key = 31;
        let fmp_key = 32;
        let fmp_path = live_path(3200);
        let mut driver =
            PacketMover2TurnDriver::new(AdmissionConfig::new(4, 8));
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

        let wrap = PacketMover2FspWrapRoute::new(fmp_owner, 1, 5151, source, dest)
            .with_ttl(42)
            .with_path_mtu(1280);
        let packet = OutboundPacket::fsp(
            fsp_owner,
            1,
            PacketClass::Liveness,
            0x03,
            b"session-priority".to_vec(),
        )
        .with_fsp_cleartext_prefix(empty_fsp_coords_prefix())
        .with_post_seal(OutboundPostSeal::FmpWrap(wrap));

        let turn = run_aead_classified_turn(&mut driver, std::iter::empty(), [packet], 2);
        assert_eq!(turn.summary().outbound_admitted(), 2);
        assert_eq!(turn.summary().dispatched(), 2);
        assert_eq!(turn.summary().outputs(), 1);
        assert!(turn.drops().is_empty());

        let output = &turn.outputs()[0];
        assert_eq!(output.owner(), fmp_owner);
        assert_eq!(output.counter(), 100);
        assert_eq!(output.target(), OutputTarget::Transport);
        assert_eq!(output.path(), Some(fmp_path));
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
            PacketMover2TurnDriver::new(AdmissionConfig::new(4, 8));
        driver.register_owner(
            fsp_owner,
            OwnerConfig::new(1, 8)
                .with_bulk_in_flight_limit(2)
                .with_next_send_counter(10),
        );
        driver.register_owner(
            fmp_owner,
            OwnerConfig::new(1, 8)
                .with_bulk_in_flight_limit(2)
                .with_next_send_counter(20),
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

        let wrap = PacketMover2FspWrapRoute::new(fmp_owner, 1, 6000, source, dest)
            .with_ttl(42)
            .with_path_mtu(1280);
        let packets = (0..4).map(|idx| {
            OutboundPacket::fsp(
                fsp_owner,
                1,
                PacketClass::Bulk,
                crate::node::session_wire::FSP_FLAG_CP,
                format!("session-{idx}").into_bytes(),
            )
            .with_fsp_cleartext_prefix(empty_fsp_coords_prefix())
            .with_post_seal(OutboundPostSeal::FmpWrap(wrap))
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
            assert_eq!(output.path(), Some(fmp_path.clone()));
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
                    SocketPacket::from_fmp_established_wire(
                        owner,
                        1,
                        OutputTarget::Tun,
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
                b"outbound-liveness".to_vec(),
            ))
            .unwrap();

        let turn = run_aead_available(&mut mover, 2);

        assert_eq!(turn.dispatched(), 2);
        let outputs = turn.outputs();
        assert_eq!(outputs.len(), 2);
        assert_eq!(outputs[0].target, OutputTarget::Tun);
        assert_eq!(outputs[0].counter, 100);
        assert_eq!(outputs[1].target, OutputTarget::Transport);
        assert_eq!(outputs[1].counter, 900);
        assert_eq!(outputs[1].path(), Some(path));
        assert_eq!(
            open_sealed_output(outputs[1], seal_key),
            b"outbound-liveness"
        );
        assert_eq!(queue_lens(&mover), (0, 3));
        assert_eq!(outbound_queue_lens(&mover), (0, 0));
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
                b"needs key".to_vec(),
            ))
            .unwrap();

        let turn = run_aead_available(&mut mover, 8);
        assert_eq!(turn.dispatched(), 1);
        assert_eq!(turn.retired().len(), 1);
        match &turn.retired()[0] {
            RetiredPacket::Drop(drop) => {
                assert_eq!(drop.reason, PacketDropReason::CryptoFailed);
                assert_eq!(drop.counter, Some(0));
                assert_eq!(drop.lane, Lane::Bulk);
            }
            RetiredPacket::Output(output) => panic!("unexpected output: {output:?}"),
            RetiredPacket::Outbound(packet) => panic!("unexpected outbound: {packet:?}"),
        }
        assert_eq!(turn.drops().len(), 1);
        assert_eq!(turn.drops()[0].reason, PacketDropReason::CryptoFailed);
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
                b"after rekey".to_vec(),
            ))
            .unwrap();

        let turn = run_aead_available(&mut mover, 8);
        assert_eq!(turn.dispatched(), 1);
        match &turn.retired()[0] {
            RetiredPacket::Drop(drop) => {
                assert_eq!(drop.reason, PacketDropReason::CryptoFailed);
                assert_eq!(drop.counter, Some(0));
            }
            RetiredPacket::Output(output) => panic!("unexpected output: {output:?}"),
            RetiredPacket::Outbound(packet) => panic!("unexpected outbound: {packet:?}"),
        }
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

        let inbound_a = SocketPacket::from_fmp_established_wire(
            owner,
            1,
            OutputTarget::Tun,
            fmp_encrypted_wire(73, 1000, 0, b"in-a", open_key),
        )
        .unwrap()
        .with_source_path(path_a.clone());
        mover.submit_socket_packet(inbound_a).unwrap();
        let turn = run_aead_available(&mut mover, 8);
        assert!(turn.drops().is_empty());
        assert_eq!(turn.outputs()[0].path(), None);
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
                b"out-a".to_vec(),
            ))
            .unwrap();
        let turn = run_aead_available(&mut mover, 8);
        let output = turn.outputs()[0];
        assert_eq!(output.counter, 500);
        assert_eq!(output.target, OutputTarget::Transport);
        assert_eq!(output.path(), Some(path_a));
        assert_eq!(open_sealed_output(output, seal_key), b"out-a");

        let inbound_b = SocketPacket::from_fmp_established_wire(
            owner,
            1,
            OutputTarget::Tun,
            fmp_encrypted_wire(73, 1001, 0, b"in-b", open_key),
        )
        .unwrap()
        .with_source_path(path_b.clone());
        mover.submit_socket_packet(inbound_b).unwrap();
        let turn = run_aead_available(&mut mover, 8);
        assert!(turn.drops().is_empty());
        assert_eq!(turn.outputs()[0].path(), None);
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
                b"out-b".to_vec(),
            ))
            .unwrap();
        let turn = run_aead_available(&mut mover, 8);
        let output = turn.outputs()[0];
        assert_eq!(output.counter, 501);
        assert_eq!(output.path(), Some(path_b));
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
                    OutputTarget::Tun,
                    b"stale".to_vec(),
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
                packet(owner, 1, 1, PacketClass::Bulk, OutputTarget::Tun)
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
                packet(owner, 1, 1, PacketClass::Bulk, OutputTarget::Tun)
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
                packet(owner, 0, 2, PacketClass::Bulk, OutputTarget::Tun)
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
            PacketMover2FspWrapRoute::new(next_hop, 1, 7878, test_node_addr(1), owner.node_addr());
        let mut mover = mover();
        mover.register_owner(owner, OwnerConfig::new(1, 8).with_next_send_counter(10));

        let outbound = OutboundPacket::fsp(owner, 1, PacketClass::Bulk, 0, b"payload".to_vec())
            .with_fsp_inner_header(crate::protocol::SessionMessageType::EndpointData.to_byte(), 0)
            .with_post_seal(OutboundPostSeal::FmpWrap(wrap))
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
                owner,
                owner.node_addr(),
                crate::protocol::SessionMessageType::EndpointData.to_byte(),
                11,
                sync(1, 11),
                Some(ActivityTick::new(110)),
                std::time::Instant::now(),
            )
            .is_some());
        let activity = mover.owner_fsp_activity(owner).unwrap();
        assert_eq!(activity.last_rx_data_age_ms(115), Some(5));
        assert!(!activity.has_recent_outbound_without_inbound(115, 20));
        assert_eq!(mover.record_fsp_decrypt_failure(owner), Some(1));

        assert!(mover
            .record_authenticated_fsp_session(
                owner,
                next_hop.node_addr(),
                crate::protocol::SessionMessageType::EndpointData.to_byte(),
                13,
                sync(2, 13),
                Some(ActivityTick::new(120)),
                std::time::Instant::now(),
            )
            .is_some());
        let activity = mover.owner_fsp_activity(owner).unwrap();
        assert_eq!(activity.last_rx_age_ms(125), Some(5));
        assert_eq!(activity.last_rx_data_age_ms(125), Some(5));

        assert!(mover
            .record_authenticated_fsp_session(
                owner,
                test_node_addr(179),
                crate::protocol::SessionMessageType::EndpointData.to_byte(),
                17,
                sync(3, 17),
                Some(ActivityTick::new(130)),
                std::time::Instant::now(),
            )
            .is_some());
        let activity = mover.owner_fsp_activity(owner).unwrap();
        assert_eq!(activity.last_rx_age_ms(135), Some(5));
        assert_eq!(activity.last_rx_data_age_ms(135), Some(15));
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

        let outbound = OutboundPacket::fsp(owner, 1, PacketClass::Mmp, 0, b"sender".to_vec())
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
                owner,
                owner.node_addr(),
                crate::protocol::SessionMessageType::EndpointData.to_byte(),
                5,
                sync,
                Some(ActivityTick::new(1_030)),
                std::time::Instant::now(),
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
                owner,
                owner.node_addr(),
                crate::protocol::SessionMessageType::EndpointData.to_byte(),
                0,
                sync,
                Some(ActivityTick::new(1_010)),
                std::time::Instant::now(),
            ),
            Some(true)
        );
        assert_eq!(
            mover.record_authenticated_fsp_session(
                owner,
                owner.node_addr(),
                crate::protocol::SessionMessageType::EndpointData.to_byte(),
                0,
                FspReceiveSync { counter: 2, ..sync },
                Some(ActivityTick::new(1_020)),
                std::time::Instant::now(),
            ),
            Some(false)
        );

        mover.owner_mut(owner).unwrap().rekey(2);
        assert_eq!(
            mover.record_authenticated_fsp_session(
                owner,
                owner.node_addr(),
                crate::protocol::SessionMessageType::EndpointData.to_byte(),
                0,
                FspReceiveSync { counter: 3, ..sync },
                Some(ActivityTick::new(1_030)),
                std::time::Instant::now(),
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
                OutputTarget::Tun,
                fsp_encrypted_wire(10, 0, b"old-before", old_key),
            ))
            .unwrap();
        let turn = run_aead_available(&mut mover, 8);
        assert!(turn.drops().is_empty());
        assert_eq!(&turn.outputs()[0].payload[FSP_HEADER_SIZE..], b"old-before");

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
                OutputTarget::Tun,
                fsp_encrypted_wire(11, 0, b"old-after", old_key),
            ))
            .unwrap();
        let current_epoch_packet = SocketPacket::new(
            owner,
            2,
            1,
            PacketClass::Bulk,
            OutputTarget::Tun,
            fsp_encrypted_wire(
                1,
                crate::node::session_wire::FSP_FLAG_K,
                b"new-after",
                new_key,
            ),
        )
        .with_wire_flags(crate::node::session_wire::FSP_FLAG_K);
        mover
            .submit_socket_packet(current_epoch_packet)
            .unwrap();

        let turn = run_aead_available(&mut mover, 8);
        assert!(turn.drops().is_empty(), "{:?}", turn.drops());
        let outputs = turn.outputs();
        assert_eq!(outputs.len(), 2);
        assert_eq!(&outputs[0].payload[FSP_HEADER_SIZE..], b"old-after");
        assert_eq!(&outputs[1].payload[FSP_HEADER_SIZE..], b"new-after");
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
                    OutputTarget::Tun,
                    fsp_encrypted_wire(
                        1,
                        crate::node::session_wire::FSP_FLAG_K,
                        b"pending-new",
                        new_key,
                    ),
                )
                .with_wire_flags(crate::node::session_wire::FSP_FLAG_K),
            )
            .unwrap();
        let turn = run_aead_available(&mut mover, 8);
        assert!(turn.drops().is_empty(), "{:?}", turn.drops());
        assert_eq!(&turn.outputs()[0].payload[FSP_HEADER_SIZE..], b"pending-new");

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
                    OutputTarget::Tun,
                    fsp_encrypted_wire(
                        1,
                        crate::node::session_wire::FSP_FLAG_K,
                        b"replay",
                        new_key,
                    ),
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
                owner,
                owner.node_addr(),
                crate::protocol::SessionMessageType::EndpointData.to_byte(),
                1200,
                sync,
                Some(ActivityTick::new(1_040)),
                std::time::Instant::now(),
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
            Ok(PacketMover2FspPathMtuApplyResult::Changed(
                PacketMover2FspPathMtuChange {
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
            Ok(PacketMover2FspPathMtuApplyResult::Unchanged)
        );
    }

    #[test]
    fn hard_event_liveness_state_stays_owner_owned_across_rekey() {
        let owner = fmp_owner(79);
        let mut state = OwnerState::new(owner, OwnerConfig::new(1, 8));

        state.record_hard_event(ActivityTick::new(100));
        state.record_hard_event(ActivityTick::new(90));
        assert_eq!(state.hard_events(), 2);
        assert_eq!(state.last_hard_event(), Some(ActivityTick::new(100)));

        state.rekey(2);
        assert_eq!(state.hard_events(), 2);
        assert_eq!(state.last_hard_event(), Some(ActivityTick::new(100)));
        assert_eq!(state.last_rx_activity(), None);
        assert_eq!(state.last_tx_activity(), None);
    }

    #[test]
    fn runtime_turn_driver_runs_classified_inbound_and_outbound_once() {
        let owner = fmp_owner(78);
        let open_key = 31;
        let seal_key = 32;
        let path = live_path(7800);
        let mut driver = PacketMover2TurnDriver::new(AdmissionConfig::new(4, 8));
        driver.register_owner(owner, OwnerConfig::new(1, 8).with_next_send_counter(300));
        driver
            .owner_mut(owner)
            .unwrap()
            .set_crypto_keys(OwnerCryptoKeys::new(test_key(open_key), test_key(seal_key)));

        let inbound = SocketPacket::from_fmp_established_wire(
            owner,
            1,
            OutputTarget::Tun,
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
            b"outbound".to_vec(),
        )
        .with_activity_tick(ActivityTick::new(11));

        let turn = run_aead_classified_turn(&mut driver, [inbound], [outbound], 8);
        assert_eq!(
            turn.summary(),
            PacketMover2RuntimeSummary {
                raw_ingress_dropped: 0,
                inbound_admitted: 1,
                inbound_dropped: 0,
                outbound_admitted: 1,
                outbound_dropped: 0,
                completions: 0,
                dispatched: 2,
                outputs: 2,
                outputs_sent: 0,
                outputs_dropped: 0,
                drops: 0,
            }
        );
        assert!(turn.drops().is_empty());

        let outputs = turn.outputs();
        assert_eq!(outputs[0].target, OutputTarget::Tun);
        assert_eq!(outputs[0].counter, 100);
        assert_eq!(
            &outputs[0].payload[FMP_ESTABLISHED_HEADER_SIZE..],
            b"inbound"
        );
        assert_eq!(outputs[0].path(), None);

        assert_eq!(outputs[1].target, OutputTarget::Transport);
        assert_eq!(outputs[1].counter, 300);
        assert_eq!(outputs[1].path(), Some(path.clone()));
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
        let mut driver = PacketMover2TurnDriver::new(AdmissionConfig::new(4, 8));
        driver.register_owner(owner, OwnerConfig::new(1, 8));

        driver
            .mover
            .submit_socket_packet(
                SocketPacket::from_fmp_established_wire(
                    owner,
                    1,
                    OutputTarget::Tun,
                    fmp_encrypted_wire(80, 100, 0, b"completion-only", open_key),
                )
                .unwrap(),
            )
            .unwrap();

        let mut work = dispatch_available(&mut driver.mover, 8);
        assert_eq!(work.len(), 1);
        assert_eq!(driver.owner_mut(owner).unwrap().in_flight, 1);

        let worker = StatelessAeadOpenWorker;
        let open_work =
            AeadOpenWork::from_crypto_work(work.pop().unwrap(), test_key(open_key)).unwrap();
        let completion = worker.execute(open_work);

        {
            let turn = run_aead_completion_turn(&mut driver, [completion], 8);
            assert_eq!(
                turn.summary(),
                PacketMover2RuntimeSummary {
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
            assert_eq!(turn.outputs()[0].target(), OutputTarget::Tun);
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
        let mut driver = PacketMover2TurnDriver::new(AdmissionConfig::new(4, 8));
        driver.register_owner(owner, OwnerConfig::new(1, 8));

        let packets: [(u64, &[u8]); 3] = [(100, b"first"), (101, b"second"), (102, b"third")];
        for (counter, payload) in packets {
            driver
                .mover
                .submit_socket_packet(
                    SocketPacket::from_fmp_established_wire(
                        owner,
                        1,
                        OutputTarget::Tun,
                        fmp_encrypted_wire(84, counter, 0, payload, open_key),
                    )
                    .unwrap(),
                )
                .unwrap();
        }

        let mut work = dispatch_available(&mut driver.mover, 8);
        assert_eq!(work.len(), 3);

        let worker = StatelessAeadOpenWorker;
        let mut completions = work
            .drain(..)
            .map(|work| {
                worker.execute(AeadOpenWork::from_crypto_work(work, test_key(open_key)).unwrap())
            })
            .collect::<VecDeque<_>>();
        let third = completions.pop_back().unwrap();
        let first = completions.pop_front().unwrap();
        let second = completions.pop_front().unwrap();

        let mut raw_ingress = VecDeque::new();
        let mut outbound = VecDeque::new();
        let mut sink = BatchRecordingOutputSink::default();
        let mut completion_source = VecDeque::from([third]);

        {
            let turn = pump_aead_output_completion_turn(&mut driver,
                &mut completion_source,
                8,
                &mut raw_ingress,
                &mut NullIngressRouter,
                0,
                &mut outbound,
                0,
                &mut sink,
                8,
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

        completion_source.extend([first, second]);
        {
            let turn = pump_aead_output_completion_turn(&mut driver,
                &mut completion_source,
                8,
                &mut raw_ingress,
                &mut NullIngressRouter,
                0,
                &mut outbound,
                0,
                &mut sink,
                8,
            );
            assert_eq!(turn.summary().completions(), 2);
            assert_eq!(turn.summary().outputs(), 3);
            assert_eq!(turn.summary().outputs_sent(), 3);
            assert!(turn.outputs().is_empty());
            assert!(turn.drops().is_empty());
        }

        assert!(completion_source.is_empty());
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
    fn completion_batch_source_preserves_leftover_batch_order_when_limited() {
        let owner = fmp_owner(85);
        let open_key = 85;
        let mut driver = PacketMover2TurnDriver::new(AdmissionConfig::new(4, 8));
        driver.register_owner(owner, OwnerConfig::new(1, 8));

        let packets: [(u64, &[u8]); 3] = [(100, b"first"), (101, b"second"), (102, b"third")];
        for (counter, payload) in packets {
            driver
                .mover
                .submit_socket_packet(
                    SocketPacket::from_fmp_established_wire(
                        owner,
                        1,
                        OutputTarget::Tun,
                        fmp_encrypted_wire(85, counter, 0, payload, open_key),
                    )
                    .unwrap(),
                )
                .unwrap();
        }

        let mut work = dispatch_available(&mut driver.mover, 8);
        assert_eq!(work.len(), 3);

        let worker = StatelessAeadOpenWorker;
        let completions = work
            .drain(..)
            .map(|work| {
                worker.execute(AeadOpenWork::from_crypto_work(work, test_key(open_key)).unwrap())
            })
            .collect::<Vec<_>>();

        let mut raw_ingress = VecDeque::new();
        let mut outbound = VecDeque::new();
        let mut sink = BatchRecordingOutputSink::default();
        let mut completion_source = VecDeque::from([completions]);

        {
            let turn = pump_aead_output_completion_turn(&mut driver,
                &mut completion_source,
                2,
                &mut raw_ingress,
                &mut NullIngressRouter,
                0,
                &mut outbound,
                0,
                &mut sink,
                8,
            );
            assert_eq!(turn.summary().completions(), 2);
            assert_eq!(turn.summary().outputs_sent(), 2);
            assert!(turn.drops().is_empty());
        }
        assert_eq!(completion_source.len(), 1);
        assert_eq!(completion_source[0].len(), 1);
        assert_eq!(completion_source[0][0].reservation.counter, 102);
        assert_eq!(
            sink.outputs
                .iter()
                .map(PacketOutput::counter)
                .collect::<Vec<_>>(),
            vec![100, 101]
        );

        {
            let turn = pump_aead_output_completion_turn(&mut driver,
                &mut completion_source,
                8,
                &mut raw_ingress,
                &mut NullIngressRouter,
                0,
                &mut outbound,
                0,
                &mut sink,
                8,
            );
            assert_eq!(turn.summary().completions(), 1);
            assert_eq!(turn.summary().outputs_sent(), 1);
            assert!(turn.drops().is_empty());
        }
        assert!(completion_source.is_empty());
        assert_eq!(
            sink.outputs
                .iter()
                .map(PacketOutput::counter)
                .collect::<Vec<_>>(),
            vec![100, 101, 102]
        );
        assert_eq!(driver.owner_mut(owner).unwrap().in_flight, 0);
    }

    #[test]
    fn completion_only_turn_retires_out_of_order_completions_in_owner_order() {
        let owner = fmp_owner(81);
        let open_key = 81;
        let mut driver = PacketMover2TurnDriver::new(AdmissionConfig::new(4, 8));
        driver.register_owner(owner, OwnerConfig::new(1, 8));

        let packets: [(u64, &[u8]); 3] = [(100, b"first"), (101, b"second"), (102, b"third")];
        for (counter, payload) in packets {
            driver
                .mover
                .submit_socket_packet(
                    SocketPacket::from_fmp_established_wire(
                        owner,
                        1,
                        OutputTarget::Tun,
                        fmp_encrypted_wire(81, counter, 0, payload, open_key),
                    )
                    .unwrap(),
                )
                .unwrap();
        }

        let mut work = dispatch_available(&mut driver.mover, 8);
        assert_eq!(work.len(), 3);
        assert_eq!(driver.owner_mut(owner).unwrap().in_flight, 3);

        let worker = StatelessAeadOpenWorker;
        let mut completions = work
            .drain(..)
            .map(|work| {
                worker.execute(AeadOpenWork::from_crypto_work(work, test_key(open_key)).unwrap())
            })
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
        let mut driver = PacketMover2TurnDriver::new(AdmissionConfig::new(4, 8));
        driver.register_owner(owner, OwnerConfig::new(1, 8));

        driver
            .mover
            .submit_socket_packet(
                SocketPacket::from_fmp_established_wire(
                    owner,
                    1,
                    OutputTarget::Tun,
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
                SocketPacket::from_fmp_established_wire(
                    owner,
                    2,
                    OutputTarget::Tun,
                    fmp_encrypted_wire(82, 101, 0, b"new", open_key),
                )
                .unwrap(),
            )
            .unwrap();
        let mut new_work = dispatch_available(&mut driver.mover, 8);
        assert_eq!(new_work.len(), 1);
        assert_eq!(driver.owner_mut(owner).unwrap().in_flight, 2);

        let worker = StatelessAeadOpenWorker;
        let old_completion = worker.execute(
            AeadOpenWork::from_crypto_work(old_work.pop().unwrap(), test_key(open_key)).unwrap(),
        );
        let new_completion = worker.execute(
            AeadOpenWork::from_crypto_work(new_work.pop().unwrap(), test_key(open_key)).unwrap(),
        );

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
        let mut driver = PacketMover2TurnDriver::new(AdmissionConfig::new(4, 8));
        driver.register_owner(
            owner,
            OwnerConfig::new(1, 3)
                .with_bulk_in_flight_limit(1)
                .with_next_send_counter(10),
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
                b"bulk-1".to_vec(),
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
                b"bulk-2".to_vec(),
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
                b"priority".to_vec(),
            ))
            .unwrap();

        let worker = StatelessAeadSealWorker;
        let completion = worker.execute(
            AeadSealWork::from_outbound_work(seal_work.pop().unwrap(), test_key(seal_key))
                .unwrap(),
        );

        {
            let turn = run_aead_completion_turn(&mut driver, [completion], 1);
            assert_eq!(turn.summary().dispatched(), 1);
            assert_eq!(turn.summary().outputs(), 2);
            assert!(turn.drops().is_empty());
            assert_eq!(turn.outputs()[0].counter(), 10);
            assert_eq!(turn.outputs()[0].target(), OutputTarget::Transport);
            assert_eq!(turn.outputs()[0].path(), Some(path.clone()));
            assert_eq!(open_sealed_output(&turn.outputs()[0], seal_key), b"bulk-1");
            assert_eq!(turn.outputs()[1].counter(), 11);
            assert_eq!(turn.outputs()[1].target(), OutputTarget::Transport);
            assert_eq!(turn.outputs()[1].path(), Some(path));
            assert_eq!(
                open_sealed_output(&turn.outputs()[1], seal_key),
                b"priority"
            );
        }

        assert_eq!(driver.owner_mut(owner).unwrap().in_flight, 0);
        assert_eq!(outbound_queue_lens(&driver.mover), (0, 1));
    }

    #[test]
    fn completion_only_turn_continues_fsp_post_seal_wrap_to_fmp_output() {
        let source = NodeAddr::from_bytes([0x80; 16]);
        let dest = NodeAddr::from_bytes([0x81; 16]);
        let next_hop = NodeAddr::from_bytes([0x82; 16]);
        let fsp_owner = OwnerId::fsp_node(dest);
        let fmp_owner = OwnerId::fmp_node(next_hop);
        let fsp_key = 81;
        let fmp_key = 82;
        let fmp_path = live_path(8200);
        let mut driver = PacketMover2TurnDriver::new(AdmissionConfig::new(4, 8));
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

        let wrap = PacketMover2FspWrapRoute::new(fmp_owner, 1, 8282, source, dest)
            .with_ttl(42)
            .with_path_mtu(1280);
        let packet = OutboundPacket::fsp(
            fsp_owner,
            1,
            PacketClass::Liveness,
            0x03,
            b"wake-wrap".to_vec(),
        )
        .with_fsp_cleartext_prefix(empty_fsp_coords_prefix())
        .with_post_seal(OutboundPostSeal::FmpWrap(wrap));

        driver.mover.submit_outbound_packet(packet).unwrap();
        let mut seal_work = dispatch_outbound_available(&mut driver.mover, 1);
        assert_eq!(seal_work.len(), 1);
        assert_eq!(driver.owner_mut(fsp_owner).unwrap().in_flight, 1);

        let worker = StatelessAeadSealWorker;
        let completion = worker.execute(
            AeadSealWork::from_outbound_work(seal_work.pop().unwrap(), test_key(fsp_key)).unwrap(),
        );

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
            assert_eq!(output.path(), Some(fmp_path));

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
    fn failed_fsp_post_seal_wrap_releases_inner_owner_only() {
        let source = NodeAddr::from_bytes([0x83; 16]);
        let dest = NodeAddr::from_bytes([0x84; 16]);
        let next_hop = NodeAddr::from_bytes([0x85; 16]);
        let fsp_owner = OwnerId::fsp_node(dest);
        let fmp_owner = OwnerId::fmp_node(next_hop);
        let fmp_path = live_path(8500);
        let mut driver = PacketMover2TurnDriver::new(AdmissionConfig::new(4, 8));
        driver.register_owner(fsp_owner, OwnerConfig::new(1, 8).with_next_send_counter(50));
        driver.register_owner(fmp_owner, OwnerConfig::new(1, 8).with_next_send_counter(70));
        driver
            .owner_mut(fmp_owner)
            .unwrap()
            .set_active_path(fmp_path);

        let wrap = PacketMover2FspWrapRoute::new(fmp_owner, 1, 8585, source, dest)
            .with_ttl(42)
            .with_path_mtu(1280);
        let packet = OutboundPacket::fsp(
            fsp_owner,
            1,
            PacketClass::ReliableBulk,
            0x03,
            b"failed-wrap".to_vec(),
        )
        .with_fsp_cleartext_prefix(empty_fsp_coords_prefix())
        .with_post_seal(OutboundPostSeal::FmpWrap(wrap));

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
        let mut driver = PacketMover2TurnDriver::new(AdmissionConfig::new(1, 1));
        driver.register_owner(owner, OwnerConfig::new(1, 8));

        let first = SocketPacket::from_fsp_established_wire(
            owner,
            1,
            OutputTarget::Tun,
            fsp_encrypted_wire(10, 0, b"first", 40),
        )
        .unwrap();
        let second = SocketPacket::from_fsp_established_wire(
            owner,
            1,
            OutputTarget::Tun,
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
        assert_eq!(admission_drop.ingress_seq(), None);
        assert_eq!(admission_drop.lane(), Lane::Bulk);

        let crypto_drop = turn
            .drops()
            .iter()
            .find(|drop| drop.reason() == PacketDropReason::CryptoFailed)
            .expect("crypto drop");
        assert_eq!(crypto_drop.owner(), owner);
        assert_eq!(crypto_drop.counter(), Some(10));
        assert_eq!(crypto_drop.ingress_seq(), Some(0));
        assert_eq!(crypto_drop.lane(), Lane::Bulk);
    }

    #[test]
    fn runtime_turn_driver_reuses_output_buffers() {
        let owner = fsp_owner(80);
        let key = 41;
        let mut driver = PacketMover2TurnDriver::new(AdmissionConfig::new(4, 8));
        driver.register_owner(owner, OwnerConfig::new(1, 8).with_next_send_counter(20));
        driver
            .owner_mut(owner)
            .unwrap()
            .set_crypto_keys(OwnerCryptoKeys::new(test_key(key), test_key(key)));

        let inbound = SocketPacket::from_fsp_established_wire(
            owner,
            1,
            OutputTarget::Endpoint,
            fsp_encrypted_wire(50, 0, b"in", key),
        )
        .unwrap();
        let outbound = OutboundPacket::fsp(owner, 1, PacketClass::Bulk, 0, b"out".to_vec());
        {
            let turn = run_aead_classified_turn(&mut driver, [inbound], [outbound], 8);
            assert_eq!(turn.outputs().len(), 2);
            assert!(turn.drops().is_empty());
        }

        let capacities = (
            driver.raw_ingress_drops.capacity(),
            driver.output_drops.capacity(),
            driver.outputs.capacity(),
            driver.drops.capacity(),
        );
        let turn = run_aead_classified_turn(&mut driver, std::iter::empty(), std::iter::empty(), 8);
        assert_eq!(turn.summary(), PacketMover2RuntimeSummary::default());
        assert!(turn.outputs().is_empty());
        assert!(turn.drops().is_empty());
        assert_eq!(
            capacities,
            (
                driver.raw_ingress_drops.capacity(),
                driver.output_drops.capacity(),
                driver.outputs.capacity(),
                driver.drops.capacity(),
            )
        );
    }

    struct FixedIngressRouter {
        route: Option<PacketMover2IngressRoute>,
    }

    impl PacketMover2IngressRouter for FixedIngressRouter {
        fn route(
            &mut self,
            packet: &PacketMover2RawIngress,
            header: PacketMover2IngressHeader,
        ) -> Option<PacketMover2IngressRoute> {
            assert_eq!(packet.transport_id(), TransportId::new(5));
            assert_eq!(
                packet.remote_addr(),
                &TransportAddr::from_string("198.51.100.9:9000")
            );
            assert_eq!(packet.path(), live_path(9005));
            assert_eq!(packet.activity_tick(), Some(ActivityTick::new(123_456)));
            assert_eq!(
                packet.payload_len(),
                FMP_ESTABLISHED_HEADER_SIZE + b"raw-in".len() + AEAD_TAG_SIZE
            );
            assert_eq!(packet.protocol(), PacketProtocol::Fmp);
            assert!(matches!(header, PacketMover2IngressHeader::Fmp(_)));
            assert_eq!(header.counter(), 1200);
            self.route
        }
    }

    struct NullIngressRouter;

    impl PacketMover2IngressRouter for NullIngressRouter {
        fn route(
            &mut self,
            _packet: &PacketMover2RawIngress,
            _header: PacketMover2IngressHeader,
        ) -> Option<PacketMover2IngressRoute> {
            None
        }
    }

    #[derive(Default)]
    struct RecordingOutputSink {
        outputs: Vec<PacketOutput>,
        fail_counter: Option<u64>,
    }

    impl PacketMover2OutputSink for RecordingOutputSink {
        fn send(&mut self, output: PacketOutput) -> Result<(), PacketMover2OutputError> {
            if Some(output.counter) == self.fail_counter {
                return Err(PacketMover2OutputError::Backpressure);
            }
            self.outputs.push(output);
            Ok(())
        }
    }

    #[derive(Default)]
    struct BatchRecordingOutputSink {
        batch_calls: usize,
        outputs: Vec<PacketOutput>,
    }

    impl PacketMover2OutputSink for BatchRecordingOutputSink {
        fn send(&mut self, _output: PacketOutput) -> Result<(), PacketMover2OutputError> {
            panic!("batch sink must not use per-output send")
        }

        fn send_batch<I>(&mut self, outputs: I, drops: &mut Vec<PacketMover2OutputDrop>) -> usize
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

    #[derive(Clone, Debug, Eq, PartialEq)]
    struct LiveOutputRecord {
        owner: OwnerId,
        counter: u64,
        ingress_seq: u64,
        payload: Vec<u8>,
    }

    impl LiveOutputRecord {
        fn from_opened(output: &PacketOutput, payload: &[u8]) -> Self {
            Self {
                owner: output.owner(),
                counter: output.counter(),
                ingress_seq: output.ingress_seq(),
                payload: payload.to_vec(),
            }
        }
    }

    #[derive(Default)]
    struct LiveTunRecorder {
        outputs: Vec<LiveOutputRecord>,
    }

    impl PacketMover2TunOutput for LiveTunRecorder {
        fn send_tun(
            &mut self,
            output: &PacketOutput,
            payload: PacketBuffer,
        ) -> Result<(), PacketMover2OutputError> {
            let payload = payload.into_vec();
            self.outputs
                .push(LiveOutputRecord::from_opened(output, &payload));
            Ok(())
        }
    }

    #[derive(Default)]
    struct LiveEndpointRecorder {
        outputs: Vec<LiveOutputRecord>,
    }

    impl PacketMover2EndpointOutput for LiveEndpointRecorder {
        fn send_endpoint(
            &mut self,
            output: &PacketOutput,
            payload: PacketBuffer,
        ) -> Result<(), PacketMover2OutputError> {
            let payload = payload.into_vec();
            self.outputs
                .push(LiveOutputRecord::from_opened(output, &payload));
            Ok(())
        }
    }

    #[derive(Clone, Debug, Eq, PartialEq)]
    struct LiveTransportRecord {
        transport_id: TransportId,
        remote_addr: TransportAddr,
        owner: OwnerId,
        counter: u64,
        ingress_seq: u64,
        payload: Vec<u8>,
    }

    #[derive(Default)]
    struct LiveTransportRecorder {
        outputs: Vec<LiveTransportRecord>,
    }

    impl PacketMover2TransportOutput for LiveTransportRecorder {
        fn send_transport(
            &mut self,
            transport_id: TransportId,
            remote_addr: TransportAddr,
            output: PacketOutput,
        ) -> Result<(), PacketMover2OutputError> {
            self.outputs.push(LiveTransportRecord {
                transport_id,
                remote_addr,
                owner: output.owner(),
                counter: output.counter(),
                ingress_seq: output.ingress_seq(),
                payload: output.payload().to_vec(),
            });
            Ok(())
        }
    }

    struct SimpleIngressRouter {
        owner: OwnerId,
        generation: u64,
        class: PacketClass,
        output: OutputTarget,
    }

    impl PacketMover2IngressRouter for SimpleIngressRouter {
        fn route(
            &mut self,
            _packet: &PacketMover2RawIngress,
            _header: PacketMover2IngressHeader,
        ) -> Option<PacketMover2IngressRoute> {
            Some(
                PacketMover2IngressRoute::new(self.owner, self.generation, self.output)
                    .with_class(self.class),
            )
        }
    }
