#[test]
fn background_backlog_yields_to_control_and_normal_for_the_same_owner() {
    let mut mover = Dataplane::new(AdmissionConfig::new(8, 128));
    let owner = fmp_owner(31_000);
    mover.register_owner(owner, OwnerConfig::new(1, 128));
    let free = (0..64)
        .map(|_| outbound_packet(owner, 1, PacketClass::Background, b"free"))
        .collect();
    assert_eq!(mover.submit_outbound_packet_batch(free), (64, 0));
    for class in [PacketClass::Bulk, PacketClass::Control] {
        mover
            .submit_outbound_packet(outbound_packet(owner, 1, class, b"higher"))
            .unwrap();
    }
    let dispatched = dispatch_outbound_available(&mut mover, 64);
    assert_eq!(dispatched.len(), 3);
    assert_eq!(
        dispatched
            .iter()
            .map(|work| work.reservation.lane)
            .collect::<Vec<_>>(),
        [Lane::Priority, Lane::Bulk, Lane::Background]
    );
    assert_eq!(mover.owner_mut(owner).unwrap().background_in_flight, 1);
    assert_eq!(mover.outbound_admission_lens.background, 63);
}

#[test]
fn background_inbound_backlog_yields_to_normal_for_the_same_owner() {
    let mut mover = Dataplane::new(AdmissionConfig::new(8, 128));
    let owner = fmp_owner(31_001);
    mover.register_owner(owner, OwnerConfig::new(1, 128));
    let free = (0..32)
        .map(|counter| {
            packet(
                owner,
                1,
                counter,
                PacketClass::Background,
                OutputTarget::Transport,
            )
        })
        .collect();
    assert_eq!(mover.submit_socket_packet_batch(free), (32, 0));
    mover
        .submit_socket_packet(packet(
            owner,
            1,
            32,
            PacketClass::Bulk,
            OutputTarget::Transport,
        ))
        .unwrap();
    let dispatched = dispatch_available(&mut mover, 32);
    assert_eq!(dispatched.len(), 2);
    assert_eq!(dispatched[0].reservation.lane, Lane::Bulk);
    assert_eq!(dispatched[1].reservation.lane, Lane::Background);
    assert_eq!(mover.admission_lens.background, 31);
}

#[test]
fn background_admission_overflow_preserves_normal_and_control_capacity() {
    let mut mover = Dataplane::new(AdmissionConfig::new(2, 128));
    let owner = fmp_owner(31_002);
    let free = (0..80)
        .map(|_| outbound_packet(owner, 1, PacketClass::Background, b"free"))
        .collect();
    assert_eq!(mover.submit_outbound_packet_batch(free), (64, 16));
    assert_eq!(
        mover
            .submit_outbound_packet(outbound_packet(owner, 1, PacketClass::Background, b"free"))
            .unwrap_err()
            .reason,
        AdmissionDropReason::Background
    );
    let paid = (0..128)
        .map(|_| outbound_packet(owner, 1, PacketClass::Bulk, b"paid"))
        .collect();
    assert_eq!(mover.submit_outbound_packet_batch(paid), (128, 0));
    for _ in 0..2 {
        mover
            .submit_outbound_packet(outbound_packet(owner, 1, PacketClass::Control, b"control"))
            .unwrap();
    }
    assert_eq!(
        mover.outbound_admission_lens,
        LaneLens {
            priority: 2,
            bulk: 128,
            background: 64
        }
    );
    let free = (0..80)
        .map(|counter| {
            packet(
                owner,
                1,
                counter,
                PacketClass::Background,
                OutputTarget::Transport,
            )
        })
        .collect();
    assert_eq!(mover.submit_socket_packet_batch(free), (64, 16));
    for class in [PacketClass::Bulk, PacketClass::Control] {
        mover
            .submit_socket_packet(packet(owner, 1, 100, class, OutputTarget::Transport))
            .unwrap();
    }
}

fn background_prepared_runs(count: usize) -> (Dataplane, Vec<PreparedCryptoRun>) {
    let mut mover = Dataplane::new(AdmissionConfig::new(8, 128));
    for n in 0..count {
        let owner = fmp_owner(32_000 + n as u64);
        mover.register_owner(owner, OwnerConfig::new(1, 128));
        mover
            .submit_outbound_packet(outbound_packet(owner, 1, PacketClass::Background, b"free"))
            .unwrap();
    }
    seed_missing_test_owner_keys(&mut mover);
    let pool = test_aead_worker_pool(128);
    let mut prepared = Vec::new();
    let mut ready = Vec::new();
    let dispatched = mover.prepare_aead_available_into(128, &mut prepared, &mut ready, &pool);
    assert_eq!(dispatched, count.min(4));
    assert!(ready.is_empty());
    (mover, prepared)
}

#[test]
fn background_worker_window_keeps_room_for_normal_and_control() {
    let (mut mover, mut prepared) = background_prepared_runs(8);
    let mut pool = test_aead_worker_pool(128);
    pool.submit_prepared_chunk(&mut prepared, |slot| mover.stage_retire_slot(slot));
    assert_eq!(pool.available_capacity_for_lane(Lane::Background), 0);
    assert!(pool.available_capacity_for_lane(Lane::Bulk) > 0);
    assert!(pool.available_capacity_for_lane(Lane::Priority) > 0);
    for class in [PacketClass::Bulk, PacketClass::Control] {
        mover
            .submit_outbound_packet(outbound_packet(fmp_owner(32_000), 1, class, b"higher"))
            .unwrap();
    }
    let mut ready = Vec::new();
    assert_eq!(
        mover.prepare_aead_available_into(128, &mut prepared, &mut ready, &pool),
        2
    );
    assert!(prepared.iter().all(|run| run.lane() != Lane::Background));
    pool.submit_prepared_chunk(&mut prepared, |slot| mover.stage_retire_slot(slot));
    let mut outputs = Vec::new();
    while outputs.len() < 6 {
        wait_for_owner_readiness(&mut pool, &mover);
        retire_ready_slots_to_outputs(&mut mover, 6, &mut outputs);
    }
    assert!(mover.drain_drops().is_empty());
    assert_eq!(pool.available_capacity(), 128);
    assert_eq!(pool.available_capacity_for_lane(Lane::Background), 4);
}

#[test]
fn background_crypto_worker_queue_yields_to_queued_normal_and_control() {
    let (mut mover, free_runs) = background_prepared_runs(3);
    let owner = fmp_owner(32_100);
    mover.register_owner(owner, OwnerConfig::new(1, 128));
    seed_missing_test_owner_keys(&mut mover);
    for class in [PacketClass::Bulk, PacketClass::Control] {
        mover
            .submit_outbound_packet(outbound_packet(owner, 1, class, b"higher"))
            .unwrap();
    }
    let pool = test_aead_worker_pool(128);
    let mut higher_runs = Vec::new();
    let mut ready = Vec::new();
    assert_eq!(
        mover.prepare_aead_available_into(128, &mut higher_runs, &mut ready, &pool),
        2
    );
    let queue = CryptoWorkerQueue::new();
    for prepared in free_runs.into_iter().chain(higher_runs) {
        let (run, key) = prepared.into_parts();
        queue.push(pool.prepare_owner_run(run, key));
    }
    queue.close();
    let mut lanes = Vec::new();
    while let Some(run) = queue.pop() {
        lanes.push(run.slot.lane());
    }
    assert_eq!(
        lanes,
        [
            Lane::Priority,
            Lane::Bulk,
            Lane::Background,
            Lane::Background,
            Lane::Background
        ]
    );
}

#[test]
fn background_packets_progress_when_normal_lanes_are_idle() {
    let mut mover = Dataplane::new(AdmissionConfig::new(8, 32));
    let owner = fmp_owner(33_000);
    mover.register_owner(owner, OwnerConfig::new(1, 8));
    seed_missing_test_owner_keys(&mut mover);
    for n in 0..3u8 {
        mover
            .submit_outbound_packet(outbound_packet(owner, 1, PacketClass::Background, &[n]))
            .unwrap();
    }
    let mut pool = test_aead_worker_pool(128);
    let mut outputs = Vec::new();
    for _ in 0..3 {
        let mut prepared = Vec::new();
        let mut ready = Vec::new();
        assert_eq!(
            mover.prepare_aead_available_into(64, &mut prepared, &mut ready, &pool),
            1
        );
        pool.submit_prepared_chunk(&mut prepared, |slot| mover.stage_retire_slot(slot));
        wait_for_owner_readiness(&mut pool, &mover);
        assert_eq!(
            retire_ready_slots_to_outputs(&mut mover, 64, &mut outputs),
            1
        );
        assert_eq!(mover.owner_mut(owner).unwrap().background_in_flight, 0);
    }
    assert_eq!(
        outputs
            .iter()
            .map(|output| open_sealed_output(output, 0))
            .collect::<Vec<_>>(),
        [vec![0], vec![1], vec![2]]
    );
    assert!(
        outputs
            .windows(2)
            .all(|pair| pair[0].counter() < pair[1].counter())
    );
    assert!(!mover.has_runnable_work());
    assert!(mover.drain_drops().is_empty());
}

#[test]
fn background_transport_groups_yield_without_reordering_owner_counters() {
    let mut groups = DataplaneTransportSendGroups::new();
    let transport = TransportId::new(1);
    let remote = TransportAddr::from_string("127.0.0.1:4000");
    let free_owner = fmp_owner(34_000);
    let paid_owner = fmp_owner(34_001);
    let control_owner = fmp_owner(34_002);
    for (owner, counter, lane) in [
        (free_owner, 1, Lane::Background),
        (paid_owner, 1, Lane::Bulk),
        (free_owner, 2, Lane::Bulk),
        (control_owner, 1, Lane::Priority),
    ] {
        let mut output = transport_output(owner, counter, 0, transport, remote.clone(), vec![1]);
        output.lane = lane;
        groups.push_transport(transport, remote.clone(), output);
    }
    let planned = groups.take_groups_preserving_capacity();
    let owners: Vec<_> = planned
        .iter()
        .flat_map(|group| group.outputs.iter())
        .map(|output| (output.owner(), output.counter()))
        .collect();
    assert_eq!(
        owners,
        [
            (control_owner, 1),
            (paid_owner, 1),
            (free_owner, 1),
            (free_owner, 2)
        ]
    );
}

#[test]
fn background_crypto_dependency_does_not_stall_later_control() {
    let (mut mover, free_runs) = background_prepared_runs(1);
    let owner = fmp_owner(32_000);
    mover
        .submit_outbound_packet(outbound_packet(
            owner,
            1,
            PacketClass::Control,
            b"later control",
        ))
        .unwrap();
    let busy_owner = fmp_owner(32_200);
    mover.register_owner(busy_owner, OwnerConfig::new(1, 128));
    seed_missing_test_owner_keys(&mut mover);
    for _ in 0..32 {
        mover
            .submit_outbound_packet(outbound_packet(
                busy_owner,
                1,
                PacketClass::Bulk,
                b"unrelated normal backlog",
            ))
            .unwrap();
    }
    let pool = test_aead_worker_pool(128);
    let mut higher_runs = Vec::new();
    let mut ready = Vec::new();
    assert_eq!(
        mover.prepare_aead_available_into(128, &mut higher_runs, &mut ready, &pool),
        33
    );
    let queue = CryptoWorkerQueue::new();
    for prepared in free_runs.into_iter().chain(higher_runs) {
        let (run, key) = prepared.into_parts();
        queue.push(pool.prepare_owner_run(run, key));
    }
    queue.close();
    let first = queue.pop().unwrap();
    let second = queue.pop().unwrap();
    assert_eq!(first.slot.lane(), Lane::Background);
    assert_eq!(second.slot.lane(), Lane::Priority);
    assert!(first.slot.first_order().0 < second.slot.first_order().0);
    assert_eq!(queue.pop().unwrap().slot.lane(), Lane::Bulk);
    assert!(queue.pop().is_none());
}
