use super::*;

fn inline_receiver(class: PacketClass, payload: &[u8]) -> (Dataplane, DataplaneAeadWorkerPool) {
    let owner = fmp_owner(970);
    let mut mover = mover();
    mover.register_owner(owner, OwnerConfig::new(1, 8));
    mover
        .owner_mut(owner)
        .unwrap()
        .set_crypto_keys(OwnerCryptoKeys::new(test_key(17), test_key(17)));
    let mut packet = fmp_socket_packet(
        owner,
        1,
        OutputTarget::Transport,
        fmp_encrypted_wire(970, 4, 0, payload, 17),
    )
    .unwrap();
    packet.class = class;
    mover.submit_socket_packet(packet).unwrap();
    let mut pool = test_aead_worker_pool(8);
    pool.inline_control_remaining = 1;
    (mover, pool)
}

#[test]
fn small_idle_control_retires_without_waking_crypto_worker() {
    let (mut mover, mut pool) = inline_receiver(PacketClass::Mmp, b"small control");
    let (dispatched, retired, drops) = run_with_worker_pool_limit(&mut mover, &mut pool, 4);
    assert_eq!(dispatched, 1);
    assert!(
        pool.native_executor.is_none(),
        "an isolated small control packet must not require a worker hop"
    );
    assert!(drops.is_empty());
    assert_eq!(retired.len(), 1);
    assert_eq!(
        retired[0].opened_payload(),
        Some(b"small control".as_slice())
    );
    assert_eq!(pool.available_capacity(), 8);
    assert_eq!(pool.inline_control_remaining, 0);
    let notify = pool.readiness_notify();
    let mut notified = std::pin::pin!(notify.notified());
    assert!(
        std::future::Future::poll(
            notified.as_mut(),
            &mut std::task::Context::from_waker(std::task::Waker::noop())
        )
        .is_pending(),
        "already retired inline completion must not schedule an empty turn"
    );
}

#[test]
fn bulk_and_large_priority_packets_keep_worker_offload() {
    for (class, payload) in [
        (PacketClass::Bulk, vec![1; 8]),
        (PacketClass::Background, vec![1; 8]),
        (PacketClass::Control, vec![1; 513]),
    ] {
        let (mut mover, mut pool) = inline_receiver(class, &payload);
        let (dispatched, _, _) = run_with_worker_pool_limit(&mut mover, &mut pool, 4);
        assert_eq!(dispatched, 1);
        assert!(pool.native_executor.is_some());
        assert_eq!(pool.inline_control_remaining, 1);
    }
}

fn next_control(mover: &mut Dataplane, counter: u64, key: u8) {
    let mut packet = fmp_socket_packet(
        fmp_owner(970),
        1,
        OutputTarget::Transport,
        fmp_encrypted_wire(970, counter, 0, b"next control", key),
    )
    .unwrap();
    packet.class = PacketClass::Liveness;
    mover.submit_socket_packet(packet).unwrap();
}

#[test]
fn inline_budget_does_not_refill_when_first_packet_retires() {
    let (mut mover, mut pool) = inline_receiver(PacketClass::Control, b"first");
    let (_, retired, _) = run_with_worker_pool_limit(&mut mover, &mut pool, 4);
    assert_eq!(retired.len(), 1);
    assert!(pool.native_executor.is_none());
    assert_eq!(pool.available_capacity(), 8);
    next_control(&mut mover, 5, 17);
    run_with_worker_pool_limit(&mut mover, &mut pool, 4);
    assert!(
        pool.native_executor.is_some(),
        "a later collect pass in the same turn must offload"
    );
}

#[test]
fn ready_but_unretired_work_prevents_inline_execution() {
    let (mut mover, mut pool) = inline_receiver(PacketClass::Mmp, b"first");
    let mut prepared = Vec::new();
    let mut ready = Vec::new();
    assert_eq!(
        mover.prepare_aead_available_into(1, &mut prepared, &mut ready, &pool),
        1
    );
    mover.stage_retire_slots(&mut ready);
    assert!(pool.submit_prepared_chunk(&mut prepared, |slot| mover.stage_retire_slot(slot)));
    assert_eq!(pool.available_capacity(), 7);
    pool.inline_control_remaining = 1;
    next_control(&mut mover, 5, 17);
    let (_, mut outputs, drops) = run_with_worker_pool_limit(&mut mover, &mut pool, 4);
    assert!(drops.is_empty());
    assert!(
        pool.native_executor.is_some(),
        "ready work still owns its reservation"
    );
    while outputs.len() < 2 {
        wait_for_owner_readiness(&mut pool, &mover);
        retire_ready_slots_to_outputs(&mut mover, 4, &mut outputs);
    }
    assert_eq!(
        outputs
            .iter()
            .map(PacketOutput::counter)
            .collect::<Vec<_>>(),
        vec![4, 5]
    );
    assert_eq!(pool.available_capacity(), 8);
}

#[test]
fn failed_inline_authentication_does_not_consume_replay_counter() {
    let (mut mover, mut pool) = inline_receiver(PacketClass::Mmp, b"wrong key");
    mover
        .owner_mut(fmp_owner(970))
        .unwrap()
        .set_crypto_keys(OwnerCryptoKeys::new(test_key(18), test_key(18)));
    let (_, retired, drops) = run_with_worker_pool_limit(&mut mover, &mut pool, 4);
    assert!(retired.is_empty());
    assert_eq!(drops.len(), 1);
    assert!(pool.native_executor.is_none());
    assert_eq!(pool.available_capacity(), 8);
    pool.inline_control_remaining = 1;
    next_control(&mut mover, 4, 18);
    let (_, retired, drops) = run_with_worker_pool_limit(&mut mover, &mut pool, 4);
    assert!(drops.is_empty());
    assert_eq!(retired.len(), 1);
    assert_eq!(retired[0].counter(), 4);
    assert_eq!(
        retired[0].opened_payload(),
        Some(b"next control".as_slice())
    );
}

#[test]
fn inline_control_sealing_round_trips_through_authenticated_receive() {
    let owner = fmp_owner(970);
    let mut sender = mover();
    sender.register_owner(owner, OwnerConfig::new(1, 8).with_next_send_counter(44));
    sender
        .owner_mut(owner)
        .unwrap()
        .set_crypto_keys(OwnerCryptoKeys::new(test_key(17), test_key(17)));
    sender
        .submit_outbound_packet(outbound_packet(
            owner,
            1,
            PacketClass::Mmp,
            b"outgoing report",
        ))
        .unwrap();
    let mut pool = test_aead_worker_pool(8);
    pool.inline_control_remaining = 1;
    let (_, sealed, drops) = run_with_worker_pool_limit(&mut sender, &mut pool, 4);
    assert!(drops.is_empty());
    assert_eq!(sealed.len(), 1);
    assert!(pool.native_executor.is_none());
    assert_eq!(sealed[0].counter(), 44);
    let mut receiver = mover();
    receiver.register_owner(owner, OwnerConfig::new(1, 8));
    receiver
        .owner_mut(owner)
        .unwrap()
        .set_crypto_keys(OwnerCryptoKeys::new(test_key(17), test_key(17)));
    let mut packet = fmp_socket_packet(
        owner,
        1,
        OutputTarget::Transport,
        sealed[0].payload().to_vec(),
    )
    .unwrap();
    packet.class = PacketClass::Mmp;
    receiver.submit_socket_packet(packet).unwrap();
    pool.inline_control_remaining = 1;
    let (_, opened, drops) = run_with_worker_pool_limit(&mut receiver, &mut pool, 4);
    assert!(drops.is_empty());
    assert_eq!(opened.len(), 1);
    assert_eq!(
        opened[0].opened_payload(),
        Some(b"outgoing report".as_slice())
    );
    assert_eq!(pool.available_capacity(), 8);
}

#[test]
fn inline_completion_releases_capacity_after_owner_cancellation() {
    let (mut mover, mut pool) = inline_receiver(PacketClass::Mmp, b"cancelled");
    let mut prepared = Vec::new();
    let mut ready = Vec::new();
    assert_eq!(
        mover.prepare_aead_available_into(1, &mut prepared, &mut ready, &pool),
        1
    );
    mover.stage_retire_slots(&mut ready);
    assert!(pool.submit_prepared_chunk(&mut prepared, |slot| mover.stage_retire_slot(slot)));
    assert_eq!(pool.available_capacity(), 7);
    assert!(mover.unregister_owner(fmp_owner(970)));
    let mut outputs = Vec::new();
    assert_eq!(
        retire_ready_slots_to_outputs(&mut mover, 1, &mut outputs),
        1
    );
    assert!(outputs.is_empty());
    let drops = mover.drain_drops();
    assert_eq!(drops.len(), 1);
    assert_eq!(drops[0].reason(), PacketDropReason::UnknownOwner);
    assert_eq!(pool.available_capacity(), 8);
}

#[test]
fn authenticated_inline_packet_keeps_replay_protection() {
    let (mut mover, mut pool) = inline_receiver(PacketClass::Mmp, b"first");
    let (_, outputs, drops) = run_with_worker_pool_limit(&mut mover, &mut pool, 4);
    assert_eq!(outputs.len(), 1);
    assert!(drops.is_empty());
    pool.inline_control_remaining = 1;
    next_control(&mut mover, 4, 17);
    let (_, outputs, drops) = run_with_worker_pool_limit(&mut mover, &mut pool, 4);
    assert!(outputs.is_empty());
    assert_eq!(drops.len(), 1);
    assert_eq!(drops[0].reason(), PacketDropReason::Replay);
    assert_eq!(pool.available_capacity(), 8);
}
