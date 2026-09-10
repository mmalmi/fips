fn check_prepared_run_capacity(outbound: bool, count: usize, continuation: bool) {
    let mut mover = Dataplane::new(AdmissionConfig::new(16, 256));
    let owner = fmp_owner(9_100);
    let key = 47;
    let first_counter = 100;
    mover.register_owner(
        owner,
        OwnerConfig::new(1, count + 1).with_next_send_counter(first_counter),
    );
    mover
        .owner_mut(owner)
        .unwrap()
        .set_crypto_keys(OwnerCryptoKeys::new(test_key(key), test_key(key)));
    let class = if count == 1 {
        PacketClass::Control
    } else {
        PacketClass::Bulk
    };
    for counter in first_counter..first_counter + count as u64 {
        if outbound {
            mover
                .submit_outbound_packet(outbound_packet(owner, 1, class, &[counter as u8]))
                .unwrap();
        } else {
            mover
                .submit_socket_packet(encrypted_fmp_packet(
                    owner,
                    1,
                    counter,
                    class,
                    OutputTarget::Transport,
                    key,
                ))
                .unwrap();
        }
    }
    if continuation {
        // A blocked second owner triggers the real outbound fairness quantum.
        // The first run must then grow across separately popped admission batches.
        assert!(outbound && count > DATAPLANE_OUTBOUND_OWNER_FAIRNESS_PACKETS);
        let blocked = (9_101..10_000)
            .map(fmp_owner)
            .find(|candidate| mover.owner_shard_index(*candidate) == mover.owner_shard_index(owner))
            .unwrap();
        mover.register_owner(blocked, OwnerConfig::new(1, 0));
        mover
            .submit_outbound_packet(outbound_packet(blocked, 1, PacketClass::Bulk, b"blocked"))
            .unwrap();
        assert_eq!(
            mover.shards[mover.owner_shard_index(owner)]
                .outbound_admission
                .ready_lens(),
            (0, 2),
        );
    }

    let pool_capacity = count + DATAPLANE_AEAD_WORKER_FAIRNESS_PACKETS;
    let mut pool = test_aead_worker_pool(pool_capacity);
    let mut prepared = Vec::new();
    let mut ready = Vec::new();
    assert_eq!(
        mover.prepare_aead_available_into(count, &mut prepared, &mut ready, &pool),
        count,
    );
    assert!(ready.is_empty());
    assert_eq!(prepared.len(), 1);
    assert_eq!(prepared[0].run.len(), count);
    let capacity = prepared[0].run.items.capacity();

    pool.submit_prepared_chunk(&mut prepared, |slot| mover.stage_retire_slot(slot));
    let mut outputs = Vec::new();
    while outputs.len() < count {
        wait_for_owner_readiness(&mut pool, &mover);
        let remaining = count - outputs.len();
        assert!(retire_ready_slots_to_outputs(&mut mover, remaining, &mut outputs) > 0);
    }
    assert!(mover.drain_drops().is_empty());
    assert_eq!(mover.owner_mut(owner).unwrap().in_flight, 0);
    assert_eq!(pool.available_capacity(), pool_capacity);
    for (offset, output) in outputs.iter().enumerate() {
        let counter = first_counter + offset as u64;
        assert_eq!(output.counter(), counter);
        let payload = if outbound {
            open_sealed_output(output, key)
        } else {
            output.payload.as_slice()[FMP_ESTABLISHED_HEADER_SIZE..].to_vec()
        };
        assert_eq!(payload, [counter as u8]);
    }

    let item_bytes = std::mem::size_of::<CryptoOwnerRunItem>();
    eprintln!(
        "crypto_run_capacity outbound={outbound} continuation={continuation} packets={count} capacity={capacity} item_bytes={item_bytes} reserved_bytes={}",
        capacity * item_bytes,
    );
    assert!(capacity >= count);
    if continuation {
        assert!(capacity > DATAPLANE_OUTBOUND_OWNER_FAIRNESS_PACKETS);
        assert!(capacity <= count.next_power_of_two());
    } else {
        assert_eq!(
            capacity, count,
            "reserve items for the actual admitted batch"
        );
    }
}

#[test]
fn aead_prepared_inbound_capacity_tracks_admitted_batch() {
    for count in [DATAPLANE_AEAD_JOB_PACKETS, 1] {
        check_prepared_run_capacity(false, count, false);
    }
}

#[test]
fn aead_prepared_outbound_capacity_tracks_admitted_batch() {
    for count in [DATAPLANE_AEAD_JOB_PACKETS, 1] {
        check_prepared_run_capacity(true, count, false);
    }
}

#[test]
fn aead_prepared_capacity_grows_across_admission_batches() {
    check_prepared_run_capacity(true, DATAPLANE_OUTBOUND_OWNER_FAIRNESS_PACKETS + 1, true);
}
