#[test]
fn outbound_dispatch_gives_same_shard_peer_progress_under_saturated_bulk() {
    let mut mover = Dataplane::new(AdmissionConfig::new(16, 512));
    let saturated = fmp_owner(7_200);
    let saturated_shard = mover.owner_shard_index(saturated);
    let other = (7_201..8_000)
        .map(fmp_owner)
        .find(|owner| mover.owner_shard_index(*owner) == saturated_shard)
        .expect("same-shard test owner");
    mover.register_owner(saturated, OwnerConfig::new(1, 512));
    mover.register_owner(other, OwnerConfig::new(1, 512));

    let saturated_run = (0..256)
        .map(|_| outbound_packet(saturated, 1, PacketClass::Bulk, b"saturated"))
        .collect();
    assert_eq!(mover.submit_outbound_packet_batch(saturated_run), (256, 0));
    mover
        .submit_outbound_packet(outbound_packet(other, 1, PacketClass::Bulk, b"other"))
        .unwrap();

    let dispatched = dispatch_outbound_available(&mut mover, 16);
    assert!(
        dispatched
            .iter()
            .any(|work| work.reservation.owner == other),
        "a saturated owner must yield a bounded dispatch quantum to another peer in the same shard"
    );
}

#[test]
fn outbound_dispatch_keeps_full_quantum_for_a_lone_peer() {
    let mut mover = Dataplane::new(AdmissionConfig::new(16, 512));
    let owner = fmp_owner(8_000);
    mover.register_owner(owner, OwnerConfig::new(1, 512));
    let run = (0..256)
        .map(|_| outbound_packet(owner, 1, PacketClass::Bulk, b"single-peer"))
        .collect();
    assert_eq!(mover.submit_outbound_packet_batch(run), (256, 0));

    let dispatched = dispatch_outbound_available(&mut mover, 64);
    assert_eq!(dispatched.len(), 64);
    assert!(
        dispatched
            .iter()
            .all(|work| work.reservation.owner == owner)
    );
}

#[test]
fn outbound_priority_peer_precedes_saturated_bulk_peer() {
    let mut mover = Dataplane::new(AdmissionConfig::new(16, 512));
    let saturated = fmp_owner(8_200);
    let priority = fmp_owner(8_201);
    mover.register_owner(saturated, OwnerConfig::new(1, 512));
    mover.register_owner(priority, OwnerConfig::new(1, 512));

    let saturated_run = (0..256)
        .map(|_| outbound_packet(saturated, 1, PacketClass::Bulk, b"saturated"))
        .collect();
    assert_eq!(mover.submit_outbound_packet_batch(saturated_run), (256, 0));
    mover
        .submit_outbound_packet(outbound_packet(
            priority,
            1,
            PacketClass::Liveness,
            b"priority",
        ))
        .unwrap();

    let dispatched = dispatch_outbound_available(&mut mover, 8);
    assert_eq!(dispatched[0].reservation.owner, priority);
    assert_eq!(dispatched[0].reservation.lane, Lane::Priority);
}

#[test]
fn outbound_local_session_cuts_in_once_then_transit_progresses() {
    let mut mover = Dataplane::new(AdmissionConfig::new(16, 512));
    let transit = fmp_owner(8_400);
    let local = fsp_owner(8_401);
    let newer_local = fsp_owner(8_402);
    for owner in [transit, local, newer_local] {
        mover.register_owner(owner, OwnerConfig::new(1, 512));
    }

    for owner in [transit, local, newer_local] {
        mover
            .submit_outbound_packet(outbound_packet(owner, 1, PacketClass::Bulk, b"data"))
            .unwrap();
    }

    let local_first = dispatch_outbound_available(&mut mover, 1);
    assert_eq!(local_first[0].reservation.owner, local);
    let transit_next = dispatch_outbound_available(&mut mover, 1);
    assert_eq!(
        transit_next[0].reservation.owner, transit,
        "another newly runnable local owner must not indefinitely push transit back"
    );
}

#[test]
fn outbound_control_stays_ahead_of_local_and_transit_data() {
    let mut mover = Dataplane::new(AdmissionConfig::new(16, 512));
    let transit = fmp_owner(8_600);
    let local = fsp_owner(8_601);
    let control = fmp_owner(8_602);
    for owner in [transit, local, control] {
        mover.register_owner(owner, OwnerConfig::new(1, 512));
    }
    mover
        .submit_outbound_packet(outbound_packet(
            transit,
            1,
            PacketClass::Bulk,
            b"transit",
        ))
        .unwrap();
    mover
        .submit_outbound_packet(outbound_packet(local, 1, PacketClass::Bulk, b"local"))
        .unwrap();
    mover
        .submit_outbound_packet(outbound_packet(
            control,
            1,
            PacketClass::Control,
            b"control",
        ))
        .unwrap();

    let dispatched = dispatch_outbound_available(&mut mover, 1);
    assert_eq!(dispatched[0].reservation.owner, control);
    assert_eq!(dispatched[0].reservation.lane, Lane::Priority);
}
