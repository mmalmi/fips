fn same_shard_fmp_owners(mover: &Dataplane) -> (OwnerId, OwnerId) {
    let first = fmp_owner(20_000);
    let shard = mover.owner_shard_index(first);
    let second = (20_001..30_000)
        .map(fmp_owner)
        .find(|owner| mover.owner_shard_index(*owner) == shard)
        .expect("test range should contain two owners in one dataplane shard");
    (first, second)
}

#[test]
fn dataplane_owner_fairness_rotates_saturated_bulk_owner_before_returning_to_it() {
    let mut mover = Dataplane::new(AdmissionConfig::new(8, 64));
    let (saturated, sibling) = same_shard_fmp_owners(&mover);
    mover.register_owner(saturated, OwnerConfig::new(1, 64));
    mover.register_owner(sibling, OwnerConfig::new(1, 64));

    for counter in 0..24 {
        mover
            .submit_socket_packet(packet(
                saturated,
                1,
                counter,
                PacketClass::Bulk,
                OutputTarget::Transport,
            ))
            .unwrap();
    }
    for counter in 1_000..1_004 {
        mover
            .submit_socket_packet(packet(
                sibling,
                1,
                counter,
                PacketClass::Bulk,
                OutputTarget::Transport,
            ))
            .unwrap();
    }

    let first = dispatch_available(&mut mover, 8);
    assert_eq!(first.len(), 8);
    assert!(
        first
            .iter()
            .all(|work| work.reservation.owner == saturated),
        "the first owner's contiguous run should stay batched"
    );

    // More traffic arriving for the saturated owner must not move it ahead of
    // a sibling that was already waiting in the same shard and lane.
    for counter in 24..32 {
        mover
            .submit_socket_packet(packet(
                saturated,
                1,
                counter,
                PacketClass::Bulk,
                OutputTarget::Transport,
            ))
            .unwrap();
    }
    let second = dispatch_available(&mut mover, 8);
    assert_eq!(second.len(), 8);
    assert!(
        second[..4]
            .iter()
            .all(|work| work.reservation.owner == sibling),
        "a continuously backlogged owner must yield to the next ready owner"
    );
    assert!(
        second[4..]
            .iter()
            .all(|work| work.reservation.owner == saturated),
        "the saturated owner should resume after the sibling's bounded run"
    );
}

#[test]
fn dataplane_owner_fairness_favors_priority_owner_under_saturated_bulk() {
    let mut mover = Dataplane::new(AdmissionConfig::new(8, 64));
    let (bulk_owner, priority_owner) = same_shard_fmp_owners(&mover);
    mover.register_owner(bulk_owner, OwnerConfig::new(1, 64));
    mover.register_owner(priority_owner, OwnerConfig::new(1, 64));

    for counter in 0..32 {
        mover
            .submit_socket_packet(packet(
                bulk_owner,
                1,
                counter,
                PacketClass::Bulk,
                OutputTarget::Transport,
            ))
            .unwrap();
    }
    mover
        .submit_socket_packet(packet(
            priority_owner,
            1,
            1_000,
            PacketClass::Liveness,
            OutputTarget::Transport,
        ))
        .unwrap();

    let dispatched = dispatch_available(&mut mover, 8);
    assert_eq!(dispatched.len(), 8);
    assert_eq!(dispatched[0].reservation.owner, priority_owner);
    assert_eq!(dispatched[0].reservation.lane, Lane::Priority);
    assert!(
        dispatched[1..]
            .iter()
            .all(|work| work.reservation.owner == bulk_owner),
        "bulk should use the remaining turn without preceding priority work"
    );
}

#[test]
fn inbound_local_session_cuts_in_once_then_transit_progresses() {
    let mut mover = Dataplane::new(AdmissionConfig::new(8, 64));
    let transit = fmp_owner(21_000);
    let transit_shard = mover.owner_shard_index(transit);
    let mut local_owners = (21_001..30_000)
        .map(fsp_owner)
        .filter(|owner| mover.owner_shard_index(*owner) == transit_shard);
    let local = local_owners.next().expect("same-shard local owner");
    let newer_local = local_owners.next().expect("second same-shard local owner");
    for owner in [transit, local, newer_local] {
        mover.register_owner(owner, OwnerConfig::new(1, 64));
    }

    for owner in [transit, local, newer_local] {
        mover
            .submit_socket_packet(packet(
                owner,
                1,
                1,
                PacketClass::Bulk,
                OutputTarget::Transport,
            ))
            .unwrap();
    }

    let local_first = dispatch_available(&mut mover, 1);
    assert_eq!(local_first[0].reservation.owner, local);
    let transit_next = dispatch_available(&mut mover, 1);
    assert_eq!(transit_next[0].reservation.owner, transit);
}

#[test]
fn ready_shard_local_cut_in_debt_forces_waiting_transit_progress() {
    let mut ready = ReadyShardQueue::new(3);
    ready.mark(0, false);
    ready.mark(1, true);
    ready.mark(2, true);

    assert_eq!(ready.pop(), Some(1), "one local shard should cut in");
    assert_eq!(ready.pop(), Some(0), "waiting transit must be next");
    assert_eq!(ready.pop(), Some(2));
}

