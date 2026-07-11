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
