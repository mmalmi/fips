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
                FSP_HEADER_SIZE as u16,
                PacketClass::Bulk,
                OutputTarget::SessionPayload { local_addr },
                PacketBuffer::new(fsp_encrypted_wire(counter, 0, &fsp_inner, key)),
            )
            .with_previous_hop(previous_hop)
            .with_activity_tick(ActivityTick::new(timestamp as u64)),
        )
        .unwrap();
}

fn run_with_worker_pool_limit(
    mover: &mut Dataplane,
    pool: &mut DataplaneAeadWorkerPool,
    limit: usize,
) -> (usize, Vec<PacketOutput>, Vec<PacketDrop>) {
    let mut prepared_work = Vec::new();
    let mut ready_slots = Vec::new();
    let mut retired = Vec::new();
    let mut outbound_packets = Vec::new();
    let mut fsp_authenticated_ingress = DataplaneFspAuthenticatedIngress::default();
    let mut drops = Vec::new();
    let dispatched = mover.run_aead_available_into(
        limit,
        DataplaneAeadRunBuffers::new(
            &mut prepared_work,
            &mut ready_slots,
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

fn driver_endpoint_batches(driver: &DataplaneTurnDriver) -> Vec<&DataplaneEndpointDataBatch> {
    driver
        .fsp_authenticated_ingress
        .endpoint_data_batches
        .iter()
        .collect()
}

fn take_driver_endpoint_batches(
    driver: &mut DataplaneTurnDriver,
) -> Vec<DataplaneEndpointDataBatch> {
    std::mem::take(&mut driver.fsp_authenticated_ingress).endpoint_data_batches
}

#[test]
fn aead_worker_pool_publishes_ordered_readiness_slots() {
    let owner = fmp_owner(706);
    let open_key = 20;
    let mut mover = Dataplane::new(AdmissionConfig::new(4, 16));
    mover.register_owner(owner, OwnerConfig::new(1, 16));
    mover
        .owner_mut(owner)
        .unwrap()
        .set_crypto_keys(OwnerCryptoKeys::new(test_key(open_key), test_key(open_key)));
    submit_fmp_inbound_range(&mut mover, owner, 706, open_key, 100..112, b"worker");

    let mut pool = test_aead_worker_pool(20);
    let (dispatched, retired, drops) = run_with_worker_pool_limit(&mut mover, &mut pool, 16);

    assert_eq!(dispatched, 12);
    assert!(retired.is_empty());
    assert!(drops.is_empty());
    assert_eq!(mover.owner_mut(owner).unwrap().in_flight, 12);

    let mut retired = Vec::new();
    wait_for_owner_readiness(&mut pool, &mover);
    assert_eq!(retire_ready_slots_to_outputs(&mut mover, 6, &mut retired), 6);
    assert_eq!(pool.available_capacity(), 14);

    assert_eq!(retire_ready_slots_to_outputs(&mut mover, 6, &mut retired), 6);
    let outputs = retired;
    assert_eq!(
        outputs
            .iter()
            .map(PacketOutput::counter)
            .collect::<Vec<_>>(),
        (100..112).collect::<Vec<_>>()
    );
    assert_eq!(mover.owner_mut(owner).unwrap().in_flight, 0);
    assert_eq!(pool.available_capacity(), 20);
}

#[test]
fn owner_membership_changes_wake_deferred_lanes() {
    let inbound_owner = fmp_owner(712);
    let mut inbound = mover();
    inbound.register_owner(inbound_owner, OwnerConfig::new(1, 1));
    submit_fmp_inbound_range(
        &mut inbound,
        inbound_owner,
        712,
        12,
        100..102,
        b"inbound",
    );
    assert_eq!(dispatch_available(&mut inbound, 8).len(), 1);
    assert!(!inbound.has_runnable_work());
    inbound.register_owner(inbound_owner, OwnerConfig::new(1, 1));
    assert!(inbound.has_runnable_work());
    assert_eq!(dispatch_available(&mut inbound, 8).len(), 1);

    let outbound_owner = fmp_owner(713);
    let mut outbound = mover();
    outbound.register_owner(
        outbound_owner,
        OwnerConfig::new(1, 1).with_next_send_counter(500),
    );
    for payload in [b"first".as_slice(), b"second".as_slice()] {
        outbound
            .submit_outbound_packet(outbound_packet(
                outbound_owner,
                1,
                PacketClass::Bulk,
                payload,
            ))
            .unwrap();
    }
    assert_eq!(dispatch_outbound_available(&mut outbound, 8).len(), 1);
    assert!(!outbound.has_runnable_work());
    assert!(outbound.unregister_owner(outbound_owner));
    assert!(outbound.has_runnable_work());
    assert!(dispatch_outbound_available(&mut outbound, 8).is_empty());
    assert!(
        outbound
            .drain_drops()
            .iter()
            .any(|drop| drop.reason == PacketDropReason::UnknownOwner)
    );
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
    let (dispatched, _retired, drops) = run_with_worker_pool_limit(
        &mut mover,
        &mut pool,
        DATAPLANE_AEAD_WORKER_FAIRNESS_PACKETS * 2,
    );
    assert_eq!(dispatched, 1);
    assert!(drops.is_empty());
}

#[test]
fn direct_fsp_owner_reports_destination_as_next_hop() {
    let dest = NodeAddr::from_bytes([0x1d; 16]);
    let next_hop = NodeAddr::from_bytes([0x1e; 16]);
    let fsp_owner = OwnerId::fsp_node(dest);
    let fmp_owner = OwnerId::fmp_node(next_hop);
    let direct_path = live_path(1900);

    let mut driver = DataplaneTurnDriver::new(AdmissionConfig::new(4, 8));
    driver.register_owner(fsp_owner, OwnerConfig::new(1, 8));
    assert_eq!(driver.owner_fsp_next_hop(fsp_owner), None);

    driver
        .owner_mut(fsp_owner)
        .unwrap()
        .set_active_path(direct_path);
    assert_eq!(driver.owner_fsp_next_hop(fsp_owner), Some(dest));

    let wrap =
        DataplaneFspWrapRoute::new(fmp_owner, 1, 4242, NodeAddr::from_bytes([0x1c; 16]), dest);
    driver
        .owner_mut(fsp_owner)
        .unwrap()
        .set_fsp_wrap_route(Some(wrap));
    assert_eq!(driver.owner_fsp_next_hop(fsp_owner), Some(next_hop));
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
    let mut driver = DataplaneTurnDriver::new(AdmissionConfig::new(4, 8));
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

    let wrap = DataplaneFspWrapRoute::new(fmp_owner, 1, 4242, source, dest)
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

    let first = run_aead_classified_turn(&mut driver, std::iter::empty(), [packet, queued_bulk], 1);
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
    driver
        .owner_mut(owner)
        .unwrap()
        .set_active_path(path.clone());

    let route = DataplaneEndpointDataRoute::fsp(owner, 1, 0, 0);
    let routed =
        route_endpoint_payloads(&route, vec![b"direct-one".to_vec(), b"direct-two".to_vec()]);
    assert!(routed.dropped.is_empty());
    assert_eq!(routed.routed.len(), 2);
    let routed_packets = routed
        .routed
        .into_iter()
        .map(|packet| packet.with_activity_tick(ActivityTick::new(2_345)))
        .collect::<Vec<_>>();

    let turn = run_aead_classified_turn(&mut driver, std::iter::empty(), routed_packets, 8);
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
        assert!(
            output.fsp_send_receipt.is_none(),
            "direct output already exposes its FSP owner and counter"
        );

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
    let mut driver = DataplaneTurnDriver::new(AdmissionConfig::new(4, 8));
    driver.register_owner(fsp_owner, OwnerConfig::new(1, 8).with_next_send_counter(90));
    driver.register_owner(
        fmp_owner,
        OwnerConfig::new(1, 8).with_next_send_counter(100),
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
    let mut driver = DataplaneTurnDriver::new(AdmissionConfig::new(4, 8));
    driver.register_owner(fsp_owner, OwnerConfig::new(1, 8).with_next_send_counter(10));
    driver.register_owner(fmp_owner, OwnerConfig::new(1, 8).with_next_send_counter(20));
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
fn failed_fsp_authentication_does_not_advance_replay_window() {
    let owner = fsp_owner(714);
    let open_key = 41;
    let mut mover = mover();
    mover.register_owner(owner, OwnerConfig::new(1, 8));
    mover
        .owner_mut(owner)
        .unwrap()
        .set_crypto_keys(OwnerCryptoKeys::new(test_key(open_key), test_key(open_key)));

    mover
        .submit_socket_packet(SocketPacket::new(
            owner,
            1,
            9_000,
            FSP_HEADER_SIZE as u16,
            PacketClass::Bulk,
            OutputTarget::Transport,
            PacketBuffer::new(fsp_encrypted_wire(9_000, 0, b"sibling", open_key + 1)),
        ))
        .unwrap();
    let failed = run_aead_available(&mut mover, 8);
    assert_eq!(failed.drops().len(), 1);
    assert_eq!(failed.drops()[0].reason(), PacketDropReason::CryptoFailed);

    mover
        .submit_socket_packet(SocketPacket::new(
            owner,
            1,
            0,
            FSP_HEADER_SIZE as u16,
            PacketClass::Bulk,
            OutputTarget::Transport,
            PacketBuffer::new(fsp_encrypted_wire(0, 0, b"approval", open_key)),
        ))
        .unwrap();
    let accepted = run_aead_available(&mut mover, 8);
    assert!(accepted.drops().is_empty(), "{:?}", accepted.drops());
    assert_eq!(
        &accepted.outputs()[0].payload.as_slice()[FSP_HEADER_SIZE..],
        b"approval"
    );
}

#[test]
fn authenticated_fsp_counter_still_rejects_a_later_reserved_old_counter() {
    let owner = fsp_owner(715);
    let open_key = 42;
    let mut mover = mover();
    mover.register_owner(owner, OwnerConfig::new(1, 8));
    mover
        .owner_mut(owner)
        .unwrap()
        .set_crypto_keys(OwnerCryptoKeys::new(test_key(open_key), test_key(open_key)));

    for (counter, payload) in [(9_000, b"new".as_slice()), (0, b"old".as_slice())] {
        mover
            .submit_socket_packet(SocketPacket::new(
                owner,
                1,
                counter,
                FSP_HEADER_SIZE as u16,
                PacketClass::Bulk,
                OutputTarget::Transport,
                PacketBuffer::new(fsp_encrypted_wire(counter, 0, payload, open_key)),
            ))
            .unwrap();
    }

    let turn = run_aead_available(&mut mover, 8);
    assert_eq!(turn.outputs().len(), 1);
    assert_eq!(
        &turn.outputs()[0].payload.as_slice()[FSP_HEADER_SIZE..],
        b"new"
    );
    assert!(
        turn.drops()
            .iter()
            .any(|drop| drop.reason() == PacketDropReason::Replay && drop.counter() == Some(0))
    );
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
                FSP_HEADER_SIZE as u16,
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
