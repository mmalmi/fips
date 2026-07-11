#[test]
fn packet_rx_priority_ready_includes_pending_batch_tail() {
    let (tx, mut rx) = packet_channel(10);
    let addr = TransportAddr::from_string("test");

    tx.send_packet_batch(packet_batch(vec![
        received_packet(TransportId::new(1), addr.clone(), priority_msg1(0x11)),
        received_packet(TransportId::new(1), addr.clone(), priority_msg2(0x22)),
        received_packet(TransportId::new(1), addr, priority_msg1(0x33)),
    ]))
    .expect("priority batch send should succeed");

    assert_eq!(rx.priority_ready_packets(), 3);
    assert_eq!(packet_marker(&rx.try_recv().unwrap()), 0x11);
    assert_eq!(
        priority_queued_packets(&tx),
        0,
        "sender-side channel hint should clear once PacketRx owns the batch"
    );
    assert_eq!(
        rx.priority_ready_packets(),
        2,
        "rx-loop scheduling must still see the priority batch tail"
    );
    assert_eq!(packet_marker(&rx.try_recv().unwrap()), 0x22);
    assert_eq!(rx.priority_ready_packets(), 1);
    assert_eq!(packet_marker(&rx.try_recv().unwrap()), 0x33);
    assert_eq!(rx.priority_ready_packets(), 0);
}

#[test]
fn packet_rx_drain_ready_drains_bulk_batch_tail_in_one_call() {
    let (tx, mut rx) = packet_channel(10);
    let addr = TransportAddr::from_string("test");

    tx.send_packet_batch(packet_batch(vec![
        received_packet(TransportId::new(1), addr.clone(), bulk_packet(0xaa)),
        received_packet(TransportId::new(1), addr.clone(), bulk_packet(0xbb)),
        received_packet(TransportId::new(1), addr, bulk_packet(0xcc)),
    ]))
    .expect("bulk batch send should succeed");

    let mut drained = Vec::new();
    assert_eq!(
        rx.drain_ready(2, |packet| {
            drained.push(packet_marker(&packet));
            true
        }),
        2
    );
    assert_eq!(drained, vec![0xaa, 0xbb]);
    assert_eq!(
        queued_packets(&tx),
        0,
        "dequeued batch tail should be rx-loop-owned, not channel-owned"
    );
    assert_eq!(bulk_queued_packets(&tx), 0);
    assert_eq!(packet_marker(&rx.try_recv().unwrap()), 0xcc);
}

#[test]
fn packet_rx_drain_ready_leaves_tail_when_consumer_stops() {
    let (tx, mut rx) = packet_channel(10);
    let addr = TransportAddr::from_string("test");

    tx.send_packet_batch(packet_batch(vec![
        received_packet(TransportId::new(1), addr.clone(), bulk_packet(0xaa)),
        received_packet(TransportId::new(1), addr.clone(), bulk_packet(0xbb)),
        received_packet(TransportId::new(1), addr, bulk_packet(0xcc)),
    ]))
    .expect("bulk batch send should succeed");

    let mut drained = Vec::new();
    assert_eq!(
        rx.drain_ready(8, |packet| {
            let byte = packet_marker(&packet);
            drained.push(byte);
            byte != 0xbb
        }),
        2
    );
    assert_eq!(drained, vec![0xaa, 0xbb]);
    assert_eq!(packet_marker(&rx.try_recv().unwrap()), 0xcc);
    assert!(matches!(rx.try_recv(), Err(TryRecvError::Empty)));
}

#[test]
fn packet_rx_drain_ready_preserves_priority_overtaking_bulk_tail() {
    let (tx, mut rx) = packet_channel(10);
    let addr = TransportAddr::from_string("test");

    tx.send_packet_batch(packet_batch(vec![
        received_packet(TransportId::new(1), addr.clone(), bulk_packet(0xaa)),
        received_packet(TransportId::new(1), addr.clone(), bulk_packet(0xbb)),
    ]))
    .expect("bulk batch send should succeed");

    let mut first = Vec::new();
    assert_eq!(
        rx.drain_ready(1, |packet| {
            first.push(packet_marker(&packet));
            true
        }),
        1
    );
    assert_eq!(first, vec![0xaa]);

    tx.send(received_packet(
        TransportId::new(1),
        addr,
        priority_msg1(0x11),
    ))
    .expect("priority packet send should succeed");

    let mut drained = Vec::new();
    assert_eq!(
        rx.drain_ready(8, |packet| {
            drained.push(packet_marker(&packet));
            true
        }),
        2
    );
    assert_eq!(drained, vec![0x11, 0xbb]);
    assert!(matches!(rx.try_recv(), Err(TryRecvError::Empty)));
}

#[tokio::test]
async fn packet_channel_priority_overtakes_pending_bulk_batch_tail() {
    let (tx, mut rx) = packet_channel(10);
    let addr = TransportAddr::from_string("test");

    tx.send_packet_batch(packet_batch(vec![
        received_packet(TransportId::new(1), addr.clone(), bulk_packet(0xaa)),
        received_packet(TransportId::new(1), addr.clone(), bulk_packet(0xbb)),
    ]))
    .expect("bulk batch send should succeed");

    assert_eq!(packet_marker(&rx.recv().await.unwrap()), 0xaa);
    tx.send(received_packet(
        TransportId::new(1),
        addr,
        priority_msg1(0x11),
    ))
    .expect("priority packet send should succeed");

    assert_eq!(packet_marker(&rx.recv().await.unwrap()), 0x11);
    assert_eq!(packet_marker(&rx.recv().await.unwrap()), 0xbb);
}

#[tokio::test]
async fn packet_channel_bounded_bulk_drops_without_blocking_priority() {
    let (tx, mut rx) = packet_channel(1);
    let addr = TransportAddr::from_string("test");

    tx.send(received_packet(
        TransportId::new(1),
        addr.clone(),
        bulk_packet(0xaa),
    ))
    .expect("first bulk packet should fill bounded bulk lane");
    assert_eq!(queued_packets(&tx), 1);
    assert_eq!(bulk_queued_packets(&tx), 1);

    tx.send(received_packet(
        TransportId::new(1),
        addr.clone(),
        bulk_packet(0xbb),
    ))
    .expect("full bulk lane should drop overload without closing sender");
    assert_eq!(
        queued_packets(&tx),
        1,
        "dropped bulk must roll back channel-owned backlog accounting"
    );
    assert_eq!(bulk_queued_packets(&tx), 1);
    assert_eq!(rx.bulk.len(), 1);

    tx.send(received_packet(
        TransportId::new(1),
        addr,
        priority_msg1(0x11),
    ))
    .expect("priority packet should still enter reserve lane");
    assert_eq!(queued_packets(&tx), 2);
    assert_eq!(
        bulk_queued_packets(&tx),
        1,
        "priority packets must not consume bulk packet capacity"
    );

    assert_eq!(packet_marker(&rx.recv().await.unwrap()), 0x11);
    assert_eq!(queued_packets(&tx), 1);
    assert_eq!(bulk_queued_packets(&tx), 1);
    assert_eq!(packet_marker(&rx.recv().await.unwrap()), 0xaa);
    assert_eq!(queued_packets(&tx), 0);
    assert_eq!(bulk_queued_packets(&tx), 0);
    assert!(matches!(rx.try_recv(), Err(TryRecvError::Empty)));
}

#[tokio::test]
async fn packet_channel_bounded_bulk_batch_drop_counts_packets_not_items() {
    let (tx, mut rx) = packet_channel(2);
    let addr = TransportAddr::from_string("test");

    tx.send_packet_batch(packet_batch(vec![
        received_packet(TransportId::new(1), addr.clone(), bulk_packet(0xaa)),
        received_packet(TransportId::new(1), addr.clone(), bulk_packet(0xab)),
    ]))
    .expect("first bulk batch should fill bounded bulk lane");
    assert_eq!(queued_packets(&tx), 2);
    assert_eq!(bulk_queued_packets(&tx), 2);
    assert_eq!(
        rx.bulk.len(),
        1,
        "batching should still amortize channel items"
    );

    tx.send_packet_batch(packet_batch(vec![
        received_packet(TransportId::new(1), addr.clone(), bulk_packet(0xbb)),
        received_packet(TransportId::new(1), addr, bulk_packet(0xbc)),
    ]))
    .expect("full bulk packet budget should drop batch overload without closing sender");
    assert_eq!(
        queued_packets(&tx),
        2,
        "dropped bulk batch must roll back every packet it accounted"
    );
    assert_eq!(
        bulk_queued_packets(&tx),
        2,
        "dropped bulk batch must not expand the packet-count backlog"
    );
    assert_eq!(rx.bulk.len(), 1);

    assert_eq!(packet_marker(&rx.recv().await.unwrap()), 0xaa);
    assert_eq!(queued_packets(&tx), 0);
    assert_eq!(bulk_queued_packets(&tx), 0);
    assert_eq!(packet_marker(&rx.recv().await.unwrap()), 0xab);
    assert!(matches!(rx.try_recv(), Err(TryRecvError::Empty)));
}

#[tokio::test]
async fn packet_channel_bounded_bulk_batch_admits_prefix_before_dropping_tail() {
    let (tx, mut rx) = packet_channel(3);
    let addr = TransportAddr::from_string("test");

    tx.send(received_packet(
        TransportId::new(1),
        addr.clone(),
        bulk_packet(0xaa),
    ))
    .expect("first bulk packet should consume one bulk packet credit");
    assert_eq!(queued_packets(&tx), 1);
    assert_eq!(bulk_queued_packets(&tx), 1);

    tx.send_packet_batch(packet_batch(vec![
        received_packet(TransportId::new(1), addr.clone(), bulk_packet(0xbb)),
        received_packet(TransportId::new(1), addr.clone(), bulk_packet(0xbc)),
        received_packet(TransportId::new(1), addr.clone(), bulk_packet(0xbd)),
    ]))
    .expect("partial bulk admission should shed only overflow tail");
    assert_eq!(
        queued_packets(&tx),
        3,
        "only the admitted prefix should count as channel-owned"
    );
    assert_eq!(
        bulk_queued_packets(&tx),
        3,
        "bulk packet credits should be capped at channel capacity"
    );
    assert_eq!(
        rx.bulk.len(),
        2,
        "the admitted prefix should stay grouped behind the already queued packet"
    );

    tx.send(received_packet(
        TransportId::new(1),
        addr,
        priority_msg1(0x11),
    ))
    .expect("priority packets should still enter their reserve lane");
    assert_eq!(priority_queued_packets(&tx), 1);
    assert_eq!(bulk_queued_packets(&tx), 3);

    assert_eq!(packet_marker(&rx.recv().await.unwrap()), 0x11);
    assert_eq!(priority_queued_packets(&tx), 0);
    assert_eq!(bulk_queued_packets(&tx), 3);
    assert_eq!(packet_marker(&rx.recv().await.unwrap()), 0xaa);
    assert_eq!(bulk_queued_packets(&tx), 2);
    assert_eq!(packet_marker(&rx.recv().await.unwrap()), 0xbb);
    assert_eq!(
        bulk_queued_packets(&tx),
        0,
        "dequeued bulk batch should release all admitted prefix credits"
    );
    assert_eq!(packet_marker(&rx.recv().await.unwrap()), 0xbc);
    assert!(matches!(rx.try_recv(), Err(TryRecvError::Empty)));
}

#[test]
fn packet_channel_partial_bulk_drop_recycles_overflow_packet_buffers() {
    let (tx, _rx) = packet_channel(2);
    let addr = TransportAddr::from_string("test");

    tx.send(received_packet(
        TransportId::new(1),
        addr.clone(),
        bulk_packet(0xaa),
    ))
    .expect("first bulk packet should leave one credit free");

    let mut admitted = tx.recv_buffer(1600);
    admitted.clear();
    admitted.resize(BULK_PACKET_LEN, 0xbb);
    let mut dropped = tx.recv_buffer(1600);
    dropped.clear();
    dropped.resize(BULK_PACKET_LEN, 0xbc);
    let dropped_ptr = dropped.as_ptr();

    let mut batch = tx.packet_batch(2);
    batch.push(received_packet(
        TransportId::new(1),
        addr.clone(),
        tx.packet_buffer(admitted),
    ));
    batch.push(received_packet(
        TransportId::new(1),
        addr,
        tx.packet_buffer(dropped),
    ));

    tx.send_packet_batch(batch)
        .expect("partial bulk admission should not close sender");
    assert_eq!(
        packet_buffer_pool_cached_len(&tx.buffer_pool),
        1,
        "overflow tail packet should return its receive buffer immediately"
    );
    let reused = tx.recv_buffer(1600);
    assert_eq!(
        reused.as_ptr(),
        dropped_ptr,
        "next receive refill should reuse the dropped tail buffer"
    );
}

#[test]
fn packet_channel_counts_channel_owned_packet_backlog() {
    let (tx, mut rx) = packet_channel(10);
    let addr = TransportAddr::from_string("test");

    assert_eq!(queued_packets(&tx), 0);
    tx.send_packet_batch(packet_batch(vec![
        received_packet(TransportId::new(1), addr.clone(), bulk_packet(0xaa)),
        received_packet(TransportId::new(1), addr.clone(), bulk_packet(0xbb)),
        received_packet(TransportId::new(1), addr.clone(), bulk_packet(0xcc)),
    ]))
    .expect("bulk batch send should succeed");
    assert_eq!(queued_packets(&tx), 3);
    assert_eq!(bulk_queued_packets(&tx), 3);

    assert_eq!(packet_marker(&rx.try_recv().unwrap()), 0xaa);
    assert_eq!(
        queued_packets(&tx),
        0,
        "once a batch item is dequeued, its tail is rx-loop-owned, not channel-owned"
    );
    assert_eq!(
        bulk_queued_packets(&tx),
        0,
        "bulk capacity is released when the rx loop owns the batch tail"
    );

    tx.send(received_packet(
        TransportId::new(1),
        addr,
        priority_msg1(0x11),
    ))
    .expect("priority packet send should succeed");
    assert_eq!(queued_packets(&tx), 1);
    assert_eq!(bulk_queued_packets(&tx), 0);

    assert_eq!(packet_marker(&rx.try_recv().unwrap()), 0x11);
    assert_eq!(queued_packets(&tx), 0);
    assert_eq!(bulk_queued_packets(&tx), 0);
    assert_eq!(packet_marker(&rx.try_recv().unwrap()), 0xbb);
    assert_eq!(packet_marker(&rx.try_recv().unwrap()), 0xcc);
    assert_eq!(queued_packets(&tx), 0);
    assert_eq!(bulk_queued_packets(&tx), 0);
}

#[test]
fn packet_channel_send_failure_rolls_back_backlog() {
    let (tx, rx) = packet_channel(10);
    let addr = TransportAddr::from_string("test");
    drop(rx);

    let packet = received_packet(TransportId::new(1), addr.clone(), priority_msg1(0x11));
    assert!(tx.send(packet).is_err());
    assert_eq!(queued_packets(&tx), 0);
    assert_eq!(priority_queued_packets(&tx), 0);

    let packets = vec![
        received_packet(TransportId::new(1), addr.clone(), priority_msg2(0x22)),
        received_packet(TransportId::new(1), addr.clone(), priority_msg1(0x33)),
    ];
    assert!(tx.send_packet_batch(packet_batch(packets)).is_err());
    assert_eq!(queued_packets(&tx), 0);
    assert_eq!(priority_queued_packets(&tx), 0);

    let packets = vec![
        received_packet(TransportId::new(1), addr.clone(), bulk_packet(0xaa)),
        received_packet(TransportId::new(1), addr, bulk_packet(0xbb)),
    ];
    assert!(tx.send_packet_batch(packet_batch(packets)).is_err());
    assert_eq!(queued_packets(&tx), 0);
    assert_eq!(bulk_queued_packets(&tx), 0);
}
