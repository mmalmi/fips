fn forged_priority(marker: u8) -> ReceivedPacket {
    received_packet(
        TransportId::new(1),
        TransportAddr::from_string("untrusted"),
        established_fmp_packet(65_534, marker),
    )
}

#[test]
fn priority_flood_is_bounded_before_authentication() {
    let (tx, mut rx) = packet_channel(1);
    for _ in 0..512 {
        tx.send(forged_priority(0x11)).unwrap();
    }
    assert_eq!(rx.queued_packets_for_test(), 64);
    assert_eq!(rx.drain_ready(1024, |_| true), 64);
    tx.send(forged_priority(0x22)).unwrap();
    assert_eq!(packet_marker(&rx.try_recv().unwrap()), 0x22);
    assert_eq!(priority_queued_packets(&tx), 0);
}

#[test]
fn priority_batch_tail_keeps_its_packet_reservations() {
    let (tx, mut rx) = packet_channel(1);
    let batch = || packet_batch((0..512).map(|_| forged_priority(0x11)).collect());
    tx.send_packet_batch(batch()).unwrap();
    assert_eq!(rx.drain_ready(1, |_| true), 1);
    assert_eq!(rx.queued_packets_for_test(), 63);
    tx.send_packet_batch(batch()).unwrap();
    assert_eq!(rx.queued_packets_for_test(), 64);
    assert_eq!(rx.drain_ready(1024, |_| true), 64);
    assert_eq!(priority_queued_packets(&tx), 0);
}

#[test]
fn priority_reservations_are_shared_by_concurrent_senders() {
    let (tx, mut rx) = packet_channel(1);
    std::thread::scope(|scope| {
        for _ in 0..8 {
            let tx = tx.clone();
            scope.spawn(move || {
                for _ in 0..128 {
                    let packet = received_packet(
                        TransportId::new(1),
                        TransportAddr::from_string("untrusted"),
                        priority_msg1(0x11),
                    );
                    tx.send(packet).unwrap();
                }
            });
        }
    });
    assert_eq!(rx.queued_packets_for_test(), 64);
    assert_eq!(rx.drain_ready(1024, |_| true), 64);
}

#[test]
fn priority_overflow_keeps_bulk_and_close_semantics() {
    let (tx, mut rx) = packet_channel(1);
    tx.send(received_packet(
        TransportId::new(1),
        TransportAddr::from_string("test"),
        bulk_packet(0xaa),
    ))
    .unwrap();
    tx.send_packet_batch(packet_batch(
        (0..512).map(|_| forged_priority(0x11)).collect(),
    ))
    .unwrap();
    assert_eq!(
        rx.drain_ready(64, |packet| {
            assert_eq!(packet_marker(&packet), 0x11);
            true
        }),
        64
    );
    assert_eq!(packet_marker(&rx.try_recv().unwrap()), 0xaa);
    tx.send(forged_priority(0x22)).unwrap();
    drop(rx);
    assert!(tx.send(forged_priority(0x33)).is_err());
    assert!(
        tx.send_packet_batch(packet_batch(vec![forged_priority(0x44)]))
            .is_err()
    );
    assert_eq!(priority_queued_packets(&tx), 0);
    assert_eq!(bulk_reserved_packets(&tx), 0);
}

#[test]
fn bulk_batch_tail_keeps_its_packet_reservations() {
    let (tx, mut rx) = packet_channel(2);
    let batch = || {
        packet_batch(
            (0..4)
                .map(|_| {
                    received_packet(
                        TransportId::new(1),
                        TransportAddr::from_string("test"),
                        bulk_packet(0xaa),
                    )
                })
                .collect(),
        )
    };
    tx.send_packet_batch(batch()).unwrap();
    assert_eq!(rx.drain_ready(1, |_| false), 1);
    tx.send_packet_batch(batch()).unwrap();
    assert_eq!(rx.queued_packets_for_test(), 2);
    assert_eq!(rx.drain_ready(1024, |_| true), 2);
    assert_eq!(bulk_reserved_packets(&tx), 0);
}

#[test]
fn mixed_batch_overflow_preserves_both_lane_budgets() {
    let (tx, mut rx) = packet_channel(2);
    let packets = (0..100)
        .flat_map(|_| {
            [
                forged_priority(0x11),
                received_packet(
                    TransportId::new(1),
                    TransportAddr::from_string("test"),
                    bulk_packet(0xaa),
                ),
            ]
        })
        .collect();
    tx.send_packet_batch(packet_batch(packets)).unwrap();
    assert_eq!(rx.queued_packets_for_test(), 66);
    assert_eq!(
        rx.drain_ready(64, |packet| {
            assert_eq!(packet_marker(&packet), 0x11);
            true
        }),
        64
    );
    assert_eq!(
        rx.drain_ready(2, |packet| {
            assert_eq!(packet_marker(&packet), 0xaa);
            true
        }),
        2
    );
    assert_eq!(tx.priority_reserved_packets.load(Relaxed), 0);
    assert_eq!(bulk_reserved_packets(&tx), 0);
}

#[test]
fn close_during_reserved_send_returns_credits_and_closed_error() {
    let (tx, rx) = packet_channel(2);
    for lane in [PacketQueueTx::Priority, PacketQueueTx::Bulk] {
        assert_eq!(
            reserve_packet_prefix(lane.reserved(&tx), lane.capacity(&tx), 1),
            1
        );
    }
    // This is the boundary a receiver can close at while concurrent producers
    // have reserved packet credits but have not submitted their channel items.
    drop(rx);
    for lane in [PacketQueueTx::Priority, PacketQueueTx::Bulk] {
        assert!(
            tx.send_reserved_item(lane, PacketQueueItem::One(forged_priority(0x11)))
                .is_err()
        );
        assert_eq!(lane.reserved(&tx).load(Relaxed), 0);
    }
    assert_eq!(priority_queued_packets(&tx), 0);
    assert_eq!(queued_packets(&tx), 0);
}

#[test]
fn receiver_drop_releases_queued_and_pending_batch_credits() {
    let (tx, mut rx) = packet_channel(2);
    tx.send_packet_batch(packet_batch(
        (0..2)
            .map(|_| {
                received_packet(
                    TransportId::new(1),
                    TransportAddr::from_string("test"),
                    bulk_packet(0xaa),
                )
            })
            .collect(),
    ))
    .unwrap();
    assert_eq!(rx.drain_ready(1, |_| false), 1);
    tx.send_packet_batch(packet_batch(
        (0..64).map(|_| forged_priority(0x11)).collect(),
    ))
    .unwrap();
    assert_eq!(rx.drain_ready(1, |_| false), 1);
    assert_eq!(tx.priority_reserved_packets.load(Relaxed), 63);
    tx.send(forged_priority(0x22)).unwrap();
    drop(rx);
    assert_eq!(tx.priority_reserved_packets.load(Relaxed), 0);
    assert_eq!(bulk_reserved_packets(&tx), 0);
    assert_eq!(priority_queued_packets(&tx), 0);
    assert_eq!(queued_packets(&tx), 0);
}

#[tokio::test]
async fn pending_priority_batch_drains_after_all_senders_close() {
    let (tx, mut rx) = packet_channel(1);
    tx.send_packet_batch(packet_batch(
        (0..4).map(|_| forged_priority(0x11)).collect(),
    ))
    .unwrap();
    assert_eq!(rx.drain_ready(1, |_| false), 1);
    drop(tx);
    for _ in 0..3 {
        assert_eq!(packet_marker(&rx.recv().await.unwrap()), 0x11);
    }
    assert!(rx.recv().await.is_none());
}

#[test]
fn item_drop_returns_credit_when_receiver_closes_during_channel_send() {
    let (tx, rx) = packet_channel(1);
    let reserved = Arc::clone(&tx.priority_reserved_packets);
    let queued = Arc::clone(&tx.priority_queued_packets);
    assert_eq!(reserve_packet_prefix(&reserved, 64, 1), 1);
    let item = ReservedPacketQueueItem {
        item: PacketQueueItem::One(forged_priority(0x11)),
        credits: PacketCredits::new(PacketQueueTx::Priority, &tx, 1),
    };
    // Hold the channel's own send permit across receiver teardown. A manual
    // receiver drain cannot account for an item that has not arrived yet.
    let permit = tx.priority.clone().try_reserve_owned().unwrap();
    drop(rx);
    drop(permit.send(item));
    drop(tx);
    assert_eq!(reserved.load(Relaxed), 0);
    assert_eq!(queued.load(Relaxed), 0);
}
