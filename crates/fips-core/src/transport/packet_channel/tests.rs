use super::*;
use crate::transport::{TransportAddr, TransportId};
use tokio::sync::mpsc::error::TryRecvError;

#[test]
fn test_received_packet() {
    let packet = ReceivedPacket::new(
        TransportId::new(1),
        TransportAddr::from_string("192.168.1.1:2121"),
        vec![1, 2, 3, 4],
    );

    assert_eq!(packet.transport_id, TransportId::new(1));
    assert_eq!(packet.data, vec![1, 2, 3, 4]);
    assert!(packet.timestamp_ms > 0);
}

#[test]
fn test_received_packet_with_timestamp() {
    let packet = ReceivedPacket::with_timestamp(
        TransportId::new(1),
        TransportAddr::from_string("test"),
        vec![5, 6],
        12345,
    );

    assert_eq!(packet.timestamp_ms, 12345);
}

#[test]
fn packet_buffer_keep_range_reuses_allocation() {
    let mut buffer = PacketBuffer::from(vec![0, 1, 2, 3, 4, 5, 6]);
    let ptr = buffer.as_ptr();
    let capacity = buffer.capacity();

    buffer.keep_range(2, 3);

    assert_eq!(&buffer[..], &[2, 3, 4]);
    assert_eq!(buffer.as_ptr(), ptr);
    assert_eq!(buffer.capacity(), capacity);
}

#[test]
fn packet_buffer_keep_range_can_truncate_from_front() {
    let mut buffer = PacketBuffer::from(vec![0, 1, 2, 3, 4]);
    let ptr = buffer.as_ptr();

    buffer.keep_range(0, 3);

    assert_eq!(&buffer[..], &[0, 1, 2]);
    assert_eq!(buffer.as_ptr(), ptr);
}

#[test]
fn received_packet_can_reuse_batch_timestamps() {
    let trace_enqueued_at = crate::perf_profile::stamp();
    let packet = ReceivedPacket::with_trace_timestamp(
        TransportId::new(7),
        TransportAddr::from_string("batch"),
        vec![8, 9],
        67890,
        trace_enqueued_at,
    );

    assert_eq!(packet.transport_id, TransportId::new(7));
    assert_eq!(packet.timestamp_ms, 67890);
    assert_eq!(packet.trace_enqueued_at, trace_enqueued_at);
}

#[tokio::test]
async fn test_packet_channel() {
    let (tx, mut rx) = packet_channel(10);

    let packet = ReceivedPacket::new(
        TransportId::new(1),
        TransportAddr::from_string("test"),
        vec![1, 2, 3],
    );

    tx.send(packet.clone()).unwrap();

    let received = rx.recv().await.unwrap();
    assert_eq!(received.data, vec![1, 2, 3]);
}

#[tokio::test]
async fn packet_channel_reserves_priority_progress_ahead_of_bulk_backlog() {
    let (tx, mut rx) = packet_channel(10);
    let addr = TransportAddr::from_string("test");

    tx.send(ReceivedPacket::new(
        TransportId::new(1),
        addr.clone(),
        vec![0xaa; PRIORITY_PACKET_MAX_LEN + 1],
    ))
    .unwrap();
    tx.send(ReceivedPacket::new(
        TransportId::new(1),
        addr.clone(),
        vec![0x11; 32],
    ))
    .unwrap();
    tx.send(ReceivedPacket::new(
        TransportId::new(1),
        addr.clone(),
        vec![0x22; 48],
    ))
    .unwrap();
    tx.send(ReceivedPacket::new(
        TransportId::new(1),
        addr,
        vec![0xbb; PRIORITY_PACKET_MAX_LEN + 2],
    ))
    .unwrap();

    assert_eq!(rx.recv().await.unwrap().data[0], 0x11);
    assert_eq!(rx.recv().await.unwrap().data[0], 0x22);
    assert_eq!(rx.recv().await.unwrap().data[0], 0xaa);
    assert_eq!(rx.recv().await.unwrap().data[0], 0xbb);
}

#[test]
fn packet_channel_try_recv_uses_same_priority_policy() {
    let (tx, mut rx) = packet_channel(10);
    let addr = TransportAddr::from_string("test");

    tx.send(ReceivedPacket::new(
        TransportId::new(1),
        addr.clone(),
        vec![0xaa; PRIORITY_PACKET_MAX_LEN + 1],
    ))
    .unwrap();
    tx.send(ReceivedPacket::new(
        TransportId::new(1),
        addr,
        vec![0x11; 32],
    ))
    .unwrap();

    assert_eq!(rx.try_recv().unwrap().data[0], 0x11);
    assert_eq!(rx.try_recv().unwrap().data[0], 0xaa);
}

#[tokio::test]
async fn packet_channel_batch_send_amortizes_bulk_channel_items() {
    let (tx, mut rx) = packet_channel(10);
    let addr = TransportAddr::from_string("test");

    tx.send_batch(vec![
        ReceivedPacket::new(
            TransportId::new(1),
            addr.clone(),
            vec![0xaa; PRIORITY_PACKET_MAX_LEN + 1],
        ),
        ReceivedPacket::new(
            TransportId::new(1),
            addr.clone(),
            vec![0xbb; PRIORITY_PACKET_MAX_LEN + 2],
        ),
        ReceivedPacket::new(
            TransportId::new(1),
            addr,
            vec![0xcc; PRIORITY_PACKET_MAX_LEN + 3],
        ),
    ])
    .expect("bulk batch send should succeed");

    assert_eq!(
        rx.bulk.len(),
        1,
        "bulk kernel receive batch should occupy one channel item"
    );
    assert_eq!(rx.recv().await.unwrap().data[0], 0xaa);
    assert_eq!(rx.recv().await.unwrap().data[0], 0xbb);
    assert_eq!(rx.recv().await.unwrap().data[0], 0xcc);
}

#[tokio::test]
async fn packet_channel_reuses_pooled_batch_container_after_rx_drain() {
    let (tx, mut rx) = packet_channel(10);
    let addr = TransportAddr::from_string("test");
    let mut batch = tx.packet_batch(2);
    batch.push(ReceivedPacket::new(
        TransportId::new(1),
        addr.clone(),
        vec![0xaa; PRIORITY_PACKET_MAX_LEN + 1],
    ));
    batch.push(ReceivedPacket::new(
        TransportId::new(1),
        addr,
        vec![0xbb; PRIORITY_PACKET_MAX_LEN + 2],
    ));
    let batch_ptr = batch.packets.as_ptr();
    let batch_capacity = batch.packets.capacity();

    tx.send_packet_batch(batch)
        .expect("pooled bulk batch send should succeed");
    assert_eq!(rx.recv().await.unwrap().data[0], 0xaa);
    assert_eq!(rx.recv().await.unwrap().data[0], 0xbb);

    let reused = tx.packet_batch(2);
    assert_eq!(reused.packets.len(), 0);
    assert_eq!(reused.packets.capacity(), batch_capacity);
    assert_eq!(reused.packets.as_ptr(), batch_ptr);
}

#[test]
fn packet_channel_does_not_retain_oversized_batch_container() {
    let pool = PacketBatchPool::new();
    {
        let mut batch = pool.take(PACKET_BATCH_MAX_RETAINED_CAPACITY + 1);
        batch.push(ReceivedPacket::new(
            TransportId::new(1),
            TransportAddr::from_string("test"),
            vec![0xaa; PRIORITY_PACKET_MAX_LEN + 1],
        ));
    }

    assert_eq!(
        pool.cached_len(),
        0,
        "oversized receive batches should not stay pinned in the hot-path pool"
    );
}

#[test]
fn packet_channel_recycles_pooled_packet_buffer_when_bulk_batch_is_dropped() {
    let (tx, _rx) = packet_channel(1);
    let addr = TransportAddr::from_string("test");

    tx.send(ReceivedPacket::new(
        TransportId::new(1),
        addr.clone(),
        vec![0xaa; PRIORITY_PACKET_MAX_LEN + 1],
    ))
    .expect("first bulk packet should fill bounded bulk lane");

    let mut buffer = tx.recv_buffer(1600);
    buffer.clear();
    buffer.resize(PRIORITY_PACKET_MAX_LEN + 2, 0xbb);
    let original_ptr = buffer.as_ptr();
    let mut batch = tx.packet_batch(1);
    batch.push(ReceivedPacket::new(
        TransportId::new(1),
        addr,
        tx.packet_buffer(buffer),
    ));

    tx.send_packet_batch(batch)
        .expect("full bulk lane should shed pooled overload without closing sender");

    assert_eq!(
        tx.buffer_pool.cached_len(),
        1,
        "dropped receive-owned bulk packet should return its byte buffer"
    );
    let reused = tx.recv_buffer(1600);
    assert_eq!(
        reused.as_ptr(),
        original_ptr,
        "next receive refill should reuse the dropped packet buffer"
    );
}

#[test]
fn packet_channel_keeps_single_lane_batches_grouped() {
    let (tx, mut rx) = packet_channel(10);
    let addr = TransportAddr::from_string("test");

    tx.send_batch(vec![
        ReceivedPacket::new(TransportId::new(1), addr.clone(), vec![0x11; 32]),
        ReceivedPacket::new(TransportId::new(1), addr.clone(), vec![0x22; 48]),
    ])
    .expect("priority batch send should succeed");
    tx.send_batch(vec![
        ReceivedPacket::new(
            TransportId::new(1),
            addr.clone(),
            vec![0xaa; PRIORITY_PACKET_MAX_LEN + 1],
        ),
        ReceivedPacket::new(
            TransportId::new(1),
            addr,
            vec![0xbb; PRIORITY_PACKET_MAX_LEN + 2],
        ),
    ])
    .expect("bulk batch send should succeed");

    assert_eq!(
        rx.priority.len(),
        1,
        "priority-only receive batch should occupy one channel item"
    );
    assert_eq!(
        rx.bulk.len(),
        1,
        "bulk-only receive batch should occupy one channel item"
    );
    match rx.priority.try_recv().expect("priority channel item") {
        PacketQueueItem::Batch(packets) => {
            assert_eq!(packets.len(), 2);
            assert_eq!(packets[0].data[0], 0x11);
            assert_eq!(packets[1].data[0], 0x22);
        }
        item => panic!("expected grouped priority batch, got {item:?}"),
    }
    match rx.bulk.try_recv().expect("bulk channel item") {
        PacketQueueItem::Batch(packets) => {
            assert_eq!(packets.len(), 2);
            assert_eq!(packets[0].data[0], 0xaa);
            assert_eq!(packets[1].data[0], 0xbb);
        }
        item => panic!("expected grouped bulk batch, got {item:?}"),
    }
}

#[test]
fn packet_channel_dequeue_counts_preserve_item_and_lane_counts() {
    let addr = TransportAddr::from_string("test");

    let item = PacketQueueItem::One(ReceivedPacket::new(
        TransportId::new(1),
        addr.clone(),
        vec![0x11; 32],
    ));
    assert_eq!(
        item.dequeue_counts(PacketLane::Priority),
        PacketQueueDequeueCounts {
            total: 1,
            priority: 1,
            bulk: 0,
        }
    );

    let item = PacketQueueItem::Batch(PacketBatch::from(vec![
        ReceivedPacket::new(TransportId::new(1), addr.clone(), vec![0x11; 32]),
        ReceivedPacket::new(TransportId::new(1), addr.clone(), vec![0x22; 48]),
    ]));
    assert_eq!(
        item.dequeue_counts(PacketLane::Priority),
        PacketQueueDequeueCounts {
            total: 2,
            priority: 2,
            bulk: 0,
        }
    );

    let item = PacketQueueItem::Batch(PacketBatch::from(vec![
        ReceivedPacket::new(
            TransportId::new(1),
            addr.clone(),
            vec![0xaa; PRIORITY_PACKET_MAX_LEN + 1],
        ),
        ReceivedPacket::new(
            TransportId::new(1),
            addr,
            vec![0xbb; PRIORITY_PACKET_MAX_LEN + 2],
        ),
    ]));
    assert_eq!(
        item.dequeue_counts(PacketLane::Bulk),
        PacketQueueDequeueCounts {
            total: 2,
            priority: 0,
            bulk: 2,
        }
    );
}

#[test]
fn pending_packets_apply_rx_loop_owned_stamp_as_packets_are_taken() {
    let addr = TransportAddr::from_string("test");
    let rx_loop_owned_at = Some(crate::perf_profile::test_stamp());
    let packets = PacketBatch::from(vec![
        ReceivedPacket::new(TransportId::new(1), addr.clone(), vec![0xaa; 32]),
        ReceivedPacket::new(TransportId::new(1), addr, vec![0xbb; 48]),
    ]);
    let mut pending = Some(PendingPackets::new(packets, rx_loop_owned_at));

    let first = PacketRx::take_pending(&mut pending).expect("first pending packet");
    assert_eq!(first.trace_rx_loop_owned_at, rx_loop_owned_at);
    assert!(
        pending.is_some(),
        "one packet should remain after taking the first pending packet"
    );

    let second = PacketRx::take_pending(&mut pending).expect("second pending packet");
    assert_eq!(second.trace_rx_loop_owned_at, rx_loop_owned_at);
    assert!(
        pending.is_none(),
        "pending batch should clear after the last packet is taken"
    );
}

#[test]
fn packet_channel_priority_hint_counts_channel_owned_packets() {
    let (tx, mut rx) = packet_channel(10);
    let addr = TransportAddr::from_string("test");

    tx.send_batch(vec![
        ReceivedPacket::new(TransportId::new(1), addr.clone(), vec![0x11; 32]),
        ReceivedPacket::new(TransportId::new(1), addr.clone(), vec![0x22; 48]),
    ])
    .expect("priority batch send should succeed");
    assert_eq!(tx.priority_queued_packets(), 2);
    assert_eq!(tx.bulk_queued_packets(), 0);

    assert_eq!(rx.try_recv().unwrap().data[0], 0x11);
    assert_eq!(
        tx.priority_queued_packets(),
        0,
        "once a priority batch is dequeued, its tail is rx-loop-owned"
    );
    assert_eq!(rx.try_recv().unwrap().data[0], 0x22);
    assert_eq!(tx.priority_queued_packets(), 0);

    tx.send_batch(vec![
        ReceivedPacket::new(
            TransportId::new(1),
            addr.clone(),
            vec![0xaa; PRIORITY_PACKET_MAX_LEN + 1],
        ),
        ReceivedPacket::new(
            TransportId::new(1),
            addr,
            vec![0xbb; PRIORITY_PACKET_MAX_LEN + 2],
        ),
    ])
    .expect("bulk batch send should succeed");
    assert_eq!(
        tx.priority_queued_packets(),
        0,
        "bulk traffic should not make PacketRx probe the priority lane"
    );
}

#[test]
fn packet_rx_priority_ready_includes_pending_batch_tail() {
    let (tx, mut rx) = packet_channel(10);
    let addr = TransportAddr::from_string("test");

    tx.send_batch(vec![
        ReceivedPacket::new(TransportId::new(1), addr.clone(), vec![0x11; 32]),
        ReceivedPacket::new(TransportId::new(1), addr.clone(), vec![0x22; 48]),
        ReceivedPacket::new(TransportId::new(1), addr, vec![0x33; 64]),
    ])
    .expect("priority batch send should succeed");

    assert_eq!(rx.priority_ready_packets(), 3);
    assert_eq!(rx.try_recv().unwrap().data[0], 0x11);
    assert_eq!(
        tx.priority_queued_packets(),
        0,
        "sender-side channel hint should clear once PacketRx owns the batch"
    );
    assert_eq!(
        rx.priority_ready_packets(),
        2,
        "rx-loop scheduling must still see the priority batch tail"
    );
    assert_eq!(rx.try_recv().unwrap().data[0], 0x22);
    assert_eq!(rx.priority_ready_packets(), 1);
    assert_eq!(rx.try_recv().unwrap().data[0], 0x33);
    assert_eq!(rx.priority_ready_packets(), 0);
}

#[tokio::test]
async fn packet_channel_priority_overtakes_pending_bulk_batch_tail() {
    let (tx, mut rx) = packet_channel(10);
    let addr = TransportAddr::from_string("test");

    tx.send_batch(vec![
        ReceivedPacket::new(
            TransportId::new(1),
            addr.clone(),
            vec![0xaa; PRIORITY_PACKET_MAX_LEN + 1],
        ),
        ReceivedPacket::new(
            TransportId::new(1),
            addr.clone(),
            vec![0xbb; PRIORITY_PACKET_MAX_LEN + 2],
        ),
    ])
    .expect("bulk batch send should succeed");

    assert_eq!(rx.recv().await.unwrap().data[0], 0xaa);
    tx.send(ReceivedPacket::new(
        TransportId::new(1),
        addr,
        vec![0x11; 32],
    ))
    .expect("priority packet send should succeed");

    assert_eq!(rx.recv().await.unwrap().data[0], 0x11);
    assert_eq!(rx.recv().await.unwrap().data[0], 0xbb);
}

#[tokio::test]
async fn packet_channel_bounded_bulk_drops_without_blocking_priority() {
    let (tx, mut rx) = packet_channel(1);
    let addr = TransportAddr::from_string("test");

    tx.send(ReceivedPacket::new(
        TransportId::new(1),
        addr.clone(),
        vec![0xaa; PRIORITY_PACKET_MAX_LEN + 1],
    ))
    .expect("first bulk packet should fill bounded bulk lane");
    assert_eq!(tx.queued_packets(), 1);
    assert_eq!(tx.bulk_queued_packets(), 1);

    tx.send(ReceivedPacket::new(
        TransportId::new(1),
        addr.clone(),
        vec![0xbb; PRIORITY_PACKET_MAX_LEN + 2],
    ))
    .expect("full bulk lane should drop overload without closing sender");
    assert_eq!(
        tx.queued_packets(),
        1,
        "dropped bulk must roll back channel-owned backlog accounting"
    );
    assert_eq!(tx.bulk_queued_packets(), 1);
    assert_eq!(rx.bulk.len(), 1);

    tx.send(ReceivedPacket::new(
        TransportId::new(1),
        addr,
        vec![0x11; 32],
    ))
    .expect("priority packet should still enter reserve lane");
    assert_eq!(tx.queued_packets(), 2);
    assert_eq!(
        tx.bulk_queued_packets(),
        1,
        "priority packets must not consume bulk packet capacity"
    );

    assert_eq!(rx.recv().await.unwrap().data[0], 0x11);
    assert_eq!(tx.queued_packets(), 1);
    assert_eq!(tx.bulk_queued_packets(), 1);
    assert_eq!(rx.recv().await.unwrap().data[0], 0xaa);
    assert_eq!(tx.queued_packets(), 0);
    assert_eq!(tx.bulk_queued_packets(), 0);
    assert!(matches!(rx.try_recv(), Err(TryRecvError::Empty)));
}

#[tokio::test]
async fn packet_channel_bounded_priority_drops_without_blocking_bulk() {
    crate::perf_profile::force_event_counters_for_test();
    let dropped_before = crate::perf_profile::event_count_for_test(
        crate::perf_profile::Event::TransportPriorityDropped,
    );
    let (tx, mut rx) = packet_channel(1);
    let addr = TransportAddr::from_string("test");

    tx.send(ReceivedPacket::new(
        TransportId::new(1),
        addr.clone(),
        vec![0x11; 32],
    ))
    .expect("first priority packet should fill bounded priority lane");
    assert_eq!(tx.queued_packets(), 1);
    assert_eq!(tx.priority_queued_packets(), 1);

    tx.send(ReceivedPacket::new(
        TransportId::new(1),
        addr.clone(),
        vec![0x22; 48],
    ))
    .expect("full priority lane should drop overload without closing sender");
    assert!(
        crate::perf_profile::event_count_for_test(
            crate::perf_profile::Event::TransportPriorityDropped
        ) - dropped_before
            >= 1
    );
    assert_eq!(tx.queued_packets(), 1);
    assert_eq!(tx.priority_queued_packets(), 1);

    tx.send(ReceivedPacket::new(
        TransportId::new(1),
        addr,
        vec![0xaa; PRIORITY_PACKET_MAX_LEN + 1],
    ))
    .expect("bulk packet should still enter its separate bounded lane");
    assert_eq!(tx.queued_packets(), 2);
    assert_eq!(tx.bulk_queued_packets(), 1);

    assert_eq!(rx.recv().await.unwrap().data[0], 0x11);
    assert_eq!(tx.priority_queued_packets(), 0);
    assert_eq!(rx.recv().await.unwrap().data[0], 0xaa);
    assert_eq!(tx.bulk_queued_packets(), 0);
    assert!(matches!(rx.try_recv(), Err(TryRecvError::Empty)));
}

#[tokio::test]
async fn packet_channel_bounded_bulk_batch_drop_counts_packets_not_items() {
    let (tx, mut rx) = packet_channel(2);
    let addr = TransportAddr::from_string("test");

    tx.send_batch(vec![
        ReceivedPacket::new(
            TransportId::new(1),
            addr.clone(),
            vec![0xaa; PRIORITY_PACKET_MAX_LEN + 1],
        ),
        ReceivedPacket::new(
            TransportId::new(1),
            addr.clone(),
            vec![0xab; PRIORITY_PACKET_MAX_LEN + 2],
        ),
    ])
    .expect("first bulk batch should fill bounded bulk lane");
    assert_eq!(tx.queued_packets(), 2);
    assert_eq!(tx.bulk_queued_packets(), 2);
    assert_eq!(
        rx.bulk.len(),
        1,
        "batching should still amortize channel items"
    );

    tx.send_batch(vec![
        ReceivedPacket::new(
            TransportId::new(1),
            addr.clone(),
            vec![0xbb; PRIORITY_PACKET_MAX_LEN + 3],
        ),
        ReceivedPacket::new(
            TransportId::new(1),
            addr,
            vec![0xbc; PRIORITY_PACKET_MAX_LEN + 4],
        ),
    ])
    .expect("full bulk packet budget should drop batch overload without closing sender");
    assert_eq!(
        tx.queued_packets(),
        2,
        "dropped bulk batch must roll back every packet it accounted"
    );
    assert_eq!(
        tx.bulk_queued_packets(),
        2,
        "dropped bulk batch must not expand the packet-count backlog"
    );
    assert_eq!(rx.bulk.len(), 1);

    assert_eq!(rx.recv().await.unwrap().data[0], 0xaa);
    assert_eq!(tx.queued_packets(), 0);
    assert_eq!(tx.bulk_queued_packets(), 0);
    assert_eq!(rx.recv().await.unwrap().data[0], 0xab);
    assert!(matches!(rx.try_recv(), Err(TryRecvError::Empty)));
}

#[tokio::test]
async fn packet_channel_bounded_bulk_batch_admits_prefix_before_dropping_tail() {
    let (tx, mut rx) = packet_channel(3);
    let addr = TransportAddr::from_string("test");

    tx.send(ReceivedPacket::new(
        TransportId::new(1),
        addr.clone(),
        vec![0xaa; PRIORITY_PACKET_MAX_LEN + 1],
    ))
    .expect("first bulk packet should consume one bulk packet credit");
    assert_eq!(tx.queued_packets(), 1);
    assert_eq!(tx.bulk_queued_packets(), 1);

    tx.send_batch(vec![
        ReceivedPacket::new(
            TransportId::new(1),
            addr.clone(),
            vec![0xbb; PRIORITY_PACKET_MAX_LEN + 2],
        ),
        ReceivedPacket::new(
            TransportId::new(1),
            addr.clone(),
            vec![0xbc; PRIORITY_PACKET_MAX_LEN + 3],
        ),
        ReceivedPacket::new(
            TransportId::new(1),
            addr.clone(),
            vec![0xbd; PRIORITY_PACKET_MAX_LEN + 4],
        ),
    ])
    .expect("partial bulk admission should shed only overflow tail");
    assert_eq!(
        tx.queued_packets(),
        3,
        "only the admitted prefix should count as channel-owned"
    );
    assert_eq!(
        tx.bulk_queued_packets(),
        3,
        "bulk packet credits should be capped at channel capacity"
    );
    assert_eq!(
        rx.bulk.len(),
        2,
        "the admitted prefix should stay grouped behind the already queued packet"
    );

    tx.send(ReceivedPacket::new(
        TransportId::new(1),
        addr,
        vec![0x11; 32],
    ))
    .expect("priority packets should still enter their reserve lane");
    assert_eq!(tx.priority_queued_packets(), 1);
    assert_eq!(tx.bulk_queued_packets(), 3);

    assert_eq!(rx.recv().await.unwrap().data[0], 0x11);
    assert_eq!(tx.priority_queued_packets(), 0);
    assert_eq!(tx.bulk_queued_packets(), 3);
    assert_eq!(rx.recv().await.unwrap().data[0], 0xaa);
    assert_eq!(tx.bulk_queued_packets(), 2);
    assert_eq!(rx.recv().await.unwrap().data[0], 0xbb);
    assert_eq!(
        tx.bulk_queued_packets(),
        0,
        "dequeued bulk batch should release all admitted prefix credits"
    );
    assert_eq!(rx.recv().await.unwrap().data[0], 0xbc);
    assert!(matches!(rx.try_recv(), Err(TryRecvError::Empty)));
}

#[tokio::test]
async fn packet_channel_bounded_priority_batch_admits_prefix_before_dropping_tail() {
    crate::perf_profile::force_event_counters_for_test();
    let dropped_before = crate::perf_profile::event_count_for_test(
        crate::perf_profile::Event::TransportPriorityDropped,
    );
    let (tx, mut rx) = packet_channel(2);
    let addr = TransportAddr::from_string("test");

    tx.send_batch(vec![
        ReceivedPacket::new(TransportId::new(1), addr.clone(), vec![0x11; 32]),
        ReceivedPacket::new(TransportId::new(1), addr.clone(), vec![0x22; 48]),
        ReceivedPacket::new(TransportId::new(1), addr, vec![0x33; 64]),
    ])
    .expect("partial priority admission should shed only overflow tail");
    assert!(
        crate::perf_profile::event_count_for_test(
            crate::perf_profile::Event::TransportPriorityDropped
        ) - dropped_before
            >= 1
    );
    assert_eq!(tx.queued_packets(), 2);
    assert_eq!(tx.priority_queued_packets(), 2);

    assert_eq!(rx.recv().await.unwrap().data[0], 0x11);
    assert_eq!(
        tx.priority_queued_packets(),
        0,
        "dequeued priority batch should release all admitted prefix credits"
    );
    assert_eq!(rx.recv().await.unwrap().data[0], 0x22);
    assert!(matches!(rx.try_recv(), Err(TryRecvError::Empty)));
}

#[test]
fn packet_channel_partial_bulk_drop_recycles_overflow_packet_buffers() {
    let (tx, _rx) = packet_channel(2);
    let addr = TransportAddr::from_string("test");

    tx.send(ReceivedPacket::new(
        TransportId::new(1),
        addr.clone(),
        vec![0xaa; PRIORITY_PACKET_MAX_LEN + 1],
    ))
    .expect("first bulk packet should leave one credit free");

    let mut admitted = tx.recv_buffer(1600);
    admitted.clear();
    admitted.resize(PRIORITY_PACKET_MAX_LEN + 2, 0xbb);
    let mut dropped = tx.recv_buffer(1600);
    dropped.clear();
    dropped.resize(PRIORITY_PACKET_MAX_LEN + 3, 0xbc);
    let dropped_ptr = dropped.as_ptr();

    let mut batch = tx.packet_batch(2);
    batch.push(ReceivedPacket::new(
        TransportId::new(1),
        addr.clone(),
        tx.packet_buffer(admitted),
    ));
    batch.push(ReceivedPacket::new(
        TransportId::new(1),
        addr,
        tx.packet_buffer(dropped),
    ));

    tx.send_packet_batch(batch)
        .expect("partial bulk admission should not close sender");
    assert_eq!(
        tx.buffer_pool.cached_len(),
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

    assert_eq!(tx.queued_packets(), 0);
    tx.send_batch(vec![
        ReceivedPacket::new(
            TransportId::new(1),
            addr.clone(),
            vec![0xaa; PRIORITY_PACKET_MAX_LEN + 1],
        ),
        ReceivedPacket::new(
            TransportId::new(1),
            addr.clone(),
            vec![0xbb; PRIORITY_PACKET_MAX_LEN + 2],
        ),
        ReceivedPacket::new(
            TransportId::new(1),
            addr.clone(),
            vec![0xcc; PRIORITY_PACKET_MAX_LEN + 3],
        ),
    ])
    .expect("bulk batch send should succeed");
    assert_eq!(tx.queued_packets(), 3);
    assert_eq!(tx.bulk_queued_packets(), 3);

    assert_eq!(rx.try_recv().unwrap().data[0], 0xaa);
    assert_eq!(
        tx.queued_packets(),
        0,
        "once a batch item is dequeued, its tail is rx-loop-owned, not channel-owned"
    );
    assert_eq!(
        tx.bulk_queued_packets(),
        0,
        "bulk capacity is released when the rx loop owns the batch tail"
    );

    tx.send(ReceivedPacket::new(
        TransportId::new(1),
        addr,
        vec![0x11; 32],
    ))
    .expect("priority packet send should succeed");
    assert_eq!(tx.queued_packets(), 1);
    assert_eq!(tx.bulk_queued_packets(), 0);

    assert_eq!(rx.try_recv().unwrap().data[0], 0x11);
    assert_eq!(tx.queued_packets(), 0);
    assert_eq!(tx.bulk_queued_packets(), 0);
    assert_eq!(rx.try_recv().unwrap().data[0], 0xbb);
    assert_eq!(rx.try_recv().unwrap().data[0], 0xcc);
    assert_eq!(tx.queued_packets(), 0);
    assert_eq!(tx.bulk_queued_packets(), 0);
}

#[test]
fn packet_channel_send_failure_rolls_back_backlog() {
    let (tx, rx) = packet_channel(10);
    let addr = TransportAddr::from_string("test");
    drop(rx);

    let packet = ReceivedPacket::new(TransportId::new(1), addr.clone(), vec![0x11; 32]);
    assert!(tx.send(packet).is_err());
    assert_eq!(tx.queued_packets(), 0);
    assert_eq!(tx.priority_queued_packets(), 0);

    let packets = vec![
        ReceivedPacket::new(TransportId::new(1), addr.clone(), vec![0x22; 48]),
        ReceivedPacket::new(TransportId::new(1), addr.clone(), vec![0x33; 64]),
    ];
    assert!(tx.send_batch(packets).is_err());
    assert_eq!(tx.queued_packets(), 0);
    assert_eq!(tx.priority_queued_packets(), 0);

    let packets = vec![
        ReceivedPacket::new(
            TransportId::new(1),
            addr.clone(),
            vec![0xaa; PRIORITY_PACKET_MAX_LEN + 1],
        ),
        ReceivedPacket::new(
            TransportId::new(1),
            addr,
            vec![0xbb; PRIORITY_PACKET_MAX_LEN + 2],
        ),
    ];
    assert!(tx.send_batch(packets).is_err());
    assert_eq!(tx.queued_packets(), 0);
    assert_eq!(tx.bulk_queued_packets(), 0);
}
