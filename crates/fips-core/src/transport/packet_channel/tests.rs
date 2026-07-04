use super::*;
use crate::transport::{TransportAddr, TransportId};
use std::sync::atomic::{AtomicUsize, Ordering::Relaxed};
use tokio::sync::mpsc::error::TryRecvError;

const BULK_PACKET_LEN: usize = FMP_MSG1_WIRE_SIZE + 1;

fn priority_msg1(marker: u8) -> Vec<u8> {
    let mut packet = vec![0u8; FMP_MSG1_WIRE_SIZE];
    packet[0] = FMP_PHASE_MSG1;
    *packet.last_mut().expect("priority msg1 has a marker byte") = marker;
    packet
}

fn priority_msg2(marker: u8) -> Vec<u8> {
    let mut packet = vec![0u8; FMP_MSG2_WIRE_SIZE];
    packet[0] = FMP_PHASE_MSG2;
    *packet.last_mut().expect("priority msg2 has a marker byte") = marker;
    packet
}

fn bulk_packet(marker: u8) -> Vec<u8> {
    vec![marker; BULK_PACKET_LEN]
}

fn bulk_packet_len(marker: u8, len: usize) -> Vec<u8> {
    vec![marker; len]
}

fn small_app_packet(marker: u8) -> Vec<u8> {
    vec![marker; 32]
}

#[test]
fn packet_buffer_replace_visible_prefix_can_expand_into_headroom() {
    let mut buffer = PacketBuffer::new(vec![0xaa, 0xbb, 1, 2, 3, 4, 5]);
    assert!(buffer.trim_front(2));

    assert!(buffer.replace_visible_prefix(2, &[9, 8, 7, 6]));

    assert_eq!(buffer.start, 0);
    assert_eq!(buffer.as_slice(), &[9, 8, 7, 6, 3, 4, 5]);
}

fn packet_marker(packet: &ReceivedPacket) -> u8 {
    *packet.data.last().expect("test packet carries a marker")
}

#[test]
fn transport_priority_is_visible_fmp_handshake_only() {
    let addr = TransportAddr::from_string("test");
    let priority_msg1 = ReceivedPacket::new(TransportId::new(1), addr.clone(), priority_msg1(0x11));
    let priority_msg2 = ReceivedPacket::new(TransportId::new(1), addr.clone(), priority_msg2(0x22));
    let small_app = ReceivedPacket::new(TransportId::new(1), addr.clone(), small_app_packet(0x33));
    let malformed_msg1 =
        ReceivedPacket::new(TransportId::new(1), addr.clone(), bulk_packet_len(0x01, 32));
    let wrong_version = ReceivedPacket::new(
        TransportId::new(1),
        addr,
        bulk_packet_len(0x11, FMP_MSG1_WIRE_SIZE),
    );

    assert!(priority_msg1.is_transport_priority());
    assert!(priority_msg2.is_transport_priority());
    assert!(!small_app.is_transport_priority());
    assert!(!malformed_msg1.is_transport_priority());
    assert!(!wrong_version.is_transport_priority());
}

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
        bulk_packet(0xaa),
    ))
    .unwrap();
    tx.send(ReceivedPacket::new(
        TransportId::new(1),
        addr.clone(),
        priority_msg1(0x11),
    ))
    .unwrap();
    tx.send(ReceivedPacket::new(
        TransportId::new(1),
        addr.clone(),
        priority_msg2(0x22),
    ))
    .unwrap();
    tx.send(ReceivedPacket::new(
        TransportId::new(1),
        addr,
        bulk_packet(0xbb),
    ))
    .unwrap();

    assert_eq!(packet_marker(&rx.recv().await.unwrap()), 0x11);
    assert_eq!(packet_marker(&rx.recv().await.unwrap()), 0x22);
    assert_eq!(packet_marker(&rx.recv().await.unwrap()), 0xaa);
    assert_eq!(packet_marker(&rx.recv().await.unwrap()), 0xbb);
}

#[test]
fn packet_channel_try_recv_uses_same_priority_policy() {
    let (tx, mut rx) = packet_channel(10);
    let addr = TransportAddr::from_string("test");

    tx.send(ReceivedPacket::new(
        TransportId::new(1),
        addr.clone(),
        bulk_packet(0xaa),
    ))
    .unwrap();
    tx.send(ReceivedPacket::new(
        TransportId::new(1),
        addr,
        priority_msg1(0x11),
    ))
    .unwrap();

    assert_eq!(packet_marker(&rx.try_recv().unwrap()), 0x11);
    assert_eq!(packet_marker(&rx.try_recv().unwrap()), 0xaa);
}

#[tokio::test]
async fn packet_channel_batch_send_amortizes_bulk_channel_items() {
    let (tx, mut rx) = packet_channel(10);
    let addr = TransportAddr::from_string("test");

    tx.send_batch(vec![
        ReceivedPacket::new(TransportId::new(1), addr.clone(), bulk_packet(0xaa)),
        ReceivedPacket::new(TransportId::new(1), addr.clone(), bulk_packet(0xbb)),
        ReceivedPacket::new(TransportId::new(1), addr, bulk_packet(0xcc)),
    ])
    .expect("bulk batch send should succeed");

    assert_eq!(
        rx.bulk.len(),
        1,
        "bulk kernel receive batch should occupy one channel item"
    );
    assert_eq!(packet_marker(&rx.recv().await.unwrap()), 0xaa);
    assert_eq!(packet_marker(&rx.recv().await.unwrap()), 0xbb);
    assert_eq!(packet_marker(&rx.recv().await.unwrap()), 0xcc);
}

#[tokio::test]
async fn packet_channel_reuses_pooled_batch_container_after_rx_drain() {
    let (tx, mut rx) = packet_channel(10);
    let addr = TransportAddr::from_string("test");
    let mut batch = tx.packet_batch(2);
    batch.push(ReceivedPacket::new(
        TransportId::new(1),
        addr.clone(),
        bulk_packet(0xaa),
    ));
    batch.push(ReceivedPacket::new(
        TransportId::new(1),
        addr,
        bulk_packet(0xbb),
    ));
    let batch_ptr = batch.packets.as_ptr();
    let batch_capacity = batch.packets.capacity();

    tx.send_packet_batch(batch)
        .expect("pooled bulk batch send should succeed");
    assert_eq!(packet_marker(&rx.recv().await.unwrap()), 0xaa);
    assert_eq!(packet_marker(&rx.recv().await.unwrap()), 0xbb);

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
            bulk_packet(0xaa),
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
        bulk_packet(0xaa),
    ))
    .expect("first bulk packet should fill bounded bulk lane");

    let mut buffer = tx.recv_buffer(1600);
    buffer.clear();
    buffer.resize(BULK_PACKET_LEN, 0xbb);
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
fn packet_buffer_trim_front_keeps_visible_payload_canonical() {
    let mut packet = PacketBuffer::new(b"headerpayload".to_vec());

    assert!(packet.trim_front(b"header".len()));
    assert_eq!(packet.as_slice(), b"payload");
    assert_eq!(&packet[..], b"payload");
    assert_eq!(packet.to_vec(), b"payload".to_vec());
    assert_eq!(packet.len(), b"payload".len());

    assert!(packet.try_prepend_slices(&[b"ip"], 0));
    assert_eq!(packet.as_slice(), b"ippayload");
    assert_eq!(packet.clone().into_vec(), b"ippayload".to_vec());
    assert_eq!(packet.into_vec(), b"ippayload".to_vec());
}

#[test]
fn packet_channel_keeps_single_lane_batches_grouped() {
    let (tx, mut rx) = packet_channel(10);
    let addr = TransportAddr::from_string("test");

    tx.send_batch(vec![
        ReceivedPacket::new(TransportId::new(1), addr.clone(), priority_msg1(0x11)),
        ReceivedPacket::new(TransportId::new(1), addr.clone(), priority_msg2(0x22)),
    ])
    .expect("priority batch send should succeed");
    tx.send_batch(vec![
        ReceivedPacket::new(TransportId::new(1), addr.clone(), bulk_packet(0xaa)),
        ReceivedPacket::new(TransportId::new(1), addr, bulk_packet(0xbb)),
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
            assert_eq!(packet_marker(&packets[0]), 0x11);
            assert_eq!(packet_marker(&packets[1]), 0x22);
        }
        item => panic!("expected grouped priority batch, got {item:?}"),
    }
    match rx.bulk.try_recv().expect("bulk channel item") {
        PacketQueueItem::Batch(packets) => {
            assert_eq!(packets.len(), 2);
            assert_eq!(packet_marker(&packets[0]), 0xaa);
            assert_eq!(packet_marker(&packets[1]), 0xbb);
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
        priority_msg1(0x11),
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
        ReceivedPacket::new(TransportId::new(1), addr.clone(), priority_msg1(0x11)),
        ReceivedPacket::new(TransportId::new(1), addr.clone(), priority_msg2(0x22)),
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
        ReceivedPacket::new(TransportId::new(1), addr.clone(), bulk_packet(0xaa)),
        ReceivedPacket::new(TransportId::new(1), addr, bulk_packet(0xbb)),
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
        ReceivedPacket::new(TransportId::new(1), addr.clone(), priority_msg1(0xaa)),
        ReceivedPacket::new(TransportId::new(1), addr, priority_msg2(0xbb)),
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
fn release_reserved_bulk_packets_subtracts_exact_count() {
    let counter = AtomicUsize::new(5);

    release_reserved_bulk_packets(&counter, 0);
    assert_eq!(counter.load(Relaxed), 5);

    release_reserved_bulk_packets(&counter, 3);
    assert_eq!(counter.load(Relaxed), 2);
}

#[test]
fn release_priority_packets_subtracts_exact_count() {
    let counter = AtomicUsize::new(5);

    release_priority_packets(&counter, 0);
    assert_eq!(counter.load(Relaxed), 5);

    release_priority_packets(&counter, 3);
    assert_eq!(counter.load(Relaxed), 2);
}

#[test]
fn packet_channel_priority_hint_counts_channel_owned_packets() {
    let (tx, mut rx) = packet_channel(10);
    let addr = TransportAddr::from_string("test");

    tx.send_batch(vec![
        ReceivedPacket::new(TransportId::new(1), addr.clone(), priority_msg1(0x11)),
        ReceivedPacket::new(TransportId::new(1), addr.clone(), priority_msg2(0x22)),
    ])
    .expect("priority batch send should succeed");
    assert_eq!(tx.priority_queued_packets(), 2);
    assert_eq!(tx.bulk_queued_packets(), 0);

    assert_eq!(packet_marker(&rx.try_recv().unwrap()), 0x11);
    assert_eq!(
        tx.priority_queued_packets(),
        0,
        "once a priority batch is dequeued, its tail is rx-loop-owned"
    );
    assert_eq!(packet_marker(&rx.try_recv().unwrap()), 0x22);
    assert_eq!(tx.priority_queued_packets(), 0);

    tx.send_batch(vec![
        ReceivedPacket::new(TransportId::new(1), addr.clone(), bulk_packet(0xaa)),
        ReceivedPacket::new(TransportId::new(1), addr, bulk_packet(0xbb)),
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
        ReceivedPacket::new(TransportId::new(1), addr.clone(), priority_msg1(0x11)),
        ReceivedPacket::new(TransportId::new(1), addr.clone(), priority_msg2(0x22)),
        ReceivedPacket::new(TransportId::new(1), addr, priority_msg1(0x33)),
    ])
    .expect("priority batch send should succeed");

    assert_eq!(rx.priority_ready_packets(), 3);
    assert_eq!(packet_marker(&rx.try_recv().unwrap()), 0x11);
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
    assert_eq!(packet_marker(&rx.try_recv().unwrap()), 0x22);
    assert_eq!(rx.priority_ready_packets(), 1);
    assert_eq!(packet_marker(&rx.try_recv().unwrap()), 0x33);
    assert_eq!(rx.priority_ready_packets(), 0);
}

#[test]
fn packet_rx_drain_ready_drains_bulk_batch_tail_in_one_call() {
    let (tx, mut rx) = packet_channel(10);
    let addr = TransportAddr::from_string("test");

    tx.send_batch(vec![
        ReceivedPacket::new(TransportId::new(1), addr.clone(), bulk_packet(0xaa)),
        ReceivedPacket::new(TransportId::new(1), addr.clone(), bulk_packet(0xbb)),
        ReceivedPacket::new(TransportId::new(1), addr, bulk_packet(0xcc)),
    ])
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
        tx.queued_packets(),
        0,
        "dequeued batch tail should be rx-loop-owned, not channel-owned"
    );
    assert_eq!(tx.bulk_queued_packets(), 0);
    assert_eq!(packet_marker(&rx.try_recv().unwrap()), 0xcc);
}

#[test]
fn packet_rx_drain_ready_leaves_tail_when_consumer_stops() {
    let (tx, mut rx) = packet_channel(10);
    let addr = TransportAddr::from_string("test");

    tx.send_batch(vec![
        ReceivedPacket::new(TransportId::new(1), addr.clone(), bulk_packet(0xaa)),
        ReceivedPacket::new(TransportId::new(1), addr.clone(), bulk_packet(0xbb)),
        ReceivedPacket::new(TransportId::new(1), addr, bulk_packet(0xcc)),
    ])
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

    tx.send_batch(vec![
        ReceivedPacket::new(TransportId::new(1), addr.clone(), bulk_packet(0xaa)),
        ReceivedPacket::new(TransportId::new(1), addr.clone(), bulk_packet(0xbb)),
    ])
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

    tx.send(ReceivedPacket::new(
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

    tx.send_batch(vec![
        ReceivedPacket::new(TransportId::new(1), addr.clone(), bulk_packet(0xaa)),
        ReceivedPacket::new(TransportId::new(1), addr.clone(), bulk_packet(0xbb)),
    ])
    .expect("bulk batch send should succeed");

    assert_eq!(packet_marker(&rx.recv().await.unwrap()), 0xaa);
    tx.send(ReceivedPacket::new(
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

    tx.send(ReceivedPacket::new(
        TransportId::new(1),
        addr.clone(),
        bulk_packet(0xaa),
    ))
    .expect("first bulk packet should fill bounded bulk lane");
    assert_eq!(tx.queued_packets(), 1);
    assert_eq!(tx.bulk_queued_packets(), 1);

    tx.send(ReceivedPacket::new(
        TransportId::new(1),
        addr.clone(),
        bulk_packet(0xbb),
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
        priority_msg1(0x11),
    ))
    .expect("priority packet should still enter reserve lane");
    assert_eq!(tx.queued_packets(), 2);
    assert_eq!(
        tx.bulk_queued_packets(),
        1,
        "priority packets must not consume bulk packet capacity"
    );

    assert_eq!(packet_marker(&rx.recv().await.unwrap()), 0x11);
    assert_eq!(tx.queued_packets(), 1);
    assert_eq!(tx.bulk_queued_packets(), 1);
    assert_eq!(packet_marker(&rx.recv().await.unwrap()), 0xaa);
    assert_eq!(tx.queued_packets(), 0);
    assert_eq!(tx.bulk_queued_packets(), 0);
    assert!(matches!(rx.try_recv(), Err(TryRecvError::Empty)));
}

#[tokio::test]
async fn packet_channel_bounded_bulk_batch_drop_counts_packets_not_items() {
    let (tx, mut rx) = packet_channel(2);
    let addr = TransportAddr::from_string("test");

    tx.send_batch(vec![
        ReceivedPacket::new(TransportId::new(1), addr.clone(), bulk_packet(0xaa)),
        ReceivedPacket::new(TransportId::new(1), addr.clone(), bulk_packet(0xab)),
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
        ReceivedPacket::new(TransportId::new(1), addr.clone(), bulk_packet(0xbb)),
        ReceivedPacket::new(TransportId::new(1), addr, bulk_packet(0xbc)),
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

    assert_eq!(packet_marker(&rx.recv().await.unwrap()), 0xaa);
    assert_eq!(tx.queued_packets(), 0);
    assert_eq!(tx.bulk_queued_packets(), 0);
    assert_eq!(packet_marker(&rx.recv().await.unwrap()), 0xab);
    assert!(matches!(rx.try_recv(), Err(TryRecvError::Empty)));
}

#[tokio::test]
async fn packet_channel_bounded_bulk_batch_admits_prefix_before_dropping_tail() {
    let (tx, mut rx) = packet_channel(3);
    let addr = TransportAddr::from_string("test");

    tx.send(ReceivedPacket::new(
        TransportId::new(1),
        addr.clone(),
        bulk_packet(0xaa),
    ))
    .expect("first bulk packet should consume one bulk packet credit");
    assert_eq!(tx.queued_packets(), 1);
    assert_eq!(tx.bulk_queued_packets(), 1);

    tx.send_batch(vec![
        ReceivedPacket::new(TransportId::new(1), addr.clone(), bulk_packet(0xbb)),
        ReceivedPacket::new(TransportId::new(1), addr.clone(), bulk_packet(0xbc)),
        ReceivedPacket::new(TransportId::new(1), addr.clone(), bulk_packet(0xbd)),
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
        priority_msg1(0x11),
    ))
    .expect("priority packets should still enter their reserve lane");
    assert_eq!(tx.priority_queued_packets(), 1);
    assert_eq!(tx.bulk_queued_packets(), 3);

    assert_eq!(packet_marker(&rx.recv().await.unwrap()), 0x11);
    assert_eq!(tx.priority_queued_packets(), 0);
    assert_eq!(tx.bulk_queued_packets(), 3);
    assert_eq!(packet_marker(&rx.recv().await.unwrap()), 0xaa);
    assert_eq!(tx.bulk_queued_packets(), 2);
    assert_eq!(packet_marker(&rx.recv().await.unwrap()), 0xbb);
    assert_eq!(
        tx.bulk_queued_packets(),
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

    tx.send(ReceivedPacket::new(
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
        ReceivedPacket::new(TransportId::new(1), addr.clone(), bulk_packet(0xaa)),
        ReceivedPacket::new(TransportId::new(1), addr.clone(), bulk_packet(0xbb)),
        ReceivedPacket::new(TransportId::new(1), addr.clone(), bulk_packet(0xcc)),
    ])
    .expect("bulk batch send should succeed");
    assert_eq!(tx.queued_packets(), 3);
    assert_eq!(tx.bulk_queued_packets(), 3);

    assert_eq!(packet_marker(&rx.try_recv().unwrap()), 0xaa);
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
        priority_msg1(0x11),
    ))
    .expect("priority packet send should succeed");
    assert_eq!(tx.queued_packets(), 1);
    assert_eq!(tx.bulk_queued_packets(), 0);

    assert_eq!(packet_marker(&rx.try_recv().unwrap()), 0x11);
    assert_eq!(tx.queued_packets(), 0);
    assert_eq!(tx.bulk_queued_packets(), 0);
    assert_eq!(packet_marker(&rx.try_recv().unwrap()), 0xbb);
    assert_eq!(packet_marker(&rx.try_recv().unwrap()), 0xcc);
    assert_eq!(tx.queued_packets(), 0);
    assert_eq!(tx.bulk_queued_packets(), 0);
}

#[test]
fn packet_channel_send_failure_rolls_back_backlog() {
    let (tx, rx) = packet_channel(10);
    let addr = TransportAddr::from_string("test");
    drop(rx);

    let packet = ReceivedPacket::new(TransportId::new(1), addr.clone(), priority_msg1(0x11));
    assert!(tx.send(packet).is_err());
    assert_eq!(tx.queued_packets(), 0);
    assert_eq!(tx.priority_queued_packets(), 0);

    let packets = vec![
        ReceivedPacket::new(TransportId::new(1), addr.clone(), priority_msg2(0x22)),
        ReceivedPacket::new(TransportId::new(1), addr.clone(), priority_msg1(0x33)),
    ];
    assert!(tx.send_batch(packets).is_err());
    assert_eq!(tx.queued_packets(), 0);
    assert_eq!(tx.priority_queued_packets(), 0);

    let packets = vec![
        ReceivedPacket::new(TransportId::new(1), addr.clone(), bulk_packet(0xaa)),
        ReceivedPacket::new(TransportId::new(1), addr, bulk_packet(0xbb)),
    ];
    assert!(tx.send_batch(packets).is_err());
    assert_eq!(tx.queued_packets(), 0);
    assert_eq!(tx.bulk_queued_packets(), 0);
}
