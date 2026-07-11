use super::*;
use crate::transport::{TransportAddr, TransportId};
use std::sync::atomic::{AtomicUsize, Ordering::Relaxed};
use tokio::sync::mpsc::error::TryRecvError;

const BULK_PACKET_LEN: usize = FMP_MSG1_WIRE_SIZE + 1;

fn priority_msg1(marker: u8) -> PacketBuffer {
    let mut packet = vec![0u8; FMP_MSG1_WIRE_SIZE];
    packet[0] = FMP_PHASE_MSG1;
    *packet.last_mut().expect("priority msg1 has a marker byte") = marker;
    PacketBuffer::new(packet)
}

fn priority_msg2(marker: u8) -> PacketBuffer {
    let mut packet = vec![0u8; FMP_MSG2_WIRE_SIZE];
    packet[0] = FMP_PHASE_MSG2;
    *packet.last_mut().expect("priority msg2 has a marker byte") = marker;
    PacketBuffer::new(packet)
}

fn bulk_packet(marker: u8) -> PacketBuffer {
    PacketBuffer::new(vec![marker; BULK_PACKET_LEN])
}

fn bulk_packet_len(marker: u8, len: usize) -> PacketBuffer {
    PacketBuffer::new(vec![marker; len])
}

fn established_fmp_packet(payload_len: usize, marker: u8) -> PacketBuffer {
    let mut packet = vec![0u8; FMP_ESTABLISHED_HEADER_SIZE + payload_len + AEAD_TAG_SIZE];
    packet[0] = FMP_PHASE_ESTABLISHED;
    packet[2..4].copy_from_slice(&(payload_len as u16).to_le_bytes());
    *packet
        .last_mut()
        .expect("established FMP packet has a marker byte") = marker;
    PacketBuffer::new(packet)
}

fn established_fmp_packet_with_actual_len(
    payload_len: usize,
    actual_len: usize,
    marker: u8,
) -> PacketBuffer {
    let mut packet = vec![0u8; actual_len];
    packet[0] = FMP_PHASE_ESTABLISHED;
    packet[2..4].copy_from_slice(&(payload_len as u16).to_le_bytes());
    *packet
        .last_mut()
        .expect("established FMP packet has a marker byte") = marker;
    PacketBuffer::new(packet)
}

fn direct_fsp_packet(payload_len: usize, marker: u8) -> PacketBuffer {
    let mut packet =
        vec![0u8; crate::node::session_wire::FSP_HEADER_SIZE + payload_len + AEAD_TAG_SIZE];
    packet[0] = FMP_PHASE_ESTABLISHED;
    packet[2..4].copy_from_slice(&(payload_len as u16).to_le_bytes());
    *packet
        .last_mut()
        .expect("direct FSP packet has a marker byte") = marker;
    PacketBuffer::new(packet)
}

fn small_app_packet(marker: u8) -> PacketBuffer {
    PacketBuffer::new(vec![marker; 32])
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
    *packet
        .data
        .as_slice()
        .last()
        .expect("test packet carries a marker")
}

fn received_packet(
    transport_id: TransportId,
    remote_addr: TransportAddr,
    data: PacketBuffer,
) -> ReceivedPacket {
    ReceivedPacket::with_timestamp(transport_id, remote_addr, data, 1)
}

fn packet_batch(packets: Vec<ReceivedPacket>) -> PacketBatch {
    PacketBatch {
        packets,
        pool: None,
    }
}

fn packet_batch_pool_cached_len(pool: &PacketBatchPool) -> usize {
    pool.inner
        .lock()
        .unwrap_or_else(|error| error.into_inner())
        .len()
}

fn packet_buffer_pool_cached_len(pool: &PacketBufferPool) -> usize {
    pool.available.load(Relaxed)
}

#[test]
fn packet_buffer_batch_recycle_preserves_pool_accounting() {
    let (tx, _rx) = packet_channel(1);
    let first = tx.recv_buffer(1600);
    let first_ptr = first.as_ptr();
    let second = tx.recv_buffer(1600);
    let second_ptr = second.as_ptr();
    let mut packets = [tx.packet_buffer(first), tx.packet_buffer(second)];

    PacketBuffer::recycle_batch(&mut packets);

    assert_eq!(packet_buffer_pool_cached_len(&tx.buffer_pool), 2);
    let reused = [tx.recv_buffer(1600), tx.recv_buffer(1600)];
    assert!(reused.iter().any(|buffer| buffer.as_ptr() == first_ptr));
    assert!(reused.iter().any(|buffer| buffer.as_ptr() == second_ptr));
}

fn queued_packets(tx: &PacketTx) -> usize {
    tx.queued_packets.load(Relaxed)
}

fn priority_queued_packets(tx: &PacketTx) -> usize {
    tx.priority_queued_packets.load(Relaxed)
}

fn bulk_queued_packets(tx: &PacketTx) -> usize {
    tx.bulk_queued_packets.load(Relaxed)
}

#[test]
fn transport_priority_is_visible_fmp_handshake_liveness_and_mmp_only() {
    let addr = TransportAddr::from_string("test");
    let priority_msg1 = received_packet(TransportId::new(1), addr.clone(), priority_msg1(0x11));
    let priority_msg2 = received_packet(TransportId::new(1), addr.clone(), priority_msg2(0x22));
    let heartbeat = received_packet(
        TransportId::new(1),
        addr.clone(),
        established_fmp_packet(FMP_HEARTBEAT_PLAINTEXT_SIZE, 0x33),
    );
    let sender_report = received_packet(
        TransportId::new(1),
        addr.clone(),
        established_fmp_packet(FMP_MMP_SENDER_REPORT_PLAINTEXT_SIZE, 0x44),
    );
    let receiver_report = received_packet(
        TransportId::new(1),
        addr.clone(),
        established_fmp_packet(FMP_MMP_RECEIVER_REPORT_PLAINTEXT_SIZE, 0x55),
    );
    let small_app = received_packet(TransportId::new(1), addr.clone(), small_app_packet(0x33));
    let malformed_msg1 =
        received_packet(TransportId::new(1), addr.clone(), bulk_packet_len(0x01, 32));
    let malformed_established = received_packet(
        TransportId::new(1),
        addr.clone(),
        established_fmp_packet_with_actual_len(
            FMP_HEARTBEAT_PLAINTEXT_SIZE,
            FMP_ESTABLISHED_HEADER_SIZE + FMP_HEARTBEAT_PLAINTEXT_SIZE + AEAD_TAG_SIZE + 1,
            0x66,
        ),
    );
    let large_established = received_packet(
        TransportId::new(1),
        addr.clone(),
        established_fmp_packet(1200, 0x77),
    );
    let direct_fsp = received_packet(
        TransportId::new(1),
        addr.clone(),
        direct_fsp_packet(FMP_HEARTBEAT_PLAINTEXT_SIZE, 0x88),
    );
    let wrong_version = received_packet(
        TransportId::new(1),
        addr,
        bulk_packet_len(0x11, FMP_MSG1_WIRE_SIZE),
    );

    assert!(priority_msg1.is_transport_priority());
    assert!(priority_msg2.is_transport_priority());
    assert!(heartbeat.is_transport_priority());
    assert!(sender_report.is_transport_priority());
    assert!(receiver_report.is_transport_priority());
    assert!(!small_app.is_transport_priority());
    assert!(!malformed_msg1.is_transport_priority());
    assert!(!malformed_established.is_transport_priority());
    assert!(!large_established.is_transport_priority());
    assert!(!direct_fsp.is_transport_priority());
    assert!(!wrong_version.is_transport_priority());
}

#[test]
fn test_received_packet() {
    let packet = received_packet(
        TransportId::new(1),
        TransportAddr::from_string("192.168.1.1:2121"),
        PacketBuffer::new(vec![1, 2, 3, 4]),
    );

    assert_eq!(packet.transport_id, TransportId::new(1));
    assert_eq!(packet.data.as_slice(), &[1, 2, 3, 4]);
    assert!(packet.timestamp_ms > 0);
}

#[test]
fn test_received_packet_with_timestamp() {
    let packet = ReceivedPacket::with_timestamp(
        TransportId::new(1),
        TransportAddr::from_string("test"),
        PacketBuffer::new(vec![5, 6]),
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
        PacketBuffer::new(vec![8, 9]),
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

    let packet = received_packet(
        TransportId::new(1),
        TransportAddr::from_string("test"),
        PacketBuffer::new(vec![1, 2, 3]),
    );

    tx.send(packet.clone()).unwrap();

    let received = rx.recv().await.unwrap();
    assert_eq!(received.data.as_slice(), &[1, 2, 3]);
}

#[tokio::test]
async fn packet_channel_reserves_priority_progress_ahead_of_bulk_backlog() {
    let (tx, mut rx) = packet_channel(10);
    let addr = TransportAddr::from_string("test");

    tx.send(received_packet(
        TransportId::new(1),
        addr.clone(),
        bulk_packet(0xaa),
    ))
    .unwrap();
    tx.send(received_packet(
        TransportId::new(1),
        addr.clone(),
        priority_msg1(0x11),
    ))
    .unwrap();
    tx.send(received_packet(
        TransportId::new(1),
        addr.clone(),
        priority_msg2(0x22),
    ))
    .unwrap();
    tx.send(received_packet(
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

#[tokio::test]
async fn packet_channel_prioritizes_established_liveness_without_promoting_bulk() {
    let (tx, mut rx) = packet_channel(10);
    let addr = TransportAddr::from_string("test");

    tx.send(received_packet(
        TransportId::new(1),
        addr.clone(),
        bulk_packet(0xaa),
    ))
    .unwrap();
    tx.send(received_packet(
        TransportId::new(1),
        addr.clone(),
        established_fmp_packet(FMP_HEARTBEAT_PLAINTEXT_SIZE, 0x11),
    ))
    .unwrap();
    tx.send(received_packet(
        TransportId::new(1),
        addr,
        established_fmp_packet(1200, 0xbb),
    ))
    .unwrap();

    assert_eq!(packet_marker(&rx.recv().await.unwrap()), 0x11);
    assert_eq!(packet_marker(&rx.recv().await.unwrap()), 0xaa);
    assert_eq!(packet_marker(&rx.recv().await.unwrap()), 0xbb);
}

#[test]
fn packet_channel_try_recv_uses_same_priority_policy() {
    let (tx, mut rx) = packet_channel(10);
    let addr = TransportAddr::from_string("test");

    tx.send(received_packet(
        TransportId::new(1),
        addr.clone(),
        bulk_packet(0xaa),
    ))
    .unwrap();
    tx.send(received_packet(
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

    tx.send_packet_batch(packet_batch(vec![
        received_packet(TransportId::new(1), addr.clone(), bulk_packet(0xaa)),
        received_packet(TransportId::new(1), addr.clone(), bulk_packet(0xbb)),
        received_packet(TransportId::new(1), addr, bulk_packet(0xcc)),
    ]))
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
    batch.push(received_packet(
        TransportId::new(1),
        addr.clone(),
        bulk_packet(0xaa),
    ));
    batch.push(received_packet(
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
        batch.push(received_packet(
            TransportId::new(1),
            TransportAddr::from_string("test"),
            bulk_packet(0xaa),
        ));
    }

    assert_eq!(
        packet_batch_pool_cached_len(&pool),
        0,
        "oversized receive batches should not stay pinned in the hot-path pool"
    );
}

#[test]
fn packet_channel_recycles_pooled_packet_buffer_when_bulk_batch_is_dropped() {
    let (tx, _rx) = packet_channel(1);
    let addr = TransportAddr::from_string("test");

    tx.send(received_packet(
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
    batch.push(received_packet(
        TransportId::new(1),
        addr,
        tx.packet_buffer(buffer),
    ));

    tx.send_packet_batch(batch)
        .expect("full bulk lane should shed pooled overload without closing sender");

    assert_eq!(
        packet_buffer_pool_cached_len(&tx.buffer_pool),
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

    tx.send_packet_batch(packet_batch(vec![
        received_packet(TransportId::new(1), addr.clone(), priority_msg1(0x11)),
        received_packet(TransportId::new(1), addr.clone(), priority_msg2(0x22)),
    ]))
    .expect("priority batch send should succeed");
    tx.send_packet_batch(packet_batch(vec![
        received_packet(TransportId::new(1), addr.clone(), bulk_packet(0xaa)),
        received_packet(TransportId::new(1), addr, bulk_packet(0xbb)),
    ]))
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
            assert_eq!(packets.packets.len(), 2);
            assert_eq!(packet_marker(&packets.packets[0]), 0x11);
            assert_eq!(packet_marker(&packets.packets[1]), 0x22);
        }
        item => panic!("expected grouped priority batch, got {item:?}"),
    }
    match rx.bulk.try_recv().expect("bulk channel item") {
        PacketQueueItem::Batch(packets) => {
            assert_eq!(packets.packets.len(), 2);
            assert_eq!(packet_marker(&packets.packets[0]), 0xaa);
            assert_eq!(packet_marker(&packets.packets[1]), 0xbb);
        }
        item => panic!("expected grouped bulk batch, got {item:?}"),
    }
}

#[test]
fn packet_channel_dequeue_counts_preserve_item_and_lane_counts() {
    let addr = TransportAddr::from_string("test");

    let item = PacketQueueItem::One(received_packet(
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

    let item = PacketQueueItem::Batch(packet_batch(vec![
        received_packet(TransportId::new(1), addr.clone(), priority_msg1(0x11)),
        received_packet(TransportId::new(1), addr.clone(), priority_msg2(0x22)),
    ]));
    assert_eq!(
        item.dequeue_counts(PacketLane::Priority),
        PacketQueueDequeueCounts {
            total: 2,
            priority: 2,
            bulk: 0,
        }
    );

    let item = PacketQueueItem::Batch(packet_batch(vec![
        received_packet(TransportId::new(1), addr.clone(), bulk_packet(0xaa)),
        received_packet(TransportId::new(1), addr, bulk_packet(0xbb)),
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
    let packets = packet_batch(vec![
        received_packet(TransportId::new(1), addr.clone(), priority_msg1(0xaa)),
        received_packet(TransportId::new(1), addr, priority_msg2(0xbb)),
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

    tx.send_packet_batch(packet_batch(vec![
        received_packet(TransportId::new(1), addr.clone(), priority_msg1(0x11)),
        received_packet(TransportId::new(1), addr.clone(), priority_msg2(0x22)),
    ]))
    .expect("priority batch send should succeed");
    assert_eq!(priority_queued_packets(&tx), 2);
    assert_eq!(bulk_queued_packets(&tx), 0);

    assert_eq!(packet_marker(&rx.try_recv().unwrap()), 0x11);
    assert_eq!(
        priority_queued_packets(&tx),
        0,
        "once a priority batch is dequeued, its tail is rx-loop-owned"
    );
    assert_eq!(packet_marker(&rx.try_recv().unwrap()), 0x22);
    assert_eq!(priority_queued_packets(&tx), 0);

    tx.send_packet_batch(packet_batch(vec![
        received_packet(TransportId::new(1), addr.clone(), bulk_packet(0xaa)),
        received_packet(TransportId::new(1), addr, bulk_packet(0xbb)),
    ]))
    .expect("bulk batch send should succeed");
    assert_eq!(
        priority_queued_packets(&tx),
        0,
        "bulk traffic should not make PacketRx probe the priority lane"
    );
}

include!("tests_io.rs");
