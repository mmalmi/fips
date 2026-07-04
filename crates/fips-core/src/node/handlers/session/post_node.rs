fn session_receiver_report_can_drive_route_quality(mode: MmpMode, srtt_ms: Option<f64>) -> bool {
    match mode {
        MmpMode::Full => srtt_ms.is_some(),
        MmpMode::Lightweight => true,
        MmpMode::Minimal => false,
    }
}

#[cfg(test)]
mod pending_queue_tests {
    use crate::config::Config;
    use crate::node::{EndpointDataPayload, Node, NodeAddr};

    fn make_node() -> Node {
        Node::new(Config::new()).unwrap()
    }

    fn make_node_addr(val: u8) -> NodeAddr {
        let mut bytes = [0u8; 16];
        bytes[0] = val;
        NodeAddr::from_bytes(bytes)
    }

    fn endpoint_payloads(payloads: Vec<Vec<u8>>) -> Vec<EndpointDataPayload> {
        payloads
            .into_iter()
            .map(|payload| {
                EndpointDataPayload::from_packet_payload(payload)
                    .expect("test endpoint payload should fit FSP endpoint data")
            })
            .collect()
    }

    fn endpoint_payload_bodies(payloads: Vec<EndpointDataPayload>) -> Vec<Vec<u8>> {
        payloads
            .into_iter()
            .map(|payload| payload.into_body().into_vec())
            .collect()
    }

    #[test]
    fn pending_session_queues_drop_oldest_per_destination() {
        let mut node = make_node();
        node.config.node.session.pending_packets_per_dest = 2;

        let tun_dest = make_node_addr(0x41);
        node.queue_pending_tun_packet(tun_dest, vec![1]);
        node.queue_pending_tun_packet(tun_dest, vec![2]);
        node.queue_pending_tun_packet(tun_dest, vec![3]);
        let tun_packets: Vec<Vec<u8>> = node
            .pending_session_traffic
            .take_tun_packets(&tun_dest)
            .expect("tun queue")
            .into_packets()
            .into_iter()
            .collect();
        assert_eq!(tun_packets, vec![vec![2], vec![3]]);

        let endpoint_dest = make_node_addr(0x42);
        node.queue_pending_endpoint_data_batch_with_enqueued_at_ms(
            endpoint_dest,
            endpoint_payloads(vec![vec![4]]),
            1_000,
        );
        node.queue_pending_endpoint_data_batch_with_enqueued_at_ms(
            endpoint_dest,
            endpoint_payloads(vec![vec![5]]),
            1_001,
        );
        node.queue_pending_endpoint_data_batch_with_enqueued_at_ms(
            endpoint_dest,
            endpoint_payloads(vec![vec![6]]),
            1_002,
        );
        let endpoint_payloads: Vec<Vec<u8>> = node
            .pending_session_traffic
            .take_endpoint_data(&endpoint_dest)
            .expect("endpoint queue")
            .into_pending_payloads()
            .into_iter()
            .flat_map(|payload| endpoint_payload_bodies(payload.into_payloads()))
            .collect();
        assert_eq!(endpoint_payloads, vec![vec![5], vec![6]]);
    }

    #[test]
    fn pending_endpoint_data_queue_owns_drop_oldest_policy() {
        let mut queue = crate::node::endpoint_traffic::PendingEndpointDataQueue::default();
        assert!(!queue.push_batch_bounded(endpoint_payloads(vec![vec![1]]), 1_000, 2));
        assert!(!queue.push_batch_bounded(endpoint_payloads(vec![vec![2]]), 1_001, 2));
        assert!(queue.push_batch_bounded(endpoint_payloads(vec![vec![3]]), 1_002, 2));

        let payloads: Vec<Vec<u8>> = queue
            .into_pending_payloads()
            .into_iter()
            .flat_map(|payload| endpoint_payload_bodies(payload.into_payloads()))
            .collect();
        assert_eq!(payloads, vec![vec![2], vec![3]]);
    }

    #[test]
    fn pending_endpoint_data_queue_preserves_batch_shape() {
        let mut queue = crate::node::endpoint_traffic::PendingEndpointDataQueue::default();
        assert!(!queue.push_batch_bounded(
            endpoint_payloads(vec![vec![1], vec![2]]),
            1_000,
            4
        ));

        let mut batches = queue.into_pending_payloads();
        let batch = batches.pop_front().expect("queued endpoint batch");
        assert_eq!(batch.enqueued_at_ms(), 1_000);
        assert_eq!(
            endpoint_payload_bodies(batch.into_payloads()),
            vec![vec![1], vec![2]]
        );
        assert!(batches.is_empty());
    }

    #[test]
    fn pending_endpoint_data_queue_bounds_batches_by_packet_count() {
        let mut queue = crate::node::endpoint_traffic::PendingEndpointDataQueue::default();
        assert!(!queue.push_batch_bounded(
            endpoint_payloads(vec![vec![1], vec![2]]),
            1_000,
            3
        ));
        assert!(queue.push_batch_bounded(
            endpoint_payloads(vec![vec![3], vec![4]]),
            1_001,
            3
        ));

        let payloads: Vec<Vec<u8>> = queue
            .into_pending_payloads()
            .into_iter()
            .flat_map(|payload| endpoint_payload_bodies(payload.into_payloads()))
            .collect();
        assert_eq!(payloads, vec![vec![2], vec![3], vec![4]]);
    }

    #[test]
    fn pending_endpoint_data_queue_preserves_enqueue_times() {
        let mut queue = crate::node::endpoint_traffic::PendingEndpointDataQueue::default();
        assert!(!queue.push_batch_bounded(endpoint_payloads(vec![vec![1]]), 1_000, 4));
        assert!(!queue.push_batch_bounded(endpoint_payloads(vec![vec![2]]), 1_500, 4));

        let payloads = queue.into_pending_payloads();
        let observed: Vec<(Vec<Vec<u8>>, u64)> = payloads
            .into_iter()
            .map(|payload| {
                let enqueued_at_ms = payload.enqueued_at_ms();
                (
                    endpoint_payload_bodies(payload.into_payloads()),
                    enqueued_at_ms,
                )
            })
            .collect();
        assert_eq!(
            observed,
            vec![(vec![vec![1]], 1_000), (vec![vec![2]], 1_500)]
        );
    }

    #[test]
    fn pending_tun_packet_queue_owns_drop_oldest_policy() {
        let mut queue = crate::node::endpoint_traffic::PendingTunPacketQueue::default();
        assert!(!queue.push_bounded(vec![1], 1_000, 2));
        assert!(!queue.push_bounded(vec![2], 1_001, 2));
        assert!(queue.push_bounded(vec![3], 1_002, 2));

        let packets: Vec<Vec<u8>> = queue.into_packets().into_iter().collect();
        assert_eq!(packets, vec![vec![2], vec![3]]);
    }

    #[test]
    fn pending_tun_packet_queue_drops_stale_packets_on_fresh_drain() {
        let mut queue = crate::node::endpoint_traffic::PendingTunPacketQueue::default();
        assert!(!queue.push_bounded(vec![1], 1_000, 8));
        assert!(!queue.push_bounded(vec![2], 3_500, 8));

        let (packets, stale) = queue.into_fresh_packets(4_000, 2_000);

        assert_eq!(stale, 1);
        assert_eq!(
            packets
                .into_iter()
                .map(|packet| packet.into_packet())
                .collect::<Vec<_>>(),
            vec![vec![2]]
        );
    }

    #[test]
    fn pending_session_traffic_queues_own_destination_admission() {
        let mut queues = crate::node::PendingSessionTrafficQueues::default();
        let tun_dest = NodeAddr::from_bytes([1u8; 16]);
        let rejected_tun_dest = NodeAddr::from_bytes([2u8; 16]);
        let endpoint_dest = NodeAddr::from_bytes([3u8; 16]);
        let rejected_endpoint_dest = NodeAddr::from_bytes([4u8; 16]);

        assert!(
            !queues
                .push_tun_packet(tun_dest, vec![1], 1, 2)
                .destination_dropped()
        );
        assert!(queues.has_traffic_for(&tun_dest));
        assert!(
            queues
                .push_tun_packet(rejected_tun_dest, vec![2], 1, 2)
                .destination_dropped()
        );
        assert!(!queues.has_traffic_for(&rejected_tun_dest));

        assert!(
            !queues
                .push_endpoint_data_batch_with_enqueued_at_ms(
                    endpoint_dest,
                    endpoint_payloads(vec![vec![3]]),
                    1,
                    2,
                    1_000,
                )
                .destination_dropped()
        );
        assert!(queues.has_traffic_for(&endpoint_dest));
        assert!(
            queues
                .push_endpoint_data_batch_with_enqueued_at_ms(
                    rejected_endpoint_dest,
                    endpoint_payloads(vec![vec![4]]),
                    1,
                    2,
                    1_001,
                )
                .destination_dropped()
        );
        assert!(!queues.has_traffic_for(&rejected_endpoint_dest));

        assert!(
            !queues
                .push_tun_packet(tun_dest, vec![5], 1, 2)
                .dropped_oldest()
        );
        assert!(
            queues
                .push_tun_packet(tun_dest, vec![6], 1, 2)
                .dropped_oldest()
        );

        let removed = queues.remove_destination(&tun_dest);
        let removed_tun: Vec<Vec<u8>> = removed
            .into_tun_packets()
            .expect("accepted TUN queue")
            .into_packets()
            .into_iter()
            .collect();
        assert_eq!(removed_tun, vec![vec![5], vec![6]]);
        assert!(queues.tun_packets_for(&tun_dest).is_none());
        assert!(!queues.has_traffic_for(&tun_dest));
        assert!(queues.endpoint_data_for(&endpoint_dest).is_some());
        assert!(queues.has_traffic_for(&endpoint_dest));
    }

    #[test]
    fn pending_session_traffic_destination_guard_tracks_partial_takes() {
        let mut queues = crate::node::PendingSessionTrafficQueues::default();
        let dest = NodeAddr::from_bytes([9u8; 16]);

        assert!(
            !queues
                .push_tun_packet(dest, vec![1], 8, 2)
                .destination_dropped()
        );
        assert!(
            !queues
                .push_endpoint_data_batch_with_enqueued_at_ms(
                    dest,
                    endpoint_payloads(vec![vec![2]]),
                    8,
                    2,
                    1_000,
                )
                .destination_dropped()
        );
        assert!(queues.has_traffic_for(&dest));

        assert!(queues.take_tun_packets(&dest).is_some());
        assert!(
            queues.has_traffic_for(&dest),
            "endpoint payloads should keep the destination guard set"
        );
        assert!(queues.take_endpoint_data(&dest).is_some());
        assert!(
            !queues.has_traffic_for(&dest),
            "guard should clear after the final pending queue is removed"
        );
    }

    #[test]
    fn pending_session_traffic_restore_keeps_unsent_tail() {
        let mut queues = crate::node::PendingSessionTrafficQueues::default();
        let dest = NodeAddr::from_bytes([0x0a; 16]);

        assert!(
            !queues
                .push_tun_packet(dest, vec![1], 8, 4)
                .destination_dropped()
        );
        assert!(
            !queues
                .push_tun_packet(dest, vec![2], 8, 4)
                .destination_dropped()
        );
        let (mut packets, stale) = queues
            .take_tun_packets(&dest)
            .expect("tun packets")
            .into_fresh_packets(2_000, 2_000);
        assert_eq!(stale, 0);
        assert_eq!(packets.pop_front().map(|packet| packet.into_packet()), Some(vec![1]));
        queues.restore_tun_packets(dest, packets);
        let restored_tun: Vec<Vec<u8>> = queues
            .take_tun_packets(&dest)
            .expect("restored TUN queue")
            .into_packets()
            .into_iter()
            .collect();
        assert_eq!(restored_tun, vec![vec![2]]);

        assert!(
            !queues
                .push_endpoint_data_batch_with_enqueued_at_ms(
                    dest,
                    endpoint_payloads(vec![vec![3]]),
                    8,
                    4,
                    1_000,
                )
                .destination_dropped()
        );
        assert!(
            !queues
                .push_endpoint_data_batch_with_enqueued_at_ms(
                    dest,
                    endpoint_payloads(vec![vec![4]]),
                    8,
                    4,
                    1_001,
                )
                .destination_dropped()
        );
        let mut payloads = queues
            .take_endpoint_data(&dest)
            .expect("endpoint data")
            .into_pending_payloads();
        assert_eq!(
            payloads
                .pop_front()
                .map(|payload| endpoint_payload_bodies(payload.into_payloads())),
            Some(vec![vec![3]])
        );
        queues.restore_endpoint_data(dest, payloads);
        let restored_endpoint: Vec<Vec<u8>> = queues
            .take_endpoint_data(&dest)
            .expect("restored endpoint queue")
            .into_pending_payloads()
            .into_iter()
            .flat_map(|payload| endpoint_payload_bodies(payload.into_payloads()))
            .collect();
        assert_eq!(restored_endpoint, vec![vec![4]]);
    }

    #[test]
    fn pending_session_queues_reject_new_destinations_at_cap() {
        let mut node = make_node();
        node.config.node.session.pending_max_destinations = 1;

        let accepted_tun_dest = make_node_addr(0x51);
        let rejected_tun_dest = make_node_addr(0x52);
        node.queue_pending_tun_packet(accepted_tun_dest, vec![1]);
        node.queue_pending_tun_packet(rejected_tun_dest, vec![2]);
        assert!(
            node.pending_session_traffic
                .tun_packets_for(&accepted_tun_dest)
                .is_some()
        );
        assert!(
            node.pending_session_traffic
                .tun_packets_for(&rejected_tun_dest)
                .is_none()
        );

        let accepted_endpoint_dest = make_node_addr(0x61);
        let rejected_endpoint_dest = make_node_addr(0x62);
        node.queue_pending_endpoint_data_batch_with_enqueued_at_ms(
            accepted_endpoint_dest,
            endpoint_payloads(vec![vec![3]]),
            1_000,
        );
        node.queue_pending_endpoint_data_batch_with_enqueued_at_ms(
            rejected_endpoint_dest,
            endpoint_payloads(vec![vec![4]]),
            1_001,
        );
        assert!(
            node.pending_session_traffic
                .endpoint_data_for(&accepted_endpoint_dest)
                .is_some()
        );
        assert!(
            node.pending_session_traffic
                .endpoint_data_for(&rejected_endpoint_dest)
                .is_none()
        );
    }
}

/// Mark ECN-CE in an IPv6 packet's Traffic Class field.
///
/// IPv6 Traffic Class occupies bits across bytes 0 and 1:
///   byte[0] bits[3:0] = TC[7:4]
///   byte[1] bits[7:4] = TC[3:0]
/// ECN is TC[1:0]. Only marks CE (0b11) if the packet is ECN-capable
/// (ECT(0) or ECT(1)). Packets with ECN=0b00 (Not-ECT) are never marked
/// per RFC 3168.
///
/// No checksum update needed: IPv6 has no header checksum, and the Traffic
/// Class field is not part of the TCP/UDP pseudo-header.
pub(in crate::node) fn mark_ipv6_ecn_ce(packet: &mut [u8]) {
    if packet.len() < 2 {
        return;
    }
    // Extract 8-bit Traffic Class from IPv6 header bytes 0-1
    let tc = ((packet[0] & 0x0F) << 4) | (packet[1] >> 4);
    let ecn = tc & 0x03;
    // Only mark CE on ECN-capable packets (ECT(0)=0b10 or ECT(1)=0b01)
    if ecn == 0 {
        return;
    }
    // Set both ECN bits to 1 (CE = 0b11)
    let new_tc = tc | 0x03;
    packet[0] = (packet[0] & 0xF0) | (new_tc >> 4);
    packet[1] = (new_tc << 4) | (packet[1] & 0x0F);
}
