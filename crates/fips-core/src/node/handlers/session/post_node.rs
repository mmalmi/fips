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
    use crate::node::{Node, NodeAddr};

    fn make_node() -> Node {
        Node::new(Config::new()).unwrap()
    }

    fn make_node_addr(val: u8) -> NodeAddr {
        let mut bytes = [0u8; 16];
        bytes[0] = val;
        NodeAddr::from_bytes(bytes)
    }

    fn ipv6_tcp_packet(flags: u8, tcp_payload_len: usize) -> Vec<u8> {
        let tcp_len = 20 + tcp_payload_len;
        let mut packet = vec![0u8; 40 + tcp_len];
        packet[0] = 0x60;
        packet[4..6].copy_from_slice(&(tcp_len as u16).to_be_bytes());
        packet[6] = 6;
        packet[40 + 12] = 5 << 4;
        packet[40 + 13] = flags;
        packet
    }

    #[test]
    fn pending_session_queues_drop_oldest_per_destination() {
        let mut node = make_node();
        node.config.node.session.pending_packets_per_dest = 2;

        let tun_dest = make_node_addr(0x41);
        node.queue_pending_packet(tun_dest, vec![1]);
        node.queue_pending_packet(tun_dest, vec![2]);
        node.queue_pending_packet(tun_dest, vec![3]);
        let tun_packets: Vec<Vec<u8>> = node
            .pending_session_traffic
            .tun_packets_for(&tun_dest)
            .expect("tun queue")
            .iter()
            .cloned()
            .collect();
        assert_eq!(tun_packets, vec![vec![2], vec![3]]);

        let endpoint_dest = make_node_addr(0x42);
        node.queue_pending_endpoint_data(endpoint_dest, vec![4]);
        node.queue_pending_endpoint_data(endpoint_dest, vec![5]);
        node.queue_pending_endpoint_data(endpoint_dest, vec![6]);
        let endpoint_payloads: Vec<Vec<u8>> = node
            .pending_session_traffic
            .endpoint_data_for(&endpoint_dest)
            .expect("endpoint queue")
            .iter()
            .map(|payload| payload.as_slice().to_vec())
            .collect();
        assert_eq!(endpoint_payloads, vec![vec![5], vec![6]]);
    }

    #[test]
    fn pending_endpoint_data_queue_owns_drop_oldest_policy() {
        let mut queue = crate::node::PendingEndpointDataQueue::default();
        assert!(!queue.push_bounded(vec![1].into(), 2).dropped_oldest());
        assert!(!queue.push_bounded(vec![2].into(), 2).dropped_oldest());
        assert!(queue.push_bounded(vec![3].into(), 2).dropped_oldest());

        let payloads: Vec<Vec<u8>> = queue
            .iter()
            .map(|payload| payload.as_slice().to_vec())
            .collect();
        assert_eq!(payloads, vec![vec![2], vec![3]]);
    }

    #[test]
    fn pending_endpoint_data_queue_preserves_priority_under_pressure() {
        let mut queue = crate::node::PendingEndpointDataQueue::default();
        let first_ack = ipv6_tcp_packet(0x10, 0);
        let second_ack = ipv6_tcp_packet(0x10, 0);
        let discardable = vec![0xdd; 64];
        let bulk_tcp = ipv6_tcp_packet(0x18, 512);

        assert!(
            !queue
                .push_bounded(
                    crate::node::EndpointDataPayload::new(first_ack.clone()),
                    2
                )
                .dropped_payload()
        );
        assert!(
            !queue
                .push_bounded(
                    crate::node::EndpointDataPayload::new(second_ack.clone()),
                    2
                )
                .dropped_payload()
        );

        let discardable_admission =
            queue.push_bounded(crate::node::EndpointDataPayload::new(discardable), 2);
        assert!(discardable_admission.dropped_payload());
        assert!(!discardable_admission.dropped_oldest());
        let bulk_admission =
            queue.push_bounded(crate::node::EndpointDataPayload::new(bulk_tcp), 2);
        assert!(bulk_admission.dropped_payload());
        assert!(!bulk_admission.dropped_oldest());

        let payloads: Vec<Vec<u8>> = queue
            .iter()
            .map(|payload| payload.as_slice().to_vec())
            .collect();
        assert_eq!(payloads, vec![first_ack, second_ack]);
    }

    #[test]
    fn pending_endpoint_data_queue_drops_discardable_before_bulk_or_priority() {
        let mut queue = crate::node::PendingEndpointDataQueue::default();
        let ack = ipv6_tcp_packet(0x10, 0);
        let discardable = vec![0xdd; 64];
        let bulk_tcp = ipv6_tcp_packet(0x18, 512);
        let second_ack = ipv6_tcp_packet(0x10, 0);

        assert!(
            !queue
                .push_bounded(crate::node::EndpointDataPayload::new(ack.clone()), 2)
                .dropped_payload()
        );
        assert!(
            !queue
                .push_bounded(crate::node::EndpointDataPayload::new(discardable), 2)
                .dropped_payload()
        );
        assert!(
            queue
                .push_bounded(crate::node::EndpointDataPayload::new(bulk_tcp.clone()), 2)
                .dropped_oldest()
        );
        assert!(
            queue
                .push_bounded(crate::node::EndpointDataPayload::new(second_ack.clone()), 2)
                .dropped_oldest()
        );

        let payloads: Vec<Vec<u8>> = queue
            .iter()
            .map(|payload| payload.as_slice().to_vec())
            .collect();
        assert_eq!(payloads, vec![ack, second_ack]);
        assert!(!payloads.iter().any(|payload| payload == &bulk_tcp));
    }

    #[test]
    fn pending_tun_packet_queue_owns_drop_oldest_policy() {
        let mut queue = crate::node::PendingTunPacketQueue::default();
        assert!(!queue.push_bounded(vec![1], 2).dropped_oldest());
        assert!(!queue.push_bounded(vec![2], 2).dropped_oldest());
        assert!(queue.push_bounded(vec![3], 2).dropped_oldest());

        let packets: Vec<Vec<u8>> = queue.iter().cloned().collect();
        assert_eq!(packets, vec![vec![2], vec![3]]);
    }

    #[test]
    fn pending_tun_packet_queue_preserves_priority_under_pressure() {
        let mut queue = crate::node::PendingTunPacketQueue::default();
        let first_ack = ipv6_tcp_packet(0x10, 0);
        let second_ack = ipv6_tcp_packet(0x10, 0);
        let discardable = vec![0xdd; 64];
        let bulk_tcp = ipv6_tcp_packet(0x18, 512);

        assert!(!queue.push_bounded(first_ack.clone(), 2).dropped_packet());
        assert!(!queue.push_bounded(second_ack.clone(), 2).dropped_packet());
        let discardable_admission = queue.push_bounded(discardable, 2);
        assert!(discardable_admission.dropped_packet());
        assert!(!discardable_admission.dropped_oldest());
        let bulk_admission = queue.push_bounded(bulk_tcp, 2);
        assert!(bulk_admission.dropped_packet());
        assert!(!bulk_admission.dropped_oldest());

        let packets: Vec<Vec<u8>> = queue.iter().cloned().collect();
        assert_eq!(packets, vec![first_ack, second_ack]);
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
                .push_endpoint_data(endpoint_dest, vec![3], 1, 2)
                .destination_dropped()
        );
        assert!(queues.has_traffic_for(&endpoint_dest));
        assert!(
            queues
                .push_endpoint_data(rejected_endpoint_dest, vec![4], 1, 2)
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

        let packets: Vec<Vec<u8>> = queues
            .tun_packets_for(&tun_dest)
            .expect("accepted TUN queue")
            .iter()
            .cloned()
            .collect();
        assert_eq!(packets, vec![vec![5], vec![6]]);

        let removed = queues.remove_destination(&tun_dest);
        assert_eq!(removed.tun_packets().map(|queue| queue.len()), Some(2));
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
                .push_endpoint_data(dest, vec![2], 8, 2)
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
    fn pending_session_queues_reject_new_destinations_at_cap() {
        let mut node = make_node();
        node.config.node.session.pending_max_destinations = 1;

        let accepted_tun_dest = make_node_addr(0x51);
        let rejected_tun_dest = make_node_addr(0x52);
        node.queue_pending_packet(accepted_tun_dest, vec![1]);
        node.queue_pending_packet(rejected_tun_dest, vec![2]);
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
        node.queue_pending_endpoint_data(accepted_endpoint_dest, vec![3]);
        node.queue_pending_endpoint_data(rejected_endpoint_dest, vec![4]);
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
