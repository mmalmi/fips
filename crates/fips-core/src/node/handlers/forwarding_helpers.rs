fn copy_forwarded_session_datagram(payload: &[u8], ttl: u8, path_mtu: u16) -> Vec<u8> {
    let mut buf = Vec::with_capacity(1 + payload.len());
    buf.push(LinkMessageType::SessionDatagram.to_byte());
    buf.extend_from_slice(payload);
    let rewritten = rewrite_forwarded_session_datagram_bytes(&mut buf, ttl, path_mtu);
    debug_assert!(
        rewritten,
        "decoded session datagram must remain rewriteable"
    );
    buf
}

fn rewrite_forwarded_session_datagram(
    plaintext: &mut PacketBuffer,
    ttl: u8,
    path_mtu: u16,
) -> bool {
    rewrite_forwarded_session_datagram_bytes(plaintext.as_mut_slice(), ttl, path_mtu)
}

fn rewrite_forwarded_session_datagram_bytes(plaintext: &mut [u8], ttl: u8, path_mtu: u16) -> bool {
    let Some(header) = plaintext.get_mut(..4) else {
        return false;
    };
    if header[0] != LinkMessageType::SessionDatagram.to_byte() {
        return false;
    }
    header[1] = ttl;
    header[2..4].copy_from_slice(&path_mtu.to_le_bytes());
    true
}

fn owned_session_datagram_from_ref(
    datagram: &SessionDatagramRef<'_>,
    ttl: u8,
    path_mtu: u16,
) -> SessionDatagram {
    SessionDatagram {
        src_addr: datagram.src_addr,
        dest_addr: datagram.dest_addr,
        ttl,
        path_mtu,
        payload: datagram.payload.to_vec(),
    }
}

fn claim_route_failure_once(
    failed_routes: &mut std::collections::HashSet<(NodeAddr, NodeAddr)>,
    dest_addr: NodeAddr,
    next_hop_addr: NodeAddr,
    failed: bool,
) -> bool {
    failed && failed_routes.insert((dest_addr, next_hop_addr))
}

fn forward_run_reached_limit(run_len: usize, configured_limit: usize) -> bool {
    run_len >= configured_limit.max(1)
}

fn forwarding_lane(forward: &PreparedSessionForward) -> ForwardingLane {
    if crate::node::endpoint_traffic::fmp_plaintext_is_bulk_session_datagram(
        forward.plaintext.as_slice(),
    ) {
        ForwardingLane::Bulk
    } else {
        ForwardingLane::Priority
    }
}

fn forwarding_submission_limit(transport_batch_packets: usize) -> usize {
    transport_batch_packets
        .clamp(1, crate::dataplane::DATAPLANE_TRANSPORT_SEND_BATCH_PACKETS)
        .saturating_mul(FORWARDING_IN_FLIGHT_TRANSPORT_BATCHES)
}
