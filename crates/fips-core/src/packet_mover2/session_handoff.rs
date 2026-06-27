#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PacketMover2SessionHandoffError {
    InvalidPacket,
    NoRoute,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum PacketMover2FspPayloadDelivery {
    Tun(Vec<u8>),
    Endpoint(Vec<u8>),
}

fn packet_mover2_session_ingress_from_output(
    output: &PacketOutput,
    local_addr: NodeAddr,
) -> Result<PacketMover2RawIngress, PacketMover2SessionHandoffError> {
    if output.owner.protocol() != PacketProtocol::Fmp {
        return Err(PacketMover2SessionHandoffError::InvalidPacket);
    }

    let link_payload = output
        .opened_payload()
        .ok_or(PacketMover2SessionHandoffError::InvalidPacket)?;
    let Some((&msg_type, datagram_payload)) = link_payload.split_first() else {
        return Err(PacketMover2SessionHandoffError::InvalidPacket);
    };
    if msg_type != crate::protocol::LinkMessageType::SessionDatagram.to_byte() {
        return Err(PacketMover2SessionHandoffError::NoRoute);
    }

    let datagram = crate::protocol::SessionDatagramRef::decode(datagram_payload)
        .map_err(|_| PacketMover2SessionHandoffError::InvalidPacket)?;
    if datagram.ttl == 0 || datagram.dest_addr != local_addr {
        return Err(PacketMover2SessionHandoffError::NoRoute);
    }

    let Some(TransportPath::Live {
        transport_id,
        remote_addr,
    }) = output.source_path.clone()
    else {
        return Err(PacketMover2SessionHandoffError::NoRoute);
    };
    let path = TransportPath::Live {
        transport_id,
        remote_addr: remote_addr.clone(),
    };

    Ok(PacketMover2RawIngress {
        protocol: PacketProtocol::Fsp,
        transport_id,
        remote_addr,
        path,
        fsp_source: Some(datagram.src_addr),
        activity_tick: output.activity_tick,
        payload: datagram.payload.to_vec().into(),
    })
}

fn packet_mover2_fsp_payload_delivery(
    output: &PacketOutput,
    local_addr: NodeAddr,
) -> Result<PacketMover2FspPayloadDelivery, PacketMover2SessionHandoffError> {
    if output.owner.protocol() != PacketProtocol::Fsp {
        return Err(PacketMover2SessionHandoffError::InvalidPacket);
    }
    let source_addr = output
        .owner
        .node_addr()
        .ok_or(PacketMover2SessionHandoffError::NoRoute)?;
    let plaintext = output
        .opened_payload()
        .ok_or(PacketMover2SessionHandoffError::InvalidPacket)?;
    let Some((_timestamp, msg_type, _inner_flags, body)) =
        crate::node::session_wire::fsp_strip_inner_header(plaintext)
    else {
        return Err(PacketMover2SessionHandoffError::InvalidPacket);
    };

    match crate::protocol::SessionMessageType::from_byte(msg_type) {
        Some(crate::protocol::SessionMessageType::EndpointData) => {
            Ok(PacketMover2FspPayloadDelivery::Endpoint(body.to_vec()))
        }
        Some(crate::protocol::SessionMessageType::DataPacket) => {
            packet_mover2_ipv6_shim_payload(source_addr, local_addr, body)
                .map(PacketMover2FspPayloadDelivery::Tun)
        }
        _ => Err(PacketMover2SessionHandoffError::NoRoute),
    }
}

fn packet_mover2_ipv6_shim_payload(
    source_addr: NodeAddr,
    local_addr: NodeAddr,
    body: &[u8],
) -> Result<Vec<u8>, PacketMover2SessionHandoffError> {
    if body.len() < crate::node::session_wire::FSP_PORT_HEADER_SIZE {
        return Err(PacketMover2SessionHandoffError::InvalidPacket);
    }
    let dst_port = u16::from_le_bytes([body[2], body[3]]);
    if dst_port != crate::node::session_wire::FSP_PORT_IPV6_SHIM {
        return Err(PacketMover2SessionHandoffError::NoRoute);
    }

    let src_ipv6 = crate::FipsAddress::from_node_addr(&source_addr)
        .to_ipv6()
        .octets();
    let dst_ipv6 = crate::FipsAddress::from_node_addr(&local_addr)
        .to_ipv6()
        .octets();
    crate::upper::ipv6_shim::decompress_ipv6(
        &body[crate::node::session_wire::FSP_PORT_HEADER_SIZE..],
        src_ipv6,
        dst_ipv6,
    )
    .ok_or(PacketMover2SessionHandoffError::InvalidPacket)
}
