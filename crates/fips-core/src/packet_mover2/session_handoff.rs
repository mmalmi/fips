#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PacketMover2SessionHandoffError {
    InvalidPacket,
    NoRoute,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum PacketMover2SessionIngressHandoff {
    Raw(PacketMover2RawIngress),
    Local(PacketMover2FspLocalSessionIngress),
}

fn packet_mover2_session_ingress_from_output(
    output: &PacketOutput,
    local_addr: NodeAddr,
) -> Result<PacketMover2SessionIngressHandoff, PacketMover2SessionHandoffError> {
    if output.owner.protocol() != PacketProtocol::Fmp {
        return Err(PacketMover2SessionHandoffError::InvalidPacket);
    }

    let link_payload = output
        .opened_payload()
        .ok_or(PacketMover2SessionHandoffError::InvalidPacket)?;
    if link_payload.len() < 4 {
        return Err(PacketMover2SessionHandoffError::InvalidPacket);
    }
    let link_payload = &link_payload[4..];
    let Some((&msg_type, datagram_payload)) = link_payload.split_first() else {
        return Err(PacketMover2SessionHandoffError::InvalidPacket);
    };
    if msg_type != crate::protocol::LinkMessageType::SessionDatagram.to_byte() {
        return Err(PacketMover2SessionHandoffError::NoRoute);
    }
    let previous_hop = output
        .owner
        .node_addr()
        .ok_or(PacketMover2SessionHandoffError::NoRoute)?;
    let fmp_header = FmpWireHeader::parse(output.payload())
        .map_err(|_| PacketMover2SessionHandoffError::InvalidPacket)?;

    let datagram = crate::protocol::SessionDatagramRef::decode(datagram_payload)
        .map_err(|_| PacketMover2SessionHandoffError::InvalidPacket)?;
    if datagram.ttl == 0 || datagram.dest_addr != local_addr {
        return Err(PacketMover2SessionHandoffError::NoRoute);
    }
    let prefix = crate::node::session_wire::FspCommonPrefix::parse(datagram.payload)
        .ok_or(PacketMover2SessionHandoffError::InvalidPacket)?;

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
    let ce_flag = fmp_header.flags() & crate::node::wire::FLAG_CE != 0;

    if prefix.phase != FSP_PHASE_ESTABLISHED || prefix.is_unencrypted() {
        return Ok(PacketMover2SessionIngressHandoff::Local(
            PacketMover2FspLocalSessionIngress::new(
                datagram.src_addr,
                previous_hop,
                ce_flag,
                datagram.path_mtu,
                datagram.payload.to_vec().into(),
            ),
        ));
    }

    Ok(PacketMover2SessionIngressHandoff::Raw(PacketMover2RawIngress {
        protocol: PacketProtocol::Fsp,
        transport_id,
        remote_addr,
        path,
        fsp_source: Some(datagram.src_addr),
        previous_hop: Some(previous_hop),
        ce_flag,
        activity_tick: output.activity_tick,
        payload: datagram.payload.to_vec().into(),
    }))
}
