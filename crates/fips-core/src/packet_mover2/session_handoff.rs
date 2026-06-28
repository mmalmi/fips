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

type PacketMover2SessionHandoffResult = Result<
    PacketMover2SessionIngressHandoff,
    (PacketOutput, PacketMover2SessionHandoffError),
>;

fn packet_mover2_session_ingress_from_output(
    output: PacketOutput,
    local_addr: NodeAddr,
) -> PacketMover2SessionHandoffResult {
    if output.owner.protocol() != PacketProtocol::Fmp {
        return Err((output, PacketMover2SessionHandoffError::InvalidPacket));
    }

    const FMP_LINK_TIMESTAMP_LEN: usize = 4;
    const FMP_LINK_MSG_TYPE_LEN: usize = 1;
    const FMP_SESSION_PAYLOAD_OFFSET: usize = FMP_LINK_TIMESTAMP_LEN
        + FMP_LINK_MSG_TYPE_LEN
        + crate::protocol::SessionDatagramRef::HEADER_LEN;

    let previous_hop = match output.owner.node_addr() {
        Some(previous_hop) => previous_hop,
        None => return Err((output, PacketMover2SessionHandoffError::NoRoute)),
    };
    let fmp_header = match FmpWireHeader::parse(output.payload()) {
        Ok(header) => header,
        Err(_) => return Err((output, PacketMover2SessionHandoffError::InvalidPacket)),
    };

    let Some(TransportPath::Live {
        transport_id,
        remote_addr,
    }) = output.source_path.clone()
    else {
        return Err((output, PacketMover2SessionHandoffError::NoRoute));
    };

    let (source_addr, path_mtu, local_delivery) = {
        let Some(link_payload) = output.opened_payload() else {
            return Err((output, PacketMover2SessionHandoffError::InvalidPacket));
        };
        if link_payload.len() < FMP_LINK_TIMESTAMP_LEN {
            return Err((output, PacketMover2SessionHandoffError::InvalidPacket));
        }
        let link_payload = &link_payload[FMP_LINK_TIMESTAMP_LEN..];
        let Some((&msg_type, datagram_payload)) = link_payload.split_first() else {
            return Err((output, PacketMover2SessionHandoffError::InvalidPacket));
        };
        if msg_type != crate::protocol::LinkMessageType::SessionDatagram.to_byte() {
            return Err((output, PacketMover2SessionHandoffError::NoRoute));
        }

        let datagram = match crate::protocol::SessionDatagramRef::decode(datagram_payload) {
            Ok(datagram) => datagram,
            Err(_) => return Err((output, PacketMover2SessionHandoffError::InvalidPacket)),
        };
        if datagram.ttl == 0 || datagram.dest_addr != local_addr {
            return Err((output, PacketMover2SessionHandoffError::NoRoute));
        }
        let Some(prefix) = crate::node::session_wire::FspCommonPrefix::parse(datagram.payload)
        else {
            return Err((output, PacketMover2SessionHandoffError::InvalidPacket));
        };
        (
            datagram.src_addr,
            datagram.path_mtu,
            prefix.phase != FSP_PHASE_ESTABLISHED || prefix.is_unencrypted(),
        )
    };

    let path = TransportPath::Live {
        transport_id,
        remote_addr: remote_addr.clone(),
    };
    let ce_flag = fmp_header.flags() & crate::node::wire::FLAG_CE != 0;
    let activity_tick = output.activity_tick;
    let mut payload = match output.into_opened_payload() {
        Ok(payload) => payload,
        Err(output) => return Err((output, PacketMover2SessionHandoffError::InvalidPacket)),
    };
    debug_assert!(payload.len() >= FMP_SESSION_PAYLOAD_OFFSET);
    payload.drain(..FMP_SESSION_PAYLOAD_OFFSET);

    if local_delivery {
        return Ok(PacketMover2SessionIngressHandoff::Local(
            PacketMover2FspLocalSessionIngress::new(
                source_addr,
                previous_hop,
                ce_flag,
                path_mtu,
                payload,
            ),
        ));
    }

    Ok(PacketMover2SessionIngressHandoff::Raw(PacketMover2RawIngress {
        protocol: PacketProtocol::Fsp,
        transport_id,
        remote_addr,
        path,
        fsp_source: Some(source_addr),
        previous_hop: Some(previous_hop),
        ce_flag,
        activity_tick,
        payload,
    }))
}
