#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DataplaneSessionHandoffError {
    InvalidPacket,
    NoRoute,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum DataplaneSessionIngressHandoff {
    Raw {
        raw: DataplaneRawIngress,
        coord_warmup: DataplaneFspCoordWarmup,
    },
    Local(DataplaneFspLocalSessionIngress),
}

type DataplaneSessionHandoffResult =
    Result<DataplaneSessionIngressHandoff, (PacketOutput, DataplaneSessionHandoffError)>;

fn dataplane_session_ingress_from_output(
    output: PacketOutput,
    local_addr: NodeAddr,
) -> DataplaneSessionHandoffResult {
    if output.owner.protocol() != PacketProtocol::Fmp {
        return Err((output, DataplaneSessionHandoffError::InvalidPacket));
    }

    const FMP_LINK_TIMESTAMP_LEN: usize = 4;
    const FMP_LINK_MSG_TYPE_LEN: usize = 1;
    const FMP_SESSION_PAYLOAD_OFFSET: usize = FMP_LINK_TIMESTAMP_LEN
        + FMP_LINK_MSG_TYPE_LEN
        + crate::protocol::SessionDatagramRef::HEADER_LEN;

    let previous_hop = output.owner.node_addr();
    let fmp_header = match FmpWireHeader::parse(output.payload()) {
        Ok(header) => header,
        Err(_) => return Err((output, DataplaneSessionHandoffError::InvalidPacket)),
    };

    let (transport_id, remote_addr) = match output.source_path() {
        Some(TransportPath::Live {
            transport_id,
            remote_addr,
        }) => (*transport_id, remote_addr.clone()),
        _ => return Err((output, DataplaneSessionHandoffError::NoRoute)),
    };

    let handoff_facts = {
        let Some(link_payload) = output.opened_payload() else {
            return Err((output, DataplaneSessionHandoffError::InvalidPacket));
        };
        if link_payload.len() < FMP_LINK_TIMESTAMP_LEN {
            return Err((output, DataplaneSessionHandoffError::InvalidPacket));
        }
        let link_payload = &link_payload[FMP_LINK_TIMESTAMP_LEN..];
        let Some((&msg_type, datagram_payload)) = link_payload.split_first() else {
            return Err((output, DataplaneSessionHandoffError::InvalidPacket));
        };
        if msg_type != crate::protocol::LinkMessageType::SessionDatagram.to_byte() {
            return Err((output, DataplaneSessionHandoffError::NoRoute));
        }

        let datagram = match crate::protocol::SessionDatagramRef::decode(datagram_payload) {
            Ok(datagram) => datagram,
            Err(_) => return Err((output, DataplaneSessionHandoffError::InvalidPacket)),
        };
        if datagram.ttl == 0 || datagram.dest_addr != local_addr {
            return Err((output, DataplaneSessionHandoffError::NoRoute));
        }
        let Some(prefix) = crate::node::session_wire::FspCommonPrefix::parse(datagram.payload)
        else {
            return Err((output, DataplaneSessionHandoffError::InvalidPacket));
        };
        let coord_warmup = dataplane_fsp_coord_warmup(
            datagram.src_addr,
            local_addr,
            datagram.payload,
            &prefix,
        );
        coord_warmup.map(|coord_warmup| {
            (
                datagram.src_addr,
                datagram.path_mtu,
                prefix.phase != FSP_PHASE_ESTABLISHED || prefix.is_unencrypted(),
                coord_warmup,
            )
        })
    };
    let (source_addr, path_mtu, local_delivery, coord_warmup) = match handoff_facts {
        Ok(facts) => facts,
        Err(error) => return Err((output, error)),
    };

    let ce_flag = fmp_header.flags() & crate::node::wire::FLAG_CE != 0;
    let activity_tick = output.activity_tick;
    let mut payload = output
        .into_opened_payload()
        .map_err(|output| (output, DataplaneSessionHandoffError::InvalidPacket))?;
    debug_assert!(payload.len() >= FMP_SESSION_PAYLOAD_OFFSET);
    assert!(payload.trim_front(FMP_SESSION_PAYLOAD_OFFSET));

    let path = TransportPath::Live {
        transport_id,
        remote_addr: remote_addr.clone(),
    };

    if local_delivery {
        return Ok(DataplaneSessionIngressHandoff::Local(
            DataplaneFspLocalSessionIngress::new(
                source_addr,
                previous_hop,
                ce_flag,
                path_mtu,
                payload,
            ),
        ));
    }

    Ok(DataplaneSessionIngressHandoff::Raw {
        raw: DataplaneRawIngress {
            protocol: PacketProtocol::Fsp,
            transport_id,
            remote_addr,
            path,
            fsp_source: Some(source_addr),
            previous_hop: Some(previous_hop),
            ce_flag,
            path_mtu,
            activity_tick,
            payload,
        },
        coord_warmup,
    })
}

fn dataplane_fsp_coord_warmup(
    source_addr: NodeAddr,
    local_addr: NodeAddr,
    payload: &[u8],
    prefix: &crate::node::session_wire::FspCommonPrefix,
) -> Result<DataplaneFspCoordWarmup, DataplaneSessionHandoffError> {
    if prefix.phase != FSP_PHASE_ESTABLISHED
        || prefix.is_unencrypted()
        || prefix.flags & crate::node::session_wire::FSP_FLAG_CP == 0
    {
        return Ok(DataplaneFspCoordWarmup::default());
    }
    if payload.len() < FSP_HEADER_SIZE {
        return Err(DataplaneSessionHandoffError::InvalidPacket);
    }
    let (source_coords, local_coords, _coords_len) =
        crate::node::session_wire::parse_encrypted_coords(&payload[FSP_HEADER_SIZE..])
            .map_err(|_| DataplaneSessionHandoffError::InvalidPacket)?;
    Ok(DataplaneFspCoordWarmup::from_parsed(
        source_addr,
        local_addr,
        source_coords,
        local_coords,
    ))
}
