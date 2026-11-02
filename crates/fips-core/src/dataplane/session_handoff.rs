#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DataplaneSessionHandoffError {
    InvalidPacket,
    NoRoute,
}

#[derive(Clone, Debug, Eq, PartialEq)]
// `NoRoute` also carries ordinary transit packets. Keep their output inline to
// avoid allocating on every routed session handoff.
#[allow(clippy::large_enum_variant)]
enum DataplaneSessionIngressHandoff {
    Raw(DataplaneRawIngress),
    Local(DataplaneFspLocalSessionIngress),
    Rejected {
        output: PacketOutput,
        error: DataplaneSessionHandoffError,
    },
}

impl DataplaneSessionIngressHandoff {
    fn rejected(output: PacketOutput, error: DataplaneSessionHandoffError) -> Self {
        Self::Rejected { output, error }
    }
}

fn dataplane_session_ingress_from_output(
    output: PacketOutput,
    local_addr: NodeAddr,
) -> DataplaneSessionIngressHandoff {
    if output.owner.protocol() != PacketProtocol::Fmp {
        return DataplaneSessionIngressHandoff::rejected(
            output,
            DataplaneSessionHandoffError::InvalidPacket,
        );
    }

    const FMP_LINK_TIMESTAMP_LEN: usize = 4;
    const FMP_LINK_MSG_TYPE_LEN: usize = 1;
    const FMP_SESSION_PAYLOAD_OFFSET: usize = FMP_LINK_TIMESTAMP_LEN
        + FMP_LINK_MSG_TYPE_LEN
        + crate::protocol::SessionDatagramRef::HEADER_LEN;

    let previous_hop = output.owner.node_addr();
    let fmp_header = match FmpWireHeader::parse(output.payload()) {
        Ok(header) => header,
        Err(_) => {
            return DataplaneSessionIngressHandoff::rejected(
                output,
                DataplaneSessionHandoffError::InvalidPacket,
            );
        }
    };

    let Some(source_path) = output.source_path() else {
        return DataplaneSessionIngressHandoff::rejected(
            output,
            DataplaneSessionHandoffError::NoRoute,
        );
    };
    let transport_id = source_path.transport_id;
    let remote_addr = source_path.remote_addr.clone();

    let (source_addr, path_mtu, local_delivery) = {
        let Some(link_payload) = output.opened_payload() else {
            return DataplaneSessionIngressHandoff::rejected(
                output,
                DataplaneSessionHandoffError::InvalidPacket,
            );
        };
        if link_payload.len() < FMP_LINK_TIMESTAMP_LEN {
            return DataplaneSessionIngressHandoff::rejected(
                output,
                DataplaneSessionHandoffError::InvalidPacket,
            );
        }
        let link_payload = &link_payload[FMP_LINK_TIMESTAMP_LEN..];
        let Some((&msg_type, datagram_payload)) = link_payload.split_first() else {
            return DataplaneSessionIngressHandoff::rejected(
                output,
                DataplaneSessionHandoffError::InvalidPacket,
            );
        };
        if msg_type != crate::protocol::LinkMessageType::SessionDatagram.to_byte() {
            return DataplaneSessionIngressHandoff::rejected(
                output,
                DataplaneSessionHandoffError::NoRoute,
            );
        }

        let datagram = match crate::protocol::SessionDatagramRef::decode(datagram_payload) {
            Ok(datagram) => datagram,
            Err(_) => {
                return DataplaneSessionIngressHandoff::rejected(
                    output,
                    DataplaneSessionHandoffError::InvalidPacket,
                );
            }
        };
        if datagram.ttl == 0 || datagram.dest_addr != local_addr {
            return DataplaneSessionIngressHandoff::rejected(
                output,
                DataplaneSessionHandoffError::NoRoute,
            );
        }
        let Some(prefix) = crate::node::session_wire::FspCommonPrefix::parse(datagram.payload)
        else {
            return DataplaneSessionIngressHandoff::rejected(
                output,
                DataplaneSessionHandoffError::InvalidPacket,
            );
        };
        (
            datagram.src_addr,
            datagram.path_mtu,
            prefix.phase != FSP_PHASE_ESTABLISHED || prefix.is_unencrypted(),
        )
    };

    let ce_flag = fmp_header.flags() & crate::node::wire::FLAG_CE != 0;
    let activity_tick = output.activity_tick;
    let mut output = output;
    let Some(mut payload) = output.take_opened_payload() else {
        return DataplaneSessionIngressHandoff::rejected(
            output,
            DataplaneSessionHandoffError::InvalidPacket,
        );
    };
    debug_assert!(payload.len() >= FMP_SESSION_PAYLOAD_OFFSET);
    assert!(payload.trim_front(FMP_SESSION_PAYLOAD_OFFSET));

    let path = TransportPath::live(transport_id, remote_addr.clone());

    if local_delivery {
        return DataplaneSessionIngressHandoff::Local(
            DataplaneFspLocalSessionIngress::new(
                source_addr,
                previous_hop,
                ce_flag,
                path_mtu,
                payload,
            ),
        );
    }

    DataplaneSessionIngressHandoff::Raw(DataplaneRawIngress {
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
    })
}
