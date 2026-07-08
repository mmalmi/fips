#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(crate) struct FipsTunDestinationPrefix([u8; 15]);

impl FipsTunDestinationPrefix {
    const IPV6_HEADER_LEN: usize = 40;

    fn from_node_addr(node_addr: NodeAddr) -> Self {
        let mut prefix = [0u8; 15];
        prefix.copy_from_slice(&node_addr.as_bytes()[..15]);
        Self(prefix)
    }

    fn from_ipv6_packet(packet: &[u8]) -> Result<Self, DataplaneTunOutboundDropReason> {
        if packet.len() < Self::IPV6_HEADER_LEN || packet[0] >> 4 != 6 {
            return Err(DataplaneTunOutboundDropReason::InvalidPacket);
        }
        if packet[24] != crate::identity::FIPS_ADDRESS_PREFIX {
            return Err(DataplaneTunOutboundDropReason::NoRoute);
        }
        let mut prefix = [0u8; 15];
        prefix.copy_from_slice(&packet[25..40]);
        Ok(Self(prefix))
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct DataplaneTunOutboundRoute {
    owner: OwnerId,
    generation: u64,
    class: PacketClass,
    flags: u8,
    inner_flags: u8,
    max_packet_len: Option<usize>,
}

impl DataplaneTunOutboundRoute {
    pub(crate) fn fsp_ipv6_shim(
        owner: OwnerId,
        generation: u64,
        class: PacketClass,
        flags: u8,
        inner_flags: u8,
    ) -> Self {
        Self {
            owner,
            generation,
            class,
            flags,
            inner_flags,
            max_packet_len: None,
        }
    }

    pub(crate) fn with_max_packet_len(mut self, max_packet_len: usize) -> Self {
        self.max_packet_len = Some(max_packet_len);
        self
    }

    fn owner(&self) -> OwnerId {
        self.owner
    }

    fn route_packet(
        &self,
        packet: &[u8],
    ) -> Result<&Self, DataplaneTunOutboundDropReason> {
        if let Some(max_packet_len) = self.max_packet_len
            && packet.len() > max_packet_len
        {
            return Err(DataplaneTunOutboundDropReason::MtuExceeded {
                mtu: max_packet_len as u32,
            });
        }
        Ok(self)
    }

    fn to_outbound_packet(&self, mut payload: Vec<u8>) -> OutboundPacket {
        assert!(
            crate::upper::ipv6_shim::compress_ipv6_with_port_header_in_place(
                &mut payload,
                crate::node::session_wire::FSP_PORT_IPV6_SHIM,
                crate::node::session_wire::FSP_PORT_IPV6_SHIM,
            ),
            "TUN outbound preflight must match IPv6 shim compression preflight"
        );
        OutboundPacket::fsp(
            self.owner,
            self.generation,
            self.class,
            self.flags,
            PacketBuffer::new(payload),
        )
            .with_fsp_inner_header(
                crate::protocol::SessionMessageType::DataPacket.to_byte(),
                self.inner_flags,
            )
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DataplaneTunOutboundDropReason {
    InvalidPacket,
    NoRoute,
    MtuExceeded { mtu: u32 },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct DataplaneTunOutboundDrop {
    packet: Vec<u8>,
    reason: DataplaneTunOutboundDropReason,
}

impl DataplaneTunOutboundDrop {
    pub(crate) fn packet(&self) -> &[u8] {
        &self.packet
    }

    pub(crate) fn payload_len(&self) -> usize {
        self.packet.len()
    }

    pub(crate) fn reason(&self) -> DataplaneTunOutboundDropReason {
        self.reason
    }
}

fn route_tun_outbound_packet_with_route_table<F>(
    packet: Vec<u8>,
    routes: &DataplaneLiveRouteTable,
    activity_tick: ActivityTick,
    drops: &mut Vec<DataplaneTunOutboundDrop>,
    deferred_packets: &mut Vec<Vec<u8>>,
    mut push: F,
) where
    F: FnMut(OutboundPacket),
{
    let dest = match FipsTunDestinationPrefix::from_ipv6_packet(&packet) {
        Ok(dest) => dest,
        Err(reason) => {
            drops.push(DataplaneTunOutboundDrop { packet, reason });
            return;
        }
    };
    match routes.route_tun_outbound(&packet, dest) {
        Ok(route) => push(
            route
                .to_outbound_packet(packet)
                .with_activity_tick(activity_tick),
        ),
        Err(DataplaneTunOutboundDropReason::NoRoute) => deferred_packets.push(packet),
        Err(reason) => drops.push(DataplaneTunOutboundDrop { packet, reason }),
    }
}
