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
    wire: OutboundWire,
    fsp_cleartext_prefix: Vec<u8>,
    payload: DataplaneTunPayload,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DataplaneTunPayload {
    Raw,
    Ipv6Shim { inner_flags: u8 },
}

impl DataplaneTunOutboundRoute {
    pub(crate) fn fmp(
        owner: OwnerId,
        generation: u64,
        class: PacketClass,
        receiver_idx: u32,
        flags: u8,
    ) -> Self {
        Self {
            owner,
            generation,
            class,
            wire: OutboundWire::Fmp {
                receiver_idx,
                flags,
            },
            fsp_cleartext_prefix: Vec::new(),
            payload: DataplaneTunPayload::Raw,
        }
    }

    pub(crate) fn fsp(owner: OwnerId, generation: u64, class: PacketClass, flags: u8) -> Self {
        Self {
            owner,
            generation,
            class,
            wire: OutboundWire::Fsp { flags },
            fsp_cleartext_prefix: Vec::new(),
            payload: DataplaneTunPayload::Raw,
        }
    }

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
            wire: OutboundWire::Fsp { flags },
            fsp_cleartext_prefix: Vec::new(),
            payload: DataplaneTunPayload::Ipv6Shim { inner_flags },
        }
    }

    pub(crate) fn with_fsp_cleartext_prefix(mut self, prefix: Vec<u8>) -> Self {
        self.fsp_cleartext_prefix = prefix;
        self
    }

    fn owner(&self) -> OwnerId {
        self.owner
    }

    fn into_outbound_packet(
        self,
        mut payload: Vec<u8>,
    ) -> Result<OutboundPacket, DataplaneTunOutboundDropReason> {
        let Self {
            owner,
            generation,
            class,
            wire,
            fsp_cleartext_prefix,
            payload: payload_kind,
        } = self;
        let inner_flags = match payload_kind {
            DataplaneTunPayload::Raw => None,
            DataplaneTunPayload::Ipv6Shim { inner_flags } => {
                if !crate::upper::ipv6_shim::compress_ipv6_with_port_header_in_place(
                    &mut payload,
                    crate::node::session_wire::FSP_PORT_IPV6_SHIM,
                    crate::node::session_wire::FSP_PORT_IPV6_SHIM,
                ) {
                    return Err(DataplaneTunOutboundDropReason::InvalidPacket);
                }
                Some(inner_flags)
            }
        };
        let mut packet = match wire {
            OutboundWire::Fmp {
                receiver_idx,
                flags,
            } => OutboundPacket::fmp(owner, generation, class, receiver_idx, flags, payload),
            OutboundWire::Fsp { flags } => {
                OutboundPacket::fsp(owner, generation, class, flags, payload)
                    .with_fsp_cleartext_prefix(fsp_cleartext_prefix)
            }
        };
        if let Some(inner_flags) = inner_flags {
            packet = packet.with_fsp_inner_header(
                crate::protocol::SessionMessageType::DataPacket.to_byte(),
                inner_flags,
            );
        }
        Ok(packet)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct DataplaneTunDestinationRoute {
    route: DataplaneTunOutboundRoute,
    max_packet_len: Option<usize>,
}

impl DataplaneTunDestinationRoute {
    pub(crate) fn new(route: DataplaneTunOutboundRoute) -> Self {
        Self {
            route,
            max_packet_len: None,
        }
    }

    pub(crate) fn with_max_packet_len(mut self, max_packet_len: usize) -> Self {
        self.max_packet_len = Some(max_packet_len);
        self
    }

    fn owner(&self) -> OwnerId {
        self.route.owner()
    }

    fn route_packet(
        &self,
        packet: &[u8],
    ) -> Result<DataplaneTunOutboundRoute, DataplaneTunOutboundDropReason> {
        if let Some(max_packet_len) = self.max_packet_len
            && packet.len() > max_packet_len
        {
            return Err(DataplaneTunOutboundDropReason::MtuExceeded {
                mtu: max_packet_len as u32,
            });
        }
        Ok(self.route.clone())
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
    payload_len: usize,
    reason: DataplaneTunOutboundDropReason,
}

impl DataplaneTunOutboundDrop {
    fn new(packet: Vec<u8>, reason: DataplaneTunOutboundDropReason) -> Self {
        let payload_len = packet.len();
        Self::with_payload_len(packet, payload_len, reason)
    }

    fn with_payload_len(
        packet: Vec<u8>,
        payload_len: usize,
        reason: DataplaneTunOutboundDropReason,
    ) -> Self {
        Self {
            packet,
            payload_len,
            reason,
        }
    }

    pub(crate) fn packet(&self) -> &[u8] {
        &self.packet
    }

    pub(crate) fn payload_len(&self) -> usize {
        self.payload_len
    }

    pub(crate) fn reason(&self) -> DataplaneTunOutboundDropReason {
        self.reason
    }
}

pub(crate) trait DataplaneTunOutboundRouter {
    fn route_tun_outbound(
        &mut self,
        packet: &[u8],
        dest: FipsTunDestinationPrefix,
    ) -> Result<DataplaneTunOutboundRoute, DataplaneTunOutboundDropReason>;
}

fn route_tun_outbound_packet_with_router<R, F>(
    packet: Vec<u8>,
    router: &mut R,
    activity_tick: ActivityTick,
    drops: &mut Vec<DataplaneTunOutboundDrop>,
    deferred_packets: &mut Vec<Vec<u8>>,
    mut push: F,
) where
    R: DataplaneTunOutboundRouter,
    F: FnMut(OutboundPacket),
{
    let payload_len = packet.len();
    let dest = match FipsTunDestinationPrefix::from_ipv6_packet(&packet) {
        Ok(dest) => dest,
        Err(reason) => {
            drops.push(DataplaneTunOutboundDrop::new(packet, reason));
            return;
        }
    };
    match router.route_tun_outbound(&packet, dest) {
        Ok(route) => match route.into_outbound_packet(packet) {
            Ok(packet) => push(packet.with_activity_tick(activity_tick)),
            Err(reason) => {
                drops.push(DataplaneTunOutboundDrop::with_payload_len(
                    Vec::new(),
                    payload_len,
                    reason,
                ));
            }
        },
        Err(DataplaneTunOutboundDropReason::NoRoute) => deferred_packets.push(packet),
        Err(reason) => drops.push(DataplaneTunOutboundDrop::new(packet, reason)),
    }
}
