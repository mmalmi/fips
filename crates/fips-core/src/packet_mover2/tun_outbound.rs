#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
struct FipsTunDestinationPrefix([u8; 15]);

impl FipsTunDestinationPrefix {
    const IPV6_HEADER_LEN: usize = 40;

    fn from_node_addr(node_addr: NodeAddr) -> Self {
        let mut prefix = [0u8; 15];
        prefix.copy_from_slice(&node_addr.as_bytes()[..15]);
        Self(prefix)
    }

    fn from_ipv6_packet(packet: &[u8]) -> Result<Self, PacketMover2TunOutboundDropReason> {
        if packet.len() < Self::IPV6_HEADER_LEN || packet[0] >> 4 != 6 {
            return Err(PacketMover2TunOutboundDropReason::InvalidPacket);
        }
        if packet[24] != crate::identity::FIPS_ADDRESS_PREFIX {
            return Err(PacketMover2TunOutboundDropReason::NoRoute);
        }
        let mut prefix = [0u8; 15];
        prefix.copy_from_slice(&packet[25..40]);
        Ok(Self(prefix))
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct PacketMover2TunOutboundRoute {
    owner: OwnerId,
    generation: u64,
    class: PacketClass,
    wire: OutboundWire,
    post_seal: OutboundPostSeal,
    payload: PacketMover2TunPayload,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PacketMover2TunPayload {
    Raw,
    Ipv6Shim {
        timestamp_ms: u32,
        inner_flags: u8,
    },
}

impl PacketMover2TunOutboundRoute {
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
            post_seal: OutboundPostSeal::Transport,
            payload: PacketMover2TunPayload::Raw,
        }
    }

    pub(crate) fn fsp(owner: OwnerId, generation: u64, class: PacketClass, flags: u8) -> Self {
        Self {
            owner,
            generation,
            class,
            wire: OutboundWire::Fsp { flags },
            post_seal: OutboundPostSeal::Transport,
            payload: PacketMover2TunPayload::Raw,
        }
    }

    pub(crate) fn fsp_ipv6_shim(
        owner: OwnerId,
        generation: u64,
        class: PacketClass,
        flags: u8,
        timestamp_ms: u32,
        inner_flags: u8,
    ) -> Self {
        Self {
            owner,
            generation,
            class,
            wire: OutboundWire::Fsp { flags },
            post_seal: OutboundPostSeal::Transport,
            payload: PacketMover2TunPayload::Ipv6Shim {
                timestamp_ms,
                inner_flags,
            },
        }
    }

    pub(crate) fn with_fmp_wrap(mut self, route: PacketMover2FspWrapRoute) -> Self {
        self.post_seal = OutboundPostSeal::FmpWrap(route);
        self
    }

    fn owner(&self) -> OwnerId {
        self.owner
    }

    fn refresh_generation(&mut self, generation: u64) {
        self.generation = generation;
    }

    fn into_outbound_packet(
        self,
        payload: Vec<u8>,
    ) -> Result<OutboundPacket, PacketMover2TunOutboundDropReason> {
        let payload = self.encode_payload(payload)?;
        match self.wire {
            OutboundWire::Fmp {
                receiver_idx,
                flags,
            } => Ok(OutboundPacket::fmp(
                self.owner,
                self.generation,
                self.class,
                receiver_idx,
                flags,
                payload,
            )
            .with_post_seal(self.post_seal)),
            OutboundWire::Fsp { flags } => Ok(OutboundPacket::fsp(
                self.owner,
                self.generation,
                self.class,
                flags,
                payload,
            )
            .with_post_seal(self.post_seal)),
        }
    }

    fn encode_payload(
        &self,
        payload: Vec<u8>,
    ) -> Result<Vec<u8>, PacketMover2TunOutboundDropReason> {
        match self.payload {
            PacketMover2TunPayload::Raw => Ok(payload),
            PacketMover2TunPayload::Ipv6Shim {
                timestamp_ms,
                inner_flags,
            } => {
                let compressed = crate::upper::ipv6_shim::compress_ipv6(&payload)
                    .ok_or(PacketMover2TunOutboundDropReason::InvalidPacket)?;
                let mut port_payload = Vec::with_capacity(
                    crate::node::session_wire::FSP_PORT_HEADER_SIZE + compressed.len(),
                );
                port_payload.extend_from_slice(
                    &crate::node::session_wire::FSP_PORT_IPV6_SHIM.to_le_bytes(),
                );
                port_payload.extend_from_slice(
                    &crate::node::session_wire::FSP_PORT_IPV6_SHIM.to_le_bytes(),
                );
                port_payload.extend_from_slice(&compressed);
                Ok(crate::node::session_wire::fsp_prepend_inner_header(
                    timestamp_ms,
                    crate::protocol::SessionMessageType::DataPacket.to_byte(),
                    inner_flags,
                    &port_payload,
                ))
            }
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct PacketMover2TunDestinationRoute {
    route: PacketMover2TunOutboundRoute,
    max_packet_len: Option<usize>,
}

impl PacketMover2TunDestinationRoute {
    pub(crate) fn new(route: PacketMover2TunOutboundRoute) -> Self {
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

    fn refresh_generation(&mut self, generation: u64) {
        self.route.refresh_generation(generation);
    }

    fn route_packet(
        &self,
        packet: &[u8],
    ) -> Result<PacketMover2TunOutboundRoute, PacketMover2TunOutboundDropReason> {
        if self
            .max_packet_len
            .is_some_and(|max_packet_len| packet.len() > max_packet_len)
        {
            return Err(PacketMover2TunOutboundDropReason::MtuExceeded);
        }
        Ok(self.route.clone())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PacketMover2TunOutboundDropReason {
    InvalidPacket,
    NoRoute,
    MtuExceeded,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct PacketMover2TunOutboundDrop {
    payload_len: usize,
    reason: PacketMover2TunOutboundDropReason,
}

impl PacketMover2TunOutboundDrop {
    fn new(payload_len: usize, reason: PacketMover2TunOutboundDropReason) -> Self {
        Self {
            payload_len,
            reason,
        }
    }

    pub(crate) fn payload_len(&self) -> usize {
        self.payload_len
    }

    pub(crate) fn reason(&self) -> PacketMover2TunOutboundDropReason {
        self.reason
    }
}

pub(crate) trait PacketMover2TunOutboundRouter {
    fn route_tun_outbound(
        &mut self,
        packet: &[u8],
    ) -> Result<PacketMover2TunOutboundRoute, PacketMover2TunOutboundDropReason>;
}

impl<F> PacketMover2TunOutboundRouter for F
where
    F: FnMut(&[u8]) -> Result<PacketMover2TunOutboundRoute, PacketMover2TunOutboundDropReason>,
{
    fn route_tun_outbound(
        &mut self,
        packet: &[u8],
    ) -> Result<PacketMover2TunOutboundRoute, PacketMover2TunOutboundDropReason> {
        self(packet)
    }
}

fn route_tun_outbound_packet_with_router<R, F>(
    packet: Vec<u8>,
    router: &mut R,
    drops: &mut Vec<PacketMover2TunOutboundDrop>,
    mut push: F,
) where
    R: PacketMover2TunOutboundRouter,
    F: FnMut(OutboundPacket),
{
    let payload_len = packet.len();
    match router.route_tun_outbound(&packet) {
        Ok(route) => match route.into_outbound_packet(packet) {
            Ok(packet) => push(packet),
            Err(reason) => drops.push(PacketMover2TunOutboundDrop::new(payload_len, reason)),
        },
        Err(reason) => drops.push(PacketMover2TunOutboundDrop::new(packet.len(), reason)),
    }
}
