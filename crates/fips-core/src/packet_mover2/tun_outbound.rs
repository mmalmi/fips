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
    fsp_cleartext_prefix: Vec<u8>,
    post_seal: OutboundPostSeal,
    payload: PacketMover2TunPayload,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PacketMover2TunPayload {
    Raw,
    Ipv6Shim { inner_flags: u8 },
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
            fsp_cleartext_prefix: Vec::new(),
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
            fsp_cleartext_prefix: Vec::new(),
            post_seal: OutboundPostSeal::Transport,
            payload: PacketMover2TunPayload::Raw,
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
            post_seal: OutboundPostSeal::Transport,
            payload: PacketMover2TunPayload::Ipv6Shim { inner_flags },
        }
    }

    pub(crate) fn with_fsp_cleartext_prefix(mut self, prefix: Vec<u8>) -> Self {
        self.fsp_cleartext_prefix = prefix;
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
        let class = self.class_for_payload(&payload);
        let payload = self.encode_payload(payload)?;
        let packet = match self.wire {
            OutboundWire::Fmp {
                receiver_idx,
                flags,
            } => OutboundPacket::fmp(
                self.owner,
                self.generation,
                class,
                receiver_idx,
                flags,
                payload,
            )
            .with_post_seal(self.post_seal),
            OutboundWire::Fsp { flags } => OutboundPacket::fsp(
                self.owner,
                self.generation,
                class,
                flags,
                payload,
            )
            .with_fsp_cleartext_prefix(self.fsp_cleartext_prefix.clone())
            .with_post_seal(self.post_seal),
        };
        Ok(self.apply_payload_transform(packet))
    }

    fn class_for_payload(&self, payload: &[u8]) -> PacketClass {
        if self.class != PacketClass::Bulk {
            return self.class;
        }
        if crate::node::endpoint_payload_is_liveness_probe(payload) {
            PacketClass::Liveness
        } else {
            let traffic_class = crate::node::classify_endpoint_payload(payload);
            if traffic_class.is_latency_sensitive() {
                PacketClass::Control
            } else if traffic_class.drop_on_backpressure() {
                PacketClass::Bulk
            } else {
                PacketClass::ReliableBulk
            }
        }
    }

    fn encode_payload(
        &self,
        payload: Vec<u8>,
    ) -> Result<Vec<u8>, PacketMover2TunOutboundDropReason> {
        match self.payload {
            PacketMover2TunPayload::Raw => Ok(payload),
            PacketMover2TunPayload::Ipv6Shim { inner_flags: _ } => {
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
                Ok(port_payload)
            }
        }
    }

    fn apply_payload_transform(&self, packet: OutboundPacket) -> OutboundPacket {
        match self.payload {
            PacketMover2TunPayload::Raw => packet,
            PacketMover2TunPayload::Ipv6Shim { inner_flags } => packet.with_fsp_inner_header(
                crate::protocol::SessionMessageType::DataPacket.to_byte(),
                inner_flags,
            ),
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
            return Err(PacketMover2TunOutboundDropReason::MtuExceeded {
                mtu: self.max_packet_len.unwrap_or_default() as u32,
            });
        }
        Ok(self.route.clone())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PacketMover2TunOutboundDropReason {
    InvalidPacket,
    NoRoute,
    MtuExceeded { mtu: u32 },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct PacketMover2TunOutboundDrop {
    packet: Vec<u8>,
    payload_len: usize,
    reason: PacketMover2TunOutboundDropReason,
}

impl PacketMover2TunOutboundDrop {
    fn new(packet: Vec<u8>, reason: PacketMover2TunOutboundDropReason) -> Self {
        let payload_len = packet.len();
        Self::with_payload_len(packet, payload_len, reason)
    }

    fn with_payload_len(
        packet: Vec<u8>,
        payload_len: usize,
        reason: PacketMover2TunOutboundDropReason,
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
    deferred_packets: &mut Vec<Vec<u8>>,
    mut push: F,
) where
    R: PacketMover2TunOutboundRouter,
    F: FnMut(OutboundPacket),
{
    let payload_len = packet.len();
    match router.route_tun_outbound(&packet) {
        Ok(route) => match route.into_outbound_packet(packet) {
            Ok(packet) => push(packet.with_activity_tick(ActivityTick::new(crate::time::now_ms()))),
            Err(reason) => {
                drops.push(PacketMover2TunOutboundDrop::with_payload_len(
                    Vec::new(),
                    payload_len,
                    reason,
                ));
            }
        },
        Err(PacketMover2TunOutboundDropReason::NoRoute) if tun_packet_can_defer_no_route(&packet) => {
            deferred_packets.push(packet);
        }
        Err(reason) => drops.push(PacketMover2TunOutboundDrop::new(packet, reason)),
    }
}

fn tun_packet_can_defer_no_route(packet: &[u8]) -> bool {
    FipsTunDestinationPrefix::from_ipv6_packet(packet).is_ok()
}
