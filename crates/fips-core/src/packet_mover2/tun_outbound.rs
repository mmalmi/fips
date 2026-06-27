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
        }
    }

    pub(crate) fn fsp(owner: OwnerId, generation: u64, class: PacketClass, flags: u8) -> Self {
        Self {
            owner,
            generation,
            class,
            wire: OutboundWire::Fsp { flags },
        }
    }

    fn owner(&self) -> OwnerId {
        self.owner
    }

    fn into_outbound_packet(self, payload: Vec<u8>) -> OutboundPacket {
        match self.wire {
            OutboundWire::Fmp {
                receiver_idx,
                flags,
            } => OutboundPacket::fmp(
                self.owner,
                self.generation,
                self.class,
                receiver_idx,
                flags,
                payload,
            ),
            OutboundWire::Fsp { flags } => {
                OutboundPacket::fsp(self.owner, self.generation, self.class, flags, payload)
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

pub(crate) struct PacketMover2TunOutboundSource<'a, R> {
    rx: &'a mut TunOutboundRx,
    router: &'a mut R,
    drops: Vec<PacketMover2TunOutboundDrop>,
}

impl<'a, R> PacketMover2TunOutboundSource<'a, R> {
    pub(crate) fn new(rx: &'a mut TunOutboundRx, router: &'a mut R) -> Self {
        Self {
            rx,
            router,
            drops: Vec::new(),
        }
    }

    pub(crate) fn drops(&self) -> &[PacketMover2TunOutboundDrop] {
        &self.drops
    }

    fn take_drops(&mut self) -> Vec<PacketMover2TunOutboundDrop> {
        std::mem::take(&mut self.drops)
    }
}

impl<R> PacketMover2OutboundSource for PacketMover2TunOutboundSource<'_, R>
where
    R: PacketMover2TunOutboundRouter,
{
    fn drain_outbound<F>(&mut self, limit: usize, mut push: F) -> usize
    where
        F: FnMut(OutboundPacket),
    {
        let mut drained = 0;
        while drained < limit {
            let Ok(packet) = self.rx.try_recv() else {
                break;
            };
            route_tun_outbound_packet_with_router(packet, self.router, &mut self.drops, &mut push);
            drained += 1;
        }
        drained
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
    match router.route_tun_outbound(&packet) {
        Ok(route) => push(route.into_outbound_packet(packet)),
        Err(reason) => drops.push(PacketMover2TunOutboundDrop::new(packet.len(), reason)),
    }
}
