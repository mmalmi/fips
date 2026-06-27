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
            match self.router.route_tun_outbound(&packet) {
                Ok(route) => push(route.into_outbound_packet(packet)),
                Err(reason) => self
                    .drops
                    .push(PacketMover2TunOutboundDrop::new(packet.len(), reason)),
            }
            drained += 1;
        }
        drained
    }
}

