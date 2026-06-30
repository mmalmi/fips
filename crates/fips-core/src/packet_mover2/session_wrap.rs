#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct PacketMover2FspWrapRoute {
    fmp_owner: OwnerId,
    fmp_generation: u64,
    receiver_idx: u32,
    fmp_flags: u8,
    source_addr: NodeAddr,
    dest_addr: NodeAddr,
    ttl: u8,
    path_mtu: u16,
}

impl PacketMover2FspWrapRoute {
    pub(crate) fn new(
        fmp_owner: OwnerId,
        fmp_generation: u64,
        receiver_idx: u32,
        source_addr: NodeAddr,
        dest_addr: NodeAddr,
    ) -> Self {
        Self {
            fmp_owner,
            fmp_generation,
            receiver_idx,
            fmp_flags: 0,
            source_addr,
            dest_addr,
            ttl: 64,
            path_mtu: u16::MAX,
        }
    }

    pub(crate) fn with_fmp_flags(mut self, flags: u8) -> Self {
        self.fmp_flags = flags;
        self
    }

    pub(crate) fn with_ttl(mut self, ttl: u8) -> Self {
        self.ttl = ttl;
        self
    }

    pub(crate) fn with_path_mtu(mut self, path_mtu: u16) -> Self {
        self.path_mtu = path_mtu;
        self
    }

    fn fmp_payload(self, fsp_wire: PacketBuffer) -> PacketBuffer {
        let fsp_wire = fsp_wire.into_vec();
        let mut payload =
            Vec::with_capacity(crate::protocol::SESSION_DATAGRAM_HEADER_SIZE + fsp_wire.len());
        payload.push(crate::protocol::LinkMessageType::SessionDatagram.to_byte());
        payload.push(self.ttl);
        payload.extend_from_slice(&self.path_mtu.to_le_bytes());
        payload.extend_from_slice(self.source_addr.as_bytes());
        payload.extend_from_slice(self.dest_addr.as_bytes());
        payload.extend_from_slice(&fsp_wire);
        payload.into()
    }

    fn into_fmp_outbound(self, class: PacketClass, fsp_wire: PacketBuffer) -> OutboundPacket {
        OutboundPacket::fmp(
            self.fmp_owner,
            self.fmp_generation,
            class,
            self.receiver_idx,
            self.fmp_flags,
            self.fmp_payload(fsp_wire),
        )
    }

    fn reserve_fmp_outbound(self, class: PacketClass) -> OutboundPacket {
        self.into_fmp_outbound(class, Vec::<u8>::new().into())
    }

    fn fill_reserved_fmp_outbound(self, packet: &mut OutboundPacket, fsp_wire: PacketBuffer) {
        packet.payload = self.fmp_payload(fsp_wire);
    }
}
