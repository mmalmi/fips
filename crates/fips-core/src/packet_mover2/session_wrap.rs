#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct PacketMover2FspWrapRoute {
    fmp_owner: OwnerId,
    fmp_generation: u64,
    class: PacketClass,
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
        class: PacketClass,
        receiver_idx: u32,
        source_addr: NodeAddr,
        dest_addr: NodeAddr,
    ) -> Self {
        Self {
            fmp_owner,
            fmp_generation,
            class,
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

    fn into_fmp_outbound(self, fsp_wire: PacketBuffer) -> OutboundPacket {
        let fsp_wire = fsp_wire.into_vec();
        let mut payload =
            Vec::with_capacity(crate::protocol::SESSION_DATAGRAM_HEADER_SIZE + fsp_wire.len());
        payload.push(crate::protocol::LinkMessageType::SessionDatagram.to_byte());
        payload.push(self.ttl);
        payload.extend_from_slice(&self.path_mtu.to_le_bytes());
        payload.extend_from_slice(self.source_addr.as_bytes());
        payload.extend_from_slice(self.dest_addr.as_bytes());
        payload.extend_from_slice(&fsp_wire);

        OutboundPacket::fmp(
            self.fmp_owner,
            self.fmp_generation,
            self.class,
            self.receiver_idx,
            self.fmp_flags,
            payload,
        )
    }
}
