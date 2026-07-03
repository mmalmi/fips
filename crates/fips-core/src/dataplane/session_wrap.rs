#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct DataplaneFspWrapRoute {
    fmp_owner: OwnerId,
    fmp_generation: u64,
    receiver_idx: u32,
    fmp_flags: u8,
    source_addr: NodeAddr,
    dest_addr: NodeAddr,
    ttl: u8,
    path_mtu: u16,
}

impl DataplaneFspWrapRoute {
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

    pub(crate) fn next_hop_addr(self) -> NodeAddr {
        self.fmp_owner.node_addr()
    }

    fn fmp_payload_header(self) -> [u8; crate::protocol::SESSION_DATAGRAM_HEADER_SIZE] {
        let mut header = [0u8; crate::protocol::SESSION_DATAGRAM_HEADER_SIZE];
        header[0] = crate::protocol::LinkMessageType::SessionDatagram.to_byte();
        header[1] = self.ttl;
        header[2..4].copy_from_slice(&self.path_mtu.to_le_bytes());
        header[4..20].copy_from_slice(self.source_addr.as_bytes());
        header[20..36].copy_from_slice(self.dest_addr.as_bytes());
        header
    }

    fn fmp_payload(self, fsp_wire: PacketBuffer) -> PacketBuffer {
        let mut fsp_wire = fsp_wire;
        let header = self.fmp_payload_header();
        let outer_fmp_tail = FMP_ESTABLISHED_HEADER_SIZE
            .saturating_add(std::mem::size_of::<u32>())
            .saturating_add(AEAD_TAG_SIZE);
        if fsp_wire.try_prepend_slices(&[&header], outer_fmp_tail) {
            return fsp_wire;
        }

        let fsp_wire = fsp_wire.into_vec();
        let mut payload =
            Vec::with_capacity(crate::protocol::SESSION_DATAGRAM_HEADER_SIZE + fsp_wire.len());
        payload.extend_from_slice(&header);
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

}
