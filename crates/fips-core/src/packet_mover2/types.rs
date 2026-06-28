pub(crate) type AeadKey = Arc<LessSafeKey>;

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(crate) enum PacketProtocol {
    Fmp,
    Fsp,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(crate) struct OwnerId {
    peer: OwnerPeerId,
    protocol: PacketProtocol,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(crate) enum OwnerPeerId {
    Scratch(u64),
    Node(NodeAddr),
}

impl OwnerId {
    pub(crate) fn fmp(peer: u64) -> Self {
        Self {
            peer: OwnerPeerId::Scratch(peer),
            protocol: PacketProtocol::Fmp,
        }
    }

    pub(crate) fn fsp(peer: u64) -> Self {
        Self {
            peer: OwnerPeerId::Scratch(peer),
            protocol: PacketProtocol::Fsp,
        }
    }

    pub(crate) fn fmp_node(node_addr: NodeAddr) -> Self {
        Self {
            peer: OwnerPeerId::Node(node_addr),
            protocol: PacketProtocol::Fmp,
        }
    }

    pub(crate) fn fsp_node(node_addr: NodeAddr) -> Self {
        Self {
            peer: OwnerPeerId::Node(node_addr),
            protocol: PacketProtocol::Fsp,
        }
    }

    pub(crate) fn peer_id(self) -> OwnerPeerId {
        self.peer
    }

    pub(crate) fn protocol(self) -> PacketProtocol {
        self.protocol
    }

    pub(crate) fn node_addr(self) -> Option<NodeAddr> {
        match self.peer {
            OwnerPeerId::Scratch(_) => None,
            OwnerPeerId::Node(node_addr) => Some(node_addr),
        }
    }

    #[cfg(test)]
    fn scratch_peer(self) -> Option<u64> {
        match self.peer {
            OwnerPeerId::Scratch(peer) => Some(peer),
            OwnerPeerId::Node(_) => None,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PacketClass {
    Control,
    Rekey,
    Mmp,
    Liveness,
    Bulk,
}

impl PacketClass {
    fn lane(self) -> Lane {
        match self {
            Self::Control | Self::Rekey | Self::Mmp | Self::Liveness => Lane::Priority,
            Self::Bulk => Lane::Bulk,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Lane {
    Priority,
    Bulk,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum OutputTarget {
    Tun,
    Endpoint,
    Transport,
    SessionIngress { local_addr: NodeAddr },
    SessionPayload { local_addr: NodeAddr },
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub(crate) enum TransportPath {
    Scratch(u64),
    Live {
        transport_id: TransportId,
        remote_addr: TransportAddr,
    },
}

impl TransportPath {
    pub(crate) fn new(id: u64) -> Self {
        Self::Scratch(id)
    }

    pub(crate) fn live(transport_id: TransportId, remote_addr: TransportAddr) -> Self {
        Self::Live {
            transport_id,
            remote_addr,
        }
    }

    pub(crate) fn transport_id(&self) -> Option<TransportId> {
        match self {
            Self::Scratch(_) => None,
            Self::Live { transport_id, .. } => Some(*transport_id),
        }
    }

    pub(crate) fn remote_addr(&self) -> Option<&TransportAddr> {
        match self {
            Self::Scratch(_) => None,
            Self::Live { remote_addr, .. } => Some(remote_addr),
        }
    }

    #[cfg(test)]
    fn scratch_id(&self) -> Option<u64> {
        match self {
            Self::Scratch(id) => Some(*id),
            Self::Live { .. } => None,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub(crate) struct ActivityTick(u64);

impl ActivityTick {
    pub(crate) fn new(tick: u64) -> Self {
        Self(tick)
    }

    fn get(self) -> u64 {
        self.0
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct SocketPacket {
    owner: OwnerId,
    generation: u64,
    counter: u64,
    class: PacketClass,
    output: OutputTarget,
    source_path: Option<TransportPath>,
    previous_hop: Option<NodeAddr>,
    ce_flag: bool,
    wire_flags: u8,
    activity_tick: Option<ActivityTick>,
    payload: PacketBuffer,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum OutboundWire {
    Fmp { receiver_idx: u32, flags: u8 },
    Fsp { flags: u8 },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum OutboundPostSeal {
    Transport,
    FmpWrap(PacketMover2FspWrapRoute),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum OutboundPayloadTransform {
    None,
    FspInnerHeader { msg_type: u8, inner_flags: u8 },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct OutboundPacket {
    owner: OwnerId,
    generation: u64,
    class: PacketClass,
    wire: OutboundWire,
    post_seal: OutboundPostSeal,
    payload_transform: OutboundPayloadTransform,
    fsp_cleartext_prefix: Vec<u8>,
    fsp_auto_coords_warmup: bool,
    activity_tick: Option<ActivityTick>,
    payload: PacketBuffer,
}

impl OutboundPacket {
    pub(crate) fn fmp(
        owner: OwnerId,
        generation: u64,
        class: PacketClass,
        receiver_idx: u32,
        flags: u8,
        payload: impl Into<PacketBuffer>,
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
            payload_transform: OutboundPayloadTransform::None,
            fsp_cleartext_prefix: Vec::new(),
            fsp_auto_coords_warmup: true,
            activity_tick: None,
            payload: payload.into(),
        }
    }

    pub(crate) fn fsp(
        owner: OwnerId,
        generation: u64,
        class: PacketClass,
        flags: u8,
        payload: impl Into<PacketBuffer>,
    ) -> Self {
        Self {
            owner,
            generation,
            class,
            wire: OutboundWire::Fsp { flags },
            post_seal: OutboundPostSeal::Transport,
            payload_transform: OutboundPayloadTransform::None,
            fsp_cleartext_prefix: Vec::new(),
            fsp_auto_coords_warmup: true,
            activity_tick: None,
            payload: payload.into(),
        }
    }

    pub(crate) fn with_fsp_inner_header(mut self, msg_type: u8, inner_flags: u8) -> Self {
        self.payload_transform = OutboundPayloadTransform::FspInnerHeader {
            msg_type,
            inner_flags,
        };
        self
    }

    pub(crate) fn with_post_seal(mut self, post_seal: OutboundPostSeal) -> Self {
        self.post_seal = post_seal;
        self
    }

    pub(crate) fn with_fsp_cleartext_prefix(mut self, prefix: Vec<u8>) -> Self {
        self.fsp_cleartext_prefix = prefix;
        self
    }

    pub(crate) fn without_fsp_auto_coords_warmup(mut self) -> Self {
        self.fsp_auto_coords_warmup = false;
        self
    }

    fn crypto_plaintext_prefix(
        &mut self,
        fmp_timestamp_ms: Option<u32>,
        fsp_timestamp_ms: Option<u32>,
    ) -> Result<Vec<u8>, WireBuildError> {
        let mut prefix = Vec::new();
        if self.owner.protocol == PacketProtocol::Fmp
            && let Some(timestamp_ms) = fmp_timestamp_ms
        {
            prefix.extend_from_slice(&timestamp_ms.to_le_bytes());
        }

        match self.payload_transform {
            OutboundPayloadTransform::None => {}
            OutboundPayloadTransform::FspInnerHeader {
                msg_type,
                inner_flags,
            } => {
                let timestamp_ms = fsp_timestamp_ms.ok_or(WireBuildError::MissingFspTimestamp)?;
                prefix.extend_from_slice(&timestamp_ms.to_le_bytes());
                prefix.push(msg_type);
                prefix.push(inner_flags);
                self.payload_transform = OutboundPayloadTransform::None;
            }
        }
        Ok(prefix)
    }

    pub(crate) fn with_activity_tick(mut self, tick: ActivityTick) -> Self {
        self.activity_tick = Some(tick);
        self
    }

    fn lane(&self) -> Lane {
        self.class.lane()
    }
}

impl SocketPacket {
    pub(crate) fn new(
        owner: OwnerId,
        generation: u64,
        counter: u64,
        class: PacketClass,
        output: OutputTarget,
        payload: impl Into<PacketBuffer>,
    ) -> Self {
        Self {
            owner,
            generation,
            counter,
            class,
            output,
            source_path: None,
            previous_hop: None,
            ce_flag: false,
            wire_flags: 0,
            activity_tick: None,
            payload: payload.into(),
        }
    }

    pub(crate) fn with_source_path(mut self, path: TransportPath) -> Self {
        self.source_path = Some(path);
        self
    }

    pub(crate) fn with_previous_hop(mut self, previous_hop: NodeAddr) -> Self {
        self.previous_hop = Some(previous_hop);
        self
    }

    pub(crate) fn with_ce_flag(mut self, ce_flag: bool) -> Self {
        self.ce_flag = ce_flag;
        self
    }

    pub(crate) fn with_wire_flags(mut self, wire_flags: u8) -> Self {
        self.wire_flags = wire_flags;
        self
    }

    pub(crate) fn with_activity_tick(mut self, tick: ActivityTick) -> Self {
        self.activity_tick = Some(tick);
        self
    }

    fn lane(&self) -> Lane {
        self.class.lane()
    }

    pub(crate) fn from_fmp_established_wire(
        owner: OwnerId,
        generation: u64,
        output: OutputTarget,
        data: impl Into<PacketBuffer>,
    ) -> Result<Self, WirePreflightError> {
        let payload: PacketBuffer = data.into();
        let header = FmpWireHeader::parse(&payload)?;
        Ok(Self::new(
            owner,
            generation,
            header.counter,
            PacketClass::Bulk,
            output,
            payload,
        )
        .with_wire_flags(header.flags()))
    }

    pub(crate) fn from_fsp_established_wire(
        owner: OwnerId,
        generation: u64,
        output: OutputTarget,
        data: impl Into<PacketBuffer>,
    ) -> Result<Self, WirePreflightError> {
        let payload: PacketBuffer = data.into();
        let header = FspWireHeader::parse(&payload)?;
        Ok(Self::new(
            owner,
            generation,
            header.counter,
            PacketClass::Bulk,
            output,
            payload,
        )
        .with_wire_flags(header.flags()))
    }
}
