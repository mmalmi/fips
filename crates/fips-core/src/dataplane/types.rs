pub(crate) type AeadKey = Arc<LessSafeKey>;

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(crate) enum PacketProtocol {
    Fmp,
    Fsp,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(crate) struct OwnerId {
    node_addr: NodeAddr,
    protocol: PacketProtocol,
}

impl OwnerId {
    pub(crate) fn fmp_node(node_addr: NodeAddr) -> Self {
        Self {
            node_addr,
            protocol: PacketProtocol::Fmp,
        }
    }

    pub(crate) fn fsp_node(node_addr: NodeAddr) -> Self {
        Self {
            node_addr,
            protocol: PacketProtocol::Fsp,
        }
    }

    pub(crate) fn protocol(self) -> PacketProtocol {
        self.protocol
    }

    pub(crate) fn node_addr(self) -> NodeAddr {
        self.node_addr
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

pub(crate) fn dataplane_fsp_message_is_application_data(msg_type: u8) -> bool {
    msg_type == crate::protocol::SessionMessageType::DataPacket.to_byte()
        || msg_type == crate::protocol::SessionMessageType::EndpointData.to_byte()
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

/// Authenticated FSP receive metadata produced by dataplane.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct FspReceiveSync {
    pub(crate) counter: u64,
    pub(crate) received_k_bit: bool,
    pub(crate) timestamp: u32,
    pub(crate) plaintext_len: usize,
    pub(crate) ce_flag: bool,
    pub(crate) path_mtu: u16,
    pub(crate) spin_bit: bool,
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub(crate) enum TransportPath {
    Live {
        transport_id: TransportId,
        remote_addr: TransportAddr,
    },
}

impl TransportPath {
    pub(crate) fn live(transport_id: TransportId, remote_addr: TransportAddr) -> Self {
        Self::Live {
            transport_id,
            remote_addr,
        }
    }

    pub(crate) fn transport_id(&self) -> Option<TransportId> {
        match self {
            Self::Live { transport_id, .. } => Some(*transport_id),
        }
    }

    pub(crate) fn remote_addr(&self) -> Option<&TransportAddr> {
        match self {
            Self::Live { remote_addr, .. } => Some(remote_addr),
        }
    }

}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub(crate) struct ActivityTick(u64);

impl ActivityTick {
    pub(crate) fn new(tick: u64) -> Self {
        Self(tick)
    }

    pub(crate) fn age_ms(self, now_ms: u64) -> u64 {
        now_ms.saturating_sub(self.0)
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
    path_mtu: u16,
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
enum OutboundPostSeal {
    Transport,
    FmpWrap(DataplaneFspWrapRoute),
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
    fsp_send_receipt: Option<DataplaneFspSendReceipt>,
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
            fsp_send_receipt: None,
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
            fsp_send_receipt: None,
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

    fn refresh_fsp_inner_flags(&mut self, refreshed_inner_flags: u8) {
        if let OutboundPayloadTransform::FspInnerHeader { inner_flags, .. } =
            &mut self.payload_transform
        {
            *inner_flags = refreshed_inner_flags;
        }
    }

    fn apply_fsp_owner_wrap_route(&mut self, route: DataplaneFspWrapRoute) {
        if self.owner.protocol() != PacketProtocol::Fsp
            || !matches!(self.post_seal, OutboundPostSeal::Transport)
        {
            return;
        }
        self.post_seal = OutboundPostSeal::FmpWrap(route);
    }

    pub(crate) fn with_fsp_cleartext_prefix(mut self, prefix: Vec<u8>) -> Self {
        self.fsp_cleartext_prefix = prefix;
        self
    }

    pub(crate) fn without_fsp_auto_coords_warmup(mut self) -> Self {
        self.fsp_auto_coords_warmup = false;
        self
    }

    fn with_fsp_send_receipt(mut self, receipt: DataplaneFspSendReceipt) -> Self {
        self.fsp_send_receipt = Some(receipt);
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

    fn fsp_next_hop(&self) -> Option<NodeAddr> {
        if self.owner.protocol() != PacketProtocol::Fsp {
            return None;
        }
        match self.post_seal {
            OutboundPostSeal::FmpWrap(route) => Some(route.next_hop_addr()),
            OutboundPostSeal::Transport => None,
        }
    }

    fn fsp_application_data_len(&self) -> Option<usize> {
        if self.owner.protocol() != PacketProtocol::Fsp {
            return None;
        }
        match self.payload_transform {
            OutboundPayloadTransform::FspInnerHeader { msg_type, .. } => {
                dataplane_fsp_message_is_application_data(msg_type)
                    .then_some(self.payload.len())
            }
            OutboundPayloadTransform::None => None,
        }
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
            path_mtu: u16::MAX,
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

    pub(crate) fn with_path_mtu(mut self, path_mtu: u16) -> Self {
        self.path_mtu = path_mtu;
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

}
