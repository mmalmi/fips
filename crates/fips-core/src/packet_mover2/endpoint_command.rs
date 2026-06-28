#[derive(Clone, Copy, Debug)]
pub(crate) struct PacketMover2EndpointCommandPayload<'a> {
    dest_addr: NodeAddr,
    dest_pubkey: secp256k1::PublicKey,
    lane: EndpointCommandLane,
    payload: &'a [u8],
}

impl<'a> PacketMover2EndpointCommandPayload<'a> {
    fn new(send: &'a EndpointDataSend) -> Self {
        Self {
            dest_addr: send.dest_addr(),
            dest_pubkey: send.dest_pubkey(),
            lane: send.payload().lane(),
            payload: send.payload().as_slice(),
        }
    }

    pub(crate) fn dest_addr(&self) -> NodeAddr {
        self.dest_addr
    }

    pub(crate) fn dest_pubkey(&self) -> secp256k1::PublicKey {
        self.dest_pubkey
    }

    pub(crate) fn lane(&self) -> EndpointCommandLane {
        self.lane
    }

    pub(crate) fn payload(&self) -> &'a [u8] {
        self.payload
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct PacketMover2EndpointRoutedDestination {
    dest_addr: NodeAddr,
    packets: usize,
    payload_bytes: usize,
    routed_at_ms: u64,
}

impl PacketMover2EndpointRoutedDestination {
    fn from_request(request: &PacketMover2EndpointCommandPayload<'_>, routed_at_ms: u64) -> Self {
        Self {
            dest_addr: request.dest_addr(),
            packets: 1,
            payload_bytes: request.payload().len(),
            routed_at_ms,
        }
    }

    fn merge(&mut self, other: Self) {
        debug_assert_eq!(self.dest_addr, other.dest_addr);
        self.packets = self.packets.saturating_add(other.packets);
        self.payload_bytes = self.payload_bytes.saturating_add(other.payload_bytes);
        self.routed_at_ms = self.routed_at_ms.max(other.routed_at_ms);
    }

    pub(crate) fn dest_addr(&self) -> NodeAddr {
        self.dest_addr
    }

    pub(crate) fn packets(&self) -> usize {
        self.packets
    }

    pub(crate) fn payload_bytes(&self) -> usize {
        self.payload_bytes
    }

    pub(crate) fn routed_at_ms(&self) -> u64 {
        self.routed_at_ms
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct PacketMover2EndpointCommandRoute {
    owner: OwnerId,
    generation: u64,
    flags: u8,
    inner_flags: u8,
    fsp_cleartext_prefix: Vec<u8>,
    post_seal: OutboundPostSeal,
    max_payload_len: Option<usize>,
}

impl PacketMover2EndpointCommandRoute {
    pub(crate) fn fsp(owner: OwnerId, generation: u64, flags: u8, inner_flags: u8) -> Self {
        Self {
            owner,
            generation,
            flags,
            inner_flags,
            fsp_cleartext_prefix: Vec::new(),
            post_seal: OutboundPostSeal::Transport,
            max_payload_len: None,
        }
    }

    pub(crate) fn with_fmp_wrap(mut self, route: PacketMover2FspWrapRoute) -> Self {
        self.post_seal = OutboundPostSeal::FmpWrap(route);
        self
    }

    pub(crate) fn with_fsp_cleartext_prefix(mut self, prefix: Vec<u8>) -> Self {
        self.fsp_cleartext_prefix = prefix;
        self
    }

    pub(crate) fn with_max_payload_len(mut self, max_payload_len: usize) -> Self {
        self.max_payload_len = Some(max_payload_len);
        self
    }

    fn owner(&self) -> OwnerId {
        self.owner
    }

    fn refresh_generation(&mut self, generation: u64) {
        self.generation = generation;
    }

    fn route_request(
        &self,
        request: PacketMover2EndpointCommandPayload<'_>,
    ) -> Result<OutboundPacket, PacketMover2EndpointCommandDropReason> {
        if self
            .max_payload_len
            .is_some_and(|max_payload_len| request.payload().len() > max_payload_len)
        {
            return Err(PacketMover2EndpointCommandDropReason::MtuExceeded);
        }
        let max_fsp_payload = u16::MAX as usize - crate::node::session_wire::FSP_INNER_HEADER_SIZE;
        if request.payload().len() > max_fsp_payload {
            return Err(PacketMover2EndpointCommandDropReason::InvalidPayload);
        }
        let packet = OutboundPacket::fsp(
            self.owner,
            self.generation,
            endpoint_packet_class(request.lane()),
            self.flags,
            request.payload().to_vec(),
        )
        .with_fsp_inner_header(
            crate::protocol::SessionMessageType::EndpointData.to_byte(),
            self.inner_flags,
        )
        .with_fsp_cleartext_prefix(self.fsp_cleartext_prefix.clone())
        .with_post_seal(self.post_seal);
        Ok(packet)
    }
}

fn endpoint_packet_class(lane: EndpointCommandLane) -> PacketClass {
    match lane {
        EndpointCommandLane::Priority => PacketClass::Control,
        EndpointCommandLane::Bulk => PacketClass::Bulk,
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PacketMover2EndpointCommandDropReason {
    InvalidPayload,
    NoRoute,
    NotEstablished,
    MtuExceeded,
    StaleGeneration,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct PacketMover2EndpointCommandDrop {
    dest_addr: NodeAddr,
    lane: EndpointCommandLane,
    payload_len: usize,
    reason: PacketMover2EndpointCommandDropReason,
}

impl PacketMover2EndpointCommandDrop {
    fn new(
        request: &PacketMover2EndpointCommandPayload<'_>,
        reason: PacketMover2EndpointCommandDropReason,
    ) -> Self {
        Self {
            dest_addr: request.dest_addr(),
            lane: request.lane(),
            payload_len: request.payload().len(),
            reason,
        }
    }

    pub(crate) fn dest_addr(&self) -> NodeAddr {
        self.dest_addr
    }

    pub(crate) fn lane(&self) -> EndpointCommandLane {
        self.lane
    }

    pub(crate) fn payload_len(&self) -> usize {
        self.payload_len
    }

    pub(crate) fn reason(&self) -> PacketMover2EndpointCommandDropReason {
        self.reason
    }
}

pub(crate) trait PacketMover2EndpointCommandRouter {
    fn route_endpoint_command_payload(
        &mut self,
        request: PacketMover2EndpointCommandPayload<'_>,
    ) -> Result<OutboundPacket, PacketMover2EndpointCommandDropReason>;
}

impl<F> PacketMover2EndpointCommandRouter for F
where
    F: for<'a> FnMut(
        PacketMover2EndpointCommandPayload<'a>,
    ) -> Result<OutboundPacket, PacketMover2EndpointCommandDropReason>,
{
    fn route_endpoint_command_payload(
        &mut self,
        request: PacketMover2EndpointCommandPayload<'_>,
    ) -> Result<OutboundPacket, PacketMover2EndpointCommandDropReason> {
        self(request)
    }
}

fn route_endpoint_send_with_router<R, F>(
    send: &EndpointDataSend,
    router: &mut R,
    mut push: F,
) -> Result<PacketMover2EndpointRoutedDestination, PacketMover2EndpointCommandDropReason>
where
    R: PacketMover2EndpointCommandRouter,
    F: FnMut(OutboundPacket),
{
    let request = PacketMover2EndpointCommandPayload::new(&send);
    let routed_at_ms = crate::time::now_ms();
    let routed = PacketMover2EndpointRoutedDestination::from_request(&request, routed_at_ms);
    match router.route_endpoint_command_payload(request) {
        Ok(packet) => {
            push(packet.with_activity_tick(ActivityTick::new(routed_at_ms)));
            Ok(routed)
        }
        Err(reason) => Err(reason),
    }
}

fn push_endpoint_command_drop(
    send: &EndpointDataSend,
    reason: PacketMover2EndpointCommandDropReason,
    drops: &mut Vec<PacketMover2EndpointCommandDrop>,
) {
    let request = PacketMover2EndpointCommandPayload::new(send);
    drops.push(PacketMover2EndpointCommandDrop::new(&request, reason));
}

fn route_endpoint_command_with_router<R, F>(
    command: NodeEndpointCommand,
    router: &mut R,
    drops: &mut Vec<PacketMover2EndpointCommandDrop>,
    deferred_commands: &mut Vec<NodeEndpointCommand>,
    routed_destinations: &mut Vec<PacketMover2EndpointRoutedDestination>,
    mut push: F,
) where
    R: PacketMover2EndpointCommandRouter,
    F: FnMut(OutboundPacket),
{
    match command {
        NodeEndpointCommand::Send {
            command,
            response_tx,
        } => {
            let dest_addr = command.data_send().dest_addr();
            match route_endpoint_send_with_router(command.data_send(), router, &mut push) {
                Ok(routed) => {
                    routed_destinations.push(routed);
                    let _ = response_tx.send(Ok(()));
                }
                Err(PacketMover2EndpointCommandDropReason::NoRoute) => {
                    deferred_commands.push(NodeEndpointCommand::Send {
                        command,
                        response_tx,
                    });
                }
                Err(reason) => {
                    push_endpoint_command_drop(command.data_send(), reason, drops);
                    let _ = response_tx.send(Err(NodeError::SendFailed {
                        node_addr: dest_addr,
                        reason: format!("packet_mover2 endpoint route drop: {reason:?}"),
                    }));
                }
            }
        }
        NodeEndpointCommand::SendOneway { command } => {
            match route_endpoint_send_with_router(command.data_send(), router, &mut push) {
                Ok(routed) => {
                    routed_destinations.push(routed);
                }
                Err(PacketMover2EndpointCommandDropReason::NoRoute) => {
                    deferred_commands.push(NodeEndpointCommand::SendOneway { command });
                }
                Err(reason) => {
                    push_endpoint_command_drop(command.data_send(), reason, drops);
                }
            }
        }
        NodeEndpointCommand::SendBatchOneway { command, lane } => {
            let (remote, payloads, queued_at) = command.into_parts();
            let mut any_routed = false;
            let mut routed_destination: Option<PacketMover2EndpointRoutedDestination> = None;
            let mut defer_unrouted = false;
            for payload in &payloads {
                let send = EndpointDataSend::new(remote, payload.clone());
                match route_endpoint_send_with_router(&send, router, &mut push) {
                    Ok(routed) => {
                        any_routed = true;
                        match &mut routed_destination {
                            Some(summary) => summary.merge(routed),
                            None => routed_destination = Some(routed),
                        }
                    }
                    Err(PacketMover2EndpointCommandDropReason::NoRoute) if !any_routed => {
                        defer_unrouted = true;
                        break;
                    }
                    Err(reason) => {
                        push_endpoint_command_drop(&send, reason, drops);
                    }
                }
            }
            if defer_unrouted {
                let command = EndpointSendBatchCommand::new(remote, payloads, queued_at)
                    .expect("deferred endpoint batch should remain non-empty");
                deferred_commands.push(NodeEndpointCommand::SendBatchOneway { command, lane });
            } else if let Some(routed) = routed_destination {
                routed_destinations.push(routed);
            }
        }
        other => deferred_commands.push(other),
    }
}
