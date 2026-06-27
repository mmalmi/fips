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

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct PacketMover2EndpointCommandRoute {
    owner: OwnerId,
    generation: u64,
    flags: u8,
    timestamp_ms: u32,
    inner_flags: u8,
    max_payload_len: Option<usize>,
}

impl PacketMover2EndpointCommandRoute {
    pub(crate) fn fsp(
        owner: OwnerId,
        generation: u64,
        flags: u8,
        timestamp_ms: u32,
        inner_flags: u8,
    ) -> Self {
        Self {
            owner,
            generation,
            flags,
            timestamp_ms,
            inner_flags,
            max_payload_len: None,
        }
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
        let inner_plaintext = crate::node::session_wire::fsp_prepend_inner_header(
            self.timestamp_ms,
            crate::protocol::SessionMessageType::EndpointData.to_byte(),
            self.inner_flags,
            request.payload(),
        );
        Ok(OutboundPacket::fsp(
            self.owner,
            self.generation,
            endpoint_packet_class(request.lane()),
            self.flags,
            inner_plaintext,
        ))
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
    send: EndpointDataSend,
    router: &mut R,
    drops: &mut Vec<PacketMover2EndpointCommandDrop>,
    mut push: F,
) -> Result<(), PacketMover2EndpointCommandDropReason>
where
    R: PacketMover2EndpointCommandRouter,
    F: FnMut(OutboundPacket),
{
    let request = PacketMover2EndpointCommandPayload::new(&send);
    match router.route_endpoint_command_payload(request) {
        Ok(packet) => {
            push(packet);
            Ok(())
        }
        Err(reason) => {
            drops.push(PacketMover2EndpointCommandDrop::new(&request, reason));
            Err(reason)
        }
    }
}

fn route_endpoint_command_with_router<R, F>(
    command: NodeEndpointCommand,
    router: &mut R,
    drops: &mut Vec<PacketMover2EndpointCommandDrop>,
    deferred_commands: &mut Vec<NodeEndpointCommand>,
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
            let (send, queued_at) = command.into_parts();
            let _ = queued_at;
            let dest_addr = send.dest_addr();
            let result =
                route_endpoint_send_with_router(send, router, drops, &mut push).map_err(
                    |reason| NodeError::SendFailed {
                        node_addr: dest_addr,
                        reason: format!("packet_mover2 endpoint route drop: {reason:?}"),
                    },
                );
            let _ = response_tx.send(result);
        }
        NodeEndpointCommand::SendOneway { command } => {
            let (send, queued_at) = command.into_parts();
            let _ = queued_at;
            let _ = route_endpoint_send_with_router(send, router, drops, &mut push);
        }
        NodeEndpointCommand::SendBatchOneway { command, lane } => {
            let (remote, payloads, queued_at) = command.into_parts();
            let _ = (lane, queued_at);
            for payload in payloads {
                let _ = route_endpoint_send_with_router(
                    EndpointDataSend::new(remote, payload),
                    router,
                    drops,
                    &mut push,
                );
            }
        }
        other => deferred_commands.push(other),
    }
}
