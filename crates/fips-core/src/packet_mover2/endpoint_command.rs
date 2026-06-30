#[derive(Clone, Copy, Debug)]
pub(crate) struct PacketMover2EndpointCommandPayload<'a> {
    dest_addr: NodeAddr,
    dest_pubkey: secp256k1::PublicKey,
    lane: EndpointCommandLane,
    drop_on_backpressure: bool,
    payload: &'a [u8],
}

impl<'a> PacketMover2EndpointCommandPayload<'a> {
    fn new(send: &'a EndpointDataSend) -> Self {
        Self {
            dest_addr: send.dest_addr(),
            dest_pubkey: send.dest_pubkey(),
            lane: send.payload().lane(),
            drop_on_backpressure: send.payload().drop_on_backpressure(),
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

    fn packet_class(&self) -> PacketClass {
        endpoint_packet_class(self.lane, self.drop_on_backpressure)
    }
}

#[derive(Debug)]
pub(crate) struct PacketMover2EndpointCommandOwnedPayload {
    send: EndpointDataSend,
}

impl PacketMover2EndpointCommandOwnedPayload {
    fn new(send: EndpointDataSend) -> Self {
        Self { send }
    }

    fn as_borrowed(&self) -> PacketMover2EndpointCommandPayload<'_> {
        PacketMover2EndpointCommandPayload::new(&self.send)
    }

    fn dest_addr(&self) -> NodeAddr {
        self.send.dest_addr()
    }

    fn lane(&self) -> EndpointCommandLane {
        self.send.payload().lane()
    }

    fn packet_class(&self) -> PacketClass {
        endpoint_packet_class(
            self.send.payload().lane(),
            self.send.payload().drop_on_backpressure(),
        )
    }

    fn payload_len(&self) -> usize {
        self.send.payload().len()
    }

    fn into_payload_bytes(self) -> Vec<u8> {
        self.send.into_payload().into_bytes()
    }

    fn into_send(self) -> EndpointDataSend {
        self.send
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct PacketMover2EndpointCommandRoute {
    owner: OwnerId,
    generation: u64,
    flags: u8,
    inner_flags: u8,
    fsp_cleartext_prefix: Vec<u8>,
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
            max_payload_len: None,
        }
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
        self.validate_payload_len(request.payload().len())?;
        Ok(self.build_packet(request.packet_class(), request.payload().to_vec()))
    }

    fn route_owned_request(
        &self,
        request: PacketMover2EndpointCommandOwnedPayload,
    ) -> Result<OutboundPacket, (PacketMover2EndpointCommandOwnedPayload, PacketMover2EndpointCommandDropReason)>
    {
        if let Err(reason) = self.validate_payload_len(request.payload_len()) {
            return Err((request, reason));
        }
        let class = request.packet_class();
        Ok(self.build_packet(class, request.into_payload_bytes()))
    }

    fn validate_payload_len(
        &self,
        payload_len: usize,
    ) -> Result<(), PacketMover2EndpointCommandDropReason> {
        if self
            .max_payload_len
            .is_some_and(|max_payload_len| payload_len > max_payload_len)
        {
            return Err(PacketMover2EndpointCommandDropReason::MtuExceeded);
        }
        let max_fsp_payload = u16::MAX as usize - crate::node::session_wire::FSP_INNER_HEADER_SIZE;
        if payload_len > max_fsp_payload {
            return Err(PacketMover2EndpointCommandDropReason::InvalidPayload);
        }
        Ok(())
    }

    fn build_packet(&self, class: PacketClass, payload: Vec<u8>) -> OutboundPacket {
        OutboundPacket::fsp(
            self.owner,
            self.generation,
            class,
            self.flags,
            payload,
        )
        .with_fsp_inner_header(
            crate::protocol::SessionMessageType::EndpointData.to_byte(),
            self.inner_flags,
        )
        .with_fsp_cleartext_prefix(self.fsp_cleartext_prefix.clone())
    }
}

fn endpoint_packet_class(lane: EndpointCommandLane, drop_on_backpressure: bool) -> PacketClass {
    match lane {
        EndpointCommandLane::Priority => PacketClass::Control,
        EndpointCommandLane::Bulk if drop_on_backpressure => PacketClass::Bulk,
        EndpointCommandLane::Bulk => PacketClass::ReliableBulk,
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PacketMover2EndpointCommandDropReason {
    InvalidPayload,
    NoRoute,
    NotEstablished,
    MtuExceeded,
    StaleGeneration,
    StaleQueuedBulk,
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

    fn route_endpoint_command_owned_payload(
        &mut self,
        request: PacketMover2EndpointCommandOwnedPayload,
    ) -> Result<
        OutboundPacket,
        (
            PacketMover2EndpointCommandOwnedPayload,
            PacketMover2EndpointCommandDropReason,
        ),
    > {
        let result = {
            let borrowed = request.as_borrowed();
            self.route_endpoint_command_payload(borrowed)
        };
        match result {
            Ok(packet) => Ok(packet),
            Err(reason) => Err((request, reason)),
        }
    }
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

fn route_endpoint_send_with_router_owned<R, F>(
    send: EndpointDataSend,
    router: &mut R,
    mut push: F,
) -> Result<(), (EndpointDataSend, PacketMover2EndpointCommandDropReason)>
where
    R: PacketMover2EndpointCommandRouter,
    F: FnMut(OutboundPacket),
{
    let request = PacketMover2EndpointCommandOwnedPayload::new(send);
    let routed_at_ms = crate::time::now_ms();
    match router.route_endpoint_command_owned_payload(request) {
        Ok(packet) => {
            push(packet.with_activity_tick(ActivityTick::new(routed_at_ms)));
            Ok(())
        }
        Err((request, reason)) => Err((request.into_send(), reason)),
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
            let (send, queued_at, enqueued_at_ms) = command.into_deferred_parts();
            let dest_addr = send.dest_addr();
            match route_endpoint_send_with_router_owned(send, router, &mut push) {
                Ok(()) => {
                    let _ = response_tx.send(Ok(()));
                }
                Err((send, PacketMover2EndpointCommandDropReason::NoRoute)) => {
                    let command = EndpointSendCommand::from_send_with_enqueued_at_ms(
                        send,
                        queued_at,
                        enqueued_at_ms,
                    );
                    deferred_commands.push(NodeEndpointCommand::Send {
                        command,
                        response_tx,
                    });
                }
                Err((send, reason)) => {
                    push_endpoint_command_drop(&send, reason, drops);
                    let _ = response_tx.send(Err(NodeError::SendFailed {
                        node_addr: dest_addr,
                        reason: format!("packet_mover2 endpoint route drop: {reason:?}"),
                    }));
                }
            }
        }
        NodeEndpointCommand::SendOneway { command } => {
            let (send, queued_at, enqueued_at_ms) = command.into_deferred_parts();
            match route_endpoint_send_with_router_owned(send, router, &mut push) {
                Ok(()) => {}
                Err((send, PacketMover2EndpointCommandDropReason::NoRoute)) => {
                    let command = EndpointSendCommand::from_send_with_enqueued_at_ms(
                        send,
                        queued_at,
                        enqueued_at_ms,
                    );
                    deferred_commands.push(NodeEndpointCommand::SendOneway { command });
                }
                Err((send, reason)) => {
                    push_endpoint_command_drop(&send, reason, drops);
                }
            }
        }
        NodeEndpointCommand::SendBatchOneway { command, lane } => {
            let (remote, payloads, queued_at, enqueued_at_ms) = command.into_deferred_parts();
            let mut any_routed = false;
            let mut deferred_payloads = None;
            let mut payloads = payloads.into_iter();
            while let Some(payload) = payloads.next() {
                let send = EndpointDataSend::new(remote, payload);
                match route_endpoint_send_with_router_owned(send, router, &mut push) {
                    Ok(()) => {
                        any_routed = true;
                    }
                    Err((send, PacketMover2EndpointCommandDropReason::NoRoute))
                        if !any_routed =>
                    {
                        let mut remaining =
                            Vec::with_capacity(payloads.size_hint().0.saturating_add(1));
                        remaining.push(send.into_payload());
                        remaining.extend(payloads);
                        deferred_payloads = Some(remaining);
                        break;
                    }
                    Err((send, reason)) => {
                        push_endpoint_command_drop(&send, reason, drops);
                    }
                }
            }
            if let Some(payloads) = deferred_payloads {
                let command = EndpointSendBatchCommand::new_with_enqueued_at_ms(
                    remote,
                    payloads,
                    queued_at,
                    enqueued_at_ms,
                )
                    .expect("deferred endpoint batch should remain non-empty");
                deferred_commands.push(NodeEndpointCommand::SendBatchOneway { command, lane });
            }
        }
        other => deferred_commands.push(other),
    }
}

fn stale_bulk_endpoint_command_drop_count(
    command: &NodeEndpointCommand,
    now_ms: u64,
    max_age_ms: u64,
) -> usize {
    match command {
        NodeEndpointCommand::SendOneway { command }
            if command.lane() == EndpointCommandLane::Bulk
                && command.stale_at(now_ms, max_age_ms) =>
        {
            1
        }
        NodeEndpointCommand::SendBatchOneway { command, lane }
            if *lane == EndpointCommandLane::Bulk && command.stale_at(now_ms, max_age_ms) =>
        {
            command.len()
        }
        _ => 0,
    }
}

fn drop_stale_bulk_endpoint_command(
    command: NodeEndpointCommand,
    drops: &mut Vec<PacketMover2EndpointCommandDrop>,
) {
    match command {
        NodeEndpointCommand::SendOneway { command } => {
            push_endpoint_command_drop(
                command.data_send(),
                PacketMover2EndpointCommandDropReason::StaleQueuedBulk,
                drops,
            );
        }
        NodeEndpointCommand::SendBatchOneway { command, .. } => {
            let (remote, payloads, _) = command.into_parts();
            for payload in payloads {
                let send = EndpointDataSend::new(remote, payload);
                push_endpoint_command_drop(
                    &send,
                    PacketMover2EndpointCommandDropReason::StaleQueuedBulk,
                    drops,
                );
            }
        }
        _ => {}
    }
}
