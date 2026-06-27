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

pub(crate) struct PacketMover2EndpointCommandSource<'a, R> {
    priority_rx: &'a mut tokio::sync::mpsc::Receiver<NodeEndpointCommand>,
    bulk_rx: &'a mut tokio::sync::mpsc::Receiver<NodeEndpointCommand>,
    router: &'a mut R,
    drops: Vec<PacketMover2EndpointCommandDrop>,
    deferred_commands: Vec<NodeEndpointCommand>,
}

impl<'a, R> PacketMover2EndpointCommandSource<'a, R> {
    pub(crate) fn new(
        priority_rx: &'a mut tokio::sync::mpsc::Receiver<NodeEndpointCommand>,
        bulk_rx: &'a mut tokio::sync::mpsc::Receiver<NodeEndpointCommand>,
        router: &'a mut R,
    ) -> Self {
        Self {
            priority_rx,
            bulk_rx,
            router,
            drops: Vec::new(),
            deferred_commands: Vec::new(),
        }
    }

    pub(crate) fn drops(&self) -> &[PacketMover2EndpointCommandDrop] {
        &self.drops
    }

    fn take_drops(&mut self) -> Vec<PacketMover2EndpointCommandDrop> {
        std::mem::take(&mut self.drops)
    }

    pub(crate) fn deferred_commands(&self) -> &[NodeEndpointCommand] {
        &self.deferred_commands
    }

    fn take_deferred_commands(&mut self) -> Vec<NodeEndpointCommand> {
        std::mem::take(&mut self.deferred_commands)
    }
}

impl<R> PacketMover2EndpointCommandSource<'_, R>
where
    R: PacketMover2EndpointCommandRouter,
{
    fn route_send<F>(
        &mut self,
        send: EndpointDataSend,
        mut push: F,
    ) -> Result<(), PacketMover2EndpointCommandDropReason>
    where
        F: FnMut(OutboundPacket),
    {
        let request = PacketMover2EndpointCommandPayload::new(&send);
        match self.router.route_endpoint_command_payload(request) {
            Ok(packet) => {
                push(packet);
                Ok(())
            }
            Err(reason) => {
                self.drops
                    .push(PacketMover2EndpointCommandDrop::new(&request, reason));
                Err(reason)
            }
        }
    }

    fn route_command<F>(&mut self, command: NodeEndpointCommand, mut push: F)
    where
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
                    self.route_send(send, &mut push)
                        .map_err(|reason| NodeError::SendFailed {
                            node_addr: dest_addr,
                            reason: format!("packet_mover2 endpoint route drop: {reason:?}"),
                        });
                let _ = response_tx.send(result);
            }
            NodeEndpointCommand::SendOneway { command } => {
                let (send, queued_at) = command.into_parts();
                let _ = queued_at;
                let _ = self.route_send(send, &mut push);
            }
            NodeEndpointCommand::SendBatchOneway { command, lane } => {
                let (remote, payloads, queued_at) = command.into_parts();
                let _ = (lane, queued_at);
                for payload in payloads {
                    let _ = self.route_send(EndpointDataSend::new(remote, payload), &mut push);
                }
            }
            other => self.deferred_commands.push(other),
        }
    }
}

impl<R> PacketMover2OutboundSource for PacketMover2EndpointCommandSource<'_, R>
where
    R: PacketMover2EndpointCommandRouter,
{
    fn drain_outbound<F>(&mut self, limit: usize, mut push: F) -> usize
    where
        F: FnMut(OutboundPacket),
    {
        let mut drained_cost = 0usize;
        while drained_cost < limit {
            let Ok(command) = self.priority_rx.try_recv() else {
                break;
            };
            drained_cost = drained_cost.saturating_add(command.drain_cost());
            self.route_command(command, &mut push);
        }
        while drained_cost < limit {
            let Ok(command) = self.bulk_rx.try_recv() else {
                break;
            };
            drained_cost = drained_cost.saturating_add(command.drain_cost());
            self.route_command(command, &mut push);
        }
        drained_cost
    }
}
