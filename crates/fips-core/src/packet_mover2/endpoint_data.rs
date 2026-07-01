#[derive(Debug, Default)]
pub(crate) struct PacketMover2EndpointDataBatchRoute {
    routed: Vec<OutboundPacket>,
    dropped: Vec<(PeerIdentity, Vec<u8>, PacketMover2EndpointDataDropReason)>,
    deferred_payloads: Option<Vec<Vec<u8>>>,
}

impl PacketMover2EndpointDataBatchRoute {
    fn routed_mut(&mut self) -> &mut Vec<OutboundPacket> {
        &mut self.routed
    }

    fn dropped_mut(
        &mut self,
    ) -> &mut Vec<(PeerIdentity, Vec<u8>, PacketMover2EndpointDataDropReason)> {
        &mut self.dropped
    }

    fn set_deferred_payloads(&mut self, payloads: Vec<Vec<u8>>) {
        if !payloads.is_empty() {
            self.deferred_payloads = Some(payloads);
        }
    }

    fn finish_batch<F>(
        self,
        drops: &mut Vec<PacketMover2EndpointDataDrop>,
        mut push: F,
    ) -> Option<Vec<Vec<u8>>>
    where
        F: FnMut(Vec<OutboundPacket>),
    {
        if !self.routed.is_empty() {
            push(self.routed);
        }
        for (remote, payload, reason) in self.dropped {
            push_endpoint_data_drop(remote, payload.len(), reason, drops);
        }
        self.deferred_payloads
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct PacketMover2EndpointDataRoute {
    owner: OwnerId,
    generation: u64,
    flags: u8,
    inner_flags: u8,
    fsp_cleartext_prefix: Vec<u8>,
}

impl PacketMover2EndpointDataRoute {
    pub(crate) fn fsp(owner: OwnerId, generation: u64, flags: u8, inner_flags: u8) -> Self {
        Self {
            owner,
            generation,
            flags,
            inner_flags,
            fsp_cleartext_prefix: Vec::new(),
        }
    }

    pub(crate) fn with_fsp_cleartext_prefix(mut self, prefix: Vec<u8>) -> Self {
        self.fsp_cleartext_prefix = prefix;
        self
    }

    fn owner(&self) -> OwnerId {
        self.owner
    }

    fn refresh_generation(&mut self, generation: u64) {
        self.generation = generation;
    }

    fn route_batch<I>(
        &self,
        remote: PeerIdentity,
        payloads: I,
    ) -> PacketMover2EndpointDataBatchRoute
    where
        I: IntoIterator<Item = Vec<u8>>,
    {
        let mut result = PacketMover2EndpointDataBatchRoute::default();
        let routed_at_ms = crate::time::now_ms();
        for payload in payloads {
            if let Err(reason) = self.validate_payload_len(payload.len()) {
                result.dropped_mut().push((remote, payload, reason));
                continue;
            }
            result.routed_mut().push(
                self.build_bulk_packet(payload)
                    .with_activity_tick(ActivityTick::new(routed_at_ms)),
            );
        }
        result
    }

    fn validate_payload_len(
        &self,
        payload_len: usize,
    ) -> Result<(), PacketMover2EndpointDataDropReason> {
        let max_fsp_payload = u16::MAX as usize - crate::node::session_wire::FSP_INNER_HEADER_SIZE;
        if payload_len > max_fsp_payload {
            return Err(PacketMover2EndpointDataDropReason::InvalidPayload);
        }
        Ok(())
    }

    fn build_bulk_packet(&self, payload: Vec<u8>) -> OutboundPacket {
        OutboundPacket::fsp(
            self.owner,
            self.generation,
            PacketClass::Bulk,
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PacketMover2EndpointDataDropReason {
    InvalidPayload,
    NoRoute,
    StaleQueuedBatch,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct PacketMover2EndpointDataDrop {
    dest_addr: NodeAddr,
    payload_len: usize,
    reason: PacketMover2EndpointDataDropReason,
}

impl PacketMover2EndpointDataDrop {
    fn new(
        dest_addr: NodeAddr,
        payload_len: usize,
        reason: PacketMover2EndpointDataDropReason,
    ) -> Self {
        Self {
            dest_addr,
            payload_len,
            reason,
        }
    }

    pub(crate) fn dest_addr(&self) -> NodeAddr {
        self.dest_addr
    }

    pub(crate) fn payload_len(&self) -> usize {
        self.payload_len
    }

    pub(crate) fn reason(&self) -> PacketMover2EndpointDataDropReason {
        self.reason
    }
}

pub(crate) trait PacketMover2EndpointDataRouter {
    fn route_endpoint_data_batch(
        &mut self,
        remote: PeerIdentity,
        payloads: Vec<Vec<u8>>,
    ) -> PacketMover2EndpointDataBatchRoute;
}

fn push_endpoint_data_drop(
    remote: PeerIdentity,
    payload_len: usize,
    reason: PacketMover2EndpointDataDropReason,
    drops: &mut Vec<PacketMover2EndpointDataDrop>,
) {
    drops.push(PacketMover2EndpointDataDrop::new(
        *remote.node_addr(),
        payload_len,
        reason,
    ));
}

fn route_endpoint_data_batch_with_router<R, F>(
    batch: NodeEndpointDataBatch,
    router: &mut R,
    drops: &mut Vec<PacketMover2EndpointDataDrop>,
    deferred_batches: &mut Vec<NodeEndpointDataBatch>,
    mut push: F,
) where
    R: PacketMover2EndpointDataRouter,
    F: FnMut(Vec<OutboundPacket>),
{
    let (remote, payloads, queued_at, enqueued_at_ms) = batch.into_parts();
    let route = router.route_endpoint_data_batch(remote, payloads);
    let deferred_payloads = route.finish_batch(drops, &mut push);
    if let Some(payloads) = deferred_payloads {
        let batch = NodeEndpointDataBatch::batch_with_enqueued_at_ms(
            remote,
            payloads,
            queued_at,
            enqueued_at_ms,
        )
        .expect("deferred endpoint batch should remain non-empty");
        deferred_batches.push(batch);
    }
}

fn stale_endpoint_data_drop_count(
    batch: &NodeEndpointDataBatch,
    now_ms: u64,
    max_age_ms: u64,
) -> usize {
    if max_age_ms > 0 && now_ms.saturating_sub(batch.enqueued_at_ms()) > max_age_ms {
        batch.packet_count()
    } else {
        0
    }
}

fn drop_stale_endpoint_data_batch(
    batch: NodeEndpointDataBatch,
    drops: &mut Vec<PacketMover2EndpointDataDrop>,
) {
    let (remote, payloads, _, _) = batch.into_parts();
    for payload in payloads {
        push_endpoint_data_drop(
            remote,
            payload.len(),
            PacketMover2EndpointDataDropReason::StaleQueuedBatch,
            drops,
        );
    }
}
