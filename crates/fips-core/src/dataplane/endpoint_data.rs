#[derive(Debug, Default)]
pub(crate) struct DataplaneEndpointDataBatchRoute {
    routed: Vec<OutboundPacket>,
    dropped: Vec<(usize, DataplaneEndpointDataDropReason)>,
    deferred_payloads: Option<Vec<EndpointDataPayload>>,
}

impl DataplaneEndpointDataBatchRoute {
    fn with_capacity(capacity: usize) -> Self {
        Self {
            routed: Vec::with_capacity(capacity),
            ..Default::default()
        }
    }

    fn deferred(payloads: Vec<EndpointDataPayload>) -> Self {
        Self {
            deferred_payloads: (!payloads.is_empty()).then_some(payloads),
            ..Default::default()
        }
    }

    fn finish_batch<F>(
        self,
        remote: PeerIdentity,
        drops: &mut Vec<DataplaneEndpointDataDrop>,
        mut push: F,
    ) -> Option<Vec<EndpointDataPayload>>
    where
        F: FnMut(Vec<OutboundPacket>),
    {
        if !self.routed.is_empty() {
            push(self.routed);
        }
        for (payload_len, reason) in self.dropped {
            push_endpoint_data_drop(remote, payload_len, reason, drops);
        }
        self.deferred_payloads
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct DataplaneEndpointDataRoute {
    owner: OwnerId,
    generation: u64,
    flags: u8,
    inner_flags: u8,
    fsp_cleartext_prefix: Vec<u8>,
    fsp_auto_coords_warmup: bool,
}

impl DataplaneEndpointDataRoute {
    pub(crate) fn fsp(owner: OwnerId, generation: u64, flags: u8, inner_flags: u8) -> Self {
        Self {
            owner,
            generation,
            flags,
            inner_flags,
            fsp_cleartext_prefix: Vec::new(),
            fsp_auto_coords_warmup: true,
        }
    }

    pub(crate) fn with_fsp_cleartext_prefix(mut self, prefix: Vec<u8>) -> Self {
        self.fsp_cleartext_prefix = prefix;
        self
    }

    pub(crate) fn with_direct_transport(mut self) -> Self {
        self.fsp_auto_coords_warmup = false;
        self
    }

    #[cfg(test)]
    fn route_batch(&self, payloads: Vec<Vec<u8>>) -> DataplaneEndpointDataBatchRoute {
        let mut routed_payloads = Vec::new();
        let mut dropped = Vec::new();
        for payload in payloads {
            let payload_len = payload.len();
            match EndpointDataPayload::from_packet_payload(payload) {
                Some(payload) => routed_payloads.push(payload),
                None => dropped.push((payload_len, DataplaneEndpointDataDropReason::InvalidPayload)),
            }
        }
        let mut result = self.route_payloads(routed_payloads);
        result.dropped.extend(dropped);
        result
    }

    fn owner(&self) -> OwnerId {
        self.owner
    }

    fn route_payloads(
        &self,
        payloads: Vec<EndpointDataPayload>,
    ) -> DataplaneEndpointDataBatchRoute {
        let mut result = DataplaneEndpointDataBatchRoute::with_capacity(payloads.len());
        let routed_at_ms = crate::time::now_ms();
        let max_fsp_payload = self.max_fsp_body_len();
        for payload in payloads {
            let payload_len = payload.body_len();
            if payload_len > max_fsp_payload {
                result
                    .dropped
                    .push((payload_len, DataplaneEndpointDataDropReason::InvalidPayload));
                continue;
            }
            result.routed.push(
                self.build_packet(
                    crate::protocol::SessionMessageType::EndpointData.to_byte(),
                    payload.into_body(),
                )
                .with_activity_tick(ActivityTick::new(routed_at_ms)),
            );
        }
        result
    }

    fn max_fsp_body_len(&self) -> usize {
        crate::node::session_wire::fsp_endpoint_data_max_body_len()
    }

    fn build_packet(
        &self,
        msg_type: u8,
        payload: crate::transport::PacketBuffer,
    ) -> OutboundPacket {
        let mut packet = OutboundPacket::fsp(
            self.owner,
            self.generation,
            PacketClass::Bulk,
            self.flags,
            payload,
        )
        .with_fsp_inner_header(msg_type, self.inner_flags)
        .with_fsp_cleartext_prefix(self.fsp_cleartext_prefix.clone());
        if !self.fsp_auto_coords_warmup {
            packet = packet.without_fsp_auto_coords_warmup();
        }
        packet
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DataplaneEndpointDataDropReason {
    InvalidPayload,
    NoRoute,
    StaleQueuedBatch,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct DataplaneEndpointDataDrop {
    dest_addr: NodeAddr,
    payload_len: usize,
    reason: DataplaneEndpointDataDropReason,
}

impl DataplaneEndpointDataDrop {
    fn new(
        dest_addr: NodeAddr,
        payload_len: usize,
        reason: DataplaneEndpointDataDropReason,
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

    pub(crate) fn reason(&self) -> DataplaneEndpointDataDropReason {
        self.reason
    }
}

pub(crate) trait DataplaneEndpointDataRouter {
    fn route_endpoint_data_batch(
        &mut self,
        remote: PeerIdentity,
        payloads: Vec<EndpointDataPayload>,
    ) -> DataplaneEndpointDataBatchRoute;
}

fn push_endpoint_data_drop(
    remote: PeerIdentity,
    payload_len: usize,
    reason: DataplaneEndpointDataDropReason,
    drops: &mut Vec<DataplaneEndpointDataDrop>,
) {
    drops.push(DataplaneEndpointDataDrop::new(
        *remote.node_addr(),
        payload_len,
        reason,
    ));
}

fn route_endpoint_data_batch_with_router<R, F>(
    batch: NodeEndpointDataBatch,
    router: &mut R,
    drops: &mut Vec<DataplaneEndpointDataDrop>,
    deferred_batches: &mut Vec<NodeEndpointDataBatch>,
    mut push: F,
) where
    R: DataplaneEndpointDataRouter,
    F: FnMut(Vec<OutboundPacket>),
{
    let (remote, payloads, queued_at, enqueued_at_ms) = batch.into_parts();
    let route = router.route_endpoint_data_batch(remote, payloads);
    let deferred_payloads = route.finish_batch(remote, drops, &mut push);
    if let Some(payloads) = deferred_payloads {
        let batch = NodeEndpointDataBatch::batch_with_enqueued_at_ms(
            remote,
            payloads
                .into_iter()
                .map(|payload| payload.into_body().into_vec())
                .collect(),
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
    drops: &mut Vec<DataplaneEndpointDataDrop>,
) {
    let (remote, payloads, _, _) = batch.into_parts();
    for payload in payloads {
        push_endpoint_data_drop(
            remote,
            payload.body_len(),
            DataplaneEndpointDataDropReason::StaleQueuedBatch,
            drops,
        );
    }
}
