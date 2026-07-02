#[derive(Debug, Default)]
pub(crate) struct PacketMover2EndpointDataBatchRoute {
    routed: Vec<OutboundPacket>,
    dropped: Vec<(usize, PacketMover2EndpointDataDropReason)>,
    deferred_payloads: Option<Vec<Vec<u8>>>,
}

impl PacketMover2EndpointDataBatchRoute {
    fn with_capacity(capacity: usize) -> Self {
        Self {
            routed: Vec::with_capacity(capacity),
            ..Default::default()
        }
    }

    fn deferred(payloads: Vec<Vec<u8>>) -> Self {
        Self {
            deferred_payloads: (!payloads.is_empty()).then_some(payloads),
            ..Default::default()
        }
    }

    fn finish_batch<F>(
        self,
        remote: PeerIdentity,
        drops: &mut Vec<PacketMover2EndpointDataDrop>,
        mut push: F,
    ) -> Option<Vec<Vec<u8>>>
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
pub(crate) struct PacketMover2EndpointDataRoute {
    owner: OwnerId,
    generation: u64,
    flags: u8,
    inner_flags: u8,
    fsp_cleartext_prefix: Vec<u8>,
    fsp_auto_coords_warmup: bool,
}

impl PacketMover2EndpointDataRoute {
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

    fn owner(&self) -> OwnerId {
        self.owner
    }

    fn route_batch(&self, payloads: Vec<Vec<u8>>) -> PacketMover2EndpointDataBatchRoute {
        let mut result = PacketMover2EndpointDataBatchRoute::with_capacity(payloads.len());
        let routed_at_ms = crate::time::now_ms();
        let max_fsp_payload = self.max_fsp_bulk_body_len();
        let mut bulk_payloads = Vec::new();
        let mut bulk_wire_len = crate::node::session_wire::fsp_endpoint_data_bulk_base_wire_len();
        for payload in payloads {
            let Some(packet_wire_len) =
                crate::node::session_wire::fsp_endpoint_data_bulk_packet_wire_len(payload.len())
            else {
                result
                    .dropped
                    .push((payload.len(), PacketMover2EndpointDataDropReason::InvalidPayload));
                continue;
            };
            if crate::node::session_wire::fsp_endpoint_data_bulk_base_wire_len()
                .saturating_add(packet_wire_len)
                > max_fsp_payload
            {
                result
                    .dropped
                    .push((payload.len(), PacketMover2EndpointDataDropReason::InvalidPayload));
                continue;
            }
            if !bulk_payloads.is_empty()
                && (bulk_payloads.len()
                    >= crate::node::session_wire::FSP_ENDPOINT_DATA_BULK_MAX_PACKETS
                    || bulk_wire_len.saturating_add(packet_wire_len) > max_fsp_payload)
            {
                self.push_endpoint_data_bulk(
                    &mut result,
                    &mut bulk_payloads,
                    &mut bulk_wire_len,
                    routed_at_ms,
                );
            }
            bulk_wire_len = bulk_wire_len.saturating_add(packet_wire_len);
            bulk_payloads.push(payload);
        }
        self.push_endpoint_data_bulk(
            &mut result,
            &mut bulk_payloads,
            &mut bulk_wire_len,
            routed_at_ms,
        );
        result
    }

    fn max_fsp_bulk_body_len(&self) -> usize {
        crate::node::session_wire::fsp_endpoint_data_max_body_len()
    }

    fn push_endpoint_data_bulk(
        &self,
        result: &mut PacketMover2EndpointDataBatchRoute,
        bulk_payloads: &mut Vec<Vec<u8>>,
        bulk_wire_len: &mut usize,
        routed_at_ms: u64,
    ) {
        if bulk_payloads.is_empty() {
            return;
        }
        let payloads = std::mem::take(bulk_payloads);
        *bulk_wire_len = crate::node::session_wire::fsp_endpoint_data_bulk_base_wire_len();
        let packet_count = payloads.len();
        match crate::node::session_wire::encode_fsp_endpoint_data_bulk_payload(payloads) {
            Some(payload) => result.routed.push(
                self.build_bulk_packet(
                    crate::protocol::SessionMessageType::EndpointDataBulk.to_byte(),
                    payload,
                )
                .with_activity_tick(ActivityTick::new(routed_at_ms)),
            ),
            None => {
                for _ in 0..packet_count {
                    result
                        .dropped
                        .push((0, PacketMover2EndpointDataDropReason::InvalidPayload));
                }
            }
        }
    }

    fn build_bulk_packet(&self, msg_type: u8, payload: Vec<u8>) -> OutboundPacket {
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
    let deferred_payloads = route.finish_batch(remote, drops, &mut push);
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
