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
    fsp_auto_coords_warmup: bool,
}

impl DataplaneEndpointDataRoute {
    pub(crate) fn fsp(owner: OwnerId, generation: u64, flags: u8, inner_flags: u8) -> Self {
        Self {
            owner,
            generation,
            flags,
            inner_flags,
            fsp_auto_coords_warmup: true,
        }
    }

    pub(crate) fn with_direct_transport(mut self) -> Self {
        self.fsp_auto_coords_warmup = false;
        self
    }

    fn owner(&self) -> OwnerId {
        self.owner
    }

    fn route_payloads(
        &self,
        payloads: Vec<EndpointDataPayload>,
        activity_tick: ActivityTick,
    ) -> DataplaneEndpointDataBatchRoute {
        let mut result = DataplaneEndpointDataBatchRoute::with_capacity(payloads.len());
        for payload in payloads {
            let (msg_type, body) = payload.into_fsp_payload();
            result.routed.push(
                self.build_packet(msg_type, body)
                    .with_activity_tick(activity_tick),
            );
        }
        result
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
        .with_fsp_inner_header(msg_type, self.inner_flags);
        if !self.fsp_auto_coords_warmup {
            packet = packet.without_fsp_auto_coords_warmup();
        }
        packet
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DataplaneEndpointDataDropReason {
    StaleQueuedBatch,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct DataplaneEndpointDataDrop {
    dest_addr: NodeAddr,
    payload_len: usize,
    reason: DataplaneEndpointDataDropReason,
}

impl DataplaneEndpointDataDrop {
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

fn push_endpoint_data_drop(
    remote: PeerIdentity,
    payload_len: usize,
    reason: DataplaneEndpointDataDropReason,
    drops: &mut Vec<DataplaneEndpointDataDrop>,
) {
    drops.push(DataplaneEndpointDataDrop {
        dest_addr: *remote.node_addr(),
        payload_len,
        reason,
    });
}

fn route_endpoint_data_batch_with_route_table<F>(
    batch: NodeEndpointDataBatch,
    routes: &DataplaneLiveRouteTable,
    drops: &mut Vec<DataplaneEndpointDataDrop>,
    deferred_batches: &mut Vec<NodeEndpointDataBatch>,
    activity_tick: ActivityTick,
    mut push: F,
) where
    F: FnMut(Vec<OutboundPacket>),
{
    let (remote, payloads, queued_at, enqueued_at_ms) = batch.into_parts();
    let route = routes.route_endpoint_data_batch(remote, payloads, activity_tick);
    let deferred_payloads = route.finish_batch(remote, drops, &mut push);
    if let Some(payloads) = deferred_payloads {
        let batch = NodeEndpointDataBatch::from_payloads_with_enqueued_at_ms(
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
