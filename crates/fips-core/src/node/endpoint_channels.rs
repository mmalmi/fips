use super::*;
use tokio::sync::mpsc::error::TryRecvError;

pub(crate) const ENDPOINT_STALE_DATA_DROP_MS: u64 = 150;

const ENDPOINT_DATA_BATCH_DRAIN_QUANTUM: usize = 8;

fn endpoint_data_batch_drain_cost(packet_count: usize) -> usize {
    packet_count
        .max(1)
        .saturating_add(ENDPOINT_DATA_BATCH_DRAIN_QUANTUM - 1)
        / ENDPOINT_DATA_BATCH_DRAIN_QUANTUM
}

#[derive(Clone, Debug)]
pub(crate) struct EndpointDataBatchTx {
    tx: tokio::sync::mpsc::UnboundedSender<NodeEndpointDataBatch>,
    queued_drain_cost: Arc<AtomicUsize>,
    drain_cost_capacity: usize,
}

#[derive(Debug)]
pub(crate) struct EndpointDataBatchRx {
    rx: tokio::sync::mpsc::UnboundedReceiver<NodeEndpointDataBatch>,
    queued_drain_cost: Arc<AtomicUsize>,
}

pub(crate) fn endpoint_data_batch_channel(
    capacity: usize,
) -> (EndpointDataBatchTx, EndpointDataBatchRx) {
    let queued_drain_cost = Arc::new(AtomicUsize::new(0));
    let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
    (
        EndpointDataBatchTx {
            tx,
            queued_drain_cost: Arc::clone(&queued_drain_cost),
            drain_cost_capacity: capacity.max(1),
        },
        EndpointDataBatchRx {
            rx,
            queued_drain_cost,
        },
    )
}

fn try_reserve_endpoint_data_batch_drain_cost(
    counter: &AtomicUsize,
    capacity: usize,
    cost: usize,
) -> bool {
    if cost == 0 {
        return true;
    }

    counter
        .fetch_update(Relaxed, Relaxed, |current| {
            current.checked_add(cost).filter(|next| *next <= capacity)
        })
        .is_ok()
}

fn release_endpoint_data_batch_drain_cost(counter: &AtomicUsize, cost: usize) {
    if cost > 0 {
        counter.fetch_sub(cost, Relaxed);
    }
}

impl EndpointDataBatchTx {
    pub(crate) fn send_or_drop(&self, batch: NodeEndpointDataBatch) -> Result<(), ()> {
        let packet_count = batch.packet_count();
        let drain_cost = batch.drain_cost();
        if !try_reserve_endpoint_data_batch_drain_cost(
            &self.queued_drain_cost,
            self.drain_cost_capacity,
            drain_cost,
        ) {
            crate::perf_profile::record_event_count(
                crate::perf_profile::Event::EndpointDataBulkDropped,
                packet_count as u64,
            );
            return Ok(());
        }

        match self.tx.send(batch) {
            Ok(()) => Ok(()),
            Err(error) => {
                release_endpoint_data_batch_drain_cost(&self.queued_drain_cost, drain_cost);
                drop(error);
                Err(())
            }
        }
    }
}

impl EndpointDataBatchRx {
    pub(crate) async fn recv(&mut self) -> Option<NodeEndpointDataBatch> {
        let batch = self.rx.recv().await?;
        release_endpoint_data_batch_drain_cost(&self.queued_drain_cost, batch.drain_cost());
        Some(batch)
    }

    pub(crate) fn try_recv(&mut self) -> Result<NodeEndpointDataBatch, TryRecvError> {
        let batch = self.rx.try_recv()?;
        release_endpoint_data_batch_drain_cost(&self.queued_drain_cost, batch.drain_cost());
        Ok(batch)
    }
}

/// Fire-and-forget endpoint data batch accepted by the node endpoint data service.
#[derive(Debug)]
pub(crate) struct NodeEndpointDataBatch {
    remote: PeerIdentity,
    payloads: Vec<EndpointDataBulkBody>,
    queued_at: Option<crate::perf_profile::TraceStamp>,
    enqueued_at_ms: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct EndpointDataBulkBody {
    body: Vec<u8>,
    packet_count: usize,
    packet_bytes: usize,
}

impl EndpointDataBulkBody {
    pub(crate) fn from_encoded_body(body: Vec<u8>) -> Option<Self> {
        let ranges = crate::node::session_wire::decode_fsp_endpoint_data_bulk_ranges(&body)?;
        let packet_count = ranges.len();
        let packet_bytes = ranges.iter().map(|range| range.len()).sum();
        Some(Self::from_parts(body, packet_count, packet_bytes))
    }

    fn from_parts(body: Vec<u8>, packet_count: usize, packet_bytes: usize) -> Self {
        Self {
            body,
            packet_count,
            packet_bytes,
        }
    }

    fn from_packet_payloads(payloads: Vec<Vec<u8>>) -> Option<Vec<Self>> {
        if payloads.is_empty() {
            return None;
        }

        let mut bodies = Vec::new();
        let mut builder = EndpointDataBulkBodyBuilder::new();
        for payload in payloads {
            if !builder.can_push_packet(&payload) {
                if let Some(body) = builder.finish() {
                    bodies.push(body);
                }
                builder = EndpointDataBulkBodyBuilder::new();
            }
            if !builder.push_packet(&payload) {
                continue;
            }
        }
        if let Some(body) = builder.finish() {
            bodies.push(body);
        }
        (!bodies.is_empty()).then_some(bodies)
    }

    pub(crate) fn body_len(&self) -> usize {
        self.body.len()
    }

    pub(crate) fn packet_count(&self) -> usize {
        self.packet_count
    }

    pub(crate) fn packet_bytes(&self) -> usize {
        self.packet_bytes
    }

    pub(crate) fn packet_lengths(&self) -> Vec<usize> {
        crate::node::session_wire::decode_fsp_endpoint_data_bulk_lengths(&self.body)
            .unwrap_or_default()
    }

    pub(crate) fn into_body(self) -> Vec<u8> {
        self.body
    }

    pub(crate) fn into_packet_payloads(self) -> Vec<Vec<u8>> {
        let Some(ranges) =
            crate::node::session_wire::decode_fsp_endpoint_data_bulk_ranges(&self.body)
        else {
            return Vec::new();
        };
        ranges
            .into_iter()
            .map(|range| self.body[range].to_vec())
            .collect()
    }
}

#[derive(Debug)]
pub(crate) struct EndpointDataBulkBodyBuilder {
    body: Vec<u8>,
    packet_count: usize,
    packet_bytes: usize,
}

impl Default for EndpointDataBulkBodyBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl EndpointDataBulkBodyBuilder {
    pub(crate) fn new() -> Self {
        let mut body =
            Vec::with_capacity(crate::node::session_wire::fsp_endpoint_data_bulk_base_wire_len());
        body.extend_from_slice(&0_u16.to_le_bytes());
        Self {
            body,
            packet_count: 0,
            packet_bytes: 0,
        }
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.packet_count == 0
    }

    pub(crate) fn packet_count(&self) -> usize {
        self.packet_count
    }

    pub(crate) fn packet_bytes(&self) -> usize {
        self.packet_bytes
    }

    pub(crate) fn body_len(&self) -> usize {
        self.body.len()
    }

    pub(crate) fn can_push_packet(&self, packet: &[u8]) -> bool {
        let Some(packet_wire_len) =
            crate::node::session_wire::fsp_endpoint_data_bulk_packet_wire_len(packet.len())
        else {
            return false;
        };
        self.packet_count() < crate::node::session_wire::FSP_ENDPOINT_DATA_BULK_MAX_PACKETS
            && self.body_len().saturating_add(packet_wire_len)
                <= crate::node::session_wire::fsp_endpoint_data_max_body_len()
    }

    pub(crate) fn push_packet(&mut self, packet: &[u8]) -> bool {
        if !self.can_push_packet(packet) {
            return false;
        }
        self.body
            .extend_from_slice(&(packet.len() as u16).to_le_bytes());
        self.body.extend_from_slice(packet);
        self.packet_count += 1;
        self.packet_bytes = self.packet_bytes.saturating_add(packet.len());
        let packet_count = self.packet_count() as u16;
        self.body[..2].copy_from_slice(&packet_count.to_le_bytes());
        true
    }

    pub(crate) fn finish(self) -> Option<EndpointDataBulkBody> {
        (self.packet_count > 0).then(|| {
            EndpointDataBulkBody::from_parts(self.body, self.packet_count, self.packet_bytes)
        })
    }
}

impl NodeEndpointDataBatch {
    pub(crate) fn batch(
        remote: PeerIdentity,
        payloads: Vec<Vec<u8>>,
        queued_at: Option<crate::perf_profile::TraceStamp>,
    ) -> Option<Self> {
        Self::batch_with_enqueued_at_ms(remote, payloads, queued_at, crate::time::now_ms())
    }

    pub(crate) fn batch_with_enqueued_at_ms(
        remote: PeerIdentity,
        payloads: Vec<Vec<u8>>,
        queued_at: Option<crate::perf_profile::TraceStamp>,
        enqueued_at_ms: u64,
    ) -> Option<Self> {
        let bodies = EndpointDataBulkBody::from_packet_payloads(payloads)?;
        Self::bulk_bodies_with_enqueued_at_ms(remote, bodies, queued_at, enqueued_at_ms)
    }

    pub(crate) fn bulk_bodies(
        remote: PeerIdentity,
        bodies: Vec<EndpointDataBulkBody>,
        queued_at: Option<crate::perf_profile::TraceStamp>,
    ) -> Option<Self> {
        Self::bulk_bodies_with_enqueued_at_ms(remote, bodies, queued_at, crate::time::now_ms())
    }

    pub(crate) fn bulk_bodies_with_enqueued_at_ms(
        remote: PeerIdentity,
        bodies: Vec<EndpointDataBulkBody>,
        queued_at: Option<crate::perf_profile::TraceStamp>,
        enqueued_at_ms: u64,
    ) -> Option<Self> {
        if bodies.is_empty() {
            return None;
        }
        Some(Self {
            remote,
            payloads: bodies,
            queued_at,
            enqueued_at_ms,
        })
    }

    pub(crate) fn drain_cost(&self) -> usize {
        endpoint_data_batch_drain_cost(self.packet_count())
    }

    pub(crate) fn packet_count(&self) -> usize {
        self.payloads
            .iter()
            .map(EndpointDataBulkBody::packet_count)
            .sum()
    }

    pub(crate) fn enqueued_at_ms(&self) -> u64 {
        self.enqueued_at_ms
    }

    pub(crate) fn into_parts(
        self,
    ) -> (
        PeerIdentity,
        Vec<EndpointDataBulkBody>,
        Option<crate::perf_profile::TraceStamp>,
        u64,
    ) {
        (
            self.remote,
            self.payloads,
            self.queued_at,
            self.enqueued_at_ms,
        )
    }
}

/// Control commands accepted by the node endpoint data service.
#[derive(Debug)]
pub(crate) enum NodeEndpointControlCommand {
    PeerSnapshot {
        response_tx: tokio::sync::oneshot::Sender<Vec<NodeEndpointPeer>>,
    },
    LocalAdvertSnapshot {
        response_tx:
            tokio::sync::oneshot::Sender<Vec<crate::discovery::nostr::OverlayEndpointAdvert>>,
    },
    RelaySnapshot {
        response_tx: tokio::sync::oneshot::Sender<Vec<NodeEndpointRelayStatus>>,
    },
    UpdateRelays {
        advert_relays: Vec<String>,
        dm_relays: Vec<String>,
        response_tx: tokio::sync::oneshot::Sender<Result<(), NodeError>>,
    },
    UpdatePeers {
        peers: Vec<crate::config::PeerConfig>,
        response_tx: tokio::sync::oneshot::Sender<Result<UpdatePeersOutcome, NodeError>>,
    },
    RefreshPeerPaths {
        npubs: Vec<String>,
        response_tx: tokio::sync::oneshot::Sender<Result<usize, NodeError>>,
    },
}
