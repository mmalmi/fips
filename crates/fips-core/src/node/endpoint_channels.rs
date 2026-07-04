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
                crate::perf_profile::Event::EndpointDataBatchDropped,
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
    payloads: Vec<EndpointDataPayload>,
    queued_at: Option<crate::perf_profile::TraceStamp>,
    enqueued_at_ms: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct EndpointDataPayload {
    body: crate::transport::PacketBuffer,
}

impl EndpointDataPayload {
    fn from_packet_payloads(payloads: Vec<Vec<u8>>) -> Option<Vec<Self>> {
        if payloads.is_empty() {
            return None;
        }
        let payloads: Vec<_> = payloads
            .into_iter()
            .filter_map(Self::from_packet_payload)
            .collect();
        (!payloads.is_empty()).then_some(payloads)
    }

    pub(crate) fn from_packet_payload(payload: Vec<u8>) -> Option<Self> {
        (payload.len() <= crate::node::session_wire::fsp_endpoint_data_max_body_len()).then_some(
            Self {
                body: payload.into(),
            },
        )
    }

    pub(crate) fn body_len(&self) -> usize {
        self.body.len()
    }

    pub(crate) fn into_body(self) -> crate::transport::PacketBuffer {
        self.body
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
        let payloads = EndpointDataPayload::from_packet_payloads(payloads)?;
        if payloads.is_empty() {
            return None;
        }
        Some(Self {
            remote,
            payloads,
            queued_at,
            enqueued_at_ms,
        })
    }

    pub(crate) fn drain_cost(&self) -> usize {
        endpoint_data_batch_drain_cost(self.packet_count())
    }

    pub(crate) fn packet_count(&self) -> usize {
        self.payloads.len()
    }

    pub(crate) fn enqueued_at_ms(&self) -> u64 {
        self.enqueued_at_ms
    }

    pub(crate) fn into_parts(
        self,
    ) -> (
        PeerIdentity,
        Vec<EndpointDataPayload>,
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
