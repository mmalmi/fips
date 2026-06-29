use super::*;

pub(crate) fn endpoint_data_command_capacity(requested: usize) -> usize {
    if let Ok(raw) = std::env::var("FIPS_ENDPOINT_DATA_QUEUE_CAP")
        && let Ok(value) = raw.trim().parse::<usize>()
        && value > 0
    {
        return value;
    }

    requested.max(1).max(32_768)
}

const DEFAULT_ENDPOINT_STALE_BULK_DROP_MS: u64 = 150;
const MAX_ENDPOINT_STALE_BULK_DROP_MS: u64 = 10_000;

pub(crate) fn endpoint_stale_bulk_drop_ms() -> u64 {
    static VALUE: std::sync::OnceLock<u64> = std::sync::OnceLock::new();
    *VALUE.get_or_init(|| {
        std::env::var("FIPS_ENDPOINT_STALE_BULK_DROP_MS")
            .ok()
            .and_then(|raw| raw.trim().parse::<u64>().ok())
            .map(|value| value.min(MAX_ENDPOINT_STALE_BULK_DROP_MS))
            .unwrap_or(DEFAULT_ENDPOINT_STALE_BULK_DROP_MS)
    })
}

const ENDPOINT_SEND_BATCH_DRAIN_QUANTUM: usize = 8;

fn endpoint_send_batch_drain_cost(packet_count: usize) -> usize {
    packet_count
        .max(1)
        .saturating_add(ENDPOINT_SEND_BATCH_DRAIN_QUANTUM - 1)
        / ENDPOINT_SEND_BATCH_DRAIN_QUANTUM
}

/// Commands accepted by the node endpoint data service.
#[derive(Debug)]
pub(crate) enum NodeEndpointCommand {
    /// Send with an explicit response channel — used by callers that
    /// care whether the local-stack handoff succeeded (e.g.
    /// `blocking_send` waits for the runtime to accept the send).
    Send {
        command: EndpointSendCommand,
        response_tx: tokio::sync::oneshot::Sender<Result<(), NodeError>>,
    },
    /// Fire-and-forget variant of `Send`: no oneshot allocation and no
    /// per-packet result channel.
    SendOneway { command: EndpointSendCommand },
    /// Fire-and-forget batch of endpoint payloads that already share the same
    /// peer and command lane.
    SendBatchOneway {
        command: EndpointSendBatchCommand,
        lane: EndpointCommandLane,
    },
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

#[derive(Debug)]
pub(crate) struct EndpointSendCommand {
    send: EndpointDataSend,
    queued_at: Option<crate::perf_profile::TraceStamp>,
    enqueued_at_ms: u64,
}

impl EndpointSendCommand {
    pub(crate) fn new(
        remote: PeerIdentity,
        payload: Vec<u8>,
        queued_at: Option<crate::perf_profile::TraceStamp>,
    ) -> Self {
        Self::new_with_enqueued_at_ms(remote, payload, queued_at, crate::time::now_ms())
    }

    pub(crate) fn from_payload(
        remote: PeerIdentity,
        payload: EndpointDataPayload,
        queued_at: Option<crate::perf_profile::TraceStamp>,
    ) -> Self {
        Self::from_payload_with_enqueued_at_ms(remote, payload, queued_at, crate::time::now_ms())
    }

    pub(crate) fn from_payload_with_enqueued_at_ms(
        remote: PeerIdentity,
        payload: EndpointDataPayload,
        queued_at: Option<crate::perf_profile::TraceStamp>,
        enqueued_at_ms: u64,
    ) -> Self {
        Self {
            send: EndpointDataSend::new(remote, payload),
            queued_at,
            enqueued_at_ms,
        }
    }

    pub(crate) fn from_send_with_enqueued_at_ms(
        send: EndpointDataSend,
        queued_at: Option<crate::perf_profile::TraceStamp>,
        enqueued_at_ms: u64,
    ) -> Self {
        Self {
            send,
            queued_at,
            enqueued_at_ms,
        }
    }

    pub(crate) fn new_with_enqueued_at_ms(
        remote: PeerIdentity,
        payload: Vec<u8>,
        queued_at: Option<crate::perf_profile::TraceStamp>,
        enqueued_at_ms: u64,
    ) -> Self {
        Self {
            send: EndpointDataSend::new(remote, EndpointDataPayload::new(payload)),
            queued_at,
            enqueued_at_ms,
        }
    }

    pub(crate) fn lane(&self) -> EndpointCommandLane {
        self.send.payload().lane()
    }

    pub(crate) fn drop_on_backpressure(&self) -> bool {
        self.send.payload().drop_on_backpressure()
    }

    pub(crate) fn data_send(&self) -> &EndpointDataSend {
        &self.send
    }

    pub(crate) fn stale_at(&self, now_ms: u64, max_age_ms: u64) -> bool {
        max_age_ms > 0 && now_ms.saturating_sub(self.enqueued_at_ms) > max_age_ms
    }

    pub(crate) fn triggers_stale_bulk_drop(&self) -> bool {
        self.send.payload().triggers_stale_bulk_drop()
    }

    pub(crate) fn into_parts(self) -> (EndpointDataSend, Option<crate::perf_profile::TraceStamp>) {
        (self.send, self.queued_at)
    }

    pub(crate) fn into_deferred_parts(
        self,
    ) -> (
        EndpointDataSend,
        Option<crate::perf_profile::TraceStamp>,
        u64,
    ) {
        (self.send, self.queued_at, self.enqueued_at_ms)
    }
}

#[derive(Debug)]
pub(crate) struct EndpointSendBatchCommand {
    remote: PeerIdentity,
    payloads: Vec<EndpointDataPayload>,
    queued_at: Option<crate::perf_profile::TraceStamp>,
    enqueued_at_ms: u64,
}

impl EndpointSendBatchCommand {
    pub(crate) fn new(
        remote: PeerIdentity,
        payloads: Vec<EndpointDataPayload>,
        queued_at: Option<crate::perf_profile::TraceStamp>,
    ) -> Option<Self> {
        Self::new_with_enqueued_at_ms(remote, payloads, queued_at, crate::time::now_ms())
    }

    pub(crate) fn new_with_enqueued_at_ms(
        remote: PeerIdentity,
        payloads: Vec<EndpointDataPayload>,
        queued_at: Option<crate::perf_profile::TraceStamp>,
        enqueued_at_ms: u64,
    ) -> Option<Self> {
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

    pub(crate) fn lane(&self) -> EndpointCommandLane {
        self.payloads[0].lane()
    }

    pub(crate) fn len(&self) -> usize {
        self.payloads.len()
    }

    #[cfg(test)]
    pub(crate) fn can_coalesce_with(&self, other: &Self, max_payloads: usize) -> bool {
        self.remote == other.remote
            && self.lane() == other.lane()
            && self.len().saturating_add(other.len()) <= max_payloads
    }

    pub(crate) fn drop_on_backpressure(&self) -> bool {
        self.payloads
            .iter()
            .all(EndpointDataPayload::drop_on_backpressure)
    }

    pub(crate) fn stale_at(&self, now_ms: u64, max_age_ms: u64) -> bool {
        max_age_ms > 0 && now_ms.saturating_sub(self.enqueued_at_ms) > max_age_ms
    }

    pub(crate) fn triggers_stale_bulk_drop(&self) -> bool {
        self.payloads
            .iter()
            .any(EndpointDataPayload::triggers_stale_bulk_drop)
    }

    pub(crate) fn into_parts(
        self,
    ) -> (
        PeerIdentity,
        Vec<EndpointDataPayload>,
        Option<crate::perf_profile::TraceStamp>,
    ) {
        (self.remote, self.payloads, self.queued_at)
    }

    pub(crate) fn into_deferred_parts(
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

impl NodeEndpointCommand {
    pub(crate) fn send(
        remote: PeerIdentity,
        payload: Vec<u8>,
        queued_at: Option<crate::perf_profile::TraceStamp>,
        response_tx: tokio::sync::oneshot::Sender<Result<(), NodeError>>,
    ) -> Self {
        Self::Send {
            command: EndpointSendCommand::new(remote, payload, queued_at),
            response_tx,
        }
    }

    pub(crate) fn send_oneway(
        remote: PeerIdentity,
        payload: Vec<u8>,
        queued_at: Option<crate::perf_profile::TraceStamp>,
    ) -> Self {
        Self::SendOneway {
            command: EndpointSendCommand::new(remote, payload, queued_at),
        }
    }

    pub(crate) fn send_payload_oneway(
        remote: PeerIdentity,
        payload: EndpointDataPayload,
        queued_at: Option<crate::perf_profile::TraceStamp>,
    ) -> Self {
        Self::SendOneway {
            command: EndpointSendCommand::from_payload(remote, payload, queued_at),
        }
    }

    pub(crate) fn send_batch_oneway(
        remote: PeerIdentity,
        payloads: Vec<EndpointDataPayload>,
        queued_at: Option<crate::perf_profile::TraceStamp>,
        lane: EndpointCommandLane,
    ) -> Option<Self> {
        debug_assert!(payloads.iter().all(|payload| payload.lane() == lane));
        let command = EndpointSendBatchCommand::new(remote, payloads, queued_at)?;
        debug_assert_eq!(command.lane(), lane);
        Some(Self::SendBatchOneway { command, lane })
    }

    pub(crate) fn lane(&self) -> EndpointCommandLane {
        match self {
            Self::Send { command, .. } | Self::SendOneway { command } => command.lane(),
            Self::SendBatchOneway { lane, .. } => *lane,
            Self::PeerSnapshot { .. }
            | Self::LocalAdvertSnapshot { .. }
            | Self::RelaySnapshot { .. }
            | Self::UpdateRelays { .. }
            | Self::UpdatePeers { .. }
            | Self::RefreshPeerPaths { .. } => EndpointCommandLane::Priority,
        }
    }

    pub(crate) fn drop_on_backpressure(&self) -> bool {
        match self {
            Self::SendOneway { command } => {
                command.lane() == EndpointCommandLane::Bulk && command.drop_on_backpressure()
            }
            Self::SendBatchOneway { command, lane } => {
                *lane == EndpointCommandLane::Bulk && command.drop_on_backpressure()
            }
            Self::Send { .. }
            | Self::PeerSnapshot { .. }
            | Self::LocalAdvertSnapshot { .. }
            | Self::RelaySnapshot { .. }
            | Self::UpdateRelays { .. }
            | Self::UpdatePeers { .. }
            | Self::RefreshPeerPaths { .. } => false,
        }
    }

    pub(crate) fn drain_cost(&self) -> usize {
        match self {
            Self::SendBatchOneway { command, .. } => endpoint_send_batch_drain_cost(command.len()),
            Self::Send { .. }
            | Self::SendOneway { .. }
            | Self::PeerSnapshot { .. }
            | Self::LocalAdvertSnapshot { .. }
            | Self::RelaySnapshot { .. }
            | Self::UpdateRelays { .. }
            | Self::UpdatePeers { .. }
            | Self::RefreshPeerPaths { .. } => 1,
        }
    }

    pub(crate) fn packet_count(&self) -> usize {
        match self {
            Self::SendBatchOneway { command, .. } => command.len(),
            Self::Send { .. }
            | Self::SendOneway { .. }
            | Self::PeerSnapshot { .. }
            | Self::LocalAdvertSnapshot { .. }
            | Self::RelaySnapshot { .. }
            | Self::UpdateRelays { .. }
            | Self::UpdatePeers { .. }
            | Self::RefreshPeerPaths { .. } => 1,
        }
    }

    pub(crate) fn triggers_stale_bulk_drop(&self) -> bool {
        match self {
            Self::Send { command, .. } | Self::SendOneway { command } => {
                command.triggers_stale_bulk_drop()
            }
            Self::SendBatchOneway { command, .. } => command.triggers_stale_bulk_drop(),
            Self::PeerSnapshot { .. }
            | Self::LocalAdvertSnapshot { .. }
            | Self::RelaySnapshot { .. }
            | Self::UpdateRelays { .. }
            | Self::UpdatePeers { .. }
            | Self::RefreshPeerPaths { .. } => true,
        }
    }
}
