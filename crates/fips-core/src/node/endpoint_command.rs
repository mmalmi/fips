use super::*;

pub(crate) const ENDPOINT_STALE_BULK_DROP_MS: u64 = 150;

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
    /// peer.
    SendBatchOneway { command: EndpointSendBatchCommand },
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

    pub(crate) fn data_send(&self) -> &EndpointDataSend {
        &self.send
    }

    pub(crate) fn stale_at(&self, now_ms: u64, max_age_ms: u64) -> bool {
        max_age_ms > 0 && now_ms.saturating_sub(self.enqueued_at_ms) > max_age_ms
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

    pub(crate) fn len(&self) -> usize {
        self.payloads.len()
    }

    pub(crate) fn stale_at(&self, now_ms: u64, max_age_ms: u64) -> bool {
        max_age_ms > 0 && now_ms.saturating_sub(self.enqueued_at_ms) > max_age_ms
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

    pub(crate) fn send_payload_oneway_with_enqueued_at_ms(
        remote: PeerIdentity,
        payload: EndpointDataPayload,
        queued_at: Option<crate::perf_profile::TraceStamp>,
        enqueued_at_ms: u64,
    ) -> Self {
        Self::SendOneway {
            command: EndpointSendCommand::from_payload_with_enqueued_at_ms(
                remote,
                payload,
                queued_at,
                enqueued_at_ms,
            ),
        }
    }

    pub(crate) fn send_batch_oneway(
        remote: PeerIdentity,
        payloads: Vec<EndpointDataPayload>,
        queued_at: Option<crate::perf_profile::TraceStamp>,
    ) -> Option<Self> {
        let command = EndpointSendBatchCommand::new(remote, payloads, queued_at)?;
        Some(Self::SendBatchOneway { command })
    }

    pub(crate) fn send_batch_oneway_with_enqueued_at_ms(
        remote: PeerIdentity,
        payloads: Vec<EndpointDataPayload>,
        queued_at: Option<crate::perf_profile::TraceStamp>,
        enqueued_at_ms: u64,
    ) -> Option<Self> {
        let command = EndpointSendBatchCommand::new_with_enqueued_at_ms(
            remote,
            payloads,
            queued_at,
            enqueued_at_ms,
        )?;
        Some(Self::SendBatchOneway { command })
    }

    pub(crate) fn drop_on_backpressure(&self) -> bool {
        match self {
            Self::SendOneway { .. } | Self::SendBatchOneway { .. } => true,
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
            Self::SendBatchOneway { command } => endpoint_send_batch_drain_cost(command.len()),
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
            Self::SendBatchOneway { command } => command.len(),
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
}
