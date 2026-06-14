//! Library-first endpoint API for embedding FIPS in applications.
//!
//! This module exposes a no-system-TUN runtime shape for apps that want to own
//! peer admission and local routing policy while reusing FIPS connectivity.

use crate::config::{EthernetConfig, NostrDiscoveryPolicy, TransportInstances, UdpConfig};
#[cfg(test)]
use crate::node::ENDPOINT_EVENT_PRIORITY_MAX_LEN;
use crate::node::{
    EndpointCommandLane, EndpointDataPayload, EndpointEventSender, EndpointPayloadClass,
    NodeEndpointCommand, NodeEndpointEvent,
};
use crate::{
    Config, FipsAddress, IdentityConfig, Node, NodeAddr, NodeDeliveredPacket, NodeError,
    PeerIdentity,
};
use std::sync::Arc;
use thiserror::Error;
use tokio::sync::{Mutex, mpsc, oneshot};
use tokio::task::JoinHandle;

const ENDPOINT_SEND_BATCH_COMMAND_MAX: usize = 64;
const ENDPOINT_RECV_BATCH_MAX: usize = 128;

mod builder;
mod receive;
mod status;

#[cfg(test)]
mod tests;

pub use builder::FipsEndpointBuilder;
use receive::EndpointReceiveState;
pub use status::{FipsEndpointPeer, FipsEndpointRelayStatus};

/// App-owned endpoint payload plus its queue/pressure policy.
///
/// `FipsEndpointPayload::new` classifies raw packet bytes once. Embedders that
/// already classified a packet while staging their own priority/bulk queues can
/// use `from_classified` to carry the same class into FIPS without parsing the
/// packet a second time.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FipsEndpointPayload {
    bytes: Vec<u8>,
    class: EndpointPayloadClass,
}

impl FipsEndpointPayload {
    pub fn new(bytes: Vec<u8>) -> Self {
        let class = crate::node::classify_endpoint_payload(&bytes);
        Self { bytes, class }
    }

    pub fn from_classified(bytes: Vec<u8>, class: EndpointPayloadClass) -> Self {
        Self { bytes, class }
    }

    pub fn class(&self) -> EndpointPayloadClass {
        self.class
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.bytes
    }

    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }
}

impl From<FipsEndpointPayload> for EndpointDataPayload {
    fn from(payload: FipsEndpointPayload) -> Self {
        EndpointDataPayload::from_classified(payload.bytes, payload.class)
    }
}

#[derive(Debug)]
enum EndpointPayloadLaneBatches {
    Empty,
    Single {
        lane: EndpointCommandLane,
        payloads: Vec<EndpointDataPayload>,
    },
    Split {
        priority_payloads: Vec<EndpointDataPayload>,
        bulk_payloads: Vec<EndpointDataPayload>,
    },
}

#[cfg(debug_assertions)]
fn endpoint_debug_log(message: impl AsRef<str>) {
    use std::io::Write as _;

    if let Ok(mut file) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(std::env::temp_dir().join("nvpn-fips-endpoint-debug.log"))
    {
        let _ = writeln!(
            file,
            "{:?} {}",
            std::time::SystemTime::now(),
            message.as_ref()
        );
    }
}

#[cfg(not(debug_assertions))]
fn endpoint_debug_log(_message: impl AsRef<str>) {}

/// Errors returned by the endpoint API.
#[derive(Debug, Error)]
pub enum FipsEndpointError {
    #[error("node error: {0}")]
    Node(#[from] NodeError),

    #[error("endpoint task failed: {0}")]
    TaskJoin(#[from] tokio::task::JoinError),

    #[error("endpoint is closed")]
    Closed,

    #[error("invalid remote npub '{npub}': {reason}")]
    InvalidRemoteNpub { npub: String, reason: String },
}

/// Source-attributed endpoint data delivered to an embedded application.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FipsEndpointMessage {
    /// Authenticated FIPS peer that originated the endpoint data.
    pub source_peer: PeerIdentity,
    /// Application-owned payload bytes.
    pub data: Vec<u8>,
}

impl FipsEndpointMessage {
    /// FIPS node address that originated the endpoint data.
    pub fn source_node_addr(&self) -> &NodeAddr {
        self.source_peer.node_addr()
    }

    /// Source Nostr public key as human-facing bech32 text.
    pub fn source_npub(&self) -> String {
        self.source_peer.npub()
    }
}

/// Reports what changed in response to [`FipsEndpoint::update_peers`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct UpdatePeersOutcome {
    /// Number of npubs that were not previously in the runtime peer list
    /// and got an `initiate_peer_connection` call.
    pub added: usize,
    /// Number of npubs that were dropped from the runtime peer list. Their
    /// retry entries are gone; any active session stays up until the
    /// regular liveness timeout reaps it.
    pub removed: usize,
    /// Number of npubs that were already in the list but had a different
    /// `addresses`, `alias`, `connect_policy`, or `auto_reconnect` value.
    /// The new values are now in effect for retries and aliasing; refreshed
    /// direct addresses may also trigger a new direct dial for auto peers.
    pub updated: usize,
    /// Number of npubs that were in the list and identical to the new entry.
    pub unchanged: usize,
}

impl From<crate::node::UpdatePeersOutcome> for UpdatePeersOutcome {
    fn from(value: crate::node::UpdatePeersOutcome) -> Self {
        Self {
            added: value.added,
            removed: value.removed,
            updated: value.updated,
            unchanged: value.unchanged,
        }
    }
}

fn apply_default_scoped_discovery(config: &mut Config, scope: &str) {
    if config.node.discovery.nostr.enabled || !config.transports.is_empty() {
        return;
    }

    config.node.discovery.nostr.enabled = true;
    config.node.discovery.nostr.advertise = true;
    config.node.discovery.nostr.policy = NostrDiscoveryPolicy::Open;
    config.node.discovery.nostr.share_local_candidates = true;
    config.node.discovery.nostr.app = scope.to_string();
    config.node.discovery.lan.scope = Some(scope.to_string());
    config.node.discovery.local.enabled = true;
    config.transports.udp = TransportInstances::Single(UdpConfig {
        bind_addr: Some("0.0.0.0:0".to_string()),
        advertise_on_nostr: Some(true),
        public: Some(false),
        outbound_only: Some(false),
        accept_connections: Some(true),
        ..UdpConfig::default()
    });
}

fn endpoint_ethernet_config(interface: &str, scope: Option<&str>) -> EthernetConfig {
    EthernetConfig {
        interface: interface.to_string(),
        discovery: Some(true),
        announce: Some(true),
        auto_connect: Some(true),
        accept_connections: Some(true),
        discovery_scope: scope
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_string),
        ..EthernetConfig::default()
    }
}

fn add_endpoint_ethernet_transport(config: &mut Config, interface: &str, scope: Option<&str>) {
    let eth = endpoint_ethernet_config(interface, scope);
    if config.transports.ethernet.is_empty() {
        config.transports.ethernet = TransportInstances::Single(eth);
        return;
    }

    let existing = std::mem::take(&mut config.transports.ethernet);
    let mut named = match existing {
        TransportInstances::Single(config) => {
            let mut map = std::collections::HashMap::new();
            map.insert("default".to_string(), config);
            map
        }
        TransportInstances::Named(map) => map,
    };

    let base_name = endpoint_ethernet_instance_name(interface);
    let mut name = base_name.clone();
    let mut suffix = 2usize;
    while named.contains_key(&name) {
        name = format!("{base_name}-{suffix}");
        suffix += 1;
    }
    named.insert(name, eth);
    config.transports.ethernet = TransportInstances::Named(named);
}

fn endpoint_ethernet_instance_name(interface: &str) -> String {
    let suffix: String = interface
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() {
                c.to_ascii_lowercase()
            } else {
                '-'
            }
        })
        .collect();
    let suffix = suffix.trim_matches('-');
    if suffix.is_empty() {
        "local-ethernet".to_string()
    } else {
        format!("local-ethernet-{suffix}")
    }
}

fn spawn_node_task(
    mut node: Node,
    shutdown_rx: oneshot::Receiver<()>,
) -> JoinHandle<Result<(), NodeError>> {
    tokio::spawn(async move {
        tokio::pin!(shutdown_rx);
        let loop_result = tokio::select! {
            result = node.run_rx_loop() => result,
            _ = &mut shutdown_rx => Ok(()),
        };
        let stop_result = if node.state().can_stop() {
            node.stop().await
        } else {
            Ok(())
        };
        loop_result?;
        stop_result
    })
}

/// A running embedded FIPS endpoint.
pub struct FipsEndpoint {
    identity: PeerIdentity,
    npub: String,
    node_addr: NodeAddr,
    address: FipsAddress,
    discovery_scope: Option<String>,
    outbound_packets: mpsc::Sender<Vec<u8>>,
    delivered_packets: Arc<Mutex<mpsc::Receiver<NodeDeliveredPacket>>>,
    endpoint_priority_commands: mpsc::Sender<NodeEndpointCommand>,
    endpoint_commands: mpsc::Sender<NodeEndpointCommand>,
    /// In-process loopback sender — `send()` to our own npub injects an
    /// event into the same queue without going through the wire/encrypt
    /// path. The node's rx_loop also sends into this channel directly
    /// (it holds a clone of this sender) so there is no per-packet relay
    /// task between the node task and `recv()`.
    inbound_endpoint_tx: EndpointEventSender,
    /// Unbounded receiver plus pending tail from an internal batch. This was
    /// previously fed by a per-packet relay task
    /// that translated `NodeEndpointEvent::Data` into `FipsEndpointMessage`
    /// across an additional bounded mpsc; collapsed into a single channel
    /// — the translation happens inline in `recv()` and the second hop
    /// (with its scheduler wake per packet) is gone.
    inbound_endpoint_rx: Arc<Mutex<EndpointReceiveState>>,
    /// Cache of resolved PeerIdentity by npub string. Avoids the per-packet
    /// secp256k1 EC point parse that `PeerIdentity::from_npub` performs;
    /// without this cache the bulk-data send hot path spends ~10–30% of CPU
    /// re-validating identity bytes the application has already configured.
    peer_identity_cache: std::sync::Mutex<std::collections::HashMap<String, PeerIdentity>>,
    shutdown_tx: Option<oneshot::Sender<()>>,
    task: JoinHandle<Result<(), NodeError>>,
}

impl FipsEndpoint {
    /// Create a builder for an embedded endpoint.
    pub fn builder() -> FipsEndpointBuilder {
        FipsEndpointBuilder::default()
    }

    /// Local endpoint npub.
    pub fn npub(&self) -> &str {
        &self.npub
    }

    /// Local FIPS node address.
    pub fn node_addr(&self) -> &NodeAddr {
        &self.node_addr
    }

    /// Local FIPS IPv6-compatible address.
    pub fn address(&self) -> FipsAddress {
        self.address
    }

    /// Application-level discovery scope, if configured.
    pub fn discovery_scope(&self) -> Option<&str> {
        self.discovery_scope.as_deref()
    }

    /// Send application-owned endpoint data to a remote npub.
    ///
    /// Fire-and-forget: enqueues the Send command on the node task and
    /// returns once the command channel accepts it. The node task's send
    /// result is discarded — TCP and the upper protocol handle loss
    /// recovery, and the per-packet oneshot round-trip the previous design
    /// used for error reporting added several hundred microseconds of
    /// queueing latency under load (measured: 456ms avg ping under iperf3
    /// saturation → 1ms after this change, 430× lower).
    ///
    /// PeerIdentity for `remote_npub` is cached after first resolution to
    /// avoid the secp256k1 EC point parse on every packet.
    pub async fn send(
        &self,
        remote_npub: impl Into<String>,
        data: impl Into<Vec<u8>>,
    ) -> Result<(), FipsEndpointError> {
        let remote_npub = remote_npub.into();
        let data = data.into();
        if remote_npub == self.npub {
            return self.send_loopback(data);
        }

        let remote = self.resolve_peer_identity(&remote_npub)?;
        self.send_to_peer(remote, data).await
    }

    /// Send application-owned endpoint data to a resolved remote identity.
    ///
    /// This is the fast path for applications that already validate and cache
    /// peer identities in their own routing table. It avoids per-packet npub
    /// allocation, endpoint cache lookup, and `PeerIdentity::from_npub` parsing
    /// while preserving the same owned-payload command semantics as [`Self::send`].
    pub async fn send_to_peer(
        &self,
        remote: PeerIdentity,
        data: impl Into<Vec<u8>>,
    ) -> Result<(), FipsEndpointError> {
        let data = data.into();
        if *remote.node_addr() == self.node_addr {
            return self.send_loopback(data);
        }
        // Fire-and-forget: caller already drops the result, so skip
        // the per-packet `oneshot::channel()` allocation entirely.
        // The node task's `SendOneway` arm runs the same code path as
        // `Send` but without writing the result into a oneshot.
        let command = NodeEndpointCommand::send_oneway(remote, data, crate::perf_profile::stamp());
        send_endpoint_command(
            command,
            &self.endpoint_priority_commands,
            &self.endpoint_commands,
        )
        .await?;
        Ok(())
    }

    /// Send a burst of application-owned endpoint payloads to one resolved peer.
    ///
    /// Raw payloads are classified once, then enqueued as bounded lane batches
    /// instead of one command per packet. Callers that already classified packets
    /// while staging their own queues can use [`Self::send_classified_batch_to_peer`].
    pub async fn send_batch_to_peer(
        &self,
        remote: PeerIdentity,
        payloads: Vec<Vec<u8>>,
    ) -> Result<(), FipsEndpointError> {
        let payloads = payloads.into_iter().map(FipsEndpointPayload::new).collect();
        self.send_classified_batch_to_peer(remote, payloads).await
    }

    /// Send a burst of already-classified endpoint payloads to one resolved peer.
    pub async fn send_classified_batch_to_peer(
        &self,
        remote: PeerIdentity,
        payloads: Vec<FipsEndpointPayload>,
    ) -> Result<(), FipsEndpointError> {
        if *remote.node_addr() == self.node_addr {
            for payload in payloads {
                self.send_loopback(payload.into_bytes())?;
            }
            return Ok(());
        }

        let queued_at = crate::perf_profile::stamp();
        match endpoint_payload_lane_batches(payloads) {
            EndpointPayloadLaneBatches::Empty => {}
            EndpointPayloadLaneBatches::Single { lane, payloads } => {
                self.send_endpoint_command_batch(remote, payloads, queued_at, lane)
                    .await?;
            }
            EndpointPayloadLaneBatches::Split {
                priority_payloads,
                bulk_payloads,
            } => {
                self.send_endpoint_command_batch(
                    remote,
                    priority_payloads,
                    queued_at,
                    EndpointCommandLane::Priority,
                )
                .await?;
                self.send_endpoint_command_batch(
                    remote,
                    bulk_payloads,
                    queued_at,
                    EndpointCommandLane::Bulk,
                )
                .await?;
            }
        }
        Ok(())
    }

    async fn send_endpoint_command_batch(
        &self,
        remote: PeerIdentity,
        mut payloads: Vec<EndpointDataPayload>,
        queued_at: Option<crate::perf_profile::TraceStamp>,
        lane: EndpointCommandLane,
    ) -> Result<(), FipsEndpointError> {
        while !payloads.is_empty() {
            let tail = if payloads.len() > ENDPOINT_SEND_BATCH_COMMAND_MAX {
                payloads.split_off(ENDPOINT_SEND_BATCH_COMMAND_MAX)
            } else {
                Vec::new()
            };
            let batch = std::mem::replace(&mut payloads, tail);
            let Some(command) =
                NodeEndpointCommand::send_batch_oneway(remote, batch, queued_at, lane)
            else {
                continue;
            };
            send_endpoint_command(
                command,
                &self.endpoint_priority_commands,
                &self.endpoint_commands,
            )
            .await?;
        }
        Ok(())
    }

    fn resolve_peer_identity(&self, remote_npub: &str) -> Result<PeerIdentity, FipsEndpointError> {
        // Fast path: cached identity (PeerIdentity is Copy after eager
        // pubkey_full precompute landed in b1e92af, so dereference is free).
        if let Ok(cache) = self.peer_identity_cache.lock()
            && let Some(remote) = cache.get(remote_npub)
        {
            return Ok(*remote);
        }

        let remote = PeerIdentity::from_npub(remote_npub).map_err(|error| {
            FipsEndpointError::InvalidRemoteNpub {
                npub: remote_npub.to_string(),
                reason: error.to_string(),
            }
        })?;

        if let Ok(mut cache) = self.peer_identity_cache.lock() {
            cache.entry(remote_npub.to_string()).or_insert(remote);
        }
        Ok(remote)
    }

    fn send_loopback(&self, data: Vec<u8>) -> Result<(), FipsEndpointError> {
        self.inbound_endpoint_tx
            .send(NodeEndpointEvent::Data {
                source_peer: self.identity,
                payload: data,
                queued_at: crate::perf_profile::stamp(),
            })
            .map_err(|_| FipsEndpointError::Closed)
    }

    /// Receive the next source-attributed endpoint data message.
    ///
    /// Translation from the internal `NodeEndpointEvent::Data` shape to
    /// the public `FipsEndpointMessage` shape happens inline here — the
    /// rx_loop pushes directly onto this channel, no relay task in
    /// between, no extra cross-task hop per packet.
    pub async fn recv(&self) -> Option<FipsEndpointMessage> {
        let mut state = self.inbound_endpoint_rx.lock().await;
        if let Some(message) = state.pop_pending_priority() {
            return Some(message);
        }
        if let Ok(event) = state.rx.try_recv_priority() {
            return state.first_from_event(event);
        }
        if let Some(message) = state.pop_pending_bulk() {
            return Some(message);
        }
        let event = state.rx.recv().await?;
        state.first_from_event(event)
    }

    /// Receive one endpoint message, then drain currently queued follow-ons.
    ///
    /// This is the receive-side counterpart to [`Self::send_batch_to_peer`]:
    /// callers still get individual source-attributed messages, but a hot
    /// dataplane consumer can amortize the endpoint receiver lock and task wake
    /// across a bounded burst.
    pub async fn recv_batch(&self, max: usize) -> Option<Vec<FipsEndpointMessage>> {
        let max = max.clamp(1, ENDPOINT_RECV_BATCH_MAX);
        let mut messages = Vec::with_capacity(max);
        self.recv_batch_into(&mut messages, max).await?;
        Some(messages)
    }

    /// Receive one endpoint message, then drain ready follow-ons into a caller-owned buffer.
    ///
    /// This is the allocation-conscious form of [`Self::recv_batch`] for hot
    /// dataplane consumers. The provided buffer is cleared before use and keeps
    /// its allocation across calls.
    pub async fn recv_batch_into(
        &self,
        messages: &mut Vec<FipsEndpointMessage>,
        max: usize,
    ) -> Option<usize> {
        let max = max.clamp(1, ENDPOINT_RECV_BATCH_MAX);
        messages.clear();

        let mut state = self.inbound_endpoint_rx.lock().await;
        state.drain_priority_pending_into(messages, max);
        while messages.len() < max {
            match state.rx.try_recv_priority() {
                Ok(event) => state.push_event_into(event, messages, max),
                Err(_) => break,
            }
        }
        state.drain_bulk_pending_into(messages, max);

        while messages.len() < max {
            let event = if messages.is_empty() {
                state.rx.recv().await?
            } else {
                match state.rx.try_recv() {
                    Ok(event) => event,
                    Err(_) => break,
                }
            };
            state.push_event_into(event, messages, max);
        }

        Some(messages.len())
    }

    /// Synchronous blocking send — parks the calling **OS thread** on
    /// the FIPS endpoint command channel until the runtime accepts
    /// the send. MUST be called only from a thread spawned via
    /// `std::thread::spawn`, not from inside a tokio runtime.
    ///
    /// Companion to [`Self::blocking_recv`] for control-frame replies
    /// (e.g. responding to a Ping with a Pong) issued from the
    /// dedicated TUN-write thread. Failures are returned via
    /// `FipsEndpointError::Closed` if the runtime has stopped.
    pub fn blocking_send(
        &self,
        remote_npub: impl Into<String>,
        data: impl Into<Vec<u8>>,
    ) -> Result<(), FipsEndpointError> {
        let remote_npub = remote_npub.into();
        let data = data.into();
        if remote_npub == self.npub {
            return self.send_loopback(data);
        }
        let remote = self.resolve_peer_identity(&remote_npub)?;
        self.blocking_send_to_peer(remote, data)
    }

    /// Synchronous blocking send to a resolved remote identity.
    ///
    /// This mirrors [`Self::send_to_peer`] for callers that already own a
    /// `PeerIdentity` but need to use the blocking endpoint command path.
    pub fn blocking_send_to_peer(
        &self,
        remote: PeerIdentity,
        data: impl Into<Vec<u8>>,
    ) -> Result<(), FipsEndpointError> {
        let data = data.into();
        if *remote.node_addr() == self.node_addr {
            return self.send_loopback(data);
        }
        let (response_tx, _response_rx) = oneshot::channel();
        let command =
            NodeEndpointCommand::send(remote, data, crate::perf_profile::stamp(), response_tx);
        endpoint_command_tx_for_command(
            &command,
            &self.endpoint_priority_commands,
            &self.endpoint_commands,
        )
        .blocking_send(command)
        .map_err(|_| FipsEndpointError::Closed)?;
        Ok(())
    }

    /// Synchronous blocking receive — parks the calling **OS thread**
    /// on the channel until an event arrives or the channel closes.
    ///
    /// MUST NOT be called from inside a tokio runtime; use this only
    /// from a thread spawned via `std::thread::spawn` so the tokio
    /// scheduler doesn't deadlock.
    ///
    /// The motivation is the bench's CLI receive task: when run as a
    /// regular tokio task each `recv().await` is a full task-wake on
    /// the runtime (~1–3 µs scheduler bookkeeping), and at 113 kpps
    /// that's ~10–30% of one core spent in plumbing the wake-up
    /// rather than writing the packet to TUN. A dedicated OS thread
    /// blocked on the channel via `blocking_recv` parks on a futex
    /// directly — the wake is a single futex_wake() with no scheduler
    /// involvement, an order of magnitude cheaper.
    pub fn blocking_recv(&self) -> Option<FipsEndpointMessage> {
        let mut state = self.inbound_endpoint_rx.blocking_lock();
        if let Some(message) = state.pop_pending_priority() {
            return Some(message);
        }
        if let Ok(event) = state.rx.try_recv_priority() {
            return state.first_from_event(event);
        }
        if let Some(message) = state.pop_pending_bulk() {
            return Some(message);
        }
        let event = state.rx.blocking_recv()?;
        state.first_from_event(event)
    }

    /// Synchronous blocking batch receive into a caller-owned buffer.
    ///
    /// This is the blocking-thread counterpart to [`Self::recv_batch_into`]:
    /// it parks the calling **OS thread** for the first message, then drains
    /// ready follow-ons while holding the endpoint receiver lock. MUST NOT be
    /// called from inside a tokio runtime; use this only from a dedicated
    /// blocking thread.
    pub fn blocking_recv_batch_into(
        &self,
        messages: &mut Vec<FipsEndpointMessage>,
        max: usize,
    ) -> Option<usize> {
        messages.clear();
        self.blocking_recv_batch_for_each(max, |message| {
            messages.push(message);
            true
        })
    }

    /// Synchronous blocking batch receive that invokes a callback for each
    /// delivered endpoint message without staging them in a caller-owned
    /// `Vec`.
    ///
    /// This is for dedicated packet-mover threads that immediately forward
    /// messages onward. It preserves the same priority-before-bulk ordering,
    /// internal batch-tail handling, and receive limit as
    /// [`Self::blocking_recv_batch_into`]. Returning `false` from the callback
    /// stops the current drain after that message; any unconsumed messages from
    /// the current internal batch are retained for the next receive.
    pub fn blocking_recv_batch_for_each(
        &self,
        max: usize,
        mut handle_message: impl FnMut(FipsEndpointMessage) -> bool,
    ) -> Option<usize> {
        let max = max.clamp(1, ENDPOINT_RECV_BATCH_MAX);
        let mut drained = 0usize;

        let mut state = self.inbound_endpoint_rx.blocking_lock();
        if !state.drain_priority_pending_for_each(&mut drained, max, &mut handle_message) {
            return Some(drained);
        }
        while drained < max {
            match state.rx.try_recv_priority() {
                Ok(event) => {
                    if !state.push_event_for_each(event, &mut drained, max, &mut handle_message) {
                        return Some(drained);
                    }
                }
                Err(_) => break,
            }
        }
        if !state.drain_bulk_pending_for_each(&mut drained, max, &mut handle_message) {
            return Some(drained);
        }

        while drained < max {
            let event = if drained == 0 {
                state.rx.blocking_recv()?
            } else {
                match state.rx.try_recv() {
                    Ok(event) => event,
                    Err(_) => break,
                }
            };
            if !state.push_event_for_each(event, &mut drained, max, &mut handle_message) {
                return Some(drained);
            }
        }

        Some(drained)
    }

    /// Non-blocking receive — returns the next ready endpoint message
    /// if one is queued, otherwise `None`. Pair with `recv()` to drain
    /// follow-on packets without paying a scheduler wake per packet:
    ///
    /// ```ignore
    /// // wake on the first packet, then drain everything ready
    /// while let Some(msg) = endpoint.recv().await { process(msg); }
    /// while let Some(msg) = endpoint.try_recv() { process(msg); }
    /// ```
    ///
    /// On the bench's FIPS-tunnel receive path the kernel UDP socket
    /// delivers packets in `recvmmsg`-sized bursts, so after a `.recv()`
    /// await there are typically 5–30 packets queued waiting. Draining
    /// them inline with `try_recv` saves N-1 scheduler hops per burst
    /// at line rate, freeing the consumer task to spend its time on
    /// the TUN write syscall instead of cross-task plumbing.
    ///
    /// Returns `None` if the channel is empty, closed, or briefly
    /// contested by another consumer.
    pub fn try_recv(&self) -> Option<FipsEndpointMessage> {
        let mut state = self.inbound_endpoint_rx.try_lock().ok()?;
        if let Some(message) = state.pop_pending_priority() {
            return Some(message);
        }
        if let Ok(event) = state.rx.try_recv_priority() {
            return state.first_from_event(event);
        }
        if let Some(message) = state.pop_pending_bulk() {
            return Some(message);
        }
        let event = state.rx.try_recv().ok()?;
        state.first_from_event(event)
    }

    /// Replace the runtime peer list. Newly added auto-connect peers get
    /// dialed immediately using every known address (overlay-fresh first,
    /// then operator/cache hints). Removed peers are dropped from the
    /// retry queue but stay connected if they currently are — the regular
    /// liveness timeout reaps idle sessions. Existing entries get their
    /// `addresses` field refreshed so the next retry sees the latest hints.
    ///
    /// Pass an empty `addresses` vector for a peer if you want fips to
    /// resolve them entirely from the Nostr advert at dial time.
    pub async fn update_peers(
        &self,
        peers: Vec<crate::config::PeerConfig>,
    ) -> Result<UpdatePeersOutcome, FipsEndpointError> {
        let (response_tx, response_rx) = oneshot::channel();
        self.endpoint_priority_commands
            .send(NodeEndpointCommand::UpdatePeers { peers, response_tx })
            .await
            .map_err(|_| FipsEndpointError::Closed)?;

        match response_rx.await.map_err(|_| FipsEndpointError::Closed)? {
            Ok(outcome) => Ok(UpdatePeersOutcome::from(outcome)),
            Err(error) => Err(FipsEndpointError::Node(error)),
        }
    }

    /// Snapshot authenticated peers known by the endpoint.
    pub async fn peers(&self) -> Result<Vec<FipsEndpointPeer>, FipsEndpointError> {
        let (response_tx, response_rx) = oneshot::channel();
        self.endpoint_priority_commands
            .send(NodeEndpointCommand::PeerSnapshot { response_tx })
            .await
            .map_err(|_| FipsEndpointError::Closed)?;

        response_rx
            .await
            .map(|peers| peers.into_iter().map(FipsEndpointPeer::from).collect())
            .map_err(|_| FipsEndpointError::Closed)
    }

    /// Snapshot live Nostr relay states used by the embedded endpoint.
    pub async fn relay_statuses(&self) -> Result<Vec<FipsEndpointRelayStatus>, FipsEndpointError> {
        let (response_tx, response_rx) = oneshot::channel();
        self.endpoint_priority_commands
            .send(NodeEndpointCommand::RelaySnapshot { response_tx })
            .await
            .map_err(|_| FipsEndpointError::Closed)?;

        response_rx
            .await
            .map(|relays| {
                relays
                    .into_iter()
                    .map(FipsEndpointRelayStatus::from)
                    .collect()
            })
            .map_err(|_| FipsEndpointError::Closed)
    }

    /// Replace Nostr discovery relays without rebuilding the endpoint.
    pub async fn update_relays(
        &self,
        advert_relays: Vec<String>,
        dm_relays: Vec<String>,
    ) -> Result<(), FipsEndpointError> {
        let (response_tx, response_rx) = oneshot::channel();
        self.endpoint_priority_commands
            .send(NodeEndpointCommand::UpdateRelays {
                advert_relays,
                dm_relays,
                response_tx,
            })
            .await
            .map_err(|_| FipsEndpointError::Closed)?;

        response_rx
            .await
            .map_err(|_| FipsEndpointError::Closed)?
            .map_err(FipsEndpointError::Node)
    }

    /// Send an outbound IPv6 packet into the FIPS session pipeline.
    pub async fn send_ip_packet(
        &self,
        packet: impl Into<Vec<u8>>,
    ) -> Result<(), FipsEndpointError> {
        self.outbound_packets
            .send(packet.into())
            .await
            .map_err(|_| FipsEndpointError::Closed)
    }

    /// Receive the next source-attributed IPv6 packet delivered by FIPS.
    pub async fn recv_ip_packet(&self) -> Option<NodeDeliveredPacket> {
        self.delivered_packets.lock().await.recv().await
    }

    /// Shut down the endpoint and wait for the node task to stop.
    pub async fn shutdown(mut self) -> Result<(), FipsEndpointError> {
        if let Some(shutdown_tx) = self.shutdown_tx.take() {
            let _ = shutdown_tx.send(());
        }
        self.task.await??;
        Ok(())
    }
}

fn endpoint_command_tx_for_command<'a>(
    command: &NodeEndpointCommand,
    priority_tx: &'a mpsc::Sender<NodeEndpointCommand>,
    bulk_tx: &'a mpsc::Sender<NodeEndpointCommand>,
) -> &'a mpsc::Sender<NodeEndpointCommand> {
    match command.lane() {
        EndpointCommandLane::Priority => priority_tx,
        EndpointCommandLane::Bulk => bulk_tx,
    }
}

fn endpoint_payload_lane_batches(payloads: Vec<FipsEndpointPayload>) -> EndpointPayloadLaneBatches {
    let payload_count = payloads.len();
    let mut raw_payloads = payloads.into_iter();
    let Some(first) = raw_payloads.next() else {
        return EndpointPayloadLaneBatches::Empty;
    };

    let first = EndpointDataPayload::from(first);
    let mut first_lane_payloads = Vec::with_capacity(payload_count);
    let first_lane = first.lane();
    first_lane_payloads.push(first);
    let mut batches = EndpointPayloadLaneBatches::Single {
        lane: first_lane,
        payloads: first_lane_payloads,
    };

    for payload in raw_payloads.map(EndpointDataPayload::from) {
        let payload_lane = payload.lane();
        match &mut batches {
            EndpointPayloadLaneBatches::Empty => unreachable!("first payload exists"),
            EndpointPayloadLaneBatches::Single { lane, payloads } if payload_lane == *lane => {
                payloads.push(payload);
            }
            EndpointPayloadLaneBatches::Single { lane, payloads } => {
                let first_lane_payloads = std::mem::take(payloads);
                let mut priority_payloads = Vec::new();
                let mut bulk_payloads = Vec::new();
                match *lane {
                    EndpointCommandLane::Priority => priority_payloads = first_lane_payloads,
                    EndpointCommandLane::Bulk => bulk_payloads = first_lane_payloads,
                }
                match payload_lane {
                    EndpointCommandLane::Priority => priority_payloads.push(payload),
                    EndpointCommandLane::Bulk => bulk_payloads.push(payload),
                }
                batches = EndpointPayloadLaneBatches::Split {
                    priority_payloads,
                    bulk_payloads,
                };
            }
            EndpointPayloadLaneBatches::Split {
                priority_payloads,
                bulk_payloads,
            } => match payload_lane {
                EndpointCommandLane::Priority => priority_payloads.push(payload),
                EndpointCommandLane::Bulk => bulk_payloads.push(payload),
            },
        }
    }

    batches
}

async fn send_endpoint_command(
    command: NodeEndpointCommand,
    priority_tx: &mpsc::Sender<NodeEndpointCommand>,
    bulk_tx: &mpsc::Sender<NodeEndpointCommand>,
) -> Result<(), FipsEndpointError> {
    let command_tx = endpoint_command_tx_for_command(&command, priority_tx, bulk_tx);

    if command.drop_on_backpressure() {
        match command_tx.try_send(command) {
            Ok(()) => return Ok(()),
            Err(mpsc::error::TrySendError::Full(command)) => {
                crate::perf_profile::record_event_count(
                    crate::perf_profile::Event::EndpointCommandBulkDropped,
                    command.drain_cost() as u64,
                );
                return Ok(());
            }
            Err(mpsc::error::TrySendError::Closed(_)) => return Err(FipsEndpointError::Closed),
        }
    }

    command_tx
        .send(command)
        .await
        .map_err(|_| FipsEndpointError::Closed)
}
