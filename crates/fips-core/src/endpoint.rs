//! Library-first endpoint API for embedding FIPS in applications.
//!
//! This module exposes a no-system-TUN runtime shape for apps that want to own
//! peer admission and local routing policy while reusing FIPS connectivity.

use crate::config::{EthernetConfig, NostrDiscoveryPolicy, TransportInstances, UdpConfig};
use crate::node::{
    ENDPOINT_EVENT_PRIORITY_MAX_LEN, EndpointCommandLane, EndpointDataPayload,
    EndpointEventReceiver, EndpointEventSender, NodeEndpointCommand, NodeEndpointEvent,
    NodeEndpointPeer, NodeEndpointRelayStatus,
};
use crate::{
    Config, FipsAddress, IdentityConfig, Node, NodeAddr, NodeDeliveredPacket, NodeError,
    PeerIdentity,
};
use std::collections::VecDeque;
use std::sync::Arc;
use thiserror::Error;
use tokio::sync::{Mutex, mpsc, oneshot};
use tokio::task::JoinHandle;

const ENDPOINT_SEND_BATCH_COMMAND_MAX: usize = 64;
const ENDPOINT_RECV_BATCH_MAX: usize = 128;

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

struct EndpointQueuedMessage {
    source_peer: PeerIdentity,
    payload: Vec<u8>,
}

impl EndpointQueuedMessage {
    fn new(source_peer: PeerIdentity, payload: Vec<u8>) -> Self {
        Self {
            source_peer,
            payload,
        }
    }

    fn into_public(self) -> FipsEndpointMessage {
        FipsEndpointMessage {
            source_peer: self.source_peer,
            data: self.payload,
        }
    }
}

struct EndpointReceiveState {
    rx: EndpointEventReceiver,
    pending_priority: VecDeque<EndpointQueuedMessage>,
    pending_bulk: VecDeque<EndpointQueuedMessage>,
}

impl EndpointReceiveState {
    fn new(rx: EndpointEventReceiver) -> Self {
        Self {
            rx,
            pending_priority: VecDeque::new(),
            pending_bulk: VecDeque::new(),
        }
    }

    fn pop_pending_priority(&mut self) -> Option<FipsEndpointMessage> {
        self.pending_priority
            .pop_front()
            .map(EndpointQueuedMessage::into_public)
    }

    fn pop_pending_bulk(&mut self) -> Option<FipsEndpointMessage> {
        self.pending_bulk
            .pop_front()
            .map(EndpointQueuedMessage::into_public)
    }

    fn drain_priority_pending_into(&mut self, out: &mut Vec<FipsEndpointMessage>, limit: usize) {
        while out.len() < limit {
            let Some(message) = self.pop_pending_priority() else {
                break;
            };
            out.push(message);
        }
    }

    fn drain_bulk_pending_into(&mut self, out: &mut Vec<FipsEndpointMessage>, limit: usize) {
        while out.len() < limit {
            let Some(message) = self.pending_bulk.pop_front() else {
                break;
            };
            out.push(message.into_public());
        }
    }

    fn drain_priority_pending_for_each(
        &mut self,
        drained: &mut usize,
        limit: usize,
        handle_message: &mut impl FnMut(FipsEndpointMessage) -> bool,
    ) -> bool {
        while *drained < limit {
            let Some(message) = self.pop_pending_priority() else {
                break;
            };
            *drained += 1;
            if !handle_message(message) {
                return false;
            }
        }
        true
    }

    fn drain_bulk_pending_for_each(
        &mut self,
        drained: &mut usize,
        limit: usize,
        handle_message: &mut impl FnMut(FipsEndpointMessage) -> bool,
    ) -> bool {
        while *drained < limit {
            let Some(message) = self.pop_pending_bulk() else {
                break;
            };
            *drained += 1;
            if !handle_message(message) {
                return false;
            }
        }
        true
    }

    fn push_event_into(
        &mut self,
        event: NodeEndpointEvent,
        out: &mut Vec<FipsEndpointMessage>,
        limit: usize,
    ) {
        match event {
            NodeEndpointEvent::Data {
                source_peer,
                payload,
                ..
            } => {
                self.push_queued_into(EndpointQueuedMessage::new(source_peer, payload), out, limit)
            }
            NodeEndpointEvent::DataBatch { messages, .. } => {
                for message in messages {
                    self.push_queued_into(
                        EndpointQueuedMessage::new(message.source_peer, message.payload),
                        out,
                        limit,
                    );
                }
            }
        }
    }

    fn push_queued_into(
        &mut self,
        message: EndpointQueuedMessage,
        out: &mut Vec<FipsEndpointMessage>,
        limit: usize,
    ) {
        if out.len() < limit {
            out.push(message.into_public());
        } else if message.payload.len() <= ENDPOINT_EVENT_PRIORITY_MAX_LEN {
            self.pending_priority.push_back(message);
        } else {
            self.pending_bulk.push_back(message);
        }
    }

    fn push_pending(&mut self, message: EndpointQueuedMessage) {
        if message.payload.len() <= ENDPOINT_EVENT_PRIORITY_MAX_LEN {
            self.pending_priority.push_back(message);
        } else {
            self.pending_bulk.push_back(message);
        }
    }

    fn push_event_for_each(
        &mut self,
        event: NodeEndpointEvent,
        drained: &mut usize,
        limit: usize,
        handle_message: &mut impl FnMut(FipsEndpointMessage) -> bool,
    ) -> bool {
        match event {
            NodeEndpointEvent::Data {
                source_peer,
                payload,
                ..
            } => self.push_queued_for_each(
                EndpointQueuedMessage::new(source_peer, payload),
                drained,
                limit,
                handle_message,
            ),
            NodeEndpointEvent::DataBatch { messages, .. } => {
                let mut iter = messages.into_iter();
                while let Some(message) = iter.next() {
                    let queued = EndpointQueuedMessage::new(message.source_peer, message.payload);
                    if !self.push_queued_for_each(queued, drained, limit, handle_message) {
                        for message in iter {
                            self.push_pending(EndpointQueuedMessage::new(
                                message.source_peer,
                                message.payload,
                            ));
                        }
                        return false;
                    }
                }
                true
            }
        }
    }

    fn push_queued_for_each(
        &mut self,
        message: EndpointQueuedMessage,
        drained: &mut usize,
        limit: usize,
        handle_message: &mut impl FnMut(FipsEndpointMessage) -> bool,
    ) -> bool {
        if *drained < limit {
            *drained += 1;
            handle_message(message.into_public())
        } else {
            self.push_pending(message);
            false
        }
    }

    fn first_from_event(&mut self, event: NodeEndpointEvent) -> Option<FipsEndpointMessage> {
        let mut messages = Vec::with_capacity(1);
        self.push_event_into(event, &mut messages, 1);
        messages.pop()
    }
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

/// Authenticated FIPS peer state visible to an embedded application.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FipsEndpointPeer {
    /// Peer Nostr public key.
    pub npub: String,
    /// Peer FIPS node address, derived from the public key and stable across npub encodings.
    pub node_addr: NodeAddr,
    /// Whether an authenticated link-layer peer is currently active.
    pub connected: bool,
    /// Current underlay transport address, when a link has authenticated.
    pub transport_addr: Option<String>,
    /// Current underlay transport kind, when known.
    pub transport_type: Option<String>,
    /// Authenticated link id.
    pub link_id: u64,
    /// Smoothed RTT in milliseconds, once measured by FIPS MMP.
    pub srtt_ms: Option<u64>,
    /// Link packets sent.
    pub packets_sent: u64,
    /// Link packets received.
    pub packets_recv: u64,
    /// Link bytes sent.
    pub bytes_sent: u64,
    /// Link bytes received.
    pub bytes_recv: u64,
    /// Whether a link-layer rekey is currently in progress.
    pub rekey_in_progress: bool,
    /// Whether this peer is draining an old key during rekey.
    pub rekey_draining: bool,
    /// Current link-layer key bit for active peers.
    pub current_k_bit: Option<bool>,
    /// Whether direct UDP probing is queued while this peer may still be
    /// reachable through a fallback transport.
    pub direct_probe_pending: bool,
    /// Millisecond timestamp when the queued direct probe becomes eligible.
    pub direct_probe_after_ms: Option<u64>,
    /// Number of direct probe/retry attempts accumulated for this peer.
    pub direct_probe_retry_count: u32,
    /// Whether the queued direct probe is an unlimited auto-reconnect.
    pub direct_probe_auto_reconnect: bool,
    /// Millisecond timestamp when a bounded direct probe/retry entry expires.
    pub direct_probe_expires_at_ms: Option<u64>,
    /// Consecutive Nostr traversal failures recorded for this peer.
    pub nostr_traversal_consecutive_failures: u32,
    /// Whether Nostr traversal is currently cooling down for this peer.
    pub nostr_traversal_in_cooldown: bool,
    /// Millisecond timestamp when Nostr traversal cooldown ends.
    pub nostr_traversal_cooldown_until_ms: Option<u64>,
    /// Last observed Nostr timestamp skew in milliseconds for this peer.
    pub nostr_traversal_last_observed_skew_ms: Option<i64>,
}

/// Live Nostr relay state visible to an embedded application.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FipsEndpointRelayStatus {
    pub url: String,
    pub status: String,
}

/// Builder for an embedded FIPS endpoint.
#[derive(Debug, Clone)]
pub struct FipsEndpointBuilder {
    config: Config,
    identity_nsec: Option<String>,
    discovery_scope: Option<String>,
    local_ethernet_interfaces: Vec<String>,
    disable_system_networking: bool,
    packet_channel_capacity: usize,
}

impl Default for FipsEndpointBuilder {
    fn default() -> Self {
        Self {
            config: Config::new(),
            identity_nsec: None,
            discovery_scope: None,
            local_ethernet_interfaces: Vec::new(),
            disable_system_networking: true,
            packet_channel_capacity: 1024,
        }
    }
}

impl FipsEndpointBuilder {
    /// Start from an explicit FIPS config.
    pub fn config(mut self, config: Config) -> Self {
        self.config = config;
        self
    }

    /// Use an `nsec` or hex secret for the endpoint identity.
    pub fn identity_nsec(mut self, nsec: impl Into<String>) -> Self {
        self.identity_nsec = Some(nsec.into());
        self
    }

    /// Set an application-level discovery scope.
    ///
    /// When the builder owns the default empty connectivity config, this also
    /// enables scoped Nostr discovery, open same-scope peer discovery, local
    /// LAN candidates, and a UDP NAT advert. If an explicit transport or
    /// Nostr config was supplied, the explicit config is left in control and
    /// the scope is retained as endpoint metadata.
    pub fn discovery_scope(mut self, scope: impl Into<String>) -> Self {
        self.discovery_scope = Some(scope.into());
        self
    }

    /// Enable host-local Ethernet discovery on a private L2 interface.
    ///
    /// This is intended for veth/TAP interfaces attached to a per-host bridge
    /// shared by FIPS-aware applications. The endpoint announces Ethernet
    /// beacons, listens for matching peers, auto-connects to them, and accepts
    /// inbound handshakes over the interface.
    pub fn local_ethernet(mut self, interface: impl Into<String>) -> Self {
        self.local_ethernet_interfaces.push(interface.into());
        self
    }

    /// Disable FIPS-owned TUN and DNS system integration.
    pub fn without_system_tun(mut self) -> Self {
        self.disable_system_networking = true;
        self
    }

    /// Set the app packet/data channel capacity.
    pub fn packet_channel_capacity(mut self, capacity: usize) -> Self {
        self.packet_channel_capacity = capacity.max(1);
        self
    }

    fn prepared_config(&self) -> Config {
        let mut config = self.config.clone();
        if let Some(nsec) = &self.identity_nsec {
            config.node.identity = IdentityConfig {
                nsec: Some(nsec.clone()),
                persistent: false,
            };
        }
        if self.disable_system_networking {
            config.tun.enabled = false;
            config.dns.enabled = false;
            config.node.system_files_enabled = false;
        }
        if let Some(scope) = self.discovery_scope.as_deref() {
            config.node.discovery.lan.scope = Some(scope.to_string());
            config.node.discovery.local.enabled = true;
            apply_default_scoped_discovery(&mut config, scope);
        }
        for interface in &self.local_ethernet_interfaces {
            add_endpoint_ethernet_transport(
                &mut config,
                interface,
                self.discovery_scope.as_deref(),
            );
        }
        config
    }

    /// Bind and start the embedded endpoint.
    pub async fn bind(self) -> Result<FipsEndpoint, FipsEndpointError> {
        endpoint_debug_log("FipsEndpointBuilder::bind begin");
        let config = self.prepared_config();
        endpoint_debug_log("FipsEndpointBuilder::bind config prepared");

        let mut node = Node::new(config)?;
        endpoint_debug_log("FipsEndpointBuilder::bind node created");
        let identity = PeerIdentity::from_pubkey_full(node.identity().pubkey_full());
        let npub = identity.npub();
        let node_addr = *identity.node_addr();
        let address = *identity.address();
        let packet_io = node.attach_external_packet_io(self.packet_channel_capacity)?;
        endpoint_debug_log("FipsEndpointBuilder::bind packet io attached");
        let endpoint_data_io = node.attach_endpoint_data_io(self.packet_channel_capacity)?;
        endpoint_debug_log("FipsEndpointBuilder::bind endpoint data io attached");
        endpoint_debug_log("FipsEndpointBuilder::bind node.start begin");
        node.start().await?;
        endpoint_debug_log("FipsEndpointBuilder::bind node.start complete");

        let (shutdown_tx, shutdown_rx) = oneshot::channel();
        let task = spawn_node_task(node, shutdown_rx);
        endpoint_debug_log("FipsEndpointBuilder::bind node task spawned");
        let endpoint_priority_commands = endpoint_data_io.priority_command_tx;
        let endpoint_commands = endpoint_data_io.command_tx;

        Ok(FipsEndpoint {
            identity,
            npub,
            node_addr,
            address,
            discovery_scope: self.discovery_scope,
            outbound_packets: packet_io.outbound_tx,
            delivered_packets: Arc::new(Mutex::new(packet_io.inbound_rx)),
            endpoint_priority_commands,
            endpoint_commands,
            inbound_endpoint_tx: endpoint_data_io.event_tx,
            inbound_endpoint_rx: Arc::new(Mutex::new(EndpointReceiveState::new(
                endpoint_data_io.event_rx,
            ))),
            peer_identity_cache: std::sync::Mutex::new(std::collections::HashMap::new()),
            shutdown_tx: Some(shutdown_tx),
            task,
        })
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
    /// The endpoint still classifies each payload as priority or bulk, but it
    /// enqueues bounded lane batches instead of one command per packet.
    /// This is the dataplane fast path for callers that already route and batch
    /// packets by peer.
    pub async fn send_batch_to_peer(
        &self,
        remote: PeerIdentity,
        payloads: Vec<Vec<u8>>,
    ) -> Result<(), FipsEndpointError> {
        if *remote.node_addr() == self.node_addr {
            for payload in payloads {
                self.send_loopback(payload)?;
            }
            return Ok(());
        }

        let queued_at = crate::perf_profile::stamp();
        let mut priority_payloads = Vec::new();
        let mut bulk_payloads = Vec::new();

        for payload in payloads {
            let payload = EndpointDataPayload::new(payload);
            match payload.lane() {
                EndpointCommandLane::Priority => priority_payloads.push(payload),
                EndpointCommandLane::Bulk => bulk_payloads.push(payload),
            }
        }

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
        Ok(())
    }

    async fn send_endpoint_command_batch(
        &self,
        remote: PeerIdentity,
        mut payloads: Vec<EndpointDataPayload>,
        queued_at: Option<std::time::Instant>,
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

impl From<NodeEndpointPeer> for FipsEndpointPeer {
    fn from(peer: NodeEndpointPeer) -> Self {
        Self {
            npub: peer.npub,
            node_addr: peer.node_addr,
            connected: peer.connected,
            transport_addr: peer.transport_addr,
            transport_type: peer.transport_type,
            link_id: peer.link_id,
            srtt_ms: peer.srtt_ms,
            packets_sent: peer.packets_sent,
            packets_recv: peer.packets_recv,
            bytes_sent: peer.bytes_sent,
            bytes_recv: peer.bytes_recv,
            rekey_in_progress: peer.rekey_in_progress,
            rekey_draining: peer.rekey_draining,
            current_k_bit: peer.current_k_bit,
            direct_probe_pending: peer.direct_probe_pending,
            direct_probe_after_ms: peer.direct_probe_after_ms,
            direct_probe_retry_count: peer.direct_probe_retry_count,
            direct_probe_auto_reconnect: peer.direct_probe_auto_reconnect,
            direct_probe_expires_at_ms: peer.direct_probe_expires_at_ms,
            nostr_traversal_consecutive_failures: peer.nostr_traversal_consecutive_failures,
            nostr_traversal_in_cooldown: peer.nostr_traversal_in_cooldown,
            nostr_traversal_cooldown_until_ms: peer.nostr_traversal_cooldown_until_ms,
            nostr_traversal_last_observed_skew_ms: peer.nostr_traversal_last_observed_skew_ms,
        }
    }
}

impl From<NodeEndpointRelayStatus> for FipsEndpointRelayStatus {
    fn from(relay: NodeEndpointRelayStatus) -> Self {
        Self {
            url: relay.url,
            status: relay.status,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::node::{EndpointDataDelivery, NodeEndpointPeer};
    use std::time::Duration;

    fn ipv6_tcp_packet(flags: u8, tcp_payload_len: usize) -> Vec<u8> {
        let tcp_len = 20 + tcp_payload_len;
        let mut packet = vec![0u8; 40 + tcp_len];
        packet[0] = 0x60;
        packet[4..6].copy_from_slice(&(tcp_len as u16).to_be_bytes());
        packet[6] = 6;
        packet[40 + 12] = 5 << 4;
        packet[40 + 13] = flags;
        packet
    }

    fn ipv4_icmp_echo_packet() -> Vec<u8> {
        let mut packet = vec![0u8; 28];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&28u16.to_be_bytes());
        packet[9] = 1;
        packet[20] = 8;
        packet
    }

    #[test]
    fn endpoint_peer_conversion_preserves_rekey_state() {
        let peer = FipsEndpointPeer::from(NodeEndpointPeer {
            npub: "npub1peer".to_string(),
            node_addr: NodeAddr::from_bytes([7; 16]),
            connected: true,
            transport_addr: Some("127.0.0.1:9000".to_string()),
            transport_type: Some("udp".to_string()),
            link_id: 7,
            srtt_ms: Some(12),
            packets_sent: 3,
            packets_recv: 4,
            bytes_sent: 120,
            bytes_recv: 240,
            rekey_in_progress: true,
            rekey_draining: true,
            current_k_bit: Some(true),
            direct_probe_pending: false,
            direct_probe_after_ms: None,
            direct_probe_retry_count: 0,
            direct_probe_auto_reconnect: false,
            direct_probe_expires_at_ms: None,
            nostr_traversal_consecutive_failures: 2,
            nostr_traversal_in_cooldown: true,
            nostr_traversal_cooldown_until_ms: Some(1_234),
            nostr_traversal_last_observed_skew_ms: Some(-42),
        });

        assert!(peer.rekey_in_progress);
        assert!(peer.rekey_draining);
        assert_eq!(peer.current_k_bit, Some(true));
        assert_eq!(peer.nostr_traversal_consecutive_failures, 2);
        assert!(peer.nostr_traversal_in_cooldown);
        assert_eq!(peer.nostr_traversal_cooldown_until_ms, Some(1_234));
        assert_eq!(peer.nostr_traversal_last_observed_skew_ms, Some(-42));
    }

    #[test]
    fn endpoint_command_tx_helper_classifies_priority_and_bulk_payloads() {
        let (priority_tx, _priority_rx) = mpsc::channel(1);
        let (bulk_tx, _bulk_rx) = mpsc::channel(1);
        let remote = PeerIdentity::from_pubkey_full(crate::Identity::generate().pubkey_full());

        let tcp_ack = ipv6_tcp_packet(0x10, 0);
        let tcp_ack = NodeEndpointCommand::send_oneway(remote, tcp_ack, None);
        assert!(std::ptr::eq(
            endpoint_command_tx_for_command(&tcp_ack, &priority_tx, &bulk_tx),
            &priority_tx,
        ));

        let icmpv4_ping = ipv4_icmp_echo_packet();
        let icmpv4_ping = NodeEndpointCommand::send_oneway(remote, icmpv4_ping, None);
        assert!(std::ptr::eq(
            endpoint_command_tx_for_command(&icmpv4_ping, &priority_tx, &bulk_tx),
            &priority_tx,
        ));

        let bulk_tcp_data = ipv6_tcp_packet(0x18, 512);
        let bulk_tcp_data = NodeEndpointCommand::send_oneway(remote, bulk_tcp_data, None);
        assert!(std::ptr::eq(
            endpoint_command_tx_for_command(&bulk_tcp_data, &priority_tx, &bulk_tx),
            &bulk_tx,
        ));
    }

    #[test]
    fn endpoint_command_owns_lane_selected_at_construction() {
        let (priority_tx, _priority_rx) = mpsc::channel(1);
        let (bulk_tx, _bulk_rx) = mpsc::channel(1);
        let remote = PeerIdentity::from_pubkey_full(crate::Identity::generate().pubkey_full());

        let tcp_ack = ipv6_tcp_packet(0x10, 0);
        let priority_command = NodeEndpointCommand::send_oneway(remote, tcp_ack, None);
        assert_eq!(priority_command.lane(), EndpointCommandLane::Priority);
        assert!(std::ptr::eq(
            endpoint_command_tx_for_command(&priority_command, &priority_tx, &bulk_tx),
            &priority_tx,
        ));

        let bulk_tcp_data = ipv6_tcp_packet(0x18, 512);
        let bulk_command = NodeEndpointCommand::send_oneway(remote, bulk_tcp_data, None);
        assert_eq!(bulk_command.lane(), EndpointCommandLane::Bulk);
        assert!(std::ptr::eq(
            endpoint_command_tx_for_command(&bulk_command, &priority_tx, &bulk_tx),
            &bulk_tx,
        ));

        let batch_payload = crate::node::EndpointDataPayload::new(ipv6_tcp_packet(0x18, 512));
        let batch_command = NodeEndpointCommand::send_batch_oneway(
            remote,
            vec![batch_payload],
            None,
            EndpointCommandLane::Bulk,
        )
        .expect("non-empty batch command");
        assert_eq!(batch_command.lane(), EndpointCommandLane::Bulk);
        assert!(std::ptr::eq(
            endpoint_command_tx_for_command(&batch_command, &priority_tx, &bulk_tx),
            &bulk_tx,
        ));
    }

    #[test]
    fn endpoint_command_owns_discard_policy_selected_at_construction() {
        let remote = PeerIdentity::from_pubkey_full(crate::Identity::generate().pubkey_full());

        let priority_command =
            NodeEndpointCommand::send_oneway(remote, ipv6_tcp_packet(0x10, 0), None);
        assert_eq!(priority_command.lane(), EndpointCommandLane::Priority);
        assert!(!priority_command.drop_on_backpressure());

        let reliable_bulk =
            NodeEndpointCommand::send_oneway(remote, ipv6_tcp_packet(0x18, 512), None);
        assert_eq!(reliable_bulk.lane(), EndpointCommandLane::Bulk);
        assert!(!reliable_bulk.drop_on_backpressure());

        let discardable_bulk = NodeEndpointCommand::send_oneway(remote, vec![0, 1, 2, 3], None);
        assert_eq!(discardable_bulk.lane(), EndpointCommandLane::Bulk);
        assert!(discardable_bulk.drop_on_backpressure());

        let reliable_batch = NodeEndpointCommand::send_batch_oneway(
            remote,
            vec![
                crate::node::EndpointDataPayload::new(ipv6_tcp_packet(0x18, 512)),
                crate::node::EndpointDataPayload::new(vec![0, 1, 2, 3]),
            ],
            None,
            EndpointCommandLane::Bulk,
        )
        .expect("mixed bulk batch command");
        assert_eq!(reliable_batch.lane(), EndpointCommandLane::Bulk);
        assert!(!reliable_batch.drop_on_backpressure());

        let discardable_batch = NodeEndpointCommand::send_batch_oneway(
            remote,
            vec![
                crate::node::EndpointDataPayload::new(vec![0, 1, 2, 3]),
                crate::node::EndpointDataPayload::new(vec![4, 5, 6, 7]),
            ],
            None,
            EndpointCommandLane::Bulk,
        )
        .expect("discardable bulk batch command");
        assert_eq!(discardable_batch.lane(), EndpointCommandLane::Bulk);
        assert!(discardable_batch.drop_on_backpressure());
    }

    #[tokio::test]
    async fn endpoint_command_enqueue_drops_only_discardable_bulk_when_full() {
        let (priority_tx, _priority_rx) = mpsc::channel(1);
        let (bulk_tx, mut bulk_rx) = mpsc::channel(1);
        let remote = PeerIdentity::from_pubkey_full(crate::Identity::generate().pubkey_full());

        let queued_discardable = NodeEndpointCommand::send_oneway(remote, vec![0, 1, 2, 3], None);
        assert!(queued_discardable.drop_on_backpressure());
        bulk_tx
            .try_send(queued_discardable)
            .expect("bulk queue should accept the first command");

        let dropped_discardable = NodeEndpointCommand::send_oneway(remote, vec![4, 5, 6, 7], None);
        assert!(dropped_discardable.drop_on_backpressure());
        send_endpoint_command(dropped_discardable, &priority_tx, &bulk_tx)
            .await
            .expect("discardable bulk should be accepted as dropped");

        let first = bulk_rx
            .try_recv()
            .expect("only the first command should remain queued");
        assert!(first.drop_on_backpressure());
        assert!(matches!(
            bulk_rx.try_recv(),
            Err(mpsc::error::TryRecvError::Empty)
        ));

        let queued_reliable =
            NodeEndpointCommand::send_oneway(remote, ipv6_tcp_packet(0x18, 512), None);
        assert!(!queued_reliable.drop_on_backpressure());
        bulk_tx
            .try_send(queued_reliable)
            .expect("bulk queue should accept the reliable fill command");

        let waiting_reliable =
            NodeEndpointCommand::send_oneway(remote, ipv6_tcp_packet(0x18, 512), None);
        assert!(!waiting_reliable.drop_on_backpressure());
        let send_fut = send_endpoint_command(waiting_reliable, &priority_tx, &bulk_tx);
        tokio::pin!(send_fut);

        tokio::select! {
            result = &mut send_fut => panic!("reliable bulk must not be dropped: {result:?}"),
            _ = tokio::time::sleep(Duration::from_millis(20)) => {}
        }

        let first = bulk_rx
            .try_recv()
            .expect("free one bulk slot for the waiting reliable command");
        assert!(!first.drop_on_backpressure());

        tokio::time::timeout(Duration::from_secs(1), send_fut)
            .await
            .expect("reliable bulk send should complete once space is available")
            .expect("reliable bulk enqueue should succeed");

        let second = bulk_rx
            .try_recv()
            .expect("reliable command should enqueue after space is available");
        assert!(!second.drop_on_backpressure());
    }

    #[test]
    fn endpoint_send_command_owns_payload_lane_and_queue_stamp() {
        let remote = PeerIdentity::from_pubkey_full(crate::Identity::generate().pubkey_full());
        let payload = ipv6_tcp_packet(0x18, 512);
        let queued_at = Some(std::time::Instant::now());

        let command = crate::node::EndpointSendCommand::new(remote, payload.clone(), queued_at);
        assert_eq!(command.lane(), EndpointCommandLane::Bulk);

        let (owned_send, owned_queued_at) = command.into_parts();
        assert_eq!(owned_send.dest_addr(), *remote.node_addr());
        assert_eq!(owned_send.dest_pubkey(), remote.pubkey_full());
        assert_eq!(owned_send.payload().as_slice(), payload.as_slice());
        assert_eq!(owned_send.payload().lane(), EndpointCommandLane::Bulk);
        assert_eq!(owned_queued_at, queued_at);
    }

    #[test]
    fn endpoint_data_payload_owns_drop_policy_selected_at_construction() {
        let tcp_ack = crate::node::EndpointDataPayload::new(ipv6_tcp_packet(0x10, 0));
        assert_eq!(tcp_ack.lane(), EndpointCommandLane::Priority);
        assert!(!tcp_ack.drop_on_backpressure());

        let tcp_bulk = crate::node::EndpointDataPayload::new(ipv6_tcp_packet(0x18, 512));
        assert_eq!(tcp_bulk.lane(), EndpointCommandLane::Bulk);
        assert!(!tcp_bulk.drop_on_backpressure());

        let opaque_bulk = crate::node::EndpointDataPayload::new(vec![0, 1, 2, 3]);
        assert_eq!(opaque_bulk.lane(), EndpointCommandLane::Bulk);
        assert!(opaque_bulk.drop_on_backpressure());
    }

    #[test]
    fn endpoint_data_send_owns_remote_identity_and_payload_policy() {
        let remote = PeerIdentity::from_pubkey_full(crate::Identity::generate().pubkey_full());
        let payload = crate::node::EndpointDataPayload::new(ipv6_tcp_packet(0x18, 512));

        let send = crate::node::EndpointDataSend::new(remote, payload.clone());
        assert_eq!(send.dest_addr(), *remote.node_addr());
        assert_eq!(send.dest_pubkey(), remote.pubkey_full());
        assert_eq!(send.payload().lane(), EndpointCommandLane::Bulk);
        assert!(!send.payload().drop_on_backpressure());
        assert_eq!(send.payload().as_slice(), payload.as_slice());
    }

    #[tokio::test]
    async fn endpoint_starts_without_system_tun() {
        let endpoint = FipsEndpoint::builder()
            .without_system_tun()
            .bind()
            .await
            .expect("endpoint should bind");

        assert!(!endpoint.npub().is_empty());
        assert!(endpoint.discovery_scope().is_none());
        endpoint.shutdown().await.expect("shutdown should succeed");
    }

    #[tokio::test]
    async fn loopback_endpoint_data_roundtrips() {
        let endpoint = FipsEndpoint::builder()
            .without_system_tun()
            .bind()
            .await
            .expect("endpoint should bind");

        endpoint
            .send(endpoint.npub().to_string(), b"ping".to_vec())
            .await
            .expect("loopback send should succeed");
        let message = tokio::time::timeout(Duration::from_secs(1), endpoint.recv())
            .await
            .expect("recv should not time out")
            .expect("message should arrive");
        assert_eq!(*message.source_node_addr(), *endpoint.node_addr());
        assert_eq!(message.source_npub(), endpoint.npub());
        assert_eq!(message.data, b"ping");
        assert!(endpoint.discovery_scope().is_none());

        endpoint.shutdown().await.expect("shutdown should succeed");
    }

    #[tokio::test]
    async fn send_to_peer_loopback_endpoint_data_roundtrips() {
        let endpoint = FipsEndpoint::builder()
            .without_system_tun()
            .bind()
            .await
            .expect("endpoint should bind");

        let local = PeerIdentity::from_npub(endpoint.npub()).expect("local peer identity");
        endpoint
            .send_to_peer(local, b"ping".to_vec())
            .await
            .expect("loopback send should succeed");
        let message = tokio::time::timeout(Duration::from_secs(1), endpoint.recv())
            .await
            .expect("recv should not time out")
            .expect("message should arrive");
        assert_eq!(*message.source_node_addr(), *endpoint.node_addr());
        assert_eq!(message.source_npub(), endpoint.npub());
        assert_eq!(message.data, b"ping");

        endpoint.shutdown().await.expect("shutdown should succeed");
    }

    #[tokio::test]
    async fn send_batch_to_peer_loopback_endpoint_data_roundtrips() {
        let endpoint = FipsEndpoint::builder()
            .without_system_tun()
            .bind()
            .await
            .expect("endpoint should bind");

        let local = PeerIdentity::from_npub(endpoint.npub()).expect("local peer identity");
        endpoint
            .send_batch_to_peer(local, vec![b"ping".to_vec(), b"pong".to_vec()])
            .await
            .expect("loopback batch send should succeed");

        let first = tokio::time::timeout(Duration::from_secs(1), endpoint.recv())
            .await
            .expect("first recv should not time out")
            .expect("first message should arrive");
        let second = tokio::time::timeout(Duration::from_secs(1), endpoint.recv())
            .await
            .expect("second recv should not time out")
            .expect("second message should arrive");
        assert_eq!(*first.source_node_addr(), *endpoint.node_addr());
        assert_eq!(first.source_npub(), endpoint.npub());
        assert_eq!(first.data, b"ping");
        assert_eq!(*second.source_node_addr(), *endpoint.node_addr());
        assert_eq!(second.source_npub(), endpoint.npub());
        assert_eq!(second.data, b"pong");

        endpoint.shutdown().await.expect("shutdown should succeed");
    }

    #[tokio::test]
    async fn recv_batch_drains_ready_loopback_endpoint_data() {
        let endpoint = FipsEndpoint::builder()
            .without_system_tun()
            .bind()
            .await
            .expect("endpoint should bind");

        let local = PeerIdentity::from_npub(endpoint.npub()).expect("local peer identity");
        endpoint
            .send_batch_to_peer(
                local,
                vec![b"first".to_vec(), b"second".to_vec(), b"third".to_vec()],
            )
            .await
            .expect("loopback batch send should succeed");

        let messages = tokio::time::timeout(Duration::from_secs(1), endpoint.recv_batch(2))
            .await
            .expect("recv batch should not time out")
            .expect("messages should arrive");
        assert_eq!(messages.len(), 2);
        assert!(
            messages
                .iter()
                .all(|message| *message.source_node_addr() == *endpoint.node_addr())
        );
        assert_eq!(messages[0].data, b"first");
        assert_eq!(messages[1].data, b"second");

        let message = tokio::time::timeout(Duration::from_secs(1), endpoint.recv())
            .await
            .expect("recv should not time out")
            .expect("message should arrive");
        assert_eq!(message.data, b"third");

        endpoint.shutdown().await.expect("shutdown should succeed");
    }

    #[tokio::test]
    async fn recv_batch_into_reuses_caller_buffer_and_respects_limit() {
        let endpoint = FipsEndpoint::builder()
            .without_system_tun()
            .bind()
            .await
            .expect("endpoint should bind");

        let local = PeerIdentity::from_npub(endpoint.npub()).expect("local peer identity");
        endpoint
            .send_batch_to_peer(
                local,
                vec![b"first".to_vec(), b"second".to_vec(), b"third".to_vec()],
            )
            .await
            .expect("loopback batch send should succeed");

        let mut messages = Vec::with_capacity(8);
        let capacity = messages.capacity();
        let received = tokio::time::timeout(
            Duration::from_secs(1),
            endpoint.recv_batch_into(&mut messages, 2),
        )
        .await
        .expect("recv batch should not time out")
        .expect("messages should arrive");
        assert_eq!(received, 2);
        assert_eq!(messages.capacity(), capacity);
        assert_eq!(messages[0].data, b"first");
        assert_eq!(messages[1].data, b"second");

        let received = tokio::time::timeout(
            Duration::from_secs(1),
            endpoint.recv_batch_into(&mut messages, 8),
        )
        .await
        .expect("recv batch should not time out")
        .expect("message should arrive");
        assert_eq!(received, 1);
        assert_eq!(messages.capacity(), capacity);
        assert_eq!(messages[0].data, b"third");

        endpoint.shutdown().await.expect("shutdown should succeed");
    }

    #[tokio::test]
    async fn recv_batch_into_splits_internal_endpoint_batches_without_reordering() {
        let endpoint = FipsEndpoint::builder()
            .without_system_tun()
            .bind()
            .await
            .expect("endpoint should bind");
        let local = PeerIdentity::from_npub(endpoint.npub()).expect("local peer identity");

        endpoint
            .inbound_endpoint_tx
            .send(NodeEndpointEvent::DataBatch {
                messages: vec![
                    EndpointDataDelivery::new(local, b"first".to_vec()),
                    EndpointDataDelivery::new(local, b"second".to_vec()),
                    EndpointDataDelivery::new(local, b"third".to_vec()),
                ],
                queued_at: crate::perf_profile::stamp(),
            })
            .expect("inject internal batch");
        endpoint
            .inbound_endpoint_tx
            .send(NodeEndpointEvent::Data {
                source_peer: local,
                payload: b"fourth".to_vec(),
                queued_at: crate::perf_profile::stamp(),
            })
            .expect("inject follow-on message");

        let mut messages = Vec::with_capacity(8);
        let received = tokio::time::timeout(
            Duration::from_secs(1),
            endpoint.recv_batch_into(&mut messages, 2),
        )
        .await
        .expect("recv batch should not time out")
        .expect("messages should arrive");
        assert_eq!(received, 2);
        assert_eq!(messages[0].data, b"first");
        assert_eq!(messages[1].data, b"second");

        let received = tokio::time::timeout(
            Duration::from_secs(1),
            endpoint.recv_batch_into(&mut messages, 8),
        )
        .await
        .expect("recv batch should not time out")
        .expect("messages should arrive");
        assert_eq!(received, 2);
        assert_eq!(messages[0].data, b"third");
        assert_eq!(messages[1].data, b"fourth");

        endpoint.shutdown().await.expect("shutdown should succeed");
    }

    #[tokio::test]
    async fn recv_batch_into_priority_overtakes_pending_bulk_batch_tail() {
        let endpoint = FipsEndpoint::builder()
            .without_system_tun()
            .bind()
            .await
            .expect("endpoint should bind");
        let local = PeerIdentity::from_npub(endpoint.npub()).expect("local peer identity");

        endpoint
            .inbound_endpoint_tx
            .send(NodeEndpointEvent::DataBatch {
                messages: vec![
                    EndpointDataDelivery::new(
                        local,
                        vec![0xaa; ENDPOINT_EVENT_PRIORITY_MAX_LEN + 1],
                    ),
                    EndpointDataDelivery::new(
                        local,
                        vec![0xbb; ENDPOINT_EVENT_PRIORITY_MAX_LEN + 2],
                    ),
                ],
                queued_at: crate::perf_profile::stamp(),
            })
            .expect("inject bulk internal batch");

        let mut messages = Vec::with_capacity(8);
        let received = tokio::time::timeout(
            Duration::from_secs(1),
            endpoint.recv_batch_into(&mut messages, 1),
        )
        .await
        .expect("recv batch should not time out")
        .expect("message should arrive");
        assert_eq!(received, 1);
        assert_eq!(messages[0].data[0], 0xaa);

        endpoint
            .inbound_endpoint_tx
            .send(NodeEndpointEvent::Data {
                source_peer: local,
                payload: vec![0x11; 32],
                queued_at: crate::perf_profile::stamp(),
            })
            .expect("inject priority follow-on");

        let received = tokio::time::timeout(
            Duration::from_secs(1),
            endpoint.recv_batch_into(&mut messages, 8),
        )
        .await
        .expect("recv batch should not time out")
        .expect("messages should arrive");
        assert_eq!(received, 2);
        assert_eq!(messages[0].data[0], 0x11);
        assert_eq!(messages[1].data[0], 0xbb);

        endpoint.shutdown().await.expect("shutdown should succeed");
    }

    #[tokio::test]
    async fn try_recv_drains_pending_internal_endpoint_batch_tail() {
        let endpoint = FipsEndpoint::builder()
            .without_system_tun()
            .bind()
            .await
            .expect("endpoint should bind");
        let local = PeerIdentity::from_npub(endpoint.npub()).expect("local peer identity");

        endpoint
            .inbound_endpoint_tx
            .send(NodeEndpointEvent::DataBatch {
                messages: vec![
                    EndpointDataDelivery::new(local, b"first".to_vec()),
                    EndpointDataDelivery::new(local, b"second".to_vec()),
                ],
                queued_at: crate::perf_profile::stamp(),
            })
            .expect("inject internal batch");

        assert_eq!(endpoint.try_recv().expect("first message").data, b"first");
        assert_eq!(
            endpoint.try_recv().expect("pending message").data,
            b"second"
        );
        assert!(endpoint.try_recv().is_none());

        endpoint.shutdown().await.expect("shutdown should succeed");
    }

    #[tokio::test]
    async fn blocking_recv_drains_pending_internal_endpoint_batch_tail() {
        let endpoint = FipsEndpoint::builder()
            .without_system_tun()
            .bind()
            .await
            .expect("endpoint should bind");
        let local = PeerIdentity::from_npub(endpoint.npub()).expect("local peer identity");

        endpoint
            .inbound_endpoint_tx
            .send(NodeEndpointEvent::DataBatch {
                messages: vec![
                    EndpointDataDelivery::new(local, b"first".to_vec()),
                    EndpointDataDelivery::new(local, b"second".to_vec()),
                ],
                queued_at: crate::perf_profile::stamp(),
            })
            .expect("inject internal batch");

        let endpoint = tokio::task::spawn_blocking(move || {
            let first = endpoint.blocking_recv().expect("first message");
            let second = endpoint.blocking_recv().expect("pending message");
            assert_eq!(first.data, b"first");
            assert_eq!(second.data, b"second");
            endpoint
        })
        .await
        .expect("blocking receiver should join");

        endpoint.shutdown().await.expect("shutdown should succeed");
    }

    #[tokio::test]
    async fn blocking_recv_batch_into_priority_overtakes_pending_bulk_batch_tail() {
        let endpoint = FipsEndpoint::builder()
            .without_system_tun()
            .bind()
            .await
            .expect("endpoint should bind");
        let local = PeerIdentity::from_npub(endpoint.npub()).expect("local peer identity");

        endpoint
            .inbound_endpoint_tx
            .send(NodeEndpointEvent::DataBatch {
                messages: vec![
                    EndpointDataDelivery::new(
                        local,
                        vec![0xaa; ENDPOINT_EVENT_PRIORITY_MAX_LEN + 1],
                    ),
                    EndpointDataDelivery::new(
                        local,
                        vec![0xbb; ENDPOINT_EVENT_PRIORITY_MAX_LEN + 2],
                    ),
                ],
                queued_at: crate::perf_profile::stamp(),
            })
            .expect("inject bulk internal batch");

        let priority_tx = endpoint.inbound_endpoint_tx.clone();
        let endpoint = tokio::task::spawn_blocking(move || {
            let mut messages = Vec::with_capacity(8);
            let received = endpoint
                .blocking_recv_batch_into(&mut messages, 1)
                .expect("message should arrive");
            assert_eq!(received, 1);
            assert_eq!(messages[0].data[0], 0xaa);

            priority_tx
                .send(NodeEndpointEvent::Data {
                    source_peer: local,
                    payload: vec![0x11; 32],
                    queued_at: crate::perf_profile::stamp(),
                })
                .expect("inject priority follow-on");

            let received = endpoint
                .blocking_recv_batch_into(&mut messages, 8)
                .expect("messages should arrive");
            assert_eq!(received, 2);
            assert_eq!(messages[0].data[0], 0x11);
            assert_eq!(messages[1].data[0], 0xbb);
            endpoint
        })
        .await
        .expect("blocking receiver should join");

        endpoint.shutdown().await.expect("shutdown should succeed");
    }

    #[tokio::test]
    async fn blocking_recv_batch_into_reuses_caller_buffer_and_respects_limit() {
        let endpoint = FipsEndpoint::builder()
            .without_system_tun()
            .bind()
            .await
            .expect("endpoint should bind");

        let local = PeerIdentity::from_npub(endpoint.npub()).expect("local peer identity");
        endpoint
            .send_batch_to_peer(
                local,
                vec![b"first".to_vec(), b"second".to_vec(), b"third".to_vec()],
            )
            .await
            .expect("loopback batch send should succeed");

        let (endpoint, capacity) = tokio::task::spawn_blocking(move || {
            let mut messages = Vec::with_capacity(8);
            let capacity = messages.capacity();
            let received = endpoint
                .blocking_recv_batch_into(&mut messages, 2)
                .expect("messages should arrive");
            assert_eq!(received, 2);
            assert_eq!(messages.capacity(), capacity);
            assert_eq!(messages[0].data, b"first");
            assert_eq!(messages[1].data, b"second");

            let received = endpoint
                .blocking_recv_batch_into(&mut messages, 8)
                .expect("message should arrive");
            assert_eq!(received, 1);
            assert_eq!(messages.capacity(), capacity);
            assert_eq!(messages[0].data, b"third");

            (endpoint, capacity)
        })
        .await
        .expect("blocking receiver should join");
        assert_eq!(capacity, 8);

        endpoint.shutdown().await.expect("shutdown should succeed");
    }

    #[tokio::test]
    async fn blocking_recv_batch_for_each_respects_limit_without_message_vec_staging() {
        let endpoint = FipsEndpoint::builder()
            .without_system_tun()
            .bind()
            .await
            .expect("endpoint should bind");

        let local = PeerIdentity::from_npub(endpoint.npub()).expect("local peer identity");
        endpoint
            .send_batch_to_peer(
                local,
                vec![b"first".to_vec(), b"second".to_vec(), b"third".to_vec()],
            )
            .await
            .expect("loopback batch send should succeed");

        let endpoint = tokio::task::spawn_blocking(move || {
            let mut messages = Vec::with_capacity(3);
            let received = endpoint
                .blocking_recv_batch_for_each(2, |message| {
                    messages.push(message.data);
                    true
                })
                .expect("messages should arrive");
            assert_eq!(received, 2);
            assert_eq!(messages, vec![b"first".to_vec(), b"second".to_vec()]);

            let received = endpoint
                .blocking_recv_batch_for_each(8, |message| {
                    messages.push(message.data);
                    true
                })
                .expect("message should arrive");
            assert_eq!(received, 1);
            assert_eq!(
                messages,
                vec![b"first".to_vec(), b"second".to_vec(), b"third".to_vec()]
            );
            endpoint
        })
        .await
        .expect("blocking receiver should join");

        endpoint.shutdown().await.expect("shutdown should succeed");
    }

    #[tokio::test]
    async fn blocking_recv_batch_for_each_preserves_unhandled_internal_batch_tail() {
        let endpoint = FipsEndpoint::builder()
            .without_system_tun()
            .bind()
            .await
            .expect("endpoint should bind");
        let local = PeerIdentity::from_npub(endpoint.npub()).expect("local peer identity");

        endpoint
            .inbound_endpoint_tx
            .send(NodeEndpointEvent::DataBatch {
                messages: vec![
                    EndpointDataDelivery::new(local, b"first".to_vec()),
                    EndpointDataDelivery::new(local, b"second".to_vec()),
                    EndpointDataDelivery::new(local, b"third".to_vec()),
                ],
                queued_at: crate::perf_profile::stamp(),
            })
            .expect("inject internal batch");

        let endpoint = tokio::task::spawn_blocking(move || {
            let mut messages = Vec::with_capacity(3);
            let received = endpoint
                .blocking_recv_batch_for_each(8, |message| {
                    messages.push(message.data);
                    false
                })
                .expect("message should arrive");
            assert_eq!(received, 1);
            assert_eq!(messages, vec![b"first".to_vec()]);

            let received = endpoint
                .blocking_recv_batch_for_each(8, |message| {
                    messages.push(message.data);
                    true
                })
                .expect("pending messages should arrive");
            assert_eq!(received, 2);
            assert_eq!(
                messages,
                vec![b"first".to_vec(), b"second".to_vec(), b"third".to_vec()]
            );
            endpoint
        })
        .await
        .expect("blocking receiver should join");

        endpoint.shutdown().await.expect("shutdown should succeed");
    }

    #[tokio::test]
    async fn blocking_recv_batch_into_splits_internal_endpoint_batches_without_reordering() {
        let endpoint = FipsEndpoint::builder()
            .without_system_tun()
            .bind()
            .await
            .expect("endpoint should bind");
        let local = PeerIdentity::from_npub(endpoint.npub()).expect("local peer identity");

        endpoint
            .inbound_endpoint_tx
            .send(NodeEndpointEvent::DataBatch {
                messages: vec![
                    EndpointDataDelivery::new(local, b"first".to_vec()),
                    EndpointDataDelivery::new(local, b"second".to_vec()),
                    EndpointDataDelivery::new(local, b"third".to_vec()),
                ],
                queued_at: crate::perf_profile::stamp(),
            })
            .expect("inject internal batch");
        endpoint
            .inbound_endpoint_tx
            .send(NodeEndpointEvent::Data {
                source_peer: local,
                payload: b"fourth".to_vec(),
                queued_at: crate::perf_profile::stamp(),
            })
            .expect("inject follow-on message");

        let endpoint = tokio::task::spawn_blocking(move || {
            let mut messages = Vec::with_capacity(8);
            let received = endpoint
                .blocking_recv_batch_into(&mut messages, 2)
                .expect("messages should arrive");
            assert_eq!(received, 2);
            assert_eq!(messages[0].data, b"first");
            assert_eq!(messages[1].data, b"second");

            let received = endpoint
                .blocking_recv_batch_into(&mut messages, 8)
                .expect("messages should arrive");
            assert_eq!(received, 2);
            assert_eq!(messages[0].data, b"third");
            assert_eq!(messages[1].data, b"fourth");

            endpoint
        })
        .await
        .expect("blocking receiver should join");

        endpoint.shutdown().await.expect("shutdown should succeed");
    }

    #[tokio::test]
    async fn blocking_send_to_peer_loopback_endpoint_data_roundtrips() {
        let endpoint = FipsEndpoint::builder()
            .without_system_tun()
            .bind()
            .await
            .expect("endpoint should bind");

        let local = PeerIdentity::from_npub(endpoint.npub()).expect("local peer identity");
        endpoint
            .blocking_send_to_peer(local, b"ping".to_vec())
            .expect("loopback send should succeed");
        let message = tokio::time::timeout(Duration::from_secs(1), endpoint.recv())
            .await
            .expect("recv should not time out")
            .expect("message should arrive");
        assert_eq!(*message.source_node_addr(), *endpoint.node_addr());
        assert_eq!(message.source_npub(), endpoint.npub());
        assert_eq!(message.data, b"ping");

        endpoint.shutdown().await.expect("shutdown should succeed");
    }

    #[test]
    fn discovery_scope_enables_default_scoped_udp_discovery() {
        let config = FipsEndpoint::builder()
            .discovery_scope("nostr-vpn:test")
            .prepared_config();

        assert!(!config.tun.enabled);
        assert!(!config.dns.enabled);
        assert!(!config.node.system_files_enabled);
        assert!(config.node.discovery.nostr.enabled);
        assert!(config.node.discovery.nostr.advertise);
        assert_eq!(
            config.node.discovery.nostr.policy,
            NostrDiscoveryPolicy::Open
        );
        assert!(config.node.discovery.nostr.share_local_candidates);
        assert_eq!(config.node.discovery.nostr.app, "nostr-vpn:test");
        assert_eq!(
            config.node.discovery.lan.scope.as_deref(),
            Some("nostr-vpn:test")
        );
        assert!(config.node.discovery.local.enabled);

        let udp = match config.transports.udp {
            TransportInstances::Single(udp) => udp,
            TransportInstances::Named(_) => panic!("expected a default UDP transport"),
        };
        assert_eq!(udp.bind_addr(), "0.0.0.0:0");
        assert!(udp.advertise_on_nostr());
        assert!(!udp.is_public());
        assert!(!udp.outbound_only());
        assert!(udp.accept_connections());
    }

    #[test]
    fn local_ethernet_adds_scoped_discovery_transport() {
        let config = FipsEndpoint::builder()
            .discovery_scope("iris-chat:host")
            .local_ethernet("fips-app0")
            .prepared_config();

        assert!(config.node.discovery.nostr.enabled);
        assert_eq!(
            config.node.discovery.lan.scope.as_deref(),
            Some("iris-chat:host")
        );

        let eth = match config.transports.ethernet {
            TransportInstances::Single(eth) => eth,
            TransportInstances::Named(_) => panic!("expected a single Ethernet transport"),
        };
        assert_eq!(eth.interface, "fips-app0");
        assert!(eth.discovery());
        assert!(eth.announce());
        assert!(eth.auto_connect());
        assert!(eth.accept_connections());
        assert_eq!(eth.discovery_scope(), Some("iris-chat:host"));
    }

    #[test]
    fn local_ethernet_preserves_existing_ethernet_config() {
        let mut explicit = Config::new();
        explicit.transports.ethernet = TransportInstances::Single(EthernetConfig {
            interface: "br-existing".to_string(),
            announce: Some(false),
            ..EthernetConfig::default()
        });

        let config = FipsEndpoint::builder()
            .config(explicit)
            .local_ethernet("fips-app0")
            .prepared_config();

        let TransportInstances::Named(map) = config.transports.ethernet else {
            panic!("expected named Ethernet transports");
        };
        assert!(map.contains_key("default"));
        let local = map
            .get("local-ethernet-fips-app0")
            .expect("local endpoint Ethernet transport");
        assert_eq!(local.interface, "fips-app0");
        assert!(local.announce());
        assert!(local.auto_connect());
        assert!(local.accept_connections());
    }

    #[test]
    fn discovery_scope_preserves_explicit_connectivity_config() {
        let mut explicit = Config::new();
        explicit.node.discovery.nostr.enabled = true;
        explicit.node.discovery.nostr.app = "custom-app".to_string();
        explicit.node.discovery.nostr.policy = NostrDiscoveryPolicy::ConfiguredOnly;
        explicit.node.discovery.nostr.share_local_candidates = false;
        explicit.transports.udp = TransportInstances::Single(UdpConfig {
            bind_addr: Some("127.0.0.1:34567".to_string()),
            advertise_on_nostr: Some(false),
            outbound_only: Some(true),
            ..UdpConfig::default()
        });

        let config = FipsEndpoint::builder()
            .config(explicit)
            .discovery_scope("nostr-vpn:test")
            .prepared_config();

        assert_eq!(config.node.discovery.nostr.app, "custom-app");
        assert_eq!(
            config.node.discovery.nostr.policy,
            NostrDiscoveryPolicy::ConfiguredOnly
        );
        assert!(!config.node.discovery.nostr.share_local_candidates);
        assert_eq!(
            config.node.discovery.lan.scope.as_deref(),
            Some("nostr-vpn:test")
        );
        assert!(config.node.discovery.local.enabled);
        let udp = match config.transports.udp {
            TransportInstances::Single(udp) => udp,
            TransportInstances::Named(_) => panic!("expected explicit UDP transport"),
        };
        assert_eq!(udp.bind_addr.as_deref(), Some("127.0.0.1:34567"));
        assert_eq!(udp.bind_addr(), "0.0.0.0:0");
        assert!(!udp.advertise_on_nostr());
        assert!(udp.outbound_only());
    }

    #[tokio::test]
    async fn invalid_remote_npub_is_rejected() {
        let endpoint = FipsEndpoint::builder()
            .without_system_tun()
            .bind()
            .await
            .expect("endpoint should bind");

        let error = endpoint
            .send("not-an-npub", b"hello".to_vec())
            .await
            .expect_err("invalid npub should fail");
        assert!(matches!(error, FipsEndpointError::InvalidRemoteNpub { .. }));

        endpoint.shutdown().await.expect("shutdown should succeed");
    }

    #[tokio::test]
    async fn endpoint_peer_snapshot_starts_empty() {
        let endpoint = FipsEndpoint::builder()
            .without_system_tun()
            .bind()
            .await
            .expect("endpoint should bind");

        let peers = endpoint.peers().await.expect("peer snapshot");
        assert!(peers.is_empty());

        endpoint.shutdown().await.expect("shutdown should succeed");
    }
}
