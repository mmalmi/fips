//! Library-first endpoint API for embedding FIPS in applications.
//!
//! This module exposes a no-system-TUN runtime shape for apps that want to own
//! peer admission and local routing policy while reusing FIPS connectivity.

use crate::config::{EthernetConfig, NostrDiscoveryPolicy, TransportInstances, UdpConfig};
use crate::node::{
    NodeEndpointCommand, NodeEndpointEvent, NodeEndpointPeer, NodeEndpointRelayStatus,
};
use crate::{
    Config, FipsAddress, IdentityConfig, Node, NodeAddr, NodeDeliveredPacket, NodeError,
    PeerIdentity,
};
use std::sync::Arc;
use thiserror::Error;
use tokio::sync::{Mutex, mpsc, oneshot};
use tokio::task::JoinHandle;

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
    /// FIPS node address that originated the endpoint data.
    pub source_node_addr: NodeAddr,
    /// Source Nostr public key when the node has learned it.
    pub source_npub: Option<String>,
    /// Application-owned payload bytes.
    pub data: Vec<u8>,
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
    /// Whether direct UDP probing is queued while this peer may still be
    /// reachable through a fallback transport.
    pub direct_probe_pending: bool,
    /// Millisecond timestamp when the queued direct probe becomes eligible.
    pub direct_probe_after_ms: Option<u64>,
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
        let npub = node.npub();
        let node_addr = *node.node_addr();
        let address = *node.identity().address();
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
        let endpoint_commands = endpoint_data_io.command_tx;

        Ok(FipsEndpoint {
            npub,
            node_addr,
            address,
            discovery_scope: self.discovery_scope,
            outbound_packets: packet_io.outbound_tx,
            delivered_packets: Arc::new(Mutex::new(packet_io.inbound_rx)),
            endpoint_commands,
            inbound_endpoint_tx: endpoint_data_io.event_tx,
            inbound_endpoint_rx: Arc::new(Mutex::new(endpoint_data_io.event_rx)),
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
    npub: String,
    node_addr: NodeAddr,
    address: FipsAddress,
    discovery_scope: Option<String>,
    outbound_packets: mpsc::Sender<Vec<u8>>,
    delivered_packets: Arc<Mutex<mpsc::Receiver<NodeDeliveredPacket>>>,
    endpoint_commands: mpsc::Sender<NodeEndpointCommand>,
    /// In-process loopback sender — `send()` to our own npub injects an
    /// event into the same queue without going through the wire/encrypt
    /// path. The node's rx_loop also sends into this channel directly
    /// (it holds a clone of this sender) so there is no per-packet relay
    /// task between the node task and `recv()`.
    inbound_endpoint_tx: mpsc::UnboundedSender<NodeEndpointEvent>,
    /// Unbounded receiver. Was previously fed by a per-packet relay task
    /// that translated `NodeEndpointEvent::Data` into `FipsEndpointMessage`
    /// across an additional bounded mpsc; collapsed into a single channel
    /// — the translation happens inline in `recv()` and the second hop
    /// (with its scheduler wake per packet) is gone.
    inbound_endpoint_rx: Arc<Mutex<mpsc::UnboundedReceiver<NodeEndpointEvent>>>,
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
            self.inbound_endpoint_tx
                .send(NodeEndpointEvent::Data {
                    source_node_addr: self.node_addr,
                    source_npub: Some(self.npub.clone()),
                    payload: data,
                    queued_at: crate::perf_profile::stamp(),
                })
                .map_err(|_| FipsEndpointError::Closed)?;
            return Ok(());
        }

        let remote = self.resolve_peer_identity(&remote_npub)?;

        // Fire-and-forget: caller already drops the result, so skip
        // the per-packet `oneshot::channel()` allocation entirely.
        // The node task's `SendOneway` arm runs the same code path as
        // `Send` but without writing the result into a oneshot.
        self.endpoint_commands
            .send(NodeEndpointCommand::SendOneway {
                remote,
                payload: data,
                queued_at: crate::perf_profile::stamp(),
            })
            .await
            .map_err(|_| FipsEndpointError::Closed)?;
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

    /// Receive the next source-attributed endpoint data message.
    ///
    /// Translation from the internal `NodeEndpointEvent::Data` shape to
    /// the public `FipsEndpointMessage` shape happens inline here — the
    /// rx_loop pushes directly onto this channel, no relay task in
    /// between, no extra cross-task hop per packet.
    pub async fn recv(&self) -> Option<FipsEndpointMessage> {
        let event = self.inbound_endpoint_rx.lock().await.recv().await?;
        let NodeEndpointEvent::Data {
            source_node_addr,
            source_npub,
            payload,
            queued_at,
        } = event;
        crate::perf_profile::record_since(crate::perf_profile::Stage::EndpointEventWait, queued_at);
        Some(FipsEndpointMessage {
            source_node_addr,
            source_npub,
            data: payload,
        })
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
            self.inbound_endpoint_tx
                .send(NodeEndpointEvent::Data {
                    source_node_addr: self.node_addr,
                    source_npub: Some(self.npub.clone()),
                    payload: data,
                    queued_at: crate::perf_profile::stamp(),
                })
                .map_err(|_| FipsEndpointError::Closed)?;
            return Ok(());
        }
        let remote = self.resolve_peer_identity(&remote_npub)?;
        let (response_tx, _response_rx) = oneshot::channel();
        self.endpoint_commands
            .blocking_send(NodeEndpointCommand::Send {
                remote,
                payload: data,
                queued_at: crate::perf_profile::stamp(),
                response_tx,
            })
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
        let mut rx = self.inbound_endpoint_rx.blocking_lock();
        let event = rx.blocking_recv()?;
        let NodeEndpointEvent::Data {
            source_node_addr,
            source_npub,
            payload,
            queued_at,
        } = event;
        crate::perf_profile::record_since(crate::perf_profile::Stage::EndpointEventWait, queued_at);
        Some(FipsEndpointMessage {
            source_node_addr,
            source_npub,
            data: payload,
        })
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
        let mut rx = self.inbound_endpoint_rx.try_lock().ok()?;
        let event = rx.try_recv().ok()?;
        let NodeEndpointEvent::Data {
            source_node_addr,
            source_npub,
            payload,
            queued_at,
        } = event;
        crate::perf_profile::record_since(crate::perf_profile::Stage::EndpointEventWait, queued_at);
        Some(FipsEndpointMessage {
            source_node_addr,
            source_npub,
            data: payload,
        })
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
        self.endpoint_commands
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
        self.endpoint_commands
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
        self.endpoint_commands
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
        self.endpoint_commands
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

impl From<NodeEndpointPeer> for FipsEndpointPeer {
    fn from(peer: NodeEndpointPeer) -> Self {
        Self {
            npub: peer.npub,
            transport_addr: peer.transport_addr,
            transport_type: peer.transport_type,
            link_id: peer.link_id,
            srtt_ms: peer.srtt_ms,
            packets_sent: peer.packets_sent,
            packets_recv: peer.packets_recv,
            bytes_sent: peer.bytes_sent,
            bytes_recv: peer.bytes_recv,
            direct_probe_pending: peer.direct_probe_pending,
            direct_probe_after_ms: peer.direct_probe_after_ms,
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
    use std::time::Duration;

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
        assert_eq!(message.source_node_addr, *endpoint.node_addr());
        assert_eq!(message.source_npub, Some(endpoint.npub().to_string()));
        assert_eq!(message.data, b"ping");
        assert!(endpoint.discovery_scope().is_none());

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
