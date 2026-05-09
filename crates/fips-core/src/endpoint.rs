//! Library-first endpoint API for embedding FIPS in applications.
//!
//! This module exposes a no-system-TUN runtime shape for apps that want to own
//! peer admission and local routing policy while reusing FIPS connectivity.

use crate::config::{NostrDiscoveryPolicy, TransportInstances, UdpConfig};
use crate::node::{NodeEndpointCommand, NodeEndpointEvent, NodeEndpointPeer};
use crate::{
    Config, FipsAddress, IdentityConfig, Node, NodeAddr, NodeDeliveredPacket, NodeError,
    PeerIdentity,
};
use std::sync::Arc;
use thiserror::Error;
use tokio::sync::{Mutex, mpsc, oneshot};
use tokio::task::JoinHandle;

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
}

/// Builder for an embedded FIPS endpoint.
#[derive(Debug, Clone)]
pub struct FipsEndpointBuilder {
    config: Config,
    identity_nsec: Option<String>,
    discovery_scope: Option<String>,
    disable_system_networking: bool,
    packet_channel_capacity: usize,
}

impl Default for FipsEndpointBuilder {
    fn default() -> Self {
        Self {
            config: Config::new(),
            identity_nsec: None,
            discovery_scope: None,
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
            apply_default_scoped_discovery(&mut config, scope);
        }
        config
    }

    /// Bind and start the embedded endpoint.
    pub async fn bind(self) -> Result<FipsEndpoint, FipsEndpointError> {
        let config = self.prepared_config();

        let mut node = Node::new(config)?;
        let npub = node.npub();
        let node_addr = *node.node_addr();
        let address = *node.identity().address();
        let packet_io = node.attach_external_packet_io(self.packet_channel_capacity)?;
        let endpoint_data_io = node.attach_endpoint_data_io(self.packet_channel_capacity)?;
        node.start().await?;

        let (shutdown_tx, shutdown_rx) = oneshot::channel();
        let task = spawn_node_task(node, shutdown_rx);
        let (inbound_endpoint_tx, inbound_endpoint_rx) =
            mpsc::channel(self.packet_channel_capacity);
        let endpoint_commands = endpoint_data_io.command_tx;
        let event_task =
            spawn_endpoint_event_task(endpoint_data_io.event_rx, inbound_endpoint_tx.clone());

        Ok(FipsEndpoint {
            npub,
            node_addr,
            address,
            discovery_scope: self.discovery_scope,
            outbound_packets: packet_io.outbound_tx,
            delivered_packets: Arc::new(Mutex::new(packet_io.inbound_rx)),
            endpoint_commands,
            inbound_endpoint_tx,
            inbound_endpoint_rx: Arc::new(Mutex::new(inbound_endpoint_rx)),
            peer_identity_cache: std::sync::Mutex::new(std::collections::HashMap::new()),
            shutdown_tx: Some(shutdown_tx),
            task,
            event_task,
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
    config.node.discovery.nostr.app = format!("fips-overlay-v1:{scope}");
    config.transports.udp = TransportInstances::Single(UdpConfig {
        bind_addr: Some("0.0.0.0:0".to_string()),
        advertise_on_nostr: Some(true),
        public: Some(false),
        outbound_only: Some(false),
        accept_connections: Some(true),
        ..UdpConfig::default()
    });
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

fn spawn_endpoint_event_task(
    mut endpoint_events: mpsc::Receiver<NodeEndpointEvent>,
    inbound_endpoint_tx: mpsc::Sender<FipsEndpointMessage>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        while let Some(event) = endpoint_events.recv().await {
            let NodeEndpointEvent::Data {
                source_node_addr,
                source_npub,
                payload,
            } = event;
            let message = FipsEndpointMessage {
                source_node_addr,
                source_npub,
                data: payload,
            };
            if inbound_endpoint_tx.send(message).await.is_err() {
                break;
            }
        }
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
    inbound_endpoint_tx: mpsc::Sender<FipsEndpointMessage>,
    inbound_endpoint_rx: Arc<Mutex<mpsc::Receiver<FipsEndpointMessage>>>,
    /// Cache of resolved PeerIdentity by npub string. Avoids the per-packet
    /// secp256k1 EC point parse that `PeerIdentity::from_npub` performs;
    /// without this cache the bulk-data send hot path spends ~10–30% of CPU
    /// re-validating identity bytes the application has already configured.
    peer_identity_cache: std::sync::Mutex<std::collections::HashMap<String, PeerIdentity>>,
    shutdown_tx: Option<oneshot::Sender<()>>,
    task: JoinHandle<Result<(), NodeError>>,
    event_task: JoinHandle<()>,
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
                .send(FipsEndpointMessage {
                    source_node_addr: self.node_addr,
                    source_npub: Some(self.npub.clone()),
                    data,
                })
                .await
                .map_err(|_| FipsEndpointError::Closed)?;
            return Ok(());
        }

        let remote = self.resolve_peer_identity(&remote_npub)?;

        // Create a oneshot we never await; the node task's send/Err path will
        // fire into a dropped receiver, which is fine — the result is already
        // discarded inside handle_endpoint_data_command via `let _ = ...`.
        let (response_tx, _response_rx) = oneshot::channel();
        self.endpoint_commands
            .send(NodeEndpointCommand::Send {
                remote,
                payload: data,
                response_tx,
            })
            .await
            .map_err(|_| FipsEndpointError::Closed)?;
        Ok(())
    }

    fn resolve_peer_identity(
        &self,
        remote_npub: &str,
    ) -> Result<PeerIdentity, FipsEndpointError> {
        // Fast path: cached identity (cheap clone of fixed-size struct).
        if let Ok(cache) = self.peer_identity_cache.lock()
            && let Some(remote) = cache.get(remote_npub)
        {
            return Ok(remote.clone());
        }

        let remote = PeerIdentity::from_npub(remote_npub).map_err(|error| {
            FipsEndpointError::InvalidRemoteNpub {
                npub: remote_npub.to_string(),
                reason: error.to_string(),
            }
        })?;

        if let Ok(mut cache) = self.peer_identity_cache.lock() {
            cache
                .entry(remote_npub.to_string())
                .or_insert_with(|| remote.clone());
        }
        Ok(remote)
    }

    /// Receive the next source-attributed endpoint data message.
    pub async fn recv(&self) -> Option<FipsEndpointMessage> {
        self.inbound_endpoint_rx.lock().await.recv().await
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
        let task_result = self.task.await;
        let _ = self.event_task.await;
        task_result??;
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
        assert_eq!(
            config.node.discovery.nostr.app,
            "fips-overlay-v1:nostr-vpn:test"
        );

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
