//! Library-first endpoint API for embedding FIPS in applications.
//!
//! This module exposes a no-system-TUN runtime shape for apps that want to own
//! peer admission and local routing policy while reusing FIPS connectivity.

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

    /// Store an application-level discovery scope for callers that need it.
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

    /// Bind and start the embedded endpoint.
    pub async fn bind(self) -> Result<FipsEndpoint, FipsEndpointError> {
        let mut config = self.config;
        if let Some(nsec) = self.identity_nsec {
            config.node.identity = IdentityConfig {
                nsec: Some(nsec),
                persistent: false,
            };
        }
        if self.disable_system_networking {
            config.tun.enabled = false;
            config.dns.enabled = false;
        }

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
            shutdown_tx: Some(shutdown_tx),
            task,
            event_task,
        })
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

        let remote = PeerIdentity::from_npub(&remote_npub).map_err(|error| {
            FipsEndpointError::InvalidRemoteNpub {
                npub: remote_npub,
                reason: error.to_string(),
            }
        })?;

        let (response_tx, response_rx) = oneshot::channel();
        self.endpoint_commands
            .send(NodeEndpointCommand::Send {
                remote,
                payload: data,
                response_tx,
            })
            .await
            .map_err(|_| FipsEndpointError::Closed)?;

        match response_rx.await {
            Ok(Ok(())) => Ok(()),
            Ok(Err(error)) => Err(error.into()),
            Err(_) => Err(FipsEndpointError::Closed),
        }
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
            .discovery_scope("nostr-vpn:test")
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
        assert_eq!(endpoint.discovery_scope(), Some("nostr-vpn:test"));

        endpoint.shutdown().await.expect("shutdown should succeed");
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
