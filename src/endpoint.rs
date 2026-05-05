//! Library-first endpoint API for embedding FIPS in applications.
//!
//! This module exposes a no-system-TUN runtime shape for apps that want to own
//! packet admission and local routing policy while reusing FIPS connectivity.

use crate::{Config, FipsAddress, IdentityConfig, Node, NodeAddr, NodeDeliveredPacket, NodeError};
use futures::future::BoxFuture;
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
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

    #[error("protocol is empty")]
    EmptyProtocol,

    #[error("unsupported protocol: {0}")]
    UnknownProtocol(String),

    #[error("remote protocol connections are not wired yet")]
    ProtocolTransportUnavailable,
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

    /// Set the app packet channel capacity.
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
        node.start().await?;

        let (shutdown_tx, shutdown_rx) = oneshot::channel();
        let task = spawn_node_task(node, shutdown_rx);

        Ok(FipsEndpoint {
            npub,
            node_addr,
            address,
            discovery_scope: self.discovery_scope,
            outbound_packets: packet_io.outbound_tx,
            delivered_packets: Arc::new(Mutex::new(packet_io.inbound_rx)),
            protocols: Arc::new(RwLock::new(HashMap::new())),
            shutdown_tx: Some(shutdown_tx),
            task,
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

/// A running embedded FIPS endpoint.
pub struct FipsEndpoint {
    npub: String,
    node_addr: NodeAddr,
    address: FipsAddress,
    discovery_scope: Option<String>,
    outbound_packets: mpsc::Sender<Vec<u8>>,
    delivered_packets: Arc<Mutex<mpsc::Receiver<NodeDeliveredPacket>>>,
    protocols: Arc<RwLock<HashMap<Vec<u8>, ProtocolHandler>>>,
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

    /// Register a local application protocol handler.
    pub fn accept_protocol(
        &self,
        protocol: &'static [u8],
        handler: impl FipsProtocolHandler,
    ) -> Result<(), FipsEndpointError> {
        if protocol.is_empty() {
            return Err(FipsEndpointError::EmptyProtocol);
        }
        let mut protocols = self.protocols.write().expect("protocol registry poisoned");
        protocols.insert(protocol.to_vec(), Arc::new(handler));
        Ok(())
    }

    /// Open an application protocol session.
    ///
    /// Loopback sessions are fully dispatched in-process. Remote protocol
    /// sessions return `ProtocolTransportUnavailable` until the app protocol
    /// frame is wired into the mesh session data path.
    pub async fn connect_protocol(
        &self,
        remote_npub: impl Into<String>,
        protocol: &'static [u8],
    ) -> Result<FipsSession, FipsEndpointError> {
        if protocol.is_empty() {
            return Err(FipsEndpointError::EmptyProtocol);
        }

        let remote_npub = remote_npub.into();
        if remote_npub != self.npub {
            return Err(FipsEndpointError::ProtocolTransportUnavailable);
        }

        let handler = {
            let protocols = self.protocols.read().expect("protocol registry poisoned");
            protocols
                .get(protocol)
                .cloned()
                .ok_or_else(|| FipsEndpointError::UnknownProtocol(protocol_name(protocol)))?
        };

        let (local, remote) = FipsSession::pair(self.npub.clone(), remote_npub, protocol.to_vec());
        tokio::spawn(async move {
            let _ = handler.accept(remote).await;
        });
        Ok(local)
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

type ProtocolHandler = Arc<dyn FipsProtocolHandler>;

/// Handler for accepted application protocol sessions.
pub trait FipsProtocolHandler: Send + Sync + 'static {
    fn accept(&self, session: FipsSession) -> BoxFuture<'static, Result<(), FipsEndpointError>>;
}

impl<F, Fut> FipsProtocolHandler for F
where
    F: Fn(FipsSession) -> Fut + Send + Sync + 'static,
    Fut: std::future::Future<Output = Result<(), FipsEndpointError>> + Send + 'static,
{
    fn accept(&self, session: FipsSession) -> BoxFuture<'static, Result<(), FipsEndpointError>> {
        Box::pin(self(session))
    }
}

/// Bidirectional application protocol session.
#[derive(Debug)]
pub struct FipsSession {
    remote_npub: String,
    protocol: Vec<u8>,
    tx: mpsc::Sender<Vec<u8>>,
    rx: Mutex<mpsc::Receiver<Vec<u8>>>,
}

impl FipsSession {
    fn pair(initiator_npub: String, responder_npub: String, protocol: Vec<u8>) -> (Self, Self) {
        let (a_tx, a_rx) = mpsc::channel(64);
        let (b_tx, b_rx) = mpsc::channel(64);
        (
            Self {
                remote_npub: responder_npub,
                protocol: protocol.clone(),
                tx: a_tx,
                rx: Mutex::new(b_rx),
            },
            Self {
                remote_npub: initiator_npub,
                protocol,
                tx: b_tx,
                rx: Mutex::new(a_rx),
            },
        )
    }

    /// Remote peer npub for this session.
    pub fn remote_npub(&self) -> &str {
        &self.remote_npub
    }

    /// Protocol identifier for this session.
    pub fn protocol(&self) -> &[u8] {
        &self.protocol
    }

    /// Send one application frame.
    pub async fn send(&self, frame: impl Into<Vec<u8>>) -> Result<(), FipsEndpointError> {
        self.tx
            .send(frame.into())
            .await
            .map_err(|_| FipsEndpointError::Closed)
    }

    /// Receive one application frame.
    pub async fn recv(&self) -> Option<Vec<u8>> {
        self.rx.lock().await.recv().await
    }
}

fn protocol_name(protocol: &[u8]) -> String {
    String::from_utf8(protocol.to_vec()).unwrap_or_else(|_| hex::encode(protocol))
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
    async fn loopback_protocol_dispatches_registered_handler() {
        let endpoint = FipsEndpoint::builder()
            .without_system_tun()
            .discovery_scope("nostr-vpn:test")
            .bind()
            .await
            .expect("endpoint should bind");

        endpoint
            .accept_protocol(b"nostr-vpn/ip/1", |session: FipsSession| async move {
                let frame = session.recv().await.expect("frame should arrive");
                assert_eq!(frame, b"ping");
                session.send(b"pong".to_vec()).await
            })
            .expect("handler should register");

        let session = endpoint
            .connect_protocol(endpoint.npub().to_string(), b"nostr-vpn/ip/1")
            .await
            .expect("loopback connect should succeed");
        session.send(b"ping".to_vec()).await.expect("send works");
        let reply = tokio::time::timeout(Duration::from_secs(1), session.recv())
            .await
            .expect("reply should not time out")
            .expect("reply should arrive");
        assert_eq!(reply, b"pong");
        assert_eq!(endpoint.discovery_scope(), Some("nostr-vpn:test"));

        endpoint.shutdown().await.expect("shutdown should succeed");
    }

    #[tokio::test]
    async fn unknown_loopback_protocol_is_rejected() {
        let endpoint = FipsEndpoint::builder()
            .without_system_tun()
            .bind()
            .await
            .expect("endpoint should bind");

        let error = endpoint
            .connect_protocol(endpoint.npub().to_string(), b"unknown/1")
            .await
            .expect_err("unknown protocol should fail");
        assert!(matches!(error, FipsEndpointError::UnknownProtocol(_)));

        endpoint.shutdown().await.expect("shutdown should succeed");
    }
}
