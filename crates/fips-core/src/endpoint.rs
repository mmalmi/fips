//! Library-first endpoint API for embedding FIPS in applications.
//!
//! This module exposes a no-system-TUN runtime shape for apps that want to own
//! peer admission and local routing policy while reusing FIPS connectivity.

use crate::config::{EthernetConfig, NostrDiscoveryPolicy, TransportInstances, UdpConfig};
#[cfg(test)]
use crate::node::ENDPOINT_EVENT_TEST_PAYLOAD_LEN;
use crate::node::{
    EndpointDataBatchTx, EndpointDataPayload, EndpointDirectSink, EndpointEventSender,
    EndpointServiceEventSender, NodeEndpointControlCommand, NodeEndpointDataBatch,
    NodeEndpointEvent,
};
use crate::upper::tun::TunOutboundTx;
use crate::{
    Config, FipsAddress, IdentityConfig, Node, NodeAddr, NodeDeliveredPacket, NodeError,
    PeerIdentity,
};
use std::collections::HashSet;
use std::sync::{Arc, Mutex as StdMutex};
use thiserror::Error;
use tokio::sync::{Mutex, mpsc, oneshot};
use tokio::task::JoinHandle;

const ENDPOINT_DATA_BATCH_MAX: usize = 128;
const ENDPOINT_RECV_BATCH_MAX: usize = 128;

mod builder;
mod receive;
mod status;

#[cfg(test)]
mod tests;

pub use crate::node::{
    FipsEndpointDirectDeliveryError, FipsEndpointDirectPacketBatch, FipsEndpointDirectPacketRun,
    FipsEndpointDirectSink,
};
pub use builder::FipsEndpointBuilder;
use receive::{EndpointReceiveState, ServiceReceiveState};
pub use status::{FipsEndpointPeer, FipsEndpointRelayStatus};

/// Endpoint data bytes delivered by FIPS.
///
/// This is the same pooled packet owner used by the transport/dataplane, so
/// embedders can forward endpoint data without forcing another hot-path copy.
pub type FipsEndpointData = crate::transport::PacketBuffer;

/// Errors returned by the endpoint API.
#[derive(Debug, Error)]
pub enum FipsEndpointError {
    #[error("node error: {0}")]
    Node(#[from] NodeError),

    #[error("endpoint task failed: {0}")]
    TaskJoin(#[from] tokio::task::JoinError),

    #[error("endpoint is closed")]
    Closed,

    #[error("endpoint data payload is too large: {len} bytes exceeds max {max} bytes")]
    EndpointDataTooLarge { len: usize, max: usize },

    #[error("service datagram payload is too large: {len} bytes exceeds max {max} bytes")]
    ServiceDatagramTooLarge { len: usize, max: usize },

    #[error("FSP service port {port} is reserved")]
    ServicePortReserved { port: u16 },

    #[error("FSP service port {port} is already registered")]
    ServicePortAlreadyRegistered { port: u16 },
}

/// Source-attributed endpoint data delivered to an embedded application.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FipsEndpointMessage {
    /// Authenticated FIPS peer that originated the endpoint data.
    pub source_peer: PeerIdentity,
    /// Application-owned payload bytes.
    pub data: FipsEndpointData,
    /// Unix-millisecond time when FIPS queued this message for the embedder.
    pub enqueued_at_ms: u64,
}

/// One owned outbound FSP DataPacket service payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FipsEndpointOutboundDatagram {
    pub source_port: u16,
    pub destination_port: u16,
    pub data: Vec<u8>,
}

impl FipsEndpointOutboundDatagram {
    pub fn new(source_port: u16, destination_port: u16, data: Vec<u8>) -> Self {
        Self {
            source_port,
            destination_port,
            data,
        }
    }
}

/// Authenticated FSP DataPacket service payload delivered to an embedder.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FipsEndpointServiceDatagram {
    pub source_peer: PeerIdentity,
    pub source_port: u16,
    pub destination_port: u16,
    pub data: FipsEndpointData,
    pub enqueued_at_ms: u64,
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

fn endpoint_data_payloads_from_vecs(
    payloads: Vec<Vec<u8>>,
) -> Result<Vec<EndpointDataPayload>, FipsEndpointError> {
    let mut converted = Vec::with_capacity(payloads.len());
    for payload in payloads {
        let len = payload.len();
        let Some(payload) = EndpointDataPayload::from_packet_payload(payload) else {
            let max = crate::node::session_wire::fsp_endpoint_data_max_body_len();
            return Err(FipsEndpointError::EndpointDataTooLarge { len, max });
        };
        converted.push(payload);
    }
    Ok(converted)
}

fn service_datagram_payloads(
    datagrams: Vec<FipsEndpointOutboundDatagram>,
) -> Result<Vec<EndpointDataPayload>, FipsEndpointError> {
    let max = crate::node::session_wire::fsp_service_datagram_max_body_len();
    let mut payloads = Vec::with_capacity(datagrams.len());
    for datagram in datagrams {
        let len = datagram.data.len();
        let Some(payload) = EndpointDataPayload::from_service_datagram(
            datagram.source_port,
            datagram.destination_port,
            datagram.data,
        ) else {
            return Err(FipsEndpointError::ServiceDatagramTooLarge { len, max });
        };
        payloads.push(payload);
    }
    Ok(payloads)
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
    outbound_packets: TunOutboundTx,
    delivered_packets: Arc<Mutex<mpsc::Receiver<NodeDeliveredPacket>>>,
    endpoint_control_tx: mpsc::Sender<NodeEndpointControlCommand>,
    endpoint_data_batches: EndpointDataBatchTx,
    /// In-process loopback sender for local peer sends. It injects an event into
    /// the same queue without going through the wire/encrypt path. The node's
    /// rx_loop also sends into this channel directly (it holds a clone of this
    /// sender) so there is no per-packet relay task between the node task and
    /// `recv_batch_into()`.
    inbound_endpoint_tx: EndpointEventSender,
    /// Unbounded receiver plus pending tail from an internal batch. This was
    /// previously fed by a per-packet relay task
    /// that translated node endpoint events into `FipsEndpointMessage`
    /// across an additional bounded mpsc; collapsed into a single channel
    /// -- the translation happens inline in `recv()` and the second hop
    /// (with its scheduler wake per packet) is gone.
    inbound_endpoint_rx: Arc<Mutex<EndpointReceiveState>>,
    inbound_service_tx: EndpointServiceEventSender,
    inbound_service_rx: Arc<Mutex<ServiceReceiveState>>,
    registered_services: Arc<StdMutex<HashSet<u16>>>,
    shutdown_tx: StdMutex<Option<oneshot::Sender<()>>>,
    task: StdMutex<Option<JoinHandle<Result<(), NodeError>>>>,
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

    /// Send application-owned endpoint payloads to one resolved peer.
    ///
    /// This is the canonical endpoint-data send path for applications that
    /// already validate and cache peer identities in their own routing table.
    /// It avoids per-packet npub allocation, endpoint cache lookup, and
    /// `PeerIdentity::from_npub` parsing while preserving owned-payload
    /// semantics.
    pub async fn send_batch_to_peer(
        &self,
        remote: PeerIdentity,
        payloads: Vec<Vec<u8>>,
    ) -> Result<(), FipsEndpointError> {
        self.send_payloads_to_peer(remote, payloads)
    }

    /// Register one local FSP DataPacket destination port.
    ///
    /// Port 256 remains reserved for the built-in IPv6 shim. Datagrams for
    /// unregistered ports are discarded by the authenticated receive path.
    pub async fn register_service(&self, port: u16) -> Result<(), FipsEndpointError> {
        if port == crate::node::session_wire::FSP_PORT_IPV6_SHIM {
            return Err(FipsEndpointError::ServicePortReserved { port });
        }

        let (response_tx, response_rx) = oneshot::channel();
        self.endpoint_control_tx
            .send(NodeEndpointControlCommand::RegisterService { port, response_tx })
            .await
            .map_err(|_| FipsEndpointError::Closed)?;
        if !response_rx.await.map_err(|_| FipsEndpointError::Closed)? {
            return Err(FipsEndpointError::ServicePortAlreadyRegistered { port });
        }
        self.registered_services
            .lock()
            .map_err(|_| FipsEndpointError::Closed)?
            .insert(port);
        Ok(())
    }

    /// Send one owned FSP DataPacket service payload to a resolved peer.
    pub async fn send_datagram(
        &self,
        remote: PeerIdentity,
        source_port: u16,
        destination_port: u16,
        payload: Vec<u8>,
    ) -> Result<(), FipsEndpointError> {
        self.send_service_datagrams_to_peer(
            remote,
            vec![FipsEndpointOutboundDatagram::new(
                source_port,
                destination_port,
                payload,
            )],
        )
    }

    /// Send a caller-owned batch of FSP DataPacket service payloads to one peer.
    pub async fn send_datagram_batch_to_peer(
        &self,
        remote: PeerIdentity,
        datagrams: Vec<FipsEndpointOutboundDatagram>,
    ) -> Result<(), FipsEndpointError> {
        self.send_service_datagrams_to_peer(remote, datagrams)
    }

    fn send_service_datagrams_to_peer(
        &self,
        remote: PeerIdentity,
        datagrams: Vec<FipsEndpointOutboundDatagram>,
    ) -> Result<(), FipsEndpointError> {
        let max = crate::node::session_wire::fsp_service_datagram_max_body_len();
        if let Some(datagram) = datagrams.iter().find(|datagram| datagram.data.len() > max) {
            return Err(FipsEndpointError::ServiceDatagramTooLarge {
                len: datagram.data.len(),
                max,
            });
        }
        if datagrams.is_empty() {
            return Ok(());
        }

        if *remote.node_addr() == self.node_addr {
            let deliveries = {
                let registered = self
                    .registered_services
                    .lock()
                    .map_err(|_| FipsEndpointError::Closed)?;
                datagrams
                    .into_iter()
                    .filter(|datagram| registered.contains(&datagram.destination_port))
                    .map(|datagram| {
                        crate::node::EndpointServiceDatagramDelivery::new(
                            self.identity,
                            datagram.source_port,
                            datagram.destination_port,
                            crate::transport::PacketBuffer::new(datagram.data),
                        )
                    })
                    .collect()
            };
            return self
                .inbound_service_tx
                .send(deliveries)
                .map_err(|_| FipsEndpointError::Closed);
        }

        self.send_endpoint_data_batch(remote, service_datagram_payloads(datagrams)?)
    }

    fn send_payloads_to_peer(
        &self,
        remote: PeerIdentity,
        payloads: Vec<Vec<u8>>,
    ) -> Result<(), FipsEndpointError> {
        let payloads = endpoint_data_payloads_from_vecs(payloads)?;
        if *remote.node_addr() == self.node_addr {
            for payload in payloads {
                self.send_loopback(payload)?;
            }
            return Ok(());
        }

        self.send_endpoint_data_batch(remote, payloads)
    }

    fn send_endpoint_data_batch(
        &self,
        remote: PeerIdentity,
        payloads: Vec<EndpointDataPayload>,
    ) -> Result<(), FipsEndpointError> {
        if payloads.is_empty() {
            return Ok(());
        }

        if payloads.len() <= ENDPOINT_DATA_BATCH_MAX {
            self.enqueue_endpoint_data_batch(remote, payloads)?;
            return Ok(());
        }

        let mut payloads = payloads.into_iter();
        loop {
            let payload_batch: Vec<_> = payloads.by_ref().take(ENDPOINT_DATA_BATCH_MAX).collect();
            if payload_batch.is_empty() {
                break;
            }
            self.enqueue_endpoint_data_batch(remote, payload_batch)?;
        }
        Ok(())
    }

    fn enqueue_endpoint_data_batch(
        &self,
        remote: PeerIdentity,
        payload_batch: Vec<EndpointDataPayload>,
    ) -> Result<(), FipsEndpointError> {
        // Fire-and-forget: caller already drops the result, so skip
        // the per-packet `oneshot::channel()` allocation entirely.
        // Endpoint data now enters the dataplane bulk lane directly, without a
        // per-packet oneshot or control-command hop.
        if let Some(batch) = NodeEndpointDataBatch::from_payloads(
            remote,
            payload_batch,
            crate::perf_profile::stamp(),
        ) {
            self.endpoint_data_batches
                .send_or_drop(batch)
                .map_err(|_| FipsEndpointError::Closed)?;
        }
        Ok(())
    }

    fn send_loopback(&self, payload: EndpointDataPayload) -> Result<(), FipsEndpointError> {
        self.inbound_endpoint_tx
            .send(NodeEndpointEvent {
                messages: vec![crate::node::EndpointDataDelivery::new(
                    self.identity,
                    payload.into_body(),
                )],
                queued_at: crate::perf_profile::stamp(),
            })
            .map_err(|_| FipsEndpointError::Closed)
    }

    /// Receive one endpoint message, then drain ready follow-ons into a caller-owned buffer.
    ///
    /// This is the receive-side counterpart to [`Self::send_batch_to_peer`]:
    /// callers still get individual source-attributed messages, but a hot
    /// dataplane consumer can amortize the endpoint receiver lock, task wake,
    /// and message buffer allocation across a bounded burst.
    pub async fn recv_batch_into(
        &self,
        messages: &mut Vec<FipsEndpointMessage>,
        max: usize,
    ) -> Option<usize> {
        let max = max.clamp(1, ENDPOINT_RECV_BATCH_MAX);
        messages.clear();

        let mut state = self.inbound_endpoint_rx.lock().await;
        state.drain_pending_into(messages, max);

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

    /// Receive one registered service datagram and drain ready follow-ons.
    pub async fn recv_service_datagram_batch_into(
        &self,
        datagrams: &mut Vec<FipsEndpointServiceDatagram>,
        max: usize,
    ) -> Option<usize> {
        let max = max.clamp(1, ENDPOINT_RECV_BATCH_MAX);
        datagrams.clear();

        let mut state = self.inbound_service_rx.lock().await;
        state.drain_pending_into(datagrams, max);
        while datagrams.len() < max {
            let event = if datagrams.is_empty() {
                state.rx.recv().await?
            } else {
                match state.rx.try_recv() {
                    Ok(event) => event,
                    Err(_) => break,
                }
            };
            state.push_event_into(event, datagrams, max);
        }
        Some(datagrams.len())
    }

    /// Synchronous blocking batch send to one resolved remote identity.
    ///
    /// This is the blocking-thread counterpart to [`Self::send_batch_to_peer`].
    /// The caller keeps routing authority: FIPS only receives already-owned
    /// endpoint payloads for the resolved peer.
    pub fn blocking_send_batch_to_peer(
        &self,
        remote: PeerIdentity,
        payloads: Vec<Vec<u8>>,
    ) -> Result<(), FipsEndpointError> {
        self.send_payloads_to_peer(remote, payloads)
    }

    /// Synchronous blocking send of one FSP DataPacket service payload.
    pub fn blocking_send_datagram(
        &self,
        remote: PeerIdentity,
        source_port: u16,
        destination_port: u16,
        payload: Vec<u8>,
    ) -> Result<(), FipsEndpointError> {
        self.send_service_datagrams_to_peer(
            remote,
            vec![FipsEndpointOutboundDatagram::new(
                source_port,
                destination_port,
                payload,
            )],
        )
    }

    /// Synchronous blocking send of an owned service datagram batch.
    pub fn blocking_send_datagram_batch_to_peer(
        &self,
        remote: PeerIdentity,
        datagrams: Vec<FipsEndpointOutboundDatagram>,
    ) -> Result<(), FipsEndpointError> {
        self.send_service_datagrams_to_peer(remote, datagrams)
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
        let max = max.clamp(1, ENDPOINT_RECV_BATCH_MAX);
        messages.clear();

        let mut state = self.inbound_endpoint_rx.blocking_lock();
        state.drain_pending_into(messages, max);

        while messages.len() < max {
            let event = if messages.is_empty() {
                state.rx.blocking_recv()?
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

    /// Synchronous blocking receive of registered service datagrams.
    pub fn blocking_recv_service_datagram_batch_into(
        &self,
        datagrams: &mut Vec<FipsEndpointServiceDatagram>,
        max: usize,
    ) -> Option<usize> {
        let max = max.clamp(1, ENDPOINT_RECV_BATCH_MAX);
        datagrams.clear();

        let mut state = self.inbound_service_rx.blocking_lock();
        state.drain_pending_into(datagrams, max);
        while datagrams.len() < max {
            let event = if datagrams.is_empty() {
                state.rx.blocking_recv()?
            } else {
                match state.rx.try_recv() {
                    Ok(event) => event,
                    Err(_) => break,
                }
            };
            state.push_event_into(event, datagrams, max);
        }
        Some(datagrams.len())
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
        self.endpoint_control_tx
            .send(NodeEndpointControlCommand::UpdatePeers { peers, response_tx })
            .await
            .map_err(|_| FipsEndpointError::Closed)?;

        match response_rx.await.map_err(|_| FipsEndpointError::Closed)? {
            Ok(outcome) => Ok(UpdatePeersOutcome::from(outcome)),
            Err(error) => Err(FipsEndpointError::Node(error)),
        }
    }

    /// Force immediate direct-path refresh attempts for configured peers.
    ///
    /// Unlike [`FipsEndpoint::update_peers`], this does not require a config
    /// diff. It asks the running node to race a fresh direct handshake for the
    /// supplied active peers while preserving existing sessions and routes.
    pub async fn refresh_peer_paths(
        &self,
        peers: Vec<PeerIdentity>,
    ) -> Result<usize, FipsEndpointError> {
        let (response_tx, response_rx) = oneshot::channel();
        let npubs = peers.into_iter().map(|peer| peer.npub()).collect();
        self.endpoint_control_tx
            .send(NodeEndpointControlCommand::RefreshPeerPaths { npubs, response_tx })
            .await
            .map_err(|_| FipsEndpointError::Closed)?;

        match response_rx.await.map_err(|_| FipsEndpointError::Closed)? {
            Ok(refreshed) => Ok(refreshed),
            Err(error) => Err(FipsEndpointError::Node(error)),
        }
    }

    /// Snapshot authenticated peers known by the endpoint.
    pub async fn peers(&self) -> Result<Vec<FipsEndpointPeer>, FipsEndpointError> {
        let (response_tx, response_rx) = oneshot::channel();
        self.endpoint_control_tx
            .send(NodeEndpointControlCommand::PeerSnapshot { response_tx })
            .await
            .map_err(|_| FipsEndpointError::Closed)?;

        response_rx
            .await
            .map(|peers| peers.into_iter().map(FipsEndpointPeer::from).collect())
            .map_err(|_| FipsEndpointError::Closed)
    }

    /// Snapshot the endpoint addresses this node is currently advertising via
    /// Nostr discovery.
    pub async fn local_advertised_endpoints(
        &self,
    ) -> Result<Vec<crate::discovery::nostr::OverlayEndpointAdvert>, FipsEndpointError> {
        let (response_tx, response_rx) = oneshot::channel();
        self.endpoint_control_tx
            .send(NodeEndpointControlCommand::LocalAdvertSnapshot { response_tx })
            .await
            .map_err(|_| FipsEndpointError::Closed)?;

        response_rx.await.map_err(|_| FipsEndpointError::Closed)
    }

    /// Snapshot live Nostr relay states used by the embedded endpoint.
    pub async fn relay_statuses(&self) -> Result<Vec<FipsEndpointRelayStatus>, FipsEndpointError> {
        let (response_tx, response_rx) = oneshot::channel();
        self.endpoint_control_tx
            .send(NodeEndpointControlCommand::RelaySnapshot { response_tx })
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
        self.endpoint_control_tx
            .send(NodeEndpointControlCommand::UpdateRelays {
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
    pub async fn shutdown(&self) -> Result<(), FipsEndpointError> {
        let shutdown_tx = self
            .shutdown_tx
            .lock()
            .map_err(|_| FipsEndpointError::Closed)?
            .take();
        if let Some(shutdown_tx) = shutdown_tx {
            let _ = shutdown_tx.send(());
        }
        let task = self
            .task
            .lock()
            .map_err(|_| FipsEndpointError::Closed)?
            .take();
        if let Some(task) = task {
            task.await??;
        }
        Ok(())
    }
}

impl Drop for FipsEndpoint {
    fn drop(&mut self) {
        if let Ok(mut shutdown_tx) = self.shutdown_tx.lock()
            && let Some(shutdown_tx) = shutdown_tx.take()
        {
            let _ = shutdown_tx.send(());
        }
        if let Ok(mut task) = self.task.lock()
            && let Some(task) = task.take()
        {
            task.abort();
        }
    }
}
