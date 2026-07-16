//! WebRTC DataChannel transport.
//!
//! SDP offer/answer exchange is carried over an existing authenticated FIPS
//! session. Ordinary FIPS packets then travel as binary SCTP data-channel
//! messages. Reliability and ordering follow [`crate::WebRtcConfig`]; both are
//! enabled by default.

use super::link_negotiation::{
    LinkNegotiationKind, LinkNegotiationMessage, OutboundLinkNegotiation,
};
use super::{
    ConnectionState, DiscoveredPeer, PacketBuffer, PacketTx, ReceivedPacket, Transport,
    TransportAddr, TransportError, TransportId, TransportState, TransportType,
};
use crate::config::{NostrDiscoveryConfig, WebRtcConfig, validate_webrtc_candidate_socket_budget};
use ::webrtc::data_channel::RTCDataChannel;
use ::webrtc::data_channel::data_channel_init::RTCDataChannelInit;
use ::webrtc::data_channel::data_channel_message::DataChannelMessage;
use ::webrtc::ice_transport::ice_server::RTCIceServer;
use ::webrtc::peer_connection::RTCPeerConnection;
use ::webrtc::peer_connection::configuration::RTCConfiguration;
use ::webrtc::peer_connection::peer_connection_state::RTCPeerConnectionState;
use ::webrtc::peer_connection::sdp::session_description::RTCSessionDescription;
use bytes::Bytes;
use nostr::prelude::PublicKey;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::fmt::Display;
use std::future::Future;
use std::sync::{Arc, Mutex as StdMutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::{Mutex, mpsc};
use tokio::task::{JoinHandle, JoinSet};
use tracing::{debug, info, trace, warn};

const SIGNAL_TTL_MS: u64 = 60_000;
const WEBRTC_READY_FRAME: &[u8] = &[0xff, 0x46, 0x57, 0x52, 0x31]; // FWR1
const WEBRTC_READY_FALLBACK_MS: u64 = 250;
const WEBRTC_IO_TIMEOUT: Duration = Duration::from_secs(1);
const MAX_WEBRTC_SIGNAL_TASKS: usize = 32;
const MAX_WEBRTC_SEEN_SESSIONS: usize = 1024;
const MAX_WEBRTC_SDP_LENGTH: usize = 48 * 1024;
const MAX_WEBRTC_CANDIDATE_LENGTH: usize = 2048;

mod candidate_policy;
mod lifecycle;
mod mdns;
mod signaling;

#[cfg(test)]
#[path = "webrtc/send_tests.rs"]
mod send_tests;

#[cfg(test)]
use candidate_policy::build_webrtc_api;
use candidate_policy::{
    CandidateAddressPolicy, EmbeddedCandidateCount, EmbeddedCandidateScope,
    validate_embedded_ice_candidates,
};
pub use lifecycle::WebRtcResourceSnapshot;
use lifecycle::{
    ManagedPeer, ManagedPeerConnection, PhysicalPhase, PhysicalReservation, PhysicalReserveError,
    PhysicalResources, WeakPhysicalResources, WebRtcSessionOwner,
};
use mdns::SharedMdnsResolver;
use signaling::FipsSignalSender;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct IceCandidateJson {
    candidate: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    sdp_mid: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    sdp_m_line_index: Option<u16>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct WebRtcSignalPayload {
    #[serde(skip_serializing_if = "Option::is_none")]
    sdp: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    candidates: Option<Vec<IceCandidateJson>>,
}

type WebRtcSignal = LinkNegotiationMessage<WebRtcSignalPayload>;

struct IncomingSignal {
    signal: WebRtcSignal,
    sender: PublicKey,
    sender_full_hex: String,
}

struct WebRtcConnection {
    session_id: String,
    pc: ManagedPeer,
    data_channel: Arc<RTCDataChannel>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum PendingDialOrigin {
    Local,
    Remote,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum CleanupWait {
    Started,
    Bounded,
}

struct PendingDial {
    session_id: String,
    phase_owner_id: String,
    pc: ManagedPeer,
    created_at_ms: u64,
    origin: PendingDialOrigin,
    deadline: tokio::time::Instant,
}

type ConnectionPool = Arc<Mutex<HashMap<TransportAddr, WebRtcConnection>>>;
type PendingPool = Arc<Mutex<HashMap<TransportAddr, PendingDial>>>;
type FailedPool = Arc<Mutex<HashMap<TransportAddr, String>>>;
type ReadyPool = Arc<Mutex<HashSet<TransportAddr>>>;
type SeenSessionPool = Arc<Mutex<HashMap<(TransportAddr, String), u64>>>;

#[cfg(test)]
fn test_webrtc_addr(identity: &crate::Identity) -> TransportAddr {
    TransportAddr::from_string(&canonical_webrtc_pubkey_hex(identity.pubkey_full()))
}

#[derive(Clone)]
struct WebRtcSessionOwners {
    pool: ConnectionPool,
    pending: PendingPool,
    failed: FailedPool,
    ready: ReadyPool,
}

impl WebRtcSessionOwners {
    fn from_refs(
        pool: &ConnectionPool,
        pending: &PendingPool,
        failed: &FailedPool,
        ready: &ReadyPool,
    ) -> Self {
        Self {
            pool: Arc::clone(pool),
            pending: Arc::clone(pending),
            failed: Arc::clone(failed),
            ready: Arc::clone(ready),
        }
    }
}

/// WebRTC transport for FIPS.
pub struct WebRtcTransport {
    transport_id: TransportId,
    name: Option<String>,
    config: WebRtcConfig,
    state: TransportState,
    #[cfg(test)]
    api: Arc<::webrtc::api::API>,
    candidate_policy: CandidateAddressPolicy,
    mdns_resolver: SharedMdnsResolver,
    packet_tx: PacketTx,
    pool: ConnectionPool,
    pending: PendingPool,
    failed: FailedPool,
    ready: ReadyPool,
    seen_sessions: SeenSessionPool,
    physical: PhysicalResources,
    signal_tx: mpsc::UnboundedSender<IncomingSignal>,
    signal_rx: Option<mpsc::UnboundedReceiver<IncomingSignal>>,
    outgoing_signal_rx: mpsc::UnboundedReceiver<OutboundLinkNegotiation>,
    signal_task: Option<JoinHandle<()>>,
    dial_tasks: StdMutex<Vec<JoinHandle<Result<(), TransportError>>>>,
    negotiation: Arc<WebRtcNegotiationCounters>,
    signaling: FipsSignalSender,
    local_pubkey_hex: String,
    stun_servers: Vec<String>,
}

impl WebRtcTransport {
    /// Create a new WebRTC transport.
    ///
    /// This bounds one instance. Callers constructing multiple instances should
    /// validate their aggregate configuration with [`crate::Config::validate`].
    pub fn new(
        transport_id: TransportId,
        name: Option<String>,
        config: WebRtcConfig,
        packet_tx: PacketTx,
        identity: &crate::Identity,
        nostr_config: &NostrDiscoveryConfig,
    ) -> Result<Self, TransportError> {
        let local_pubkey_hex = canonical_webrtc_pubkey_hex(identity.pubkey_full());
        let stun_servers = config.stun_servers(&nostr_config.stun_servers);
        validate_webrtc_candidate_socket_budget(config.max_connections(), &stun_servers)
            .map_err(TransportError::StartFailed)?;
        let (signal_tx, signal_rx) = mpsc::unbounded_channel();
        let (outgoing_signal_tx, outgoing_signal_rx) = mpsc::unbounded_channel();
        let signaling = FipsSignalSender::new(outgoing_signal_tx);
        let physical = PhysicalResources::new(config.max_connections());

        // The WebRTC crate allocates one multicast listener per ICE agent in
        // QueryOnly mode. Keep every peer connection fully disabled and resolve
        // browser `.local` candidates through one bounded transport owner.
        let candidate_policy = CandidateAddressPolicy::system();
        #[cfg(test)]
        let api = candidate_policy.build_api()?;
        let mdns_resolver =
            SharedMdnsResolver::new(config.resolve_mdns_candidates(), config.max_connections())?;

        Ok(Self {
            transport_id,
            name,
            config,
            state: TransportState::Configured,
            #[cfg(test)]
            api,
            candidate_policy,
            mdns_resolver,
            packet_tx,
            pool: Arc::new(Mutex::new(HashMap::new())),
            pending: Arc::new(Mutex::new(HashMap::new())),
            failed: Arc::new(Mutex::new(HashMap::new())),
            ready: Arc::new(Mutex::new(HashSet::new())),
            seen_sessions: Arc::new(Mutex::new(HashMap::new())),
            physical,
            signal_tx,
            signal_rx: Some(signal_rx),
            outgoing_signal_rx,
            signal_task: None,
            dial_tasks: StdMutex::new(Vec::new()),
            negotiation: Arc::new(WebRtcNegotiationCounters::default()),
            signaling,
            local_pubkey_hex,
            stun_servers,
        })
    }

    /// Get the instance name.
    pub fn name(&self) -> Option<&str> {
        self.name.as_deref()
    }

    fn runtime(&self) -> WebRtcRuntime {
        WebRtcRuntime {
            transport_id: self.transport_id,
            config: self.config.clone(),
            candidate_policy: self.candidate_policy.clone(),
            mdns_resolver: self.mdns_resolver.clone(),
            packet_tx: self.packet_tx.clone(),
            pool: Arc::clone(&self.pool),
            pending: Arc::clone(&self.pending),
            failed: Arc::clone(&self.failed),
            ready: Arc::clone(&self.ready),
            seen_sessions: Arc::clone(&self.seen_sessions),
            physical: self.physical.clone(),
            negotiation: Arc::clone(&self.negotiation),
            local_pubkey_hex: self.local_pubkey_hex.clone(),
            stun_servers: self.stun_servers.clone(),
            signaling: self.signaling.clone(),
        }
    }

    #[cfg(test)]
    pub(crate) fn use_canonical_loopback_candidate_profile(
        &mut self,
    ) -> Result<(), TransportError> {
        let policy = CandidateAddressPolicy::loopback_udp4();
        self.api = policy.build_api()?;
        self.candidate_policy = policy;
        Ok(())
    }

    /// Start the transport asynchronously.
    pub async fn start_async(&mut self) -> Result<(), TransportError> {
        if !self.state.can_start() {
            return Err(TransportError::AlreadyStarted);
        }
        self.state = TransportState::Starting;
        self.physical.start_accepting();
        self.mdns_resolver.start_accepting();

        let mut signal_rx = self
            .signal_rx
            .take()
            .ok_or_else(|| TransportError::StartFailed("signal receiver already taken".into()))?;
        let runtime = self.runtime();
        self.signal_task = Some(tokio::spawn(async move {
            let max_tasks = runtime
                .config
                .max_connections()
                .clamp(1, MAX_WEBRTC_SIGNAL_TASKS);
            let mut tasks = JoinSet::new();
            loop {
                let has_handler_capacity = tasks.len() < max_tasks;
                tokio::select! {
                    completed = tasks.join_next(), if !tasks.is_empty() => {
                        if let Some(Err(err)) = completed {
                            warn!(error = %err, "WebRTC signal task failed");
                        }
                    }
                    incoming = signal_rx.recv(), if has_handler_capacity => {
                        let Some(incoming) = incoming else { break };
                        let runtime = runtime.clone();
                        tasks.spawn(async move {
                            if let Err(err) = runtime.handle_incoming_signal(incoming).await {
                                trace!(error = %err, "failed to handle WebRTC signal");
                            }
                        });
                    }
                }
            }
            tasks.abort_all();
            while tasks.join_next().await.is_some() {}
        }));

        self.state = TransportState::Up;
        info!(
            transport_id = %self.transport_id,
            stun_servers = self.stun_servers.len(),
            mtu = self.config.mtu(),
            "WebRTC transport started with FIPS session signaling"
        );
        Ok(())
    }

    /// Stop the transport asynchronously.
    pub async fn stop_async(&mut self) -> Result<(), TransportError> {
        if !self.state.is_operational() {
            return Err(TransportError::NotStarted);
        }
        self.physical.stop_accepting();
        if let Some(task) = self.signal_task.take() {
            task.abort();
            let _ = task.await;
        }
        let dial_tasks = {
            let mut tasks = self.dial_tasks.lock().expect("WebRTC dial tasks");
            std::mem::take(&mut *tasks)
        };
        for task in &dial_tasks {
            task.abort();
        }
        for task in dial_tasks {
            let _ = task.await;
        }
        let mdns_shutdown = self.mdns_resolver.stop().await;
        self.failed.lock().await.clear();
        self.seen_sessions.lock().await.clear();
        // Cleanup and promotion use this same pool -> pending order. Drain
        // both logical owners and readiness in one epoch so no callback can
        // reinsert ready state after stop has removed its exact session.
        let (pending, connections) = {
            let mut pool = self.pool.lock().await;
            let mut pending = self.pending.lock().await;
            let mut ready = self.ready.lock().await;
            let pending = pending
                .drain()
                .map(|(_, pending)| pending)
                .collect::<Vec<_>>();
            let connections = pool
                .drain()
                .map(|(_, connection)| connection)
                .collect::<Vec<_>>();
            ready.clear();
            (pending, connections)
        };
        // Empty logical owner maps before starting physical close. This
        // breaks callback back-reference cycles and lets all peer cleanups run
        // concurrently under the one physical-owner cap.
        for pending in pending {
            start_peer_connection_cleanup(pending.pc);
        }
        for connection in connections {
            drop(connection.data_channel);
            start_peer_connection_cleanup(connection.pc);
        }
        let quiescent = self
            .physical
            .wait_for_quiescence(WEBRTC_IO_TIMEOUT.saturating_mul(2))
            .await;
        if !quiescent {
            let snapshot = self.physical.snapshot();
            self.state = TransportState::Failed;
            return Err(TransportError::ShutdownFailed(format!(
                "WebRTC physical owners did not quiesce: {snapshot:?}"
            )));
        }
        // Detached deadline tasks hold only weak map references, but one can
        // remove a pending dial immediately before stop drains it and publish
        // the failure immediately afterward. Physical quiescence orders after
        // that cleanup, so this final clear prevents a stopped transport from
        // retaining a stale connection failure.
        self.ready.lock().await.clear();
        self.failed.lock().await.clear();
        if let Err(error) = mdns_shutdown {
            self.state = TransportState::Failed;
            return Err(error);
        }
        self.state = TransportState::Down;
        Ok(())
    }

    /// Send a FIPS packet over an established data channel.
    pub async fn send_async(
        &self,
        addr: &TransportAddr,
        data: &[u8],
    ) -> Result<usize, TransportError> {
        let addr = canonical_webrtc_addr(addr)?;
        if data.len() > self.config.mtu() as usize {
            return Err(TransportError::MtuExceeded {
                packet_size: data.len(),
                mtu: self.config.mtu(),
            });
        }
        let data_channel = {
            let pool = self.pool.lock().await;
            pool.get(&addr).map(|conn| Arc::clone(&conn.data_channel))
        }
        .ok_or_else(|| TransportError::SendFailed(format!("no WebRTC connection to {addr}")))?;

        bounded_webrtc_send(
            WEBRTC_IO_TIMEOUT,
            data_channel.send(&Bytes::copy_from_slice(data)),
            || self.close_connection_async(&addr),
        )
        .await
    }

    /// Initiate a non-blocking WebRTC dial.
    pub async fn connect_async(&self, addr: &TransportAddr) -> Result<(), TransportError> {
        let addr = canonical_webrtc_addr(addr)?;
        if self.pool.lock().await.contains_key(&addr) {
            return Ok(());
        }
        if self.pending.lock().await.contains_key(&addr) {
            return Ok(());
        }
        let reservation = match self.physical.reserve(&addr) {
            Ok(reservation) => reservation,
            Err(PhysicalReserveError::PeerBusy(
                PhysicalPhase::Creating | PhysicalPhase::Active,
            )) => return Ok(()),
            Err(
                PhysicalReserveError::Stopped
                | PhysicalReserveError::Capacity
                | PhysicalReserveError::PeerBusy(PhysicalPhase::Closing),
            ) => return Err(TransportError::ConnectionRefused),
        };
        self.failed.lock().await.remove(&addr);

        let runtime = self.runtime();
        let remote_addr = addr;
        let deadline =
            tokio::time::Instant::now() + Duration::from_millis(self.config.connect_timeout_ms());
        let task = tokio::spawn(async move {
            let result = runtime
                .start_outbound(remote_addr, reservation, deadline, None)
                .await;
            if let Err(error) = &result {
                trace!(error = %error, "WebRTC outbound setup failed");
            }
            result
        });
        let mut tasks = self.dial_tasks.lock().expect("WebRTC dial tasks");
        tasks.retain(|task| !task.is_finished());
        tasks.push(task);
        Ok(())
    }

    /// Return physical peer-connection conservation counters.
    pub fn resource_snapshot(&self) -> WebRtcResourceSnapshot {
        self.physical.snapshot()
    }

    /// Drain SDP negotiation messages for delivery over encrypted FIPS
    /// sessions. Relay adapters must never consume or republish this queue.
    pub(crate) fn drain_link_negotiations(&mut self, limit: usize) -> Vec<OutboundLinkNegotiation> {
        let mut drained = Vec::with_capacity(limit.min(32));
        while drained.len() < limit {
            match self.outgoing_signal_rx.try_recv() {
                Ok(signal) => drained.push(signal),
                Err(mpsc::error::TryRecvError::Empty | mpsc::error::TryRecvError::Disconnected) => {
                    break;
                }
            }
        }
        drained
    }

    /// Deliver an authenticated FIPS-session SDP negotiation message to the
    /// WebRTC runtime.
    pub(crate) fn ingest_link_negotiation(
        &self,
        source: secp256k1::PublicKey,
        message: LinkNegotiationMessage,
    ) -> Result<(), TransportError> {
        let signal = message
            .typed_payload::<WebRtcSignalPayload>()
            .map_err(|error| TransportError::InvalidAddress(error.to_string()))?;
        let (sender_xonly, _) = source.x_only_public_key();
        let sender = PublicKey::from_slice(&sender_xonly.serialize())
            .map_err(|error| TransportError::InvalidAddress(error.to_string()))?;
        let sender_full_hex = canonical_webrtc_pubkey_hex(source);
        self.signal_tx
            .send(IncomingSignal {
                signal,
                sender,
                sender_full_hex,
            })
            .map_err(|_| TransportError::NotStarted)
    }

    /// Query connection state synchronously.
    pub fn connection_state_sync(&self, addr: &TransportAddr) -> ConnectionState {
        let addr = match canonical_webrtc_addr(addr) {
            Ok(addr) => addr,
            Err(error) => return ConnectionState::Failed(error.to_string()),
        };
        let pool = match self.pool.try_lock() {
            Ok(pool) => pool,
            Err(_) => return ConnectionState::Connecting,
        };
        if pool.contains_key(&addr) {
            return match self.ready.try_lock() {
                Ok(ready) if ready.contains(&addr) => ConnectionState::Connected,
                _ => ConnectionState::Connecting,
            };
        }
        drop(pool);

        let failed = match self.failed.try_lock() {
            Ok(failed) => failed,
            Err(_) => return ConnectionState::Connecting,
        };
        if let Some(reason) = failed.get(&addr) {
            return ConnectionState::Failed(reason.clone());
        }
        drop(failed);

        match self.pending.try_lock() {
            Ok(pending) if pending.contains_key(&addr) => ConnectionState::Connecting,
            Ok(_) => ConnectionState::None,
            Err(_) => ConnectionState::Connecting,
        }
    }

    /// Close a WebRTC connection.
    pub async fn close_connection_async(&self, addr: &TransportAddr) {
        let Ok(addr) = canonical_webrtc_addr(addr) else {
            return;
        };
        let owners =
            WebRtcSessionOwners::from_refs(&self.pool, &self.pending, &self.failed, &self.ready);
        cleanup_webrtc_session(&owners, &addr, None, None, CleanupWait::Bounded).await;
    }

    /// Schedule connection cleanup from synchronous node-lifecycle paths.
    pub fn close_connection_detached(&self, addr: &TransportAddr) {
        if let Some(task) = self.close_connection_detached_task(addr) {
            drop(task);
        }
    }

    fn close_connection_detached_task(&self, addr: &TransportAddr) -> Option<JoinHandle<()>> {
        let addr = canonical_webrtc_addr(addr).ok()?;
        let generation = self.physical.generation(&addr)?;
        Some(spawn_webrtc_session_cleanup(
            Arc::clone(&self.pool),
            Arc::clone(&self.pending),
            Arc::clone(&self.failed),
            Arc::clone(&self.ready),
            addr,
            Some(WebRtcSessionOwner::for_generation(generation)),
            None,
        ))
    }
}

impl Drop for WebRtcTransport {
    fn drop(&mut self) {
        self.physical.stop_accepting();
        if let Some(task) = self.signal_task.take() {
            task.abort();
        }
        if let Ok(mut tasks) = self.dial_tasks.lock() {
            for task in tasks.drain(..) {
                task.abort();
            }
        }
    }
}

async fn reserve_physical_for_incoming_offer(
    physical: &PhysicalResources,
    addr: &TransportAddr,
    expires_at_ms: u64,
    deadline: tokio::time::Instant,
) -> Result<PhysicalReservation, PhysicalReserveError> {
    match physical.reserve(addr) {
        Err(PhysicalReserveError::PeerBusy(PhysicalPhase::Closing)) => {
            let signal_remaining =
                Duration::from_millis(expires_at_ms.saturating_sub(now_ms()).min(SIGNAL_TTL_MS));
            let phase_remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            let remaining = signal_remaining.min(phase_remaining);
            if remaining.is_zero()
                || !physical.wait_for_peer_release(addr, remaining).await
                || expires_at_ms < now_ms()
                || tokio::time::Instant::now() >= deadline
                || !physical.is_accepting()
            {
                return Err(PhysicalReserveError::PeerBusy(PhysicalPhase::Closing));
            }
            physical.reserve(addr)
        }
        result => result,
    }
}

async fn bounded_webrtc_send<F, E, C, CF>(
    timeout: Duration,
    send: F,
    cleanup: C,
) -> Result<usize, TransportError>
where
    F: Future<Output = Result<usize, E>>,
    E: Display,
    C: FnOnce() -> CF,
    CF: Future<Output = ()>,
{
    match tokio::time::timeout(timeout, send).await {
        Ok(Ok(bytes)) => Ok(bytes),
        Ok(Err(error)) => {
            let error = error.to_string();
            let _ = tokio::time::timeout(timeout, cleanup()).await;
            Err(TransportError::SendFailed(error))
        }
        Err(_) => {
            // Removing the connection is more important than completing the
            // underlying WebRTC close handshake. A dead SCTP association must
            // never hold the node's single event loop indefinitely.
            let _ = tokio::time::timeout(timeout, cleanup()).await;
            Err(TransportError::Timeout)
        }
    }
}

async fn close_data_channel_bounded(data_channel: Arc<RTCDataChannel>) {
    let _ = tokio::time::timeout(WEBRTC_IO_TIMEOUT, data_channel.close()).await;
}

async fn close_peer_connection_bounded(peer_connection: ManagedPeer) {
    let completion = start_peer_connection_cleanup(peer_connection);
    let _ = tokio::time::timeout(WEBRTC_IO_TIMEOUT, completion.wait()).await;
}

fn start_peer_connection_cleanup(
    peer_connection: ManagedPeer,
) -> Arc<lifecycle::CleanupCompletion> {
    let completion = peer_connection.cleanup_completion();
    spawn_managed_peer_cleanup(&peer_connection);
    // The physical cleanup job owns the raw peer and its permit now. Releasing
    // this managed reference lets it distinguish real escaped raw references
    // from the caller merely waiting for cleanup completion.
    drop(peer_connection);
    completion
}

fn spawn_managed_peer_cleanup(peer_connection: &ManagedPeerConnection) -> bool {
    let Some((peer_connection, cleanup_guard, completion)) = peer_connection.begin_cleanup() else {
        return false;
    };
    let resources = cleanup_guard.resources();
    if tokio::runtime::Handle::try_current().is_err() {
        resources.stop_accepting();
        drop(peer_connection);
        drop(cleanup_guard);
        completion.finish();
        return true;
    }
    let cleanup_resources = resources.clone();
    resources.spawn_cleanup(async move {
        run_physical_peer_cleanup(WEBRTC_IO_TIMEOUT, peer_connection, cleanup_resources).await;
        cleanup_guard.complete();
        completion.finish();
    });
    true
}

async fn run_physical_peer_cleanup(
    timeout: Duration,
    peer_connection: Arc<RTCPeerConnection>,
    resources: PhysicalResources,
) -> bool {
    // Give the normal close path a bounded chance to notify the remote SCTP,
    // DTLS, and ICE stacks. Stopping local ICE first makes a short-lived peer
    // disappear without that terminal handshake, so the remote side can retain
    // the connection and all of its gathered UDP sockets until exhaustion.
    let peer_connection_for_close = Arc::clone(&peer_connection);
    run_physical_peer_cleanup_with_close(timeout, peer_connection, resources, async move {
        peer_connection_for_close.close().await
    })
    .await
}

async fn run_physical_peer_cleanup_with_close<F, E>(
    timeout: Duration,
    peer_connection: Arc<RTCPeerConnection>,
    resources: PhysicalResources,
    full_close: F,
) -> bool
where
    F: Future<Output = Result<(), E>> + Send + 'static,
    E: Send + 'static,
{
    let mut full_close = tokio::spawn(full_close);
    let needs_ice_fallback = match tokio::time::timeout(timeout, &mut full_close).await {
        Ok(Ok(Ok(()))) => false,
        Ok(Ok(Err(_)) | Err(_)) => true,
        Err(_) => {
            // A timed-out full close may still own ICE/SCTP/DTLS resources.
            // Abort and join it before the one explicit ICE fallback, while
            // this cleanup job continues to retain the physical permit.
            full_close.abort();
            let _ = full_close.await;
            true
        }
    };

    finish_physical_peer_cleanup(timeout, peer_connection, resources, !needs_ice_fallback).await
}

async fn finish_physical_peer_cleanup(
    timeout: Duration,
    peer_connection: Arc<RTCPeerConnection>,
    resources: PhysicalResources,
    full_close_succeeded: bool,
) -> bool {
    let needs_ice_fallback = !full_close_succeeded;

    // webrtc 0.17.1's successful full close awaits data-channel, SCTP, DTLS,
    // ICE, and ops teardown. Only a failed/timed-out close needs the owned ICE
    // fallback. Retry fail-closed; capacity is never released on uncertainty.
    if needs_ice_fallback {
        loop {
            if stop_ice_bounded(timeout, &peer_connection).await {
                break;
            }
            resources.note_ice_stop_failure();
            tokio::time::sleep(timeout).await;
        }
    }

    // A raw peer reference can retain DTLS/SCTP/ICE owners even after their
    // close methods return. Capacity remains occupied until this job owns the
    // final raw reference, so replacement churn fails closed instead of
    // allocating around a physically retained peer connection.
    let _straggler_wait =
        (Arc::strong_count(&peer_connection) > 1).then(|| resources.begin_straggler_wait());
    while Arc::strong_count(&peer_connection) > 1 {
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    needs_ice_fallback
}

async fn stop_ice_bounded(timeout: Duration, peer_connection: &Arc<RTCPeerConnection>) -> bool {
    let dtls_transport = peer_connection.dtls_transport();
    let mut ice_stop = tokio::spawn(async move { dtls_transport.ice_transport().stop().await });
    match tokio::time::timeout(timeout, &mut ice_stop).await {
        Ok(Ok(Ok(()))) => true,
        Ok(_) => false,
        Err(_) => {
            ice_stop.abort();
            let _ = ice_stop.await;
            false
        }
    }
}

async fn cleanup_webrtc_session(
    owners: &WebRtcSessionOwners,
    addr: &TransportAddr,
    expected_owner: Option<&WebRtcSessionOwner>,
    failure: Option<String>,
    wait: CleanupWait,
) -> bool {
    // Promotion uses this same pool -> pending lock order. Remove from both
    // maps under one lock epoch so an on_open handoff cannot move the session
    // into the map cleanup has already scanned.
    let (connection, pending_dial) = {
        let mut pool = owners.pool.lock().await;
        let mut pending = owners.pending.lock().await;
        let connection = if pool.get(addr).is_some_and(|connection| {
            expected_owner.is_none_or(|owner| owner.matches(&connection.session_id, &connection.pc))
        }) {
            pool.remove(addr)
        } else {
            None
        };
        let pending_dial = if pending.get(addr).is_some_and(|dial| {
            expected_owner.is_none_or(|owner| owner.matches(&dial.session_id, &dial.pc))
        }) {
            pending.remove(addr)
        } else {
            None
        };
        let removed = connection.is_some() || pending_dial.is_some();
        if removed || expected_owner.is_none() {
            owners.ready.lock().await.remove(addr);
            let mut failed = owners.failed.lock().await;
            failed.remove(addr);
            if let Some(reason) = failure {
                failed.insert(addr.clone(), reason);
            }
        }
        (connection, pending_dial)
    };
    let removed = connection.is_some() || pending_dial.is_some();

    // RTCPeerConnection::close owns data-channel, SCTP, DTLS, and ICE teardown.
    // Drop the duplicate data-channel owner before starting that one tracked
    // physical cleanup path; concurrently closing the same channel can consume
    // the entire full-close budget on the library's internal channel lock.
    let pending_completion = pending_dial.map(|pending| start_peer_connection_cleanup(pending.pc));
    let connection_completion = connection.map(|connection| {
        drop(connection.data_channel);
        start_peer_connection_cleanup(connection.pc)
    });
    match wait {
        CleanupWait::Started => {}
        CleanupWait::Bounded => {
            if let Some(completion) = pending_completion {
                let _ = tokio::time::timeout(WEBRTC_IO_TIMEOUT, completion.wait()).await;
            }
            if let Some(completion) = connection_completion {
                let _ = tokio::time::timeout(WEBRTC_IO_TIMEOUT, completion.wait()).await;
            }
        }
    }
    removed
}

async fn cleanup_terminal_webrtc_session(
    owners: &WebRtcSessionOwners,
    addr: &TransportAddr,
    expected_session: &str,
    failure: Option<String>,
    peer_connection: ManagedPeer,
) -> bool {
    // A terminal callback must remove the exact logical owner before it can
    // transition the physical lease to Closing. READY send/mark operations
    // hold pool across their bounded mutation, so this orders terminal close
    // wholly before or after them instead of racing RTCPeerConnection::close.
    let expected_owner = WebRtcSessionOwner::new(expected_session, &peer_connection);
    let removed = cleanup_webrtc_session(
        owners,
        addr,
        Some(&expected_owner),
        failure,
        CleanupWait::Started,
    )
    .await;
    if !removed {
        // The logical owner may already have been removed by an independent
        // close path. Retain a mapless physical fallback so the permit and ICE
        // owner still enter the one tracked cleanup path.
        drop(start_peer_connection_cleanup(peer_connection));
    }
    removed
}

fn incoming_offer_replaces_pending(
    local_pubkey_hex: &str,
    remote_pubkey_hex: &str,
    pending_origin: PendingDialOrigin,
    pending_created_at_ms: u64,
    incoming_created_at_ms: u64,
) -> bool {
    match pending_origin {
        PendingDialOrigin::Remote => incoming_created_at_ms > pending_created_at_ms,
        PendingDialOrigin::Local => {
            webrtc_xonly_order_key(local_pubkey_hex) > webrtc_xonly_order_key(remote_pubkey_hex)
        }
    }
}

async fn evict_pending_webrtc_session_for_offer(
    pool: &ConnectionPool,
    pending: &PendingPool,
    failed: &FailedPool,
    ready: &ReadyPool,
    addr: &TransportAddr,
    expected_owner: &WebRtcSessionOwner,
) -> bool {
    let pending_dial = {
        let _pool = pool.lock().await;
        let mut pending = pending.lock().await;
        let pending_dial = if pending
            .get(addr)
            .is_some_and(|dial| expected_owner.matches(&dial.session_id, &dial.pc))
        {
            pending.remove(addr)
        } else {
            None
        };
        if pending_dial.is_some() {
            ready.lock().await.remove(addr);
            failed.lock().await.remove(addr);
        }
        pending_dial
    };
    let Some(pending_dial) = pending_dial else {
        return false;
    };
    // begin_cleanup transitions the physical generation to Closing before it
    // returns. The accepted offer then joins the single generation-bound
    // reserve waiter instead of pinning this signal handler on raw ownership.
    drop(start_peer_connection_cleanup(pending_dial.pc));
    true
}

fn spawn_webrtc_session_cleanup(
    pool: ConnectionPool,
    pending: PendingPool,
    failed: FailedPool,
    ready: ReadyPool,
    addr: TransportAddr,
    expected_owner: Option<WebRtcSessionOwner>,
    failure: Option<String>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        let owners = WebRtcSessionOwners {
            pool,
            pending,
            failed,
            ready,
        };
        cleanup_webrtc_session(
            &owners,
            &addr,
            expected_owner.as_ref(),
            failure,
            CleanupWait::Bounded,
        )
        .await;
    })
}

async fn accept_webrtc_offer_once(
    seen_sessions: &SeenSessionPool,
    remote_addr: &TransportAddr,
    session_id: &str,
    expires_at_ms: u64,
    now_ms: u64,
) -> bool {
    let mut seen = seen_sessions.lock().await;
    seen.retain(|_, expires_at| *expires_at > now_ms);

    let key = (remote_addr.clone(), session_id.to_string());
    if seen.contains_key(&key) {
        return false;
    }

    if seen.len() >= MAX_WEBRTC_SEEN_SESSIONS
        && let Some(oldest) = seen
            .iter()
            .min_by_key(|(_, expires_at)| **expires_at)
            .map(|(key, _)| key.clone())
    {
        seen.remove(&oldest);
    }
    seen.insert(key, expires_at_ms);
    true
}

include!("webrtc_utils.rs");
include!("webrtc_state_callbacks.rs");
include!("webrtc_negotiation.rs");
include!("webrtc_runtime.rs");
