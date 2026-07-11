//! WebRTC DataChannel transport.
//!
//! This transport uses the existing FIPS Nostr signaling envelope for SDP
//! offer/answer exchange and carries ordinary FIPS packets as binary SCTP data
//! channel messages. The data channel is configured as unordered and
//! zero-retransmit by default so it behaves like a datagram-ish transport.

use super::{
    ConnectionState, DiscoveredPeer, PacketBuffer, PacketTx, ReceivedPacket, Transport,
    TransportAddr, TransportError, TransportId, TransportState, TransportType,
};
use crate::config::{NostrDiscoveryConfig, WebRtcConfig};
use ::webrtc::api::APIBuilder;
use ::webrtc::api::media_engine::MediaEngine;
use ::webrtc::data_channel::RTCDataChannel;
use ::webrtc::data_channel::data_channel_init::RTCDataChannelInit;
use ::webrtc::data_channel::data_channel_message::DataChannelMessage;
use ::webrtc::ice_transport::ice_server::RTCIceServer;
use ::webrtc::peer_connection::RTCPeerConnection;
use ::webrtc::peer_connection::configuration::RTCConfiguration;
use ::webrtc::peer_connection::peer_connection_state::RTCPeerConnectionState;
use ::webrtc::peer_connection::sdp::session_description::RTCSessionDescription;
use bytes::Bytes;
use futures::future::join_all;
use nostr::prelude::PublicKey;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::fmt::Display;
use std::future::Future;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::{Mutex, mpsc};
use tokio::task::JoinHandle;
use tracing::{debug, info, trace, warn};

const WEBRTC_PROTOCOL: &str = "fips-webrtc-v1";
const WEBRTC_SIGNAL_VERSION: u32 = 1;
const SIGNAL_TTL_MS: u64 = 60_000;
const WEBRTC_READY_FRAME: &[u8] = &[0xff, 0x46, 0x57, 0x52, 0x31]; // FWR1
const WEBRTC_READY_FALLBACK_MS: u64 = 250;
const WEBRTC_IO_TIMEOUT: Duration = Duration::from_secs(1);

mod signaling;

use signaling::{NostrSignalSender, NostrWebRtcSignaling};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
enum WebRtcSignalKind {
    Offer,
    Answer,
    Candidate,
    Reject,
}

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
struct WebRtcSignal {
    protocol: String,
    version: u32,
    session_id: String,
    kind: WebRtcSignalKind,
    sender: String,
    recipient: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    sdp: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    candidates: Option<Vec<IceCandidateJson>>,
    created_at_ms: u64,
    expires_at_ms: u64,
}

struct IncomingSignal {
    signal: WebRtcSignal,
    sender: PublicKey,
}

struct WebRtcConnection {
    session_id: String,
    pc: Arc<RTCPeerConnection>,
    data_channel: Arc<RTCDataChannel>,
}

struct PendingDial {
    session_id: String,
    pc: Arc<RTCPeerConnection>,
}

type ConnectionPool = Arc<Mutex<HashMap<TransportAddr, WebRtcConnection>>>;
type PendingPool = Arc<Mutex<HashMap<TransportAddr, PendingDial>>>;
type FailedPool = Arc<Mutex<HashMap<TransportAddr, String>>>;
type ReadyPool = Arc<Mutex<HashSet<TransportAddr>>>;

/// WebRTC transport for FIPS.
pub struct WebRtcTransport {
    transport_id: TransportId,
    name: Option<String>,
    config: WebRtcConfig,
    state: TransportState,
    api: Arc<::webrtc::api::API>,
    packet_tx: PacketTx,
    pool: ConnectionPool,
    pending: PendingPool,
    failed: FailedPool,
    ready: ReadyPool,
    signal_rx: Option<mpsc::UnboundedReceiver<IncomingSignal>>,
    signal_task: Option<JoinHandle<()>>,
    signaling: Option<NostrWebRtcSignaling>,
    local_pubkey_hex: String,
    local_xonly: PublicKey,
    signal_relays: Vec<String>,
    stun_servers: Vec<String>,
}

impl WebRtcTransport {
    /// Create a new WebRTC transport.
    pub fn new(
        transport_id: TransportId,
        name: Option<String>,
        config: WebRtcConfig,
        packet_tx: PacketTx,
        identity: &crate::Identity,
        nostr_config: &NostrDiscoveryConfig,
    ) -> Result<Self, TransportError> {
        let keys = nostr::Keys::parse(&hex::encode(identity.keypair().secret_bytes()))
            .map_err(|e| TransportError::StartFailed(e.to_string()))?;
        let local_xonly = keys.public_key();
        let local_pubkey_hex = hex::encode(identity.pubkey_full().serialize());
        let signal_relays = config.signal_relays(&nostr_config.dm_relays);
        let stun_servers = config.stun_servers(&nostr_config.stun_servers);
        let (signal_tx, signal_rx) = mpsc::unbounded_channel();
        let signaling = NostrWebRtcSignaling::new(keys, signal_relays.clone(), signal_tx);

        let mut media_engine = MediaEngine::default();
        media_engine
            .register_default_codecs()
            .map_err(|e| TransportError::StartFailed(e.to_string()))?;
        let api = Arc::new(APIBuilder::new().with_media_engine(media_engine).build());

        Ok(Self {
            transport_id,
            name,
            config,
            state: TransportState::Configured,
            api,
            packet_tx,
            pool: Arc::new(Mutex::new(HashMap::new())),
            pending: Arc::new(Mutex::new(HashMap::new())),
            failed: Arc::new(Mutex::new(HashMap::new())),
            ready: Arc::new(Mutex::new(HashSet::new())),
            signal_rx: Some(signal_rx),
            signal_task: None,
            signaling: Some(signaling),
            local_pubkey_hex,
            local_xonly,
            signal_relays,
            stun_servers,
        })
    }

    /// Get the instance name.
    pub fn name(&self) -> Option<&str> {
        self.name.as_deref()
    }

    /// Start the transport asynchronously.
    pub async fn start_async(&mut self) -> Result<(), TransportError> {
        if !self.state.can_start() {
            return Err(TransportError::AlreadyStarted);
        }
        self.state = TransportState::Starting;

        if self.signal_relays.is_empty() {
            self.state = TransportState::Failed;
            return Err(TransportError::StartFailed(
                "WebRTC transport requires Nostr signaling relays".into(),
            ));
        }

        let signaling = self
            .signaling
            .as_mut()
            .ok_or_else(|| TransportError::StartFailed("signaling already taken".into()))?;
        signaling.start(self.local_xonly).await?;

        let mut signal_rx = self
            .signal_rx
            .take()
            .ok_or_else(|| TransportError::StartFailed("signal receiver already taken".into()))?;
        let runtime = WebRtcRuntime {
            transport_id: self.transport_id,
            config: self.config.clone(),
            api: Arc::clone(&self.api),
            packet_tx: self.packet_tx.clone(),
            pool: Arc::clone(&self.pool),
            pending: Arc::clone(&self.pending),
            failed: Arc::clone(&self.failed),
            ready: Arc::clone(&self.ready),
            local_pubkey_hex: self.local_pubkey_hex.clone(),
            signal_relays: self.signal_relays.clone(),
            stun_servers: self.stun_servers.clone(),
            signaling: signaling.sender(),
        };
        self.signal_task = Some(tokio::spawn(async move {
            while let Some(incoming) = signal_rx.recv().await {
                if let Err(err) = runtime.handle_incoming_signal(incoming).await {
                    trace!(error = %err, "failed to handle WebRTC signal");
                }
            }
        }));

        self.state = TransportState::Up;
        info!(
            transport_id = %self.transport_id,
            relays = self.signal_relays.len(),
            stun_servers = self.stun_servers.len(),
            mtu = self.config.mtu(),
            "WebRTC transport started"
        );
        Ok(())
    }

    /// Stop the transport asynchronously.
    pub async fn stop_async(&mut self) -> Result<(), TransportError> {
        if !self.state.is_operational() {
            return Err(TransportError::NotStarted);
        }
        if let Some(task) = self.signal_task.take() {
            task.abort();
        }
        if let Some(signaling) = self.signaling.as_mut() {
            signaling.stop().await;
        }
        self.failed.lock().await.clear();
        let pending = self
            .pending
            .lock()
            .await
            .drain()
            .map(|(_, pending)| pending)
            .collect::<Vec<_>>();
        join_all(
            pending
                .into_iter()
                .map(|pending| close_peer_connection_bounded(pending.pc)),
        )
        .await;
        self.ready.lock().await.clear();
        let connections = self
            .pool
            .lock()
            .await
            .drain()
            .map(|(_, connection)| connection)
            .collect::<Vec<_>>();
        join_all(connections.into_iter().map(|connection| async move {
            close_data_channel_bounded(connection.data_channel).await;
            close_peer_connection_bounded(connection.pc).await;
        }))
        .await;
        self.state = TransportState::Down;
        Ok(())
    }

    /// Send a FIPS packet over an established data channel.
    pub async fn send_async(
        &self,
        addr: &TransportAddr,
        data: &[u8],
    ) -> Result<usize, TransportError> {
        if data.len() > self.config.mtu() as usize {
            return Err(TransportError::MtuExceeded {
                packet_size: data.len(),
                mtu: self.config.mtu(),
            });
        }
        let data_channel = {
            let pool = self.pool.lock().await;
            pool.get(addr).map(|conn| Arc::clone(&conn.data_channel))
        }
        .ok_or_else(|| TransportError::SendFailed(format!("no WebRTC connection to {addr}")))?;

        bounded_webrtc_send(
            WEBRTC_IO_TIMEOUT,
            data_channel.send(&Bytes::copy_from_slice(data)),
            || self.close_connection_async(addr),
        )
        .await
    }

    /// Initiate a non-blocking WebRTC dial.
    pub async fn connect_async(&self, addr: &TransportAddr) -> Result<(), TransportError> {
        validate_compressed_pubkey_addr(addr)?;
        if self.pool.lock().await.contains_key(addr) {
            return Ok(());
        }
        if self.pending.lock().await.contains_key(addr) {
            return Ok(());
        }
        if self.pool.lock().await.len() + self.pending.lock().await.len()
            >= self.config.max_connections()
        {
            return Err(TransportError::ConnectionRefused);
        }
        self.failed.lock().await.remove(addr);

        let runtime = WebRtcRuntime {
            transport_id: self.transport_id,
            config: self.config.clone(),
            api: Arc::clone(&self.api),
            packet_tx: self.packet_tx.clone(),
            pool: Arc::clone(&self.pool),
            pending: Arc::clone(&self.pending),
            failed: Arc::clone(&self.failed),
            ready: Arc::clone(&self.ready),
            local_pubkey_hex: self.local_pubkey_hex.clone(),
            signal_relays: self.signal_relays.clone(),
            stun_servers: self.stun_servers.clone(),
            signaling: self
                .signaling
                .as_ref()
                .ok_or(TransportError::NotStarted)?
                .sender(),
        };
        let remote_addr = addr.clone();
        tokio::spawn(async move {
            if let Err(err) = runtime.start_outbound(remote_addr.clone()).await {
                runtime
                    .mark_failed(remote_addr, format!("WebRTC connect failed: {err}"))
                    .await;
            }
        });
        Ok(())
    }

    /// Query connection state synchronously.
    pub fn connection_state_sync(&self, addr: &TransportAddr) -> ConnectionState {
        let pool = match self.pool.try_lock() {
            Ok(pool) => pool,
            Err(_) => return ConnectionState::Connecting,
        };
        if pool.contains_key(addr) {
            return match self.ready.try_lock() {
                Ok(ready) if ready.contains(addr) => ConnectionState::Connected,
                _ => ConnectionState::Connecting,
            };
        }
        drop(pool);

        let failed = match self.failed.try_lock() {
            Ok(failed) => failed,
            Err(_) => return ConnectionState::Connecting,
        };
        if let Some(reason) = failed.get(addr) {
            return ConnectionState::Failed(reason.clone());
        }
        drop(failed);

        match self.pending.try_lock() {
            Ok(pending) if pending.contains_key(addr) => ConnectionState::Connecting,
            Ok(_) => ConnectionState::None,
            Err(_) => ConnectionState::Connecting,
        }
    }

    /// Close a WebRTC connection.
    pub async fn close_connection_async(&self, addr: &TransportAddr) {
        let pending = self.pending.lock().await.remove(addr);
        let conn = self.pool.lock().await.remove(addr);
        self.failed.lock().await.remove(addr);
        self.ready.lock().await.remove(addr);

        // Logical eviction happens before potentially slow library cleanup so
        // a canceled close future cannot leave the address reserved forever.
        if let Some(pending) = pending {
            close_peer_connection_bounded(pending.pc).await;
        }
        if let Some(conn) = conn {
            close_data_channel_bounded(conn.data_channel).await;
            close_peer_connection_bounded(conn.pc).await;
        }
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
        Ok(Err(error)) => Err(TransportError::SendFailed(error.to_string())),
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

async fn close_peer_connection_bounded(peer_connection: Arc<RTCPeerConnection>) {
    let _ = tokio::time::timeout(WEBRTC_IO_TIMEOUT, peer_connection.close()).await;
}

include!("webrtc_runtime.rs");
