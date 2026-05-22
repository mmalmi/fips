//! WebRTC DataChannel transport.
//!
//! This transport uses the existing FIPS Nostr signaling envelope for SDP
//! offer/answer exchange and carries ordinary FIPS packets as binary SCTP data
//! channel messages. The data channel is configured as unordered and
//! zero-retransmit by default so it behaves like a datagram-ish transport.

use super::{
    ConnectionState, DiscoveredPeer, PacketTx, ReceivedPacket, Transport, TransportAddr,
    TransportError, TransportId, TransportState, TransportType,
};
use crate::config::{NostrDiscoveryConfig, WebRtcConfig};
use crate::discovery::nostr::{SIGNAL_KIND, build_signal_event, unwrap_signal_event};
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
use nostr::prelude::{EventBuilder, Filter, Kind, PublicKey, Timestamp};
use nostr_sdk::{Client, ClientOptions, prelude::RelayPoolNotification};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::{Mutex, broadcast, mpsc};
use tokio::task::JoinHandle;
use tracing::{debug, info, trace, warn};

const WEBRTC_PROTOCOL: &str = "fips-webrtc-v1";
const WEBRTC_SIGNAL_VERSION: u32 = 1;
const SIGNAL_TTL_MS: u64 = 60_000;
const WEBRTC_READY_FRAME: &[u8] = &[0xff, 0x46, 0x57, 0x52, 0x31]; // FWR1
const WEBRTC_READY_FALLBACK_MS: u64 = 250;

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
        self.pending.lock().await.clear();
        self.ready.lock().await.clear();
        let mut pool = self.pool.lock().await;
        for (_, conn) in pool.drain() {
            let _ = conn.data_channel.close().await;
            let _ = conn.pc.close().await;
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

        data_channel
            .send(&Bytes::copy_from_slice(data))
            .await
            .map_err(|e| TransportError::SendFailed(e.to_string()))
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
        if let Ok(pool) = self.pool.try_lock()
            && pool.contains_key(addr)
        {
            if let Ok(ready) = self.ready.try_lock()
                && ready.contains(addr)
            {
                return ConnectionState::Connected;
            }
            return ConnectionState::Connecting;
        }
        if let Ok(failed) = self.failed.try_lock()
            && let Some(reason) = failed.get(addr)
        {
            return ConnectionState::Failed(reason.clone());
        }
        if let Ok(pending) = self.pending.try_lock()
            && pending.contains_key(addr)
        {
            return ConnectionState::Connecting;
        }
        ConnectionState::None
    }

    /// Close a WebRTC connection.
    pub async fn close_connection_async(&self, addr: &TransportAddr) {
        if let Some(pending) = self.pending.lock().await.remove(addr) {
            let _ = pending.pc.close().await;
        }
        if let Some(conn) = self.pool.lock().await.remove(addr) {
            let _ = conn.data_channel.close().await;
            let _ = conn.pc.close().await;
        }
        self.failed.lock().await.remove(addr);
        self.ready.lock().await.remove(addr);
    }
}

#[derive(Clone)]
struct WebRtcRuntime {
    transport_id: TransportId,
    config: WebRtcConfig,
    api: Arc<::webrtc::api::API>,
    packet_tx: PacketTx,
    pool: ConnectionPool,
    pending: PendingPool,
    failed: FailedPool,
    ready: ReadyPool,
    local_pubkey_hex: String,
    signal_relays: Vec<String>,
    stun_servers: Vec<String>,
    signaling: NostrSignalSender,
}

impl WebRtcRuntime {
    async fn start_outbound(&self, remote_addr: TransportAddr) -> Result<(), TransportError> {
        let remote_pubkey_hex = remote_addr.as_str().unwrap_or_default().to_string();
        let remote_xonly = xonly_from_compressed_hex(&remote_pubkey_hex)?;
        let session_id = random_session_id();

        let pc = Arc::new(self.new_peer_connection().await?);
        wire_peer_connection_state(self.transport_id, remote_addr.clone(), Arc::clone(&pc));
        let data_channel = pc
            .create_data_channel(
                self.config.data_channel_label(),
                Some(RTCDataChannelInit {
                    ordered: Some(self.config.ordered()),
                    max_retransmits: self.config.max_retransmits(),
                    ..Default::default()
                }),
            )
            .await
            .map_err(|e| TransportError::StartFailed(e.to_string()))?;

        wire_data_channel(
            self.transport_id,
            remote_addr.clone(),
            Arc::clone(&pc),
            Arc::clone(&data_channel),
            self.packet_tx.clone(),
            Arc::clone(&self.pool),
            Arc::clone(&self.pending),
            Arc::clone(&self.failed),
            Arc::clone(&self.ready),
        );

        self.pending.lock().await.insert(
            remote_addr.clone(),
            PendingDial {
                session_id: session_id.clone(),
                pc: Arc::clone(&pc),
            },
        );
        self.spawn_connect_timeout(remote_addr.clone(), session_id.clone());

        let offer = pc
            .create_offer(None)
            .await
            .map_err(|e| TransportError::StartFailed(e.to_string()))?;
        let mut gathering = pc.gathering_complete_promise().await;
        pc.set_local_description(offer)
            .await
            .map_err(|e| TransportError::StartFailed(e.to_string()))?;
        let _ = tokio::time::timeout(
            Duration::from_millis(self.config.ice_gather_timeout_ms()),
            gathering.recv(),
        )
        .await;

        let sdp = pc
            .local_description()
            .await
            .ok_or_else(|| TransportError::StartFailed("missing local WebRTC offer".into()))?
            .sdp;
        let now = now_ms();
        let signal = WebRtcSignal {
            protocol: WEBRTC_PROTOCOL.to_string(),
            version: WEBRTC_SIGNAL_VERSION,
            session_id,
            kind: WebRtcSignalKind::Offer,
            sender: self.local_pubkey_hex.clone(),
            recipient: remote_pubkey_hex,
            sdp: Some(sdp),
            candidates: None,
            created_at_ms: now,
            expires_at_ms: now.saturating_add(SIGNAL_TTL_MS),
        };
        self.signaling
            .send_signal(&self.signal_relays, remote_xonly, &signal)
            .await?;
        debug!(
            transport_id = %self.transport_id,
            remote_addr = %remote_addr,
            session = %signal.session_id,
            sdp_bytes = signal.sdp.as_ref().map(|s| s.len()).unwrap_or(0),
            "WebRTC offer sent"
        );
        Ok(())
    }

    async fn handle_incoming_signal(&self, incoming: IncomingSignal) -> Result<(), TransportError> {
        let signal = incoming.signal;
        debug!(
            transport_id = %self.transport_id,
            kind = ?signal.kind,
            session = %signal.session_id,
            sender = %signal.sender,
            "WebRTC signal received"
        );
        self.validate_signal(&signal, incoming.sender)?;
        match signal.kind {
            WebRtcSignalKind::Offer => self.handle_offer(signal, incoming.sender).await,
            WebRtcSignalKind::Answer => self.handle_answer(signal).await,
            WebRtcSignalKind::Reject => {
                let addr = TransportAddr::from_string(&signal.sender);
                self.mark_failed(addr, "peer rejected WebRTC session".to_string())
                    .await;
                Ok(())
            }
            WebRtcSignalKind::Candidate => Ok(()),
        }
    }

    async fn handle_offer(
        &self,
        signal: WebRtcSignal,
        sender_xonly: PublicKey,
    ) -> Result<(), TransportError> {
        if !self.config.accept_connections() {
            return Ok(());
        }
        if self.pool.lock().await.len() + self.pending.lock().await.len()
            >= self.config.max_connections()
        {
            let _ = self
                .send_reject(&signal.sender, sender_xonly, signal.session_id)
                .await;
            return Err(TransportError::ConnectionRefused);
        }

        let remote_addr = TransportAddr::from_string(&signal.sender);
        let pc = Arc::new(self.new_peer_connection().await?);
        wire_peer_connection_state(self.transport_id, remote_addr.clone(), Arc::clone(&pc));
        let runtime = self.clone();
        let pc_for_data_channel = Arc::clone(&pc);
        pc.on_data_channel(Box::new(move |data_channel: Arc<RTCDataChannel>| {
            let runtime = runtime.clone();
            let remote_addr = remote_addr.clone();
            let pc = Arc::clone(&pc_for_data_channel);
            Box::pin(async move {
                wire_data_channel(
                    runtime.transport_id,
                    remote_addr,
                    pc,
                    data_channel,
                    runtime.packet_tx.clone(),
                    Arc::clone(&runtime.pool),
                    Arc::clone(&runtime.pending),
                    Arc::clone(&runtime.failed),
                    Arc::clone(&runtime.ready),
                );
            })
        }));

        let offer = RTCSessionDescription::offer(signal.sdp.clone().unwrap_or_default())
            .map_err(|e| TransportError::StartFailed(e.to_string()))?;
        pc.set_remote_description(offer)
            .await
            .map_err(|e| TransportError::StartFailed(e.to_string()))?;
        let answer = pc
            .create_answer(None)
            .await
            .map_err(|e| TransportError::StartFailed(e.to_string()))?;
        let mut gathering = pc.gathering_complete_promise().await;
        pc.set_local_description(answer)
            .await
            .map_err(|e| TransportError::StartFailed(e.to_string()))?;
        let _ = tokio::time::timeout(
            Duration::from_millis(self.config.ice_gather_timeout_ms()),
            gathering.recv(),
        )
        .await;

        let sdp = pc
            .local_description()
            .await
            .ok_or_else(|| TransportError::StartFailed("missing local WebRTC answer".into()))?
            .sdp;
        let now = now_ms();
        let session_id = signal.session_id;
        let signal_sender = signal.sender;
        let reply = WebRtcSignal {
            protocol: WEBRTC_PROTOCOL.to_string(),
            version: WEBRTC_SIGNAL_VERSION,
            session_id,
            kind: WebRtcSignalKind::Answer,
            sender: self.local_pubkey_hex.clone(),
            recipient: signal_sender.clone(),
            sdp: Some(sdp),
            candidates: None,
            created_at_ms: now,
            expires_at_ms: now.saturating_add(SIGNAL_TTL_MS),
        };
        self.signaling
            .send_signal(&self.signal_relays, sender_xonly, &reply)
            .await?;
        debug!(
            transport_id = %self.transport_id,
            remote_addr = %signal_sender,
            session = %reply.session_id,
            sdp_bytes = reply.sdp.as_ref().map(|s| s.len()).unwrap_or(0),
            "WebRTC answer sent"
        );
        Ok(())
    }

    async fn handle_answer(&self, signal: WebRtcSignal) -> Result<(), TransportError> {
        let remote_addr = TransportAddr::from_string(&signal.sender);
        let pc = {
            let pending = self.pending.lock().await;
            let Some(pending) = pending.get(&remote_addr) else {
                return Ok(());
            };
            if pending.session_id != signal.session_id {
                return Err(TransportError::StartFailed(
                    "WebRTC answer session mismatch".into(),
                ));
            }
            Arc::clone(&pending.pc)
        };
        let answer = RTCSessionDescription::answer(signal.sdp.unwrap_or_default())
            .map_err(|e| TransportError::StartFailed(e.to_string()))?;
        pc.set_remote_description(answer)
            .await
            .map_err(|e| TransportError::StartFailed(e.to_string()))?;
        debug!(
            transport_id = %self.transport_id,
            remote_addr = %signal.sender,
            session = %signal.session_id,
            "WebRTC answer applied"
        );
        Ok(())
    }

    async fn send_reject(
        &self,
        recipient_full_hex: &str,
        recipient_xonly: PublicKey,
        session_id: String,
    ) -> Result<(), TransportError> {
        let now = now_ms();
        let reject = WebRtcSignal {
            protocol: WEBRTC_PROTOCOL.to_string(),
            version: WEBRTC_SIGNAL_VERSION,
            session_id,
            kind: WebRtcSignalKind::Reject,
            sender: self.local_pubkey_hex.clone(),
            recipient: recipient_full_hex.to_string(),
            sdp: None,
            candidates: None,
            created_at_ms: now,
            expires_at_ms: now.saturating_add(SIGNAL_TTL_MS),
        };
        self.signaling
            .send_signal(&self.signal_relays, recipient_xonly, &reject)
            .await
    }

    async fn new_peer_connection(&self) -> Result<RTCPeerConnection, TransportError> {
        self.api
            .new_peer_connection(RTCConfiguration {
                ice_servers: self
                    .stun_servers
                    .iter()
                    .map(|url| RTCIceServer {
                        urls: vec![url.clone()],
                        ..Default::default()
                    })
                    .collect(),
                ..Default::default()
            })
            .await
            .map_err(|e| TransportError::StartFailed(e.to_string()))
    }

    fn validate_signal(
        &self,
        signal: &WebRtcSignal,
        outer_sender: PublicKey,
    ) -> Result<(), TransportError> {
        if signal.protocol != WEBRTC_PROTOCOL {
            return Err(TransportError::InvalidAddress("bad WebRTC protocol".into()));
        }
        if signal.version != WEBRTC_SIGNAL_VERSION {
            return Err(TransportError::InvalidAddress("bad WebRTC version".into()));
        }
        if signal.recipient != self.local_pubkey_hex {
            return Err(TransportError::InvalidAddress(
                "WebRTC signal recipient is not local identity".into(),
            ));
        }
        validate_compressed_pubkey_hex(&signal.sender)?;
        validate_compressed_pubkey_hex(&signal.recipient)?;
        let sender_xonly = xonly_from_compressed_hex(&signal.sender)?;
        if sender_xonly != outer_sender {
            return Err(TransportError::InvalidAddress(
                "WebRTC signal sender does not match gift-wrap sender".into(),
            ));
        }
        let now = now_ms();
        if signal.expires_at_ms < now || signal.created_at_ms > now.saturating_add(60_000) {
            return Err(TransportError::Timeout);
        }
        if matches!(
            signal.kind,
            WebRtcSignalKind::Offer | WebRtcSignalKind::Answer
        ) && signal.sdp.as_deref().unwrap_or_default().is_empty()
        {
            return Err(TransportError::InvalidAddress(
                "WebRTC offer/answer requires SDP".into(),
            ));
        }
        Ok(())
    }

    async fn mark_failed(&self, addr: TransportAddr, reason: String) {
        if let Some(pending) = self.pending.lock().await.remove(&addr) {
            let _ = pending.pc.close().await;
        }
        self.ready.lock().await.remove(&addr);
        self.failed
            .lock()
            .await
            .insert(addr.clone(), reason.clone());
        warn!(
            transport_id = %self.transport_id,
            remote_addr = %addr,
            reason = %reason,
            "WebRTC connection failed"
        );
    }

    fn spawn_connect_timeout(&self, addr: TransportAddr, session_id: String) {
        let timeout = Duration::from_millis(self.config.connect_timeout_ms());
        let pending = Arc::clone(&self.pending);
        let failed = Arc::clone(&self.failed);
        let transport_id = self.transport_id;
        tokio::spawn(async move {
            tokio::time::sleep(timeout).await;
            let maybe_pending = {
                let mut pending = pending.lock().await;
                match pending.get(&addr) {
                    Some(dial) if dial.session_id == session_id => pending.remove(&addr),
                    _ => None,
                }
            };
            if let Some(dial) = maybe_pending {
                let _ = dial.pc.close().await;
                let reason = "WebRTC connect timed out".to_string();
                failed.lock().await.insert(addr.clone(), reason.clone());
                warn!(
                    transport_id = %transport_id,
                    remote_addr = %addr,
                    reason = %reason,
                    "WebRTC connection failed"
                );
            }
        });
    }
}

#[derive(Clone)]
struct NostrSignalSender {
    client: Client,
    keys: nostr::Keys,
    local_pubkey: PublicKey,
}

impl NostrSignalSender {
    async fn send_signal(
        &self,
        relays: &[String],
        receiver: PublicKey,
        signal: &WebRtcSignal,
    ) -> Result<(), TransportError> {
        let rumor = EventBuilder::private_msg_rumor(
            receiver,
            serde_json::to_string(signal).map_err(|e| TransportError::SendFailed(e.to_string()))?,
        )
        .build(self.local_pubkey);
        let event = build_signal_event(
            &self.keys,
            receiver,
            rumor,
            Timestamp::from((now_ms() + SIGNAL_TTL_MS) / 1000),
        )
        .await
        .map_err(|e| TransportError::SendFailed(e.to_string()))?;
        self.client
            .send_event_to(relays.to_vec(), &event)
            .await
            .map_err(|e| TransportError::SendFailed(e.to_string()))?;
        debug!(
            receiver = %receiver,
            relays = relays.len(),
            event = %event.id,
            kind = ?signal.kind,
            session = %signal.session_id,
            "WebRTC signal published"
        );
        Ok(())
    }
}

struct NostrWebRtcSignaling {
    sender: NostrSignalSender,
    relays: Vec<String>,
    signal_tx: mpsc::UnboundedSender<IncomingSignal>,
    notify_task: Option<JoinHandle<()>>,
    connect_task: Option<JoinHandle<()>>,
}

impl NostrWebRtcSignaling {
    fn new(
        keys: nostr::Keys,
        relays: Vec<String>,
        signal_tx: mpsc::UnboundedSender<IncomingSignal>,
    ) -> Self {
        let client = Client::builder()
            .signer(keys.clone())
            .opts(ClientOptions::new().autoconnect(false))
            .build();
        let local_pubkey = keys.public_key();
        Self {
            sender: NostrSignalSender {
                client,
                keys,
                local_pubkey,
            },
            relays,
            signal_tx,
            notify_task: None,
            connect_task: None,
        }
    }

    fn sender(&self) -> NostrSignalSender {
        self.sender.clone()
    }

    async fn start(&mut self, local_pubkey: PublicKey) -> Result<(), TransportError> {
        let mut unique_relays = HashSet::new();
        for relay in &self.relays {
            if unique_relays.insert(relay.clone()) {
                self.sender
                    .client
                    .add_relay(relay)
                    .await
                    .map_err(|e| TransportError::StartFailed(e.to_string()))?;
            }
        }
        let notifications = self.sender.client.notifications();
        let keys = self.sender.keys.clone();
        let signal_tx = self.signal_tx.clone();
        self.notify_task = Some(spawn_notify_loop(keys, notifications, signal_tx));

        for relay in &self.relays {
            if let Err(error) = self.sender.client.connect_relay(relay.clone()).await {
                warn!(relay = %relay, error = %error, "failed to connect WebRTC signal relay");
            }
        }
        self.sender
            .client
            .subscribe_to(
                self.relays.clone(),
                Filter::new()
                    .kind(Kind::Custom(SIGNAL_KIND))
                    .pubkey(local_pubkey)
                    .limit(100),
                None,
            )
            .await
            .map_err(|e| TransportError::StartFailed(e.to_string()))?;
        let client = self.sender.client.clone();
        self.connect_task = Some(tokio::spawn(async move {
            client.connect().await;
        }));
        Ok(())
    }

    async fn stop(&mut self) {
        if let Some(task) = self.notify_task.take() {
            task.abort();
        }
        if let Some(task) = self.connect_task.take() {
            task.abort();
        }
    }
}

fn spawn_notify_loop(
    keys: nostr::Keys,
    mut notifications: broadcast::Receiver<RelayPoolNotification>,
    signal_tx: mpsc::UnboundedSender<IncomingSignal>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            let notification = match notifications.recv().await {
                Ok(notification) => notification,
                Err(broadcast::error::RecvError::Lagged(skipped)) => {
                    warn!(skipped, "WebRTC Nostr signal notifications lagged");
                    continue;
                }
                Err(broadcast::error::RecvError::Closed) => break,
            };
            let RelayPoolNotification::Event { event, .. } = notification else {
                continue;
            };
            if event.kind != Kind::Custom(SIGNAL_KIND) {
                continue;
            }
            let unwrapped = match unwrap_signal_event(&keys, &event).await {
                Ok(unwrapped) => unwrapped,
                Err(err) => {
                    debug!(error = %err, event = %event.id, "failed to unwrap WebRTC signal");
                    continue;
                }
            };
            let signal = match serde_json::from_str::<WebRtcSignal>(&unwrapped.rumor.content) {
                Ok(signal) if signal.protocol == WEBRTC_PROTOCOL => signal,
                Ok(_) => continue,
                Err(err) => {
                    debug!(error = %err, event = %event.id, "failed to parse WebRTC signal");
                    continue;
                }
            };
            let _ = signal_tx.send(IncomingSignal {
                signal,
                sender: unwrapped.sender,
            });
        }
    })
}

fn wire_peer_connection_state(
    transport_id: TransportId,
    remote_addr: TransportAddr,
    pc: Arc<RTCPeerConnection>,
) {
    let peer_addr = remote_addr.clone();
    pc.on_peer_connection_state_change(Box::new(move |state: RTCPeerConnectionState| {
        let peer_addr = peer_addr.clone();
        Box::pin(async move {
            debug!(
                transport_id = %transport_id,
                remote_addr = %peer_addr,
                state = %state,
                "WebRTC peer connection state changed"
            );
        })
    }));
}

#[allow(clippy::too_many_arguments)]
fn wire_data_channel(
    transport_id: TransportId,
    remote_addr: TransportAddr,
    pc: Arc<RTCPeerConnection>,
    data_channel: Arc<RTCDataChannel>,
    packet_tx: PacketTx,
    pool: ConnectionPool,
    pending: PendingPool,
    failed: FailedPool,
    ready: ReadyPool,
) {
    let recv_addr = remote_addr.clone();
    let recv_tx = packet_tx.clone();
    let recv_ready = Arc::clone(&ready);
    data_channel.on_message(Box::new(move |msg: DataChannelMessage| {
        let recv_addr = recv_addr.clone();
        let recv_tx = recv_tx.clone();
        let recv_ready = Arc::clone(&recv_ready);
        Box::pin(async move {
            if msg.is_string {
                debug!(
                    transport_id = %transport_id,
                    remote_addr = %recv_addr,
                    "WebRTC string data channel message ignored"
                );
                return;
            }
            if msg.data.as_ref() == WEBRTC_READY_FRAME {
                mark_webrtc_ready(transport_id, recv_addr, recv_ready).await;
                return;
            }
            let data = msg.data.to_vec();
            match data.first().copied() {
                Some(1 | 2) => {
                    debug!(
                        transport_id = %transport_id,
                        remote_addr = %recv_addr,
                        bytes = data.len(),
                        first_byte = data.first().copied(),
                        "WebRTC data channel handshake packet received"
                    );
                }
                _ => {
                    trace!(
                        transport_id = %transport_id,
                        remote_addr = %recv_addr,
                        bytes = data.len(),
                        first_byte = data.first().copied(),
                        "WebRTC data channel packet received"
                    );
                }
            }
            if let Err(err) = recv_tx.send(ReceivedPacket::new(transport_id, recv_addr, data)) {
                warn!(
                    transport_id = %transport_id,
                    error = %err,
                    "WebRTC packet enqueue failed"
                );
            }
        })
    }));

    let open_addr = remote_addr.clone();
    let open_pc = Arc::clone(&pc);
    let open_dc = Arc::clone(&data_channel);
    let open_pool = Arc::clone(&pool);
    let open_pending = Arc::clone(&pending);
    let open_failed = Arc::clone(&failed);
    let open_ready = Arc::clone(&ready);
    data_channel.on_open(Box::new(move || {
        let open_addr = open_addr.clone();
        let open_pc = Arc::clone(&open_pc);
        let open_dc = Arc::clone(&open_dc);
        let open_pool = Arc::clone(&open_pool);
        let open_pending = Arc::clone(&open_pending);
        let open_failed = Arc::clone(&open_failed);
        let open_ready = Arc::clone(&open_ready);
        Box::pin(async move {
            let ready_dc = Arc::clone(&open_dc);
            open_failed.lock().await.remove(&open_addr);
            open_pending.lock().await.remove(&open_addr);
            open_pool.lock().await.insert(
                open_addr.clone(),
                WebRtcConnection {
                    pc: open_pc,
                    data_channel: open_dc,
                },
            );
            if let Err(err) = ready_dc
                .send(&Bytes::copy_from_slice(WEBRTC_READY_FRAME))
                .await
            {
                debug!(
                    transport_id = %transport_id,
                    remote_addr = %open_addr,
                    error = %err,
                    "Failed to send WebRTC ready marker"
                );
            }
            spawn_webrtc_ready_fallback(
                transport_id,
                open_addr.clone(),
                Arc::clone(&open_pool),
                Arc::clone(&open_ready),
            );
            debug!(remote_addr = %open_addr, "WebRTC data channel open");
        })
    }));

    let close_addr = remote_addr;
    let close_pool = pool;
    let close_pending = pending;
    let close_ready = ready;
    data_channel.on_close(Box::new(move || {
        let close_addr = close_addr.clone();
        let close_pool = Arc::clone(&close_pool);
        let close_pending = Arc::clone(&close_pending);
        let close_ready = Arc::clone(&close_ready);
        Box::pin(async move {
            close_pool.lock().await.remove(&close_addr);
            close_pending.lock().await.remove(&close_addr);
            close_ready.lock().await.remove(&close_addr);
        })
    }));
}

async fn mark_webrtc_ready(
    transport_id: TransportId,
    remote_addr: TransportAddr,
    ready: ReadyPool,
) {
    if ready.lock().await.insert(remote_addr.clone()) {
        debug!(
            transport_id = %transport_id,
            remote_addr = %remote_addr,
            "WebRTC data channel remote ready"
        );
    }
}

fn spawn_webrtc_ready_fallback(
    transport_id: TransportId,
    remote_addr: TransportAddr,
    pool: ConnectionPool,
    ready: ReadyPool,
) {
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(WEBRTC_READY_FALLBACK_MS)).await;
        if pool.lock().await.contains_key(&remote_addr) {
            mark_webrtc_ready(transport_id, remote_addr, ready).await;
        }
    });
}

fn validate_compressed_pubkey_addr(addr: &TransportAddr) -> Result<(), TransportError> {
    let Some(s) = addr.as_str() else {
        return Err(TransportError::InvalidAddress(
            "WebRTC address must be UTF-8 compressed pubkey hex".into(),
        ));
    };
    validate_compressed_pubkey_hex(s)
}

fn validate_compressed_pubkey_hex(s: &str) -> Result<(), TransportError> {
    if s.len() != 66 {
        return Err(TransportError::InvalidAddress(
            "WebRTC address must be 33-byte compressed pubkey hex".into(),
        ));
    }
    let bytes = hex::decode(s).map_err(|e| TransportError::InvalidAddress(e.to_string()))?;
    if bytes.len() != 33 || !matches!(bytes[0], 0x02 | 0x03) {
        return Err(TransportError::InvalidAddress(
            "WebRTC address must be compressed secp256k1 pubkey".into(),
        ));
    }
    Ok(())
}

fn xonly_from_compressed_hex(s: &str) -> Result<PublicKey, TransportError> {
    validate_compressed_pubkey_hex(s)?;
    let bytes = hex::decode(s).map_err(|e| TransportError::InvalidAddress(e.to_string()))?;
    PublicKey::from_slice(&bytes[1..]).map_err(|e| TransportError::InvalidAddress(e.to_string()))
}

fn random_session_id() -> String {
    let mut bytes = [0u8; 16];
    rand::Rng::fill_bytes(&mut rand::rng(), &mut bytes);
    hex::encode(bytes)
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

impl Transport for WebRtcTransport {
    fn transport_id(&self) -> TransportId {
        self.transport_id
    }

    fn transport_type(&self) -> &TransportType {
        &TransportType::WEBRTC
    }

    fn state(&self) -> TransportState {
        self.state
    }

    fn mtu(&self) -> u16 {
        self.config.mtu()
    }

    fn start(&mut self) -> Result<(), TransportError> {
        Err(TransportError::NotSupported(
            "use start_async() for WebRTC transport".into(),
        ))
    }

    fn stop(&mut self) -> Result<(), TransportError> {
        Err(TransportError::NotSupported(
            "use stop_async() for WebRTC transport".into(),
        ))
    }

    fn send(&self, _addr: &TransportAddr, _data: &[u8]) -> Result<(), TransportError> {
        Err(TransportError::NotSupported(
            "use send_async() for WebRTC transport".into(),
        ))
    }

    fn discover(&self) -> Result<Vec<DiscoveredPeer>, TransportError> {
        Ok(Vec::new())
    }

    fn auto_connect(&self) -> bool {
        self.config.auto_connect()
    }

    fn accept_connections(&self) -> bool {
        self.config.accept_connections()
    }

    fn close_connection(&self, _addr: &TransportAddr) {}
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_compressed_pubkey_addresses() {
        let good = "02aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        assert!(validate_compressed_pubkey_hex(good).is_ok());
        assert!(validate_compressed_pubkey_hex(&good[2..]).is_err());
        assert!(
            validate_compressed_pubkey_hex(
                "04aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            )
            .is_err()
        );
    }

    #[test]
    fn webrtc_signal_serializes_like_ts_transport() {
        let signal = WebRtcSignal {
            protocol: WEBRTC_PROTOCOL.to_string(),
            version: WEBRTC_SIGNAL_VERSION,
            session_id: "abc".to_string(),
            kind: WebRtcSignalKind::Offer,
            sender: "02aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                .to_string(),
            recipient: "03bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
                .to_string(),
            sdp: Some("v=0".to_string()),
            candidates: None,
            created_at_ms: 1,
            expires_at_ms: 2,
        };
        let json = serde_json::to_string(&signal).unwrap();
        assert!(json.contains(r#""sessionId":"abc""#));
        assert!(json.contains(r#""createdAtMs":1"#));
        assert!(json.contains(r#""expiresAtMs":2"#));
    }
}
