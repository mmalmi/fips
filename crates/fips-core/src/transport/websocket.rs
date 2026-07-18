//! Binary WebSocket physical transport.
//!
//! One binary WebSocket message carries one FIPS physical record. A tiny
//! nonce-bound key-hint exchange precedes Noise IK when a client has only a
//! seed URL; the hint is untrusted routing metadata and never bypasses FIPS
//! identity authentication or ACLs.

use super::tcp::stream::validate_stream_record;
use super::{
    ConnectionState, DiscoveredPeer, PacketBuffer, PacketTx, ReceivedPacket, Transport,
    TransportAddr, TransportError, TransportId, TransportState, TransportType,
};
use crate::Identity;
use crate::config::WebSocketConfig;
use crate::dataplane::validate_direct_fsp_transport_fragment;
use crate::discovery::local_udp::LocalKeyHint;
use futures::{SinkExt, StreamExt};
use rand::RngExt;
use secp256k1::XOnlyPublicKey;
use serde::Serialize;
use std::collections::{HashMap, VecDeque};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Mutex, Semaphore, mpsc};
use tokio::task::JoinHandle;
use tokio_tungstenite::tungstenite::handshake::server::{ErrorResponse, Request, Response};
use tokio_tungstenite::tungstenite::protocol::WebSocketConfig as TungsteniteConfig;
use tokio_tungstenite::tungstenite::{Bytes, Message};
use tokio_tungstenite::{WebSocketStream, accept_hdr_async_with_config, connect_async_with_config};
use tracing::{debug, info};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Direction {
    Inbound,
    Outbound,
}

struct Connection {
    generation: u64,
    tx: mpsc::Sender<Vec<u8>>,
}

type ConnectionPool = Arc<Mutex<HashMap<TransportAddr, Connection>>>;
type ConnectionStates = Arc<StdMutex<HashMap<TransportAddr, ConnectionState>>>;
type DiscoveryQueue = Arc<StdMutex<VecDeque<DiscoveredPeer>>>;

#[derive(Debug, Default)]
struct WebSocketStats {
    connections_opened: AtomicU64,
    connections_closed: AtomicU64,
    connections_rejected: AtomicU64,
    reconnect_attempts: AtomicU64,
    frames_sent: AtomicU64,
    frames_received: AtomicU64,
    bytes_sent: AtomicU64,
    bytes_received: AtomicU64,
    invalid_frames: AtomicU64,
    send_queue_full: AtomicU64,
}

#[derive(Debug, Serialize)]
pub struct WebSocketStatsSnapshot {
    pub connections_opened: u64,
    pub connections_closed: u64,
    pub connections_rejected: u64,
    pub reconnect_attempts: u64,
    pub frames_sent: u64,
    pub frames_received: u64,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub invalid_frames: u64,
    pub send_queue_full: u64,
}

impl WebSocketStats {
    fn snapshot(&self) -> WebSocketStatsSnapshot {
        let load = |value: &AtomicU64| value.load(Ordering::Relaxed);
        WebSocketStatsSnapshot {
            connections_opened: load(&self.connections_opened),
            connections_closed: load(&self.connections_closed),
            connections_rejected: load(&self.connections_rejected),
            reconnect_attempts: load(&self.reconnect_attempts),
            frames_sent: load(&self.frames_sent),
            frames_received: load(&self.frames_received),
            bytes_sent: load(&self.bytes_sent),
            bytes_received: load(&self.bytes_received),
            invalid_frames: load(&self.invalid_frames),
            send_queue_full: load(&self.send_queue_full),
        }
    }
}

#[derive(Clone)]
struct Runtime {
    transport_id: TransportId,
    config: WebSocketConfig,
    local_pubkey: [u8; 32],
    packet_tx: PacketTx,
    pool: ConnectionPool,
    states: ConnectionStates,
    discoveries: DiscoveryQueue,
    running: Arc<AtomicBool>,
    total_slots: Arc<Semaphore>,
    inbound_slots: Arc<Semaphore>,
    generation: Arc<AtomicU64>,
    stats: Arc<WebSocketStats>,
}

impl Runtime {
    fn websocket_config(&self) -> TungsteniteConfig {
        let mut config = TungsteniteConfig::default();
        config.max_message_size = Some(self.config.max_frame_bytes());
        config.max_frame_size = Some(self.config.max_frame_bytes());
        config.max_write_buffer_size = self.config.max_frame_bytes().saturating_mul(2);
        config.write_buffer_size = 0;
        config
    }

    fn next_generation(&self) -> u64 {
        self.generation.fetch_add(1, Ordering::Relaxed)
    }

    fn set_state(&self, addr: &TransportAddr, state: ConnectionState) {
        self.states
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .insert(addr.clone(), state);
    }

    fn clear_state_if(&self, addr: &TransportAddr, generation: u64) {
        let connected_generation = self
            .pool
            .try_lock()
            .ok()
            .and_then(|pool| pool.get(addr).map(|connection| connection.generation));
        if connected_generation != Some(generation) {
            self.states
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .remove(addr);
        }
    }
}

/// Generic WebSocket physical transport.
pub struct WebSocketTransport {
    transport_id: TransportId,
    name: Option<String>,
    config: WebSocketConfig,
    state: TransportState,
    local_addr: Option<SocketAddr>,
    runtime: Runtime,
    tasks: Arc<StdMutex<Vec<JoinHandle<()>>>>,
}

impl WebSocketTransport {
    pub fn new(
        transport_id: TransportId,
        name: Option<String>,
        config: WebSocketConfig,
        packet_tx: PacketTx,
        identity: &Identity,
    ) -> Self {
        let max_connections = config.max_connections();
        let max_inbound = config.max_inbound_connections();
        let runtime = Runtime {
            transport_id,
            config: config.clone(),
            local_pubkey: identity.pubkey().serialize(),
            packet_tx,
            pool: Arc::new(Mutex::new(HashMap::new())),
            states: Arc::new(StdMutex::new(HashMap::new())),
            discoveries: Arc::new(StdMutex::new(VecDeque::new())),
            running: Arc::new(AtomicBool::new(false)),
            total_slots: Arc::new(Semaphore::new(max_connections)),
            inbound_slots: Arc::new(Semaphore::new(max_inbound)),
            generation: Arc::new(AtomicU64::new(1)),
            stats: Arc::new(WebSocketStats::default()),
        };
        Self {
            transport_id,
            name,
            config,
            state: TransportState::Configured,
            local_addr: None,
            runtime,
            tasks: Arc::new(StdMutex::new(Vec::new())),
        }
    }

    pub fn name(&self) -> Option<&str> {
        self.name.as_deref()
    }

    pub fn local_addr(&self) -> Option<SocketAddr> {
        self.local_addr
    }

    pub fn public_url(&self) -> Option<&str> {
        self.config.public_url.as_deref()
    }

    pub(crate) fn is_configured_seed_addr(&self, addr: &TransportAddr) -> bool {
        addr.as_str().is_some_and(|candidate| {
            self.config
                .seed_urls
                .iter()
                .any(|seed_url| seed_url == candidate)
        })
    }

    pub(crate) fn is_configured_adjacency(
        &self,
        addr: &TransportAddr,
        handshake_is_initiator: bool,
    ) -> bool {
        if self.is_configured_seed_addr(addr) {
            // The URL identifies the operator-configured physical dial even
            // when simultaneous FIPS initiation makes this node the responder.
            // Handshake role is not transport direction.
            true
        } else if !handshake_is_initiator {
            // Accepting clients on a configured listener is an explicit
            // operator choice; every promoted client has already completed
            // the authenticated FIPS handshake.
            self.config.bind_addr.is_some()
        } else {
            false
        }
    }

    pub fn stats(&self) -> WebSocketStatsSnapshot {
        self.runtime.stats.snapshot()
    }

    fn push_task(&self, task: JoinHandle<()>) {
        self.tasks
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .push(task);
    }

    pub async fn start_async(&mut self) -> Result<(), TransportError> {
        if !self.state.can_start() {
            return Err(TransportError::AlreadyStarted);
        }
        self.config
            .validate()
            .map_err(TransportError::StartFailed)?;
        self.state = TransportState::Starting;
        self.runtime.running.store(true, Ordering::Release);

        if let Some(bind_addr) = self.config.bind_addr.as_deref() {
            let bind_addr = bind_addr
                .parse::<SocketAddr>()
                .map_err(|error| TransportError::StartFailed(error.to_string()))?;
            let listener = TcpListener::bind(bind_addr)
                .await
                .map_err(|error| TransportError::bind_failed(bind_addr, error))?;
            self.local_addr = Some(
                listener
                    .local_addr()
                    .map_err(|error| TransportError::StartFailed(error.to_string()))?,
            );
            self.push_task(tokio::spawn(run_accept_loop(
                self.runtime.clone(),
                listener,
            )));
        }

        for seed_url in self.config.seed_urls.clone() {
            let addr = TransportAddr::from_string(&seed_url);
            self.runtime.set_state(&addr, ConnectionState::Connecting);
            self.push_task(tokio::spawn(run_seed_dialer(self.runtime.clone(), addr)));
        }

        self.state = TransportState::Up;
        info!(
            transport_id = %self.transport_id,
            local_addr = ?self.local_addr,
            seeds = self.config.seed_urls.len(),
            "WebSocket transport started"
        );
        Ok(())
    }

    pub async fn stop_async(&mut self) -> Result<(), TransportError> {
        if !self.state.is_operational() {
            return Err(TransportError::NotStarted);
        }
        self.runtime.running.store(false, Ordering::Release);
        let tasks = {
            let mut tasks = self.tasks.lock().unwrap_or_else(|error| error.into_inner());
            std::mem::take(&mut *tasks)
        };
        for task in &tasks {
            task.abort();
        }
        for task in tasks {
            let _ = task.await;
        }
        self.runtime.pool.lock().await.clear();
        self.runtime
            .states
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .clear();
        self.local_addr = None;
        self.state = TransportState::Down;
        Ok(())
    }

    pub async fn send_async(
        &self,
        addr: &TransportAddr,
        data: &[u8],
    ) -> Result<usize, TransportError> {
        if !self.state.is_operational() {
            return Err(TransportError::NotStarted);
        }
        if data.len() > self.config.max_frame_bytes() {
            return Err(TransportError::MtuExceeded {
                packet_size: data.len(),
                mtu: self.config.max_frame_bytes().min(u16::MAX as usize) as u16,
            });
        }
        validate_websocket_record(data).map_err(TransportError::SendFailed)?;
        let tx = self
            .runtime
            .pool
            .lock()
            .await
            .get(addr)
            .map(|connection| connection.tx.clone())
            .ok_or(TransportError::NotStarted)?;
        tx.try_send(data.to_vec()).map_err(|error| match error {
            mpsc::error::TrySendError::Full(_) => {
                self.runtime
                    .stats
                    .send_queue_full
                    .fetch_add(1, Ordering::Relaxed);
                TransportError::SendFailed("WebSocket send queue full".into())
            }
            mpsc::error::TrySendError::Closed(_) => {
                TransportError::SendFailed("WebSocket connection closed".into())
            }
        })?;
        Ok(data.len())
    }

    pub async fn connect_async(&self, addr: &TransportAddr) -> Result<(), TransportError> {
        if !self.state.is_operational() {
            return Err(TransportError::NotStarted);
        }
        let raw = addr
            .as_str()
            .ok_or_else(|| TransportError::InvalidAddress(addr.to_string()))?;
        let candidate = WebSocketConfig {
            seed_urls: vec![raw.to_owned()],
            ..self.config.clone()
        };
        candidate
            .validate()
            .map_err(TransportError::InvalidAddress)?;
        if self.connection_state_sync(addr) == ConnectionState::Connected {
            return Ok(());
        }
        {
            let mut states = self
                .runtime
                .states
                .lock()
                .unwrap_or_else(|error| error.into_inner());
            if matches!(states.get(addr), Some(ConnectionState::Connecting)) {
                return Ok(());
            }
            states.insert(addr.clone(), ConnectionState::Connecting);
        }
        self.push_task(tokio::spawn(run_one_shot_dial(
            self.runtime.clone(),
            addr.clone(),
        )));
        Ok(())
    }

    pub fn connection_state_sync(&self, addr: &TransportAddr) -> ConnectionState {
        if let Ok(pool) = self.runtime.pool.try_lock()
            && pool.contains_key(addr)
        {
            return ConnectionState::Connected;
        }
        self.runtime
            .states
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .get(addr)
            .cloned()
            .unwrap_or(ConnectionState::None)
    }

    pub async fn close_connection_async(&self, addr: &TransportAddr) {
        self.runtime.pool.lock().await.remove(addr);
        self.runtime
            .states
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .remove(addr);
    }
}

impl Transport for WebSocketTransport {
    fn transport_id(&self) -> TransportId {
        self.transport_id
    }

    fn transport_type(&self) -> &TransportType {
        &TransportType::WEBSOCKET
    }

    fn state(&self) -> TransportState {
        self.state
    }

    fn mtu(&self) -> u16 {
        self.config.mtu()
    }

    fn start(&mut self) -> Result<(), TransportError> {
        Err(TransportError::NotSupported(
            "use start_async() for WebSocket transport".into(),
        ))
    }

    fn stop(&mut self) -> Result<(), TransportError> {
        Err(TransportError::NotSupported(
            "use stop_async() for WebSocket transport".into(),
        ))
    }

    fn send(&self, _addr: &TransportAddr, _data: &[u8]) -> Result<(), TransportError> {
        Err(TransportError::NotSupported(
            "use send_async() for WebSocket transport".into(),
        ))
    }

    fn discover(&self) -> Result<Vec<DiscoveredPeer>, TransportError> {
        Ok(self
            .runtime
            .discoveries
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .drain(..)
            .collect())
    }

    fn auto_connect(&self) -> bool {
        true
    }

    fn accept_connections(&self) -> bool {
        self.config.accept_connections()
    }
}

async fn run_accept_loop(runtime: Runtime, listener: TcpListener) {
    while runtime.running.load(Ordering::Acquire) {
        let Ok((stream, peer_addr)) = listener.accept().await else {
            continue;
        };
        let Ok(inbound_permit) = runtime.inbound_slots.clone().try_acquire_owned() else {
            runtime
                .stats
                .connections_rejected
                .fetch_add(1, Ordering::Relaxed);
            continue;
        };
        let Ok(total_permit) = runtime.total_slots.clone().try_acquire_owned() else {
            runtime
                .stats
                .connections_rejected
                .fetch_add(1, Ordering::Relaxed);
            continue;
        };
        let accepted_runtime = runtime.clone();
        tokio::spawn(async move {
            let _inbound_permit = inbound_permit;
            let _total_permit = total_permit;
            if let Err(error) = accept_connection(accepted_runtime, stream, peer_addr).await {
                debug!(%peer_addr, %error, "WebSocket inbound connection ended");
            }
        });
    }
}

#[allow(clippy::result_large_err)]
async fn accept_connection(
    runtime: Runtime,
    stream: TcpStream,
    peer_addr: SocketAddr,
) -> Result<(), TransportError> {
    let path = runtime.config.path().to_owned();
    let callback = move |request: &Request, response: Response| {
        if request.uri().path() == path {
            Ok(response)
        } else {
            let mut error = ErrorResponse::new(Some("not found".into()));
            *error.status_mut() = tokio_tungstenite::tungstenite::http::StatusCode::NOT_FOUND;
            Err(error)
        }
    };
    let websocket =
        accept_hdr_async_with_config(stream, callback, Some(runtime.websocket_config()))
            .await
            .map_err(|_| TransportError::ConnectionRefused)?;
    let generation = runtime.next_generation();
    let addr = TransportAddr::from_string(&format!("ws-peer://{peer_addr}/{generation}"));
    run_connection(
        runtime,
        addr,
        websocket,
        generation,
        Direction::Inbound,
        false,
    )
    .await
}

async fn run_seed_dialer(runtime: Runtime, addr: TransportAddr) {
    let mut delay_ms = runtime.config.reconnect_initial_ms();
    while runtime.running.load(Ordering::Acquire) {
        runtime.set_state(&addr, ConnectionState::Connecting);
        runtime
            .stats
            .reconnect_attempts
            .fetch_add(1, Ordering::Relaxed);
        let result = dial_and_run(runtime.clone(), addr.clone()).await;
        if !runtime.running.load(Ordering::Acquire) {
            break;
        }
        match result {
            Ok(()) => {
                delay_ms = runtime.config.reconnect_initial_ms();
            }
            Err(error) => {
                runtime.set_state(&addr, ConnectionState::Failed(error.to_string()));
                debug!(remote_addr = %addr, %error, "WebSocket seed connection failed");
                delay_ms = delay_ms
                    .saturating_mul(2)
                    .min(runtime.config.reconnect_max_ms());
            }
        }
        tokio::time::sleep(Duration::from_millis(delay_ms)).await;
    }
}

async fn run_one_shot_dial(runtime: Runtime, addr: TransportAddr) {
    let result = dial_and_run(runtime.clone(), addr.clone()).await;
    if let Err(error) = result {
        runtime.set_state(&addr, ConnectionState::Failed(error.to_string()));
    }
}

async fn dial_and_run(runtime: Runtime, addr: TransportAddr) -> Result<(), TransportError> {
    let _slot = runtime
        .total_slots
        .clone()
        .try_acquire_owned()
        .map_err(|_| TransportError::ConnectionRefused)?;
    let url = addr
        .as_str()
        .ok_or_else(|| TransportError::InvalidAddress(addr.to_string()))?;
    let connect = connect_async_with_config(url, Some(runtime.websocket_config()), false);
    let (websocket, _) = tokio::time::timeout(
        Duration::from_millis(runtime.config.connect_timeout_ms()),
        connect,
    )
    .await
    .map_err(|_| TransportError::Timeout)?
    .map_err(|error| TransportError::StartFailed(error.to_string()))?;
    let generation = runtime.next_generation();
    run_connection(
        runtime,
        addr,
        websocket,
        generation,
        Direction::Outbound,
        true,
    )
    .await
}

async fn run_connection<S>(
    runtime: Runtime,
    addr: TransportAddr,
    websocket: WebSocketStream<S>,
    generation: u64,
    direction: Direction,
    request_key_hint: bool,
) -> Result<(), TransportError>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let (mut sink, mut stream) = websocket.split();
    let (tx, mut rx) = mpsc::channel::<Vec<u8>>(runtime.config.max_send_queue());
    {
        let mut pool = runtime.pool.lock().await;
        if pool.contains_key(&addr) {
            return Err(TransportError::AlreadyStarted);
        }
        pool.insert(addr.clone(), Connection { generation, tx });
    }
    runtime.set_state(&addr, ConnectionState::Connected);
    runtime
        .stats
        .connections_opened
        .fetch_add(1, Ordering::Relaxed);

    let mut pending_nonce = request_key_hint.then(|| rand::rng().random::<u64>());
    if let Some(nonce) = pending_nonce {
        sink.send(Message::Binary(
            LocalKeyHint::Request { nonce }.encode().into(),
        ))
        .await
        .map_err(|error| TransportError::SendFailed(error.to_string()))?;
    }

    let started = tokio::time::Instant::now();
    let mut last_received = started;
    let ping_secs = runtime.config.ping_interval_secs();
    let idle_secs = runtime.config.idle_timeout_secs();
    let mut ping = tokio::time::interval(if ping_secs == 0 {
        Duration::from_secs(24 * 60 * 60)
    } else {
        Duration::from_secs(ping_secs)
    });
    ping.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut check = tokio::time::interval(Duration::from_secs(1));
    check.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    enum Event {
        Outbound(Option<Vec<u8>>),
        Inbound(Option<Result<Message, tokio_tungstenite::tungstenite::Error>>),
        Ping,
        Check,
    }

    let outcome = loop {
        let event = tokio::select! {
            outbound = rx.recv() => Event::Outbound(outbound),
            inbound = stream.next() => Event::Inbound(inbound),
            _ = ping.tick(), if ping_secs > 0 => Event::Ping,
            _ = check.tick() => Event::Check,
        };
        match event {
            Event::Outbound(Some(data)) => {
                let len = data.len();
                if let Err(error) = sink.send(Message::Binary(data.into())).await {
                    break Err(TransportError::SendFailed(error.to_string()));
                }
                runtime.stats.frames_sent.fetch_add(1, Ordering::Relaxed);
                runtime
                    .stats
                    .bytes_sent
                    .fetch_add(len as u64, Ordering::Relaxed);
            }
            Event::Outbound(None) => break Ok(()),
            Event::Inbound(Some(Ok(Message::Binary(data)))) => {
                last_received = tokio::time::Instant::now();
                if let Some(hint) = LocalKeyHint::decode(&data) {
                    match hint {
                        LocalKeyHint::Request { nonce } => {
                            let reply = LocalKeyHint::Response {
                                nonce,
                                pubkey: runtime.local_pubkey,
                            };
                            if let Err(error) =
                                sink.send(Message::Binary(reply.encode().into())).await
                            {
                                break Err(TransportError::SendFailed(error.to_string()));
                            }
                        }
                        LocalKeyHint::Response { nonce, pubkey }
                            if pending_nonce == Some(nonce) =>
                        {
                            pending_nonce = None;
                            if pubkey != runtime.local_pubkey
                                && let Ok(pubkey) = XOnlyPublicKey::from_slice(&pubkey)
                            {
                                runtime
                                    .discoveries
                                    .lock()
                                    .unwrap_or_else(|error| error.into_inner())
                                    .push_back(DiscoveredPeer::with_hint(
                                        runtime.transport_id,
                                        addr.clone(),
                                        pubkey,
                                    ));
                            }
                        }
                        LocalKeyHint::Response { .. } => {}
                    }
                    continue;
                }
                if data.len() > runtime.config.max_frame_bytes()
                    || validate_websocket_record(&data).is_err()
                {
                    runtime.stats.invalid_frames.fetch_add(1, Ordering::Relaxed);
                    break Err(TransportError::RecvFailed(
                        "invalid WebSocket FIPS physical record".into(),
                    ));
                }
                let len = data.len();
                let packet = ReceivedPacket::with_timestamp(
                    runtime.transport_id,
                    addr.clone(),
                    PacketBuffer::new(data.to_vec()),
                    now_ms(),
                );
                if runtime.packet_tx.send(packet).is_err() {
                    break Err(TransportError::RecvFailed(
                        "node packet channel closed".into(),
                    ));
                }
                runtime
                    .stats
                    .frames_received
                    .fetch_add(1, Ordering::Relaxed);
                runtime
                    .stats
                    .bytes_received
                    .fetch_add(len as u64, Ordering::Relaxed);
            }
            Event::Inbound(Some(Ok(Message::Ping(payload)))) => {
                last_received = tokio::time::Instant::now();
                if let Err(error) = sink.send(Message::Pong(payload)).await {
                    break Err(TransportError::SendFailed(error.to_string()));
                }
            }
            Event::Inbound(Some(Ok(Message::Pong(_)))) => {
                last_received = tokio::time::Instant::now();
            }
            Event::Inbound(Some(Ok(Message::Close(_))) | None) => break Ok(()),
            Event::Inbound(Some(Ok(Message::Text(_) | Message::Frame(_)))) => {
                runtime.stats.invalid_frames.fetch_add(1, Ordering::Relaxed);
                break Err(TransportError::RecvFailed(
                    "WebSocket transport accepts binary messages only".into(),
                ));
            }
            Event::Inbound(Some(Err(error))) => {
                break Err(TransportError::RecvFailed(error.to_string()));
            }
            Event::Ping => {
                if let Err(error) = sink.send(Message::Ping(Bytes::new())).await {
                    break Err(TransportError::SendFailed(error.to_string()));
                }
            }
            Event::Check => {
                if pending_nonce.is_some()
                    && started.elapsed()
                        >= Duration::from_millis(runtime.config.key_hint_timeout_ms())
                {
                    break Err(TransportError::Timeout);
                }
                if idle_secs > 0 && last_received.elapsed() >= Duration::from_secs(idle_secs) {
                    break Err(TransportError::Timeout);
                }
            }
        }
    };

    {
        let mut pool = runtime.pool.lock().await;
        if pool
            .get(&addr)
            .is_some_and(|connection| connection.generation == generation)
        {
            pool.remove(&addr);
        }
    }
    runtime.clear_state_if(&addr, generation);
    runtime
        .stats
        .connections_closed
        .fetch_add(1, Ordering::Relaxed);
    debug!(
        transport_id = %runtime.transport_id,
        remote_addr = %addr,
        ?direction,
        "WebSocket physical connection closed"
    );
    outcome
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

fn validate_websocket_record(data: &[u8]) -> Result<(), String> {
    if validate_direct_fsp_transport_fragment(data) {
        return Ok(());
    }
    validate_stream_record(data).map_err(|error| format!("invalid FIPS physical record: {error}"))
}

#[cfg(test)]
mod tests;
