//! Bounded request/reply records over the existing TCP/FIPS adapter.
//!
//! Configured neighbors and opt-in authenticated adjacent peers may exchange
//! control. Explicit customer networks remain inbound-only; none grant spending authority.
//! TCP acknowledgments say nothing about paid data delivery.

mod admission;
#[cfg(test)]
#[path = "control_transport/admission_delay_tests.rs"]
mod admission_delay_tests;
mod check;
mod exchange;
mod reuse;
pub(crate) use admission::AdmissionBudget;
pub use admission::{ControlAdmission, NeighborAdmission};
use check::AdmissionCheck;
use exchange::{Exchange, drive};
use reuse::IdleStreams;

use fips_core::{FipsEndpoint, NodeAddr, PeerIdentity};
use fips_tcp::{Config, ConnectionId, StackError, State};
use fips_tcp_endpoint::{AdapterError, FipsTcpEndpoint};
use ipnet::IpNet;
use serde::Serialize;
use std::{
    collections::{HashMap, VecDeque},
    sync::{
        Arc, Mutex, Weak,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};
use tokio::{
    sync::{Semaphore, mpsc, oneshot},
    task::JoinHandle,
};

pub const MAX_RECORD_BYTES: usize = 64 * 1024;
const MAX_CONNECTIONS: usize = 32;
const RESERVED_CONNECTIONS: usize = 8;
const QUEUE_SIZE: usize = 16;
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
const DRIVE_INTERVAL: Duration = Duration::from_millis(10);
const CONNECT_RETRY_INTERVAL: Duration = Duration::from_millis(50);

pub struct IncomingRequest {
    pub peer: PeerIdentity,
    pub body: Vec<u8>,
    /// Dropping this responder cancels this request. Responses are bounded by
    /// the same record limit; application success requires durable processing.
    pub respond: oneshot::Sender<Vec<u8>>,
}

struct Command {
    peer: PeerIdentity,
    body: Option<Vec<u8>>,
    response: oneshot::Sender<Result<Vec<u8>, String>>,
    retry_at: Instant,
}

pub struct ControlTransport {
    admission: Arc<ControlAdmission>,
    commands: mpsc::Sender<Command>,
    task: JoinHandle<()>,
    statistics: Arc<ControlStatistics>,
    outbound_slots: Semaphore,
    outbound_peers: Mutex<HashMap<NodeAddr, Weak<Semaphore>>>,
}

/// Volatile measurement counters. Bytes include application record framing;
/// they exclude TCP/FIPS/link headers, acknowledgments and retransmissions.
#[derive(Default)]
pub struct ControlStatistics {
    sent: AtomicU64,
    received: AtomicU64,
    requests_started: AtomicU64,
    requests_received: AtomicU64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ControlSnapshot {
    pub stream_bytes_sent: u64,
    pub stream_bytes_received: u64,
    pub requests_started: u64,
    pub requests_received: u64,
}

impl ControlStatistics {
    pub fn snapshot(&self) -> ControlSnapshot {
        ControlSnapshot {
            stream_bytes_sent: self.sent.load(Ordering::Relaxed),
            stream_bytes_received: self.received.load(Ordering::Relaxed),
            requests_started: self.requests_started.load(Ordering::Relaxed),
            requests_received: self.requests_received.load(Ordering::Relaxed),
        }
    }
}

impl ControlTransport {
    pub async fn start(
        endpoint: Arc<FipsEndpoint>,
        service_port: u16,
        neighbors: Vec<PeerIdentity>,
        isn_seed: u64,
    ) -> Result<(Self, mpsc::Receiver<IncomingRequest>), String> {
        Self::start_with_customers(endpoint, service_port, neighbors, None, isn_seed).await
    }

    /// Customer access permits inbound requests only. It never adds a peer to
    /// the set from which this node may purchase onward service.
    pub async fn start_with_customers(
        endpoint: Arc<FipsEndpoint>,
        service_port: u16,
        neighbors: Vec<PeerIdentity>,
        customer_network: Option<IpNet>,
        isn_seed: u64,
    ) -> Result<(Self, mpsc::Receiver<IncomingRequest>), String> {
        let admission = ControlAdmission::new(
            endpoint.clone(),
            neighbors,
            customer_network,
            NeighborAdmission::ConfiguredOnly,
        )?;
        Self::start_with_admission(endpoint, service_port, admission, isn_seed).await
    }

    /// Reuse the same admission object on every control port of this endpoint.
    pub async fn start_with_admission(
        endpoint: Arc<FipsEndpoint>,
        service_port: u16,
        admission: Arc<ControlAdmission>,
        isn_seed: u64,
    ) -> Result<(Self, mpsc::Receiver<IncomingRequest>), String> {
        if !admission.owns_endpoint(&endpoint) {
            return Err("control admission belongs to another endpoint".into());
        }
        let config = Config {
            receive_buffer: u16::MAX as usize,
            send_buffer: u16::MAX as usize,
            max_connections: MAX_CONNECTIONS,
            max_connections_per_peer: 4,
            fin_wait_2_ms: 250,
            time_wait_ms: 250,
            ..Config::default()
        };
        let mut tcp = FipsTcpEndpoint::bind(endpoint, service_port, config, isn_seed)
            .await
            .map_err(|e| e.to_string())?;
        let connection_admission = admission.clone();
        tcp.set_connection_reservation(
            RESERVED_CONNECTIONS,
            Arc::new(move |peer| connection_admission.reserves_connection(peer)),
        )
        .map_err(|e| e.to_string())?;
        let (commands, receive_commands) = mpsc::channel(QUEUE_SIZE);
        let (incoming, receive_incoming) = mpsc::channel(QUEUE_SIZE);
        let statistics = Arc::new(ControlStatistics::default());
        let task = tokio::spawn(run(
            tcp,
            admission.clone(),
            receive_commands,
            incoming,
            statistics.clone(),
        ));
        Ok((
            Self {
                admission,
                commands,
                task,
                statistics,
                outbound_slots: Semaphore::new(QUEUE_SIZE),
                outbound_peers: Mutex::new(HashMap::new()),
            },
            receive_incoming,
        ))
    }

    pub fn statistics(&self) -> Arc<ControlStatistics> {
        self.statistics.clone()
    }

    pub(crate) fn control_admission(&self) -> &Arc<ControlAdmission> {
        &self.admission
    }

    fn peer_request_slots(&self, peer: PeerIdentity) -> Result<Arc<Semaphore>, String> {
        let mut peers = self
            .outbound_peers
            .lock()
            .map_err(|_| "control outgoing peer slots poisoned")?;
        peers.retain(|_, slots| slots.strong_count() > 0);
        if let Some(slots) = peers.get(peer.node_addr()).and_then(Weak::upgrade) {
            return Ok(slots);
        }
        // A global slot is already held, so this registry remains bounded.
        // One slow peer may queue beyond its TCP limit without owning every
        // request slot needed by other neighbors' funding or payment exchanges.
        let slots = Arc::new(Semaphore::new(QUEUE_SIZE / 2));
        peers.insert(*peer.node_addr(), Arc::downgrade(&slots));
        Ok(slots)
    }

    pub async fn request(&self, peer: PeerIdentity, body: Vec<u8>) -> Result<Vec<u8>, String> {
        if body.len() > MAX_RECORD_BYTES {
            return Err("control record exceeds size limit".into());
        }
        self.command(peer, Some(body)).await
    }

    /// Establish an idle stream without sending an application record. The next
    /// request still needs fresh admission and may reconnect after idle eviction.
    pub async fn prepare(&self, peer: PeerIdentity) -> Result<(), String> {
        self.command(peer, None).await.map(|_| ())
    }

    async fn command(&self, peer: PeerIdentity, body: Option<Vec<u8>>) -> Result<Vec<u8>, String> {
        // Includes queued and active requests, not just the command mailbox.
        let _slot = self
            .outbound_slots
            .try_acquire()
            .map_err(|_| "control outgoing request capacity exhausted".to_string())?;
        let _peer_slot = self
            .peer_request_slots(peer)?
            .try_acquire_owned()
            .map_err(|_| "control peer request capacity exhausted".to_string())?;
        let (response, receive) = oneshot::channel();
        self.commands
            .try_send(Command {
                peer,
                body,
                response,
                retry_at: Instant::now(),
            })
            .map_err(|_| "control command queue is closed or full".to_string())?;
        tokio::time::timeout(REQUEST_TIMEOUT, receive)
            .await
            .map_err(|_| "control request timed out".to_string())?
            .map_err(|_| "control transport stopped".to_string())?
    }
}

impl Drop for ControlTransport {
    fn drop(&mut self) {
        self.task.abort();
    }
}

struct PendingCommand {
    command: Command,
    admission: AdmissionCheck,
    rechecking: bool,
}

async fn run(
    mut tcp: FipsTcpEndpoint,
    admission: Arc<ControlAdmission>,
    mut commands: mpsc::Receiver<Command>,
    incoming: mpsc::Sender<IncomingRequest>,
    statistics: Arc<ControlStatistics>,
) {
    let started = Instant::now();
    let mut exchanges = HashMap::<ConnectionId, Exchange>::new();
    let mut pending = VecDeque::<PendingCommand>::new();
    let mut idle = IdleStreams::default();
    let mut ticker = tokio::time::interval(DRIVE_INTERVAL);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        let now = started.elapsed().as_millis() as u64;
        tokio::select! {
            command = commands.recv(), if pending.len() < QUEUE_SIZE => {
                let Some(command) = command else { break; };
                if command.response.is_closed() { continue; }
                let check = AdmissionCheck::start(admission.clone(), command.peer, true);
                pending.push_back(PendingCommand { command, admission: check, rechecking: false });
            }
            result = tcp.receive_report(now) => {
                let Ok(report) = result else { break; };
                if report.connection_limited > 0 { idle.evict(&mut tcp, None, now).await; }
            }
            _ = ticker.tick() => {
                if tcp.poll(now).await.is_err() { break; }
            }
        }
        let now = started.elapsed().as_millis() as u64;
        for (id, exchange) in idle
            .ready(&mut tcp, admission.clone(), now, &statistics)
            .await
        {
            exchanges.insert(id, exchange);
        }
        // Round-robin only requests that have not connected yet. A saturated
        // peer cannot hold up another peer, and cancellation discards queued
        // work before any request is transmitted. Never replay a sent request.
        for _ in 0..pending.len() {
            let PendingCommand {
                mut command,
                admission: mut check,
                mut rechecking,
            } = pending.pop_front().expect("bounded pending queue");
            if command.response.is_closed() {
                continue;
            }
            let ready = match check.ready().await {
                Ok(ready) => ready,
                Err(error) => {
                    let _ = command.response.send(Err(error));
                    continue;
                }
            };
            if !ready || command.retry_at > Instant::now() || exchanges.len() >= MAX_CONNECTIONS {
                // A completed check cannot remain authorization across a later
                // capacity wait. Revalidate once a connection can be attempted.
                if ready {
                    rechecking = false;
                }
                pending.push_back(PendingCommand {
                    command,
                    admission: check,
                    rechecking,
                });
                continue;
            }
            if !rechecking {
                check.recheck();
                rechecking = true;
                pending.push_back(PendingCommand {
                    command,
                    admission: check,
                    rechecking,
                });
                continue;
            }
            let connection = match idle.take(&tcp, command.peer) {
                Some(id) => Ok(id),
                None => tcp.connect(command.peer, now).await,
            };
            match connection {
                Ok(id) => {
                    if command.body.is_some() {
                        statistics.requests_started.fetch_add(1, Ordering::Relaxed);
                    }
                    exchanges.insert(id, Exchange::client(command, check));
                }
                Err(AdapterError::Tcp(StackError::ConnectionLimit)) => {
                    // The TCP stack rejects before creating a connection or
                    // sending SYN. Closing streams can temporarily occupy slots.
                    idle.evict(&mut tcp, Some(command.peer), now).await;
                    command.retry_at = Instant::now() + CONNECT_RETRY_INTERVAL;
                    pending.push_back(PendingCommand {
                        command,
                        admission: check,
                        rechecking: false,
                    });
                }
                Err(error) => {
                    let _ = command.response.send(Err(error.to_string()));
                }
            }
        }
        while let Some(id) = tcp.accept() {
            if let Some(peer) = tcp.peer(id)
                && exchanges.len() < MAX_CONNECTIONS
            {
                let check = AdmissionCheck::start(admission.clone(), peer, false);
                exchanges.insert(id, Exchange::server(peer, check, Vec::new()));
                continue;
            }
            let _ = tcp.abort(id).await;
        }
        let ids: Vec<_> = exchanges.keys().copied().collect();
        for id in ids {
            let mut exchange = exchanges.remove(&id).expect("current exchange");
            match drive(&mut tcp, id, &mut exchange, &incoming, now, &statistics).await {
                Ok(true) => {
                    exchanges.insert(id, exchange);
                }
                Ok(false) => {
                    let (peer, outbound) = (exchange.peer, exchange.outbound);
                    drop(exchange);
                    idle.park(&mut tcp, id, peer, outbound, now).await;
                }
                Err(error) => {
                    exchange.fail(&error);
                    let _ = tcp.abort(id).await;
                }
            }
        }
    }
    // Dropping pending response senders reports failure to all waiting clients.
}
