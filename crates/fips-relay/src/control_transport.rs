//! Bounded request/reply records over the existing TCP/FIPS adapter.
//!
//! Configured neighbors can initiate purchases. An explicit customer network
//! also permits bounded inbound requests from authenticated direct UDP peers.
//! TCP acknowledgments say nothing about paid data delivery.

mod admission;
use admission::{CustomerAdmission, allow_request};

use fips_core::{FipsEndpoint, NodeAddr, PeerIdentity};
use fips_tcp::{Config, ConnectionId, State};
use fips_tcp_endpoint::FipsTcpEndpoint;
use ipnet::IpNet;
use serde::Serialize;
use std::{
    collections::{HashMap, HashSet},
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};
use tokio::{
    sync::{mpsc, oneshot},
    task::JoinHandle,
};

pub const MAX_RECORD_BYTES: usize = 64 * 1024;
const MAX_CONNECTIONS: usize = 32;
const QUEUE_SIZE: usize = 16;
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
const DRIVE_INTERVAL: Duration = Duration::from_millis(10);

pub struct IncomingRequest {
    pub peer: PeerIdentity,
    pub body: Vec<u8>,
    /// Dropping this responder cancels this request. Responses are bounded by
    /// the same record limit; application success requires durable processing.
    pub respond: oneshot::Sender<Vec<u8>>,
}

struct Command {
    peer: PeerIdentity,
    body: Vec<u8>,
    response: oneshot::Sender<Result<Vec<u8>, String>>,
}

pub struct ControlTransport {
    commands: mpsc::Sender<Command>,
    task: JoinHandle<()>,
    statistics: Arc<ControlStatistics>,
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
        if neighbors.len() > 64 {
            return Err("too many configured control neighbors".into());
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
        let customers =
            customer_network.map(|network| CustomerAdmission::new(endpoint.clone(), network));
        let tcp = FipsTcpEndpoint::bind(endpoint, service_port, config, isn_seed)
            .await
            .map_err(|e| e.to_string())?;
        let neighbors = neighbors.iter().map(|peer| *peer.node_addr()).collect();
        let (commands, receive_commands) = mpsc::channel(QUEUE_SIZE);
        let (incoming, receive_incoming) = mpsc::channel(QUEUE_SIZE);
        let statistics = Arc::new(ControlStatistics::default());
        let task = tokio::spawn(run(
            tcp,
            neighbors,
            customers,
            receive_commands,
            incoming,
            statistics.clone(),
        ));
        Ok((
            Self {
                commands,
                task,
                statistics,
            },
            receive_incoming,
        ))
    }

    pub fn statistics(&self) -> Arc<ControlStatistics> {
        self.statistics.clone()
    }

    pub async fn request(&self, peer: PeerIdentity, body: Vec<u8>) -> Result<Vec<u8>, String> {
        if body.len() > MAX_RECORD_BYTES {
            return Err("control record exceeds size limit".into());
        }
        let (response, receive) = oneshot::channel();
        self.commands
            .try_send(Command {
                peer,
                body,
                response,
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

struct Exchange {
    peer: PeerIdentity,
    customer: bool,
    started: Instant,
    outgoing: Vec<u8>,
    sent: usize,
    incoming: Vec<u8>,
    dispatched: bool,
    client: Option<oneshot::Sender<Result<Vec<u8>, String>>>,
    server_reply: Option<oneshot::Receiver<Vec<u8>>>,
}

impl Exchange {
    fn server(peer: PeerIdentity) -> Self {
        Self {
            peer,
            customer: false,
            started: Instant::now(),
            outgoing: Vec::new(),
            sent: 0,
            incoming: Vec::new(),
            dispatched: false,
            client: None,
            server_reply: None,
        }
    }

    fn fail(&mut self, reason: &str) {
        if let Some(response) = self.client.take() {
            let _ = response.send(Err(reason.to_string()));
        }
    }
}

fn frame(body: Vec<u8>) -> Result<Vec<u8>, String> {
    if body.len() > MAX_RECORD_BYTES {
        return Err("control record exceeds size limit".into());
    }
    let mut result = Vec::with_capacity(body.len() + 4);
    result.extend_from_slice(&(body.len() as u32).to_be_bytes());
    result.extend_from_slice(&body);
    Ok(result)
}

fn complete_frame(bytes: &[u8]) -> Result<bool, String> {
    if bytes.len() < 4 {
        return Ok(false);
    }
    let size = u32::from_be_bytes(bytes[..4].try_into().unwrap()) as usize;
    if size > MAX_RECORD_BYTES || bytes.len() > size + 4 {
        return Err("invalid control record length".into());
    }
    Ok(bytes.len() == size + 4)
}

async fn run(
    mut tcp: FipsTcpEndpoint,
    neighbors: HashSet<NodeAddr>,
    mut customers: Option<CustomerAdmission>,
    mut commands: mpsc::Receiver<Command>,
    incoming: mpsc::Sender<IncomingRequest>,
    statistics: Arc<ControlStatistics>,
) {
    let started = Instant::now();
    let mut exchanges = HashMap::<ConnectionId, Exchange>::new();
    let mut budgets = HashMap::new();
    let mut ticker = tokio::time::interval(DRIVE_INTERVAL);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        let now = started.elapsed().as_millis() as u64;
        tokio::select! {
            command = commands.recv() => {
                let Some(command) = command else { break; };
                if !neighbors.contains(command.peer.node_addr()) || exchanges.len() >= MAX_CONNECTIONS
                    || !allow_request(&mut budgets, *command.peer.node_addr(), true) {
                    let _ = command.response.send(Err("not an authorized neighbor or control capacity exhausted".into()));
                    continue;
                }
                if command.response.is_closed() { continue; }
                match tcp.connect(command.peer, now).await {
                    Ok(id) => {
                        statistics.requests_started.fetch_add(1, Ordering::Relaxed);
                        let mut exchange = Exchange::server(command.peer);
                        exchange.outgoing = frame(command.body).expect("bounded at command entry");
                        exchange.client = Some(command.response);
                        exchanges.insert(id, exchange);
                    }
                    Err(error) => { let _ = command.response.send(Err(error.to_string())); }
                }
            }
            result = tcp.receive_report(now) => {
                if result.is_err() { break; }
            }
            _ = ticker.tick() => {
                if tcp.poll(now).await.is_err() { break; }
            }
        }
        let now = started.elapsed().as_millis() as u64;
        while let Some(id) = tcp.accept() {
            if let Some(peer) = tcp.peer(id)
                && exchanges.len() < MAX_CONNECTIONS
            {
                let known = neighbors.contains(peer.node_addr());
                let allowed = if known {
                    allow_request(&mut budgets, *peer.node_addr(), false)
                } else if let Some(customers) = customers.as_mut() {
                    let active = exchanges.values().filter(|e| e.customer).count();
                    customers.allow(peer, active).await
                } else {
                    false
                };
                if allowed {
                    let mut exchange = Exchange::server(peer);
                    exchange.customer = !known;
                    exchanges.insert(id, exchange);
                    continue;
                }
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
                    let _ = tcp.close(id, now).await;
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

async fn drive(
    tcp: &mut FipsTcpEndpoint,
    id: ConnectionId,
    exchange: &mut Exchange,
    incoming: &mpsc::Sender<IncomingRequest>,
    now: u64,
    statistics: &ControlStatistics,
) -> Result<bool, String> {
    if exchange.started.elapsed() >= REQUEST_TIMEOUT
        || exchange.client.as_ref().is_some_and(|c| c.is_closed())
    {
        return Err("control request expired or canceled".into());
    }
    let Some(state) = tcp.state(id) else {
        return Err("control stream closed".into());
    };
    if !matches!(state, State::Established | State::CloseWait) {
        return Ok(true);
    }
    if let Some(receiver) = exchange.server_reply.as_mut() {
        match receiver.try_recv() {
            Ok(reply) => {
                exchange.outgoing = frame(reply)?;
                exchange.server_reply = None;
            }
            Err(oneshot::error::TryRecvError::Closed) => {
                return Err("control handler canceled request".into());
            }
            Err(oneshot::error::TryRecvError::Empty) => {}
        }
    }
    if exchange.sent < exchange.outgoing.len() {
        let end = (exchange.sent + 16 * 1024).min(exchange.outgoing.len());
        let written = tcp
            .write(id, &exchange.outgoing[exchange.sent..end], now)
            .await
            .map_err(|e| e.to_string())?;
        exchange.sent += written;
        statistics.sent.fetch_add(written as u64, Ordering::Relaxed);
    }
    if exchange.client.is_none()
        && exchange.dispatched
        && !exchange.outgoing.is_empty()
        && exchange.sent == exchange.outgoing.len()
    {
        return Ok(false);
    }
    if exchange.dispatched {
        return Ok(true);
    }
    let bytes = tcp
        .read(id, MAX_RECORD_BYTES + 4 - exchange.incoming.len(), now)
        .await
        .map_err(|e| e.to_string())?;
    statistics
        .received
        .fetch_add(bytes.len() as u64, Ordering::Relaxed);
    exchange.incoming.extend_from_slice(&bytes);
    if complete_frame(&exchange.incoming)? {
        let body = exchange.incoming.split_off(4);
        if let Some(response) = exchange.client.take() {
            let _ = response.send(Ok(body));
            return Ok(false);
        }
        let (respond, receiver) = oneshot::channel();
        statistics.requests_received.fetch_add(1, Ordering::Relaxed);
        incoming
            .try_send(IncomingRequest {
                peer: exchange.peer,
                body,
                respond,
            })
            .map_err(|_| "control handler queue is closed or full".to_string())?;
        exchange.server_reply = Some(receiver);
        exchange.dispatched = true;
    } else if tcp.is_read_closed(id) {
        return Err("control stream ended before its record".into());
    }
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn record_decoder_rejects_oversize_and_extra_records() {
        assert!(!complete_frame(&[0, 0, 1]).unwrap());
        assert!(complete_frame(&frame(vec![1; MAX_RECORD_BYTES]).unwrap()).unwrap());
        assert!(complete_frame(&[0, 1, 0, 1]).is_err());
        assert!(complete_frame(&[0, 0, 0, 0, 1]).is_err());
    }
}
