//! Bounded request/reply records over the existing TCP/FIPS adapter.
//!
//! This reliable transport is for quotes and payments between configured
//! neighbors. Its TCP acknowledgments say nothing about paid data delivery.

use fips_core::{FipsEndpoint, NodeAddr, PeerIdentity};
use fips_tcp::{Config, ConnectionId, State};
use fips_tcp_endpoint::FipsTcpEndpoint;
use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
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
const ADMISSION_BURST: u32 = 16;
const ADMISSION_INTERVAL: Duration = Duration::from_millis(100);

struct AdmissionBudget {
    updated: Instant,
    tokens: u32,
}

impl AdmissionBudget {
    fn allow(&mut self, now: Instant) -> bool {
        let intervals =
            now.duration_since(self.updated).as_millis() / ADMISSION_INTERVAL.as_millis();
        if intervals > 0 {
            self.tokens = self
                .tokens
                .saturating_add(intervals.min(u128::from(ADMISSION_BURST)) as u32)
                .min(ADMISSION_BURST);
            self.updated = now;
        }
        if self.tokens == 0 {
            return false;
        }
        self.tokens -= 1;
        true
    }
}

fn allow_request(
    budgets: &mut HashMap<(NodeAddr, bool), AdmissionBudget>,
    peer: NodeAddr,
    outbound: bool,
) -> bool {
    let now = Instant::now();
    budgets
        .entry((peer, outbound))
        .or_insert(AdmissionBudget {
            updated: now,
            tokens: ADMISSION_BURST,
        })
        .allow(now)
}

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
}

impl ControlTransport {
    pub async fn start(
        endpoint: Arc<FipsEndpoint>,
        service_port: u16,
        neighbors: Vec<PeerIdentity>,
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
        let tcp = FipsTcpEndpoint::bind(endpoint, service_port, config, isn_seed)
            .await
            .map_err(|e| e.to_string())?;
        let neighbors = neighbors.iter().map(|peer| *peer.node_addr()).collect();
        let (commands, receive_commands) = mpsc::channel(QUEUE_SIZE);
        let (incoming, receive_incoming) = mpsc::channel(QUEUE_SIZE);
        let task = tokio::spawn(run(tcp, neighbors, receive_commands, incoming));
        Ok((Self { commands, task }, receive_incoming))
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
    mut commands: mpsc::Receiver<Command>,
    incoming: mpsc::Sender<IncomingRequest>,
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
            match tcp.peer(id) {
                Some(peer)
                    if neighbors.contains(peer.node_addr())
                        && exchanges.len() < MAX_CONNECTIONS
                        && allow_request(&mut budgets, *peer.node_addr(), false) =>
                {
                    exchanges.insert(id, Exchange::server(peer));
                }
                _ => {
                    let _ = tcp.abort(id).await;
                }
            }
        }
        let ids: Vec<_> = exchanges.keys().copied().collect();
        for id in ids {
            let mut exchange = exchanges.remove(&id).expect("current exchange");
            match drive(&mut tcp, id, &mut exchange, &incoming, now).await {
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
        exchange.sent += tcp
            .write(id, &exchange.outgoing[exchange.sent..end], now)
            .await
            .map_err(|e| e.to_string())?;
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
    exchange.incoming.extend_from_slice(&bytes);
    if complete_frame(&exchange.incoming)? {
        let body = exchange.incoming.split_off(4);
        if let Some(response) = exchange.client.take() {
            let _ = response.send(Ok(body));
            return Ok(false);
        }
        let (respond, receiver) = oneshot::channel();
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
    fn admission_burst_refills_to_its_fixed_cap() {
        let now = Instant::now();
        let mut budget = AdmissionBudget {
            updated: now,
            tokens: ADMISSION_BURST,
        };
        for _ in 0..ADMISSION_BURST {
            assert!(budget.allow(now));
        }
        assert!(!budget.allow(now));
        assert!(budget.allow(now + ADMISSION_INTERVAL));
        assert!(!budget.allow(now + ADMISSION_INTERVAL));
        assert!(budget.allow(now + Duration::from_secs(10)));
        assert_eq!(budget.tokens, ADMISSION_BURST - 1);
    }

    #[test]
    fn record_decoder_rejects_oversize_and_extra_records() {
        assert!(!complete_frame(&[0, 0, 1]).unwrap());
        assert!(complete_frame(&frame(vec![1; MAX_RECORD_BYTES]).unwrap()).unwrap());
        assert!(complete_frame(&[0, 1, 0, 1]).is_err());
        assert!(complete_frame(&[0, 0, 0, 0, 1]).is_err());
    }
}
