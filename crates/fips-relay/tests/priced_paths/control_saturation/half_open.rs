//! Authenticated SYNs that never acknowledge the server's handshake.
use super::super::bench::Bench;
use fips_core::{
    Config, FipsEndpoint, FipsEndpointServiceReceiver, PeerIdentity, SimLink,
    config::{SimTransportConfig, TransportInstances},
};
use fips_tcp::{
    Stack, State,
    wire::{FIPS_VERSION, Flags, Segment},
};
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
use std::time::Duration;
use tokio::{
    sync::{mpsc, oneshot},
    task::JoinHandle,
    time::{Instant, MissedTickBehavior, timeout},
};

const PORT: u16 = 44_743;
const IDENTITIES: usize = 8;
const STREAMS: usize = 4;
const MIN_CONFIRMED: usize = 24;
const RETRANSMIT: Duration = Duration::from_millis(250);

enum Command {
    Check(oneshot::Sender<()>),
    Stop,
}

struct Worker {
    endpoint: Arc<FipsEndpoint>,
    peer: PeerIdentity,
    confirmed: Arc<AtomicUsize>,
    commands: mpsc::Sender<Command>,
    task: Option<JoinHandle<()>>,
}

impl Drop for Worker {
    fn drop(&mut self) {
        if let Some(task) = &self.task {
            task.abort();
        }
        // The final FIPS endpoint handle signals its node to stop on drop.
    }
}

pub(super) struct Attack {
    workers: Vec<Worker>,
    started: Instant,
}

impl Attack {
    pub(super) fn peers(&self) -> Vec<PeerIdentity> {
        self.workers.iter().map(|worker| worker.peer).collect()
    }

    pub(super) fn confirmed_count(&self) -> usize {
        self.workers
            .iter()
            .map(|worker| worker.confirmed.load(Ordering::Relaxed))
            .sum()
    }

    /// Includes all handshake startup time, beginning before the first SYN.
    pub(super) fn hold_age(&self) -> Duration {
        self.started.elapsed()
    }

    pub(super) async fn assert_live(&self) {
        timeout(Duration::from_secs(3), async {
            let mut replies = Vec::new();
            for worker in &self.workers {
                let (reply, checked) = oneshot::channel();
                worker.commands.send(Command::Check(reply)).await.unwrap();
                replies.push(checked);
            }
            for checked in replies {
                checked
                    .await
                    .expect("half-open driver lost a retained tuple");
            }
            assert!(self.confirmed_count() >= MIN_CONFIRMED);
        })
        .await
        .expect("fresh half-open SYN-ACK observation deadline");
    }

    pub(super) async fn stop(mut self) {
        self.assert_live().await;
        for worker in &self.workers {
            timeout(Duration::from_secs(1), worker.commands.send(Command::Stop))
                .await
                .unwrap()
                .unwrap();
        }
        // Drivers retain their receivers and transports until every offered
        // tuple answers a non-handshaking probe with the absent-tuple reset.
        for worker in &mut self.workers {
            timeout(Duration::from_secs(5), worker.task.as_mut().unwrap())
                .await
                .expect("half-open reset cleanup deadline")
                .expect("half-open driver failed");
            worker.task.take();
        }
        for worker in &self.workers {
            worker.endpoint.shutdown().await.unwrap();
        }
    }
}

pub(super) async fn start(bench: &Bench) -> Attack {
    timeout(Duration::from_secs(20), start_inner(bench))
        .await
        .expect("authenticated half-open attack startup deadline")
}

async fn start_inner(bench: &Bench) -> Attack {
    assert_eq!(bench.nodes.len(), 3);
    let mut endpoints = Vec::new();
    for index in 0..IDENTITIES {
        let address = format!("half-open-{index}");
        bench.network.set_link(
            address.clone(),
            "1",
            SimLink {
                latency_ms: 2,
                ..Default::default()
            },
        );
        let mut config = Config::new();
        config.node.identity.persistent = false;
        config.node.control.enabled = false;
        config.node.discovery.nostr.enabled = false;
        config.node.discovery.lan.enabled = false;
        config.node.discovery.local.enabled = false;
        config.transports = Default::default();
        config.transports.sim = TransportInstances::Single(SimTransportConfig {
            network: Some(bench.network_name.clone()),
            addr: Some(address),
            mtu: Some(1280),
            auto_connect: Some(true),
            accept_connections: Some(true),
        });
        endpoints.push(Arc::new(
            FipsEndpoint::builder()
                .config(config)
                .without_system_tun()
                .bind()
                .await
                .unwrap(),
        ));
    }
    for endpoint in &endpoints {
        loop {
            let ours = endpoint.peers().await.unwrap();
            let theirs = bench.nodes[1].peers().await.unwrap();
            if ours.iter().any(|peer| {
                peer.connected
                    && peer.node_addr == *bench.peers[1].node_addr()
                    && peer.transport_type.as_deref() == Some("sim")
            }) && theirs.iter().any(|peer| {
                peer.connected
                    && peer.npub == endpoint.npub()
                    && peer.transport_type.as_deref() == Some("sim")
            }) {
                assert_eq!(ours.iter().filter(|peer| peer.connected).count(), 1);
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }
    let mut attack = Attack {
        workers: Vec::new(),
        started: Instant::now(),
    };
    let mut readiness = Vec::new();
    for (index, endpoint) in endpoints.into_iter().enumerate() {
        let receiver = endpoint.register_service_receiver(PORT).await.unwrap();
        let confirmed = Arc::new(AtomicUsize::new(0));
        let (commands, input) = mpsc::channel(2);
        let (ready, sent) = oneshot::channel();
        let task = tokio::spawn(drive(
            endpoint.clone(),
            receiver,
            bench.peers[1],
            index as u64 + 1,
            confirmed.clone(),
            input,
            ready,
        ));
        attack.workers.push(Worker {
            peer: PeerIdentity::from_npub(endpoint.npub()).unwrap(),
            endpoint,
            confirmed,
            commands,
            task: Some(task),
        });
        readiness.push(sent);
    }
    for sent in readiness {
        sent.await.expect("initial SYN submission failed");
    }
    // All 32 offers are submitted. A protected server may admit only 24;
    // elapsed time alone is never acceptance: fresh retained tuples are below.
    let _ = timeout(Duration::from_secs(2), async {
        while attack.confirmed_count() != IDENTITIES * STREAMS {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await;
    attack.assert_live().await;
    attack
}

struct Tuple {
    syn: Segment,
    server_seq: Option<u32>,
    observations: u64,
    released: bool,
}

async fn send(endpoint: &FipsEndpoint, target: PeerIdentity, segment: &Segment) {
    assert!(
        !segment.flags.contains(Flags::ACK),
        "attacker emitted an ACK"
    );
    assert!(segment.ack.is_none());
    endpoint
        .send_datagram(target, PORT, PORT, segment.encode().unwrap())
        .await
        .unwrap();
}

async fn transmit(endpoint: &FipsEndpoint, target: PeerIdentity, tuples: &[Tuple], stopping: bool) {
    for tuple in tuples.iter().filter(|tuple| !tuple.released) {
        if stopping {
            // A SYN-RECEIVED reset requires exactly recv_nxt, not the SYN seq.
            let mut reset = Segment::new(tuple.syn.src_port, PORT, tuple.syn.seq.wrapping_add(1));
            reset.flags = Flags::RST;
            send(endpoint, target, &reset).await;
            // SynReceived ignores FIN without ACK. Only an absent tuple sends
            // RST|ACK acknowledging this FIN, proving the reset took effect.
            reset.flags = Flags::FIN;
            send(endpoint, target, &reset).await;
        } else {
            assert_eq!(tuple.syn.flags, Flags::SYN);
            send(endpoint, target, &tuple.syn).await;
        }
    }
}

fn observe(tuple: &mut Tuple, segment: Segment, stopping: bool, confirmed: &AtomicUsize) {
    assert!(segment.payload.is_empty());
    if stopping
        && segment.flags == (Flags::RST | Flags::ACK)
        && segment.ack == Some(tuple.syn.seq.wrapping_add(2))
    {
        assert_eq!(segment.seq, 0);
        tuple.released = true;
        return;
    }
    if stopping && segment.flags.contains(Flags::RST) {
        // A delayed refusal of a SYN is not the FIN-probe release receipt.
        return;
    }
    if segment.flags.contains(Flags::RST) && tuple.server_seq.is_none() {
        // Refusal of an unconfirmed offer is compatible with reserved capacity.
        return;
    }
    assert_eq!(segment.flags, Flags::SYN | Flags::ACK);
    assert_eq!(segment.ack, Some(tuple.syn.seq.wrapping_add(1)));
    assert!(segment.supports_fips_version(FIPS_VERSION));
    if let Some(original) = tuple.server_seq {
        assert_eq!(
            segment.seq, original,
            "retained half-open tuple was replaced"
        );
    } else {
        tuple.server_seq = Some(segment.seq);
        confirmed.fetch_add(1, Ordering::Relaxed);
    }
    tuple.observations += 1;
}

async fn drive(
    endpoint: Arc<FipsEndpoint>,
    receiver: FipsEndpointServiceReceiver,
    target: PeerIdentity,
    seed: u64,
    confirmed: Arc<AtomicUsize>,
    mut commands: mpsc::Receiver<Command>,
    ready: oneshot::Sender<()>,
) {
    let mut stack = Stack::<String>::new(
        fips_tcp::Config {
            max_connections: STREAMS,
            max_connections_per_peer: STREAMS,
            ..Default::default()
        },
        seed,
    );
    let ids: Vec<_> = (0..STREAMS)
        .map(|_| stack.connect(target.npub(), PORT, 0).unwrap())
        .collect();
    let mut tuples: Vec<_> = stack
        .drain_outbound()
        .into_iter()
        .map(|output| {
            assert_eq!(output.peer, target.npub());
            Tuple {
                syn: Segment::decode(&output.bytes).unwrap(),
                server_seq: None,
                observations: 0,
                released: false,
            }
        })
        .collect();
    assert_eq!(tuples.len(), STREAMS);
    transmit(&endpoint, target, &tuples, false).await;
    ready.send(()).unwrap();
    let mut ticker = tokio::time::interval(RETRANSMIT);
    ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);
    let mut batch = Vec::new();
    let mut check: Option<(Vec<u64>, oneshot::Sender<()>)> = None;
    let mut stopping: Option<Instant> = None;
    loop {
        // No response enters this stack: its SYN-SENT state can never produce
        // a final ACK. Every emitted raw packet also passes the no-ACK guard.
        assert!(
            ids.iter()
                .all(|&id| stack.state(id) == Some(State::SynSent))
        );
        tokio::select! {
            command = commands.recv(), if stopping.is_none() => match command {
                Some(Command::Check(reply)) => {
                    assert!(check.is_none());
                    check = Some((tuples.iter().map(|tuple| tuple.observations).collect(), reply));
                    transmit(&endpoint, target, &tuples, false).await;
                }
                Some(Command::Stop) | None => {
                    stopping = Some(Instant::now());
                    transmit(&endpoint, target, &tuples, true).await;
                }
            },
            count = receiver.recv_batch_into(&mut batch, 32) => {
                assert!(count.is_some(), "half-open FIPS receiver closed");
                for datagram in batch.drain(..) {
                    assert_eq!(datagram.source_peer, target);
                    assert_eq!((datagram.source_port, datagram.destination_port), (PORT, PORT));
                    let segment = Segment::decode(datagram.data.as_slice()).unwrap();
                    assert_eq!(segment.src_port, PORT);
                    let tuple = tuples.iter_mut().find(|tuple| tuple.syn.src_port == segment.dst_port)
                        .expect("response to an offered tuple");
                    observe(tuple, segment, stopping.is_some(), &confirmed);
                }
            }
            _ = ticker.tick() => transmit(&endpoint, target, &tuples, stopping.is_some()).await,
        }
        if check.as_ref().is_some_and(|(before, _)| {
            tuples
                .iter()
                .zip(before)
                .all(|(tuple, &count)| count == 0 || tuple.observations > count)
        }) {
            let (_, reply) = check.take().unwrap();
            let _ = reply.send(());
        }
        if let Some(started) = stopping {
            if tuples.iter().all(|tuple| tuple.released) {
                break;
            }
            assert!(
                started.elapsed() < Duration::from_secs(3),
                "half-open tuple reset was not confirmed"
            );
        }
    }
}
