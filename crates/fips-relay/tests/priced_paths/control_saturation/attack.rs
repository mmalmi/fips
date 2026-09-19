//! Authenticated neighbors holding incomplete records through the real TCP adapter.
use super::super::bench::Bench;
use fips_core::{
    Config, FipsEndpoint, PeerIdentity, SimLink,
    config::{SimTransportConfig, TransportInstances},
};
use fips_relay::control_transport::ControlAdmission;
use fips_tcp::{ConnectionId, MarkerStatus, State};
use fips_tcp_endpoint::FipsTcpEndpoint;
use std::{sync::Arc, time::Duration};
use tokio::{
    sync::{mpsc, oneshot},
    task::JoinHandle,
    time::{Instant, Interval, MissedTickBehavior, timeout},
};

const PORT: u16 = 44_743;
const STREAMS: usize = 4;
const DRIVE_INTERVAL: Duration = Duration::from_millis(10);

enum Command {
    Check(oneshot::Sender<()>),
    Stop,
}

struct Worker {
    endpoint: Arc<FipsEndpoint>,
    peer: PeerIdentity,
    commands: mpsc::Sender<Command>,
    task: Option<JoinHandle<()>>,
}

impl Drop for Worker {
    fn drop(&mut self) {
        if let Some(task) = &self.task {
            task.abort();
        }
        // Dropping the final endpoint handle also signals its node to stop.
    }
}

pub(super) struct Attack {
    workers: Vec<Worker>,
    started: Instant,
    admission: Arc<ControlAdmission>,
}

impl Attack {
    pub(super) fn peers(&self) -> [PeerIdentity; 2] {
        [self.workers[0].peer, self.workers[1].peer]
    }

    pub(super) async fn assert_live(&self) {
        timeout(Duration::from_secs(2), async {
            for worker in &self.workers {
                let (reply, checked) = oneshot::channel();
                worker
                    .commands
                    .send(Command::Check(reply))
                    .await
                    .expect("attack driver stopped");
                checked.await.expect("attack streams did not remain live");
            }
        })
        .await
        .expect("attack liveness check deadline");
    }

    /// Starts before the first SYN, conservatively including handshake time.
    pub(super) fn hold_age(&self) -> Duration {
        self.started.elapsed()
    }

    pub(super) async fn stop(mut self) {
        self.assert_live().await;
        for worker in &self.workers {
            timeout(Duration::from_secs(2), worker.commands.send(Command::Stop))
                .await
                .expect("attack stop command deadline")
                .expect("attack driver stopped before cleanup");
        }
        for worker in &mut self.workers {
            // Keep the handle in its Drop guard until the join completes.
            timeout(Duration::from_secs(5), worker.task.as_mut().unwrap())
                .await
                .expect("attack stream abort deadline")
                .expect("attack driver failed");
            worker.task.take();
        }
        // Abort only queues the RST. Keep Sim transports alive until the
        // receiver confirms that those resets released every held permit.
        timeout(Duration::from_secs(3), async {
            while self.workers.iter().any(|worker| {
                self.admission
                    .active_unconfigured_exchanges(*worker.peer.node_addr())
                    != 0
            }) {
                tokio::time::sleep(DRIVE_INTERVAL).await;
            }
        })
        .await
        .expect("attack admission release deadline");
        for worker in &self.workers {
            worker.endpoint.shutdown().await.unwrap();
        }
    }
}

pub(super) async fn start(bench: &Bench) -> Attack {
    timeout(Duration::from_secs(20), start_inner(bench))
        .await
        .expect("authenticated incomplete-record attack startup deadline")
}

async fn start_inner(bench: &Bench) -> Attack {
    assert_eq!(bench.nodes.len(), 3);
    let mut endpoints = Vec::new();
    for address in ["attacker-a", "attacker-b"] {
        // The fixture's default link is down; these are the only attack edges.
        bench.network.set_link(
            address,
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
            addr: Some(address.into()),
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
            tokio::time::sleep(DRIVE_INTERVAL).await;
        }
    }

    let mut attack = Attack {
        workers: Vec::new(),
        started: Instant::now(),
        admission: bench.admissions[1].clone(),
    };
    let mut readiness = Vec::new();
    for (index, endpoint) in endpoints.into_iter().enumerate() {
        let peer = PeerIdentity::from_npub(endpoint.npub()).unwrap();
        let tcp = FipsTcpEndpoint::bind(
            endpoint.clone(),
            PORT,
            fips_tcp::Config {
                max_connections: STREAMS,
                max_connections_per_peer: STREAMS,
                ..Default::default()
            },
            index as u64 + 1,
        )
        .await
        .unwrap();
        let (commands, receiver) = mpsc::channel(2);
        let (ready, waiting) = oneshot::channel();
        let task = tokio::spawn(drive(tcp, bench.peers[1], attack.started, receiver, ready));
        attack.workers.push(Worker {
            endpoint,
            peer,
            commands,
            task: Some(task),
        });
        readiness.push(waiting);
    }
    for ready in readiness {
        ready.await.expect("attack startup driver failed");
    }
    attack.assert_live().await;
    attack
}

fn assert_streams(tcp: &FipsTcpEndpoint, streams: &[ConnectionId]) {
    assert_eq!(streams.len(), STREAMS);
    for &id in streams {
        assert_eq!(tcp.state(id), Some(State::Established));
        assert!(!tcp.is_read_closed(id), "incomplete stream was closed");
    }
}

async fn drive_once(tcp: &mut FipsTcpEndpoint, started: Instant, ticker: &mut Interval) {
    let now = started.elapsed().as_millis() as u64;
    tokio::select! {
        report = tcp.receive_report(now) => {
            assert_eq!(report.unwrap().rejected(), 0, "invalid attack TCP input");
        }
        _ = ticker.tick() => tcp.poll(now).await.unwrap(),
    }
}

async fn drive(
    mut tcp: FipsTcpEndpoint,
    target: PeerIdentity,
    started: Instant,
    mut commands: mpsc::Receiver<Command>,
    ready: oneshot::Sender<()>,
) {
    let mut ticker = tokio::time::interval(DRIVE_INTERVAL);
    ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);
    let mut streams = Vec::new();
    for _ in 0..STREAMS {
        streams.push(
            tcp.connect(target, started.elapsed().as_millis() as u64)
                .await
                .unwrap(),
        );
    }
    while streams
        .iter()
        .any(|&id| tcp.state(id) != Some(State::Established))
    {
        for &id in &streams {
            assert!(matches!(
                tcp.state(id),
                Some(State::SynSent | State::Established)
            ));
        }
        drive_once(&mut tcp, started, &mut ticker).await;
    }

    // A valid maximum-size record prefix plus one body byte, never completed.
    let mut incomplete = (64 * 1024u32).to_be_bytes().to_vec();
    incomplete.push(0);
    let mut markers = Vec::new();
    for &id in &streams {
        let (written, marker) = tcp
            .write_with_marker(id, &incomplete, started.elapsed().as_millis() as u64)
            .await
            .unwrap();
        assert_eq!(written, incomplete.len());
        markers.push(marker);
    }
    while markers
        .iter()
        .any(|marker| tcp.marker_status(marker) != MarkerStatus::Acked)
    {
        assert_streams(&tcp, &streams);
        drive_once(&mut tcp, started, &mut ticker).await;
    }
    assert_streams(&tcp, &streams);
    ready.send(()).expect("attack startup was cancelled");
    loop {
        assert_streams(&tcp, &streams);
        tokio::select! {
            command = commands.recv() => match command {
                Some(Command::Check(reply)) => {
                    assert_streams(&tcp, &streams);
                    let _ = reply.send(());
                }
                Some(Command::Stop) | None => break,
            },
            () = drive_once(&mut tcp, started, &mut ticker) => {}
        }
    }
    for id in streams {
        tcp.abort(id).await.unwrap();
    }
}
