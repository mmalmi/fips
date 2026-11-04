//! Opt-in operator fixture. Hosts, peer pins and disposable keys are runtime
//! inputs; ordinary test execution sends no public traffic.
use super::*;
use fips_core::{FipsEndpointServiceReceiver, PeerIdentity};
use std::{
    fs::OpenOptions,
    io::Write,
    path::PathBuf,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

type ProbeResult<T> = Result<T, Box<dyn std::error::Error + Send + Sync>>;
const PORT: u16 = 44_011;

#[test]
fn prepare_external_probe_inputs() {
    prepare_inputs(false);
}

#[test]
fn prepare_external_wss_probe_inputs() {
    prepare_inputs(true);
}

fn check_websocket_url(address: &str) {
    if std::env::var("FIPS_EXTERNAL_PROBE_LOOPBACK_CONTROL").as_deref() == Ok("1") {
        let socket: std::net::SocketAddr = address
            .strip_prefix("ws://")
            .and_then(|value| value.strip_suffix("/fips"))
            .expect("private control requires a loopback WS URL")
            .parse()
            .unwrap();
        assert!(socket.ip().is_loopback());
    } else {
        assert!(address.starts_with("wss://"), "public probe requires TLS");
    }
}

fn prepare_inputs(websocket: bool) {
    let Some(path) = std::env::var_os("FIPS_EXTERNAL_PROBE_SEEDS") else {
        return;
    };
    let directory = PathBuf::from(std::env::var_os("FIPS_EXTERNAL_PROBE_DIRECTORY").unwrap());
    let seeds: Vec<serde_json::Value> =
        serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
    assert_eq!(seeds.len(), 2);
    let mut public = Vec::new();
    for (role, seed) in ["a", "b"].into_iter().zip(seeds) {
        let identity = fips_core::Identity::generate();
        let seed_npub = seed["npub"].as_str().unwrap();
        PeerIdentity::from_npub(seed_npub).unwrap();
        let mut config = Config::new();
        config.node.identity.nsec = Some(fips_core::encode_nsec(&identity.keypair().secret_key()));
        config.node.routing.mode = fips_core::config::RoutingMode::ReplyLearned;
        config.node.system_files_enabled = false;
        config.node.control.enabled = false;
        config.node.discovery.local.enabled = false;
        config.node.discovery.lan.enabled = false;
        config.node.discovery.nostr.enabled = false;
        config.transports = Default::default();
        let address = seed["address"].as_str().unwrap();
        if websocket {
            check_websocket_url(address);
            config.transports.websocket =
                fips_core::config::TransportInstances::Single(fips_core::config::WebSocketConfig {
                    seed_urls: vec![address.to_string()],
                    ..Default::default()
                });
        } else {
            config.transports.udp =
                fips_core::config::TransportInstances::Single(fips_core::UdpConfig {
                    bind_addr: Some("0.0.0.0:0".into()),
                    accept_connections: Some(true),
                    ..Default::default()
                });
        }
        config.peers = vec![fips_core::config::PeerConfig::new(
            seed_npub,
            if websocket { "websocket" } else { "udp" },
            address,
        )];
        let mut value = serde_json::to_value(config).unwrap();
        value["node"]["strict_client_only"] = true.into();
        value["node"]["peer_admission"] =
            serde_json::json!({"configured_only":true,"denied_npubs":[]});
        let mut options = OpenOptions::new();
        options.create_new(true).write(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options
            .open(directory.join(format!("{role}.config.json")))
            .unwrap();
        serde_json::to_writer(&mut file, &value).unwrap();
        public.push(serde_json::json!({"role":role,"npub":identity.npub()}));
    }
    let file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(directory.join("identities.json"))
        .unwrap();
    serde_json::to_writer(file, &public).unwrap();
}

struct Events {
    file: std::fs::File,
    started: Instant,
    count: usize,
}
impl Events {
    fn record(&mut self, event: &str, detail: serde_json::Value) -> ProbeResult<()> {
        if self.count >= 64 {
            return Err("event bound exceeded".into());
        }
        self.count += 1;
        writeln!(
            self.file,
            "{}",
            serde_json::json!({
                "event":event, "detail":detail, "elapsed_ms":self.started.elapsed().as_millis(),
                "unix_ms":SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis()
            })
        )?;
        self.file.flush()?;
        Ok(())
    }
}

async fn wait_file(path: PathBuf) {
    while !path.is_file() {
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

async fn exchange(
    endpoint: &FipsEndpoint,
    receiver: &FipsEndpointServiceReceiver,
    remote: PeerIdentity,
    initiate: bool,
    step: u8,
    events: &mut Events,
) -> ProbeResult<()> {
    let request = format!("strict-probe/request/{step}").into_bytes();
    let reply = format!("strict-probe/reply/{step}").into_bytes();
    if initiate {
        endpoint
            .send_datagram(remote, PORT, PORT, request.clone())
            .await?;
        events.record("request_sent", serde_json::json!({"step":step}))?;
    }
    loop {
        let mut packets = Vec::new();
        receiver
            // A reply and the next request can already be queued together.
            // Return only the packet consumed by this exchange; leave the
            // next step in the receiver instead of dropping a batch tail.
            .recv_batch_into(&mut packets, 1)
            .await
            .ok_or("service closed")?;
        for packet in packets {
            if packet.source_peer.npub() != remote.npub() || packet.data.as_slice().len() > 1024 {
                return Err("unexpected service sender or payload size".into());
            }
            if initiate && packet.data.as_slice() == reply {
                events.record("reply_received", serde_json::json!({"step":step}))?;
                return Ok(());
            }
            if !initiate && packet.data.as_slice() == request {
                events.record("request_received", serde_json::json!({"step":step}))?;
                endpoint.send_datagram(remote, PORT, PORT, reply).await?;
                events.record("reply_sent", serde_json::json!({"step":step}))?;
                return Ok(());
            }
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn external_seed_strict_probe() {
    run_probe(false).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn external_seed_strict_wss_probe() {
    run_probe(true).await;
}

async fn run_probe(websocket: bool) {
    let Some(config_path) = std::env::var_os("FIPS_EXTERNAL_PROBE_CONFIG") else {
        return;
    };
    let directory = PathBuf::from(std::env::var_os("FIPS_EXTERNAL_PROBE_DIRECTORY").unwrap());
    let role = std::env::var("FIPS_EXTERNAL_PROBE_ROLE").unwrap();
    assert!(role == "a" || role == "b");
    let other = if role == "a" { "b" } else { "a" };
    let remote =
        PeerIdentity::from_npub(&std::env::var("FIPS_EXTERNAL_PROBE_REMOTE_NPUB").unwrap())
            .unwrap();
    let raw: serde_json::Value =
        serde_json::from_slice(&std::fs::read(config_path).unwrap()).unwrap();
    assert_eq!(raw["node"]["strict_client_only"], true);
    assert_eq!(raw["node"]["routing"]["mode"], "reply_learned");
    assert_eq!(raw["node"]["peer_admission"]["configured_only"], true);
    let config: Config = serde_json::from_value(raw).unwrap();
    assert!(
        !config.node.discovery.local.enabled
            && !config.node.discovery.lan.enabled
            && !config.node.discovery.nostr.enabled
            && !config.node.system_files_enabled
            && !config.node.control.enabled
    );
    assert_eq!(config.peers.len(), 1);
    assert_eq!(config.peers[0].addresses.len(), 1);
    let transport = if websocket { "websocket" } else { "udp" };
    assert_eq!(config.peers[0].addresses[0].transport, transport);
    if websocket {
        assert_eq!(
            config.transports.instance_counts().collect::<Vec<_>>(),
            vec![("websocket", 1)]
        );
        let fips_core::config::TransportInstances::Single(ws) = &config.transports.websocket else {
            panic!("one WebSocket transport required");
        };
        assert!(ws.bind_addr.is_none());
        assert_eq!(
            ws.tls_verification(),
            fips_core::config::WebSocketTlsVerification::WebPki
        );
        let address = &config.peers[0].addresses[0].addr;
        assert_eq!(ws.seed_urls, vec![address.clone()]);
        check_websocket_url(address);
    }
    assert_ne!(config.peers[0].npub, remote.npub());
    let seed = config.peers[0].npub.clone();
    let mut events = Events {
        file: OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(directory.join(format!("{role}.events.jsonl")))
            .unwrap(),
        started: Instant::now(),
        count: 0,
    };
    let endpoint = FipsEndpoint::builder()
        .config(config)
        .without_system_tun()
        .bind()
        .await
        .unwrap();
    let work =
        async {
            let receiver = endpoint.register_service_receiver(PORT).await?;
            let initial_peer = loop {
                let peers = endpoint.peers().await?;
                if let Some(peer) = peers.into_iter().find(|p| p.connected && p.npub == seed) {
                    if peer.transport_type.as_deref() != Some(transport) {
                        return Err("seed authenticated over an unexpected carrier".into());
                    }
                    break peer;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            };
            if !endpoint.routing_status().await?.client_only {
                return Err("strict role inactive".into());
            }
            events.record(
                "seed_authenticated",
                serde_json::json!({"strict_client":true,"seed_npub":initial_peer.npub,
                "transport":initial_peer.transport_type,"link_id":initial_peer.link_id}),
            )?;
            std::fs::write(directory.join(format!("{role}.ready")), endpoint.npub())?;
            wait_file(directory.join(format!("{other}.ready"))).await;
            for step in 0..4 {
                if step == 2 {
                    if role == "a" {
                        if websocket {
                            if !endpoint.bound_udp_listen_addrs().await?.is_empty() {
                                return Err("UDP carrier present in WebSocket-only probe".into());
                            }
                            if endpoint.rebind_network_transports(None).await? != 1 {
                                return Err("expected exactly one WebSocket carrier rebind".into());
                            }
                            let after = loop {
                                let peers = endpoint.peers().await?;
                                if let Some(peer) = peers.into_iter().find(|p| {
                                    p.connected
                                        && p.npub == seed
                                        && p.transport_type.as_deref() == Some("websocket")
                                        && p.link_id != initial_peer.link_id
                                }) {
                                    break peer;
                                }
                                tokio::time::sleep(Duration::from_millis(20)).await;
                            };
                            events.record("wss_reauthenticated", serde_json::json!({
                            "seed_npub":after.npub,"transport":after.transport_type,
                            "before_link_id":initial_peer.link_id,"after_link_id":after.link_id
                        }))?;
                        } else {
                            let before = endpoint.bound_udp_listen_addrs().await?;
                            if before.len() != 1 {
                                return Err("probe requires one observable UDP listener".into());
                            }
                            endpoint.rebind_network_transports(None).await?;
                            let after = endpoint.bound_udp_listen_addrs().await?;
                            if after.len() != 1 || before[0].port() == after[0].port() {
                                return Err("client UDP port did not change".into());
                            }
                            events.record(
                        "rebound",
                        serde_json::json!({"before":before[0].port(),"after":after[0].port()}),
                    )?;
                        }
                        std::fs::write(directory.join("a.rebound"), b"ready")?;
                    } else {
                        wait_file(directory.join("a.rebound")).await;
                    }
                }
                exchange(
                    &endpoint,
                    &receiver,
                    remote,
                    (step % 2 == 0) == (role == "a"),
                    step,
                    &mut events,
                )
                .await?;
                if !endpoint.routing_status().await?.client_only {
                    return Err("strict role changed".into());
                }
                if endpoint
                    .peers()
                    .await?
                    .iter()
                    .any(|p| p.connected && p.npub != seed)
                {
                    return Err("unconfigured direct or fallback adjacency".into());
                }
            }
            Ok::<(), Box<dyn std::error::Error + Send + Sync>>(())
        };
    let result = tokio::time::timeout(Duration::from_secs(90), work).await;
    let failure = match &result {
        Ok(Ok(())) => None,
        Ok(Err(e)) => Some(e.to_string()),
        Err(_) => Some("90-second probe deadline".into()),
    };
    events
        .record(
            "finished",
            serde_json::json!({"passed":failure.is_none(),"error":failure}),
        )
        .unwrap();
    let _ = tokio::time::timeout(Duration::from_secs(3), endpoint.shutdown()).await;
    assert!(
        failure.is_none(),
        "external strict probe failed: {failure:?}"
    );
}
