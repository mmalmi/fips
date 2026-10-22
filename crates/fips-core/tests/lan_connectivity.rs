//! Opt-in multicast discovery plus authenticated data in separate processes.
//! The child can also run on two platforms sharing a test coordination directory;
//! only public identities/readiness cross that directory, never peer addresses.
use fips_core::config::{NostrDiscoveryPolicy, RoutingMode, TransportInstances};
use fips_core::{Config, FipsEndpoint, PeerIdentity, UdpConfig};
use std::{path::Path, process::Command, time::Duration};

// The probe runs in its own process, so optional diagnostics need no global
// logging configuration or extra dependency in the library.
struct ProbeTrace;
impl tracing::Subscriber for ProbeTrace {
    fn enabled(&self, metadata: &tracing::Metadata<'_>) -> bool {
        metadata.target().starts_with("fips_core") && *metadata.level() <= tracing::Level::DEBUG
    }
    fn new_span(&self, _: &tracing::span::Attributes<'_>) -> tracing::span::Id {
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
        tracing::span::Id::from_u64(NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed))
    }
    fn record(&self, _: &tracing::span::Id, _: &tracing::span::Record<'_>) {}
    fn record_follows_from(&self, _: &tracing::span::Id, _: &tracing::span::Id) {}
    fn event(&self, event: &tracing::Event<'_>) {
        use std::{fmt::Write as _, io::Write as _};
        struct Fields(String);
        impl tracing::field::Visit for Fields {
            fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
                let _ = write!(self.0, " {}={value:?}", field.name());
            }
        }
        let mut fields = Fields(format!(
            "pid={} {}",
            std::process::id(),
            event.metadata().target()
        ));
        event.record(&mut fields);
        fields.0.push('\n');
        let _ = std::io::stderr().lock().write_all(fields.0.as_bytes());
    }
    fn enter(&self, _: &tracing::span::Id) {}
    fn exit(&self, _: &tracing::span::Id) {}
}

async fn wait_file(path: &Path) -> String {
    loop {
        if let Ok(value) = std::fs::read_to_string(path)
            && !value.is_empty()
        {
            return value;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires a paired process and multicast-capable test network"]
async fn lan_peer_child() {
    if std::env::var_os("FIPS_LAN_PROBE_TRACE").is_some() {
        tracing::subscriber::set_global_default(ProbeTrace).unwrap();
    }
    let root = std::path::PathBuf::from(std::env::var_os("FIPS_LAN_PROBE_DIR").unwrap());
    let side = std::env::var("FIPS_LAN_PROBE_SIDE").unwrap();
    assert!(matches!(side.as_str(), "a" | "b"));
    let other = if side == "a" { "b" } else { "a" };
    let scope = std::env::var("FIPS_LAN_PROBE_SCOPE").unwrap();
    let mut config = Config::new();
    config.node.control.enabled = false;
    config.node.discovery.local.enabled = false;
    config.node.discovery.nostr.enabled = false;
    config.node.discovery.nostr.policy = NostrDiscoveryPolicy::Open;
    config.node.discovery.lan.enabled = true;
    config.node.discovery.lan.scope = Some(scope);
    config.node.discovery.lan.service_type = "_ft-proof._udp.local.".into();
    config.node.routing.mode = RoutingMode::ReplyLearned;
    config.transports.udp = TransportInstances::Single(UdpConfig {
        bind_addr: Some("0.0.0.0:0".into()),
        advertise_on_nostr: Some(false),
        public: Some(false),
        accept_connections: Some(true),
        ..UdpConfig::default()
    });
    assert!(config.peers.is_empty());
    let endpoint = FipsEndpoint::builder()
        .config(config)
        .without_system_tun()
        .bind()
        .await
        .unwrap();
    std::fs::write(root.join(format!("{side}.npub")), endpoint.npub()).unwrap();
    let result = tokio::time::timeout(Duration::from_secs(90), async {
        let expected = wait_file(&root.join(format!("{other}.npub"))).await;
        loop {
            if let Some(peer) = endpoint
                .peers()
                .await
                .unwrap()
                .into_iter()
                .find(|peer| peer.npub == expected && peer.connected)
            {
                println!(
                    "{side}: authenticated {} over {:?}",
                    expected, peer.transport_addr
                );
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        std::fs::write(root.join(format!("{side}.ready")), "ready").unwrap();
        wait_file(&root.join(format!("{other}.ready"))).await;
        println!(
            "{side}: sending payload; routing {:?}",
            endpoint.routing_status().await.unwrap()
        );
        endpoint
            .send_batch_to_peer(
                PeerIdentity::from_npub(&expected).unwrap(),
                vec![format!("FIPS LAN from {side}").into_bytes()],
            )
            .await
            .unwrap();
        let mut received = Vec::new();
        endpoint.recv_batch_into(&mut received, 1).await.unwrap();
        println!("{side}: received {} payload(s)", received.len());
        assert_eq!(received.len(), 1);
        assert_eq!(received[0].source_peer.npub(), expected);
        assert_eq!(
            received[0].data.as_slice(),
            format!("FIPS LAN from {other}").as_bytes()
        );
        std::fs::write(root.join(format!("{side}.done")), "verified").unwrap();
        wait_file(&root.join(format!("{other}.done"))).await;
        println!("{side}: verified bidirectional authenticated LAN payload");
    })
    .await;
    if result.is_err() {
        eprintln!(
            "{side}: timeout peers {:?}, routing {:?}",
            endpoint.peers().await,
            endpoint.routing_status().await
        );
    }
    endpoint.shutdown().await.unwrap();
    result.expect("LAN discovery, handshake and data must complete within 90 seconds");
}

#[test]
#[ignore = "requires multicast; run explicitly on each supported native platform"]
fn separate_processes_discover_authenticate_and_exchange_data() {
    let directory = tempfile::tempdir().unwrap();
    let scope = format!("fips-lan-proof-{:016x}", rand::random::<u64>());
    let spawn = |side| {
        Command::new(std::env::current_exe().unwrap())
            .args(["--ignored", "--exact", "lan_peer_child", "--nocapture"])
            .env("FIPS_LAN_PROBE_DIR", directory.path())
            .env("FIPS_LAN_PROBE_SIDE", side)
            .env("FIPS_LAN_PROBE_SCOPE", &scope)
            .spawn()
            .unwrap()
    };
    let mut first = spawn("a");
    let mut second = spawn("b");
    let first_status = first.wait().unwrap();
    let second_status = second.wait().unwrap();
    assert!(first_status.success() && second_status.success());
}
