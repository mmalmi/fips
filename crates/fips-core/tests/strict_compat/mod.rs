use super::*;
use std::path::Path;
use std::process::{Child, Command, Stdio};

struct Router(Child);
impl Drop for Router {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn reserve_udp() -> std::net::SocketAddr {
    std::net::UdpSocket::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
}

async fn run_mixed(binary: &Path, reply_learned: bool) {
    let directory = tempfile::tempdir().unwrap();
    let nodes = endpoints(2, true, true, true).await;
    let identities = [Identity::generate(), Identity::generate()];
    let addresses = [reserve_udp(), reserve_udp()];
    assert_ne!(addresses[0], addresses[1]);
    let mut routers = Vec::new();
    for i in 0..2 {
        let mut config = Config::new();
        config.node.identity.nsec = Some(encode_nsec(&identities[i].keypair().secret_key()));
        config.node.system_files_enabled = false;
        config.node.control.enabled = false;
        config.node.discovery.local.enabled = false;
        config.node.discovery.lan.enabled = false;
        config.node.discovery.nostr.enabled = false;
        if reply_learned {
            config.node.routing.mode = fips_core::config::RoutingMode::ReplyLearned;
        }
        config.transports.udp = TransportInstances::Single(UdpConfig {
            bind_addr: Some(addresses[i].to_string()),
            ..Default::default()
        });
        config.peers = vec![PeerConfig::new(
            identities[1 - i].npub(),
            "udp",
            addresses[1 - i].to_string(),
        )];
        let path = directory.path().join(format!("router-{i}.json"));
        std::fs::write(&path, serde_json::to_vec(&config).unwrap()).unwrap();
        let log = std::fs::File::create(directory.path().join(format!("router-{i}.log"))).unwrap();
        routers.push(Router(
            Command::new(binary)
                .args(["--exact", "compat_router_process", "--nocapture"])
                .env("FIPS_COMPAT_ROUTER_CONFIG", path)
                .env(
                    "FIPS_COMPAT_ROUTER_READY",
                    directory.path().join(format!("ready-{i}")),
                )
                .env("FIPS_COMPAT_ROUTER_STOP", directory.path().join("stop"))
                .stdin(Stdio::null())
                .stdout(log.try_clone().unwrap())
                .stderr(log)
                .spawn()
                .unwrap(),
        ));
    }
    tokio::time::timeout(Duration::from_secs(8), async {
        loop {
            if (0..2).all(|i| directory.path().join(format!("ready-{i}")).exists()) {
                break;
            }
            assert!(
                routers
                    .iter_mut()
                    .all(|r| r.0.try_wait().unwrap().is_none())
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("compatibility routers ready");
    for i in 0..2 {
        nodes[i]
            .update_peers(vec![PeerConfig::new(
                identities[i].npub(),
                "udp",
                addresses[i].to_string(),
            )])
            .await
            .unwrap();
    }
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if nodes[0].peers().await.unwrap().iter().any(|p| p.connected)
                && nodes[1].peers().await.unwrap().iter().any(|p| p.connected)
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("authenticated endpoint uplinks");
    let first = delivered(&nodes[1], &nodes[0], b"mixed first inbound").await;
    let reply = if first {
        delivered(&nodes[0], &nodes[1], b"mixed first reply").await
    } else {
        false
    };
    assert_eq!(
        first, reply_learned,
        "first contact through legacy routing mode"
    );
    assert_eq!(
        reply, reply_learned,
        "return traffic through legacy routing mode"
    );
    assert!(nodes[0].routing_status().await.unwrap().client_only);
    if reply_learned {
        nodes[0].rebind_network_transports(None).await.unwrap();
        assert!(delivered(&nodes[0], &nodes[1], b"mixed after rebind").await);
        assert!(delivered(&nodes[1], &nodes[0], b"mixed reverse after rebind").await);
    }
    for node in nodes {
        node.shutdown().await.unwrap();
    }
    std::fs::write(directory.path().join("stop"), b"stop").unwrap();
    for mut router in routers {
        assert!(router.0.wait().unwrap().success());
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires the separately hashed .117 compatibility router executable"]
async fn strict_client_mixed_117_reply_learned_and_tree_controls() {
    let binary = std::env::var_os("FIPS_COMPAT_ROUTER_BIN").expect("published .117 router fixture");
    run_mixed(Path::new(&binary), true).await;
    run_mixed(Path::new(&binary), false).await;
}
