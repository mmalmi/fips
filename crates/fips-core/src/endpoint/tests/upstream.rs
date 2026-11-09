//! Opt-in interoperability with an unmodified, revision-pinned upstream daemon.
use super::*;
use std::{
    fs::File,
    path::PathBuf,
    process::{Child, Command, Stdio},
};

struct Process(Child);

impl Drop for Process {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[tokio::test]
#[ignore = "requires FIPS_UPSTREAM_BIN, FIPS_UPSTREAM_ECHO and FIPS_INTEROP_LOG_DIR"]
async fn upstream_udp_service_round_trip() {
    run_interop(false, false, false).await;
}

#[tokio::test]
#[ignore = "requires pinned upstream daemon, echo, client and retained logs"]
async fn upstream_initiates_and_rekeys_with_multipath_enabled() {
    run_interop(true, true, false).await;
}

#[tokio::test]
#[ignore = "requires pinned upstream daemon, echo and retained logs"]
async fn upstream_routes_service_datagrams_and_rekey() {
    run_interop(false, false, true).await;
}

async fn run_interop(upstream_initiates: bool, multipath: bool, routed: bool) {
    let daemon_path = std::env::var_os("FIPS_UPSTREAM_BIN").expect("upstream daemon path");
    let echo = std::env::var_os("FIPS_UPSTREAM_ECHO").expect("upstream native echo path");
    let logs =
        PathBuf::from(std::env::var_os("FIPS_INTEROP_LOG_DIR").expect("retained log directory"))
            .join(if routed {
                "upstream-transit"
            } else if upstream_initiates {
                "upstream-initiates"
            } else {
                "fork-initiates"
            });
    std::fs::create_dir_all(&logs).unwrap();
    let directory = tempfile::tempdir().unwrap();
    let api = directory.path().join("api.sock");
    let control = directory.path().join("control.sock");
    let identity = crate::Identity::from_secret_str(&"21".repeat(32)).unwrap();
    let peer = PeerIdentity::from_pubkey_full(identity.pubkey_full());
    let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let address = socket.local_addr().unwrap();
    drop(socket);
    let config_path = directory.path().join("upstream.yaml");
    let upstream_trigger = if upstream_initiates { 16 } else { 65536 };
    let fork_trigger = if upstream_initiates { 65536 } else { 16 };
    std::fs::write(&config_path, format!(
        "node:\n  rekey:\n    after_messages: {upstream_trigger}\n  path:\n    enabled: {multipath}\n  identity:\n    nsec: '{}'\n  control:\n    socket_path: '{}'\n  native_api:\n    enabled: true\n    socket_path: '{}'\n  rendezvous:\n    nostr:\n      enabled: false\n    lan:\n      enabled: false\ntun:\n  enabled: false\ndns:\n  enabled: false\ntransports:\n  udp:\n    bind_addr: '{}'\n    mtu: 1472\n",
        "21".repeat(32), control.display(), api.display(), address,
    )).unwrap();
    let log = File::create(logs.join("upstream-daemon.log")).unwrap();
    let mut daemon = Process(
        Command::new(&daemon_path)
            .arg("--config")
            .arg(&config_path)
            .env("RUST_LOG", "debug")
            .stdin(Stdio::null())
            .stdout(log.try_clone().unwrap())
            .stderr(log)
            .spawn()
            .unwrap(),
    );
    tokio::time::timeout(Duration::from_secs(15), async {
        while !api.exists() {
            assert!(
                daemon.0.try_wait().unwrap().is_none(),
                "upstream daemon exited; inspect retained log"
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("upstream API startup");
    let echo_log_path = logs.join("upstream-echo.log");
    let log = File::create(&echo_log_path).unwrap();
    let mut echo = Process(
        Command::new(echo)
            .arg(&api)
            .arg("4600")
            .stdin(Stdio::null())
            .stdout(log.try_clone().unwrap())
            .stderr(log)
            .spawn()
            .unwrap(),
    );
    tokio::time::timeout(Duration::from_secs(5), async {
        while !std::fs::read_to_string(&echo_log_path)
            .unwrap()
            .contains("holding port 4600")
        {
            assert!(
                echo.0.try_wait().unwrap().is_none(),
                "upstream echo exited; inspect retained log"
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("upstream service startup");
    let mut router = None;
    let (neighbor_npub, neighbor_address) = if routed {
        let router_identity = crate::Identity::from_secret_str(&"22".repeat(32)).unwrap();
        let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let router_address = socket.local_addr().unwrap();
        drop(socket);
        let router_api = directory.path().join("router-api.sock");
        let router_control = directory.path().join("router-control.sock");
        let router_config = directory.path().join("router.yaml");
        std::fs::write(&router_config, format!(
            "node:\n  identity:\n    nsec: '{}'\n  control:\n    socket_path: '{}'\n  native_api:\n    enabled: true\n    socket_path: '{}'\n  rendezvous:\n    nostr:\n      enabled: false\n    lan:\n      enabled: false\ntun:\n  enabled: false\ndns:\n  enabled: false\ntransports:\n  udp:\n    bind_addr: '{}'\n    mtu: 1472\npeers:\n  - npub: '{}'\n    addresses:\n      - transport: udp\n        addr: '{}'\n",
            "22".repeat(32), router_control.display(), router_api.display(),
            router_address, identity.npub(), address,
        )).unwrap();
        let log = File::create(logs.join("upstream-router.log")).unwrap();
        router = Some(Process(
            Command::new(&daemon_path)
                .arg("--config")
                .arg(&router_config)
                .env("RUST_LOG", "debug")
                .stdin(Stdio::null())
                .stdout(log.try_clone().unwrap())
                .stderr(log)
                .spawn()
                .unwrap(),
        ));
        tokio::time::timeout(Duration::from_secs(15), async {
            while !router_api.exists() {
                assert!(
                    router.as_mut().unwrap().0.try_wait().unwrap().is_none(),
                    "upstream transit router exited; inspect retained log"
                );
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("upstream transit router startup");
        (router_identity.npub(), router_address)
    } else {
        (identity.npub(), address)
    };
    let config: Config = serde_yaml::from_str(&format!(
        "node:\n  rekey:\n    after_messages: {fork_trigger}\n  identity:\n    nsec: '{}'\n  discovery:\n    nostr:\n      enabled: false\n    local:\n      enabled: false\ntransports:\n  udp:\n    bind_addr: '127.0.0.1:0'\n    mtu: 1472\npeers:\n  - npub: '{}'\n    addresses:\n      - transport: udp\n        addr: '{}'\n",
        "31".repeat(32), neighbor_npub, neighbor_address,
    )).unwrap();
    let endpoint = FipsEndpoint::builder()
        .config(config)
        .without_system_tun()
        .bind()
        .await
        .unwrap();
    endpoint.register_service(4601).await.unwrap();
    tokio::time::timeout(Duration::from_secs(10), async {
        while !endpoint
            .peers()
            .await
            .unwrap()
            .iter()
            .any(|p| p.npub == neighbor_npub && p.connected)
        {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("mixed-peer link handshake");
    let mut client = if upstream_initiates {
        let client =
            std::env::var_os("FIPS_UPSTREAM_CLIENT").expect("upstream client fixture path");
        let log = File::create(logs.join("upstream-client.log")).unwrap();
        Some(Process(
            Command::new(client)
                .arg(&api)
                .arg(endpoint.npub())
                .stdin(Stdio::null())
                .stdout(log.try_clone().unwrap())
                .stderr(log)
                .spawn()
                .unwrap(),
        ))
    } else {
        None
    };
    for sequence in 0u16..64 {
        let payload = format!("upstream-compatible service datagram {sequence}").into_bytes();
        if !upstream_initiates {
            endpoint
                .send_datagram(peer, 4601, 4600, payload.clone())
                .await
                .unwrap();
        }
        let mut received = Vec::new();
        tokio::time::timeout(
            Duration::from_secs(12),
            endpoint.recv_service_datagram_batch_into(&mut received, 1),
        )
        .await
        .expect("mixed-peer session/service timed out; inspect retained logs")
        .unwrap();
        assert_eq!(received.len(), 1);
        assert_eq!(received[0].data.as_slice(), payload);
        assert_eq!(received[0].source_peer, peer);
        if upstream_initiates {
            endpoint
                .send_datagram(peer, 4601, received[0].source_port, payload)
                .await
                .unwrap();
        } else {
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }
    if let Some(client) = client.as_mut() {
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                if let Some(status) = client.0.try_wait().unwrap() {
                    assert!(
                        status.success(),
                        "upstream client failed; inspect retained log"
                    );
                    break;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("upstream client completion");
    }
    let upstream_log = std::fs::read_to_string(logs.join("upstream-daemon.log")).unwrap();
    let expected = if upstream_initiates {
        "FSP rekey cutover complete (initiator)"
    } else {
        "FSP rekey cutover complete (responder)"
    };
    assert!(
        upstream_log.contains(expected),
        "no completed session rekey: {expected}"
    );
    if routed {
        assert!(
            !endpoint
                .peers()
                .await
                .unwrap()
                .iter()
                .any(|p| p.npub == identity.npub() && p.connected),
            "the tested endpoint must remain behind the upstream transit router"
        );
    }
    endpoint.shutdown().await.unwrap();
    drop(router);
}
