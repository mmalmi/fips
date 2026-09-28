//! Run privileged cases in a disposable Linux network namespace, never on a live gateway.
#![cfg(all(target_os = "linux", not(target_env = "musl")))]

use std::io;
use std::net::UdpSocket;
use std::process::{Child, Command};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::time::{Duration, Instant};

struct Gateway(Child);
impl Drop for Gateway {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn wait_until(mut ready: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while !ready() {
        assert!(
            Instant::now() < deadline,
            "gateway did not converge within 10 seconds"
        );
        std::thread::sleep(Duration::from_millis(50));
    }
}

#[test]
fn occupied_dns_port_exits_before_network_setup() {
    let listener = UdpSocket::bind("[::1]:0").unwrap();
    let temp = tempfile::tempdir().unwrap();
    let config = temp.path().join("fips.yaml");
    std::fs::write(&config, format!("gateway:\n  enabled: true\n  pool: fd01::/112\n  lan_interface: absent\n  dns:\n    listen: '{}'\n", listener.local_addr().unwrap())).unwrap();
    let log = std::fs::File::create(temp.path().join("gateway.log")).unwrap();
    let mut gateway = Gateway(
        Command::new(env!("CARGO_BIN_EXE_fips-gateway"))
            .arg("--config")
            .arg(config)
            .stdout(log.try_clone().unwrap())
            .stderr(log)
            .spawn()
            .unwrap(),
    );
    let mut exit = None;
    wait_until(|| {
        exit = gateway.0.try_wait().unwrap();
        exit.is_some()
    });
    assert_eq!(exit.unwrap().code(), Some(1));
    let log = std::fs::read_to_string(temp.path().join("gateway.log")).unwrap();
    assert!(
        log.contains("cannot bind the gateway DNS listener"),
        "{log}"
    );
    assert!(
        !log.contains("IPv6 forwarding is disabled"),
        "DNS must fail before network setup: {log}"
    );
}

struct Upstream {
    address: std::net::SocketAddr,
    stop: Arc<AtomicBool>,
    worker: Option<std::thread::JoinHandle<()>>,
}
impl Upstream {
    fn start() -> Self {
        let socket = UdpSocket::bind("[::1]:0").unwrap();
        socket
            .set_read_timeout(Some(Duration::from_millis(100)))
            .unwrap();
        let address = socket.local_addr().unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let flag = stop.clone();
        let worker = std::thread::spawn(move || {
            let mut query = [0; 4096];
            while !flag.load(Ordering::Relaxed) {
                let (len, client) = match socket.recv_from(&mut query) {
                    Ok(value) => value,
                    Err(e)
                        if matches!(
                            e.kind(),
                            io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                        ) =>
                    {
                        continue;
                    }
                    Err(e) => panic!("upstream receive: {e}"),
                };
                let mut reply = query[..len].to_vec();
                reply[2..4].copy_from_slice(&0x8180u16.to_be_bytes());
                reply[6..8].copy_from_slice(&1u16.to_be_bytes());
                reply.extend_from_slice(&[0xc0, 0x0c, 0, 28, 0, 1, 0, 0, 0, 60, 0, 16]);
                reply
                    .extend_from_slice(&"fd02::12".parse::<std::net::Ipv6Addr>().unwrap().octets());
                socket.send_to(&reply, client).unwrap();
            }
        });
        Self {
            address,
            stop,
            worker: Some(worker),
        }
    }
}
impl Drop for Upstream {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        let _ = self.worker.take().unwrap().join();
    }
}

struct Interface;
impl Drop for Interface {
    fn drop(&mut self) {
        let _ = Command::new("ip").args(["link", "del", "fips0"]).status();
    }
}

fn rule_count() -> Option<usize> {
    let output = Command::new("nft")
        .args(["-j", "list", "table", "inet", "fips_gateway"])
        .output()
        .unwrap();
    if !output.status.success() {
        return None;
    }
    let table: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    Some(
        table["nftables"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|row| row.get("rule").is_some())
            .count(),
    )
}

#[test]
#[ignore = "requires isolated Linux namespace, CAP_NET_ADMIN, IPv6 forwarding=1, ip and nft"]
fn kernel_gateway_serves_dns_installs_nat_and_cleans_up() {
    assert!(
        !Command::new("ip")
            .args(["link", "show", "fips0"])
            .output()
            .unwrap()
            .status
            .success(),
        "run only in an isolated namespace without fips0"
    );
    assert_eq!(
        rule_count(),
        None,
        "run only in an isolated namespace without a gateway table"
    );
    assert_eq!(
        std::fs::read_to_string("/proc/sys/net/ipv6/conf/all/forwarding")
            .unwrap()
            .trim(),
        "1"
    );
    assert!(
        Command::new("ip")
            .args(["link", "add", "fips0", "type", "dummy"])
            .status()
            .unwrap()
            .success()
    );
    let _interface = Interface;
    assert!(
        Command::new("ip")
            .args(["link", "set", "fips0", "up"])
            .status()
            .unwrap()
            .success()
    );
    let upstream = Upstream::start();
    let port = UdpSocket::bind("[::1]:0").unwrap().local_addr().unwrap();
    let temp = tempfile::tempdir().unwrap();
    let config = temp.path().join("fips.yaml");
    std::fs::write(&config, format!("gateway:\n  enabled: true\n  pool: fd01::/112\n  lan_interface: lo\n  dns:\n    listen: '{port}'\n    upstream: '{}'\n", upstream.address)).unwrap();
    let log = std::fs::File::create(temp.path().join("gateway.log")).unwrap();
    let mut gateway = Gateway(
        Command::new(env!("CARGO_BIN_EXE_fips-gateway"))
            .arg("--config")
            .arg(config)
            .stdout(log.try_clone().unwrap())
            .stderr(log)
            .spawn()
            .unwrap(),
    );
    wait_until(|| {
        assert!(
            gateway.0.try_wait().unwrap().is_none(),
            "{}",
            std::fs::read_to_string(temp.path().join("gateway.log")).unwrap()
        );
        rule_count() == Some(1)
    });
    let client = UdpSocket::bind("[::1]:0").unwrap();
    client
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    for (qtype, answers) in [(1u16, 0u8), (28, 1)] {
        let mut query = vec![
            0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 4, b'p', b'e', b'e', b'r', 4, b'f', b'i',
            b'p', b's', 0,
        ];
        query.extend_from_slice(&qtype.to_be_bytes());
        query.extend_from_slice(&1u16.to_be_bytes());
        client.send_to(&query, port).unwrap();
        let mut buf = [0; 4096];
        let (len, source) = client.recv_from(&mut buf).unwrap();
        assert_eq!(source, port);
        assert_eq!(&buf[..2], &[0x12, 0x34]);
        assert_eq!(buf[3] & 15, 0);
        assert_eq!(buf[7], answers);
        if answers == 0 {
            assert_eq!(rule_count(), Some(1));
        } else {
            assert_eq!(
                &buf[len - 16..len],
                &"fd01::1".parse::<std::net::Ipv6Addr>().unwrap().octets()
            );
            wait_until(|| rule_count() == Some(3));
        }
    }
    assert!(
        Command::new("kill")
            .args(["-TERM", &gateway.0.id().to_string()])
            .status()
            .unwrap()
            .success()
    );
    let mut exit = None;
    wait_until(|| {
        exit = gateway.0.try_wait().unwrap();
        exit.is_some()
    });
    let log = std::fs::read_to_string(temp.path().join("gateway.log")).unwrap();
    assert!(exit.unwrap().success(), "{log}");
    assert!(log.contains("shutdown complete"), "{log}");
    assert_eq!(rule_count(), None);
    let routes = Command::new("ip")
        .args(["-6", "route", "show", "table", "local", "fd01::/112"])
        .output()
        .unwrap();
    assert!(routes.stdout.is_empty());
}
