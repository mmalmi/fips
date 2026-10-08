//! Real packet sockets in a disposable network namespace, with counted loss.
use fips_core::config::{EthernetConfig, TransportInstances};
use fips_relay::{
    control_transport::NeighborAdmission,
    service::{AdminRequest, ServiceConfig, native_request, request},
};
use serde_json::{Value, json};
use std::{collections::BTreeSet, io::Write, process::Command, sync::Mutex, time::Duration};

pub(super) struct EthernetNetwork {
    pairs: Vec<(String, String)>,
    bridge: String,
    topology: String,
    tables: [String; 2],
    enabled: Mutex<bool>,
}

impl EthernetNetwork {
    pub fn new() -> Self {
        assert_ne!(
            std::fs::read_link("/proc/self/ns/net").unwrap(),
            std::fs::read_link("/proc/1/ns/net").unwrap(),
            "Ethernet qualification requires an isolated network namespace"
        );
        let links: Vec<Value> = serde_json::from_slice(&command("ip", &["-j", "link"])).unwrap();
        assert_eq!(links.len(), 1, "namespace must contain only loopback");
        assert_eq!(links[0]["ifname"], "lo");
        let id = std::process::id();
        let mut network = Self {
            pairs: Vec::new(),
            bridge: format!("fb{id}"),
            topology: format!("fips_topology_{id}"),
            tables: [format!("fips_loss_{id}_0"), format!("fips_loss_{id}_2")],
            enabled: Mutex::new(false),
        };
        command("ip", &["link", "add", &network.bridge, "type", "bridge"]);
        for suffix in ["a", "b"] {
            let endpoint = format!("fe{id}{suffix}");
            let middle = format!("fm{id}{suffix}");
            network.pairs.push((endpoint.clone(), middle.clone()));
            command(
                "ip",
                &[
                    "link", "add", &endpoint, "type", "veth", "peer", "name", &middle,
                ],
            );
            command("ip", &["link", "set", &middle, "master", &network.bridge]);
            for name in [&endpoint, &middle] {
                command("ip", &["link", "set", name, "up"]);
            }
        }
        command("ip", &["link", "set", &network.bridge, "up"]);
        network
    }

    pub async fn discover_triangle(&self, configs: &[ServiceConfig], npubs: &[String]) {
        let states = wait_topology(configs, npubs, false, 60).await;
        for state in states {
            assert_eq!(state["funding_budget"]["wallet_debited_sat"], 0);
            assert_eq!(state["funding_budget"]["locked_sat"], 0);
            assert_eq!(state["purchases"], json!([]));
            assert_eq!(state["watched_routes"], json!([]));
        }
        eprintln!("sustained Ethernet topology: authenticated triangle with default beacon timing");
    }

    pub async fn form_line(&self, configs: &[ServiceConfig], npubs: &[String]) {
        // Match the physical fixture: let all peers authenticate before cutting
        // only the test EtherType's leaf shortcut on the shared medium.
        let table = &self.topology;
        let mut rules = format!("create table netdev {table}\n");
        for (direction, (endpoint, _)) in self.pairs.iter().enumerate() {
            let other = mac(&self.pairs[1 - direction].0);
            rules.push_str(&format!(
                "add chain netdev {table} ingress{direction} {{ type filter hook ingress device \"{endpoint}\" priority -510; policy accept; }}\n\
                 add rule netdev {table} ingress{direction} ether type 0x88b5 ether saddr {other} counter drop\n"
            ));
        }
        nft(&rules);
        wait_topology(configs, npubs, true, 100).await;
        eprintln!("sustained Ethernet topology: shortcut peers removed; discovered line ready");
    }

    pub fn configure(&self, node: usize, config: &mut ServiceConfig) {
        let interfaces = match node {
            0 => vec![&self.pairs[0].0],
            1 => vec![&self.bridge],
            2 => vec![&self.pairs[1].0],
            _ => unreachable!(),
        };
        config.transports = Default::default();
        config.transports.ethernet = TransportInstances::Named(
            interfaces
                .into_iter()
                .map(|name| {
                    (
                        name.clone(),
                        EthernetConfig {
                            interface: name.clone(),
                            ethertype: Some(0x88b5),
                            discovery: Some(true),
                            announce: Some(true),
                            auto_connect: Some(true),
                            accept_connections: Some(true),
                            ..Default::default()
                        },
                    )
                })
                .collect(),
        );
        config.neighbors.clear();
        config.neighbor_admission = NeighborAdmission::AuthenticatedAdjacent;
    }

    pub fn enable(&self, enabled: bool) {
        let mut previous = self.enabled.lock().unwrap();
        if enabled == *previous {
            return;
        }
        let mut rules = String::new();
        for (direction, table) in self.tables.iter().enumerate() {
            if enabled {
                let (endpoint, _) = &self.pairs[direction];
                let mac = mac(&self.bridge);
                // Match the physical-router rule: the first selected frame and
                // every twentieth frame thereafter are dropped, including control.
                rules.push_str(&format!(
                    "create table netdev {table}\n\
                     add chain netdev {table} ingress {{ type filter hook ingress device \"{endpoint}\" priority -500; policy accept; }}\n\
                     add chain netdev {table} loss\n\
                     add counter netdev {table} seen\n\
                     add counter netdev {table} dropped\n\
                     add rule netdev {table} ingress ether type 0x88b5 ether saddr {mac} counter name seen jump loss\n\
                     add rule netdev {table} loss numgen inc mod 20 0 counter name dropped drop\n"
                ));
            } else {
                rules.push_str(&format!("flush chain netdev {table} ingress\n"));
            }
        }
        nft(&rules);
        *previous = enabled;
    }

    pub fn counts(&self) -> [(u64, u64); 2] {
        self.tables.each_ref().map(|table| {
            let value: Value =
                serde_json::from_slice(&command("nft", &["-j", "list", "table", "netdev", table]))
                    .unwrap();
            let count = |name| {
                let counters: Vec<_> = value["nftables"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .filter_map(|entry| entry.get("counter"))
                    .filter(|counter| counter["name"] == name)
                    .collect();
                assert_eq!(counters.len(), 1);
                counters[0]["packets"].as_u64().unwrap()
            };
            (count("seen"), count("dropped"))
        })
    }
}

async fn wait_topology(
    configs: &[ServiceConfig],
    npubs: &[String],
    line: bool,
    seconds: u64,
) -> Vec<Value> {
    tokio::time::timeout(Duration::from_secs(seconds), async {
        loop {
            let mut ready = Vec::new();
            for (node, config) in configs.iter().enumerate() {
                let Ok(state) = request(config, &AdminRequest::Status).await else {
                    continue;
                };
                let peers = state["peers"].as_array().unwrap();
                let expected: BTreeSet<_> = npubs
                    .iter()
                    .enumerate()
                    .filter(|(other, _)| *other != node && (!line || node.abs_diff(*other) == 1))
                    .map(|(_, npub)| npub.as_str())
                    .collect();
                let connected: BTreeSet<_> = peers
                    .iter()
                    .filter(|p| p["connected"] == true && p["transport"] == "ethernet")
                    .map(|p| p["npub"].as_str().unwrap())
                    .collect();
                // A stale direct peer can still affect route lookup. Require
                // actual removal, as the physical fixture does.
                if connected != expected || peers.len() != expected.len() {
                    continue;
                }
                if !line {
                    let report = native_request(config, &json!({"command":"show_transports"}))
                        .await
                        .unwrap();
                    let stats = &report["data"]["transports"][0]["stats"];
                    if stats["beacons_sent"].as_u64().unwrap() == 0
                        || stats["beacons_recv"].as_u64().unwrap() == 0
                    {
                        continue;
                    }
                }
                ready.push(state);
            }
            if ready.len() == configs.len() {
                return ready;
            }
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
    })
    .await
    .expect("authenticated Ethernet topology should converge")
}

impl Drop for EthernetNetwork {
    fn drop(&mut self) {
        // Only generated resources inside the initially empty namespace belong
        // to this fixture. Namespace exit also removes them after a failed test.
        for table in self.tables.iter().chain(std::iter::once(&self.topology)) {
            let _ = Command::new("nft")
                .args(["delete", "table", "netdev", table])
                .output();
        }
        for (endpoint, _) in &self.pairs {
            let _ = Command::new("ip")
                .args(["link", "delete", endpoint])
                .output();
        }
        let _ = Command::new("ip")
            .args(["link", "delete", &self.bridge])
            .output();
    }
}

fn mac(interface: &str) -> String {
    let links: Vec<Value> =
        serde_json::from_slice(&command("ip", &["-j", "link", "show", interface])).unwrap();
    links[0]["address"].as_str().unwrap().to_owned()
}

fn nft(rules: &str) {
    let mut child = Command::new("nft")
        .args(["-f", "-"])
        .stdin(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(rules.as_bytes())
        .unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

fn command(program: &str, args: &[&str]) -> Vec<u8> {
    let output = Command::new(program).args(args).output().unwrap();
    assert!(
        output.status.success(),
        "{program} {args:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    output.stdout
}
