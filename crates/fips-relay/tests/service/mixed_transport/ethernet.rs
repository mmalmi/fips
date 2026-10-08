//! Real packet sockets in a disposable network namespace, with counted loss.
use fips_core::config::{EthernetConfig, TransportInstances};
use fips_relay::{control_transport::NeighborAdmission, service::ServiceConfig};
use serde_json::Value;
use std::{io::Write, process::Command, sync::Mutex};

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
        // All nodes share one Ethernet medium, as on the radio triangle. Only
        // the test EtherType's leaf-to-leaf shortcut is excluded; each relay
        // uses one packet socket and the middle forwards over that same socket.
        let table = &network.topology;
        let mut rules = format!("create table netdev {table}\n");
        for (direction, (endpoint, _)) in network.pairs.iter().enumerate() {
            let other = mac(&network.pairs[1 - direction].0);
            rules.push_str(&format!(
                "add chain netdev {table} ingress{direction} {{ type filter hook ingress device \"{endpoint}\" priority -510; policy accept; }}\n\
                 add rule netdev {table} ingress{direction} ether type 0x88b5 ether saddr {other} counter drop\n"
            ));
        }
        nft(&rules);
        network
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
                            beacon_interval_secs: Some(1),
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
