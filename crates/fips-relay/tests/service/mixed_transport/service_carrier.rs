//! The optional carrier field crosses the real daemon's private status path.
use super::*;

pub(super) async fn assert_status(bench: &MixedBench, active: bool) {
    for (node, status) in bench.states().await.into_iter().enumerate() {
        let data = status
            .get("data_carrier")
            .expect("explicit data availability");
        if cfg!(feature = "measurements") {
            assert_eq!(data["service_port"], 44_740);
            assert_eq!(data["ambiguous_port_datagrams"], 0);
            assert_eq!(data["discarded_outputs"], 0);
            let transports = data["transports"].as_array().unwrap();
            assert_eq!(transports.len(), 9);
            for transport in transports {
                let kind = transport["transport"].as_str().unwrap();
                let packets = transport["submitted_packets"].as_u64().unwrap();
                let bytes = transport["fips_payload_bytes"].as_u64().unwrap();
                assert_eq!(transport["ethernet_framing_bytes"], 0);
                if active
                    && ((node == 0 && kind == "udp")
                        || (node == 2 && kind == bench.second_hop_kind()))
                {
                    assert!(
                        packets > 0 && bytes > 0,
                        "originating data reaches its carrier"
                    );
                } else {
                    assert_eq!((packets, bytes), (0, 0), "opaque transit is not local data");
                }
            }
        } else {
            assert!(data.is_null(), "unavailable is not measured zero");
        }
        let entries = status["control_traffic"].as_array().unwrap();
        assert_eq!(entries.len(), 3);
        for (index, entry) in entries.iter().enumerate() {
            let port = 44_741 + index as u64;
            assert_eq!(entry["service_port"], port);
            let application = entry["counters"].as_object().unwrap();
            assert_eq!(
                application.len(),
                4,
                "application counters keep their meaning"
            );
            for field in [
                "stream_bytes_sent",
                "stream_bytes_received",
                "requests_started",
                "requests_received",
            ] {
                assert!(application[field].as_u64().is_some());
            }
            let carrier = entry.get("service_carrier").expect("explicit availability");
            if !cfg!(feature = "measurements") || port != 44_743 {
                assert!(carrier.is_null(), "unavailable is not measured zero");
                continue;
            }
            assert_eq!(carrier["service_port"], port);
            assert_eq!(carrier["ambiguous_port_datagrams"], 0);
            assert_eq!(carrier["discarded_outputs"], 0);
            let transports = carrier["transports"].as_array().unwrap();
            assert_eq!(transports.len(), 9);
            for transport in transports {
                let kind = transport["transport"].as_str().unwrap();
                let packets = transport["submitted_packets"].as_u64().unwrap();
                let bytes = transport["fips_payload_bytes"].as_u64().unwrap();
                assert_eq!(transport["ethernet_framing_bytes"], 0);
                let possible = match node {
                    0 => kind == "udp",
                    1 => kind == "udp" || kind == bench.second_hop_kind(),
                    2 => kind == bench.second_hop_kind(),
                    _ => unreachable!(),
                };
                if !possible {
                    assert_eq!((packets, bytes), (0, 0));
                } else if active {
                    assert!(
                        packets > 0 && bytes > 0,
                        "each funded endpoint and both middle-router carriers submit measured segments"
                    );
                }
            }
        }
    }
}

impl MixedBench {
    pub async fn assert_carriers(&self) {
        if self.seed_carrier().is_some() {
            let report = fips_relay::service::native_request(
                &self.configs[2],
                &serde_json::json!({"command": "show_transports"}),
            )
            .await
            .unwrap();
            assert_eq!(report["status"], "ok");
            let transports = report["data"]["transports"].as_array().unwrap();
            assert_eq!(transports.len(), 1);
            assert_eq!(transports[0]["type"], "websocket");
            assert_eq!(transports[0]["state"], "up");
            assert!(
                transports[0].get("local_addr").is_none(),
                "seed client has no listener"
            );
        }
        for (node, status) in self.states().await.iter().enumerate() {
            let mut actual: Vec<_> = status["peers"]
                .as_array()
                .unwrap()
                .iter()
                .filter(|peer| peer["connected"] == true)
                .map(|peer| peer["transport"].as_str().unwrap())
                .collect();
            actual.sort_unstable();
            let first = if self.configs[0].transports.ethernet.is_empty() {
                "udp"
            } else {
                "ethernet"
            };
            let mut expected = match node {
                0 => vec![first],
                1 => vec![self.second_hop_kind(), first],
                _ => vec![self.second_hop_kind()],
            };
            expected.sort_unstable();
            assert_eq!(actual, expected, "native carrier topology at node {node}");
        }
    }
}
