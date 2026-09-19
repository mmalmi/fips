//! The optional carrier field crosses the real daemon's private status path.
use super::*;

pub(super) async fn assert_status(bench: &MixedBench, active: bool) {
    for (node, status) in bench.states().await.into_iter().enumerate() {
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
                    1 => matches!(kind, "udp" | "tcp"),
                    2 => kind == "tcp",
                    _ => unreachable!(),
                };
                if !possible {
                    assert_eq!((packets, bytes), (0, 0));
                } else if active {
                    assert!(packets > 0 && bytes > 0,
                        "each funded endpoint and both middle-router carriers submit measured segments");
                }
            }
        }
    }
}
