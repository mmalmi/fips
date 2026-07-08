use nostr::prelude::{EventBuilder, JsonUtil, Kind, Tag, TagKind, Timestamp};

use super::runtime::{NostrDiscovery, VerifiedEvent, suppress_responder_for_own_initiator};
use super::signal::{
    FreshnessOutcome, TraversalSignalTiming, build_signal_event, create_traversal_answer,
    create_traversal_offer, estimate_clock_skew, unwrap_signal_event, validate_offer_freshness,
    validate_traversal_answer_for_offer,
};
use super::stun::{
    compatible_stun_targets, parse_stun_binding_success, parse_stun_url, perform_stun_any,
};
use super::traversal::{
    PunchStrategy, build_punch_packet, parse_punch_packet, plan_punch_targets,
    planned_remote_endpoints, session_hash,
};
use super::types::TraversalAddressObservation;
use super::{
    ADVERT_IDENTIFIER, ADVERT_KIND, ADVERT_VERSION, OverlayAdvert, OverlayEndpointAdvert,
    OverlayTransportKind, PunchHint, PunchPacketKind, TraversalAddress,
};
use crate::NodeAddr;

#[derive(Clone, Copy, PartialEq, Eq)]
enum NatType {
    RestrictedCone,
    PortRestricted,
    Symmetric,
}

fn addr(ip: &str, port: u16) -> TraversalAddress {
    TraversalAddress {
        protocol: "udp".to_string(),
        ip: ip.to_string(),
        port,
    }
}

fn observed(
    reflexive_address: Option<TraversalAddress>,
    local_addresses: Vec<TraversalAddress>,
    stun_server: Option<&str>,
) -> TraversalAddressObservation {
    TraversalAddressObservation {
        reflexive_address,
        local_addresses,
        stun_server: stun_server.map(str::to_string),
    }
}

fn can_reach(local_nat: NatType, remote_nat: NatType) -> bool {
    if local_nat == NatType::Symmetric || remote_nat == NatType::Symmetric {
        return false;
    }
    !(local_nat == NatType::PortRestricted && remote_nat == NatType::PortRestricted)
}

fn node_addr(first_byte: u8) -> NodeAddr {
    let mut bytes = [0u8; 16];
    bytes[0] = first_byte;
    NodeAddr::from_bytes(bytes)
}

fn signed_overlay_advert_event(created_at_secs: u64, expiration_secs: Option<u64>) -> nostr::Event {
    let keys = nostr::Keys::generate();
    let content = r#"{"identifier":"fips-overlay-v1","version":1,"endpoints":[{"transport":"tcp","addr":"8.8.8.8:443"}]}"#;
    let mut builder = EventBuilder::new(Kind::Custom(ADVERT_KIND), content)
        .custom_created_at(Timestamp::from(created_at_secs));
    if let Some(expiration_secs) = expiration_secs {
        builder = builder.tags([Tag::expiration(Timestamp::from(expiration_secs))]);
    }
    builder.sign_with_keys(&keys).unwrap()
}

fn signed_overlay_advert_event_for_app(app: &str) -> nostr::Event {
    let keys = nostr::Keys::generate();
    let content = r#"{"identifier":"fips-overlay-v1","version":1,"endpoints":[{"transport":"tcp","addr":"8.8.8.8:443"}]}"#;
    EventBuilder::new(Kind::Custom(ADVERT_KIND), content)
        .tags([
            Tag::identifier(app),
            Tag::custom(TagKind::custom("protocol"), [app.to_string()]),
        ])
        .sign_with_keys(&keys)
        .unwrap()
}

#[test]
fn serializes_direct_overlay_advert_without_nat_metadata() {
    let advert = OverlayAdvert {
        identifier: ADVERT_IDENTIFIER.to_string(),
        version: ADVERT_VERSION,
        endpoints: vec![
            OverlayEndpointAdvert {
                transport: OverlayTransportKind::Tcp,
                addr: "203.0.113.10:443".to_string(),
            },
            OverlayEndpointAdvert {
                transport: OverlayTransportKind::Tor,
                addr: "exampleonion.onion:1234".to_string(),
            },
        ],
        signal_relays: None,
        stun_servers: None,
    };

    let json = serde_json::to_string(&advert).unwrap();
    assert!(json.contains("\"endpoints\""));
    assert!(!json.contains("\"signalRelays\""));
    assert!(!json.contains("\"stunServers\""));
}

#[test]
fn responder_suppression_election_keeps_smaller_initiator() {
    let smaller = node_addr(0x01);
    let larger = node_addr(0x02);

    assert!(suppress_responder_for_own_initiator(
        &smaller, &larger, true
    ));
    assert!(!suppress_responder_for_own_initiator(
        &larger, &smaller, true
    ));
    assert!(!suppress_responder_for_own_initiator(
        &smaller, &larger, false
    ));
    assert!(!suppress_responder_for_own_initiator(
        &larger, &smaller, false
    ));
    assert!(!suppress_responder_for_own_initiator(
        &smaller, &smaller, true
    ));
}

#[test]
fn serializes_and_validates_webrtc_overlay_advert() {
    let advert = OverlayAdvert {
        identifier: ADVERT_IDENTIFIER.to_string(),
        version: ADVERT_VERSION,
        endpoints: vec![OverlayEndpointAdvert {
            transport: OverlayTransportKind::WebRtc,
            addr: "02".to_string() + &"11".repeat(32),
        }],
        signal_relays: Some(vec!["wss://relay.example".to_string()]),
        stun_servers: Some(vec!["stun:stun.example.org:3478".to_string()]),
    };

    let json = serde_json::to_string(&advert).unwrap();
    assert!(json.contains("\"transport\":\"webrtc\""));

    let sanitized = NostrDiscovery::validate_overlay_advert(advert).unwrap();
    assert_eq!(sanitized.endpoints.len(), 1);
    assert_eq!(
        sanitized.endpoints[0].transport,
        OverlayTransportKind::WebRtc
    );
    assert_eq!(
        sanitized.signal_relays,
        Some(vec!["wss://relay.example".to_string()])
    );
}

#[test]
fn serializes_nat_overlay_advert_with_metadata() {
    let advert = OverlayAdvert {
        identifier: ADVERT_IDENTIFIER.to_string(),
        version: ADVERT_VERSION,
        endpoints: vec![OverlayEndpointAdvert {
            transport: OverlayTransportKind::Udp,
            addr: "nat".to_string(),
        }],
        signal_relays: Some(vec!["wss://relay.example".to_string()]),
        stun_servers: Some(vec!["stun:stun.example.org:3478".to_string()]),
    };

    let json = serde_json::to_string(&advert).unwrap();
    assert!(json.contains("\"signalRelays\""));
    assert!(json.contains("\"stunServers\""));
}

#[test]
fn rejects_invalid_overlay_adverts() {
    let missing_nat_metadata = OverlayAdvert {
        identifier: ADVERT_IDENTIFIER.to_string(),
        version: ADVERT_VERSION,
        endpoints: vec![OverlayEndpointAdvert {
            transport: OverlayTransportKind::Udp,
            addr: "nat".to_string(),
        }],
        signal_relays: None,
        stun_servers: None,
    };
    assert!(NostrDiscovery::validate_overlay_advert(missing_nat_metadata).is_err());

    let wrong_identifier = OverlayAdvert {
        identifier: "not-fips-overlay".to_string(),
        version: ADVERT_VERSION,
        endpoints: vec![OverlayEndpointAdvert {
            transport: OverlayTransportKind::Tcp,
            addr: "203.0.113.10:443".to_string(),
        }],
        signal_relays: None,
        stun_servers: None,
    };
    assert!(NostrDiscovery::validate_overlay_advert(wrong_identifier).is_err());
}

#[test]
fn validate_overlay_advert_filters_unroutable_direct_endpoints() {
    let advert = OverlayAdvert {
        identifier: ADVERT_IDENTIFIER.to_string(),
        version: ADVERT_VERSION,
        endpoints: vec![
            OverlayEndpointAdvert {
                transport: OverlayTransportKind::Udp,
                addr: "10.44.236.44:51820".to_string(),
            },
            OverlayEndpointAdvert {
                transport: OverlayTransportKind::Tcp,
                addr: "192.168.1.20:443".to_string(),
            },
            OverlayEndpointAdvert {
                transport: OverlayTransportKind::Udp,
                addr: "nat".to_string(),
            },
        ],
        signal_relays: Some(vec!["wss://relay.example".to_string()]),
        stun_servers: Some(vec!["stun:stun.example.org:3478".to_string()]),
    };

    let sanitized = NostrDiscovery::validate_overlay_advert(advert).unwrap();
    assert_eq!(sanitized.endpoints.len(), 1);
    assert_eq!(sanitized.endpoints[0].transport, OverlayTransportKind::Udp);
    assert_eq!(sanitized.endpoints[0].addr, "nat");
}

#[test]
fn validate_overlay_advert_rejects_only_unroutable_direct_endpoints() {
    let advert = OverlayAdvert {
        identifier: ADVERT_IDENTIFIER.to_string(),
        version: ADVERT_VERSION,
        endpoints: vec![OverlayEndpointAdvert {
            transport: OverlayTransportKind::Udp,
            addr: "10.44.236.44:51820".to_string(),
        }],
        signal_relays: None,
        stun_servers: None,
    };

    assert!(NostrDiscovery::validate_overlay_advert(advert).is_err());
}

#[test]
fn parses_only_signed_overlay_advert_events() {
    let event = signed_overlay_advert_event_for_app("fips-test");
    let event = VerifiedEvent::try_from(&event).expect("signed advert should verify");

    let advert = NostrDiscovery::parse_overlay_advert_event(event, "fips-test")
        .expect("signed advert should parse");

    assert_eq!(advert.identifier, ADVERT_IDENTIFIER);
    assert_eq!(advert.endpoints.len(), 1);
}

#[test]
fn advert_prefilter_accepts_only_matching_app_tags() {
    let event = signed_overlay_advert_event_for_app("fips-test");
    assert!(NostrDiscovery::advert_event_targets_app(
        &event,
        "fips-test"
    ));
    assert!(!NostrDiscovery::advert_event_targets_app(
        &event,
        "other-app"
    ));

    let missing_protocol = signed_overlay_advert_event(Timestamp::now().as_secs(), None);
    assert!(!NostrDiscovery::advert_event_targets_app(
        &missing_protocol,
        "fips-test"
    ));
}

#[test]
fn rejects_tampered_overlay_advert_event_content() {
    let mut event = signed_overlay_advert_event_for_app("fips-test");
    event.content = r#"{"identifier":"fips-overlay-v1","version":1,"endpoints":[{"transport":"tcp","addr":"1.1.1.1:443"}]}"#.to_string();

    let err = VerifiedEvent::try_from(&event)
        .expect_err("tampered advert content must fail event verification");

    assert!(err.to_string().contains("signature"), "{err}");
}

#[test]
fn advert_freshness_rejects_expired_events() {
    let now_secs = Timestamp::now().as_secs();
    let event = signed_overlay_advert_event(now_secs, Some(now_secs.saturating_sub(1)));
    let valid_until =
        NostrDiscovery::compute_advert_valid_until_ms(&event, 600_000, now_secs * 1000);
    assert!(valid_until.is_none());
}

#[test]
fn advert_freshness_rejects_stale_created_at_without_expiration() {
    let now_secs = Timestamp::now().as_secs();
    let stale_created = now_secs.saturating_sub(10_000);
    let event = signed_overlay_advert_event(stale_created, None);
    let valid_until =
        NostrDiscovery::compute_advert_valid_until_ms(&event, 600_000, now_secs * 1000);
    assert!(valid_until.is_none());
}

#[test]
fn advert_freshness_uses_earliest_expiration_bound() {
    let now_secs = Timestamp::now().as_secs();
    let event = signed_overlay_advert_event(now_secs.saturating_sub(10), Some(now_secs + 30));
    let valid_until =
        NostrDiscovery::compute_advert_valid_until_ms(&event, 3_600_000, now_secs * 1000)
            .expect("event should be fresh");
    assert_eq!(valid_until, (now_secs + 30) * 1000);
}

#[test]
fn parses_stun_urls() {
    let parsed = parse_stun_url("stun:stun.l.google.com:19302").unwrap();
    assert_eq!(parsed.host, "stun.l.google.com");
    assert_eq!(parsed.port, 19302);
}

#[test]
fn parses_ipv6_stun_urls() {
    let parsed = parse_stun_url("stun:[2001:db8::10]:3478").unwrap();
    assert_eq!(parsed.host, "[2001:db8::10]");
    assert_eq!(parsed.port, 3478);
}

#[test]
fn parses_ipv6_xor_mapped_address() {
    let txn_id = [
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x10, 0x32, 0x54, 0x76,
    ];
    let addr = std::net::SocketAddr::new("2001:db8::1234".parse().unwrap(), 3478);
    let port = addr.port() ^ 0x2112;

    let mut attr = Vec::with_capacity(24);
    attr.extend_from_slice(&0x0020u16.to_be_bytes());
    attr.extend_from_slice(&20u16.to_be_bytes());
    attr.push(0);
    attr.push(0x02);
    attr.extend_from_slice(&port.to_be_bytes());

    let ipv6 = match addr.ip() {
        std::net::IpAddr::V6(ip) => ip.octets(),
        std::net::IpAddr::V4(_) => panic!("expected IPv6 test address"),
    };
    let cookie = 0x2112_a442u32.to_be_bytes();
    for index in 0..16 {
        let mask = if index < 4 {
            cookie[index]
        } else {
            txn_id[index - 4]
        };
        attr.push(ipv6[index] ^ mask);
    }

    let mut packet = Vec::with_capacity(44);
    packet.extend_from_slice(&0x0101u16.to_be_bytes());
    packet.extend_from_slice(&(attr.len() as u16).to_be_bytes());
    packet.extend_from_slice(&0x2112_a442u32.to_be_bytes());
    packet.extend_from_slice(&txn_id);
    packet.extend_from_slice(&attr);

    assert_eq!(parse_stun_binding_success(&packet, &txn_id), Some(addr));
}

#[tokio::test]
async fn stun_observation_uses_first_success_without_waiting_for_dead_first_server() {
    let silent = tokio::net::UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("bind silent STUN socket");
    let silent_addr = silent.local_addr().expect("silent addr");
    let responder = tokio::net::UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("bind responder STUN socket");
    let responder_addr = responder.local_addr().expect("responder addr");

    tokio::spawn(async move {
        let mut buf = [0u8; 2048];
        let (len, src) = responder.recv_from(&mut buf).await.expect("recv STUN");
        let txn_id: [u8; 12] = buf[8..20]
            .try_into()
            .expect("binding request should carry transaction id");
        let src_ip = match src.ip() {
            std::net::IpAddr::V4(ip) => ip,
            std::net::IpAddr::V6(_) => panic!("test uses IPv4 sockets"),
        };
        let cookie = 0x2112_a442u32.to_be_bytes();
        let mut response = Vec::new();
        response.extend_from_slice(&0x0101u16.to_be_bytes());
        response.extend_from_slice(&12u16.to_be_bytes());
        response.extend_from_slice(&0x2112_a442u32.to_be_bytes());
        response.extend_from_slice(&txn_id);
        response.extend_from_slice(&0x0020u16.to_be_bytes());
        response.extend_from_slice(&8u16.to_be_bytes());
        response.push(0);
        response.push(0x01);
        response.extend_from_slice(&(src.port() ^ 0x2112).to_be_bytes());
        for (octet, mask) in src_ip.octets().into_iter().zip(cookie) {
            response.push(octet ^ mask);
        }
        assert!(len >= 20);
        responder
            .send_to(&response, src)
            .await
            .expect("send STUN response");
    });

    let client = std::net::UdpSocket::bind("0.0.0.0:0").expect("bind client");
    client
        .set_nonblocking(true)
        .expect("tokio requires nonblocking socket");
    let client_port = client.local_addr().expect("client addr").port();
    let servers = vec![
        format!("stun:{}", silent_addr),
        format!("stun:{}", responder_addr),
    ];

    let started = std::time::Instant::now();
    let (mapped, stun_server) =
        perform_stun_any(&client, &servers, std::time::Duration::from_secs(2))
            .await
            .expect("second STUN server should answer");

    assert_eq!(stun_server, format!("stun:{}", responder_addr));
    assert_eq!(mapped.expect("mapped address").port(), client_port);
    assert!(
        started.elapsed() < std::time::Duration::from_millis(500),
        "parallel STUN should not wait for the silent first server"
    );

    drop(silent);
}

#[test]
fn builds_and_parses_probe_packets() {
    let packet = build_punch_packet(PunchPacketKind::Probe, 7, "sess-1");
    let parsed = parse_punch_packet(&packet).unwrap();
    assert_eq!(parsed.kind, PunchPacketKind::Probe);
    assert_eq!(parsed.sequence, 7);
    assert_eq!(parsed.session_hash, session_hash("sess-1"));
}

#[test]
fn stun_targets_keep_socket_family_when_dns_returns_ipv6_first() {
    let local_addr: std::net::SocketAddr = "0.0.0.0:51820".parse().unwrap();
    let ipv6_first: Vec<std::net::SocketAddr> = vec![
        "[2001:4860:4864:5:8000::1]:19302".parse().unwrap(),
        "74.125.250.129:19302".parse().unwrap(),
    ];

    let targets = compatible_stun_targets(local_addr, ipv6_first);

    assert_eq!(
        targets,
        vec![
            "74.125.250.129:19302"
                .parse::<std::net::SocketAddr>()
                .unwrap()
        ]
    );
}

#[test]
fn validates_offer_answer_pair() {
    let offer = create_traversal_offer(
        "sess-1".to_string(),
        TraversalSignalTiming::new(1_700_000_000_000, 60_000),
        "offer-1".to_string(),
        "npub1client".to_string(),
        "npub1server".to_string(),
        observed(
            Some(addr("203.0.113.10", 62000)),
            vec![addr("192.168.1.10", 62000)],
            Some("stun:example.org:3478"),
        ),
    );
    let answer = create_traversal_answer(
        &offer,
        TraversalSignalTiming::new(1_700_000_000_500, 60_000),
        "answer-1".to_string(),
        "npub1server".to_string(),
        observed(
            Some(addr("198.51.100.20", 63000)),
            vec![addr("192.168.1.20", 63000)],
            Some("stun:example.org:3478"),
        ),
        Some(PunchHint {
            start_at_ms: 1_700_000_002_000,
            interval_ms: 200,
            duration_ms: 10_000,
        }),
        Some(1_700_000_000_400),
    );

    assert!(
        validate_traversal_answer_for_offer(
            &offer,
            &answer,
            1_700_000_000_900,
            60_000,
            "npub1server",
            "npub1client",
        )
        .is_ok()
    );
}

#[test]
fn rejects_offer_with_mismatched_actual_sender() {
    let offer = create_traversal_offer(
        "sess-1".to_string(),
        TraversalSignalTiming::new(1_700_000_000_000, 60_000),
        "offer-1".to_string(),
        "npub1claimed".to_string(),
        "npub1server".to_string(),
        observed(None, vec![addr("192.168.1.10", 62000)], None),
    );

    let result = validate_offer_freshness(
        &offer,
        1_700_000_000_100,
        60_000,
        "npub1actual",
        "npub1server",
    );

    assert!(result.is_err());
}

#[test]
fn rejects_answer_with_mismatched_actual_sender() {
    let offer = create_traversal_offer(
        "sess-1".to_string(),
        TraversalSignalTiming::new(1_700_000_000_000, 60_000),
        "offer-1".to_string(),
        "npub1client".to_string(),
        "npub1server".to_string(),
        observed(
            Some(addr("203.0.113.10", 62000)),
            vec![addr("192.168.1.10", 62000)],
            Some("stun:example.org:3478"),
        ),
    );
    let answer = create_traversal_answer(
        &offer,
        TraversalSignalTiming::new(1_700_000_000_500, 60_000),
        "answer-1".to_string(),
        "npub1server".to_string(),
        observed(
            Some(addr("198.51.100.20", 63000)),
            vec![addr("192.168.1.20", 63000)],
            Some("stun:example.org:3478"),
        ),
        Some(PunchHint {
            start_at_ms: 1_700_000_002_000,
            interval_ms: 200,
            duration_ms: 10_000,
        }),
        Some(1_700_000_000_400),
    );

    let result = validate_traversal_answer_for_offer(
        &offer,
        &answer,
        1_700_000_000_900,
        60_000,
        "npub1spoofed",
        "npub1client",
    );

    assert!(result.is_err());
}

#[test]
fn plans_reflexive_targets_before_lan() {
    let planned = plan_punch_targets(
        &[addr("192.168.1.10", 62000)],
        Some(&addr("203.0.113.10", 62000)),
        &[addr("192.168.1.20", 63000)],
        Some(&addr("198.51.100.20", 63000)),
        false,
    );

    assert_eq!(planned[0].strategy, PunchStrategy::Reflexive);
    assert_eq!(planned[1].strategy, PunchStrategy::Lan);
}

#[test]
fn plans_lan_targets_before_reflexive_when_preferred() {
    let planned = plan_punch_targets(
        &[addr("192.168.1.10", 62000)],
        Some(&addr("203.0.113.10", 62000)),
        &[addr("192.168.1.20", 63000)],
        Some(&addr("198.51.100.20", 63000)),
        true,
    );

    assert_eq!(planned[0].strategy, PunchStrategy::Lan);
    assert_eq!(planned[1].strategy, PunchStrategy::Reflexive);
}

#[test]
fn simulated_lan_scenario_includes_lan_target_and_succeeds() {
    let planned = plan_punch_targets(
        &[addr("192.168.1.10", 62000)],
        Some(&addr("203.0.113.10", 62000)),
        &[addr("192.168.1.20", 63000)],
        Some(&addr("198.51.100.20", 63000)),
        false,
    );

    assert!(
        planned
            .iter()
            .any(|target| target.strategy == PunchStrategy::Lan)
    );
    assert!(can_reach(NatType::RestrictedCone, NatType::RestrictedCone));
}

#[test]
fn simulated_symmetric_nat_scenario_requires_fallback() {
    let planned = plan_punch_targets(
        &[addr("10.0.0.10", 62000)],
        Some(&addr("203.0.113.10", 62000)),
        &[addr("10.0.1.10", 63000)],
        Some(&addr("198.51.100.20", 63000)),
        false,
    );

    assert!(
        planned
            .iter()
            .any(|target| target.strategy == PunchStrategy::Reflexive)
    );
    assert!(!can_reach(NatType::Symmetric, NatType::RestrictedCone));
}

#[test]
fn planned_remote_endpoints_include_private_and_reflexive_paths() {
    let endpoints = planned_remote_endpoints(
        &[addr("192.168.1.10", 62000)],
        Some(&addr("203.0.113.10", 62000)),
        &[addr("192.168.1.20", 63000)],
        Some(&addr("198.51.100.20", 63000)),
        true,
    )
    .expect("endpoint planning should succeed");

    assert!(
        endpoints
            .remotes
            .contains(&"192.168.1.20:63000".parse().unwrap())
    );
    assert!(
        endpoints
            .remotes
            .contains(&"198.51.100.20:63000".parse().unwrap())
    );
    assert_eq!(endpoints.preferred_count, 1);
}

/// Cross-LAN private remote candidate must NOT appear in the planned set:
/// pairing our public reflexive against a remote private host that lives
/// on a different /24 is unrouteable and risks latching a slow overlay-
/// relay path as `runtime_endpoint`. The public reflexive target and any
/// same-LAN private target are still included.
#[test]
fn planned_remote_endpoints_skip_cross_lan_private_remote() {
    let endpoints = planned_remote_endpoints(
        // Our LAN: 192.168.1.0/24
        &[addr("192.168.1.10", 62000)],
        Some(&addr("203.0.113.10", 62000)),
        // Their reported local candidates: a *different* private LAN.
        // From our public reflexive these are unrouteable.
        &[addr("192.168.178.91", 35576), addr("10.0.0.5", 35576)],
        Some(&addr("198.51.100.20", 63000)),
        false,
    )
    .expect("endpoint planning should succeed");

    // Public reflexive ↔ public reflexive: always present.
    assert!(
        endpoints
            .remotes
            .contains(&"198.51.100.20:63000".parse().unwrap()),
        "public reflexive target must be included"
    );
    // The cross-LAN private host candidates must be filtered out of the
    // (our_reflexive ↔ remote_local) mixed pairing.
    assert!(
        !endpoints
            .remotes
            .contains(&"192.168.178.91:35576".parse().unwrap()),
        "cross-LAN 192.168.178.91 must be filtered"
    );
    assert!(
        !endpoints
            .remotes
            .contains(&"10.0.0.5:35576".parse().unwrap()),
        "cross-LAN 10.0.0.5 must be filtered"
    );
}

/// Same-LAN private remote candidates SHOULD remain — we still might need
/// the (our_reflexive ↔ remote_local) mixed pairing when our local socket
/// is wildcard-bound and not enumerated in `local_addresses`, or as a
/// belt-and-braces alongside the same-LAN strategy.
#[test]
fn planned_remote_endpoints_keep_same_lan_private_remote() {
    let endpoints = planned_remote_endpoints(
        &[addr("192.168.1.10", 62000)],
        Some(&addr("203.0.113.10", 62000)),
        &[addr("192.168.1.20", 35576)],
        Some(&addr("198.51.100.20", 63000)),
        false,
    )
    .expect("endpoint planning should succeed");

    assert!(
        endpoints
            .remotes
            .contains(&"192.168.1.20:35576".parse().unwrap()),
        "same-LAN private remote must still be tried"
    );
}

/// B4: strict-fresh path returns Fresh; the offer is well within TTL and
/// not expired.
#[test]
fn freshness_strict_returns_fresh_outcome() {
    let offer = create_traversal_offer(
        "sess-1".to_string(),
        TraversalSignalTiming::new(1_700_000_000_000, 60_000),
        "offer-1".to_string(),
        "npub1client".to_string(),
        "npub1server".to_string(),
        observed(
            Some(addr("203.0.113.10", 62000)),
            vec![addr("192.168.1.10", 62000)],
            Some("stun:example.org:3478"),
        ),
    );

    let result = validate_offer_freshness(
        &offer,
        1_700_000_000_500,
        60_000,
        "npub1client",
        "npub1server",
    )
    .expect("strict-fresh offer should validate");
    assert_eq!(result, FreshnessOutcome::Fresh);
}

/// B4: an offer whose `expires_at` has already passed by < SKEW_TOL is
/// accepted but flagged FreshWithinSkewTolerance — emulates the case where
/// the responder's clock is ahead of the initiator's.
#[test]
fn freshness_responder_clock_ahead_within_tolerance_is_tolerated() {
    let offer = create_traversal_offer(
        "sess-1".to_string(),
        TraversalSignalTiming::new(1_700_000_000_000, 60_000), // expires_at = 1_700_000_060_000
        "offer-1".to_string(),
        "npub1client".to_string(),
        "npub1server".to_string(),
        observed(
            Some(addr("203.0.113.10", 62000)),
            vec![addr("192.168.1.10", 62000)],
            None,
        ),
    );

    // now 90s past issued_at — 30s past strict expiry, but inside the 60s
    // SKEW_TOL grace.
    let result = validate_offer_freshness(
        &offer,
        1_700_000_090_000,
        60_000,
        "npub1client",
        "npub1server",
    )
    .expect("offer just past strict expiry should be tolerated");
    assert_eq!(result, FreshnessOutcome::FreshWithinSkewTolerance);
}

/// B4: an offer beyond TTL + SKEW_TOL is rejected as expired.
#[test]
fn freshness_responder_clock_far_ahead_is_rejected() {
    let offer = create_traversal_offer(
        "sess-1".to_string(),
        TraversalSignalTiming::new(1_700_000_000_000, 60_000),
        "offer-1".to_string(),
        "npub1client".to_string(),
        "npub1server".to_string(),
        observed(
            Some(addr("203.0.113.10", 62000)),
            vec![addr("192.168.1.10", 62000)],
            None,
        ),
    );

    // 130s past issued_at: 70s past strict expiry, 10s past tolerated expiry.
    let err = validate_offer_freshness(
        &offer,
        1_700_000_130_000,
        60_000,
        "npub1client",
        "npub1server",
    )
    .expect_err("offer past tolerated expiry should be rejected");
    assert!(err.to_string().contains("expired-offer"), "{}", err);
}

/// B5a: the NTP-style skew estimator returns the responder's apparent
/// clock offset relative to the initiator. Symmetric one-way delays of
/// 50ms each plus a +500ms responder skew should yield ≈+500ms.
#[test]
fn estimate_clock_skew_matches_responder_offset() {
    // T1 (initiator sent)
    let offer = create_traversal_offer(
        "sess-1".to_string(),
        TraversalSignalTiming::new(1_700_000_000_000, 60_000),
        "offer-1".to_string(),
        "npub1client".to_string(),
        "npub1server".to_string(),
        observed(None, vec![addr("192.168.1.10", 62000)], None),
    );
    // Wire takes 50ms, responder clock is +500ms ahead, so:
    //   T2 = 1_700_000_000_000 + 50 + 500 = 1_700_000_000_550
    //   T3 = 1_700_000_000_550 (no processing time for this synthetic case)
    //   T4 = T1 + 50 + (T3 - T2 + 500_skew_corrected) + 50 wire return
    //      For simplicity: T4 = T1 + 100ms wire + 0 responder processing
    //                       = 1_700_000_000_100 (initiator wall clock)
    let answer = create_traversal_answer(
        &offer,
        TraversalSignalTiming::new(1_700_000_000_550, 60_000), // T3
        "answer-1".to_string(),
        "npub1server".to_string(),
        observed(Some(addr("198.51.100.20", 63000)), vec![], None),
        None,
        Some(1_700_000_000_550), // T2
    );
    let answer_received_at = 1_700_000_000_100; // T4

    let skew = estimate_clock_skew(&offer, &answer, answer_received_at)
        .expect("offer_received_at populated -> Some");
    // ((550 - 0) + (550 - 100)) / 2 = (550 + 450) / 2 = 500
    assert_eq!(skew, 500);
}

/// B5a: backward-compat — when the responder did not populate
/// `offer_received_at` (older daemon), skew estimation returns None
/// and callers should silently skip logging it.
#[test]
fn estimate_clock_skew_returns_none_without_responder_timestamp() {
    let offer = create_traversal_offer(
        "sess-1".to_string(),
        TraversalSignalTiming::new(1_700_000_000_000, 60_000),
        "offer-1".to_string(),
        "npub1client".to_string(),
        "npub1server".to_string(),
        observed(None, vec![], None),
    );
    let answer = create_traversal_answer(
        &offer,
        TraversalSignalTiming::new(1_700_000_000_500, 60_000),
        "answer-1".to_string(),
        "npub1server".to_string(),
        observed(Some(addr("198.51.100.20", 63000)), vec![], None),
        None,
        None, // older responder
    );
    assert!(estimate_clock_skew(&offer, &answer, 1_700_000_000_900).is_none());
}

#[tokio::test]
async fn signal_events_use_current_timestamps() {
    let sender = nostr::Keys::generate();
    let receiver = nostr::Keys::generate();
    let rumor = EventBuilder::private_msg_rumor(receiver.public_key(), "hello".to_string())
        .build(sender.public_key());
    let before = Timestamp::now().as_secs();

    let event = build_signal_event(
        &sender,
        receiver.public_key(),
        rumor,
        Timestamp::from(before + 30),
    )
    .await
    .expect("signal event should build");

    let after = Timestamp::now().as_secs();
    let created_at = event.created_at.as_secs();

    assert!(created_at >= before);
    assert!(created_at <= after);
}

#[tokio::test]
async fn unwraps_ts_built_webrtc_signal_wrap() {
    let recipient =
        nostr::Keys::parse("5555555555555555555555555555555555555555555555555555555555555555")
            .expect("recipient key should parse");
    let event = nostr::prelude::Event::from_json(
        r#"{"id":"08d9b1f5201c7ea3054e43d99b641b8279b5c4d2b6a679f8f252a11b48cf937f","sig":"bfa4195e2472100cf02a541395d0eb32857cdec6321da6603e4ce1702d1a0083ca62153b05c96133650c9957c3d27c63dde1e1bc0c73cef2e837fc43d1910722","pubkey":"b98a19f1f0aec66a23e3a477f16165264a7e6befc7e16453fbb1108e93c541e9","created_at":1779364084,"kind":21059,"tags":[["p","9ac20335eb38768d2052be1dbbc3c8f6178407458e51e6b4ad22f1d91758895b"]],"content":"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"}"#,
    )
    .expect("event should parse");

    let unwrapped = unwrap_signal_event(&recipient, &event)
        .await
        .expect("TS gift wrap should unwrap in Rust");

    assert_eq!(
        unwrapped.sender.to_string(),
        "2c0b7cf95324a07d05398b240174dc0c2be444d96b159aa6c7f7b1e668680991"
    );
    assert_eq!(unwrapped.rumor.kind, Kind::PrivateDirectMessage);
    assert!(
        unwrapped
            .rumor
            .content
            .contains(r#""protocol":"fips-webrtc-v1""#)
    );
}
