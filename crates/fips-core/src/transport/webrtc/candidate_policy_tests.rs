use super::*;
use super::candidate_policy::CandidateAddressPolicy;
use super::candidate_policy::validate_embedded_ice_candidates;
use crate::config::{
    MAX_WEBRTC_CONFIG_CANDIDATE_SOCKETS, MAX_WEBRTC_HOST_CANDIDATE_SOCKETS,
    MAX_WEBRTC_LOCAL_CANDIDATE_ROUTES, MAX_WEBRTC_REMOTE_CANDIDATE_LINES,
    MAX_WEBRTC_REMOTE_CANDIDATE_ROUTES, MAX_WEBRTC_SOCKETS_PER_STUN_SERVER,
    MAX_WEBRTC_STUN_SERVERS,
};
use ::webrtc::stun::fingerprint::FINGERPRINT;
use ::webrtc::stun::message::{BINDING_SUCCESS, Message};
use ::webrtc::stun::xoraddr::XorMappedAddress;
use ::webrtc::util::vnet::interface::Interface;
use ::webrtc::util::vnet::net::{Net, NetConfig};
use ::webrtc::util::vnet::router::{Router, RouterConfig};
use if_addrs::IfOperStatus;
use std::collections::HashSet;
use std::net::{IpAddr, SocketAddr};
use tokio::net::UdpSocket;

fn candidate_socket_routes(sdp: &str) -> HashSet<String> {
    sdp.lines()
        .filter_map(|line| line.trim().strip_prefix("a=candidate:"))
        .filter_map(|candidate| {
            let fields: Vec<_> = candidate.split_whitespace().collect();
            (fields.len() >= 8 && fields[1] == "1").then(|| {
                format!(
                    "{}|{}|{}|{}",
                    fields[2].to_ascii_lowercase(),
                    fields[4].to_ascii_lowercase(),
                    fields[5],
                    fields[7].to_ascii_lowercase()
                )
            })
        })
        .collect::<HashSet<_>>()
}

async fn gather_candidate_offer(
    api: &::webrtc::api::API,
    label: &str,
) -> (RTCPeerConnection, String) {
    let pc = api
        .new_peer_connection(RTCConfiguration::default())
        .await
        .expect("VNet peer connection");
    pc.create_data_channel(label, None)
        .await
        .expect("data channel");
    let offer = pc.create_offer(None).await.expect("offer");
    let mut gathering = pc.gathering_complete_promise().await;
    pc.set_local_description(offer)
        .await
        .expect("local description");
    wait_for_ice_gathering(Duration::from_secs(1), &mut gathering)
        .await
        .expect("VNet ICE gathering");
    let sdp = pc
        .local_description()
        .await
        .expect("complete local description")
        .sdp;
    (pc, sdp)
}

#[tokio::test]
async fn synthetic_many_address_vnet_gather_stays_within_host_socket_budget() {
    let static_ips: Vec<_> = (1..=24)
        .map(|index| format!("10.42.0.{index}"))
        .collect();
    let policy = CandidateAddressPolicy::from_test_snapshot(
        static_ips.iter().enumerate().map(|(index, ip)| {
            (
                format!("synthetic{index}"),
                ip.parse::<IpAddr>().expect("synthetic IP"),
                index % 3 == 0,
                index as u32 + 1,
            )
        }),
    );
    let vnet = Arc::new(Net::new(Some(NetConfig {
        static_ips: static_ips.clone(),
        ..NetConfig::default()
    })));
    let router = Arc::new(Mutex::new(
        Router::new(RouterConfig {
            cidr: "10.42.0.0/24".into(),
            ..RouterConfig::default()
        })
        .expect("VNet router"),
    ));
    let nic = vnet.get_nic().expect("VNet NIC");
    router
        .lock()
        .await
        .add_net(Arc::clone(&nic))
        .await
        .expect("attach VNet");
    nic.lock()
        .await
        .set_router(Arc::clone(&router))
        .await
        .expect("route VNet");
    router.lock().await.start().await.expect("start VNet router");
    let api = policy
        .build_api_with_vnet(Arc::clone(&vnet))
        .expect("budgeted VNet API");
    let (first_pc, first_sdp) = gather_candidate_offer(&api, "candidate-budget-first").await;
    let first_routes = candidate_socket_routes(&first_sdp);

    assert!(
        first_routes.len() <= MAX_WEBRTC_HOST_CANDIDATE_SOCKETS,
        "one peer connection gathered {} host candidate sockets; budget is {MAX_WEBRTC_HOST_CANDIDATE_SOCKETS}",
        first_routes.len()
    );
    assert_eq!(first_routes.len(), MAX_WEBRTC_HOST_CANDIDATE_SOCKETS);

    let changed_ip = static_ips.last().expect("changed address");
    let changed_policy = CandidateAddressPolicy::from_test_snapshot([(
        "changed-route".into(),
        changed_ip.parse().expect("changed IP"),
        true,
        100,
    )]);
    let changed_api = changed_policy
        .build_api_with_vnet(vnet)
        .expect("changed VNet API generation");
    let (changed_pc, changed_sdp) =
        gather_candidate_offer(&changed_api, "candidate-budget-changed").await;
    let changed_routes = candidate_socket_routes(&changed_sdp);
    assert_eq!(changed_routes.len(), 1);
    assert!(changed_routes.iter().any(|route| route.contains(changed_ip)));
    let first_after_change = first_pc
        .local_description()
        .await
        .expect("first generation remains active")
        .sdp;
    assert_eq!(candidate_socket_routes(&first_after_change), first_routes);

    changed_pc.close().await.expect("close changed VNet PC");
    first_pc.close().await.expect("close first VNet PC");
}

#[tokio::test]
async fn production_profile_gathers_selected_ipv4_ipv6_and_vpn_addresses() {
    let addresses: Vec<IpAddr> = [
        "192.0.2.44",
        "2001:db8:44::1",
        "10.44.0.1",
        "fd44::1",
    ]
    .into_iter()
    .map(|ip| ip.parse().expect("test IP"))
    .collect();
    let policy = CandidateAddressPolicy::from_test_snapshot([
        ("lan-v4".into(), addresses[0], false, 1),
        ("lan-v6".into(), addresses[1], false, 1),
        ("vpn-v4".into(), addresses[2], true, 2),
        ("vpn-v6".into(), addresses[3], true, 2),
    ]);
    let vnet = Arc::new(Net::new(Some(NetConfig::default())));
    let nic = vnet.get_nic().expect("VNet NIC");
    let ipnets: Vec<_> = addresses
        .iter()
        .map(|ip| {
            Interface::convert(SocketAddr::new(*ip, 0), None).expect("VNet interface address")
        })
        .collect();
    nic.lock()
        .await
        .add_addrs_to_interface("eth0", &ipnets)
        .await
        .expect("attach dual-stack VNet addresses");
    let api = policy
        .build_api_with_vnet(vnet)
        .expect("dual-stack VNet API");
    let (pc, sdp) = gather_candidate_offer(&api, "dual-stack-candidates").await;
    let routes = candidate_socket_routes(&sdp);

    assert_eq!(routes.len(), addresses.len());
    for address in addresses {
        assert!(
            routes.iter().any(|route| route.contains(&address.to_string())),
            "missing gathered route for {address}: {routes:?}"
        );
    }
    pc.close().await.expect("close dual-stack VNet PC");
}

#[tokio::test]
async fn production_profile_stun_gathering_survives_host_address_filtering() {
    let socket = UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("local STUN socket");
    let server_addr = socket.local_addr().expect("local STUN address");
    let server = tokio::spawn(async move {
        let mut buffer = [0u8; 1500];
        let (length, source) = socket.recv_from(&mut buffer).await.expect("STUN request");
        let mut request = Message::new();
        request
            .unmarshal_binary(&buffer[..length])
            .expect("decode STUN request");
        let mut response = Message::new();
        response
            .build(&[
                Box::new(BINDING_SUCCESS),
                Box::new(request.transaction_id),
                Box::new(XorMappedAddress {
                    ip: source.ip(),
                    port: source.port(),
                }),
                Box::new(FINGERPRINT),
            ])
            .expect("build STUN response");
        socket
            .send_to(&response.raw, source)
            .await
            .expect("send STUN response");
    });
    let api = CandidateAddressPolicy::system()
        .build_api()
        .expect("production WebRTC API");
    let pc = api
        .new_peer_connection(RTCConfiguration {
            ice_servers: vec![RTCIceServer {
                urls: vec![format!("stun:{server_addr}")],
                ..Default::default()
            }],
            ..Default::default()
        })
        .await
        .expect("STUN peer connection");
    pc.create_data_channel("stun-filter", None)
        .await
        .expect("data channel");
    let offer = pc.create_offer(None).await.expect("offer");
    let mut gathering = pc.gathering_complete_promise().await;
    pc.set_local_description(offer)
        .await
        .expect("local description");
    wait_for_ice_gathering(Duration::from_secs(1), &mut gathering)
        .await
        .expect("STUN gathering");
    let sdp = pc.local_description().await.expect("STUN SDP").sdp;
    assert!(
        candidate_socket_routes(&sdp)
            .iter()
            .any(|route| route.ends_with("|srflx")),
        "server-reflexive route missing from {sdp}"
    );
    server.await.expect("STUN server task");
    pc.close().await.expect("close STUN PC");
}

#[tokio::test]
async fn configured_stun_urls_reach_peer_connection_configuration() {
    let urls = vec![
        "stun:192.0.2.1:3478".to_string(),
        "stun:192.0.2.2:3478".to_string(),
    ];
    let identity = crate::Identity::generate();
    let (packet_tx, _packet_rx) = crate::packet_channel(1);
    let transport = WebRtcTransport::new(
        TransportId::new(603),
        None,
        WebRtcConfig {
            max_connections: Some(1),
            stun_servers: Some(urls.clone()),
            ..WebRtcConfig::default()
        },
        packet_tx,
        &identity,
        &NostrDiscoveryConfig::default(),
    )
    .expect("WebRTC transport");
    let pc = transport
        .runtime()
        .new_peer_connection()
        .await
        .expect("peer connection");
    let configured: Vec<_> = pc
        .get_configuration()
        .await
        .ice_servers
        .into_iter()
        .flat_map(|server| server.urls)
        .collect();

    assert_eq!(configured, urls);
    pc.close().await.expect("close configured PC");
}

#[test]
fn transport_constructor_rejects_unsupported_or_invalid_ice_urls() {
    for url in ["turn:turn.example:3478", "stun:", "stun:stun.example:bad"] {
        let identity = crate::Identity::generate();
        let (packet_tx, _packet_rx) = crate::packet_channel(1);
        assert!(
            WebRtcTransport::new(
                TransportId::new(604),
                None,
                WebRtcConfig {
                    max_connections: Some(1),
                    stun_servers: Some(vec![url.into()]),
                    ..WebRtcConfig::default()
                },
                packet_tx,
                &identity,
                &NostrDiscoveryConfig::default(),
            )
            .is_err(),
            "unsupported or malformed ICE URL must fail during construction: {url}"
        );
    }
}

#[test]
fn synthetic_many_interface_selection_preserves_ip_families_and_p2p_routes() {
    let mut snapshot = Vec::new();
    for index in 1..=12u32 {
        snapshot.push((
            format!("lan{index}"),
            format!("192.0.2.{index}").parse().unwrap(),
            false,
            index,
        ));
        snapshot.push((
            format!("lan{index}"),
            format!("2001:db8::{index}").parse().unwrap(),
            false,
            index,
        ));
        snapshot.push((
            format!("vpn{index}"),
            format!("10.0.0.{index}").parse().unwrap(),
            true,
            100 + index,
        ));
        snapshot.push((
            format!("vpn{index}"),
            format!("fd00::{index}").parse().unwrap(),
            true,
            100 + index,
        ));
    }
    let selected = CandidateAddressPolicy::from_test_snapshot(snapshot)
        .selected_ips_for_test()
        .expect("candidate selection");
    assert_eq!(selected.len(), MAX_WEBRTC_HOST_CANDIDATE_SOCKETS);
    assert!(selected.iter().any(IpAddr::is_ipv4));
    assert!(selected.iter().any(IpAddr::is_ipv6));
    assert!(selected.iter().any(|ip| matches!(ip, IpAddr::V4(ip) if ip.is_private())));
    assert!(selected.iter().any(|ip| matches!(ip, IpAddr::V6(ip) if ip.segments()[0] & 0xfe00 == 0xfc00)));
}

#[test]
fn temporary_addresses_on_one_interface_do_not_multiply_sockets() {
    let mut snapshot = vec![(
        "uplink".to_string(),
        "192.0.2.10".parse().unwrap(),
        false,
        1,
    )];
    for index in 1..=12u32 {
        snapshot.push((
            "uplink".to_string(),
            format!("2001:db8::{index}").parse().unwrap(),
            false,
            1,
        ));
    }
    let selected = CandidateAddressPolicy::from_test_snapshot(snapshot)
        .selected_ips_for_test()
        .expect("candidate selection");
    assert_eq!(selected.len(), 2);
    assert!(selected.iter().any(IpAddr::is_ipv4));
    assert!(selected.iter().any(IpAddr::is_ipv6));
}

#[test]
fn unknown_oper_status_preserves_point_to_point_and_vpn_routes() {
    let selected = CandidateAddressPolicy::from_test_status_snapshot([
        (
            "vpn-unknown-v4".into(),
            "10.77.0.1".parse().unwrap(),
            true,
            40,
            IfOperStatus::Unknown,
        ),
        (
            "vpn-unknown-v6".into(),
            "fd77::1".parse().unwrap(),
            true,
            40,
            IfOperStatus::Unknown,
        ),
        (
            "vpn-explicitly-down".into(),
            "10.88.0.1".parse().unwrap(),
            true,
            41,
            IfOperStatus::Down,
        ),
    ])
    .selected_ips_for_test()
    .expect("candidate selection");

    assert_eq!(selected.len(), 2);
    assert!(selected.contains(&"10.77.0.1".parse().unwrap()));
    assert!(selected.contains(&"fd77::1".parse().unwrap()));
    assert!(!selected.contains(&"10.88.0.1".parse().unwrap()));
}

#[test]
fn known_up_routes_are_not_crowded_out_by_unknown_interfaces() {
    let mut snapshot = Vec::new();
    for index in 1..=8u32 {
        snapshot.push((
            format!("unknown-{index}"),
            format!("198.51.100.{index}").parse().unwrap(),
            false,
            index,
            IfOperStatus::Unknown,
        ));
    }
    snapshot.extend([
        (
            "known-up-lan-v4".into(),
            "192.168.77.9".parse().unwrap(),
            false,
            100,
            IfOperStatus::Up,
        ),
        (
            "known-up-lan-v6".into(),
            "2001:db8:77::9".parse().unwrap(),
            false,
            100,
            IfOperStatus::Up,
        ),
        (
            "unknown-vpn-v4".into(),
            "10.77.0.1".parse().unwrap(),
            true,
            101,
            IfOperStatus::Unknown,
        ),
        (
            "unknown-vpn-v6".into(),
            "fd77::1".parse().unwrap(),
            true,
            101,
            IfOperStatus::Unknown,
        ),
    ]);
    let selected = CandidateAddressPolicy::from_test_status_snapshot(snapshot)
        .selected_ips_for_test()
        .expect("candidate selection");

    assert_eq!(selected.len(), MAX_WEBRTC_HOST_CANDIDATE_SOCKETS);
    assert!(selected.contains(&"192.168.77.9".parse().unwrap()));
    assert!(selected.contains(&"2001:db8:77::9".parse().unwrap()));
    assert!(selected.contains(&"10.77.0.1".parse().unwrap()));
    assert!(selected.contains(&"fd77::1".parse().unwrap()));
}

#[test]
fn known_up_lans_fill_spare_slots_before_unknown_p2p_routes() {
    let mut snapshot = (1..=4u32)
        .map(|index| {
            (
                format!("lan-{index}"),
                format!("192.0.2.{index}").parse().unwrap(),
                false,
                index,
                IfOperStatus::Up,
            )
        })
        .collect::<Vec<_>>();
    for index in 1..=6u32 {
        snapshot.push((
            format!("vpn-v4-{index}"),
            format!("10.0.0.{index}").parse().unwrap(),
            true,
            100 + index,
            IfOperStatus::Unknown,
        ));
        snapshot.push((
            format!("vpn-v6-{index}"),
            format!("fd00::{index}").parse().unwrap(),
            true,
            200 + index,
            IfOperStatus::Unknown,
        ));
    }
    let selected = CandidateAddressPolicy::from_test_status_snapshot(snapshot)
        .selected_ips_for_test()
        .expect("candidate selection");

    assert_eq!(selected.len(), MAX_WEBRTC_HOST_CANDIDATE_SOCKETS);
    for index in 1..=4u32 {
        assert!(selected.contains(&format!("192.0.2.{index}").parse().unwrap()));
    }
}

#[test]
fn system_candidate_snapshot_is_bounded() {
    let selected = CandidateAddressPolicy::system()
        .selected_ips_for_test()
        .expect("system interfaces");
    assert!(selected.len() <= MAX_WEBRTC_HOST_CANDIDATE_SOCKETS);
    assert!(selected.iter().all(|ip| !ip.is_loopback()));
}

#[test]
fn remote_sdp_can_exceed_the_local_socket_route_budget() {
    let identity = crate::Identity::generate();
    let (packet_tx, _packet_rx) = crate::packet_channel(1);
    let transport = WebRtcTransport::new(
        TransportId::new(601),
        None,
        WebRtcConfig {
            stun_servers: Some(Vec::new()),
            ..WebRtcConfig::default()
        },
        packet_tx,
        &identity,
        &NostrDiscoveryConfig::default(),
    )
    .expect("WebRTC transport");
    let mut sdp = String::from("v=0\r\n");
    for index in 0..MAX_WEBRTC_LOCAL_CANDIDATE_ROUTES + 4 {
        sdp.push_str(&format!(
            "a=candidate:{index} 1 UDP 1 192.0.2.1 {} typ host\r\n",
            5_000 + index
        ));
    }
    assert!(
        validate_embedded_ice_candidates(&sdp, EmbeddedCandidateScope::Local).is_err(),
        "the same SDP exceeds the locally generated socket-route budget"
    );
    validate_embedded_ice_candidates(&sdp, EmbeddedCandidateScope::Remote)
        .expect("bounded remote SDP can describe more routes than this host binds");
    let now = now_ms();
    let signal = WebRtcSignal {
        version: crate::transport::link_negotiation::LINK_NEGOTIATION_VERSION,
        negotiation_id: "browser-sized-embedded-sdp".into(),
        link_type: "webrtc".into(),
        kind: LinkNegotiationKind::Offer,
        created_at_ms: now,
        expires_at_ms: now + 1_000,
        payload: WebRtcSignalPayload {
            sdp: Some(sdp),
            candidates: None,
        },
    };

    transport
        .runtime()
        .validate_signal(&signal)
        .expect("remote browser routes do not allocate matching local sockets");
    assert_eq!(transport.resource_snapshot().created_total, 0);
    assert_eq!(transport.mdns_resolver.snapshot().owner_count, 0);
}

#[test]
fn oversized_remote_sdp_is_rejected_at_signal_admission() {
    let identity = crate::Identity::generate();
    let (packet_tx, _packet_rx) = crate::packet_channel(1);
    let transport = WebRtcTransport::new(
        TransportId::new(605),
        None,
        WebRtcConfig {
            stun_servers: Some(Vec::new()),
            ..WebRtcConfig::default()
        },
        packet_tx,
        &identity,
        &NostrDiscoveryConfig::default(),
    )
    .expect("WebRTC transport");
    let mut sdp = String::from("v=0\r\n");
    for index in 0..=MAX_WEBRTC_REMOTE_CANDIDATE_ROUTES {
        sdp.push_str(&format!(
            "a=candidate:{index} 1 UDP 1 192.0.2.1 {} typ host\r\n",
            5_000 + index
        ));
    }
    let now = now_ms();
    let signal = WebRtcSignal {
        version: crate::transport::link_negotiation::LINK_NEGOTIATION_VERSION,
        negotiation_id: "oversized-remote-sdp".into(),
        link_type: "webrtc".into(),
        kind: LinkNegotiationKind::Offer,
        created_at_ms: now,
        expires_at_ms: now + 1_000,
        payload: WebRtcSignalPayload {
            sdp: Some(sdp),
            candidates: None,
        },
    };

    assert!(transport.runtime().validate_signal(&signal).is_err());
    assert_eq!(transport.resource_snapshot().created_total, 0);
    assert_eq!(transport.mdns_resolver.snapshot().owner_count, 0);
}

#[test]
fn embedded_candidate_budget_deduplicates_components_but_caps_raw_lines() {
    let twins = concat!(
        "v=0\r\n",
        "a=candidate:same 1 UDP 1 192.0.2.10 5000 typ host\r\n",
        "a=candidate:same 2 UDP 1 192.0.2.10 5000 typ host\r\n",
    );
    let count = validate_embedded_ice_candidates(twins, EmbeddedCandidateScope::Remote)
        .expect("component twins");
    assert_eq!(count.raw_lines, 2);
    assert_eq!(count.unique_routes, 1);

    let mut duplicates = String::from("v=0\r\n");
    for index in 0..=MAX_WEBRTC_REMOTE_CANDIDATE_LINES {
        duplicates.push_str(&format!(
            "a=candidate:{index} 1 UDP 1 192.0.2.10 5000 typ host\r\n"
        ));
    }
    assert!(
        validate_embedded_ice_candidates(&duplicates, EmbeddedCandidateScope::Remote).is_err()
    );
}

#[tokio::test]
async fn oversized_embedded_offer_never_starts_mdns_or_allocates_a_pc() {
    let local = crate::Identity::generate();
    let remote = crate::Identity::generate();
    let (packet_tx, _packet_rx) = crate::packet_channel(1);
    let transport = WebRtcTransport::new(
        TransportId::new(602),
        None,
        WebRtcConfig {
            accept_connections: Some(true),
            max_connections: Some(1),
            resolve_mdns_candidates: Some(true),
            stun_servers: Some(Vec::new()),
            ..WebRtcConfig::default()
        },
        packet_tx,
        &local,
        &NostrDiscoveryConfig::default(),
    )
    .expect("WebRTC transport");
    let mut sdp = String::from("v=0\r\n");
    for index in 0..=MAX_WEBRTC_REMOTE_CANDIDATE_ROUTES {
        sdp.push_str(&format!(
            "a=candidate:{index} 1 UDP 1 one-host.local {} typ host\r\n",
            5_000 + index
        ));
    }
    let now = now_ms();
    let remote_full = remote.pubkey_full().serialize();
    let incoming = IncomingSignal {
        signal: WebRtcSignal {
            version: crate::transport::link_negotiation::LINK_NEGOTIATION_VERSION,
            negotiation_id: "pre-mdns-budget".into(),
            link_type: "webrtc".into(),
            kind: LinkNegotiationKind::Offer,
            created_at_ms: now,
            expires_at_ms: now + 1_000,
            payload: WebRtcSignalPayload {
                sdp: Some(sdp),
                candidates: None,
            },
        },
        sender: PublicKey::from_slice(&remote_full[1..]).expect("remote Nostr key"),
        sender_full_hex: hex::encode(remote_full),
    };

    let result = transport.runtime().handle_incoming_signal(incoming).await;
    assert!(matches!(result, Err(TransportError::InvalidAddress(_))));
    assert_eq!(
        transport.mdns_resolver.snapshot(),
        mdns::MdnsResolverSnapshot {
            owner_count: 0,
            max_waiters: 1,
            active_waiters: 0,
            peak_waiters: 0,
        }
    );
    assert_eq!(transport.resource_snapshot().created_total, 0);
    assert!(transport.seen_sessions.lock().await.is_empty());
}

#[test]
fn default_connection_capacity_fits_the_reviewed_configured_socket_budget() {
    let worst_case_per_pc = MAX_WEBRTC_HOST_CANDIDATE_SOCKETS
        + MAX_WEBRTC_STUN_SERVERS * MAX_WEBRTC_SOCKETS_PER_STUN_SERVER;
    let configured = WebRtcConfig::default().max_connections();
    assert_eq!(MAX_WEBRTC_LOCAL_CANDIDATE_ROUTES, worst_case_per_pc);
    assert!(
        configured * worst_case_per_pc <= MAX_WEBRTC_CONFIG_CANDIDATE_SOCKETS,
        "default {configured} peer connections can allocate {} candidate sockets; configured budget is {MAX_WEBRTC_CONFIG_CANDIDATE_SOCKETS}",
        configured * worst_case_per_pc
    );
}

#[tokio::test]
async fn failure_diagnostic_tracks_candidates_and_data_channel_stage() {
    let api = build_webrtc_api().expect("WebRTC API");
    let resources = PhysicalResources::new(1);
    let peer = resources
        .reserve(&TransportAddr::from_string("diagnostic-peer"))
        .expect("physical reservation")
        .activate(
            api.new_peer_connection(RTCConfiguration::default())
                .await
                .expect("peer connection"),
        );
    peer.record_local_candidates(EmbeddedCandidateCount {
        raw_lines: 2,
        unique_routes: 1,
    });
    peer.record_remote_candidates(EmbeddedCandidateCount {
        raw_lines: 4,
        unique_routes: 3,
    });
    peer.record_data_channel_wired();
    peer.record_data_channel_open();

    let open = peer.failure_stage_diagnostic();
    assert!(open.contains("dataChannel=Open"));
    assert!(open.contains("localCandidatesRawUnique=2/1"));
    assert!(open.contains("remoteCandidatesRawUnique=4/3"));

    peer.record_data_channel_closed();
    assert!(
        peer.failure_stage_diagnostic()
            .contains("dataChannel=Closed")
    );
    close_peer_connection_bounded(peer).await;
    assert!(resources.wait_for_quiescence(Duration::from_secs(3)).await);
}

#[tokio::test]
async fn failure_diagnostic_captures_local_description_candidate_progress() {
    let policy = CandidateAddressPolicy::loopback_udp4();
    let api = policy.build_api().expect("loopback WebRTC API");
    let resources = PhysicalResources::new(1);
    let peer = resources
        .reserve(&TransportAddr::from_string("partial-diagnostic-peer"))
        .expect("physical reservation")
        .activate(
            api.new_peer_connection(RTCConfiguration::default())
                .await
                .expect("peer connection"),
        );
    peer.create_data_channel("partial-diagnostic", None)
        .await
        .expect("data channel");
    let offer = peer.create_offer(None).await.expect("offer");
    let mut gathering = peer.gathering_complete_promise().await;
    peer.set_local_description(offer)
        .await
        .expect("local description");
    wait_for_ice_gathering(Duration::from_secs(1), &mut gathering)
        .await
        .expect("loopback gathering");

    WebRtcRuntime::record_partial_local_candidate_diagnostic(&peer).await;
    let diagnostic = peer.failure_stage_diagnostic();
    assert!(
        diagnostic.contains("localCandidatesRawUnique=2/1"),
        "unexpected candidate diagnostic: {diagnostic}"
    );

    close_peer_connection_bounded(peer).await;
    assert!(resources.wait_for_quiescence(Duration::from_secs(3)).await);
}
