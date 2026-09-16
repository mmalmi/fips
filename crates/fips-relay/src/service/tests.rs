use super::*;

#[test]
fn return_allowance_is_explicit_and_cannot_change_legacy_tariffs() {
    let mut config: ServiceConfig =
        serde_json::from_str(include_str!("../../service.example.json")).unwrap();
    assert!(!config.return_allowance);
    config.return_allowance = true;
    assert!(config.validate().unwrap_err().contains("forwarding-data"));
    config.terms.billing = BillingBasis::ForwardingData;
    config.validate().unwrap();
}

#[test]
fn restored_allowance_is_inaccessible_until_service_startup_finishes() {
    use crate::ledger::{BytePrice, ChannelTerms, Contract};
    let directory = tempfile::tempdir().unwrap();
    let ingress = PeerIdentity::from_pubkey_full(Identity::generate().pubkey_full());
    let destination = *Identity::generate().node_addr();
    let local = *Identity::generate().node_addr();
    let seller = Arc::new(
        DurableRelay::create(&directory.path().join("seller"), Limits::default(), 100).unwrap(),
    );
    let buyer = Arc::new(
        BuyerAuthorizer::create(&directory.path().join("buyer"), local, 1, Limits::default())
            .unwrap(),
    );
    let expires = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
        + 60;
    seller
        .open_channel_verified(
            ChannelTerms {
                id: "channel".into(),
                buyer: *ingress.node_addr(),
                mint_url: "http://test.invalid".into(),
                capacity_sat: 1,
                grace_msat: 100,
                expires_unix: expires,
            },
            0,
        )
        .unwrap();
    seller
        .add_contract(Contract {
            billing: BillingBasis::ForwardingData,
            id: "route".into(),
            channel_id: "channel".into(),
            destination,
            next_hop: destination,
            price: BytePrice {
                msat: 1,
                per_bytes: 1,
            },
            max_units: 100,
            expires_unix: expires,
        })
        .unwrap();
    let forwarding = ServiceForwarder {
        relay: PaidForwarder::for_billing(seller.clone(), buyer, BillingBasis::ForwardingData),
        ready: AtomicBool::new(false),
    };
    let handshake =
        fips_core::protocol::SessionMsg3::new(vec![0; fips_core::noise::XK_HANDSHAKE_MSG3_SIZE])
            .encode();
    let mut request = ForwardingRequest {
        ingress,
        source: *ingress.node_addr(),
        destination,
        next_hop: destination,
        session_payload: &handshake,
    };
    assert!(forwarding.admit(&request).is_none());
    assert_eq!(
        forwarding.relay.bootstrap_stats().unwrap().admitted_packets,
        0
    );
    request.session_payload = &[1, 2, 3, 4];
    assert!(forwarding.admit(&request).is_none());
    assert_eq!(seller.channel_usage("channel").unwrap().reserved_msat, 0);
    forwarding.ready.store(true, Ordering::Release);
    let token = forwarding
        .admit(&request)
        .expect("validated startup exposes the existing allowance");
    request.session_payload = &handshake;
    let free = forwarding.admit(&request).unwrap();
    assert_eq!(free, 0);
    forwarding.complete(free, ForwardingOutcome::Submitted);
    forwarding.complete(free, ForwardingOutcome::Unconfirmed);
    assert_eq!(seller.channel_usage("channel").unwrap().submitted_msat, 0);
    forwarding.complete(token, ForwardingOutcome::Submitted);
    assert_eq!(seller.channel_usage("channel").unwrap().submitted_msat, 4);
}

#[test]
fn native_interface_configuration_has_no_implicit_udp_or_discovery_shortcut() {
    let config = ServiceConfig {
        state_directory: "/tmp/fips-relay-example".into(),
        udp_bind: None,
        customer_network: None,
        destination_fees: Default::default(),
        return_allowance: false,
        payment_cadence: Default::default(),
        ethernet_interfaces: vec!["mesh0".into()],
        neighbors: vec![],
        terms: ServiceTerms {
            billing: Default::default(),
            controller: ControllerPolicy {
                mint_url: "http://127.0.0.1:3338".into(),
                channel_capacity_sat: 32,
                max_locked_sat: 64,
                channel_lifetime_secs: 600,
                renewal: None,
            },
            buyer_budget_sat: 64,
            window_msat: 4_000,
            grace_msat: 8_000,
            fee_msat_per_kib: 1_024,
            max_rate_msat_per_kib: 8_192,
            quote_lifetime_secs: 300,
            quote_max_units: 30_000,
        },
    };
    config.validate().unwrap();
    let native = config.network(&Identity::generate(), false);
    assert!(native.transports.udp.is_empty());
    assert!(native.transports.tcp.is_empty());
    assert!(!native.node.discovery.nostr.enabled);
    assert!(!native.node.discovery.lan.enabled);
    assert!(!native.node.discovery.local.enabled);
    let TransportInstances::Named(interfaces) = native.transports.ethernet else {
        panic!("explicit interfaces");
    };
    assert_eq!(interfaces.len(), 1);
    assert_eq!(interfaces["mesh0"].interface, "mesh0");
    assert_eq!(interfaces["mesh0"].ethertype(), 0x2121);
    assert_eq!(interfaces["mesh0"].discovery, Some(false));
    assert_eq!(interfaces["mesh0"].auto_connect, Some(false));
    let mut invalid = config;
    invalid.neighbors.push(PeerConfig::new(
        Identity::generate().npub(),
        "udp",
        "127.0.0.1:2121",
    ));
    assert!(
        invalid.validate().is_err(),
        "unconfigured transport cannot become a fallback"
    );
}

#[test]
fn customer_entry_requires_an_explicit_matching_listener_and_bounded_native_state() {
    let mut config: ServiceConfig =
        serde_json::from_str(include_str!("../../service.example.json")).unwrap();
    assert!(
        config.customer_network.is_none(),
        "existing accounts remain neighbor-only"
    );
    config.customer_network = Some("192.0.2.0/24".parse().unwrap());
    for bind in [
        None,
        Some("0.0.0.0:2121"),
        Some("198.51.100.1:2121"),
        Some("[::1]:2121"),
    ] {
        config.udp_bind = bind.map(|s| s.parse().unwrap());
        assert!(
            config.validate().is_err(),
            "mismatched customer bind: {bind:?}"
        );
    }
    config.udp_bind = Some("192.0.2.1:2121".parse().unwrap());
    config.validate().unwrap();
    let native = config.network(&Identity::generate(), false);
    assert_eq!(native.node.limits.max_peers, config.neighbors.len() + 16);
    assert_eq!(native.node.limits.max_pending_inbound, 16);
    assert_eq!(native.node.limits.max_sessions, 128);
    config.customer_network = Some("0.0.0.0/0".parse().unwrap());
    assert!(config.validate().is_err());
    config.customer_network = Some("fd00::/64".parse().unwrap());
    config.udp_bind = Some("[fd00::1]:2121".parse().unwrap());
    config.validate().unwrap();
}

#[test]
fn cadence_is_local_configuration_and_old_configs_keep_the_default() {
    let original: ServiceConfig =
        serde_json::from_str(include_str!("../../service.example.json")).unwrap();
    assert_eq!(original.payment_cadence.max_delay_ms, 500);
    let encoded = serde_json::to_value(&original).unwrap();
    assert!(encoded.get("payment_cadence").is_none());
    let mut changed = original.clone();
    changed.payment_cadence.max_delay_ms = 2_000;
    changed.validate().unwrap();
    assert_eq!(changed.terms, original.terms);
    changed.payment_cadence.unpaid_percent = 100;
    assert!(changed.validate().is_err());
}
