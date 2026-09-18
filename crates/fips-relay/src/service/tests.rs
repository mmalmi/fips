use super::*;

#[path = "network_tests.rs"]
mod network_tests;

fn zero_default_fee_config() -> ServiceConfig {
    let mut config: ServiceConfig =
        serde_json::from_str(include_str!("../../service.example.json")).unwrap();
    config.terms.billing = BillingBasis::ForwardingData;
    config.terms.fee_msat_per_kib = 0;
    config
}

#[test]
fn public_configuration_accepts_zero_default_fee_and_free_only_ceiling() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("service.json");
    for max_rate in [0, 8_192] {
        let mut config = zero_default_fee_config();
        config.terms.max_rate_msat_per_kib = max_rate;
        std::fs::write(&path, serde_json::to_vec(&config).unwrap()).unwrap();
        let loaded = ServiceConfig::read(&path).expect("explicit free forwarding-data tariff");
        assert_eq!(loaded.terms, config.terms);
        assert!(loaded.destination_fees.is_empty());
    }
}

#[test]
fn zero_default_fee_does_not_enable_free_legacy_billing() {
    for billing in [
        BillingBasis::UniqueSessionEnvelope,
        BillingBasis::ForwardingAttempt,
    ] {
        let mut config = zero_default_fee_config();
        config.terms.billing = billing;
        assert!(config.validate().is_err(), "unsupported free {billing:?}");
        config.terms.fee_msat_per_kib = 1;
        config.validate().expect("existing positive tariff");
    }
}

#[test]
fn zero_price_ceiling_rejects_positive_default_and_destination_fees() {
    let mut config = zero_default_fee_config();
    config.terms.max_rate_msat_per_kib = 0;
    let destination = Identity::from_secret_bytes(&[91; 32]).unwrap().npub();
    config.destination_fees = serde_json::from_value(json!({destination.clone(): 0})).unwrap();
    config.validate().expect("all offered routes are free");

    config.terms.fee_msat_per_kib = 1;
    assert!(
        config.validate().is_err(),
        "global fee exceeds free-only ceiling"
    );
    config.terms.fee_msat_per_kib = 0;
    config.destination_fees = serde_json::from_value(json!({destination: 1})).unwrap();
    assert!(
        config.validate().is_err(),
        "destination fee exceeds free-only ceiling"
    );
}

#[test]
fn free_default_keeps_positive_destination_fees_within_the_price_ceiling() {
    let mut config = zero_default_fee_config();
    config.terms.max_rate_msat_per_kib = 7;
    let destination = Identity::from_secret_bytes(&[92; 32]).unwrap().npub();
    config.destination_fees = serde_json::from_value(json!({destination.clone(): 7})).unwrap();
    config
        .validate()
        .expect("paid exception at the configured ceiling");
    config.destination_fees = serde_json::from_value(json!({destination: 8})).unwrap();
    assert!(config.validate().is_err(), "paid exception exceeds ceiling");
}

#[test]
fn price_selection_is_opt_in_and_validated_outside_financial_terms() {
    let mut config: ServiceConfig =
        serde_json::from_str(include_str!("../../service.example.json")).unwrap();
    assert!(config.price_selection.is_none());
    config.price_selection = Some(Default::default());
    assert!(config.validate().unwrap_err().contains("forwarding-data"));
    config.terms.billing = BillingBasis::ForwardingData;
    config.validate().unwrap();
    config.price_selection.as_mut().unwrap().trial_max_units = 0;
    assert!(config.validate().is_err());
}

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
fn free_bandwidth_is_opt_in_and_rejects_invalid_or_legacy_configuration() {
    let mut value: Value =
        serde_json::from_str(include_str!("../../service.example.json")).unwrap();
    let original: ServiceConfig = serde_json::from_value(value.clone()).unwrap();
    assert!(original.free_bandwidth.is_none());
    value["free_bandwidth"] = json!({
        "global_bytes_per_second": 16_384,
        "global_burst_bytes": 32_768,
        "peer_bytes_per_second": 4_096,
        "peer_burst_bytes": 8_192
    });
    let legacy: ServiceConfig = serde_json::from_value(value.clone()).unwrap();
    assert!(legacy.validate().unwrap_err().contains("forwarding-data"));
    value["terms"]["billing"] = json!("forwarding_data");
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("service.json");
    std::fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();
    let loaded = ServiceConfig::read(&path).unwrap();
    assert_eq!(loaded.free_bandwidth.unwrap().peer_bytes_per_second, 4_096);
    for (field, invalid) in [
        ("global_bytes_per_second", 0),
        ("peer_bytes_per_second", 0),
        ("peer_bytes_per_second", 16_385),
        ("peer_burst_bytes", 255),
        ("peer_burst_bytes", 32_769),
    ] {
        let mut rejected = value.clone();
        rejected["free_bandwidth"][field] = json!(invalid);
        std::fs::write(&path, serde_json::to_vec(&rejected).unwrap()).unwrap();
        assert!(ServiceConfig::read(&path).is_err(), "invalid {field}");
    }
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
    assert!(forwarding.admit_classified(&request).is_none());
    assert_eq!(
        forwarding.relay.bootstrap_stats().unwrap().admitted_packets,
        0
    );
    request.session_payload = &[1, 2, 3, 4];
    assert!(forwarding.admit(&request).is_none());
    assert_eq!(seller.channel_usage("channel").unwrap().reserved_msat, 0);
    forwarding.ready.store(true, Ordering::Release);
    let token = forwarding
        .admit_classified(&request)
        .expect("validated startup exposes the existing allowance");
    assert_eq!(token.class, fips_core::node::ForwardingClass::Normal);
    request.session_payload = &handshake;
    let free = forwarding.admit_classified(&request).unwrap();
    assert_eq!(free.token, 0);
    assert_eq!(free.class, fips_core::node::ForwardingClass::Control);
    forwarding.complete(free.token, ForwardingOutcome::Submitted);
    forwarding.complete(free.token, ForwardingOutcome::Unconfirmed);
    assert_eq!(seller.channel_usage("channel").unwrap().submitted_msat, 0);
    forwarding.complete(token.token, ForwardingOutcome::Submitted);
    assert_eq!(seller.channel_usage("channel").unwrap().submitted_msat, 4);
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
