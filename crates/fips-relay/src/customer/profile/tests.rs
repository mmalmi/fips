use super::*;
use fips_core::Identity;
use serde_json::{Value, json};

fn saved_original() -> Value {
    json!({
        "version": 1, "test_only": true,
        "entry_npub": Identity::generate().npub(),
        "entry_address": "127.0.0.1:2121",
        "destination_npub": Identity::generate().npub(),
        "mint_url": "http://127.0.0.1:3338", "budget_sat": 128,
        "channel_capacity_sat": 32, "max_rate_msat_per_kib": 8192
    })
}

#[test]
fn absent_billing_retains_exact_original_tariff_and_service_configuration() {
    let saved = saved_original();
    assert!(saved.get("billing").is_none());
    let original: CustomerProfile = serde_json::from_value(saved.clone()).unwrap();
    original.validate().unwrap();
    assert_eq!(original.billing, BillingBasis::ForwardingAttempt);
    assert_eq!(
        original.config(Path::new("/customer")).terms.billing,
        BillingBasis::ForwardingAttempt
    );
    let mut explicit = saved;
    explicit["billing"] = json!("forwarding_attempt");
    let explicit: CustomerProfile = serde_json::from_value(explicit).unwrap();
    assert_eq!(original, explicit);
    assert_eq!(
        serde_json::to_value(original.config(Path::new("/customer"))).unwrap(),
        serde_json::to_value(explicit.config(Path::new("/customer"))).unwrap()
    );
}

#[test]
fn supported_billing_is_immutable_serialized_policy_and_changes_only_service_tariff() {
    let original: CustomerProfile = serde_json::from_value(saved_original()).unwrap();
    let original_config = serde_json::to_value(original.config(Path::new("/customer"))).unwrap();
    for billing in [
        BillingBasis::ForwardingAttempt,
        BillingBasis::ForwardingData,
    ] {
        let mut chosen = original.clone();
        chosen.billing = billing;
        chosen.validate().unwrap();
        let encoded = serde_json::to_value(&chosen).unwrap();
        assert_eq!(encoded["billing"], serde_json::to_value(billing).unwrap());
        let restored: CustomerProfile = serde_json::from_value(encoded).unwrap();
        assert_eq!(restored, chosen);
        let mut expected = original_config.clone();
        expected["terms"]["billing"] = serde_json::to_value(billing).unwrap();
        assert_eq!(
            serde_json::to_value(restored.config(Path::new("/customer"))).unwrap(),
            expected
        );
        assert_eq!(
            chosen == original,
            billing == BillingBasis::ForwardingAttempt
        );
    }
}

#[test]
fn legacy_and_malformed_billing_never_fall_back_to_another_tariff() {
    let mut saved = saved_original();
    saved["billing"] = json!("unique_session_envelope");
    let unsupported: CustomerProfile = serde_json::from_value(saved.clone()).unwrap();
    assert!(unsupported.validate().is_err());
    for invalid in [Value::Null, json!("forwarding_date"), json!(0)] {
        saved["billing"] = invalid;
        assert!(serde_json::from_value::<CustomerProfile>(saved.clone()).is_err());
    }
}
