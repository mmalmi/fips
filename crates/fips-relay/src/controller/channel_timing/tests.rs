use super::*;

#[test]
fn explicit_deadlines_survive_reload_and_legacy_requests_keep_their_original_expiry() {
    let legacy = crate::controller::tests::unresolved_journal();
    let legacy_request = legacy.funding["test-1"]
        .wallet_request(&legacy.policy)
        .unwrap();
    assert_eq!(legacy_request.expiry_unix, 760);
    let bytes = serde_json::to_vec(&legacy).unwrap();
    let restored: Journal = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(
        restored.funding["test-1"]
            .wallet_request(&restored.policy)
            .unwrap()
            .expiry_unix,
        760
    );
    for lifetime in [60, 600, ControllerPolicy::DEFAULT_CHANNEL_LIFETIME_SECS] {
        let mut j = legacy.clone();
        j.policy.channel_lifetime_secs = lifetime;
        j.version |= journal::FUNDING_DEADLINES_VERSION;
        let f = j.funding.get_mut("test-1").unwrap();
        f.expires_unix = f.created_unix + lifetime / 2;
        f.refund_after_unix = Some(f.created_unix + lifetime);
        Controller::validate_journal(&j, &j.policy, j.local).unwrap();
        let decoded: Journal = serde_json::from_slice(&serde_json::to_vec(&j).unwrap()).unwrap();
        let f = &decoded.funding["test-1"];
        assert_eq!(
            f.wallet_request(&decoded.policy).unwrap().expiry_unix,
            f.created_unix + lifetime
        );
        assert_eq!(f.expires_unix, f.created_unix + lifetime / 2);
        for changed in 0..3 {
            let mut bad = decoded.clone();
            match changed {
                0 => bad.version &= !journal::FUNDING_DEADLINES_VERSION,
                1 => {
                    *bad.funding
                        .get_mut("test-1")
                        .unwrap()
                        .refund_after_unix
                        .as_mut()
                        .unwrap() += 1
                }
                _ => bad.funding.get_mut("test-1").unwrap().expires_unix += 1,
            }
            assert!(Controller::validate_journal(&bad, &bad.policy, bad.local).is_err());
        }
    }
    let mut config = serde_json::to_value(&legacy.policy).unwrap();
    config
        .as_object_mut()
        .unwrap()
        .remove("channel_lifetime_secs");
    let defaults: ControllerPolicy = serde_json::from_value(config).unwrap();
    assert_eq!(defaults.channel_lifetime_secs, 24 * 60 * 60);
    assert_eq!(defaults.service_lifetime_secs(), 12 * 60 * 60);
}
