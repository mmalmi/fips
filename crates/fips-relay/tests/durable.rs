use fips_core::{
    Identity, NodeAddr, PeerIdentity,
    node::{ForwardingOutcome, ForwardingPolicy, ForwardingRequest},
};
use fips_relay::{
    durable::DurableRelay,
    ledger::{BytePrice, ChannelTerms, Contract, Limits},
};

fn buyer() -> PeerIdentity {
    PeerIdentity::from_pubkey_full(Identity::from_secret_bytes(&[1; 32]).unwrap().pubkey_full())
}

fn channel() -> ChannelTerms {
    ChannelTerms {
        id: "neighbor".into(),
        buyer: *buyer().node_addr(),
        mint_url: "http://127.0.0.1:1234".into(),
        expires_unix: u64::MAX,
        capacity_sat: 1,
        grace_msat: 30,
    }
}

fn contract() -> Contract {
    Contract {
        id: "quote".into(),
        channel_id: "neighbor".into(),
        destination: NodeAddr::from_bytes([9; 16]),
        next_hop: NodeAddr::from_bytes([2; 16]),
        expires_unix: u64::MAX,
        price: BytePrice {
            msat: 1,
            per_bytes: 1,
        },
        max_units: 1_000,
    }
}

fn request(bytes: &[u8]) -> ForwardingRequest<'_> {
    ForwardingRequest {
        ingress: buyer(),
        source: NodeAddr::from_bytes([8; 16]),
        destination: contract().destination,
        next_hop: contract().next_hop,
        session_payload: bytes,
    }
}

fn start(path: &std::path::Path) -> DurableRelay {
    let relay = DurableRelay::create(path, Limits::default(), 10).unwrap();
    relay.open_channel_verified(channel(), 0).unwrap();
    relay.add_contract(contract()).unwrap();
    relay
}

#[test]
fn renewal_carries_unbilled_crash_exposure_without_creating_another_grace() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("relay");
    let relay = start(&path);
    drop(relay); // An unrecorded ten-msat window must remain reserved.
    let relay = DurableRelay::load(&path).unwrap();
    let old = relay.seal_channel("neighbor").unwrap();
    assert_eq!((old.lost_msat, old.submitted_msat), (10, 0));
    let mut next = channel();
    next.id = "renewed".into();
    relay.open_channel_verified(next, 0).unwrap();
    let mut quote = contract();
    quote.id = "renewed-quote".into();
    quote.channel_id = "renewed".into();
    relay.add_contract(quote).unwrap();
    let token = relay.admit(&request(b"0123456789")).unwrap();
    relay.complete(token, ForwardingOutcome::Submitted);
    relay.checkpoint().unwrap();
    let token = relay.admit(&request(b"abcdefghij")).unwrap();
    relay.complete(token, ForwardingOutcome::Submitted);
    assert!(relay.admit(&request(b"x")).is_none());
    let claims = relay.checkpoint().unwrap();
    assert_eq!(claims["neighbor"].submitted_msat, 0);
    assert_eq!(claims["renewed"].submitted_msat, 20);
    relay.apply_verified_balance("renewed", 20).unwrap();
    assert!(relay.admit(&request(b"paid")).is_some());
    relay.suspend().unwrap();
    drop(relay);
    let relay = DurableRelay::load(&path).unwrap();
    assert_eq!(relay.channel_usage("neighbor").unwrap().lost_msat, 10);
    assert_eq!(relay.channel_usage("renewed").unwrap().submitted_msat, 20);
    assert!(relay.admit(&request(b"0123456789")).is_none());
}

#[test]
fn sealing_freezes_the_final_claim_and_keeps_late_sends_unconfirmed() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("relay");
    let relay = start(&path);
    let token = relay.admit(&request(b"pending")).unwrap();
    let final_usage = relay.seal_channel("neighbor").unwrap();
    assert_eq!(
        (final_usage.reserved_msat, final_usage.submitted_msat),
        (7, 0)
    );
    relay.complete(token, ForwardingOutcome::Submitted);
    assert_eq!(relay.checkpoint().unwrap()["neighbor"], final_usage);
    assert_eq!(relay.usage("quote").unwrap().unconfirmed_units, 7);
    drop(relay);
    let relay = DurableRelay::load(&path).unwrap();
    assert_eq!(relay.channel_usage("neighbor").unwrap(), final_usage);
    assert!(relay.admit(&request(b"new")).is_none());
}

#[test]
fn windows_are_durable_before_admission_and_crashes_never_reset_grace() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("relay");
    let relay = start(&path);
    assert!(
        relay.admit(&request(&[0; 11])).is_none(),
        "window is smaller than total grace"
    );
    let token = relay.admit(&request(b"abcd")).unwrap();
    relay.complete(token, ForwardingOutcome::Submitted);
    // Simulate process loss without a checkpoint, including the submitted record.
    drop(relay);
    let relay = DurableRelay::load(&path).unwrap();
    let usage = relay.channel_usage("neighbor").unwrap();
    assert_eq!(
        (usage.reserved_msat, usage.submitted_msat, usage.lost_msat),
        (10, 0, 10)
    );
    assert!(relay.admit(&request(b"new")).is_some());
    drop(relay);
    let relay = DurableRelay::load(&path).unwrap();
    assert_eq!(relay.channel_usage("neighbor").unwrap().lost_msat, 20);
    drop(relay);
    let relay = DurableRelay::load(&path).unwrap();
    assert_eq!(relay.channel_usage("neighbor").unwrap().lost_msat, 30);
    assert!(
        relay.admit(&request(b"x")).is_none(),
        "repeated restarts exhaust the same allowance"
    );
    assert_eq!(
        relay.checkpoint().unwrap()["neighbor"].submitted_msat,
        0,
        "unknown attempts are never billed"
    );
    relay.apply_verified_balance("neighbor", 10).unwrap();
    assert!(
        relay.admit(&request(b"x")).is_some(),
        "explicit additional credit allows conservative recovery"
    );
}

#[test]
fn claims_are_checkpointed_and_replay_history_survives_recovery() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("relay");
    let relay = start(&path);
    let token = relay.admit(&request(b"abcd")).unwrap();
    relay.complete(token, ForwardingOutcome::Submitted);
    let claim = relay.checkpoint().unwrap();
    assert_eq!(claim["neighbor"].submitted_msat, 4);
    let pending = relay.admit(&request(b"pending")).unwrap();
    let claim = relay.checkpoint().unwrap();
    assert_eq!(claim["neighbor"].submitted_msat, 4);
    // The result arriving after the checkpoint may not be included in its claim.
    relay.complete(pending, ForwardingOutcome::Submitted);
    drop(relay);
    let relay = DurableRelay::load(&path).unwrap();
    let usage = relay.channel_usage("neighbor").unwrap();
    assert_eq!(
        (usage.reserved_msat, usage.submitted_msat, usage.lost_msat),
        (21, 4, 10)
    );
    assert_eq!(relay.usage("quote").unwrap().unconfirmed_units, 7);
    assert!(relay.admit(&request(b"abcd")).is_none());
    assert!(relay.admit(&request(b"pending")).is_none());
    assert!(relay.admit(&request(b"new")).is_some());
}

#[test]
fn orderly_restart_reuses_channel_and_quotes_without_losing_an_unused_window() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("relay");
    let relay = start(&path);
    let token = relay.admit(&request(b"abc")).unwrap();
    relay.complete(token, ForwardingOutcome::Submitted);
    assert_eq!(relay.suspend().unwrap()["neighbor"].submitted_msat, 3);
    assert!(relay.admit(&request(b"new")).is_none());
    drop(relay);
    let relay = DurableRelay::load(&path).unwrap();
    assert_eq!(relay.channel_usage("neighbor").unwrap().lost_msat, 0);
    assert_eq!(relay.channel_usage("neighbor").unwrap().reserved_msat, 3);
    assert!(relay.admit(&request(b"abc")).is_none());
    assert!(relay.admit(&request(b"new")).is_some());
}

#[test]
fn close_and_quote_changes_are_durable_without_reactivating_old_terms() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("relay");
    let relay = start(&path);
    let token = relay.admit(&request(b"paid")).unwrap();
    relay.complete(token, ForwardingOutcome::Submitted);
    relay.close_contract("quote").unwrap();
    drop(relay);
    let relay = DurableRelay::load(&path).unwrap();
    assert_eq!(
        relay.channel_usage("neighbor").unwrap().lost_msat,
        0,
        "a closed quote grants no crash window"
    );
    relay.add_contract(contract()).unwrap();
    assert!(relay.admit(&request(b"no")).is_none());
    let mut replacement = contract();
    replacement.id = "replacement".into();
    relay.add_contract(replacement).unwrap();
    assert!(relay.admit(&request(b"paid")).is_none());
    assert!(relay.admit(&request(b"new")).is_some());
    relay.close_channel("neighbor").unwrap();
    drop(relay);
    let relay = DurableRelay::load(&path).unwrap();
    relay.open_channel_verified(channel(), 0).unwrap();
    relay.apply_verified_balance("neighbor", 10).unwrap();
    assert!(relay.admit(&request(b"closed")).is_none());
}

#[test]
fn exclusive_owner_corruption_and_failed_persistence_fail_closed() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("relay");
    let relay = start(&path);
    assert!(DurableRelay::load(&path).is_err());
    assert!(DurableRelay::create(&path, Limits::default(), 10).is_err());
    // Making the destination a directory makes the atomic replace fail.
    std::fs::remove_file(path.join("ledger.json")).unwrap();
    std::fs::create_dir(path.join("ledger.json")).unwrap();
    assert!(relay.checkpoint().is_err());
    assert!(relay.admit(&request(b"x")).is_none());
    assert!(
        relay.checkpoint().is_err(),
        "a failed writer requires restart/recovery"
    );
    drop(relay);
    assert!(DurableRelay::load(&path).is_err());
    std::fs::remove_dir(path.join("ledger.json")).unwrap();
    std::fs::write(path.join("ledger.json"), b"{broken").unwrap();
    assert!(DurableRelay::load(&path).is_err());
}

#[test]
fn malformed_recovery_windows_cannot_create_credit() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("relay");
    drop(start(&path));
    let original: serde_json::Value =
        serde_json::from_slice(&std::fs::read(path.join("ledger.json")).unwrap()).unwrap();
    let mut cases = Vec::new();
    let mut oversized = original.clone();
    oversized["ceilings"]["neighbor"] = 31.into();
    cases.push(oversized);
    let mut absent = original.clone();
    absent["ceilings"] = serde_json::json!({});
    cases.push(absent);
    let mut closed = original.clone();
    closed["ledger"]["channels"][0]["active"] = false.into();
    cases.push(closed);
    let mut lost = original.clone();
    lost["ledger"]["channels"][0]["usage"]["lost_msat"] = 1.into();
    cases.push(lost);
    let mut version = original;
    version["version"] = 999.into();
    cases.push(version);
    for malformed in cases {
        std::fs::write(
            path.join("ledger.json"),
            serde_json::to_vec(&malformed).unwrap(),
        )
        .unwrap();
        assert!(DurableRelay::load(&path).is_err());
    }
}

#[cfg(unix)]
#[test]
fn journal_and_owner_directory_are_private() {
    use std::os::unix::fs::PermissionsExt;
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("relay");
    let _relay = start(&path);
    assert_eq!(
        std::fs::metadata(&path).unwrap().permissions().mode() & 0o077,
        0
    );
    assert_eq!(
        std::fs::metadata(path.join("ledger.json"))
            .unwrap()
            .permissions()
            .mode()
            & 0o077,
        0
    );
}
