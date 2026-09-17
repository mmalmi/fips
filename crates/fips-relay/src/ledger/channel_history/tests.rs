use super::*;
use crate::durable::DurableRelay;
use fips_core::{Identity, PeerIdentity};

fn peer(n: u8) -> PeerIdentity {
    PeerIdentity::from_pubkey_full(Identity::from_secret_bytes(&[n; 32]).unwrap().pubkey_full())
}

fn terms(n: u64, buyer: u8) -> ChannelTerms {
    ChannelTerms {
        id: format!("channel-{n}"),
        buyer: *peer(buyer).node_addr(),
        mint_url: "http://test.invalid".into(),
        expires_unix: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 1000
            + n,
        capacity_sat: 10,
        grace_msat: 4000,
    }
}

fn open(seller: &DurableRelay, terms: &ChannelTerms, paid: u64) {
    seller.open_channel_verified(terms.clone(), paid).unwrap();
    seller
        .add_contract(Contract {
            id: format!("quote-{}", terms.id),
            channel_id: terms.id.clone(),
            destination: *peer(9).node_addr(),
            next_hop: *peer(8).node_addr(),
            expires_unix: terms.expires_unix,
            price: BytePrice {
                msat: 1,
                per_bytes: 1,
            },
            max_units: 10_000,
            billing: BillingBasis::ForwardingAttempt,
        })
        .unwrap();
}

fn send(seller: &DurableRelay, buyer: u8) -> Option<u64> {
    seller.admit(&ForwardingRequest {
        ingress: peer(buyer),
        source: *peer(buyer).node_addr(),
        destination: *peer(9).node_addr(),
        next_hop: *peer(8).node_addr(),
        session_payload: &[1; 1000],
    })
}

fn seal(seller: &DurableRelay, terms: &ChannelTerms) -> Plan {
    seller.seal_channel(&terms.id).unwrap();
    seller
        .retire_closed_routes(&terms.id, terms.expires_unix)
        .unwrap();
    seller
        .channel_retirement_plan(std::slice::from_ref(&terms.id), terms.expires_unix + 1)
        .unwrap()
}

#[test]
fn completed_seller_channels_recycle_slots_and_retain_totals_across_restarts() {
    let root = tempfile::tempdir().unwrap();
    let directory = root.path().join("seller");
    let mut seller = DurableRelay::create(
        &directory,
        Limits {
            max_channels: 1,
            max_contracts: 1,
            ..Limits::default()
        },
        1000,
    )
    .unwrap();
    for n in 1..=64 {
        let t = terms(n, 1);
        open(&seller, &t, 1000);
        seller.complete(send(&seller, 1).unwrap(), ForwardingOutcome::Submitted);
        let plan = seal(&seller, &t);
        seller.retire_channels(&plan).unwrap();
        assert_eq!(plan.after.channels, n);
        assert_eq!(plan.after.usage.reserved_msat, n * 1000);
        assert_eq!(plan.after.usage.submitted_msat, n * 1000);
        assert_eq!(plan.after.usage.paid_msat, n * 1000);
        assert!(plan.after.debts.is_empty());
        assert!(seller.channel_usage(&t.id).is_none());
        let path = directory.join("ledger.json");
        let modified = std::fs::metadata(&path).unwrap().modified().unwrap();
        seller.retire_channels(&plan).unwrap();
        assert_eq!(
            std::fs::metadata(&path).unwrap().modified().unwrap(),
            modified
        );
        assert!(std::fs::metadata(&path).unwrap().len() < 2200);
        assert!(!seller.checkpoint_due().unwrap());
        assert!(seller.open_channel_verified(t.clone(), 1000).is_err());
        let mut renamed = t;
        renamed.id.push_str("-renamed");
        assert!(seller.open_channel_verified(renamed, 0).is_err());
        drop(seller);
        seller = DurableRelay::load(&directory).unwrap();
    }
}

#[test]
fn unpaid_usage_survives_new_channels_and_unrelated_overpayments() {
    let root = tempfile::tempdir().unwrap();
    let directory = root.path().join("seller");
    let seller = DurableRelay::create(&directory, Limits::default(), 1000).unwrap();
    let first = terms(1, 1);
    open(&seller, &first, 0);
    seller.complete(send(&seller, 1).unwrap(), ForwardingOutcome::Submitted);
    let plan = seal(&seller, &first);
    seller.retire_channels(&plan).unwrap();
    assert_eq!(plan.after.debt(&first), 1000);
    drop(seller);
    let seller = DurableRelay::load(&directory).unwrap();
    let next = terms(2, 1);
    open(&seller, &next, 0);
    for _ in 0..3 {
        seller.complete(send(&seller, 1).unwrap(), ForwardingOutcome::Submitted);
        seller.checkpoint().unwrap();
    }
    assert!(
        send(&seller, 1).is_none(),
        "old debt consumes the fourth free packet"
    );
    assert_eq!(
        seller.channel_usage(&next.id).unwrap().submitted_msat,
        3000,
        "old usage is never billed again"
    );
    seller.apply_verified_balance(&next.id, 1000).unwrap();
    seller.complete(send(&seller, 1).unwrap(), ForwardingOutcome::Submitted);
    let plan = seal(&seller, &next);
    seller.retire_channels(&plan).unwrap();
    assert_eq!(plan.after.debt(&next), 4000);
    let third = terms(3, 1);
    assert!(seller.open_channel_verified(third.clone(), 0).is_err());
    // This channel is overpaid but forwards nothing; it cannot erase another
    // channel's positive unpaid exposure by netting aggregate balances.
    open(&seller, &third, 5000);
    let plan = seal(&seller, &third);
    seller.retire_channels(&plan).unwrap();
    assert_eq!(plan.after.debt(&third), 4000);
    assert!(seller.open_channel_verified(terms(4, 1), 0).is_err());
    seller.open_channel_verified(terms(4, 2), 0).unwrap();
    let mut other_mint = terms(5, 1);
    other_mint.mint_url = "http://another.invalid".into();
    seller.open_channel_verified(other_mint, 0).unwrap();
}

#[test]
fn crashed_windows_remain_unpaid_without_becoming_a_claim() {
    let root = tempfile::tempdir().unwrap();
    let directory = root.path().join("seller");
    let seller = DurableRelay::create(&directory, Limits::default(), 1000).unwrap();
    let t = terms(1, 1);
    open(&seller, &t, 0);
    drop(seller);
    let seller = DurableRelay::load(&directory).unwrap();
    let plan = seal(&seller, &t);
    assert_eq!(plan.after.usage.lost_msat, 1000);
    assert_eq!(plan.after.usage.submitted_msat, 0);
    assert_eq!(plan.after.debt(&t), 1000);
    seller.retire_channels(&plan).unwrap();
    drop(seller);
    let seller = DurableRelay::load(&directory).unwrap();
    let next = terms(2, 1);
    open(&seller, &next, 0);
    for _ in 0..3 {
        seller.complete(send(&seller, 1).unwrap(), ForwardingOutcome::Submitted);
        seller.checkpoint().unwrap();
    }
    assert!(send(&seller, 1).is_none());
    assert_eq!(seller.channel_usage(&next.id).unwrap().submitted_msat, 3000);
}

#[test]
fn full_debt_history_retains_new_evidence_instead_of_dropping_an_identity() {
    let root = tempfile::tempdir().unwrap();
    let directory = root.path().join("seller");
    let seller = DurableRelay::create(
        &directory,
        Limits {
            max_channels: 1,
            ..Limits::default()
        },
        1000,
    )
    .unwrap();
    let first = terms(1, 1);
    open(&seller, &first, 0);
    seller.complete(send(&seller, 1).unwrap(), ForwardingOutcome::Submitted);
    seller.retire_channels(&seal(&seller, &first)).unwrap();
    let next = terms(2, 2);
    open(&seller, &next, 0);
    seller.complete(send(&seller, 2).unwrap(), ForwardingOutcome::Submitted);
    seller.seal_channel(&next.id).unwrap();
    seller
        .retire_closed_routes(&next.id, next.expires_unix)
        .unwrap();
    assert!(
        seller
            .channel_retirement_plan(std::slice::from_ref(&next.id), next.expires_unix + 1)
            .is_err()
    );
    assert_eq!(seller.channel_usage(&next.id).unwrap().reserved_msat, 1000);
    drop(seller);
    let seller = DurableRelay::load(&directory).unwrap();
    assert_eq!(seller.channel_usage(&next.id).unwrap().reserved_msat, 1000);
}

#[test]
fn missing_or_inconsistent_retired_debt_cannot_restore_an_allowance() {
    let root = tempfile::tempdir().unwrap();
    let directory = root.path().join("seller");
    let seller = DurableRelay::create(&directory, Limits::default(), 1000).unwrap();
    let t = terms(1, 1);
    open(&seller, &t, 0);
    seller.complete(send(&seller, 1).unwrap(), ForwardingOutcome::Submitted);
    seller.retire_channels(&seal(&seller, &t)).unwrap();
    drop(seller);
    let path = directory.join("ledger.json");
    let original: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    for mode in 0..5 {
        let mut j = original.clone();
        match mode {
            0 => {
                j["ledger"].as_object_mut().unwrap().remove("history");
            }
            1 => j["ledger"]["version"] = 5.into(),
            2 => j["ledger"]["history"]["debts"] = serde_json::json!([]),
            3 => {
                let duplicate = j["ledger"]["history"]["debts"][0].clone();
                j["ledger"]["history"]["debts"]
                    .as_array_mut()
                    .unwrap()
                    .push(duplicate);
            }
            _ => j["ledger"]["history"]["usage"]["reserved_msat"] = 0.into(),
        }
        std::fs::write(&path, serde_json::to_vec(&j).unwrap()).unwrap();
        assert!(DurableRelay::load(&directory).is_err(), "mode {mode}");
    }
    std::fs::write(&path, serde_json::to_vec(&original).unwrap()).unwrap();
    let seller = DurableRelay::load(&directory).unwrap();
    let next = terms(2, 1);
    open(&seller, &next, 0);
    for _ in 0..3 {
        seller.complete(send(&seller, 1).unwrap(), ForwardingOutcome::Submitted);
        seller.checkpoint().unwrap();
    }
    assert!(send(&seller, 1).is_none());
}
