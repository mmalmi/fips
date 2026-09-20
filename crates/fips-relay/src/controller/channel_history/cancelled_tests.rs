use super::super::transition_tests::reload;
use super::abandoned_tests::{append_disposition, append_reclaim};
use super::tests::{ack, append, fixture, pending};
use super::*;
use cashu_service::CashuSpilmanFundingReclaim as Wallet;

#[test]
fn cancelled_prefixes_stay_bounded_without_wallet_sends_or_buyer_channels() {
    let root = tempfile::tempdir().unwrap();
    let (mut store, buyer, template) = fixture(root.path());
    let policy = store.journal.policy.clone();
    for n in 1..=64 {
        let id = append_disposition(&mut store, &template, FundingReclaim::Cancelled);
        let original = store.journal.funding[&id].clone();
        store.prepare_channel_retirement(&buyer, 10_000).unwrap();
        store = reload(store);
        let p = pending(&store);
        assert!(
            p.buyer.is_none(),
            "a cancelled admission has no buyer channel"
        );
        assert_eq!(p.after.cancelled_requests, n);
        assert_eq!(p.after.channels, 0);
        assert_eq!(p.after.abandoned_requests, 0);
        assert_eq!(p.after.capacity_sat, 0);
        assert_eq!(p.after.signed_sat, 0);
        assert_eq!(p.after.refund_sat, 0);
        assert_eq!(p.after.cost, cashu_service::CashuSendCost::default());
        assert_eq!(p.after.through, n);
        assert_eq!(p.after.expires_through_unix, original.expires_unix + 60);
        let sdk = ack(&p, &policy.mint_url);
        assert_eq!(sdk.send.requests, 0);
        assert_eq!(sdk.cancelled_requests, n);
        assert_eq!(
            store
                .resume_channel_retirement(&buyer, |_, _| Ok(sdk))
                .unwrap(),
            1
        );
        assert_eq!(
            Controller::capital(&store.journal).unwrap(),
            FundingBudget::default()
        );
        assert_eq!(buyer.remaining_budget_sat(), Some(64));
        assert!(store.journal.policy == policy);
        assert_eq!(store.journal.next_funding, n + 1);
        assert!(store.journal.funding.is_empty() && store.journal.buyer_settlements.is_empty());
        store = reload(store);
        assert_eq!(
            store
                .resume_channel_retirement(&buyer, |_, _| panic!("duplicate SDK retirement"))
                .unwrap(),
            0
        );
        let mut replay = store.journal.clone();
        replay.funding.insert(id, original);
        assert!(Controller::validate_journal(&replay, &replay.policy, replay.local).is_err());
        for flag in [
            journal::FUNDING_CANCELLED_VERSION,
            journal::FUNDING_RECLAIM_VERSION,
        ] {
            let mut unsupported = store.journal.clone();
            unsupported.version &= !flag;
            assert!(
                Controller::validate_journal(&unsupported, &unsupported.policy, unsupported.local)
                    .is_err()
            );
        }
        assert!(
            std::fs::metadata(store.directory.join("controller.json"))
                .unwrap()
                .len()
                < 8000
        );
    }
}

#[test]
fn mixed_cancellation_retirement_requires_exact_zero_cost_sdk_evidence() {
    let root = tempfile::tempdir().unwrap();
    let (mut store, buyer, template) = fixture(root.path());
    append(&mut store, &buyer, &template);
    append_reclaim(&mut store, &template, true);
    append_disposition(&mut store, &template, FundingReclaim::Cancelled);
    let budget = Controller::capital(&store.journal).unwrap();
    store.prepare_channel_retirement(&buyer, 10_000).unwrap();
    let p = pending(&store);
    assert_eq!(p.funding.len(), 3);
    assert_eq!(p.after.channels, 1);
    assert_eq!(p.after.abandoned_requests, 1);
    assert_eq!(p.after.cancelled_requests, 1);
    assert_eq!(p.buyer.as_ref().unwrap().terms().count(), 1);
    assert_eq!(p.after.cost.wallet_debit_sat, 64);
    assert_eq!(p.after.refund_sat, 60);
    for mismatch in 0..5 {
        let mut sdk = ack(&p, &store.journal.policy.mint_url);
        match mismatch {
            0 => sdk.cancelled_requests = 0,
            1 => sdk.send.requests += 1,
            2 => sdk.abandoned_requests += 1,
            3 => sdk.send.cost.wallet_debit_sat += 1,
            _ => sdk.refund_sat += 1,
        }
        assert!(
            store
                .resume_channel_retirement(&buyer, |_, _| Ok(sdk))
                .is_err()
        );
        assert_eq!(store.journal.funding.len(), 3);
        store = reload(store);
    }
    let sdk = ack(&p, &store.journal.policy.mint_url);
    assert_eq!(
        store
            .resume_channel_retirement(&buyer, |_, _| Ok(sdk))
            .unwrap(),
        3
    );
    assert_eq!(Controller::capital(&store.journal).unwrap(), budget);
    reload(store);
}

#[test]
fn cancellation_retirement_waits_for_original_expiry_and_uncertain_prefix() {
    let root = tempfile::tempdir().unwrap();
    let (mut store, buyer, template) = fixture(root.path());
    let first = append_reclaim(&mut store, &template, false);
    let mut other = template.clone();
    other.provider = NodeAddr::from_bytes([3; 16]);
    let second = append_disposition(&mut store, &other, FundingReclaim::Cancelled);
    store.prepare_channel_retirement(&buyer, 10_000).unwrap();
    assert!(
        !store
            .journal
            .history
            .as_ref()
            .unwrap()
            .channels
            .as_ref()
            .unwrap()
            .pending()
    );
    let expected = store.journal.funding[&first].clone();
    store
        .change(|j| Controller::record_wallet_reclaim(j, &expected, Wallet::Cancelled))
        .unwrap();
    store
        .prepare_channel_retirement(&buyer, expected.expires_unix + 60)
        .unwrap();
    assert!(
        !store
            .journal
            .history
            .as_ref()
            .unwrap()
            .channels
            .as_ref()
            .unwrap()
            .pending()
    );
    store.prepare_channel_retirement(&buyer, 10_000).unwrap();
    let plan = pending(&store);
    assert_eq!(plan.funding, vec![first, second]);
    assert_eq!(plan.after.cancelled_requests, 2);
    assert_eq!(plan.after.cost, cashu_service::CashuSendCost::default());
    reload(store);
}

#[test]
fn cancellation_only_totals_reject_money_and_record_overflow() {
    let valid = Totals {
        through: 1,
        cancelled_requests: 1,
        expires_through_unix: 100,
        ..Totals::default()
    };
    assert!(valid.valid());
    for mutation in 0..6 {
        let mut invalid = valid.clone();
        match mutation {
            0 => invalid.cancelled_requests = 2,
            1 => {
                invalid.cost = cashu_service::CashuSendCost {
                    token_amount_sat: 1,
                    swap_fee_sat: 0,
                    wallet_debit_sat: 1,
                }
            }
            2 => invalid.refund_sat = 1,
            3 => invalid.channels = u64::MAX,
            4 => invalid.expires_through_unix = 0,
            _ => invalid.abandoned_requests = u64::MAX,
        }
        assert!(!invalid.valid());
    }
}
