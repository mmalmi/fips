use super::super::transition_tests::reload;
use super::tests::{ack, append, fixture, pending};
use super::*;

pub(super) fn append_reclaim(
    store: &mut Store,
    template: &FundingIntent,
    complete: bool,
) -> String {
    let n = store.journal.next_funding;
    let reclaim = if complete {
        FundingReclaim::Complete {
            result: ReclaimedFunding {
                wallet_operation_id: format!("reclaimed-{n}"),
                wallet_cost: cashu_service::CashuSendCost {
                    token_amount_sat: 32,
                    swap_fee_sat: 0,
                    wallet_debit_sat: 32,
                },
                recovered_amount_sat: 30,
            },
        }
    } else {
        FundingReclaim::Pending
    };
    append_disposition(store, template, reclaim)
}

pub(super) fn append_disposition(
    store: &mut Store,
    template: &FundingIntent,
    reclaim: FundingReclaim,
) -> String {
    let j = &mut store.journal;
    j.advance_history_version(4);
    j.version |= journal::FUNDING_RECLAIM_VERSION;
    if reclaim.cancelled() {
        j.version |= journal::FUNDING_CANCELLED_VERSION;
    }
    if matches!(reclaim, FundingReclaim::PreparedCancelled { .. }) {
        j.version |= journal::PREPARED_CANCELLED_VERSION;
    }
    j.history
        .get_or_insert_with(History::default)
        .channels
        .get_or_insert_with(ChannelHistory::default);
    let mut f = template.clone();
    let n = j.next_funding;
    f.id = CashuRequestSequence::new(scope(j), n).unwrap().request_id();
    f.created_unix = 100 + n;
    f.expires_unix = f.created_unix + j.policy.channel_lifetime_secs;
    f.funded = None;
    if matches!(reclaim, FundingReclaim::Pending) {
        // Model the real withdrawn reservation, so journal load validates the
        // Pending disposition before any terminal evidence is available.
        let (_, old) =
            super::super::transition_tests::fixture(&store.directory.join(format!("offer-{n}")));
        let mut offer = old.offer;
        offer.provider = f.provider;
        offer.buyer = j.local;
        offer.id = format!("withdrawn-{n}");
        j.recovery_only.insert(offer.id.clone());
        j.requested.insert(offer.id.clone(), offer);
        j.version |= journal::RECOVERY_ONLY_VERSION;
    }
    f.reclaim = Some(reclaim);
    let id = f.id.clone();
    j.funding.insert(id.clone(), f);
    j.next_funding += 1;
    Controller::validate_journal(j, &j.policy, j.local).unwrap();
    store.persist().unwrap();
    id
}

#[test]
fn repeated_abandoned_prefixes_preserve_cost_without_buyer_channels() {
    let root = tempfile::tempdir().unwrap();
    let (mut store, buyer, template) = fixture(root.path());
    store.journal.policy.max_wallet_spend_sat = 128;
    for n in 1..=64 {
        let id = append_reclaim(&mut store, &template, true);
        let old = store.journal.funding[&id].clone();
        let budget = Controller::capital(&store.journal).unwrap();
        store.prepare_channel_retirement(&buyer, 10_000).unwrap();
        store = reload(store);
        let p = pending(&store);
        assert!(
            p.buyer.is_none(),
            "no invented channel or empty buyer retirement"
        );
        assert_eq!(p.after.channels, 0);
        assert_eq!(p.after.abandoned_requests, n);
        assert_eq!(p.after.capacity_sat, 0);
        assert_eq!(p.after.signed_sat, 0);
        let sdk = ack(&p, &store.journal.policy.mint_url);
        assert_eq!(
            store
                .resume_channel_retirement(&buyer, |_, _| Ok(sdk))
                .unwrap(),
            1
        );
        assert_eq!(Controller::capital(&store.journal).unwrap(), budget);
        assert_eq!(budget.wallet_debited_sat, n * 32);
        assert_eq!(budget.wallet_refunded_sat, n * 30);
        assert_eq!(budget.exposure_sat, n * 2);
        assert_eq!(buyer.remaining_budget_sat(), Some(64));
        assert!(store.journal.funding.is_empty());
        assert!(store.journal.buyer_settlements.is_empty());
        store = reload(store);
        let mut replay = store.journal.clone();
        replay.funding.insert(id, old);
        assert!(Controller::validate_journal(&replay, &replay.policy, replay.local).is_err());
        assert_eq!(
            store
                .resume_channel_retirement(&buyer, |_, _| panic!("duplicate wallet retirement"))
                .unwrap(),
            0
        );
        let mut unsupported = store.journal.clone();
        unsupported.version &= !journal::FUNDING_RECLAIM_VERSION;
        assert!(
            Controller::validate_journal(&unsupported, &unsupported.policy, unsupported.local)
                .is_err()
        );
        assert!(
            std::fs::metadata(store.directory.join("controller.json"))
                .unwrap()
                .len()
                < 8000
        );
    }
    let mut exhausted = store.journal.clone();
    let mut next = template.clone();
    next.id = CashuRequestSequence::new(scope(&exhausted), exhausted.next_funding)
        .unwrap()
        .request_id();
    next.funded = None;
    exhausted.funding.insert(next.id.clone(), next);
    exhausted.next_funding += 1;
    assert!(
        Controller::validate_capital(&exhausted).is_err(),
        "refunds cannot erase lifetime fees"
    );
}

#[test]
fn mixed_prefix_requires_exact_shared_sdk_totals_and_replays_after_reload() {
    let root = tempfile::tempdir().unwrap();
    let (mut store, buyer, template) = fixture(root.path());
    append(&mut store, &buyer, &template);
    append_reclaim(&mut store, &template, true);
    let budget = Controller::capital(&store.journal).unwrap();
    store.prepare_channel_retirement(&buyer, 10_000).unwrap();
    let p = pending(&store);
    assert_eq!(p.buyer.as_ref().unwrap().terms().count(), 1);
    assert_eq!(p.funding.len(), 2);
    assert_eq!(p.after.channels, 1);
    assert_eq!(p.after.abandoned_requests, 1);
    assert_eq!(p.after.capacity_sat, 32);
    assert_eq!(p.after.signed_sat, 1);
    assert_eq!(p.after.cost.wallet_debit_sat, 64);
    assert_eq!(p.after.refund_sat, 60);
    for mismatch in 0..4 {
        let mut sdk = ack(&p, &store.journal.policy.mint_url);
        match mismatch {
            0 => sdk.abandoned_requests = 0,
            1 => sdk.send.requests = 1,
            2 => sdk.refund_sat -= 1,
            _ => sdk.capacity_sat += 32,
        }
        assert!(
            store
                .resume_channel_retirement(&buyer, |_, _| Ok(sdk))
                .is_err()
        );
        assert_eq!(store.journal.funding.len(), 2);
        store = reload(store);
    }
    let sdk = ack(&p, &store.journal.policy.mint_url);
    assert_eq!(
        store
            .resume_channel_retirement(&buyer, |_, _| Ok(sdk))
            .unwrap(),
        2
    );
    assert_eq!(Controller::capital(&store.journal).unwrap(), budget);
    reload(store);
}

#[test]
fn pending_reclaim_blocks_ordered_prefix_and_original_expiry_is_preserved() {
    let root = tempfile::tempdir().unwrap();
    let (mut store, buyer, template) = fixture(root.path());
    let first = append_reclaim(&mut store, &template, false);
    let second = append_reclaim(&mut store, &template, true);
    store.prepare_channel_retirement(&buyer, 10_000).unwrap();
    assert!(
        store
            .journal
            .history
            .as_ref()
            .unwrap()
            .channels
            .as_ref()
            .unwrap()
            .pending
            .is_none()
    );
    let expected = store.journal.funding[&first].clone();
    let result = store.journal.funding[&second].reclaimed().unwrap().clone();
    let result = ReclaimedFunding {
        wallet_operation_id: "first-original-send".into(),
        ..result
    };
    store
        .change(|j| Controller::record_funding_reclaim(j, &expected, result))
        .unwrap();
    let expiry = expected.expires_unix + 60;
    store.prepare_channel_retirement(&buyer, expiry).unwrap();
    assert!(
        store
            .journal
            .history
            .as_ref()
            .unwrap()
            .channels
            .as_ref()
            .unwrap()
            .pending
            .is_none()
    );
    store.prepare_channel_retirement(&buyer, 10_000).unwrap();
    assert_eq!(pending(&store).funding, vec![first, second]);
    reload(store);
}
