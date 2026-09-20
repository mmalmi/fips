use super::*;
use crate::ledger::Limits;
use cashu_service::{CashuSendSequenceHistory, CashuSpilmanPaymentSigner};

struct Signer;
impl CashuSpilmanPaymentSigner for Signer {
    fn sign_cashu_spilman_payment(
        &self,
        id: &str,
        balance: u64,
        _: bool,
    ) -> Result<CashuSpilmanPayment, String> {
        Ok(CashuSpilmanPayment {
            channel_id: id.into(),
            balance,
            signature: "fixture".into(),
            params: None,
            funding_proofs: None,
        })
    }
}

pub(super) fn fixture(root: &Path) -> (Store, BuyerAuthorizer, FundingIntent) {
    let (mut store, _) = super::super::transition_tests::fixture(&root.join("controller"));
    let f = store.journal.funding.remove("test-1").unwrap();
    store.journal.outgoing.clear();
    store.journal.requested.clear();
    store.journal.next_funding = 1;
    let buyer = BuyerAuthorizer::create(
        &root.join("buyer"),
        store.journal.local,
        64,
        Limits {
            max_channels: 1,
            ..Limits::default()
        },
    )
    .unwrap();
    (store, buyer, f)
}

pub(super) fn append(
    store: &mut Store,
    buyer: &BuyerAuthorizer,
    template: &FundingIntent,
) -> String {
    let j = &mut store.journal;
    j.version = 4;
    j.history
        .get_or_insert_with(History::default)
        .channels
        .get_or_insert_with(ChannelHistory::default);
    let n = j.next_funding;
    let mut f = template.clone();
    f.id = CashuRequestSequence::new(scope(j), n).unwrap().request_id();
    f.created_unix = 100 + n;
    f.expires_unix = f.created_unix + j.policy.channel_lifetime_secs;
    let funded = f.funded.as_mut().unwrap();
    funded.wallet_operation_id = format!("operation-{n}");
    funded.terms.id = format!("channel-{n}");
    funded.terms.expires_unix = f.expires_unix;
    funded.opening.channel_id = funded.terms.id.clone();
    let terms = funded.terms.clone();
    buyer.accept_channel(f.provider, terms.clone(), 1).unwrap();
    let payment = buyer
        .sign_claim(&Signer, f.provider, &terms.id, 1, f.created_unix)
        .unwrap();
    buyer.close_channel(&terms.id).unwrap();
    let settlement = serde_json::from_value(serde_json::json!({
        "provider": f.provider.as_bytes(), "channel": terms,
        "usage": {"paid_msat":1000,"reserved_msat":0,"submitted_msat":0,"lost_msat":0},
        "payment": payment, "report": {"channel_id":terms.id,"value_after_stage1_sat":32,
        "paid_sat":1,"refunded_sat":30,"fee_sat":1}, "refunded":true,"released":true,"wallet_refund_sat":30
    }))
    .unwrap();
    j.buyer_settlements.insert(terms.id.clone(), settlement);
    j.funding.insert(f.id.clone(), f);
    j.next_funding += 1;
    j.history
        .get_or_insert_with(History::default)
        .buyers
        .insert(terms.id.clone());
    Controller::validate_journal(j, &j.policy, j.local).unwrap();
    store.persist().unwrap();
    terms.id
}

pub(super) fn ack(p: &Plan, mint: &str) -> CashuSpilmanRetiredHistory {
    CashuSpilmanRetiredHistory {
        send: CashuSendSequenceHistory {
            mint_url: mint.into(),
            through: p.after.through,
            requests: p.after.channels + p.after.abandoned_requests,
            requested_sat: p.after.capacity_sat,
            cost: p.after.cost.clone(),
        },
        abandoned_requests: p.after.abandoned_requests,
        cancelled_requests: p.after.cancelled_requests,
        capacity_sat: p.after.capacity_sat,
        signed_sat: p.after.signed_sat,
        refund_sat: p.after.refund_sat,
        expires_through_unix: p.after.expires_through_unix,
    }
}

pub(super) fn pending(store: &Store) -> Plan {
    store
        .journal
        .history
        .as_ref()
        .unwrap()
        .channels
        .as_ref()
        .unwrap()
        .pending
        .clone()
        .unwrap()
}

#[test]
fn repeated_completed_channels_preserve_lifetime_budgets_and_reject_replays() {
    let root = tempfile::tempdir().unwrap();
    let (mut store, mut buyer, template) = fixture(root.path());
    store.journal.policy.max_wallet_spend_sat = 128;
    for n in 1..=64 {
        let id = append(&mut store, &buyer, &template);
        let before = Controller::capital(&store.journal).unwrap();
        store.prepare_channel_retirement(&buyer, 10_000).unwrap();
        let p = pending(&store);
        let sdk = ack(&p, &store.journal.policy.mint_url);
        assert_eq!(
            store
                .resume_channel_retirement(&buyer, |_, _| Ok(sdk))
                .unwrap(),
            1
        );
        assert_eq!(Controller::capital(&store.journal).unwrap(), before);
        assert_eq!(before.wallet_debited_sat, n * 32);
        assert_eq!(before.wallet_refunded_sat, n * 30);
        assert_eq!(before.exposure_sat, n * 2);
        assert_eq!(buyer.remaining_budget_sat(), Some(64 - n));
        assert!(buyer.authorized_sat(&id).is_none());
        assert!(
            buyer
                .sign_claim(&Signer, template.provider, &id, 1, 100)
                .is_err()
        );
        let mut replay = template.funded.as_ref().unwrap().terms.clone();
        replay.id = format!("renamed-{n}");
        replay.expires_unix = 100 + n;
        assert!(buyer.accept_channel(template.provider, replay, 0).is_err());
        assert!(store.journal.funding.is_empty());
        assert!(store.journal.buyer_settlements.is_empty());
        let controller_file = store.directory.join("controller.json");
        let buyer_file = root.path().join("buyer/buyer.json");
        let modified = std::fs::metadata(&controller_file)
            .unwrap()
            .modified()
            .unwrap();
        let buyer_modified = std::fs::metadata(&buyer_file).unwrap().modified().unwrap();
        store.prepare_channel_retirement(&buyer, 10_000).unwrap();
        assert_eq!(
            store
                .resume_channel_retirement(&buyer, |_, _| panic!("idle wallet call"))
                .unwrap(),
            0
        );
        buyer.retire_channels(p.buyer.as_ref().unwrap()).unwrap();
        assert_eq!(
            std::fs::metadata(&controller_file)
                .unwrap()
                .modified()
                .unwrap(),
            modified
        );
        assert_eq!(
            std::fs::metadata(&buyer_file).unwrap().modified().unwrap(),
            buyer_modified
        );
        assert!(std::fs::metadata(&controller_file).unwrap().len() < 8000);
        assert!(std::fs::metadata(&buyer_file).unwrap().len() < 2000);
        store = super::super::transition_tests::reload(store);
        drop(buyer);
        buyer = BuyerAuthorizer::load(&root.path().join("buyer")).unwrap();
    }
    // Remaining capital can be unlocked while the lifetime fee/spend limit is spent.
    let mut terms = template.funded.as_ref().unwrap().terms.clone();
    terms.id = "after-lifetime-budget".into();
    terms.expires_unix = 100_000;
    buyer
        .accept_channel(template.provider, terms.clone(), 1)
        .unwrap();
    assert!(matches!(
        buyer.sign_claim(&Signer, template.provider, &terms.id, 1, 100),
        Err(crate::buyer::BuyerError::Budget)
    ));
    let mut f = template;
    f.funded = None;
    assert!(
        store
            .change(|j| {
                j.funding.insert("new".into(), f);
                Ok(())
            })
            .is_err()
    );
    assert_eq!(buyer.remaining_budget_sat(), Some(0));
}

#[test]
fn interrupted_handoff_resumes_before_or_after_buyer_and_wallet_commit() {
    for boundary in 0..=2 {
        let root = tempfile::tempdir().unwrap();
        let (mut store, buyer, template) = fixture(root.path());
        append(&mut store, &buyer, &template);
        store.prepare_channel_retirement(&buyer, 10_000).unwrap();
        let p = pending(&store);
        if boundary >= 1 {
            buyer.retire_channels(p.buyer.as_ref().unwrap()).unwrap();
        }
        let expected = ack(&p, &store.journal.policy.mint_url);
        if boundary == 2 {
            let mut mismatch = expected.clone();
            mismatch.refund_sat -= 1;
            assert!(
                store
                    .resume_channel_retirement(&buyer, |_, _| Ok(mismatch))
                    .is_err()
            );
        }
        assert!(store.change(|_| Ok(())).is_err());
        store = super::super::transition_tests::reload(store);
        drop(buyer);
        let buyer = BuyerAuthorizer::load(&root.path().join("buyer")).unwrap();
        assert_eq!(
            store
                .resume_channel_retirement(&buyer, |_, _| Ok(expected))
                .unwrap(),
            1
        );
        assert_eq!(buyer.remaining_budget_sat(), Some(63));
        assert_eq!(Controller::capital(&store.journal).unwrap().exposure_sat, 2);
    }
}

#[test]
fn unfinished_expiring_and_legacy_funding_remain_and_corrupt_plans_fail() {
    let root = tempfile::tempdir().unwrap();
    let (mut store, buyer, template) = fixture(root.path());
    append(&mut store, &buyer, &template);
    let expiry = store.journal.funding.values().next().unwrap().expires_unix;
    store
        .prepare_channel_retirement(&buyer, expiry + 60)
        .unwrap();
    assert!(!store.journal.history.as_ref().unwrap().pending());
    store
        .prepare_channel_retirement(&buyer, expiry + 61)
        .unwrap();
    let p = pending(&store);
    for field in ["cost", "funding", "buyer", "version"] {
        let mut value = serde_json::to_value(&store.journal).unwrap();
        match field {
            "cost" => {
                value["history"]["channels"]["pending"]["after"]["cost"]["wallet_debit_sat"] =
                    0.into()
            }
            "funding" => value["history"]["channels"]["pending"]["funding"] = serde_json::json!([]),
            "buyer" => {
                value["history"]["channels"]["pending"]["buyer"]["after"]["authorized_sat"] =
                    0.into()
            }
            _ => value["version"] = 3.into(),
        }
        let journal: Journal = serde_json::from_value(value).unwrap();
        assert!(
            Controller::validate_journal(&journal, &journal.policy, journal.local).is_err(),
            "{field}"
        );
    }
    let expected = ack(&p, &store.journal.policy.mint_url);
    store
        .resume_channel_retirement(&buyer, |_, _| Ok(expected))
        .unwrap();
    let mut legacy = template;
    legacy.funded = None;
    store.journal.funding.insert(legacy.id.clone(), legacy);
    store.prepare_channel_retirement(&buyer, 10_000).unwrap();
    assert!(!store.journal.history.as_ref().unwrap().pending());
}

fn disk_reload(store: Store) -> Store {
    let directory = store.directory.clone();
    drop(store);
    let journal: Journal =
        serde_json::from_slice(&std::fs::read(directory.join("controller.json")).unwrap()).unwrap();
    Controller::validate_journal(&journal, &journal.policy, journal.local).unwrap();
    Store {
        _owner: acquire_owner(&directory).unwrap(),
        directory,
        control_obligations: ControlObligations::from_journal(&journal).unwrap(),
        journal,
        ready: true,
    }
}

#[test]
fn failed_writes_never_certify_unpersisted_cleanup_or_reset_spending() {
    for boundary in 0..=2 {
        let root = tempfile::tempdir().unwrap();
        let (mut store, buyer, template) = fixture(root.path());
        append(&mut store, &buyer, &template);
        if boundary != 0 {
            store.prepare_channel_retirement(&buyer, 10_000).unwrap();
        }
        let path = root.path().join(if boundary == 1 {
            "buyer/buyer.json"
        } else {
            "controller/controller.json"
        });
        let saved = root.path().join("original.json");
        std::fs::rename(&path, &saved).unwrap();
        std::fs::create_dir(&path).unwrap();
        if boundary == 0 {
            assert!(store.prepare_channel_retirement(&buyer, 10_000).is_err());
        } else {
            let p = pending(&store);
            let result = ack(&p, &store.journal.policy.mint_url);
            let mut called = false;
            assert!(
                store
                    .resume_channel_retirement(&buyer, |_, _| {
                        called = true;
                        Ok(result)
                    })
                    .is_err()
            );
            assert_eq!(called, boundary == 2);
        }
        assert!(
            store
                .resume_channel_retirement(&buyer, |_, _| panic!("failed writer reached wallet"))
                .is_err()
        );
        assert!(store.change(|_| Ok(())).is_err());
        // Restore the last durable file, never the failed in-memory candidate.
        std::fs::remove_dir(&path).unwrap();
        std::fs::rename(&saved, &path).unwrap();
        store = disk_reload(store);
        drop(buyer);
        let buyer = BuyerAuthorizer::load(&root.path().join("buyer")).unwrap();
        store.prepare_channel_retirement(&buyer, 10_000).unwrap();
        let result = ack(&pending(&store), &store.journal.policy.mint_url);
        store
            .resume_channel_retirement(&buyer, |_, _| Ok(result))
            .unwrap();
        assert_eq!(buyer.remaining_budget_sat(), Some(63));
        assert_eq!(Controller::capital(&store.journal).unwrap().exposure_sat, 2);
    }
}

#[test]
fn unresolved_numbered_prefix_cannot_skip_to_a_later_completed_channel() {
    let root = tempfile::tempdir().unwrap();
    let (mut store, buyer, template) = fixture(root.path());
    let channel = append(&mut store, &buyer, &template);
    let settled = store.journal.buyer_settlements.remove(&channel).unwrap();
    store.prepare_channel_retirement(&buyer, 10_000).unwrap();
    assert!(!store.journal.history.as_ref().unwrap().pending());
    store.journal.buyer_settlements.insert(channel, settled);
    let id = store.journal.funding.keys().next().unwrap().clone();
    let funded = store
        .journal
        .funding
        .get_mut(&id)
        .unwrap()
        .funded
        .take()
        .unwrap();
    store.prepare_channel_retirement(&buyer, 10_000).unwrap();
    assert!(!store.journal.history.as_ref().unwrap().pending());
    store.journal.funding.get_mut(&id).unwrap().funded = Some(funded);
    store.prepare_channel_retirement(&buyer, 10_000).unwrap();
    assert!(store.journal.history.as_ref().unwrap().pending());
}

#[test]
fn buyer_schema_cannot_omit_or_downgrade_retired_obligations() {
    let root = tempfile::tempdir().unwrap();
    let (mut store, buyer, template) = fixture(root.path());
    append(&mut store, &buyer, &template);
    store.prepare_channel_retirement(&buyer, 10_000).unwrap();
    let p = pending(&store);
    let result = ack(&p, &store.journal.policy.mint_url);
    store
        .resume_channel_retirement(&buyer, |_, _| Ok(result))
        .unwrap();
    drop(buyer);
    let path = root.path().join("buyer/buyer.json");
    let original: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    for mode in 0..3 {
        let mut value = original.clone();
        match mode {
            0 => {
                value.as_object_mut().unwrap().remove("history");
            }
            1 => {
                value["version"] = 3.into();
            }
            _ => {
                value["history"]["authorized_sat"] = 33.into();
            }
        }
        std::fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();
        assert!(BuyerAuthorizer::load(&root.path().join("buyer")).is_err());
    }
    std::fs::write(&path, serde_json::to_vec(&original).unwrap()).unwrap();
    assert_eq!(
        BuyerAuthorizer::load(&root.path().join("buyer"))
            .unwrap()
            .remaining_budget_sat(),
        Some(63)
    );
}
