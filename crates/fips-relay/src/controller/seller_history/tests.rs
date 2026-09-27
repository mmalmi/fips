use super::*;
use crate::ledger::{ChannelUsage, Limits};
mod recovery;
mod support;
use support::{prepare_sales, resume_sales, retire_sales};

fn fixture(root: &Path) -> (Store, DurableRelay, ChannelTerms) {
    let (mut store, old) = super::super::transition_tests::fixture(&root.join("controller"));
    store.journal.funding.clear();
    store.journal.outgoing.clear();
    store.journal.requested.clear();
    store.journal.version = 3;
    store.journal.history = Some(History::default());
    let mut terms = old.purchase.channel;
    terms.buyer = old.purchase.provider;
    let seller = DurableRelay::create(
        &root.join("seller"),
        Limits {
            max_channels: 1,
            ..Limits::default()
        },
        1000,
    )
    .unwrap();
    (store, seller, terms)
}

fn append(
    store: &mut Store,
    seller: &DurableRelay,
    template: &ChannelTerms,
    n: u64,
    released: bool,
) -> ChannelTerms {
    let mut t = template.clone();
    t.id = format!("sale-{n}");
    t.expires_unix += n;
    seller.open_channel_verified(t.clone(), 0).unwrap();
    seller.seal_channel(&t.id).unwrap();
    let h = store.journal.history.as_mut().unwrap();
    h.through_unix = h.through_unix.max(t.expires_unix);
    h.sellers.insert(t.id.clone(), t.clone());
    store.journal.seller_settlements.insert(
        t.id.clone(),
        SellerSettlement {
            channel: t.clone(),
            usage: Some(ChannelUsage::default()),
            payment: Some(CashuSpilmanPayment {
                channel_id: t.id.clone(),
                balance: 0,
                signature: "fixture".into(),
                params: None,
                funding_proofs: None,
            }),
            report: Some(SettlementReport {
                channel_id: t.id.clone(),
                value_after_stage1_sat: t.capacity_sat,
                paid_sat: 0,
                receiver_fee_reserve_sat: 0,
                refunded_sat: t.capacity_sat - 1,
                fee_sat: 1,
            }),
            released,
        },
    );
    Controller::validate_journal(&store.journal, &store.journal.policy, store.journal.local)
        .unwrap();
    store.persist().unwrap();
    t
}

fn pending(store: &Store) -> Plan {
    store
        .journal
        .history
        .as_ref()
        .unwrap()
        .seller
        .as_ref()
        .unwrap()
        .pending
        .clone()
        .unwrap()
}

fn reload(store: Store) -> Store {
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
fn controller_recycles_acknowledged_sales_and_keeps_cumulative_settlement_fees() {
    let root = tempfile::tempdir().unwrap();
    let (mut store, mut seller, t) = fixture(root.path());
    for n in 1..=64 {
        let t = append(&mut store, &seller, &t, n, true);
        assert_eq!(
            retire_sales(&mut store, &seller, t.expires_unix + 61).unwrap(),
            1
        );
        let h = store.journal.history.as_ref().unwrap();
        let total = &h.seller.as_ref().unwrap().totals;
        assert_eq!(total.accounting.channels, n);
        assert_eq!(total.value_sat, n * t.capacity_sat);
        assert_eq!(total.returned_sat, n * (t.capacity_sat - 1));
        assert_eq!(total.fee_sat, n);
        assert!(h.sellers.is_empty() && store.journal.seller_settlements.is_empty());
        assert!(seller.channel_terms(&t.id).is_none());
        let path = store.directory.join("controller.json");
        let modified = std::fs::metadata(&path).unwrap().modified().unwrap();
        assert_eq!(
            retire_sales(&mut store, &seller, t.expires_unix + 61).unwrap(),
            0
        );
        assert_eq!(
            std::fs::metadata(&path).unwrap().modified().unwrap(),
            modified
        );
        assert!(std::fs::metadata(&path).unwrap().len() < 4000);
        store = reload(store);
        drop(seller);
        seller = DurableRelay::load(&root.path().join("seller")).unwrap();
    }
}

#[test]
fn seller_history_retains_receiver_fee_reserves_without_rebilling_them() {
    let root = tempfile::tempdir().unwrap();
    let (mut store, seller, t) = fixture(root.path());
    let t = append(&mut store, &seller, &t, 1, true);
    seller.apply_verified_balance(&t.id, 3_000).unwrap();
    let sale = store.journal.seller_settlements.get_mut(&t.id).unwrap();
    sale.payment.as_mut().unwrap().balance = 3;
    sale.usage.as_mut().unwrap().paid_msat = 3_000;
    let report = sale.report.as_mut().unwrap();
    report.paid_sat = 3;
    report.receiver_fee_reserve_sat = 1;
    report.refunded_sat -= 4;
    store.persist().unwrap();
    assert_eq!(
        retire_sales(&mut store, &seller, t.expires_unix + 61).unwrap(),
        1
    );
    let mut store = reload(store);
    let total = &store
        .journal
        .history
        .as_ref()
        .unwrap()
        .seller
        .as_ref()
        .unwrap()
        .totals;
    assert_eq!(total.paid_sat, 3);
    assert_eq!(total.accounting.usage.paid_msat, 3_000);
    assert_eq!(total.receiver_fee_reserve_sat, 1);
    assert_eq!(total.fee_sat, 1);
    let mut missing = serde_json::to_value(&store.journal).unwrap();
    missing["history"]["seller"]["totals"]
        .as_object_mut()
        .unwrap()
        .remove("receiver_fee_reserve_sat");
    let missing: Journal = serde_json::from_value(missing).unwrap();
    assert!(Controller::validate_journal(&missing, &missing.policy, missing.local).is_err());
    assert_eq!(
        retire_sales(&mut store, &seller, t.expires_unix + 61).unwrap(),
        0
    );
}

#[test]
fn completed_sales_keep_reports_until_immutable_refund_expiry() {
    for released in [false, true] {
        let root = tempfile::tempdir().unwrap();
        let (mut store, seller, t) = fixture(root.path());
        let t = append(&mut store, &seller, &t, 1, released);
        assert_eq!(
            retire_sales(&mut store, &seller, t.expires_unix + 60).unwrap(),
            0
        );
        assert!(store.journal.seller_settlements[&t.id].report.is_some());
        assert_eq!(
            retire_sales(&mut store, &seller, t.expires_unix + 61).unwrap(),
            1
        );
    }
}

#[test]
fn each_seller_cleanup_write_boundary_recovers_without_losing_evidence() {
    for boundary in 0..=3 {
        let root = tempfile::tempdir().unwrap();
        let (mut store, seller, template) = fixture(root.path());
        let t = append(&mut store, &seller, &template, 1, true);
        if boundary != 0 {
            prepare_sales(&mut store, &seller, t.expires_unix + 61).unwrap();
        }
        if boundary == 3 {
            seller.retire_channels(&pending(&store).ledger).unwrap();
        } else {
            let path = root.path().join(if boundary == 1 {
                "seller/ledger.json"
            } else {
                "controller/controller.json"
            });
            let saved = root.path().join("saved.json");
            std::fs::rename(&path, &saved).unwrap();
            std::fs::create_dir(&path).unwrap();
            let failed = if boundary == 0 {
                prepare_sales(&mut store, &seller, t.expires_unix + 61)
            } else {
                resume_sales(&mut store, &seller).map(|_| ())
            };
            assert!(failed.is_err());
            assert!(store.change(|_| Ok(())).is_err());
            assert!(resume_sales(&mut store, &seller).is_err());
            std::fs::remove_dir(&path).unwrap();
            std::fs::rename(&saved, &path).unwrap();
        }
        store = reload(store);
        drop(seller);
        let seller = DurableRelay::load(&root.path().join("seller")).unwrap();
        assert_eq!(
            retire_sales(&mut store, &seller, t.expires_unix + 61).unwrap(),
            1
        );
        assert_eq!(
            store
                .journal
                .history
                .as_ref()
                .unwrap()
                .seller
                .as_ref()
                .unwrap()
                .totals
                .fee_sat,
            1
        );
        assert!(seller.channel_terms(&t.id).is_none());
    }
}

#[test]
fn changed_retirement_evidence_and_missing_modern_history_are_rejected() {
    let root = tempfile::tempdir().unwrap();
    let (mut store, seller, t) = fixture(root.path());
    let t = append(&mut store, &seller, &t, 1, true);
    prepare_sales(&mut store, &seller, t.expires_unix + 61).unwrap();
    for field in ["history", "fees", "report", "paid"] {
        let mut j = store.journal.clone();
        match field {
            "history" => j.history.as_mut().unwrap().seller = None,
            "fees" => {
                j.history
                    .as_mut()
                    .unwrap()
                    .seller
                    .as_mut()
                    .unwrap()
                    .pending
                    .as_mut()
                    .unwrap()
                    .after
                    .fee_sat += 1
            }
            "report" => j.seller_settlements.get_mut(&t.id).unwrap().report = None,
            _ => {
                j.history
                    .as_mut()
                    .unwrap()
                    .seller
                    .as_mut()
                    .unwrap()
                    .pending
                    .as_mut()
                    .unwrap()
                    .ledger
                    .channels[0]
                    .usage
                    .paid_msat = 1
            }
        }
        assert!(
            Controller::validate_journal(&j, &j.policy, j.local).is_err(),
            "{field}"
        );
    }
}
