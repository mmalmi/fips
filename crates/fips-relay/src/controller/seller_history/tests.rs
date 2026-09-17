use super::*;
use crate::ledger::{ChannelUsage, Limits};

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
        assert_eq!(store.retire_sales(&seller, t.expires_unix + 61).unwrap(), 1);
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
        assert_eq!(store.retire_sales(&seller, t.expires_unix + 61).unwrap(), 0);
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
fn unacknowledged_or_unexpired_sales_keep_their_reports() {
    let root = tempfile::tempdir().unwrap();
    let (mut store, seller, t) = fixture(root.path());
    let t = append(&mut store, &seller, &t, 1, false);
    assert_eq!(store.retire_sales(&seller, t.expires_unix + 61).unwrap(), 0);
    assert!(store.journal.seller_settlements[&t.id].report.is_some());
    store
        .journal
        .seller_settlements
        .get_mut(&t.id)
        .unwrap()
        .released = true;
    assert_eq!(store.retire_sales(&seller, t.expires_unix + 60).unwrap(), 0);
    assert_eq!(store.retire_sales(&seller, t.expires_unix + 61).unwrap(), 1);
}

#[test]
fn each_seller_cleanup_write_boundary_recovers_without_losing_evidence() {
    for boundary in 0..=3 {
        let root = tempfile::tempdir().unwrap();
        let (mut store, seller, template) = fixture(root.path());
        let t = append(&mut store, &seller, &template, 1, true);
        if boundary != 0 {
            store.prepare_sales(&seller, t.expires_unix + 61).unwrap();
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
                store.prepare_sales(&seller, t.expires_unix + 61)
            } else {
                store.resume_sales(&seller).map(|_| ())
            };
            assert!(failed.is_err());
            assert!(store.change(|_| Ok(())).is_err());
            assert!(store.resume_sales(&seller).is_err());
            std::fs::remove_dir(&path).unwrap();
            std::fs::rename(&saved, &path).unwrap();
        }
        store = reload(store);
        drop(seller);
        let seller = DurableRelay::load(&root.path().join("seller")).unwrap();
        assert_eq!(store.retire_sales(&seller, t.expires_unix + 61).unwrap(), 1);
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
    store.prepare_sales(&seller, t.expires_unix + 61).unwrap();
    for field in ["history", "fees", "release", "paid"] {
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
            "release" => j.seller_settlements.get_mut(&t.id).unwrap().released = false,
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
