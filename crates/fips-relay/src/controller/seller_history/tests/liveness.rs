use super::*;

#[test]
fn receiver_planning_keeps_controller_reads_available() {
    let root = tempfile::tempdir().unwrap();
    let (mut store, seller, template) = fixture(root.path());
    let t = append(&mut store, &seller, &template, 1, true);
    let shared = Mutex::new(store);
    let prepared = Store::prepare_sales(&shared, &seller, t.expires_unix + 61, |ids| {
        let mut store = shared
            .try_lock()
            .map_err(|_| "receiver planning blocks controller reads")?;
        // Planning has not persisted an intent yet. An unrelated change must
        // survive when the selected receiver evidence is attached.
        store.change(|j| {
            j.next_funding += 1;
            Ok(())
        })?;
        support::receiver_plan(&store.journal, ids)
    });
    assert_eq!(prepared, Ok(()));
    let store = shared.into_inner().unwrap();
    assert_eq!(store.journal.next_funding, 3);
    assert!(store.journal.history.as_ref().unwrap().pending());
}

#[test]
fn receiver_retirement_keeps_controller_reads_available() {
    let root = tempfile::tempdir().unwrap();
    let (mut store, seller, template) = fixture(root.path());
    let t = append(&mut store, &seller, &template, 1, true);
    prepare_sales(&mut store, &seller, t.expires_unix + 61).unwrap();
    let shared = Mutex::new(store);
    let retired = Store::resume_sales(
        &shared,
        &seller,
        |_| panic!("saved intent"),
        |p| {
            let mut store = shared
                .try_lock()
                .map_err(|_| "receiver retirement blocks controller reads")?;
            assert!(store.journal.seller_settlements.contains_key(&t.id));
            assert!(
                store.change(|_| Ok(())).is_err(),
                "pending handoff must fence writes"
            );
            Ok(p.accounting.after.clone())
        },
    );
    assert_eq!(retired, Ok(1));
    let mut store = shared.into_inner().unwrap();
    store.change(|_| Ok(())).unwrap();
    assert!(!store.journal.seller_settlements.contains_key(&t.id));
}

#[test]
fn receiver_planning_revalidates_reports_before_saving_its_intent() {
    let root = tempfile::tempdir().unwrap();
    let (mut store, seller, template) = fixture(root.path());
    let t = append(&mut store, &seller, &template, 1, true);
    let shared = Mutex::new(store);
    let result = Store::prepare_sales(&shared, &seller, t.expires_unix + 61, |ids| {
        let mut store = shared.lock().unwrap();
        let original = support::receiver_plan(&store.journal, ids)?;
        store.change(|j| {
            let report = j
                .seller_settlements
                .get_mut(&t.id)
                .unwrap()
                .report
                .as_mut()
                .unwrap();
            report.fee_sat -= 1;
            report.refunded_sat += 1;
            Ok(())
        })?;
        Ok(original)
    });
    assert!(
        result
            .unwrap_err()
            .contains("differs from original settlement")
    );
    let mut store = shared.into_inner().unwrap();
    assert!(!store.journal.history.as_ref().unwrap().pending());
    assert!(seller.channel_terms(&t.id).is_some());
    assert_eq!(
        store.journal.seller_settlements[&t.id]
            .report
            .as_ref()
            .unwrap()
            .fee_sat,
        0
    );
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
        0
    );
}
