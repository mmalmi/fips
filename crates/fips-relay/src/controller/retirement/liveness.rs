//! Route handoff releases reads while its original intent continues fencing writes.
use super::*;
use crate::controller::{retirement_tests, transition_tests};
use std::sync::mpsc;

#[test]
fn route_retirement_keeps_reads_live_and_mutations_fenced() {
    let root = tempfile::tempdir().unwrap();
    let (mut store, old, buyer, seller) = retirement_tests::fixture(root.path());
    let next = retirement_tests::replace(&mut store, &old, &buyer);
    store
        .prepare_retirement(&buyer, &seller, old.offer.expires_unix)
        .unwrap();
    let path = store.directory.join("controller.json");
    let saved = std::fs::read(&path).unwrap();
    let shared = Mutex::new(store);
    let (observed, unchanged, retired) = std::thread::scope(|threads| {
        // A timeout disconnects the worker before the scope joins it.
        let (entered, waiting) = mpsc::sync_channel(0);
        let (release, resume) = mpsc::sync_channel(0);
        let shared = &shared;
        let buyer = &buyer;
        let seller = &seller;
        let worker = threads.spawn(move || {
            Store::resume_retirement_with(shared, |plan| {
                entered.send(()).map_err(|e| e.to_string())?;
                resume.recv().map_err(|e| e.to_string())?;
                plan.apply_lower_stores(buyer, seller)
            })
        });
        waiting.recv_timeout(Duration::from_secs(5)).unwrap();
        let observed = shared.try_lock().ok().map(|mut store| {
            let mutation = store.change(|_| Ok(()));
            (store.ready, store.journal.clone(), mutation)
        });
        let unchanged = std::fs::read(&path).map(|bytes| bytes == saved);
        // Release before asserting so a regression cannot strand the worker.
        release.send(()).unwrap();
        (observed, unchanged, worker.join().unwrap())
    });

    let (ready, snapshot, mutation) = observed.expect("lower retirement blocked controller reads");
    assert!(ready && snapshot.history.as_ref().unwrap().routes_pending());
    assert!(snapshot.outgoing.contains_key(&next.purchase.contract.id));
    assert_eq!(mutation.unwrap_err(), HISTORY_PENDING);
    assert!(
        unchanged.unwrap(),
        "reading and a fenced mutation changed the intent"
    );
    assert_eq!(retired.unwrap(), 1);
    let store = shared.into_inner().unwrap();
    assert!(!store.journal.history.as_ref().unwrap().routes_pending());
    assert_eq!(
        buyer.retired_route_evidence("channel").unwrap().contracts,
        1
    );
    transition_tests::reload(store);
}

#[test]
fn changed_route_intent_is_not_overwritten_after_lower_stores_finish() {
    let root = tempfile::tempdir().unwrap();
    let (mut store, old, buyer, seller) = retirement_tests::fixture(root.path());
    retirement_tests::replace(&mut store, &old, &buyer);
    store
        .prepare_retirement(&buyer, &seller, old.offer.expires_unix)
        .unwrap();
    let original = store.pending_retirement().unwrap().unwrap();
    let shared = Mutex::new(store);
    let result = Store::resume_retirement_with(&shared, |plan| {
        plan.apply_lower_stores(&buyer, &seller)?;
        with_store(&shared, |store| {
            let changed = store
                .journal
                .history
                .as_mut()
                .unwrap()
                .pending
                .as_mut()
                .unwrap();
            changed.through_unix += 1;
            store.persist()
        })
    });
    assert_eq!(result.unwrap_err(), "route retirement intent changed");
    with_store(&shared, |store| {
        assert!(store.journal.history.as_ref().unwrap().pending.as_ref() != Some(&original));
        assert_eq!(store.journal.outgoing.len(), 2);
        assert_eq!(store.change(|_| Ok(())).unwrap_err(), HISTORY_PENDING);
        let persisted: Journal = serde_json::from_slice(
            &std::fs::read(store.directory.join("controller.json")).unwrap(),
        )
        .unwrap();
        assert!(
            persisted.history.as_ref().unwrap().pending.as_ref()
                == store.journal.history.as_ref().unwrap().pending.as_ref()
        );
        // Retry the original saved handoff after restoring its exact identity.
        store.journal.history.as_mut().unwrap().pending = Some(original);
        store.persist()
    })
    .unwrap();
    assert_eq!(
        Store::resume_retirement_with(&shared, |plan| plan.apply_lower_stores(&buyer, &seller))
            .unwrap(),
        1
    );
    assert_eq!(
        buyer.retired_route_evidence("channel").unwrap().contracts,
        1
    );
    transition_tests::reload(shared.into_inner().unwrap());
}
