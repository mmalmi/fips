use super::*;
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    mpsc,
};

fn incoming(store: &Store, old: &Outgoing, number: usize) -> Incoming {
    let mut offer = old.offer.clone();
    offer.id = format!("incoming-{number}");
    offer.buyer = NodeAddr::from_bytes([number as u8 + 3; 16]);
    offer.provider = store.journal.local;
    offer.path = vec![offer.provider, *offer.destination.node_addr()];
    let mut channel = old.purchase.channel.clone();
    channel.id = format!("incoming-channel-{number}");
    channel.buyer = offer.buyer;
    Incoming {
        contract: contract_from_offer(&offer, &channel).unwrap(),
        offer,
        channel,
        downstream: None,
        verified_paid_msat: 0,
        phase: Phase::Prepared,
        replaces: None,
        replacement_retired: false,
    }
}

#[test]
fn last_incoming_slot_excludes_competing_receiver_writes_but_keeps_retries() {
    let root = tempfile::tempdir().unwrap();
    let directory = root.path().join("controller");
    let (mut store, old) = super::super::transition_tests::fixture(&directory);
    for number in 0..MAX_ROUTES - 1 {
        let saved = incoming(&store, &old, number);
        store
            .journal
            .incoming
            .insert(saved.contract.id.clone(), saved);
    }
    store.persist().unwrap();
    let first = incoming(&store, &old, MAX_ROUTES);
    let retry = first.clone();
    let second = incoming(&store, &old, MAX_ROUTES + 1);
    let store = Arc::new(Mutex::new(store));
    let writes = Arc::new(AtomicUsize::new(0));
    let (entered, reached) = mpsc::channel();
    let (release, held) = mpsc::channel();
    let first_worker = {
        let store = store.clone();
        let writes = writes.clone();
        std::thread::spawn(move || {
            store.lock().unwrap().change(|j| {
                Controller::admit_incoming(j, first, |_| {
                    writes.fetch_add(1, Ordering::SeqCst);
                    entered.send(()).unwrap();
                    held.recv_timeout(Duration::from_secs(5)).unwrap();
                    Ok(0)
                })
            })
        })
    };
    reached.recv_timeout(Duration::from_secs(5)).unwrap();
    assert!(
        store.try_lock().is_err(),
        "verification lost admission ownership"
    );
    let second_worker = {
        let store = store.clone();
        let writes = writes.clone();
        std::thread::spawn(move || {
            store.lock().unwrap().change(|j| {
                Controller::admit_incoming(j, second, |_| {
                    writes.fetch_add(1, Ordering::SeqCst);
                    Ok(0)
                })
            })
        })
    };
    release.send(()).unwrap();
    assert!(first_worker.join().unwrap().is_ok());
    assert!(second_worker.join().unwrap().is_err());
    assert_eq!(
        writes.load(Ordering::SeqCst),
        1,
        "rejected funding was persisted"
    );
    let store = Arc::try_unwrap(store).ok().unwrap().into_inner().unwrap();
    let mut store = super::super::transition_tests::reload(store);
    assert_eq!(store.journal.incoming.len(), MAX_ROUTES);
    let before = std::fs::read(directory.join("controller.json")).unwrap();
    let credited = store
        .change(|j| {
            Controller::admit_incoming(j, retry, |_| {
                writes.fetch_add(1, Ordering::SeqCst);
                Ok(1_000)
            })
        })
        .unwrap();
    assert_eq!(credited.verified_paid_msat, 1_000);
    assert_eq!(writes.load(Ordering::SeqCst), 2);
    assert_eq!(store.journal.incoming.len(), MAX_ROUTES);
    assert_eq!(
        std::fs::read(directory.join("controller.json")).unwrap(),
        before
    );
}

#[test]
fn replacement_checks_precede_receiver_writes_and_verification_keeps_old_service() {
    let root = tempfile::tempdir().unwrap();
    let directory = root.path().join("controller");
    let (mut store, old) = super::super::transition_tests::fixture(&directory);
    let mut previous = incoming(&store, &old, 0);
    previous.phase = Phase::Active;
    store
        .journal
        .incoming
        .insert(previous.contract.id.clone(), previous.clone());
    store.persist().unwrap();
    let mut replacement = incoming(&store, &old, 1);
    replacement.offer.buyer = previous.channel.buyer;
    replacement.channel.buyer = previous.channel.buyer;
    replacement.replaces = Some("absent-route".into());
    let writes = AtomicUsize::new(0);
    let before = std::fs::read(directory.join("controller.json")).unwrap();
    assert!(
        store
            .change(|j| Controller::admit_incoming(j, replacement.clone(), |_| {
                writes.fetch_add(1, Ordering::SeqCst);
                Ok(0)
            }))
            .is_err()
    );
    assert_eq!(writes.load(Ordering::SeqCst), 0);
    replacement.replaces = Some(previous.contract.id.clone());
    assert!(
        store
            .change(|j| Controller::admit_incoming(j, replacement.clone(), |_| {
                Err("funding verification failed".into())
            }))
            .is_err()
    );
    assert!(store.journal.incoming[&previous.contract.id].phase == Phase::Active);
    assert_eq!(
        std::fs::read(directory.join("controller.json")).unwrap(),
        before
    );
    let accepted = store
        .change(|j| Controller::admit_incoming(j, replacement, |_| Ok(0)))
        .unwrap();
    assert!(store.journal.incoming[&previous.contract.id].phase == Phase::Stopped);
    let store = super::super::transition_tests::reload(store);
    assert!(store.journal.incoming[&accepted.contract.id].phase == Phase::Prepared);
}
