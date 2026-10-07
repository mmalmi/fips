use super::*;

fn fixture() -> (QuotePolicy, StoredOffer) {
    let (policy, _, mut offer) = crate::route_quotes::tests::quote_fixture();
    offer.expires_unix = unix_now().unwrap() + 100;
    (
        policy,
        StoredOffer {
            offer,
            downstream: None,
        },
    )
}

fn open(directory: &Path, policy: &QuotePolicy, entry: &StoredOffer, create: bool) -> Offers {
    let (journal, pending) =
        OfferJournal::open(directory, entry.offer.provider, policy, create).unwrap();
    Offers {
        epoch: "test-epoch".into(),
        next_id: 1,
        pending,
        journal: Some(journal),
        ready: true,
    }
}

#[test]
fn issued_quotes_and_retirement_survive_restart_with_original_terms() {
    let root = tempfile::tempdir().unwrap();
    let (policy, entry) = fixture();
    let mut offers = open(root.path(), &policy, &entry, true);
    offers
        .commit(BTreeMap::from([(entry.offer.id.clone(), entry.clone())]))
        .unwrap();
    assert!(
        OfferJournal::open(root.path(), entry.offer.provider, &policy, false).is_err(),
        "a live quote journal has one owner"
    );
    drop(offers);
    let mut recovered = open(root.path(), &policy, &entry, false);
    assert_eq!(recovered.pending[&entry.offer.id].offer, entry.offer);
    assert!(recovered.pending[&entry.offer.id].downstream.is_none());
    recovered.retire(&entry.offer.id).unwrap();
    let after = std::fs::read(root.path().join(FILE)).unwrap();
    recovered.retire(&entry.offer.id).unwrap();
    assert_eq!(
        std::fs::read(root.path().join(FILE)).unwrap(),
        after,
        "idempotent retirement does not rewrite the journal"
    );
    drop(recovered);
    assert!(open(root.path(), &policy, &entry, false).pending.is_empty());
}

#[test]
fn changed_scope_malformed_quotes_and_missing_journals_fail_closed() {
    let root = tempfile::tempdir().unwrap();
    let (policy, entry) = fixture();
    let mut offers = open(root.path(), &policy, &entry, true);
    offers
        .commit(BTreeMap::from([(entry.offer.id.clone(), entry.clone())]))
        .unwrap();
    drop(offers);
    let original = std::fs::read(root.path().join(FILE)).unwrap();
    let mut changed = policy.clone();
    changed.fee_msat_per_kib += 1;
    assert!(OfferJournal::open(root.path(), entry.offer.provider, &changed, false).is_err());
    assert!(OfferJournal::open(root.path(), entry.offer.buyer, &policy, false).is_err());
    for case in 0..6 {
        let mut saved: Saved = serde_json::from_slice(&original).unwrap();
        match case {
            0 => saved
                .pending
                .values_mut()
                .next()
                .unwrap()
                .offer
                .path
                .reverse(),
            1 => saved.pending.values_mut().next().unwrap().offer.price.msat += 1,
            2 => saved.pending.values_mut().next().unwrap().offer.id = "different-id".into(),
            3 => {
                saved
                    .pending
                    .values_mut()
                    .next()
                    .unwrap()
                    .offer
                    .receiver_pubkey_hex = "00".repeat(33)
            }
            4 => {
                for index in 0..MAX_OFFERS_PER_BUYER {
                    let mut extra = entry.clone();
                    extra.offer.id = format!("extra-{index}");
                    saved.pending.insert(extra.offer.id.clone(), extra);
                }
            }
            _ => saved.version += 1,
        }
        std::fs::write(root.path().join(FILE), serde_json::to_vec(&saved).unwrap()).unwrap();
        assert!(
            OfferJournal::open(root.path(), entry.offer.provider, &policy, false).is_err(),
            "case {case}"
        );
    }
    std::fs::write(root.path().join(FILE), vec![b' '; MAX_BYTES as usize + 1]).unwrap();
    assert!(OfferJournal::open(root.path(), entry.offer.provider, &policy, false).is_err());
    std::fs::remove_file(root.path().join(FILE)).unwrap();
    assert!(OfferJournal::open(root.path(), entry.offer.provider, &policy, false).is_err());
}

#[test]
fn failed_quote_commit_suspends_publication_and_retirement() {
    let root = tempfile::tempdir().unwrap();
    let (policy, entry) = fixture();
    let mut offers = open(root.path(), &policy, &entry, true);
    std::fs::remove_file(root.path().join(FILE)).unwrap();
    std::fs::create_dir(root.path().join(FILE)).unwrap();
    assert!(
        offers
            .commit(BTreeMap::from([(entry.offer.id.clone(), entry.clone())]))
            .is_err()
    );
    assert!(offers.pending.is_empty());
    assert!(offers.ensure_ready().is_err());
    assert!(offers.retire(&entry.offer.id).is_err());
}
