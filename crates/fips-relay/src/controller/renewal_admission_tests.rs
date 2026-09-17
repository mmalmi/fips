//! Durable acceptance can precede its parent renewal's completion checkpoint.
use super::*;
use crate::controller::transition_tests::{fixture, reload};
use crate::ledger::ChannelUsage;

fn funded_replacement(journal: &mut Journal, old: &Outgoing, provider: NodeAddr) -> Outgoing {
    let sequence = journal.next_funding;
    let mut funding = journal.funding[&old.funding_id].clone();
    funding.id = format!("test-{sequence}");
    funding.provider = provider;
    let funded = funding.funded.as_mut().unwrap();
    funded.terms.id = format!("channel-{sequence}");
    funded.opening.channel_id = funded.terms.id.clone();
    funded.wallet_operation_id = format!("fixture-operation-{sequence}");
    let mut offer = old.offer.clone();
    offer.id = format!("offer-{sequence}");
    offer.provider = provider;
    offer.path[0] = provider;
    let replacement = Outgoing {
        purchase: Purchase {
            provider,
            channel: funded.terms.clone(),
            contract: contract_from_offer(&offer, &funded.terms).unwrap(),
        },
        offer: offer.clone(),
        funding_id: funding.id.clone(),
        accepted: false,
        retired: false,
    };
    journal.next_funding += 1;
    journal.funding.insert(funding.id.clone(), funding);
    journal.requested.insert(offer.id.clone(), offer);
    journal.outgoing.insert(
        replacement.purchase.contract.id.clone(),
        replacement.clone(),
    );
    replacement
}

fn accepted_before_completion(directory: &Path) -> (Store, Outgoing, Outgoing) {
    let (mut store, old) = fixture(directory);
    let replacement = store
        .change(|journal| {
            Controller::reserve_renewal(journal, old.purchase.channel.id.clone())?;
            let channel = &old.purchase.channel;
            let mut payment = journal.funding[&old.funding_id]
                .funded
                .as_ref()
                .unwrap()
                .opening
                .clone();
            payment.balance = channel.capacity_sat;
            journal.buyer_settlements.insert(
                channel.id.clone(),
                BuyerSettlement {
                    provider: old.purchase.provider,
                    channel: channel.clone(),
                    usage: Some(ChannelUsage {
                        reserved_msat: channel.capacity_sat * 1_000,
                        submitted_msat: channel.capacity_sat * 1_000,
                        lost_msat: 0,
                        paid_msat: channel.capacity_sat * 1_000,
                    }),
                    payment: Some(payment),
                    report: Some(SettlementReport {
                        channel_id: channel.id.clone(),
                        value_after_stage1_sat: channel.capacity_sat,
                        paid_sat: channel.capacity_sat,
                        receiver_fee_reserve_sat: 0,
                        refunded_sat: 0,
                        fee_sat: 0,
                    }),
                    released: true,
                    refunded: true,
                    wallet_refund_sat: Some(0),
                },
            );
            journal
                .outgoing
                .get_mut(&old.purchase.contract.id)
                .unwrap()
                .retired = true;
            journal.requested.remove(&old.offer.id);
            let replacement = funded_replacement(journal, &old, old.purchase.provider);
            journal.renewals.get_mut(&channel.id).unwrap().replacements =
                Some(vec![replacement.offer.clone()]);
            assert!(Controller::finish_acceptance(
                journal,
                &replacement.purchase.contract.id
            )?);
            Ok(journal.outgoing[&replacement.purchase.contract.id].clone())
        })
        .unwrap();
    (reload(store), old, replacement)
}

#[test]
fn accepted_replacement_cannot_reserve_renewal_before_its_predecessor_completes() {
    let root = tempfile::tempdir().unwrap();
    let (mut store, old, replacement) = accepted_before_completion(&root.path().join("controller"));
    assert!(replacement.accepted);
    assert!(!store.journal.renewals[&old.purchase.channel.id].completed);
    let journal = serde_json::to_value(&store.journal).unwrap();
    let saved = std::fs::read(store.directory.join("controller.json")).unwrap();
    let capital = Controller::capital(&store.journal).unwrap();
    let funding = serde_json::to_value(&store.journal.funding).unwrap();
    assert_eq!(capital.wallet_debited_sat, 64);
    assert_eq!(capital.locked_sat, 32);
    assert_eq!(capital.wallet_refunded_sat, 0);
    assert!(
        store
            .change(|j| Controller::reserve_renewal(j, replacement.purchase.channel.id.clone()))
            .is_err(),
        "an accepted replacement cannot block its own unfinished predecessor"
    );
    assert_eq!(serde_json::to_value(&store.journal).unwrap(), journal);
    assert_eq!(
        std::fs::read(store.directory.join("controller.json")).unwrap(),
        saved
    );
    let mut store = reload(store);

    // maintain_renewals records a reservation error and still advances pending
    // renewals. Its accepted-offer path must remain usable after this rejection.
    Controller::check_purchase(
        &store.journal,
        &replacement.offer,
        Some(&replacement.purchase.channel.id),
    )
    .unwrap();
    store
        .change(|j| {
            Controller::reserve_renewal(j, old.purchase.channel.id.clone())?;
            j.renewals
                .get_mut(&old.purchase.channel.id)
                .unwrap()
                .completed = true;
            Ok(())
        })
        .unwrap();
    let mut store = reload(store);
    for _ in 0..2 {
        store
            .change(|j| Controller::reserve_renewal(j, replacement.purchase.channel.id.clone()))
            .unwrap();
        store = reload(store);
    }
    assert_eq!(store.journal.renewals.len(), 2);
    assert!(store.journal.renewals[&old.purchase.channel.id].completed);
    let next = &store.journal.renewals[&replacement.purchase.channel.id];
    assert_eq!(next.previous.len(), 1);
    assert_eq!(next.previous[0].purchase, replacement.purchase);
    assert!(next.replacements.is_none());
    assert_eq!(Controller::capital(&store.journal).unwrap(), capital);
    assert_eq!(
        serde_json::to_value(&store.journal.funding).unwrap(),
        funding
    );
}

#[test]
fn incomplete_predecessor_does_not_reserve_an_unrelated_provider() {
    let root = tempfile::tempdir().unwrap();
    let (mut store, old, _) = accepted_before_completion(&root.path().join("controller"));
    let independent = store
        .change(|j| {
            j.policy.max_locked_sat = 64;
            let independent = funded_replacement(j, &old, NodeAddr::from_bytes([3; 16]));
            assert!(Controller::finish_acceptance(
                j,
                &independent.purchase.contract.id
            )?);
            Ok(j.outgoing[&independent.purchase.contract.id].clone())
        })
        .unwrap();
    let mut store = reload(store);
    let capital = Controller::capital(&store.journal).unwrap();
    let funding = serde_json::to_value(&store.journal.funding).unwrap();
    store
        .change(|j| Controller::reserve_renewal(j, independent.purchase.channel.id.clone()))
        .unwrap();
    let store = reload(store);
    assert!(!store.journal.renewals[&old.purchase.channel.id].completed);
    assert!(
        store
            .journal
            .renewals
            .contains_key(&independent.purchase.channel.id)
    );
    assert_eq!(Controller::capital(&store.journal).unwrap(), capital);
    assert_eq!(
        serde_json::to_value(&store.journal.funding).unwrap(),
        funding
    );
}
