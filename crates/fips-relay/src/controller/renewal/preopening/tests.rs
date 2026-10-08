//! Exercise the production reservation and persisted owner across restarts.
use super::*;
use crate::controller::transition_tests::{fixture, reload};

fn prepared(directory: &Path) -> (Store, Outgoing, RouteOffer) {
    let (mut store, old) = fixture(directory);
    let mut offer = old.offer.clone();
    offer.id = "successor-offer".into();
    store
        .change(|j| {
            j.policy.max_locked_sat = 64;
            Controller::reserve_renewal(j, old.purchase.channel.id.clone())?;
            j.renewals
                .get_mut(&old.purchase.channel.id)
                .unwrap()
                .preopening = Some(Preopening {
                offers: vec![offer.clone()],
                funding_id: None,
            });
            Ok(())
        })
        .unwrap();
    let store = reload(store);
    // Offers persist an npub, while a live identity may also carry ECDH parity.
    // Recovery uses the persisted approval, rather than a pre-save key cache.
    let old = store.journal.outgoing[&old.purchase.contract.id].clone();
    let offer = store.journal.renewals[&old.purchase.channel.id]
        .preopening
        .as_ref()
        .unwrap()
        .offers[0]
        .clone();
    (store, old, offer)
}

#[test]
fn one_owned_successor_survives_restart_without_retiring_or_billing_old_traffic() {
    let root = tempfile::tempdir().unwrap();
    let (mut store, old, offer) = prepared(root.path());
    let initial = Controller::capital(&store.journal).unwrap();
    assert!(
        Controller::preopening_fits(
            &store.journal,
            &store.journal.renewals[&old.purchase.channel.id]
        )
        .unwrap()
    );
    let successor = store
        .change(|j| {
            Controller::reserve_route_funding(
                j,
                &offer,
                Some(&old.purchase.channel.id),
                true,
                now()?,
            )
        })
        .unwrap();
    for _ in 0..2 {
        store = reload(store);
        let again = store
            .change(|j| {
                Controller::reserve_route_funding(
                    j,
                    &offer,
                    Some(&old.purchase.channel.id),
                    true,
                    now()?,
                )
            })
            .unwrap();
        assert_eq!(again.id, successor.id);
        assert_eq!(store.journal.funding.len(), 2);
        assert_eq!(store.journal.next_funding, 3);
        assert_eq!(store.journal.requested.len(), 1);
        assert_eq!(store.journal.outgoing.len(), 1);
        assert!(store.journal.buyer_settlements.is_empty());
        assert!(Controller::routing_eligible(
            &store.journal,
            &store.journal.outgoing[&old.purchase.contract.id]
        ));
        let budget = Controller::capital(&store.journal).unwrap();
        assert_eq!(budget.wallet_debited_sat, initial.wallet_debited_sat);
        assert_eq!(budget.wallet_refunded_sat, initial.wallet_refunded_sat);
        assert_eq!(budget.pending_reserved_sat, 32);
        assert_eq!(budget.locked_sat, 64);
    }
    let before = serde_json::to_value(&store.journal).unwrap();
    // No unrelated buyer may replace the successor's retained owner or reserve
    // a third channel by dropping only the association after a restart.
    assert!(
        store
            .change(|j| {
                j.renewals
                    .get_mut(&old.purchase.channel.id)
                    .unwrap()
                    .preopening
                    .as_mut()
                    .unwrap()
                    .funding_id = None;
                Controller::reserve_route_funding(
                    j,
                    &offer,
                    Some(&old.purchase.channel.id),
                    true,
                    now()?,
                )
            })
            .is_err()
    );
    assert_eq!(serde_json::to_value(&store.journal).unwrap(), before);
    reload(store);
}

#[test]
fn successor_reservation_rechecks_authorization_wallet_ownership_and_capital() {
    let root = tempfile::tempdir().unwrap();
    for case in 0..7 {
        let (mut store, old, offer) = prepared(&root.path().join(case.to_string()));
        let before = serde_json::to_value(&store.journal).unwrap();
        assert!(
            store
                .change(|j| {
                    let mut offer = offer.clone();
                    match case {
                        0 => offer.id = "unapproved".into(),
                        1 => offer.price.msat += 1,
                        2 => j.policy.max_locked_sat = 32,
                        3 => j.policy.max_wallet_spend_sat = 32,
                        4 => j.renewals_paused = true,
                        5 => offer.expires_unix = 1,
                        _ => {}
                    }
                    Controller::reserve_route_funding(
                        j,
                        &offer,
                        Some(&old.purchase.channel.id),
                        case != 6,
                        now()?,
                    )
                })
                .is_err(),
            "case {case}"
        );
        assert_eq!(serde_json::to_value(&store.journal).unwrap(), before);
        let mut store = reload(store);
        store
            .change(|j| {
                j.policy.max_locked_sat = 32;
                Ok(())
            })
            .unwrap();
        assert!(
            !Controller::preopening_fits(
                &store.journal,
                &store.journal.renewals[&old.purchase.channel.id]
            )
            .unwrap()
        );
        assert_eq!(store.journal.funding.len(), 1);
    }
}

#[test]
fn unbound_pair_and_corrupt_successor_binding_cannot_be_loaded() {
    let root = tempfile::tempdir().unwrap();
    let (mut store, old, offer) = prepared(root.path());
    store
        .change(|j| {
            Controller::reserve_route_funding(
                j,
                &offer,
                Some(&old.purchase.channel.id),
                true,
                now()?,
            )
        })
        .unwrap();
    let before = serde_json::to_value(&store.journal).unwrap();
    for case in 0..4 {
        assert!(
            store
                .change(|j| {
                    let p = &mut j
                        .renewals
                        .get_mut(&old.purchase.channel.id)
                        .unwrap()
                        .preopening;
                    match case {
                        0 => *p = None,
                        1 => p.as_mut().unwrap().funding_id = Some(old.funding_id.clone()),
                        2 => {
                            p.as_mut().unwrap().offers[0].receiver_pubkey_hex =
                                format!("02{}", "22".repeat(32))
                        }
                        _ => p.as_mut().unwrap().offers[0]
                            .path
                            .push(NodeAddr::from_bytes([9; 16])),
                    }
                    Controller::validate_journal(j, &j.policy, j.local)
                })
                .is_err()
        );
        assert_eq!(serde_json::to_value(&store.journal).unwrap(), before);
        store = reload(store);
    }
}

#[test]
fn funded_handover_retains_both_capital_owners_through_restart_and_acceptance() {
    let root = tempfile::tempdir().unwrap();
    let (mut store, old, offer) = prepared(root.path());
    let id = old.purchase.channel.id.clone();
    store
        .change(|j| {
            // This fixture exercises persisted authority, not payment signatures.
            let mut funding = j.funding[&old.funding_id].clone();
            funding.id = "test-2".into();
            let funded = funding.funded.as_mut().unwrap();
            funded.terms.id = "successor-channel".into();
            funded.opening.channel_id = funded.terms.id.clone();
            funded.wallet_operation_id = "fixture-operation-2".into();
            j.next_funding += 1;
            j.renewals
                .get_mut(&id)
                .unwrap()
                .preopening
                .as_mut()
                .unwrap()
                .funding_id = Some(funding.id.clone());
            j.funding.insert(funding.id.clone(), funding);
            let payment = j.funding[&old.funding_id]
                .funded
                .as_ref()
                .unwrap()
                .opening
                .clone();
            j.buyer_settlements.insert(
                id.clone(),
                BuyerSettlement {
                    kind: SettlementKind::Cooperative,
                    provider: old.purchase.provider,
                    channel: old.purchase.channel.clone(),
                    usage: Some(ChannelUsage::default()),
                    payment: Some(payment),
                    report: None,
                    released: false,
                    refunded: false,
                    wallet_refund_sat: None,
                },
            );
            Ok(())
        })
        .unwrap();
    store = reload(store);
    store
        .change(|j| Controller::replace_renewal_routes(j, &id, vec![offer.clone()], true))
        .unwrap();
    store = reload(store);
    let funding = Controller::selected_funding(&store.journal, &offer, None)
        .unwrap()
        .unwrap()
        .clone();
    assert_eq!(funding.id, "test-2");
    let channel = funding.funded.as_ref().unwrap().terms.clone();
    let successor = Outgoing {
        offer: offer.clone(),
        funding_id: funding.id,
        purchase: Purchase {
            provider: offer.provider,
            contract: contract_from_offer(&offer, &channel).unwrap(),
            channel,
        },
        accepted: false,
        retired: false,
    };
    for accepted in [false, true] {
        store
            .change(|j| {
                Controller::record_purchase(j, successor.clone())?;
                if accepted {
                    Controller::finish_acceptance(j, &successor.purchase.contract.id)?;
                }
                Ok(())
            })
            .unwrap();
        store = reload(store);
        assert_eq!(store.journal.funding.len(), 2);
        assert!(!store.journal.buyer_settlements[&id].refunded);
        assert!(!store.journal.renewals[&id].completed);
        assert_eq!(Controller::capital(&store.journal).unwrap().locked_sat, 64);
        assert!(!Controller::routing_eligible(
            &store.journal,
            &store.journal.outgoing[&old.purchase.contract.id]
        ));
        assert_eq!(
            store.journal.outgoing[&successor.purchase.contract.id].accepted,
            accepted
        );
        assert!(Controller::check_purchase(&store.journal, &offer, Some(&id)).is_err());
        let mut unowned = offer.clone();
        unowned.id = "unowned-successor".into();
        assert!(Controller::check_purchase(&store.journal, &unowned, None).is_err());
        let before = serde_json::to_value(&store.journal).unwrap();
        assert!(
            store
                .change(|j| Controller::reserve_renewal(j, successor.purchase.channel.id.clone()))
                .is_err()
        );
        for case in 0..5 {
            assert!(
                store
                    .change(|j| {
                        match case {
                            0 => j.renewals.get_mut(&id).unwrap().completed = true,
                            1 => j.buyer_settlements.get_mut(&id).unwrap().payment = None,
                            2 => j.renewals.get_mut(&id).unwrap().handover = false,
                            3 => {
                                j.renewals
                                    .get_mut(&id)
                                    .unwrap()
                                    .preopening
                                    .as_mut()
                                    .unwrap()
                                    .funding_id = Some(old.funding_id.clone())
                            }
                            _ => j.buyer_settlements.get_mut(&id).unwrap().usage = None,
                        }
                        Controller::validate_journal(j, &j.policy, j.local)
                    })
                    .is_err(),
                "case {case}"
            );
            assert_eq!(serde_json::to_value(&store.journal).unwrap(), before);
        }
    }
    reload(store);
}
