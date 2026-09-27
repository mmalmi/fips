//! Real buyer/journal mutations with explicitly modeled mint settlement evidence.
use super::*;
use cashu_service::CashuSpilmanPaymentSigner;

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

fn retained_history(
    root: &Path,
    route_change: bool,
) -> (
    Store,
    Outgoing,
    BuyerAuthorizer,
    DurableRelay,
    FundingIntent,
) {
    let (mut store, old, buyer, seller) = fixture(root);
    consume(&buyer, &old, 1_234);
    let payment = buyer
        .sign_claim(
            &Signer,
            old.purchase.provider,
            &old.purchase.channel.id,
            1_234,
            now().unwrap(),
        )
        .unwrap();
    assert_eq!(payment.balance, 2);
    if route_change {
        // Retain an accepted full target without completing the source Watch:
        // the predecessor still carries its consumed trial allowance.
        replacement(&mut store, &old, &buyer, 30_000, false);
        let watch = store.journal.watched_routes[&old.offer.destination.npub()].clone();
        store
            .change(|j| Controller::withdraw_watched_purchase(j, &watch))
            .unwrap();
    }
    buyer.close_channel(&old.purchase.channel.id).unwrap();
    // This unit fixture supplies validated terminal mint evidence. The buyer's
    // usage, cumulative signature authorization and closure above are real.
    let settlement = serde_json::from_value(serde_json::json!({
        "provider": old.purchase.provider.as_bytes(), "channel": old.purchase.channel,
        "usage": {"paid_msat":2_000,"reserved_msat":1_234,"submitted_msat":1_234,"lost_msat":0},
        "payment": payment,
        "report": {"channel_id":old.purchase.channel.id,"value_after_stage1_sat":32,
            "signed_sat":2,"paid_sat":2,"refunded_sat":30,"fee_sat":0},
        "refunded":true,"released":true,"wallet_refund_sat":30
    }))
    .unwrap();
    store
        .change(|j| {
            j.buyer_settlements
                .insert(old.purchase.channel.id.clone(), settlement);
            Ok(())
        })
        .unwrap();

    // Another destination may legitimately use a fresh funding intent at the
    // same provider after the original channel has been refunded.
    let mut offer = old.offer.clone();
    offer.id = "abandoned-other-destination".into();
    offer.destination = PeerIdentity::from_pubkey_full(Identity::generate().pubkey_full());
    offer.next_hop = *offer.destination.node_addr();
    offer.path = vec![offer.provider, offer.next_hop];
    let watch = WatchedRoute {
        destination: offer.destination.npub(),
        pending: None,
        selected_trial: None,
        ..store.journal.watched_routes[&old.offer.destination.npub()].clone()
    };
    let mut intent = store.journal.funding[&old.funding_id].clone();
    intent.id = "test-2".into();
    intent.funded = None;
    store
        .change(|j| {
            j.watched_routes
                .insert(watch.destination.clone(), watch.clone());
            let reserved = Controller::reserve_purchase(j, offer.clone())?;
            Controller::reserve_watched_offer(j, Some(&watch), &reserved)?;
            j.funding.insert(intent.id.clone(), intent.clone());
            j.next_funding = 3;
            Ok(())
        })
        .unwrap();
    let pending = store.journal.watched_routes[&watch.destination].clone();
    store
        .change(|j| Controller::withdraw_watched_purchase(j, &pending))
        .unwrap();
    (transition_tests::reload(store), old, buyer, seller, intent)
}

#[test]
fn terminal_trial_history_does_not_own_a_different_abandoned_funding() {
    for route_change in [false, true] {
        let root = tempfile::tempdir().unwrap();
        let (mut store, old, buyer, seller, intent) = retained_history(root.path(), route_change);
        let original = store.journal.clone();
        let quota = buyer.retained_quota(&old.offer).unwrap();
        let budget = buyer.remaining_budget_sat();
        assert_eq!(quota, Some((false, 28_766)));
        assert_eq!(budget, Some(1022));
        assert_eq!(
            store.journal.outgoing[&old.purchase.contract.id].retired,
            route_change
        );
        assert_eq!(store.journal.route_changes.len(), usize::from(route_change));
        assert_eq!(
            Controller::capital(&store.journal)
                .unwrap()
                .pending_reserved_sat,
            32
        );
        let pending = store
            .change(|j| Controller::prepare_funding_reclaim(j, &intent))
            .expect("terminal history on another intent must not own this abandoned send");
        store = transition_tests::reload(store);
        assert_eq!(
            Controller::capital(&store.journal)
                .unwrap()
                .pending_reserved_sat,
            32
        );
        let result = ReclaimedFunding {
            wallet_operation_id: "original-second-send".into(),
            wallet_cost: cashu_service::CashuSendCost {
                token_amount_sat: 32,
                swap_fee_sat: 0,
                wallet_debit_sat: 32,
            },
            recovered_amount_sat: 30,
        };
        for _ in 0..2 {
            store
                .change(|j| Controller::record_funding_reclaim(j, &pending, result.clone()))
                .unwrap();
            store = transition_tests::reload(store);
        }
        let capital = Controller::capital(&store.journal).unwrap();
        assert_eq!((capital.pending_reserved_sat, capital.locked_sat), (0, 0));
        assert_eq!(
            (capital.wallet_debited_sat, capital.wallet_refunded_sat),
            (64, 60)
        );
        assert_eq!(capital.exposure_sat, 4);
        assert!(store.journal.funding[&old.funding_id] == original.funding[&old.funding_id]);
        for key in [
            "outgoing",
            "requested",
            "route_changes",
            "watched_routes",
            "buyer_settlements",
        ] {
            assert_eq!(
                serde_json::to_value(&store.journal).unwrap()[key],
                serde_json::to_value(&original).unwrap()[key],
                "retained {key}"
            );
        }
        assert_eq!(store.journal.next_funding, original.next_funding);
        assert!(
            Controller::check_purchase(&store.journal, &old.offer, Some(&old.purchase.channel.id))
                .is_err()
        );
        assert_eq!(
            store
                .retire_routes(&buyer, &seller, old.offer.expires_unix)
                .unwrap(),
            0
        );
        drop(buyer);
        let buyer = BuyerAuthorizer::load(&root.path().join("buyer")).unwrap();
        assert_eq!(buyer.retained_quota(&old.offer).unwrap(), quota);
        assert_eq!(buyer.remaining_budget_sat(), budget);
        assert_eq!(buyer.observed_units(&old.purchase.contract.id), Some(1_234));
        assert_eq!(
            Controller::interrupted_trial_hint(
                &store.journal,
                &store.journal.watched_routes[&old.offer.destination.npub()]
            )
            .unwrap(),
            Some(old.offer)
        );
        transition_tests::reload(store);
    }
}

#[test]
fn reclaim_does_not_ignore_live_owners_or_unproven_terminal_history() {
    for case in [
        "same funding",
        "missing funding",
        "missing settlement",
        "release unfinished",
        "different channel",
        "different provider",
        "refund missing",
        "refund differs",
        "live request",
        "pending watch",
        "prepared incoming",
        "unfinished renewal",
        "unknown predecessor",
        "changed historical offer",
    ] {
        let root = tempfile::tempdir().unwrap();
        let history = matches!(case, "unknown predecessor" | "changed historical offer");
        let (mut store, old, buyer, _, intent) = retained_history(root.path(), history);
        let offer = store.journal.requested["abandoned-other-destination"].clone();
        match case {
            // Corrupt/unmatched references must fail closed, even when the
            // remaining channel and settlement evidence looks terminal.
            "same funding" => {
                store
                    .journal
                    .outgoing
                    .get_mut(&old.purchase.contract.id)
                    .unwrap()
                    .funding_id = intent.id.clone();
            }
            "missing funding" => {
                store.journal.funding.remove(&old.funding_id);
            }
            "missing settlement" => {
                store
                    .journal
                    .buyer_settlements
                    .remove(&old.purchase.channel.id);
            }
            "release unfinished" => {
                store
                    .journal
                    .buyer_settlements
                    .get_mut(&old.purchase.channel.id)
                    .unwrap()
                    .released = false;
            }
            "different channel" => {
                store
                    .journal
                    .buyer_settlements
                    .get_mut(&old.purchase.channel.id)
                    .unwrap()
                    .channel
                    .capacity_sat -= 1;
            }
            "different provider" => {
                store
                    .journal
                    .buyer_settlements
                    .get_mut(&old.purchase.channel.id)
                    .unwrap()
                    .provider = NodeAddr::from_bytes([7; 16]);
            }
            "refund missing" => {
                store
                    .journal
                    .buyer_settlements
                    .get_mut(&old.purchase.channel.id)
                    .unwrap()
                    .wallet_refund_sat = None;
            }
            "refund differs" => {
                store
                    .journal
                    .buyer_settlements
                    .get_mut(&old.purchase.channel.id)
                    .unwrap()
                    .wallet_refund_sat = Some(29);
            }
            "live request" | "pending watch" => {
                store.journal.recovery_only.remove(&offer.id);
                if case == "pending watch" {
                    store
                        .journal
                        .watched_routes
                        .get_mut(&offer.destination.npub())
                        .unwrap()
                        .pending = Some(offer.clone());
                }
            }
            "prepared incoming" => {
                let mut upstream = offer.clone();
                upstream.id = "live-upstream-owner".into();
                upstream.provider = store.journal.local;
                upstream.buyer = NodeAddr::from_bytes([7; 16]);
                upstream.next_hop = offer.provider;
                upstream.path.insert(0, upstream.provider);
                let mut terms = old.purchase.channel.clone();
                terms.id = "live-upstream-channel".into();
                terms.buyer = upstream.buyer;
                let incoming = Incoming {
                    contract: contract_from_offer(&upstream, &terms).unwrap(),
                    offer: upstream,
                    downstream: Some(offer.clone()),
                    channel: terms,
                    verified_paid_msat: 0,
                    phase: Phase::Prepared,
                    replaces: None,
                    replacement_retired: false,
                };
                store
                    .journal
                    .incoming
                    .insert(incoming.contract.id.clone(), incoming);
            }
            "unfinished renewal" => {
                store.journal.renewals.insert(
                    old.purchase.channel.id.clone(),
                    serde_json::from_value(serde_json::json!({
                        "previous":[old], "replacements":null, "completed":false
                    }))
                    .unwrap(),
                );
            }
            "unknown predecessor" => {
                store
                    .journal
                    .route_changes
                    .values_mut()
                    .next()
                    .unwrap()
                    .previous[0]
                    .contract
                    .id = "unknown-history".into();
            }
            "changed historical offer" => {
                let mut changed = old.offer.clone();
                changed.price.msat += 1;
                store.journal.requested.insert(changed.id.clone(), changed);
            }
            _ => unreachable!(),
        }
        if matches!(
            case,
            "release unfinished"
                | "live request"
                | "pending watch"
                | "prepared incoming"
                | "unfinished renewal"
                | "changed historical offer"
        ) {
            Controller::validate_journal(
                &store.journal,
                &store.journal.policy,
                store.journal.local,
            )
            .unwrap();
        }
        let before = serde_json::to_value(&store.journal).unwrap();
        let disk = std::fs::read(store.directory.join("controller.json")).unwrap();
        assert!(
            store
                .change(|j| Controller::prepare_funding_reclaim(j, &intent))
                .is_err(),
            "{case}"
        );
        assert_eq!(
            serde_json::to_value(&store.journal).unwrap(),
            before,
            "{case}"
        );
        assert_eq!(
            std::fs::read(store.directory.join("controller.json")).unwrap(),
            disk,
            "{case}"
        );
        assert_eq!(buyer.retained_quota(&old.offer), Ok(Some((false, 28_766))));
        assert_eq!(buyer.remaining_budget_sat(), Some(1022));
    }
}

#[test]
fn terminal_trial_history_does_not_own_a_different_unused_opening() {
    for route_change in [false, true] {
        let root = tempfile::tempdir().unwrap();
        let (mut store, old, buyer, seller, intent) = retained_history(root.path(), route_change);
        let original = store.journal.clone();
        // Model a verified original SDK opening, retaining the existing intent
        // and operation. There is no accepted purchase or local buyer channel.
        let mut funded = store.journal.funding[&old.funding_id]
            .funded
            .clone()
            .unwrap();
        funded.terms.id = "original-second-channel".into();
        funded.opening.channel_id = funded.terms.id.clone();
        funded.wallet_operation_id = "original-second-send".into();
        store
            .change(|j| Controller::record_funding(j, intent.clone(), funded.clone()))
            .unwrap();
        store = transition_tests::reload(store);
        let intent = store.journal.funding[&intent.id].clone();
        let deadline = intent.expires_unix + 60;
        let before = serde_json::to_value(&store.journal).unwrap();
        assert!(
            store
                .prepare_expiry_refund(&buyer, &intent, deadline)
                .is_err()
        );
        assert_eq!(serde_json::to_value(&store.journal).unwrap(), before);
        let channel = store
            .prepare_expiry_refund(&buyer, &intent, deadline + 1)
            .expect("terminal history on another intent must not own this unused channel");
        assert_eq!(channel, funded.terms);
        store = transition_tests::reload(store);
        let pending = &store.journal.buyer_settlements[&channel.id];
        assert!(pending.kind == SettlementKind::Expiry && !pending.terminal());
        assert!(pending.usage.is_none() && pending.payment.is_none() && pending.report.is_none());
        assert_eq!(buyer.authorized_sat(&channel.id), None);
        let before = serde_json::to_value(&store.journal).unwrap();
        assert!(
            store
                .change(|j| Controller::finish_expiry_refund(j, &intent, &channel, 33))
                .is_err()
        );
        assert_eq!(serde_json::to_value(&store.journal).unwrap(), before);
        for _ in 0..2 {
            store
                .change(|j| Controller::finish_expiry_refund(j, &intent, &channel, 30))
                .unwrap();
            store = transition_tests::reload(store);
        }
        let capital = Controller::capital(&store.journal).unwrap();
        assert_eq!((capital.pending_reserved_sat, capital.locked_sat), (0, 0));
        assert_eq!(
            (capital.wallet_debited_sat, capital.wallet_refunded_sat),
            (64, 60)
        );
        assert_eq!(capital.exposure_sat, 4);
        assert!(store.journal.funding[&old.funding_id] == original.funding[&old.funding_id]);
        assert!(store.journal.funding[&intent.id] == intent);
        assert_eq!(
            serde_json::to_value(&store.journal.buyer_settlements[&old.purchase.channel.id])
                .unwrap(),
            serde_json::to_value(&original.buyer_settlements[&old.purchase.channel.id]).unwrap()
        );
        for key in ["outgoing", "requested", "route_changes", "watched_routes"] {
            assert_eq!(
                serde_json::to_value(&store.journal).unwrap()[key],
                serde_json::to_value(&original).unwrap()[key],
                "retained {key}"
            );
        }
        assert_eq!(store.journal.next_funding, original.next_funding);
        assert!(
            Controller::check_purchase(&store.journal, &old.offer, Some(&old.purchase.channel.id))
                .is_err()
        );
        assert_eq!(
            store
                .retire_routes(&buyer, &seller, old.offer.expires_unix)
                .unwrap(),
            0
        );
        drop(buyer);
        let buyer = BuyerAuthorizer::load(&root.path().join("buyer")).unwrap();
        assert_eq!(buyer.retained_quota(&old.offer), Ok(Some((false, 28_766))));
        assert_eq!(buyer.remaining_budget_sat(), Some(1022));
        assert_eq!(buyer.observed_units(&old.purchase.contract.id), Some(1_234));
        transition_tests::reload(store);
    }
}
