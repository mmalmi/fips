//! Real mint regression for a wallet-committed channel with no Outgoing record.
use super::*;
use cashu_service::{
    FileSpilmanPaymentReceiverConfig, create_topup_quote, load_mint_balance, load_wallet_overview,
    open_streaming_route_cashu_spilman_channel_from_wallet, receive_payment_token,
    refund_expired_cashu_spilman_channel, send_payment_token,
    simulation::{IssuerMode, LocalMint, PaymentNetwork, VirtualClock},
};

#[tokio::test]
async fn withdrawn_funding_without_outgoing_recovers_only_after_immutable_expiry() {
    exercise(false, false).await;
}

#[tokio::test]
async fn unused_installed_channel_recovers_without_fabricating_provider_acceptance() {
    exercise(true, false).await;
}

#[tokio::test]
async fn lost_expiry_completion_reloads_exact_refund_without_reviving_spent_outputs() {
    exercise(false, true).await;
}

async fn exercise(installed: bool, lost_completion: bool) {
    tokio::time::timeout(Duration::from_secs(45), async {
        let root = tempfile::tempdir().unwrap();
        let network = PaymentNetwork::new(8413, 0, Arc::new(VirtualClock::new(now().unwrap())));
        let mint = LocalMint::start(
            root.path(),
            network.clone(),
            "withdrawn-expiry",
            IssuerMode::ClosedLoop,
        )
        .await
        .unwrap();
        let mut policy = crate::controller::tests::unresolved_journal().policy;
        policy.mint_url = mint.url().into();
        policy.channel_lifetime_secs = 60;
        let mut controller =
            crate::controller::refresh::tests::disconnected_controller_with_policy(
                root.path(),
                policy,
            )
            .await;
        let wallet = controller.services.wallet_directory.clone();
        let quote = create_topup_quote(&wallet, mint.url(), 64).await.unwrap();
        network
            .orchestrator_funding()
            .settle_external(&quote.payment_request)
            .unwrap();
        assert!(
            load_wallet_overview(&wallet, true)
                .await
                .unwrap()
                .warnings
                .is_empty()
        );
        let receiver = FileSpilmanPaymentReceiver::load_with_keyset_refresh(
            &root.path().join("expiry-receiver"),
            FileSpilmanPaymentReceiverConfig::new([mint.url().to_string()]),
        )
        .await
        .unwrap();
        let sdk_expiry = now().unwrap() + 5;
        let snapshot = controller.snapshot().await.unwrap();
        let funding = FundingIntent {
            id: cashu_service::CashuRequestSequence::new(
                channel_history::scope(&snapshot),
                snapshot.next_funding,
            )
            .unwrap()
            .request_id(),
            provider: NodeAddr::from_bytes([2; 16]),
            receiver_pubkey_hex: receiver.receiver_pubkey_hex().into(),
            capacity_sat: 32,
            max_wallet_debit_sat: 32,
            grace_msat: 8_000,
            created_unix: sdk_expiry - 120,
            expires_unix: sdk_expiry - 60,
            funded: None,
        };
        // An older persisted reservation may be recovered while the immutable
        // wallet locktime is still in the future. No mint clock is shortened.
        let (_, old) = crate::controller::transition_tests::fixture(&root.path().join("fixture"));
        let mut offer = old.offer;
        offer.buyer = snapshot.local;
        offer.mint_url = mint.url().into();
        offer.receiver_pubkey_hex = funding.receiver_pubkey_hex.clone();
        offer.expires_unix = funding.expires_unix;
        let saved = funding.clone();
        let saved_offer = offer.clone();
        controller
            .change(move |j| {
                j.funding.insert(saved.id.clone(), saved);
                j.next_funding += 1;
                j.advance_history_version(4);
                j.history.as_mut().unwrap().channels =
                    Some(channel_history::ChannelHistory::default());
                j.requested
                    .insert(saved_offer.id.clone(), saved_offer.clone());
                let watch = WatchedRoute {
                    billing: saved_offer.billing,
                    destination: saved_offer.destination.npub(),
                    max_rate_msat_per_kib: 1024,
                    paused: false,
                    pending: Some(saved_offer),
                };
                j.watched_routes
                    .insert(watch.destination.clone(), watch.clone());
                assert!(Controller::withdraw_watched_purchase(j, &watch)?);
                Ok(())
            })
            .await
            .unwrap();
        let opened = open_streaming_route_cashu_spilman_channel_from_wallet(
            &wallet,
            funding.wallet_request(&controller.policy).unwrap(),
        )
        .await
        .unwrap();
        let funded = funding
            .funded_channel(snapshot.local, &controller.policy, opened)
            .unwrap();
        let channel = funded.terms.clone();
        let saved = funding.clone();
        controller
            .change(move |j| Controller::record_funding(j, saved, funded))
            .await
            .unwrap();
        if installed {
            controller
                .services
                .buyer
                .accept_channel(funding.provider, channel.clone(), 0)
                .unwrap();
        }
        assert!(
            now().unwrap() <= sdk_expiry,
            "fixture must exercise the pre-expiry boundary"
        );
        controller.resume_pending().await.unwrap();
        let before = controller.funding_budget().await.unwrap();
        assert_eq!(before.locked_sat, 32);
        assert_eq!(before.wallet_refunded_sat, 0);
        assert_eq!(
            controller.services.buyer.authorized_sat(&channel.id),
            installed.then_some(0)
        );
        while now().unwrap() <= sdk_expiry {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        if lost_completion {
            let saved = controller.snapshot().await.unwrap().funding[&funding.id].clone();
            controller
                .store
                .lock()
                .unwrap()
                .prepare_expiry_refund(&controller.services.buyer, &saved, now().unwrap())
                .unwrap();
            let refund = refund_expired_cashu_spilman_channel(&wallet, &channel.id)
                .await
                .unwrap();
            assert!(refund.complete);
            assert_eq!(refund.total_recovered_amount_sat, Some(32));
            assert_eq!(refund.imported_amount_sat, 32);
            // Consume all original change and recovered outputs before the
            // controller records success. Its retry must use cached SDK evidence.
            let token = send_payment_token(&wallet, mint.url(), 64).await.unwrap();
            let recipient = root.path().join("recipient");
            receive_payment_token(&recipient, &token.token)
                .await
                .unwrap();
            assert_eq!(
                load_mint_balance(&recipient, mint.url())
                    .await
                    .unwrap()
                    .balance_sat,
                64
            );
            let services = controller.services.clone();
            let policy = controller.policy.clone();
            drop(controller);
            controller =
                Controller::load(&root.path().join("controller"), policy, services).unwrap();
            let pending = controller.snapshot().await.unwrap();
            let recovery = &pending.buyer_settlements[&channel.id];
            assert!(!recovery.refunded && !recovery.released);
            assert!(recovery.wallet_refund_sat.is_none() && recovery.report.is_none());
            assert_eq!(controller.funding_budget().await.unwrap().locked_sat, 32);
        }
        controller.resume_pending().await.unwrap();
        let after = controller.funding_budget().await.unwrap();
        assert_eq!(
            after.locked_sat, 0,
            "verified expiry recovery must release the original funded liability"
        );
        assert_eq!(after.wallet_debited_sat, before.wallet_debited_sat);
        assert_eq!(after.wallet_refunded_sat, 32);
        assert_eq!(
            load_mint_balance(&wallet, mint.url())
                .await
                .unwrap()
                .balance_sat,
            if lost_completion { 0 } else { 64 }
        );
        let saved = controller.snapshot().await.unwrap();
        assert!(saved.outgoing.is_empty());
        assert!(saved.history.as_ref().unwrap().buyers.is_empty());
        assert_eq!(saved.next_funding, 2);
        assert!(controller.purchases().await.unwrap().is_empty());
        assert_eq!(controller.services.buyer.authorized_sat(&channel.id), None);
        assert!(
            controller
                .services
                .buyer
                .accept_channel(funding.provider, channel.clone(), 0)
                .is_err(),
            "retirement must fence a delayed local installation"
        );
        let budget = serde_json::to_value(after).unwrap();
        controller.resume_pending().await.unwrap();
        assert_eq!(
            serde_json::to_value(controller.funding_budget().await.unwrap()).unwrap(),
            budget
        );
        assert_eq!(
            load_mint_balance(&wallet, mint.url())
                .await
                .unwrap()
                .balance_sat,
            if lost_completion { 0 } else { 64 }
        );
        controller.services.endpoint.shutdown().await.unwrap();
    })
    .await
    .expect("bounded real-mint withdrawn-funding expiry");
}
