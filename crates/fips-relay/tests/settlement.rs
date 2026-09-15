//! Real CDK mint/Spilman settlement. Only Lightning funding is simulated.
//! Native FIPS transport is covered separately; this test supplies local
//! submission outcomes to production accounting for three neighboring sellers.

use cashu::{
    Token,
    nuts::{CurrencyUnit, Proof},
};
use cashu_service::{
    CashuSpilmanPaymentSigner, FileSpilmanPaymentReceiver, FileSpilmanPaymentReceiverConfig,
    FileSpilmanPaymentSigner, StreamingRouteOpenCashuSpilmanChannelFromWalletRequest,
    create_topup_quote, load_mint_balance, load_wallet_overview,
    open_streaming_route_cashu_spilman_channel_from_wallet, receive_payment_token,
    restore_streaming_route_cashu_spilman_refund, send_payment_token,
    simulation::{IssuerMode, LocalMint, PaymentNetwork, VirtualClock},
};
use fips_core::{
    Identity, NodeAddr, PeerIdentity,
    node::{ForwardingOutcome, ForwardingPolicy, ForwardingRequest},
};
use fips_relay::{
    ledger::{BytePrice, ChannelTerms, Contract, Limits, RelayLedger},
    payment::process_payment,
};
use std::{
    path::Path,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

async fn redeem_proofs(wallet: &Path, mint: &str, encoded: &str) -> String {
    let proofs: Vec<Proof> = serde_json::from_str(encoded).unwrap();
    let token = Token::new(mint.parse().unwrap(), proofs, None, CurrencyUnit::Sat).to_string();
    receive_payment_token(wallet, &token)
        .await
        .expect("redeem signed receiver payout");
    token
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn persistent_neighbor_channels_settle_multiple_routes_and_preserve_every_relay_margin() {
    tokio::time::timeout(Duration::from_secs(90), async {
        let root = tempfile::tempdir().unwrap();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let network = PaymentNetwork::new(91, 0, Arc::new(VirtualClock::new(now)));
        let mint = LocalMint::start(
            root.path(),
            network.clone(),
            "relay-test",
            IssuerMode::ClosedLoop,
        )
        .await
        .unwrap();
        let wallets: Vec<_> = (0..4)
            .map(|i| root.path().join(format!("wallet-{i}")))
            .collect();
        let identities: Vec<_> = (1..=5)
            .map(|i| {
                PeerIdentity::from_pubkey_full(
                    Identity::from_secret_bytes(&[i; 32]).unwrap().pubkey_full(),
                )
            })
            .collect();
        for wallet in wallets.iter().take(3) {
            let quote = create_topup_quote(wallet, mint.url(), 64).await.unwrap();
            network
                .orchestrator_funding()
                .settle_external(&quote.payment_request)
                .unwrap();
            let overview = load_wallet_overview(wallet, true).await.unwrap();
            assert!(overview.warnings.is_empty());
            assert_eq!(
                load_mint_balance(wallet, mint.url())
                    .await
                    .unwrap()
                    .balance_sat,
                64
            );
        }
        let mut sellers = Vec::new();
        let mut channels = Vec::new();
        let mut quotes = Vec::new();
        let mut ledgers = Vec::new();
        for i in 0..3 {
            let seller = FileSpilmanPaymentReceiver::load_with_keyset_refresh(
                &root.path().join(format!("receiver-{i}")),
                FileSpilmanPaymentReceiverConfig::new([mint.url().to_string()]),
            )
            .await
            .unwrap();
            let opened = open_streaming_route_cashu_spilman_channel_from_wallet(
                &wallets[i],
                StreamingRouteOpenCashuSpilmanChannelFromWalletRequest {
                    mint_url: mint.url().to_string(),
                    receiver_pubkey_hex: seller.receiver_pubkey_hex().to_string(),
                    capacity_sat: 8,
                    expiry_unix: now + 600,
                    max_amount_per_output: 0,
                    unit: "sat".into(),
                    opening_paid_msat: 0,
                    keyset_id: None,
                    keyset_info_json: None,
                    client_request_id: Some(format!("test-neighbor-{i}")),
                    route_created_at_unix: Some(now),
                },
            )
            .await
            .unwrap();
            let channel = ChannelTerms {
                id: opened.channel.channel_id,
                buyer: *identities[i].node_addr(),
                mint_url: mint.url().to_string(),
                expires_unix: now + 600,
                capacity_sat: 8,
                grace_msat: (3 - i) as u64 * 500,
            };
            let mut smaller = channel.clone();
            smaller.capacity_sat = 7;
            assert!(
                process_payment(
                    &seller,
                    &smaller,
                    identities[i],
                    &opened.channel.payment,
                    true
                )
                .is_err()
            );
            let credit = process_payment(
                &seller,
                &channel,
                identities[i],
                &opened.channel.payment,
                true,
            )
            .unwrap();
            let ledger = RelayLedger::new(Limits::default());
            ledger
                .open_channel_verified(channel.clone(), credit.paid_msat)
                .unwrap();
            let a = Contract {
                id: format!("route-{i}-a"),
                channel_id: channel.id.clone(),
                destination: *identities[4].node_addr(),
                next_hop: *identities[i + 2].node_addr(),
                expires_unix: now + 300,
                price: BytePrice {
                    msat: (3 - i) as u64,
                    per_bytes: 1,
                },
                max_units: 500,
            };
            let mut b = a.clone();
            b.id = format!("route-{i}-b");
            b.destination = NodeAddr::from_bytes([77; 16]);
            ledger.add_contract(a.clone()).unwrap();
            ledger.add_contract(b.clone()).unwrap();
            quotes.push([a, b]);
            channels.push(channel);
            sellers.push(seller);
            ledgers.push(ledger);
        }
        let payload = [0xa5; 500];
        for (batch, route) in quotes[0].iter().enumerate() {
            for i in 0..3 {
                let request = ForwardingRequest {
                    ingress: identities[i],
                    next_hop: quotes[i][batch].next_hop,
                    source: *identities[0].node_addr(),
                    destination: route.destination,
                    session_payload: &payload,
                };
                let token = ledgers[i].admit_at(&request, now).unwrap();
                ledgers[i].complete(token, ForwardingOutcome::Submitted);
                assert!(ledgers[i].admit_at(&request, now).is_none());
                let due_msat = ledgers[i]
                    .channel_usage(&channels[i].id)
                    .unwrap()
                    .submitted_msat;
                assert_eq!(due_msat, (3 - i) as u64 * 500 * (batch + 1) as u64);
                let signer = FileSpilmanPaymentSigner::load(&wallets[i]).unwrap();
                // Round the cumulative channel balance, never each flow/update separately.
                let payment = signer
                    .sign_cashu_spilman_payment(&channels[i].id, due_msat.div_ceil(1_000), false)
                    .unwrap();
                assert!(
                    process_payment(&sellers[i], &channels[i], identities[4], &payment, false)
                        .is_err()
                );
                let mut forged = payment.clone();
                forged.balance += 1;
                assert!(
                    process_payment(&sellers[i], &channels[i], identities[i], &forged, false)
                        .is_err()
                );
                let credit =
                    process_payment(&sellers[i], &channels[i], identities[i], &payment, false)
                        .unwrap();
                ledgers[i]
                    .apply_verified_balance(&channels[i].id, credit.paid_msat)
                    .unwrap();
                assert_eq!(
                    process_payment(&sellers[i], &channels[i], identities[i], &payment, false)
                        .unwrap(),
                    credit
                );
            }
        }
        sellers.clear();
        for i in 0..3 {
            sellers.push(
                FileSpilmanPaymentReceiver::load_with_keyset_refresh(
                    &root.path().join(format!("receiver-{i}")),
                    FileSpilmanPaymentReceiverConfig::new([mint.url().to_string()]),
                )
                .await
                .unwrap(),
            );
        }
        for i in 0..3 {
            let closed = sellers[i]
                .close_cashu_spilman_channel(&channels[i].id)
                .await
                .unwrap();
            assert_eq!(closed.receiver_sum, (3 - i) as u64);
            let payout =
                redeem_proofs(&wallets[i + 1], mint.url(), &closed.receiver_proofs_json).await;
            let refund = restore_streaming_route_cashu_spilman_refund(&wallets[i], &channels[i].id)
                .await
                .unwrap();
            assert!(refund.complete);
            assert_eq!(refund.recovered_amount_sat, closed.sender_sum);
            assert!(
                receive_payment_token(&root.path().join(format!("replay-{i}")), &payout)
                    .await
                    .is_err()
            );
            assert!(
                sellers[i]
                    .close_cashu_spilman_channel(&channels[i].id)
                    .await
                    .unwrap()
                    .already_closed
            );
        }
        for (wallet, expected) in wallets.iter().zip([61, 65, 65, 1]) {
            assert_eq!(
                load_mint_balance(wallet, mint.url())
                    .await
                    .unwrap()
                    .balance_sat,
                expected
            );
            let spend = send_payment_token(wallet, mint.url(), expected)
                .await
                .expect("entire final balance must be spendable");
            assert_eq!(
                receive_payment_token(&root.path().join("spendability-check"), &spend.token)
                    .await
                    .unwrap()
                    .amount_sat,
                expected
            );
        }
        assert_eq!(
            load_mint_balance(&root.path().join("spendability-check"), mint.url())
                .await
                .unwrap()
                .balance_sat,
            192
        );
        assert!(network.accounting().unwrap().is_conserved());
        assert_eq!(network.accounting().unwrap().external_funding_sat, 192);
    })
    .await
    .expect("local-mint settlement deadline");
}
