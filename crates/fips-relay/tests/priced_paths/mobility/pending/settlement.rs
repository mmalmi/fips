//! Lose a durable settlement report across genuine provider eviction/rejoin.
use super::*;
use fips_relay::controller::SettlementReport;
use serde_json::Value;

#[cfg(feature = "measurements")]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn lost_settlement_report_during_mobile_rejoin_recovers_without_replacing_funding() {
    // The ordinary lost-Accept prelude establishes a recoverable abandoned
    // account. This case adds a second departure after automatic mint closure.
    tokio::time::timeout(
        Duration::from_secs(420),
        run(
            0,
            Scenario::InterruptedMobility {
                lose_settlement: true,
            },
            114,
        ),
    )
    .await
    .expect("lost settlement report mobility scenario deadline");
}

pub(super) struct Captured {
    report: SettlementReport,
    buyer: Value,
    seller: Value,
    funding: Value,
    sequence: Value,
    policy: Value,
    remaining: u64,
}

impl Captured {
    fn new(driver: &Driver<'_>, accepted: &gate::Accepted, report: SettlementReport) -> Self {
        assert_eq!(report.channel_id, accepted.purchase.channel.id);
        assert_eq!(report.paid_sat + report.refunded_sat, 64);
        assert_eq!(report.value_after_stage1_sat, 64);
        assert_eq!(report.fee_sat + report.receiver_fee_reserve_sat, 0);
        let buyer = journal(driver.root, 0);
        let seller = journal(driver.root, 2);
        let outgoing = &buyer["buyer_settlements"][&report.channel_id];
        let incoming = &seller["seller_settlements"][&report.channel_id];
        assert!(outgoing["channel"] == serde_json::to_value(&accepted.purchase.channel).unwrap());
        assert!(incoming["channel"] == outgoing["channel"]);
        assert!(!outgoing["usage"].is_null() && !outgoing["payment"].is_null());
        assert!(incoming["usage"] == outgoing["usage"]);
        assert!(incoming["payment"] == outgoing["payment"]);
        assert_eq!(
            outgoing["payment"]["balance"].as_u64(),
            Some(report.paid_sat)
        );
        assert!(outgoing["report"].is_null());
        assert_eq!(outgoing["refunded"], false);
        assert_eq!(outgoing["released"], false);
        assert!(outgoing["wallet_refund_sat"].is_null());
        assert!(incoming["report"] == serde_json::to_value(&report).unwrap());
        assert_eq!(incoming["released"], false);
        assert_eq!(
            seller["incoming"][&accepted.purchase.contract.id]["phase"],
            "Stopped"
        );
        Self {
            report,
            buyer: outgoing.clone(),
            seller: incoming.clone(),
            funding: buyer["funding"].clone(),
            sequence: buyer["next_funding"].clone(),
            policy: buyer["policy"].clone(),
            remaining: driver.services[0].buyer.remaining_budget_sat().unwrap(),
        }
    }

    fn observe(&mut self, driver: &Driver<'_>) -> (Value, Value) {
        let buyer = journal(driver.root, 0);
        let seller = journal(driver.root, 2);
        assert!(
            buyer["funding"] == self.funding,
            "recovery changed funding or wallet operation identities"
        );
        assert_eq!(buyer["next_funding"], self.sequence);
        assert!(
            buyer["policy"] == self.policy,
            "recovery changed spending authority"
        );
        let outgoing = &buyer["buyer_settlements"][&self.report.channel_id];
        let incoming = &seller["seller_settlements"][&self.report.channel_id];
        // Never print signed payment bodies in an assertion failure.
        for field in ["channel", "usage", "payment"] {
            assert!(
                outgoing[field] == self.buyer[field],
                "final buyer {field} changed"
            );
            assert!(
                incoming[field] == self.seller[field],
                "final seller {field} changed"
            );
        }
        assert!(
            incoming["report"] == self.seller["report"],
            "durable seller report changed"
        );
        let remaining = driver.services[0].buyer.remaining_budget_sat().unwrap();
        assert!(
            remaining <= self.remaining,
            "settlement reset lifetime spending"
        );
        self.remaining = remaining;
        assert_eq!(
            driver.services[0]
                .buyer
                .authorized_sat(&self.report.channel_id),
            Some(self.report.paid_sat)
        );
        (outgoing.clone(), incoming.clone())
    }

    async fn held(&mut self, driver: &Driver<'_>) {
        let (buyer, seller) = self.observe(driver);
        assert!(buyer == self.buyer, "held report reached the buyer");
        assert!(
            seller == self.seller,
            "unacknowledged seller report was released"
        );
        let budget = driver.controllers[0].funding_budget().await.unwrap();
        assert_eq!(budget.wallet_debited_sat, 128);
        assert_eq!(budget.pending_reserved_sat, 0);
        assert_eq!(budget.locked_sat, 128);
        assert_eq!(budget.wallet_refunded_sat, 0);
    }

    pub(super) async fn completed(&mut self, driver: &Driver<'_>, deadline: Instant) {
        tokio::time::timeout_at(deadline, async {
            loop {
                let (buyer, seller) = self.observe(driver);
                if buyer["refunded"] == true
                    && buyer["released"] == true
                    && seller["released"] == true
                {
                    assert!(
                        buyer["report"] == serde_json::to_value(&self.report).unwrap(),
                        "automatic report differs from the lost reply"
                    );
                    assert_eq!(
                        buyer["wallet_refund_sat"].as_u64(),
                        Some(self.report.refunded_sat)
                    );
                    break;
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        })
        .await
        .expect(
            "automatic identical report/refund/release must precede explicit settlement replay",
        );
        let budget = driver.controllers[0].funding_budget().await.unwrap();
        assert_eq!(budget.wallet_debited_sat, 128);
        assert_eq!(budget.pending_reserved_sat, 0);
        assert_eq!(budget.locked_sat, 64);
        assert_eq!(budget.wallet_refunded_sat, self.report.refunded_sat);
        assert_eq!(budget.exposure_sat, 128 - self.report.refunded_sat);
        // Independent wallet reads belong after worker shutdown; upkeep can
        // still own the wallet while the durable completion is observed here.
    }

    pub(super) async fn replayed(&mut self, driver: &Driver<'_>, report: &SettlementReport) {
        assert_eq!(report, &self.report);
        self.completed(driver, Instant::now() + Duration::from_secs(2))
            .await;
        eprintln!(
            "lost settlement report: explicit replay preserves the exact report and financial totals"
        );
    }
}

pub(super) async fn interrupt(
    driver: &mut Driver<'_>,
    network: &SimNetwork,
    gate: &mut ResponseGate,
    accepted: &gate::Accepted,
    first: &Purchase,
) -> Captured {
    let report = gate.settled().await;
    let mut captured = Captured::new(driver, accepted, report);
    captured.held(driver).await;
    // Isolate both edges: no routed alternative may deliver a retried report.
    network.set_link_up("0", "2", false);
    network.set_link_up("2", "3", false);
    let cut = Instant::now();
    let discarded = gate.discard_settled().await;
    assert!(
        discarded > 0,
        "a real successful settlement reply must be lost"
    );
    tokio::time::timeout(Duration::from_secs(50), async {
        loop {
            captured.held(driver).await;
            if !driver.connected(0, 2).await
                && !driver.connected(2, 0).await
                && !driver.connected(2, 3).await
                && !driver.connected(3, 2).await
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await
    .expect("settled provider must actually lose all native neighbors");
    driver.paid_delivery(first, 1, 145).await;
    #[cfg(feature = "measurements")]
    {
        let target = driver.services[1]
            .seller
            .channel_usage(&first.channel.id)
            .unwrap()
            .paid_msat;
        tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                let progress = driver.controllers[0].payment_progress().await.unwrap();
                if progress[&first.channel.id]
                    .acknowledged_msat
                    .is_some_and(|paid| paid >= target)
                {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        })
        .await
        .expect("unaffected route payment must be acknowledged while provider 2 is absent");
    }
    captured.held(driver).await;
    eprintln!(
        "lost settlement report: discarded={discarded}, all provider neighbors evicted, independent delivery/payment preserved, absence_ms={}",
        cut.elapsed().as_millis()
    );
    network.set_link_up("0", "2", true);
    network.set_link_up("2", "3", true);
    tokio::time::timeout(Duration::from_secs(50), async {
        loop {
            captured.observe(driver);
            if driver.connected(0, 2).await
                && driver.connected(2, 0).await
                && driver.connected(2, 3).await
                && driver.connected(3, 2).await
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await
    .expect("settled provider must rejoin through native handshakes");
    captured
}
