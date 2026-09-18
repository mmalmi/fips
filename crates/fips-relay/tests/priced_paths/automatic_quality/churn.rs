//! Keep real loss feedback and financial authority through an alternative's departure.
use super::*;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn quality_failover_survives_alternative_departure_without_refunding_or_rebuying() {
    tokio::time::timeout(
        Duration::from_secs(360),
        run(0, Scenario::QualityChurn, 114),
    )
    .await
    .expect("combined quality and neighbor churn deadline");
}

impl Driver<'_> {
    async fn trial_accounting(&self, phase: &str) {
        let quota = self.scenario.selection_policy().trial_max_units;
        let trials: Vec<_> = self.controllers[0]
            .purchase_history()
            .await
            .unwrap()
            .into_iter()
            .filter(|p| p.contract.max_units == quota)
            .map(|p| {
                let provider = self
                    .peers
                    .iter()
                    .position(|peer| *peer.node_addr() == p.provider)
                    .unwrap();
                serde_json::json!({"provider": provider, "quota": quota,
                    "source_observed": self.services[0].buyer.observed_units(&p.contract.id),
                    "seller_usage": self.services[provider].seller.usage(&p.contract.id)})
            })
            .collect();
        // Record framing counters are separate from billed session bytes: they
        // exclude TCP/FIPS headers, acknowledgments and retransmissions.
        eprintln!(
            "quality churn {phase}: trials={trials:?} source_control quotes={:?} acceptance={:?} payments={:?}",
            self.quote_statistics.snapshot(),
            self.services[0].acceptance.statistics().snapshot(),
            self.services[0].payments.statistics().snapshot()
        );
    }

    pub(super) async fn churn_diagnostics(&self) {
        self.trial_accounting("deadline").await;
        for (index, node) in self.nodes.iter().enumerate() {
            let destination = if index == 0 { 3 } else { 0 };
            let quality = node
                .source_route_quality(self.peers[destination], Duration::from_secs(10))
                .await
                .unwrap();
            let connected: Vec<_> = node
                .peers()
                .await
                .unwrap()
                .into_iter()
                .filter(|p| p.connected)
                .map(|p| {
                    self.peers
                        .iter()
                        .position(|known| *known.node_addr() == p.node_addr)
                })
                .collect();
            let saved: serde_json::Value = serde_json::from_slice(
                &std::fs::read(
                    self.root
                        .join(format!("controller-{index}/controller.json")),
                )
                .unwrap(),
            )
            .unwrap();
            let watched: Vec<_> = saved["watched_routes"].as_object().unwrap().values()
                .map(|watch| serde_json::json!({"paused": watch["paused"], "has_pending": !watch["pending"].is_null()})).collect();
            let outgoing: Vec<_> = saved["outgoing"]
                .as_object()
                .unwrap()
                .values()
                .map(|record| {
                    serde_json::json!({"accepted": record["accepted"], "retired": record["retired"],
                    "quota": record["purchase"]["contract"]["max_units"]})
                })
                .collect();
            let purchases = self.controllers[index].purchases().await.unwrap();
            let active: Vec<_> = purchases.iter().map(|p| {
                serde_json::json!({"provider": self.peers.iter().position(|peer| *peer.node_addr() == p.provider),
                    "quota": p.contract.max_units,
                    "observed": self.services[index].buyer.observed_units(&p.contract.id).unwrap(),
                    "authorized_sat": self.services[index].buyer.authorized_sat(&p.channel.id).unwrap()})
            }).collect();
            eprintln!(
                "quality churn diagnostics node={index}: connected={connected:?} next_hop={:?} quality={quality:?} watched={watched:?} outgoing={outgoing:?} active={active:?} capital={:?}",
                quality
                    .next_hop
                    .and_then(|hop| self.peers.iter().position(|peer| *peer.node_addr() == hop)),
                self.controllers[index].funding_budget().await.unwrap()
            );
        }
    }

    async fn membership(&mut self, provider: usize, connected: bool) {
        tokio::time::timeout(Duration::from_secs(55), async {
            loop {
                self.sample().await;
                let mut observed = Vec::new();
                for (source, destination) in [(0, provider), (provider, 0)] {
                    observed.push(
                        self.nodes[source]
                            .peers()
                            .await
                            .unwrap()
                            .iter()
                            .any(|peer| {
                                peer.node_addr == *self.peers[destination].node_addr()
                                    && peer.connected
                            }),
                    );
                }
                if observed.iter().all(|value| *value == connected) {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(200)).await;
            }
        })
        .await
        .expect("native membership must actually observe the carrier change");
    }

    async fn advancing_payment(&mut self, purchase: &Purchase, provider: usize, tag: u8) {
        let initial = self.services[provider]
            .seller
            .channel_usage(&purchase.channel.id)
            .unwrap()
            .paid_msat;
        tokio::time::timeout(Duration::from_secs(30), async {
            let mut delivered = false;
            loop {
                self.sample().await;
                self.nodes[0]
                    .send_datagram(self.peers[3], 44_740, 44_740, vec![tag; 200])
                    .await
                    .unwrap();
                let mut batch = Vec::new();
                if let Ok(Some(_)) = tokio::time::timeout(
                    Duration::from_millis(150),
                    self.receiver.recv_batch_into(&mut batch, 32),
                )
                .await
                {
                    delivered |= batch.iter().any(|message| {
                        message.source_peer.node_addr() == self.peers[0].node_addr()
                            && message.data.as_slice() == [tag; 200]
                    });
                }
                let paid = self.services[provider]
                    .seller
                    .channel_usage(&purchase.channel.id)
                    .unwrap()
                    .paid_msat;
                let quality = self.nodes[0]
                    .source_route_quality(self.peers[3], Duration::from_secs(10))
                    .await
                    .unwrap();
                if delivered && paid > initial && quality.next_hop == Some(purchase.provider) {
                    assert!(
                        paid <= self.services[0]
                            .buyer
                            .authorized_sat(&purchase.channel.id)
                            .unwrap()
                            * 1000
                    );
                    return;
                }
                tokio::time::sleep(Duration::from_millis(300)).await;
            }
        })
        .await
        .expect("the reused selected channel must deliver and advance automatic payment");
    }
}

pub(super) async fn exercise(
    driver: &mut Driver<'_>,
    network: &SimNetwork,
    first: &Purchase,
    alternative: &Purchase,
) {
    driver.trial_accounting("before departure").await;
    let purchase_ids = driver.purchase_ids().await;
    let before = network.stats();
    eprintln!(
        "quality churn: working alternative selected; removing its source adjacency while original forward loss remains 35%"
    );
    network.set_link_up("0", "2", false);
    driver.membership(2, false).await;
    eprintln!(
        "quality churn: source and alternative both report adjacency absent; requesting no new route authority"
    );
    let fallback = driver
        .selected_and_delivering(1, 24, true, &purchase_ids)
        .await;
    driver.trial_accounting("fallback promoted").await;
    assert_eq!(fallback.channel, first.channel);
    driver.advancing_payment(&fallback, 1, 90).await;
    assert!(network.stats().delta_since(&before).packets_dropped_loss > 0);
    eprintln!(
        "quality churn: alternative absent; impaired original delivered and paid through its original channel"
    );

    let purchase_ids = driver.purchase_ids().await;
    network.set_link_up("0", "2", true);
    driver.membership(2, true).await;
    let returned = driver
        .selected_and_delivering(2, 25, false, &purchase_ids)
        .await;
    assert_eq!(returned.channel, alternative.channel);
    driver.advancing_payment(&returned, 2, 91).await;
    driver.sample().await;
    let budget = driver.controllers[0].funding_budget().await.unwrap();
    assert_eq!(budget.wallet_debited_sat, 128);
    assert_eq!(budget.locked_sat, 128);
    assert_eq!(budget.wallet_refunded_sat, 0);
    assert_eq!(budget.pending_reserved_sat, 0);
    eprintln!(
        "quality churn: healthy alternative rejoined; original two channels and lifetime spending preserved"
    );
}
