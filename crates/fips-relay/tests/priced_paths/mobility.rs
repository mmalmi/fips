//! Repeated simulated carrier changes with native peers and test-money accounts.
use super::*;
use fips_core::FipsEndpointServiceReceiver;
use fips_relay::controller::{FundingBudget, Purchase};
use std::{collections::BTreeMap, path::Path};
use tokio::time::Instant;

#[path = "mobility/pending.rs"]
pub(super) mod pending;

// Only these non-secret identities enter diagnostics; opening payment proofs do not.
#[derive(Clone, Debug, PartialEq, Eq)]
struct FundingIdentity {
    channel: String,
    operation: String,
}

struct Evidence {
    funding: BTreeMap<String, FundingIdentity>,
    budget: FundingBudget,
    remaining: u64,
}

impl Evidence {
    async fn read(root: &Path, controller: &Controller) -> Self {
        let saved: serde_json::Value = serde_json::from_slice(
            &std::fs::read(root.join("controller-0/controller.json")).unwrap(),
        )
        .unwrap();
        let intents = saved["funding"].as_object().unwrap();
        assert!(
            intents.len() <= 2,
            "mobility cannot create a third funding intent"
        );
        let funding = intents
            .iter()
            .filter_map(|(id, intent)| {
                let funded = intent["funded"].as_object()?;
                Some((
                    id.clone(),
                    FundingIdentity {
                        channel: funded["terms"]["id"].as_str().unwrap().into(),
                        operation: funded["wallet_operation_id"].as_str().unwrap().into(),
                    },
                ))
            })
            .collect();
        let buyer: serde_json::Value =
            serde_json::from_slice(&std::fs::read(root.join("buyer-0/buyer.json")).unwrap())
                .unwrap();
        assert_eq!(buyer["total_budget_sat"], 128);
        assert!(
            buyer["history"].is_null(),
            "no channel is retired before settlement"
        );
        let channels = buyer["channels"].as_object().unwrap();
        assert!(
            channels.len() <= 2,
            "only the original two provider accounts are allowed"
        );
        let authorized: u64 = channels
            .values()
            .map(|channel| channel["authorized_sat"].as_u64().unwrap())
            .sum();
        assert!(
            authorized <= 128,
            "original lifetime authorization remains bounded"
        );
        let budget = controller.funding_budget().await.unwrap();
        assert!(budget.locked_sat <= 128 && budget.exposure_sat <= 128);
        assert!(budget.wallet_debited_sat <= 128);
        assert_eq!(
            budget.wallet_refunded_sat, 0,
            "departure does not refund a live account"
        );
        Self {
            funding,
            budget,
            remaining: 128 - authorized,
        }
    }

    fn follows(&self, previous: &Self) {
        for (id, identity) in &previous.funding {
            assert_eq!(
                self.funding.get(id),
                Some(identity),
                "funding identity changed"
            );
        }
        assert!(self.budget.wallet_debited_sat >= previous.budget.wallet_debited_sat);
        assert!(self.budget.wallet_refunded_sat >= previous.budget.wallet_refunded_sat);
        assert!(
            self.remaining <= previous.remaining,
            "neighbor changes cannot reset spending"
        );
    }
}

struct Driver<'a> {
    nodes: &'a [Arc<FipsEndpoint>],
    peers: &'a [PeerIdentity],
    controllers: &'a [Arc<Controller>],
    services: &'a [ControllerServices],
    receiver: &'a mut FipsEndpointServiceReceiver,
    root: &'a Path,
    evidence: Evidence,
}

impl Driver<'_> {
    async fn sample(&mut self) {
        let next = Evidence::read(self.root, &self.controllers[0]).await;
        next.follows(&self.evidence);
        self.evidence = next;
    }

    async fn connected(&self, a: usize, b: usize) -> bool {
        self.nodes[a]
            .peers()
            .await
            .unwrap()
            .iter()
            .any(|peer| peer.node_addr == *self.peers[b].node_addr() && peer.connected)
    }

    async fn membership(&mut self, other: usize, connected: bool, phase: &str) {
        let started = Instant::now();
        let result = tokio::time::timeout(Duration::from_secs(50), async {
            loop {
                self.sample().await;
                if self.connected(0, other).await == connected
                    && self.connected(other, 0).await == connected
                {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(200)).await;
            }
        })
        .await;
        assert!(
            result.is_ok(),
            "{phase}: native membership deadline; {:?}",
            errors(self.controllers)
        );
        eprintln!(
            "mobile {phase}: membership after {:.2}s",
            started.elapsed().as_secs_f64()
        );
    }

    async fn selected(&mut self, provider: usize, tag: u8) -> Purchase {
        let started = Instant::now();
        let result = tokio::time::timeout(Duration::from_secs(45), async {
            loop {
                self.sample().await;
                if let Some(purchase) = self.controllers[0]
                    .purchases()
                    .await
                    .unwrap()
                    .into_iter()
                    .find(|purchase| purchase.provider == *self.peers[provider].node_addr())
                {
                    return purchase;
                }
                // Real traffic supplies native path feedback. It is not another
                // Buy, a synthetic quality sample or an explicit payment flush.
                self.nodes[0]
                    .send_datagram(self.peers[3], 44_740, 44_740, vec![tag; 200])
                    .await
                    .unwrap();
                let mut batch = Vec::new();
                let _ = tokio::time::timeout(
                    Duration::from_millis(100),
                    self.receiver.recv_batch_into(&mut batch, 32),
                )
                .await;
                tokio::time::sleep(Duration::from_millis(800)).await;
            }
        })
        .await;
        let purchase = result.unwrap_or_else(|_| {
            panic!(
                "automatic provider {provider} selection deadline: {:?}",
                errors(self.controllers)
            )
        });
        assert_eq!(purchase.contract.destination, *self.peers[3].node_addr());
        assert_eq!(
            purchase.contract.price.msat,
            if provider == 1 { 1024 } else { 2048 }
        );
        eprintln!(
            "mobile provider {provider}: automatic selection after {:.2}s",
            started.elapsed().as_secs_f64()
        );
        purchase
    }

    async fn paid_delivery(&mut self, purchase: &Purchase, provider: usize, tag: u8) {
        let started = Instant::now();
        let buyer = self.services[0].buyer.clone();
        let seller = self.services[provider].seller.clone();
        let before = seller
            .channel_usage(&purchase.channel.id)
            .unwrap()
            .paid_msat;
        let evidence_before = buyer.evidence_msat(&purchase.channel.id).unwrap();
        let mut received = [false; 3];
        let mut attempts = [0; 3];
        let mut target = None;
        let result = tokio::time::timeout(Duration::from_secs(20), async {
            loop {
                for index in 0..3 {
                    if !received[index] && attempts[index] < 6 {
                        let mut payload = vec![tag; 400];
                        payload[0] = index as u8;
                        self.nodes[0]
                            .send_datagram(self.peers[3], 44_740, 44_740, payload)
                            .await
                            .unwrap();
                        attempts[index] += 1;
                    }
                }
                let mut batch = Vec::new();
                if let Ok(Some(_)) = tokio::time::timeout(
                    Duration::from_millis(200),
                    self.receiver.recv_batch_into(&mut batch, 32),
                )
                .await
                {
                    for message in batch {
                        let payload = message.data.as_slice();
                        if message.source_peer.node_addr() == self.peers[0].node_addr()
                            && payload.len() == 400
                            && payload[1..].iter().all(|byte| *byte == tag)
                            && let Some(found) = received.get_mut(payload[0] as usize)
                        {
                            *found = true;
                        }
                    }
                }
                self.sample().await;
                if received.iter().all(|value| *value) && target.is_none() {
                    let evidence = buyer.evidence_msat(&purchase.channel.id).unwrap();
                    assert!(
                        evidence > evidence_before,
                        "fresh traffic must incur local evidence"
                    );
                    // A departure can leave attempted bytes at the buyer that
                    // never reached the provider. The production payer signs
                    // only the overlap of those two retained evidence totals.
                    let submitted = seller
                        .channel_usage(&purchase.channel.id)
                        .unwrap()
                        .submitted_msat;
                    let expected = evidence.min(submitted).div_ceil(1_000) * 1_000;
                    assert!(
                        expected > before,
                        "fresh burst must need another cumulative payment"
                    );
                    target = Some(expected);
                }
                let quality = self.nodes[0]
                    .source_route_quality(self.peers[3], Duration::from_secs(2))
                    .await
                    .unwrap();
                if target.is_some_and(|expected| {
                    seller
                        .channel_usage(&purchase.channel.id)
                        .unwrap()
                        .paid_msat
                        >= expected
                }) && quality.next_hop == Some(purchase.provider)
                    && quality.has_recent_delivery_feedback
                    && !quality.delivery_feedback_timed_out
                {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(300)).await;
            }
        })
        .await;
        assert!(
            result.is_ok(),
            "provider {provider}: delivery/feedback/payment deadline; received={received:?} attempts={attempts:?} paid={} target={target:?} errors={:?}",
            seller
                .channel_usage(&purchase.channel.id)
                .unwrap()
                .paid_msat,
            errors(self.controllers)
        );
        let paid = seller
            .channel_usage(&purchase.channel.id)
            .unwrap()
            .paid_msat;
        assert!(paid > before);
        // Sample authorization after provider credit to avoid a cross-journal race.
        assert!(paid <= buyer.authorized_sat(&purchase.channel.id).unwrap() * 1_000);
        eprintln!(
            "mobile provider {provider}: fresh delivery + automatic payment in {:.2}s",
            started.elapsed().as_secs_f64()
        );
    }
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn exercise(
    network: &SimNetwork,
    nodes: &[Arc<FipsEndpoint>],
    peers: &[PeerIdentity],
    controllers: &[Arc<Controller>],
    services: &[ControllerServices],
    receiver: &mut FipsEndpointServiceReceiver,
    first: &Purchase,
    root: &Path,
) {
    let evidence = Evidence::read(root, &controllers[0]).await;
    assert_eq!(evidence.funding.len(), 1);
    assert_eq!(evidence.budget.wallet_debited_sat, 64);
    assert_eq!(evidence.budget.locked_sat, 64);
    let original = evidence.funding.clone();
    let mut driver = Driver {
        nodes,
        peers,
        controllers,
        services,
        receiver,
        root,
        evidence,
    };
    assert!(driver.connected(0, 1).await);
    assert!(!driver.connected(0, 2).await);
    let mut two_channels = None;
    let mut alternative_channel = None;
    for cycle in 0..2 {
        let started = Instant::now();
        network.set_link_up("0", "2", true);
        driver.membership(2, true, "alternative joins").await;
        network.set_link_up("0", "1", false);
        // Configured transport addresses can remain as reconnect hints; the
        // authenticated active sessions must actually be evicted on both sides.
        driver.membership(1, false, "original departs").await;
        assert!(driver.connected(0, 2).await);
        let alternative = driver.selected(2, 110 + cycle * 4).await;
        if let Some(channel) = &alternative_channel {
            assert_eq!(
                &alternative.channel.id, channel,
                "returning provider reuses its channel"
            );
        } else {
            alternative_channel = Some(alternative.channel.id.clone());
        }
        assert_ne!(alternative.channel.id, first.channel.id);
        driver.paid_delivery(&alternative, 2, 111 + cycle * 4).await;
        assert!(
            !driver.connected(0, 1).await,
            "healthy payments progressed while old peer was absent"
        );
        driver.sample().await;
        assert_eq!(driver.evidence.funding.len(), 2);
        assert_eq!(driver.evidence.budget.wallet_debited_sat, 128);
        assert_eq!(driver.evidence.budget.locked_sat, 128);
        assert_eq!(driver.evidence.budget.pending_reserved_sat, 0);
        for (id, identity) in &original {
            assert_eq!(driver.evidence.funding.get(id), Some(identity));
        }
        if let Some(saved) = &two_channels {
            assert_eq!(
                &driver.evidence.funding, saved,
                "second departure cannot fund again"
            );
        } else {
            two_channels = Some(driver.evidence.funding.clone());
        }
        network.set_link_up("0", "1", true);
        driver.membership(1, true, "original rejoins").await;
        let returned = driver.selected(1, 112 + cycle * 4).await;
        assert_eq!(
            returned.channel, first.channel,
            "eligible original account must be reused"
        );
        driver.paid_delivery(&returned, 1, 113 + cycle * 4).await;
        driver.sample().await;
        assert_eq!(Some(&driver.evidence.funding), two_channels.as_ref());
        assert_eq!(driver.evidence.budget.wallet_debited_sat, 128);
        assert_eq!(driver.evidence.budget.locked_sat, 128);
        assert_eq!(driver.evidence.budget.pending_reserved_sat, 0);
        assert!(driver.connected(0, 1).await && driver.connected(0, 2).await);
        eprintln!(
            "mobile cycle {} complete in {:.2}s: channels=2 debit=128 refund=0 remaining={}",
            cycle + 1,
            started.elapsed().as_secs_f64(),
            driver.evidence.remaining
        );
    }
}
