//! Native impairment feedback drives a continuously authorized source watch.
use super::*;
use fips_core::FipsEndpointServiceReceiver;
use fips_relay::controller::Purchase;
use std::{collections::BTreeSet, path::Path};
use tokio::time::Instant;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn automatic_watch_leaves_impaired_routes_and_reuses_recovered_channel() {
    for (root, scenario, seed) in [
        (0, Scenario::AutomaticLoss, 114),
        (1, Scenario::AutomaticDelay, 115),
    ] {
        eprintln!("automatic quality {scenario:?}, root={root}, seed={seed}");
        tokio::time::timeout(Duration::from_secs(180), run(root, scenario, seed))
            .await
            .expect("automatic quality scenario deadline");
    }
}

struct Driver<'a> {
    scenario: Scenario,
    nodes: &'a [Arc<FipsEndpoint>],
    peers: &'a [PeerIdentity],
    controllers: &'a [Arc<Controller>],
    services: &'a [ControllerServices],
    receiver: &'a mut FipsEndpointServiceReceiver,
    root: &'a Path,
    evidence: mobility::Evidence,
    observed_degradation: bool,
}

impl Driver<'_> {
    async fn sample(&mut self) {
        let next = mobility::Evidence::read(self.root, &self.controllers[0]).await;
        next.follows(&self.evidence);
        self.evidence = next;
        let watches = self.controllers[0].watched_routes().await.unwrap();
        assert_eq!(watches.len(), 1);
        assert!(!watches[0].paused, "the original watch must remain active");
        assert_eq!(watches[0].destination, self.peers[3].npub());
        assert_eq!(watches[0].max_rate_msat_per_kib, 4096);
    }

    async fn selected_and_delivering(&mut self, provider: usize, tag: u8) -> Purchase {
        let policy = self.scenario.selection_policy();
        let before: BTreeSet<_> = self.controllers[0]
            .purchase_history()
            .await
            .unwrap()
            .into_iter()
            .map(|purchase| purchase.contract.id)
            .collect();
        let result = tokio::time::timeout(Duration::from_secs(55), async {
            let mut last_send = Instant::now() - Duration::from_secs(1);
            let mut delivering_on_selected = false;
            let mut delivered = false;
            loop {
                self.sample().await;
                if last_send.elapsed() >= Duration::from_millis(300) {
                    // Application traffic only: no additional Buy/Watch, payment
                    // flush, paused refresh, injected metric or forced binding.
                    let payload_tag = if delivering_on_selected {
                        tag + 32
                    } else {
                        tag
                    };
                    self.nodes[0]
                        .send_datagram(self.peers[3], 44_740, 44_740, vec![payload_tag; 200])
                        .await
                        .unwrap();
                    last_send = Instant::now();
                }
                let quality = self.nodes[0]
                    .source_route_quality(
                        self.peers[3],
                        Duration::from_millis(policy.feedback_timeout_ms),
                    )
                    .await
                    .unwrap();
                if quality.next_hop == Some(*self.peers[1].node_addr())
                    && self.scenario.observed(&quality)
                {
                    self.observed_degradation = true;
                }
                let mut batch = Vec::new();
                if let Ok(Some(_)) = tokio::time::timeout(
                    Duration::from_millis(20),
                    self.receiver.recv_batch_into(&mut batch, 32),
                )
                .await
                {
                    delivered |= delivering_on_selected
                        && batch.iter().any(|message| {
                            message.source_peer.node_addr() == self.peers[0].node_addr()
                                && message.data.as_slice() == [tag + 32; 200]
                        });
                }
                let selected = self.controllers[0]
                    .purchases()
                    .await
                    .unwrap()
                    .into_iter()
                    .find(|purchase| purchase.provider == *self.peers[provider].node_addr());
                if selected.is_some() && quality.next_hop == Some(*self.peers[provider].node_addr())
                {
                    // This tag is first submitted after the actual native
                    // carrier changed; queued old-path payloads cannot satisfy it.
                    delivering_on_selected = true;
                }
                if let Some(purchase) = selected
                    && purchase.contract.max_units > policy.trial_max_units
                    && delivered
                    && quality.next_hop == Some(purchase.provider)
                    && quality.has_recent_delivery_feedback
                    && !quality.delivery_feedback_timed_out
                    && quality.loss_rate.is_some_and(|loss| loss < 0.1)
                    && quality
                        .rtt_ms
                        .is_some_and(|rtt| rtt <= policy.max_rtt_ms as f64)
                {
                    assert_eq!(purchase.channel.capacity_sat, 64);
                    assert_eq!(purchase.contract.max_units, 1_000_000);
                    assert_eq!(
                        purchase.contract.price.msat,
                        if provider == 1 {
                            1024
                        } else {
                            self.scenario.alternative_price()
                        },
                    );
                    let history = self.controllers[0].purchase_history().await.unwrap();
                    assert!(
                        history.iter().any(|trial| {
                            trial.provider == purchase.provider
                                && trial.channel.id == purchase.channel.id
                                && trial.contract.max_units == policy.trial_max_units
                                && !before.contains(&trial.contract.id)
                        }),
                        "automatic replacement must begin with a newly capped trial"
                    );
                    assert_eq!(
                        history
                            .iter()
                            .map(|p| &p.channel.id)
                            .collect::<BTreeSet<_>>()
                            .len(),
                        2,
                        "only the original two provider channels may be funded",
                    );
                    return purchase;
                }
                tokio::time::sleep(Duration::from_millis(30)).await;
            }
        })
        .await;
        match result {
            Ok(purchase) => purchase,
            Err(_) => {
                let quality = self.nodes[0]
                    .source_route_quality(
                        self.peers[3],
                        Duration::from_millis(policy.feedback_timeout_ms),
                    )
                    .await
                    .unwrap();
                panic!(
                    "automatic quality {:?} provider {provider} deadline: native_bad={} quality={quality:?} errors={:?}",
                    self.scenario,
                    self.observed_degradation,
                    errors(self.controllers),
                );
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn exercise(
    scenario: Scenario,
    network: &SimNetwork,
    nodes: &[Arc<FipsEndpoint>],
    peers: &[PeerIdentity],
    controllers: &[Arc<Controller>],
    services: &[ControllerServices],
    receiver: &mut FipsEndpointServiceReceiver,
    first: &Purchase,
    root: &Path,
) {
    let evidence = mobility::Evidence::read(root, &controllers[0]).await;
    let mut driver = Driver {
        scenario,
        nodes,
        peers,
        controllers,
        services,
        receiver,
        root,
        evidence,
        observed_degradation: false,
    };
    let before = network.stats();
    scenario.apply(network);
    let alternative = driver.selected_and_delivering(2, 21).await;
    assert!(
        driver.observed_degradation,
        "native feedback must expose the actual impairment"
    );
    let wire = network.stats().delta_since(&before);
    if matches!(scenario, Scenario::AutomaticLoss) {
        assert!(
            wire.packets_dropped_loss > 0,
            "loss must reach the real carrier"
        );
    }
    assert_ne!(alternative.channel.id, first.channel.id);
    assert!(
        driver.services[2]
            .seller
            .channel_usage(&alternative.channel.id)
            .unwrap()
            .paid_msat
            > 0
    );

    network.set_directed_link("1", "3", None);
    network.set_link(
        "1",
        "3",
        SimLink {
            latency_ms: 2,
            ..Default::default()
        },
    );
    let recovered = driver.selected_and_delivering(1, 22).await;
    assert_eq!(
        recovered.channel, first.channel,
        "healthy cheap route reuses its original account"
    );
    assert_ne!(recovered.contract.id, first.contract.id);
    assert_ne!(recovered.contract.id, alternative.contract.id);
    driver.sample().await;
    let budget = controllers[0].funding_budget().await.unwrap();
    assert_eq!(budget.wallet_debited_sat, 128);
    assert_eq!(budget.wallet_refunded_sat, 0);
    assert_eq!(budget.locked_sat, 128);
    // The shared fixture now reloads the controller and selector, checks the
    // retained chosen channel, then settles both and conserves all 259 test sats.
}
