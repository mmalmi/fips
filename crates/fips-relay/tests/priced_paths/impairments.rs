//! Impair the existing paid diamond's real carrier, never its quality samples.
use super::*;
use fips_core::{FipsEndpointServiceReceiver, SourceRouteQuality};

#[derive(Clone, Copy, Debug)]
pub(super) enum Scenario {
    Blackhole,
    Exhaustion,
    AdmissionExhaustion,
    Loss,
    Delay,
    ReturnLoss,
    AutomaticLoss,
    AutomaticDelay,
    QualityChurn,
    Mobility,
    InterruptedMobility,
    RecoveryTiming,
    MergeSplit,
}

impl Scenario {
    pub(super) fn selection_policy(self) -> PriceSelectionPolicy {
        if matches!(self, Self::RecoveryTiming) {
            return PriceSelectionPolicy::default();
        }
        let mut policy = super::selection_policy();
        match self {
            // Loss must change the delivered-cost ranking, not trip the ceiling.
            Self::Loss | Self::AutomaticLoss | Self::QualityChurn => policy.max_loss_percent = 80,
            Self::Delay | Self::AutomaticDelay => policy.max_rtt_ms = 150,
            Self::Mobility | Self::InterruptedMobility => {
                policy.retry_after_ms = policy.feedback_timeout_ms;
            }
            _ => {}
        }
        if matches!(
            self,
            Self::AutomaticLoss | Self::AutomaticDelay | Self::QualityChurn
        ) {
            // Preserve observations through a five-second automatic refresh;
            // recovery still requires a fresh bounded trial after ten seconds.
            policy.feedback_timeout_ms = 10_000;
            policy.retry_after_ms = 10_000;
        }
        if matches!(self, Self::AdmissionExhaustion) {
            policy.feedback_timeout_ms = 60_000;
            policy.retry_after_ms = 60_000;
        }
        if matches!(self, Self::QualityChurn | Self::AdmissionExhaustion) {
            policy.trial_max_units = PriceSelectionPolicy::default().trial_max_units;
        }
        policy
    }

    pub(super) fn alternative_price(self) -> u64 {
        match self {
            Self::RecoveryTiming => 160,
            Self::Loss => 1126,
            // Both the loss-adjusted upgrade and healthy-price return exceed
            // the unchanged ten-percent switching margin.
            Self::AutomaticLoss | Self::QualityChurn => 1280,
            _ => 2048,
        }
    }

    pub(super) fn apply(self, network: &SimNetwork) {
        let ordinary = SimLink {
            latency_ms: 2,
            ..Default::default()
        };
        match self {
            Self::Loss | Self::AutomaticLoss | Self::QualityChurn => network.set_directed_link(
                "1",
                "3",
                Some(SimLink {
                    loss_probability: 0.35,
                    ..ordinary
                }),
            ),
            Self::Delay | Self::AutomaticDelay => network.set_link(
                "1",
                "3",
                SimLink {
                    latency_ms: 250,
                    ..ordinary
                },
            ),
            Self::ReturnLoss => network.set_directed_link(
                "3",
                "1",
                Some(SimLink {
                    loss_probability: 1.0,
                    ..ordinary
                }),
            ),
            _ => unreachable!("the original scenarios use their existing fault drivers"),
        }
    }

    pub(super) fn observed(self, q: &SourceRouteQuality) -> bool {
        match self {
            Self::Loss | Self::AutomaticLoss | Self::QualityChurn => {
                q.has_recent_delivery_feedback
                    && !q.delivery_feedback_timed_out
                    && q.loss_rate.is_some_and(|v| (0.25..=0.8).contains(&v))
            }
            Self::Delay | Self::AutomaticDelay => {
                q.has_recent_delivery_feedback
                    && !q.delivery_feedback_timed_out
                    && q.rtt_ms.is_some_and(|v| v > 150.0)
            }
            Self::ReturnLoss => q.delivery_feedback_timed_out,
            _ => false,
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn priced_routes_use_real_loss_delay_and_asymmetric_feedback() {
    for seed in [114, 115] {
        for scenario in [Scenario::Loss, Scenario::Delay, Scenario::ReturnLoss] {
            eprintln!("paid impairment {scenario:?}, seed={seed}");
            tokio::time::timeout(Duration::from_secs(120), run(0, scenario, seed))
                .await
                .expect("paid impairment scenario deadline");
        }
    }
}

pub(super) async fn observe_then_select(
    scenario: Scenario,
    network: &SimNetwork,
    nodes: &[Arc<FipsEndpoint>],
    peers: &[PeerIdentity],
    controller: &Controller,
    receiver: &mut FipsEndpointServiceReceiver,
) {
    // Retain the paid path while obtaining attributable evidence, then ask the
    // production selector to act on that evidence. Background payments continue.
    controller.pause_route_refresh().await.unwrap();
    let before = network.stats();
    let initial = nodes[0]
        .source_route_quality(peers[3], Duration::from_secs(2))
        .await
        .unwrap();
    scenario.apply(network);
    let mut delivered = 0;
    let mut last_quality = initial.clone();
    let mut batch = Vec::new();
    let observation = tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            nodes[0]
                .send_datagram(peers[3], 44_740, 44_740, vec![11; 200])
                .await
                .unwrap();
            if let Ok(Some(_)) = tokio::time::timeout(
                Duration::from_millis(100),
                receiver.recv_batch_into(&mut batch, 64),
            )
            .await
            {
                delivered += batch
                    .iter()
                    .filter(|m| {
                        m.source_peer.node_addr() == peers[0].node_addr()
                            && m.data.as_slice() == [11; 200]
                    })
                    .count();
            }
            last_quality = nodes[0]
                .source_route_quality(peers[3], Duration::from_secs(2))
                .await
                .unwrap();
            assert_eq!(last_quality.next_hop, Some(*peers[1].node_addr()));
            if last_quality.sent_packets >= initial.sent_packets + 20
                && delivered > 0
                && scenario.observed(&last_quality)
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await;
    let delta = network.stats().delta_since(&before);
    assert!(
        observation.is_ok(),
        "{scenario:?} must produce native evidence: delivered={delivered} quality={last_quality:?} wire={delta:?} error={:?}",
        controller.last_error()
    );
    if matches!(scenario, Scenario::Loss | Scenario::ReturnLoss) {
        assert!(
            delta.packets_dropped_loss > 0,
            "fault must reach the carrier"
        );
    }
    eprintln!("{scenario:?}: delivered={delivered}, quality={last_quality:?}, wire={delta:?}");
    let RouteAccess::Paid(replacement) = controller.watch_route(peers[3], 4096).await.unwrap()
    else {
        panic!("quality-selected replacement requires a paid purchase");
    };
    assert_eq!(
        replacement.provider,
        *peers[2].node_addr(),
        "{scenario:?}: actual quality must overcome the cheaper advertisement"
    );
}
