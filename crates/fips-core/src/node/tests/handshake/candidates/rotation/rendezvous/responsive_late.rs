//! Continue a missed encounter without replacing its original acceptance result.
use super::*;

pub(super) struct MissedAcceptance {
    pub encounter: usize,
    pub exposed: tokio::time::Instant,
    pub window: Duration,
    pub bridge_at: Option<Duration>,
    pub delivery_at: Option<Duration>,
    pub next_local_round: Option<tokio::time::Instant>,
}

pub(super) async fn observe(
    nodes: &mut [TestNode],
    endpoints: &mut [EndpointDataIo],
    ids: &[PeerIdentity],
    sequence: &mut u16,
    original: &[RetainedNeighbor],
    observation: &mut Observation,
    missed: MissedAcceptance,
) {
    let candidates = (nodes.len() - 4) / 2;
    let policy = nodes[0]
        .node
        .config
        .node
        .neighbor_rotation
        .as_ref()
        .unwrap();
    let service_secs = policy.idle_secs.max(policy.interval_secs);
    let timeout_secs = nodes[0].node.config.node.rate_limit.handshake_timeout_secs;
    // One population-sized service sweep plus one in-flight handshake window.
    // This is an observation budget, not proof a discovery round must finish:
    // transfers, timeouts and independently phased peers can take longer.
    let budget =
        Duration::from_secs((u64::try_from(candidates).unwrap() + 1) * service_secs + timeout_secs);
    let started = tokio::time::Instant::now();
    let deadline = started + budget;
    let exposure_observed_ms = missed
        .exposed
        .duration_since(observation.started)
        .as_millis();
    observation.post_deadline_diagnostic = true;
    observation.timing.post_deadline_diagnostic = true;
    eprintln!(
        "responsive post-deadline diagnostic start: {}",
        json!({"post_deadline_diagnostic":true,"encounter":missed.encounter,
            "original_acceptance_passed":false,"original_window_ms":missed.window.as_millis(),
            "exposure_observed_ms":exposure_observed_ms,
            "observed_ms":observation.started.elapsed().as_millis(),"native_now_ms":Node::now_ms(),
            "since_exposure_ms":missed.exposed.elapsed().as_millis(),
            "diagnostic_sweep_budget_ms":budget.as_millis(),"candidates_per_boundary":candidates,
            "minimum_age_secs":policy.idle_secs,"attempt_spacing_secs":policy.interval_secs,
            "handshake_timeout_secs":timeout_secs})
    );
    let mut bridge_at = missed.bridge_at;
    let mut delivery_at = missed.delivery_at;
    let mut completed = delivery_at.is_some();
    if !completed {
        completed = tokio::time::timeout_at(deadline, async {
            // The acceptance window may end between half-second rounds.
            // Continue that exact pending schedule instead of sending early.
            let mut next_round = missed.next_local_round.unwrap_or(started);
            loop {
                while tokio::time::Instant::now() < next_round {
                    observation.turn(nodes, ids).await;
                    useful_retained(nodes, ids, original);
                    tokio::time::sleep(Duration::from_millis(5)).await;
                }
                // The original traffic, round checks and maintenance cadence
                // continue. No extra probes, dials, topology changes or reset.
                observation
                    .round(nodes, endpoints, ids, sequence, &LOCAL_FLOWS)
                    .await;
                useful_retained(nodes, ids, original);
                if reciprocal_bridge(nodes, ids) {
                    bridge_at.get_or_insert_with(|| missed.exposed.elapsed());
                    observation
                        .round(nodes, endpoints, ids, sequence, &[(0, 1), (1, 0)])
                        .await;
                    observation
                        .round(nodes, endpoints, ids, sequence, &LOCAL_FLOWS)
                        .await;
                    useful_retained(nodes, ids, original);
                    assert!(reciprocal_bridge(nodes, ids));
                    delivery_at = Some(missed.exposed.elapsed());
                    break;
                }
                next_round = tokio::time::Instant::now() + Duration::from_millis(500);
            }
        })
        .await
        .is_ok();
    }
    caps_with_limits(nodes, observation.capacity);
    snapshot(
        nodes,
        ids,
        observation.started,
        "post-deadline-diagnostic-final",
    );
    observation.timing.observe(
        nodes,
        ids,
        observation.started,
        "post-deadline-diagnostic-final",
    );
    observation.timing.summary(observation.started);
    eprintln!(
        "responsive post-deadline diagnostic outcome: {}",
        json!({"post_deadline_diagnostic":true,"encounter":missed.encounter,
            "original_acceptance_passed":false,"original_window_ms":missed.window.as_millis(),
            "exposure_observed_ms":exposure_observed_ms,
            "observed_ms":observation.started.elapsed().as_millis(),"native_now_ms":Node::now_ms(),
            "since_exposure_ms":missed.exposed.elapsed().as_millis(),
            "diagnostic_elapsed_ms":started.elapsed().as_millis(),
            "diagnostic_sweep_budget_ms":budget.as_millis(),
            "stop":if completed {"late_delivery"} else {"diagnostic_budget_exhausted"},
            "bridge_ms_from_original_exposure":bridge_at.map(|elapsed|elapsed.as_millis()),
            "delivery_ms_from_original_exposure":delivery_at.map(|elapsed|elapsed.as_millis()),
            "cohort_maintenance_turns":observation.cohort_ticks,
            "incumbent_changes":observation.replacements,"payload_round_sequence":*sequence})
    );
}
