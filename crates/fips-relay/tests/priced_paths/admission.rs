//! A real source admission denial must not pin an unknown, exhausted trial.
use super::*;
use fips_core::FipsEndpointServiceReceiver;
use fips_relay::controller::Purchase;
use std::path::Path;
use tokio::time::Instant;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn active_watch_escapes_unqualified_trial_with_positive_remaining_quota() {
    tokio::time::timeout(
        Duration::from_secs(120),
        run(0, Scenario::AdmissionExhaustion, 114),
    )
    .await
    .expect("admission fallback scenario deadline");
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn exercise(
    nodes: &[Arc<FipsEndpoint>],
    peers: &[PeerIdentity],
    controllers: &[Arc<Controller>],
    services: &[ControllerServices],
    receiver: &mut FipsEndpointServiceReceiver,
    first: &Purchase,
    root: &Path,
) -> u64 {
    let source = &controllers[0];
    let buyer = &services[0].buyer;
    let started = Instant::now();
    let policy = Scenario::AdmissionExhaustion.selection_policy();
    let before = mobility::Evidence::read(root, source).await;
    let mut exhausted = None;
    let mut first_delivered = false;
    let alternative = tokio::time::timeout(Duration::from_secs(40), async {
        loop {
            // The watch alone drives discovery and acceptance. Source calls only
            // enqueue real application traffic; there are no assigned counters,
            // injected quality samples, forced carriers, Buy or payment flushes.
            nodes[0]
                .send_datagram(peers[3], 44_740, 44_740, vec![41; 200])
                .await
                .unwrap();
            let mut batch = Vec::new();
            if let Ok(Some(_)) = tokio::time::timeout(
                Duration::from_millis(25),
                receiver.recv_batch_into(&mut batch, 64),
            )
            .await
            {
                first_delivered |= batch
                    .iter()
                    .any(|m| m.data.as_slice() == [41; 200] && m.source_peer == peers[0]);
            }
            let used = buyer.observed_units(&first.contract.id).unwrap();
            let remaining = first.contract.max_units - used;
            if exhausted.is_none() && remaining > 0 && remaining < 200 {
                let quality = nodes[0]
                    .source_route_quality(
                        peers[3],
                        Duration::from_millis(policy.feedback_timeout_ms),
                    )
                    .await
                    .unwrap();
                assert_eq!(quality.next_hop, Some(first.provider));
                assert!(
                    !quality.delivery_feedback_timed_out,
                    "local quota denial is not native path failure: {quality:?}"
                );
                assert!(quality.receiver_reports_enabled && quality.loss_rate.is_none());
                assert!(!quality.has_recent_delivery_feedback);
                assert!(
                    first_delivered,
                    "the original trial actually carried payloads"
                );
                exhausted = Some(used);
            }
            if let Some(next) = source
                .purchases()
                .await
                .unwrap()
                .into_iter()
                .find(|p| p.provider == *peers[2].node_addr())
            {
                assert!(
                    exhausted.is_some(),
                    "fallback must follow real local exhaustion"
                );
                let quality = nodes[0]
                    .source_route_quality(
                        peers[3],
                        Duration::from_millis(policy.feedback_timeout_ms),
                    )
                    .await
                    .unwrap();
                assert!(
                    !quality.delivery_feedback_timed_out && quality.loss_rate.is_none(),
                    "fallback cannot use a different failure mechanism: {quality:?}"
                );
                break next;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("unknown exhausted trial must automatically select the available alternative");
    assert!(started.elapsed() < Duration::from_millis(policy.feedback_timeout_ms));
    assert_eq!(alternative.contract.max_units, policy.trial_max_units);
    assert_eq!(alternative.channel.capacity_sat, 64);
    assert_ne!(alternative.channel.id, first.channel.id);
    let denied_used = exhausted.unwrap();
    // A smaller native SenderReport can still fit the remainder while the
    // alternative is being accepted. It spends the original allowance.
    assert!(
        buyer
            .observed_units(&first.contract.id)
            .is_some_and(|used| used >= denied_used && used <= first.contract.max_units)
    );

    // This new tag is first submitted after the accepted alternative is visible;
    // delayed packets from the original trial cannot satisfy fresh delivery.
    tokio::time::timeout(Duration::from_secs(10), async {
        let mut delivered = false;
        loop {
            nodes[0]
                .send_datagram(peers[3], 44_740, 44_740, vec![42; 200])
                .await
                .unwrap();
            let mut batch = Vec::new();
            if let Ok(Some(_)) = tokio::time::timeout(
                Duration::from_millis(100),
                receiver.recv_batch_into(&mut batch, 64),
            )
            .await
            {
                delivered |= batch
                    .iter()
                    .any(|m| m.data.as_slice() == [42; 200] && m.source_peer == peers[0]);
            }
            let quality = nodes[0]
                .source_route_quality(peers[3], Duration::from_millis(policy.feedback_timeout_ms))
                .await
                .unwrap();
            if delivered
                && quality.next_hop == Some(alternative.provider)
                && buyer
                    .authorized_sat(&alternative.channel.id)
                    .is_some_and(|n| n > 0)
            {
                assert!(!quality.delivery_feedback_timed_out && quality.loss_rate.is_none());
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await
    .expect("alternative must deliver fresh payload and automatically advance payment");
    assert!(started.elapsed() < Duration::from_millis(policy.feedback_timeout_ms));
    let watches = source.watched_routes().await.unwrap();
    assert_eq!(watches.len(), 1);
    assert!(!watches[0].paused);
    assert_eq!(watches[0].destination, peers[3].npub());
    assert_eq!(watches[0].max_rate_msat_per_kib, 4096);
    let history = source.purchase_history().await.unwrap();
    assert_eq!(history.len(), 2);
    assert!(history.contains(first) && history.contains(&alternative));
    let used = buyer.observed_units(&first.contract.id).unwrap();
    assert!(used >= denied_used && used < first.contract.max_units);
    mobility::Evidence::read(root, source)
        .await
        .follows(&before);
    assert_eq!(source.locked_capital_sat().await.unwrap(), 128);
    eprintln!(
        "admission fallback: original trial used {used}/{}, {}B left after native switch, two 64sat channels, fresh alternative delivered",
        first.contract.max_units,
        first.contract.max_units - used
    );
    source.pause_route_refresh().await.unwrap();
    source.pause_renewals().await.unwrap();
    used
}
