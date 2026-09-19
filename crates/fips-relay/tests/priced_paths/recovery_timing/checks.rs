//! Derive confirmation from recorded events, without adding another probe stream.
use super::*;

pub(super) fn summarize(
    sent: &[Sent],
    received: &BTreeMap<usize, Received>,
    observations: &[Observation],
    cut: u64,
) -> Result<Value, &'static str> {
    if sent.len() != PACKETS || sent.iter().enumerate().any(|(i, item)| item.sequence != i) {
        return Err("the one finite numbered stream was not fully submitted");
    }
    let (first_sequence, first_receipt) = sent
        .iter()
        .filter(|item| item.started_at_ms > cut)
        .filter_map(|item| received.get(&item.sequence).map(|r| (item.sequence, r)))
        .min_by_key(|(_, receipt)| receipt.observed_at_ms)
        .ok_or("no newly submitted payload arrived after the edge cut")?;
    let first_delivery = first_receipt.observed_at_ms;
    let working = observations
        .iter()
        .find(|sample| sample.working && sample.started_at_ms >= first_delivery)
        .ok_or("no delivered, fully promoted replacement with fresh quality and provider credit")?;
    for batch in sent.chunks_exact(BATCH) {
        let first = &batch[0];
        let Some(agreement) = first
            .batch_agreement
            .as_ref()
            .filter(|a| a.provider == 2 && a.quota > 32_768)
        else {
            continue;
        };
        if first.started_at_ms <= cut
            || !observations.iter().any(|sample| {
                sample.working
                    && sample.finished_at_ms <= first.started_at_ms
                    && sample.agreement.as_ref() == Some(agreement)
            })
        {
            continue;
        }
        let arrivals: Option<Vec<_>> = batch
            .iter()
            .map(|item| received.get(&item.sequence).map(|r| r.observed_at_ms))
            .collect();
        let Some(last_arrival) = arrivals.and_then(|times| times.into_iter().max()) else {
            continue;
        };
        let confirmation = observations.iter().find(|sample| {
            sample.working
                && sample.started_at_ms >= last_arrival
                && sample.agreement.as_ref() == Some(agreement)
        });
        let Some(confirmation) = confirmation else {
            continue;
        };
        if observations.iter().any(|sample| {
            sample.started_at_ms >= first.started_at_ms
                && sample.finished_at_ms <= confirmation.finished_at_ms
                && sample.agreement.as_ref() != Some(agreement)
        }) {
            continue;
        }
        return Ok(json!({
            "first_post_cut_delivery_sequence": first_sequence,
            "first_post_cut_delivery_enqueued_unix_ms": first_receipt.enqueued_at_ms,
            "first_post_cut_delivery_observed_ms": first_delivery,
            "working_route_observed_ms": working.finished_at_ms,
            "batch_confirmation_observed_ms": confirmation.finished_at_ms,
            "batch_first_sequence": first.sequence,
            "batch_last_sequence": batch.last().unwrap().sequence,
            "delivery_after_cut_ms": first_delivery - cut,
            "working_after_cut_ms": working.finished_at_ms - cut,
            "working_after_delivery_ms": working.finished_at_ms - first_delivery,
            "confirmation_after_cut_ms": confirmation.finished_at_ms - cut,
            "confirmation_after_working_ms": confirmation.finished_at_ms - working.finished_at_ms,
            "batch_receipt_to_confirmation_ms": confirmation.finished_at_ms - last_arrival,
            "delivered_packets": received.len(),
            "first_feedback_timeout_observed_ms": observations.iter().find(|o| {
                o.details["feedback_timed_out"] == true
            }).map(|o| o.finished_at_ms),
            "first_trial_observed_ms": observations.iter().find(|o| {
                o.agreement.as_ref().is_some_and(|a| a.provider == 2 && a.quota == 32_768)
            }).map(|o| o.finished_at_ms),
            "first_full_replacement_observed_ms": observations.iter().find(|o| {
                o.agreement.as_ref().is_some_and(|a| a.provider == 2 && a.quota > 32_768)
            }).map(|o| o.finished_at_ms),
        }));
    }
    Err("no complete 32-packet batch bracketed by the same working replacement agreement")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> (Vec<Sent>, BTreeMap<usize, Received>, Vec<Observation>) {
        let agreement = Agreement {
            id: "full".into(),
            channel: "original".into(),
            provider: 2,
            quota: 131_072,
        };
        let sent = (0..PACKETS)
            .map(|sequence| Sent {
                sequence,
                started_at_ms: sequence as u64 * 500,
                submitted_at_ms: sequence as u64 * 500,
                batch_agreement: (sequence >= 32 && sequence % BATCH == 0)
                    .then(|| agreement.clone()),
            })
            .collect();
        let received = (0..PACKETS)
            .filter(|i| *i == 0 || *i >= 20)
            .map(|sequence| {
                (
                    sequence,
                    Received {
                        observed_at_ms: sequence as u64 * 500 + 10,
                        enqueued_at_ms: 1,
                    },
                )
            })
            .collect();
        let observations = [10_100, 15_900, 32_000, 48_000, 64_000]
            .into_iter()
            .map(|time| Observation {
                started_at_ms: time,
                finished_at_ms: time + 1,
                agreement: Some(agreement.clone()),
                working: true,
                details: json!({}),
            })
            .collect();
        (sent, received, observations)
    }

    #[test]
    fn delivery_and_working_route_precede_batch_confirmation() {
        let (sent, received, observations) = fixture();
        let summary = summarize(&sent, &received, &observations, 100).unwrap();
        assert_eq!(summary["first_post_cut_delivery_observed_ms"], 10_010);
        assert_eq!(summary["working_route_observed_ms"], 10_101);
        assert_eq!(summary["batch_confirmation_observed_ms"], 32_001);
        assert_eq!(summary["confirmation_after_working_ms"], 21_900);
        assert_eq!(summary["batch_first_sequence"], 32);
    }

    #[test]
    fn partial_batch_or_agreement_change_cannot_confirm_recovery() {
        let (sent, mut received, mut observations) = fixture();
        for sequence in [63, 95, 127] {
            received.remove(&sequence);
        }
        assert!(summarize(&sent, &received, &observations, 100).is_err());
        let (sent, received, _) = fixture();
        for sample in &mut observations {
            sample.agreement.as_mut().unwrap().id = "changed".into();
        }
        assert!(summarize(&sent, &received, &observations, 100).is_err());
    }

    #[test]
    fn delivery_without_observed_quality_and_credit_is_not_working_recovery() {
        let (sent, received, mut observations) = fixture();
        for sample in &mut observations {
            sample.working = false;
        }
        assert!(summarize(&sent, &received, &observations, 100).is_err());
    }

    #[test]
    fn send_started_before_cut_is_not_new_recovery_delivery() {
        let (mut sent, mut received, observations) = fixture();
        sent[1].started_at_ms = 90;
        sent[1].submitted_at_ms = 150;
        received.insert(
            1,
            Received {
                observed_at_ms: 151,
                enqueued_at_ms: 1,
            },
        );
        let summary = summarize(&sent, &received, &observations, 100).unwrap();
        assert_eq!(summary["first_post_cut_delivery_observed_ms"], 10_010);
    }

    #[test]
    fn observed_agreement_change_inside_each_batch_prevents_confirmation() {
        let (sent, received, mut observations) = fixture();
        for time in [20_000, 40_000, 60_000] {
            let mut changed = observations[0].agreement.clone().unwrap();
            changed.id = "intervening".into();
            observations.push(Observation {
                started_at_ms: time,
                finished_at_ms: time + 1,
                agreement: Some(changed),
                working: false,
                details: json!({}),
            });
        }
        observations.sort_by_key(|sample| sample.started_at_ms);
        assert!(summarize(&sent, &received, &observations, 100).is_err());
    }
}
