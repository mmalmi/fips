//! Cleanup retries preserve the original acceptance result and financial IDs.
use super::*;
use fips_relay::{control_transport::ControlSnapshot, controller::SettlementReport};

const MAX_ATTEMPTS: usize = 4;
const RETRY_INTERVAL: Duration = Duration::from_secs(2);

fn transient_control_failure(error: &str) -> bool {
    let error = error
        .strip_prefix("refund recovered; settlement report release pending: ")
        .unwrap_or(error);
    matches!(
        error,
        "control stream closed"
            | "control stream ended before its record"
            | "control request timed out"
            | "control request expired or canceled"
    )
}

fn counters(bench: &Bench) -> Vec<ControlSnapshot> {
    bench
        .services
        .iter()
        .map(|service| service.acceptance.statistics().snapshot())
        .collect()
}

// Only counter deltas are logged: no request bodies, signed payments or tokens.
fn progress(before: &[ControlSnapshot], after: &[ControlSnapshot]) -> Vec<(usize, [u64; 4])> {
    before
        .iter()
        .zip(after)
        .enumerate()
        .filter_map(|(node, (before, after))| {
            let delta = [
                after.stream_bytes_sent - before.stream_bytes_sent,
                after.stream_bytes_received - before.stream_bytes_received,
                after.requests_started - before.requests_started,
                after.requests_received - before.requests_received,
            ];
            delta
                .iter()
                .any(|value| *value != 0)
                .then_some((node, delta))
        })
        .collect()
}

async fn unchanged_authority(
    bench: &Bench,
    node: usize,
    original: &Account,
    previous_remaining: &mut u64,
) -> Result<(), String> {
    let saved: Value = serde_json::from_slice(
        &std::fs::read(
            bench
                .root
                .path()
                .join(format!("controller-{node}/controller.json")),
        )
        .map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())?;
    let funding = saved["funding"]
        .as_object()
        .ok_or("funding records missing during cleanup")?;
    if funding.len() != original.funding.len()
        || original.funding.iter().any(|(id, (channel, operation))| {
            let Some(record) = funding.get(id) else {
                return true;
            };
            let funded = &record["funded"];
            funded["terms"]["id"].as_str() != Some(channel.as_str())
                || funded["wallet_operation_id"].as_str() != Some(operation.as_str())
        })
    {
        return Err("cleanup changed original funding/channel identities".into());
    }
    if saved["buyer_settlements"]
        .as_object()
        .is_some_and(|settlements| {
            settlements.iter().any(|(id, settlement)| {
                !original.funding.values().any(|(channel, _)| channel == id)
                    || settlement["channel"]["id"].as_str() != Some(id.as_str())
            })
        })
    {
        return Err("cleanup introduced another settlement identity".into());
    }
    let budget = bench.controllers[node].funding_budget().await?;
    let remaining = bench.buyers[node]
        .remaining_budget_sat()
        .ok_or("cleanup spending budget disappeared")?;
    if budget.wallet_debited_sat != original.budget.wallet_debited_sat
        || budget.pending_reserved_sat != original.budget.pending_reserved_sat
        || remaining > *previous_remaining
    {
        return Err("cleanup changed funding or reset the spending budget".into());
    }
    *previous_remaining = remaining;
    Ok(())
}

pub(super) async fn resume(
    bench: &Bench,
    node: usize,
    original: &Account,
    deadline: Instant,
) -> Result<Vec<SettlementReport>, String> {
    let started = Instant::now();
    let mut remaining = original.remaining;
    for attempt in 1..=MAX_ATTEMPTS {
        unchanged_authority(bench, node, original, &mut remaining).await?;
        if Instant::now() >= deadline {
            return Err("cleanup settlement deadline; durable intent retained".into());
        }
        let before = counters(bench);
        // settle_all resumes the exact saved channel work under its channel
        // mutex. It does not purchase/fund, and reuses completed reports/refunds.
        let result = tokio::time::timeout_at(deadline, bench.controllers[node].settle_all())
            .await
            .map_err(|_| "cleanup settlement deadline; durable intent retained".to_owned())?;
        let delta = progress(&before, &counters(bench));
        unchanged_authority(bench, node, original, &mut remaining).await?;
        match result {
            Ok(reports) => {
                eprintln!(
                    "mesh cleanup node={node} attempt={attempt} elapsed_ms={} complete=true control_deltas(node,sent,received,started,dispatched)={delta:?}",
                    started.elapsed().as_millis()
                );
                return Ok(reports);
            }
            Err(error) => {
                let retry = transient_control_failure(&error)
                    && attempt < MAX_ATTEMPTS
                    && Instant::now() + RETRY_INTERVAL < deadline;
                eprintln!(
                    "mesh cleanup node={node} attempt={attempt} elapsed_ms={} complete=false retry={retry} error={error} control_deltas(node,sent,received,started,dispatched)={delta:?}",
                    started.elapsed().as_millis()
                );
                if !retry {
                    return Err(error);
                }
                tokio::time::sleep(RETRY_INTERVAL).await;
            }
        }
    }
    unreachable!("final attempt always returns")
}

#[test]
fn cleanup_retries_only_specific_control_failures() {
    for error in ["control stream closed", "control request timed out"] {
        assert!(transient_control_failure(error));
        assert!(transient_control_failure(&format!(
            "refund recovered; settlement report release pending: {error}"
        )));
    }
    for error in [
        "control transport stopped",
        "neighbor rejected settlement",
        "invalid final usage",
        "mint refund incomplete or mismatched",
        "mint failed: control stream closed",
        "settlement pending; durable intent retained",
    ] {
        assert!(!transient_control_failure(error), "must not retry: {error}");
    }
}
