//! Exercise the optional progress field through real process status requests.
use super::*;
use std::collections::BTreeSet;

pub(super) async fn assert_empty(bench: &MixedBench) {
    for state in bench.states().await {
        assert!(state["payment_progress"].as_object().unwrap().is_empty());
    }
}

pub(super) async fn assert_reconciled(bench: &MixedBench, channels: &[String]) {
    let expected: BTreeSet<_> = channels.iter().cloned().collect();
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let mut observed = BTreeSet::new();
            let mut reconciled = true;
            for state in bench.states().await {
                let progress = state["payment_progress"].as_object().unwrap();
                for (id, channel) in progress {
                    assert!(observed.insert(id.clone()), "channel belongs to one payer");
                    assert_eq!(channel.as_object().unwrap().len(), 4);
                    let evidence = channel["evidence_msat"].as_u64().unwrap();
                    let authorized = channel["authorized_sat"].as_u64().unwrap();
                    let in_flight = channel["in_flight"].as_bool().unwrap();
                    reconciled &= !in_flight
                        && channel["acknowledged_msat"].as_u64().is_some_and(|paid| {
                            paid >= evidence.max(authorized.checked_mul(1_000).unwrap())
                        });
                    assert!(
                        evidence > 0,
                        "fixture delivered paid data before this check"
                    );
                }
            }
            assert_eq!(
                observed, expected,
                "progress reports the active funded channels"
            );
            if reconciled {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("funded service payment progress must reconcile");
}
