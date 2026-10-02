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
            let states = bench.states().await;
            for state in &states {
                let progress = state["payment_progress"].as_object().unwrap();
                for (id, channel) in progress {
                    assert!(observed.insert(id.clone()), "channel belongs to one payer");
                    assert_eq!(channel.as_object().unwrap().len(), 6);
                    let evidence = channel["evidence_msat"].as_u64().unwrap();
                    let authorized = channel["authorized_sat"].as_u64().unwrap();
                    let in_flight = channel["in_flight"].as_bool().unwrap();
                    assert_eq!(channel.get("pending").unwrap().is_null(), !in_flight);
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
                let mut updates = 0;
                for state in &states {
                    let cost = &state["measurements"]["operations"]["payment_update"];
                    let completed = cost["spans"].as_u64().unwrap();
                    // The durable credit checkpoint also supplies the reply;
                    // acknowledging it must not write the ledger a second time.
                    assert!(
                        cost["journal_commits"].as_u64().unwrap() <= completed,
                        "payment updates must use their existing durable checkpoint: {cost}"
                    );
                    updates += completed;
                }
                assert!(updates > 0, "the service processed real payment updates");
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("funded service payment progress must reconcile");
}
