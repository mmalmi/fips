//! Fail credit publication after the native receiver accepts a signed payment.
use super::{AdminRequest, MixedBench, Value, request, signer_storage::BlockDirectoryWrites};
use cashu_service::{SharedSpilmanClientStoreLock, spilman_client_store_path};
use std::{fs, path::PathBuf, time::Duration};

pub(super) struct FailedCredit {
    channel: String,
    authorized: [u64; 2],
    submitted_before_restart: u64,
    client: PathBuf,
    signed: Vec<u8>,
    pids: Vec<Option<u32>>,
    remaining_budget: [u64; 2],
}

async fn source(bench: &MixedBench) -> Value {
    request(&bench.configs[0], &AdminRequest::Status)
        .await
        .unwrap()
}

pub(super) async fn interrupt(bench: &mut MixedBench, before: &[Value]) -> FailedCredit {
    bench.set_stage("seller-credit-storage-failure");
    bench.set_renewals_paused(true).await;
    let channels: Vec<_> = [0, 2]
        .into_iter()
        .map(|node| {
            before[node]["purchases"][0]["channel"]["id"]
                .as_str()
                .unwrap()
                .to_owned()
        })
        .collect();
    // An outstanding Usage from either payer must not suspend the seller first.
    super::payment_progress::assert_reconciled(bench, &channels).await;
    let channel = channels[0].clone();
    let pids: Vec<_> = bench.children.iter().map(|child| child.id()).collect();
    let paid = bench.relay_usage_msat(&channel).1;
    let client = spilman_client_store_path(&bench.configs[0].state_directory.join("wallet"));
    let original_client = fs::read(&client).unwrap();
    let signing = SharedSpilmanClientStoreLock::acquire(&client).unwrap();
    bench.deliver_sized(0, 2, 512).await;
    tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            if source(bench).await["payment_progress"][&channel]["pending"]["stage"] == "signing" {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("successful usage checkpoint must precede the blocked signer");
    assert!(fs::read(&client).unwrap() == original_client);

    let seller = bench.configs[1].state_directory.join("seller");
    let journal = seller.join("ledger.json");
    let saved = fs::read(&journal).unwrap();
    let log = bench.paths[1].with_extension("log");
    let offset = fs::metadata(&log).unwrap().len() as usize;
    let blocked = BlockDirectoryWrites::new(&seller);
    drop(signing);
    tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            let log = fs::read_to_string(&log).unwrap();
            if log[offset..].lines().any(|line| {
                line.contains("Payment request rejected") && line.contains("stage=\"credit\"")
            }) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("enable fips_relay::payment_control=debug to prove receiver acceptance before failed credit");
    let progress = source(bench).await;
    let progress = &progress["payment_progress"][&channel];
    let authorized_sat = progress["authorized_sat"].as_u64().unwrap();
    assert!(authorized_sat * 1_000 > paid);
    assert!(
        progress["acknowledged_msat"]
            .as_u64()
            .is_none_or(|value| value <= paid)
    );
    let signed = fs::read(&client).unwrap();
    assert!(signed != original_client);
    assert!(fs::read(&journal).unwrap() == saved);
    assert_eq!(bench.relay_usage_msat(&channel).1, paid);

    // Repair alone cannot publish the credit or reopen suspended admission.
    drop(blocked);
    for (sender, receiver) in [(0, 2), (2, 0)] {
        bench.expect_denied(sender, receiver).await;
    }
    assert!(fs::read(&journal).unwrap() == saved);
    assert!(fs::read(&client).unwrap() == signed);
    let after = bench.states().await;
    for (old, new) in before.iter().zip(&after) {
        assert_eq!(new["purchases"], old["purchases"]);
        assert_eq!(new["funding_budget"], old["funding_budget"]);
    }
    let remaining_budget = [0, 2].map(|node| {
        let id = before[node]["purchases"][0]["channel"]["id"]
            .as_str()
            .unwrap();
        let old = before[node]["payment_progress"][id]["authorized_sat"]
            .as_u64()
            .unwrap();
        let new = after[node]["payment_progress"][id]["authorized_sat"]
            .as_u64()
            .unwrap();
        let remaining = after[node]["remaining_budget_sat"].as_u64().unwrap();
        assert_eq!(
            remaining + new.checked_sub(old).unwrap(),
            before[node]["remaining_budget_sat"]
        );
        remaining
    });
    assert_eq!(
        after[0]["payment_progress"][&channel]["authorized_sat"],
        authorized_sat
    );
    assert!(
        after[0]["payment_progress"][&channel]["acknowledged_msat"]
            .as_u64()
            .is_none_or(|value| value <= paid)
    );
    for (child, pid) in bench.children.iter_mut().zip(&pids) {
        assert_eq!(child.id(), *pid);
        assert!(child.try_wait().unwrap().is_none());
    }
    eprintln!(
        "seller credit storage: receiver accepted; journal unchanged; repaired process still denies transit"
    );
    FailedCredit {
        channel,
        authorized: [0, 2].map(|node| {
            let id = before[node]["purchases"][0]["channel"]["id"]
                .as_str()
                .unwrap();
            after[node]["payment_progress"][id]["authorized_sat"]
                .as_u64()
                .unwrap()
        }),
        submitted_before_restart: bench.relay_usage_msat(&channels[0]).0,
        client,
        signed,
        pids,
        remaining_budget,
    }
}

impl FailedCredit {
    pub(super) async fn assert_recovered(self, bench: &MixedBench, before: &[Value]) {
        // Native session reports are still priced traffic. A retry may cover
        // more usage than the job held at Signing, but never charge it twice.
        tokio::time::timeout(Duration::from_secs(20), async {
            loop {
                // Hold native stores across the observation. A new signing job
                // cannot finish while we compare status with its saved payment.
                let signing: Option<Vec<_>> = [0, 2].into_iter().map(|node| {
                    SharedSpilmanClientStoreLock::try_acquire(spilman_client_store_path(
                        &bench.configs[node].state_directory.join("wallet"),
                    ))
                    .unwrap()
                }).collect();
                let Some(signing) = signing else {
                    tokio::time::sleep(Duration::from_millis(50)).await;
                    continue;
                };
                let states = bench.states().await;
                let progress = &states[0]["payment_progress"][&self.channel];
                let authorized = progress["authorized_sat"].as_u64().unwrap();
                let (submitted, paid) = bench.relay_usage_msat(&self.channel);
                let evidence = progress["evidence_msat"].as_u64().unwrap();
                let supported = self.authorized[0].max(submitted.min(evidence).div_ceil(1_000));
                assert_eq!(states[0]["purchases"], before[0]["purchases"]);
                if authorized == supported && paid == authorized * 1_000
                    && progress["acknowledged_msat"] == paid
                    && idle(&states)
                {
                    // An exchange may have signed before we acquired the locks;
                    // exclude a completion or new job during the observation.
                    let confirmed = bench.states().await;
                    if idle(&confirmed) && [0, 2].into_iter().all(|node| {
                        states[node]["remaining_budget_sat"] == confirmed[node]["remaining_budget_sat"]
                            && states[node]["payment_progress"] == confirmed[node]["payment_progress"]
                    }) {
                        self.assert_finances(bench, before, &states);
                        eprintln!("seller credit storage: recovery before_submitted={} after_submitted={submitted} evidence={evidence} before_authorized={} after_authorized={authorized} denied_probe_received={}/{}",
                            self.submitted_before_restart, self.authorized[0],
                            states[0]["probe"]["unique_packets"], states[2]["probe"]["unique_packets"]);
                        break;
                    }
                }
                drop(signing);
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        }).await.expect("middle restart must acknowledge the supported cumulative payment");
        assert_ne!(bench.children[1].id(), self.pids[1]);
        bench.set_renewals_paused(false).await;
        eprintln!(
            "seller credit storage: original payment recovered after only the middle daemon restarted"
        );
    }

    fn assert_finances(&self, bench: &MixedBench, before: &[Value], after: &[Value]) {
        let recovered = after[0]["payment_progress"][&self.channel]["authorized_sat"]
            .as_u64()
            .unwrap();
        self.assert_same_authority(recovered);
        for (index, node) in [0, 2].into_iter().enumerate() {
            let id = before[node]["purchases"][0]["channel"]["id"]
                .as_str()
                .unwrap();
            let progress = &after[node]["payment_progress"][id];
            let authorized = progress["authorized_sat"].as_u64().unwrap();
            let supported = bench
                .relay_usage_msat(id)
                .0
                .min(progress["evidence_msat"].as_u64().unwrap());
            assert!(
                (self.authorized[index]..=self.authorized[index].max(supported.div_ceil(1_000)))
                    .contains(&authorized)
            );
            assert_eq!(
                after[node]["remaining_budget_sat"].as_u64().unwrap()
                    + authorized.checked_sub(self.authorized[index]).unwrap(),
                self.remaining_budget[index]
            );
            assert_eq!(after[node]["purchases"], before[node]["purchases"]);
            assert_eq!(
                after[node]["funding_budget"],
                before[node]["funding_budget"]
            );
            assert_eq!(bench.children[node].id(), self.pids[node]);
        }
    }

    fn assert_same_authority(&self, authorized: u64) {
        let saved: Value = serde_json::from_slice(&self.signed).unwrap();
        let mut replay: Value = serde_json::from_slice(&fs::read(&self.client).unwrap()).unwrap();
        let old = &saved["payments"][&self.channel];
        let new = &mut replay["payments"][&self.channel];
        assert_eq!(old["balance"], self.authorized[0]);
        assert_eq!(new["balance"], authorized);
        assert!(new["payment_count"].as_u64().unwrap() > old["payment_count"].as_u64().unwrap());
        assert!(
            new["last_payment_at"].as_u64().unwrap() >= old["last_payment_at"].as_u64().unwrap()
        );
        // The amount is checked against supported usage above; only that amount
        // and its signature metadata may change in the native store.
        for field in ["balance", "signature", "payment_count", "last_payment_at"] {
            new[field] = old[field].clone();
        }
        assert!(
            replay == saved,
            "replayed payment changed its financial authority"
        );
    }
}

fn idle(states: &[Value]) -> bool {
    [0, 2].into_iter().all(|node| {
        states[node]["payment_progress"]
            .as_object()
            .unwrap()
            .values()
            .all(|progress| progress["in_flight"] == false)
    })
}
