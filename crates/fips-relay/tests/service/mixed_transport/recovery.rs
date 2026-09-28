//! Carrier recovery can overlap legitimate automatic channel replacement.
use super::*;
use fips_relay::ledger::{BytePrice, ChannelUsage};
use std::collections::BTreeMap;

impl MixedBench {
    pub async fn recover_seed_carrier(&mut self, silent: bool) {
        let before = self.states().await;
        let funding = self.funding_intents();
        let proxy = self.seed_carrier().unwrap();
        let accepted = proxy.connections();
        assert!(accepted > 0);
        let dropped = proxy.dropped_bytes();
        let started = tokio::time::Instant::now();
        let wait = if silent {
            let idle = self.configs[2]
                .transports
                .websocket
                .iter()
                .next()
                .unwrap()
                .1
                .idle_timeout_secs();
            assert!(idle > 0);
            proxy.blackhole().await;
            Duration::from_secs(idle + 20)
        } else {
            assert!(proxy.set_available(true).await > 0);
            Duration::from_secs(20)
        };
        tokio::time::timeout(wait, async {
            while proxy.connections() == accepted {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("seed must establish a fresh physical connection");
        if silent {
            assert!(proxy.dropped_bytes() > dropped);
        }
        eprintln!(
            "carrier recovery silent={silent} fresh_connection_ms={}",
            started.elapsed().as_millis()
        );
        ready(&self.configs, &self.paths, &self.npubs, &mut self.children).await;
        self.assert_carriers().await;
        let authenticated_ms = started.elapsed().as_millis();
        let mut baselines = Vec::new();
        for (source, destination) in [(0, 2), (2, 0)] {
            let state = request(&self.configs[source], &AdminRequest::Status)
                .await
                .unwrap();
            let baseline = self.recovery_usage(&state).unwrap();
            // Exercise repeated billable cohorts near renewal. Silent loss keeps
            // the third attempt available if replacement drops a cohort.
            let cohorts = if self.second_hop == SecondHop::WebSocketSeed {
                if silent { 2 } else { 3 }
            } else {
                1
            };
            self.deliver_cohorts(source, destination, 512, cohorts)
                .await;
            baselines.push((source, baseline));
        }
        let after = self.wait_recovery_payments(&baselines).await;
        let mut replacements = [0; 3];
        for node in [0, 2] {
            let old = &before[node];
            let new = &after[node];
            replacements[node] = new["history"]
                .as_array()
                .unwrap()
                .len()
                .checked_sub(old["history"].as_array().unwrap().len())
                .unwrap();
            assert!(
                replacements[node] <= 1,
                "bounded recovery workload cannot need multiple replacements"
            );
            if replacements[node] == 0 {
                assert_eq!(new["purchases"], old["purchases"]);
            } else {
                let previous = &old["purchases"][0];
                let id = &previous["channel"]["id"];
                let buyer =
                    read_journal(&self.configs[node].state_directory.join("buyer/buyer.json"))
                        .unwrap();
                let evidence: u64 = buyer["quotes"]
                    .as_object()
                    .unwrap()
                    .values()
                    .filter(|quote| quote["contract"]["channel_id"] == *id)
                    .map(|quote| {
                        serde_json::from_value::<BytePrice>(quote["contract"]["price"].clone())
                            .unwrap()
                            .amount_due_msat(quote["submitted_units"].as_u64().unwrap())
                            .unwrap()
                    })
                    .sum();
                let policy = &self.configs[node].terms.controller;
                assert!(
                    u128::from(evidence) * 100
                        >= u128::from(policy.channel_capacity_sat)
                            * 1000
                            * u128::from(policy.renewal.as_ref().unwrap().at_capacity_percent),
                    "carrier interruption alone must not justify a new purchase"
                );
                let replacement = &new["purchases"][0];
                assert_ne!(replacement["channel"]["id"], *id);
                assert_eq!(replacement["provider"], previous["provider"]);
                for field in ["destination", "next_hop", "price", "billing", "max_units"] {
                    assert_eq!(replacement["contract"][field], previous["contract"][field]);
                }
            }
        }
        super::super::assert_replacement_accounts(self, &before, &after, &funding, replacements)
            .await;
        eprintln!(
            "carrier recovery silent={silent} authenticated_ms={authenticated_ms} paid_progress_ms={} replacements={replacements:?}",
            started.elapsed().as_millis()
        );
    }

    fn recovery_usage(&self, state: &Value) -> Option<BTreeMap<String, ChannelUsage>> {
        let ledger =
            read_journal(&self.configs[1].state_directory.join("seller/ledger.json")).unwrap();
        state["history"]
            .as_array()
            .unwrap()
            .iter()
            .map(|purchase| {
                let id = purchase["channel"]["id"].as_str().unwrap();
                let row = ledger["ledger"]["channels"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .find(|row| row["terms"]["id"] == id)?;
                Some((
                    id.to_owned(),
                    serde_json::from_value(row["usage"].clone()).unwrap(),
                ))
            })
            .collect()
    }

    async fn wait_recovery_payments(
        &self,
        baselines: &[(usize, BTreeMap<String, ChannelUsage>)],
    ) -> Vec<Value> {
        let result = tokio::time::timeout(Duration::from_secs(20), async {
            loop {
                let states = self.states().await;
                let mut reconciled = true;
                for (source, before) in baselines {
                    let state = &states[*source];
                    let Some(usage) = self.recovery_usage(state) else {
                        reconciled = false;
                        continue;
                    };
                    for (id, old) in before {
                        let new = usage
                            .get(id)
                            .expect("recovery retains earlier channel evidence");
                        assert!(new.submitted_msat >= old.submitted_msat);
                        assert!(new.paid_msat >= old.paid_msat);
                    }
                    let controller = read_journal(
                        &self.configs[*source]
                            .state_directory
                            .join("controller/controller.json"),
                    )
                    .unwrap();
                    reconciled &= usage.iter().any(|(id, usage)| {
                        usage.submitted_msat > before.get(id).map_or(0, |old| old.paid_msat)
                    }) && usage
                        .values()
                        .all(|usage| usage.paid_msat >= usage.submitted_msat)
                        && state["funding_budget"]["pending_reserved_sat"] == 0
                        && state["purchases"].as_array().unwrap().len() == 1
                        && controller["renewals"]
                            .as_object()
                            .unwrap()
                            .values()
                            .all(|renewal| renewal["completed"] == true);
                }
                if reconciled {
                    // The same sampled purchases drive the final assertions;
                    // another status request can straddle a renewal transition.
                    return states;
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        })
        .await;
        match result {
            Ok(states) => states,
            Err(_) => {
                eprintln!("mixed-carrier recovery payment or renewal did not reconcile");
                self.failure_snapshot().await;
                panic!("automatic recovery payment and renewal reach relay");
            }
        }
    }
}
