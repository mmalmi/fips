//! A second provider cannot allocate source funding during durable retirement.
use super::*;

pub(super) struct Check {
    original: Value,
    active: String,
    rejected: Vec<Value>,
}

async fn responsive(config: &ServiceConfig) -> Value {
    tokio::time::timeout(Duration::from_secs(2), status(config))
        .await
        .expect("new purchase blocked ordinary controller status")
}

fn budget(extra: u64) -> Value {
    json!({"wallet_debited_sat": (OLD_CHANNELS as u64 + 1) * CAPACITY + extra,
        "wallet_refunded_sat": OLD_CHANNELS as u64 * CAPACITY,
        "locked_sat": CAPACITY + extra, "exposure_sat": CAPACITY + extra,
        "pending_reserved_sat": 0})
}

impl Check {
    pub(super) async fn arm(bench: &setup::Bench, active: &str) -> Self {
        assert_eq!(bench.configs.len(), 5);
        let source = &bench.configs[0];
        assert!(source.price_selection.is_none());
        assert_eq!(source.terms.controller.max_locked_sat, 2 * CAPACITY);
        assert_eq!(source.terms.controller.max_wallet_spend_sat, FUNDING);
        for config in &bench.configs[3..] {
            assert_eq!(
                load_mint_balance(
                    &config.state_directory.join("wallet"),
                    &source.terms.controller.mint_url,
                )
                .await
                .unwrap()
                .balance_sat,
                0
            );
            assert_eq!(journal(config)["next_funding"], 1);
        }
        let mut check = Self {
            original: journal(source),
            active: active.into(),
            rejected: Vec::new(),
        };
        check.rejected(bench).await;
        check
    }

    fn original_channel(&self, current: &Value) {
        assert_eq!(current["policy"], self.original["policy"]);
        let (id, intent) = self.original["funding"]
            .as_object()
            .unwrap()
            .iter()
            .find(|(_, intent)| intent["funded"]["terms"]["id"] == self.active)
            .unwrap();
        assert!(
            current["funding"][id] == *intent,
            "original funding changed"
        );
        assert!(current["buyer_settlements"][&self.active].is_null());
    }

    pub(super) async fn rejected(&mut self, bench: &setup::Bench) {
        let source = &bench.configs[0];
        let before = journal(source);
        assert!(pending(&before));
        let started = Instant::now();
        let error = tokio::time::timeout(
            Duration::from_secs(2),
            request(
                source,
                &AdminRequest::Buy {
                    destination: bench.npubs[4].clone(),
                },
            ),
        )
        .await
        .expect("new purchase must promptly reject durable maintenance")
        .unwrap_err();
        let elapsed_us = started.elapsed().as_micros();
        assert_eq!(error, HISTORY_PENDING);
        let state = responsive(source).await;
        let after = journal(source);
        for field in [
            "funding",
            "next_funding",
            "requested",
            "outgoing",
            "renewals",
            "watched_routes",
            "route_changes",
        ] {
            assert!(
                after[field] == self.original[field],
                "rejected Buy changed {field}"
            );
        }
        assert!(pending(&after));
        assert!(
            before["history"]["channels"]["pending"] == after["history"]["channels"]["pending"]
        );
        assert!(
            after["history"]["channels"]["pending"]
                == self.original["history"]["channels"]["pending"]
        );
        self.original_channel(&after);
        assert_eq!(state["funding_budget"], budget(0));
        assert_eq!(state["purchases"].as_array().unwrap().len(), 1);
        let signed = state["payment_progress"][&self.active]["authorized_sat"]
            .as_u64()
            .unwrap();
        assert_eq!(state["remaining_budget_sat"], 256 - signed);
        self.rejected
            .push(json!({"elapsed_us":elapsed_us, "error":error,
            "pending_through":after["history"]["channels"]["pending"]["after"]["through"],
            "next_funding":after["next_funding"], "budget":state["funding_budget"],
            "payment":state["payment_progress"][&self.active]}));
    }

    pub(super) async fn finish(self, bench: &setup::Bench) -> Value {
        let source = &bench.configs[0];
        let before = journal(source);
        assert!(!pending(&before));
        assert_eq!(before["funding"].as_object().unwrap().len(), 1);
        assert_eq!(before["next_funding"], self.original["next_funding"]);
        self.original_channel(&before);
        assert_eq!(responsive(source).await["funding_budget"], budget(0));
        let requested_at = now();
        tokio::time::timeout(
            Duration::from_secs(15),
            request(
                source,
                &AdminRequest::Buy {
                    destination: bench.npubs[4].clone(),
                },
            ),
        )
        .await
        .expect("same new destination must fund after maintenance")
        .unwrap();
        let completed = journal(source);
        self.original_channel(&completed);
        assert_eq!(
            completed["next_funding"].as_u64().unwrap(),
            self.original["next_funding"].as_u64().unwrap() + 1
        );
        assert_eq!(completed["funding"].as_object().unwrap().len(), 2);
        let added: Vec<_> = completed["funding"]
            .as_object()
            .unwrap()
            .iter()
            .filter(|(id, _)| self.original["funding"][*id].is_null())
            .collect();
        assert_eq!(added.len(), 1);
        let (id, intent) = added[0];
        assert_eq!(intent["capacity_sat"], CAPACITY);
        assert_eq!(intent["max_wallet_debit_sat"], CAPACITY);
        assert!(intent["created_unix"].as_u64().unwrap() >= requested_at);
        let channel = intent["funded"]["terms"]["id"].as_str().unwrap();
        let state = responsive(source).await;
        assert_eq!(state["funding_budget"], budget(CAPACITY));
        let purchases = state["purchases"].as_array().unwrap();
        assert_eq!(purchases.len(), 2);
        let old = purchases
            .iter()
            .find(|p| p["channel"]["id"] == self.active)
            .unwrap();
        let new = purchases
            .iter()
            .find(|p| p["channel"]["id"] == channel)
            .unwrap();
        assert_ne!(old["provider"], new["provider"]);
        assert_eq!(new["channel"], intent["funded"]["terms"]);
        let new_traffic = delivered_to(bench, 4, probe_to(bench, 4, 6, 128, 128).await, 128).await;
        let paid = caught_up(source, channel).await;
        assert!(
            paid["payment_progress"][channel]["authorized_sat"]
                .as_u64()
                .unwrap()
                > 0
        );
        assert!(credit(bench, 3, channel) > 0);
        let old_credit = credit(bench, 1, &self.active);
        let old_traffic = delivered(bench, probe(bench, 7, 512, 128).await, 512).await;
        let final_payment = caught_up(source, &self.active).await;
        assert!(credit(bench, 1, &self.active) > old_credit);
        let old_paid = final_payment["payment_progress"][&self.active]["authorized_sat"]
            .as_u64()
            .unwrap();
        let new_paid = final_payment["payment_progress"][channel]["authorized_sat"]
            .as_u64()
            .unwrap();
        assert_eq!(
            final_payment["remaining_budget_sat"],
            256 - old_paid - new_paid
        );
        assert_eq!(final_payment["funding_budget"], budget(CAPACITY));
        assert_eq!(journal(source)["next_funding"], completed["next_funding"]);
        json!({"completed":true, "rejected":self.rejected, "new_funding_id":id,
            "wallet_operation_id":intent["funded"]["wallet_operation_id"],
            "new_provider":new["provider"], "budget":final_payment["funding_budget"],
            "new_traffic":new_traffic, "original_traffic":old_traffic})
    }
}
