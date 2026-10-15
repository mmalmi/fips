//! One automatic successor crosses the existing retirement and mint boundaries.
use super::*;
use cashu::nuts::SwapRequest;
use fips_relay::controller::RenewalPolicy;
use tokio::sync::oneshot;

pub(super) const DUE_SAT: u64 = 2;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "opt-in ordinary renewal during real fragmented-channel retirement"]
async fn ordinary_renewal_defers_during_fragmented_sender_retirement() {
    tokio::time::timeout(Duration::from_secs(900), exercise(true))
        .await
        .expect("bounded retirement, renewal and original-funds reconciliation");
}

pub(super) fn configure(config: &mut ServiceConfig) {
    config.terms.controller.max_locked_sat = 2 * CAPACITY;
    config.terms.controller.max_wallet_spend_sat = FUNDING;
    config.terms.controller.renewal = Some(RenewalPolicy {
        at_capacity_percent: 5,
        before_expiry_secs: 1,
    });
    assert_eq!((CAPACITY * 5).div_ceil(100), DUE_SAT);
}

pub(super) struct Check {
    reached: oneshot::Receiver<()>,
    release: oneshot::Sender<()>,
    original: Value,
    active: String,
    deferred: Value,
}

async fn responsive(config: &ServiceConfig) -> Value {
    tokio::time::timeout(Duration::from_secs(2), status(config))
        .await
        .expect("wallet maintenance or funding blocked ordinary controller status")
}

fn budget(pending: u64) -> Value {
    json!({"wallet_debited_sat": (OLD_CHANNELS as u64 + 1) * CAPACITY,
        "wallet_refunded_sat": OLD_CHANNELS as u64 * CAPACITY,
        "locked_sat": CAPACITY + pending, "exposure_sat": CAPACITY + pending,
        "pending_reserved_sat": pending})
}

impl Check {
    pub(super) async fn arm(bench: &setup::Bench, proxy: &MintProxy, active: &str) -> Self {
        let original = journal(&bench.configs[0]);
        assert!(pending(&original));
        assert_eq!(original["renewals_paused"], false);
        assert!(original["renewals"].as_object().unwrap().is_empty());
        let path = cashu_service::spilman_client_store_path(
            &bench.configs[0].state_directory.join("wallet"),
        );
        let initial: BTreeSet<_> = restore::read(&path)["openings"]
            .as_object()
            .unwrap()
            .keys()
            .cloned()
            .collect();
        // Reuse the mint's selected-reply barrier. Match the durable successor
        // request's exact outputs, excluding every original channel opening.
        let (reached, release) = proxy.state.pause_matching_swap_reply(move |request| {
            restore::read(&path)["openings"]
                .as_object()
                .unwrap()
                .iter()
                .any(|(id, opening)| {
                    !initial.contains(id)
                        && opening["swap_request_json"].as_str().is_some_and(|wire| {
                            let saved: SwapRequest = serde_json::from_str(wire).unwrap();
                            saved.outputs() == request.outputs()
                        })
                })
        });
        Self {
            reached,
            release,
            original,
            active: active.into(),
            deferred: Value::Null,
        }
    }

    fn predecessor(&self, current: &Value, state: &Value) {
        assert_eq!(current["policy"], self.original["policy"]);
        let (id, original) = self.original["funding"]
            .as_object()
            .unwrap()
            .iter()
            .find(|(_, intent)| intent["funded"]["terms"]["id"] == self.active)
            .unwrap();
        assert!(
            current["funding"][id] == *original,
            "predecessor funding changed"
        );
        assert_eq!(state["purchases"].as_array().unwrap().len(), 1);
        assert_eq!(
            state["purchases"][0]["channel"],
            original["funded"]["terms"]
        );
        assert!(current["buyer_settlements"][&self.active].is_null());
        let signed = state["payment_progress"][&self.active]["authorized_sat"]
            .as_u64()
            .unwrap();
        assert_eq!(state["remaining_budget_sat"], 256 - signed);
    }

    async fn still_deferred(&mut self, bench: &setup::Bench) -> Value {
        let current = journal(&bench.configs[0]);
        assert_eq!(
            current["history"]["channels"]["pending"],
            self.original["history"]["channels"]["pending"]
        );
        assert!(
            current["funding"] == self.original["funding"],
            "retirement admitted new funding"
        );
        assert_eq!(current["next_funding"], self.original["next_funding"]);
        assert_eq!(current["renewals"], self.original["renewals"]);
        assert!(matches!(
            self.reached.try_recv(),
            Err(oneshot::error::TryRecvError::Empty)
        ));
        assert!(!self.release.is_closed());
        let state = responsive(&bench.configs[0]).await;
        self.predecessor(&current, &state);
        assert_eq!(state["funding_budget"], budget(0));
        assert!(
            state["payment_progress"][&self.active]["authorized_sat"]
                .as_u64()
                .unwrap()
                >= DUE_SAT
        );
        state
    }

    pub(super) async fn deferred(&mut self, bench: &setup::Bench) {
        let before = self.still_deferred(bench).await;
        let prior_credit = credit(bench, 1, &self.active);
        // Eight seconds spans several two-second renewal scans. The predecessor
        // has room for these exact originals, although its successor is due.
        let sending = probe(bench, 3, 512, 64).await;
        let mut samples = 0;
        while !sending.is_finished() {
            self.still_deferred(bench).await;
            samples += 1;
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
        let traffic = delivered(bench, sending, 512).await;
        caught_up(&bench.configs[0], &self.active).await;
        let after = self.still_deferred(bench).await;
        assert!(samples >= 3);
        assert!(
            after["payment_progress"][&self.active]["authorized_sat"]
                .as_u64()
                .unwrap()
                > before["payment_progress"][&self.active]["authorized_sat"]
                    .as_u64()
                    .unwrap()
        );
        assert!(credit(bench, 1, &self.active) > prior_credit);
        self.deferred = json!({"samples": samples, "traffic": traffic,
            "before": before["payment_progress"][&self.active],
            "after": after["payment_progress"][&self.active],
            "budget": after["funding_budget"]});
    }

    pub(super) async fn finish(mut self, bench: &setup::Bench) -> Value {
        let source = &bench.configs[0];
        tokio::time::timeout(Duration::from_secs(30), &mut self.reached)
            .await
            .expect("renewal must resume automatically after retirement releases its wallet")
            .expect("selected successor mint request reached");
        let held_at = Instant::now();
        let held = journal(source);
        assert!(!pending(&held));
        assert_eq!(
            held["next_funding"].as_u64().unwrap(),
            self.original["next_funding"].as_u64().unwrap() + 1
        );
        let pending: Vec<_> = held["funding"]
            .as_object()
            .unwrap()
            .iter()
            .filter(|(_, intent)| intent["funded"].is_null())
            .collect();
        assert_eq!(pending.len(), 1);
        let (id, intent) = pending[0];
        assert_eq!(intent["capacity_sat"], CAPACITY);
        assert_eq!(intent["max_wallet_debit_sat"], CAPACITY);
        assert_eq!(
            held["renewals"][&self.active]["preopening"]["funding_id"],
            *id
        );
        let before = responsive(source).await;
        self.predecessor(&held, &before);
        assert_eq!(before["funding_budget"], budget(CAPACITY));
        let prior_credit = credit(bench, 1, &self.active);
        let traffic = tokio::time::timeout(Duration::from_secs(20), async {
            let traffic = delivered(bench, probe(bench, 4, 512, 128).await, 512).await;
            caught_up(source, &self.active).await;
            traffic
        })
        .await
        .expect("predecessor payments must finish before the held mint reply times out");
        let after = responsive(source).await;
        let retained = journal(source);
        self.predecessor(&retained, &after);
        assert!(
            retained["funding"][id] == *intent,
            "reserved successor changed"
        );
        assert_eq!(retained["next_funding"], held["next_funding"]);
        assert_eq!(after["funding_budget"], budget(CAPACITY));
        let paid = after["payment_progress"][&self.active]["authorized_sat"]
            .as_u64()
            .unwrap();
        assert!(
            paid > before["payment_progress"][&self.active]["authorized_sat"]
                .as_u64()
                .unwrap()
        );
        assert!(credit(bench, 1, &self.active) > prior_credit);
        assert!(!self.release.is_closed() && held_at.elapsed() < Duration::from_secs(25));
        self.release.send(()).unwrap();
        let (completed, state) = tokio::time::timeout(Duration::from_secs(30), async {
            loop {
                let saved = journal(source);
                let state = responsive(source).await;
                assert_eq!(saved["next_funding"], held["next_funding"]);
                if saved["renewals"][&self.active]["completed"] == true {
                    break (saved, state);
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        })
        .await
        .expect("the original successor must complete without another purchase request");
        let funded = &completed["funding"][id];
        let mut unchanged = funded.clone();
        unchanged["funded"] = Value::Null;
        assert!(
            unchanged == *intent,
            "completion replaced the reserved successor"
        );
        let next = funded["funded"]["terms"]["id"].as_str().unwrap();
        assert_ne!(next, self.active);
        assert_eq!(state["purchases"].as_array().unwrap().len(), 1);
        assert_eq!(state["purchases"][0]["channel"]["id"], next);
        assert_eq!(
            completed["buyer_settlements"][&self.active]["report"]["paid_sat"],
            paid
        );
        assert_eq!(
            state["funding_budget"],
            json!({
            "wallet_debited_sat": (OLD_CHANNELS as u64 + 2) * CAPACITY,
            "wallet_refunded_sat": (OLD_CHANNELS as u64 + 1) * CAPACITY - paid,
            "locked_sat": CAPACITY, "exposure_sat": CAPACITY + paid, "pending_reserved_sat": 0})
        );
        let successor_traffic = delivered(bench, probe(bench, 5, 64, 64).await, 64).await;
        let final_payment = caught_up(source, next).await;
        let successor_paid = final_payment["payment_progress"][next]["authorized_sat"]
            .as_u64()
            .unwrap();
        assert!(0 < successor_paid && successor_paid < DUE_SAT);
        assert_eq!(
            final_payment["remaining_budget_sat"],
            256 - paid - successor_paid
        );
        assert_eq!(journal(source)["next_funding"], held["next_funding"]);
        json!({"renewal_completed":true, "deferred":self.deferred,
            "reserved_budget":after["funding_budget"], "held_successor_traffic":traffic,
            "completed_budget":state["funding_budget"], "successor_traffic":successor_traffic,
            "original_funding_id":id, "original_wallet_operation":funded["funded"]["wallet_operation_id"]})
    }
}
