//! Control-reply timing only; packet arrival is never a readiness observation.
use super::{Bench, Duration, Instant, Value};
use std::future::Future;

pub(super) struct Sample {
    pub started: Instant,
    pub completed: Instant,
    pub states: [Value; 2],
}

impl Sample {
    pub async fn read(
        left: impl Future<Output = Value>,
        right: impl Future<Output = Value>,
    ) -> Self {
        let started = Instant::now();
        let (left, right) = tokio::join!(left, right);
        Self {
            started,
            completed: Instant::now(),
            states: [left, right],
        }
    }

    pub fn learned_before(&self, root: &str, deadline: Instant) -> bool {
        self.completed < deadline
            && self.states[1]["root"] == root
            && Bench::learned(&self.states[0], &self.states[1])
            && Bench::learned(&self.states[1], &self.states[0])
    }

    pub async fn wait_next(&self, deadline: Instant) {
        let now = Instant::now();
        let interval = if now < deadline && deadline - now <= Duration::from_millis(20) {
            Duration::from_millis(1)
        } else {
            Duration::from_millis(10)
        };
        // A slow reply already consumed the sampling interval. Do not add a
        // further 10 ms blind spot; the control IO and timer still yield.
        tokio::time::sleep_until(self.started + interval).await;
    }
}

fn learned_states() -> [Value; 2] {
    let mut states = [
        serde_json::json!({"root": "root", "parent": "root", "sequence": 1, "coords": ["root"]}),
        serde_json::json!({"root": "root", "parent": "root", "sequence": 3, "coords": ["child", "root"]}),
    ];
    for index in 0..2 {
        let remote = states[1 - index].clone();
        for field in ["root", "parent", "sequence", "coords"] {
            states[index][format!("remote_{field}")] = remote[field].clone();
        }
    }
    states
}

async fn reply_after(state: Value, milliseconds: u64) -> Value {
    tokio::time::sleep(Duration::from_millis(milliseconds)).await;
    state
}

#[tokio::test(start_paused = true)]
async fn stale_left_slow_right_requeries_before_contact_deadline() {
    let open = Instant::now();
    let deadline = open + Duration::from_millis(400);
    let states = learned_states();
    let mut stale = states[0].clone();
    stale["remote_sequence"] = Value::Null;
    tokio::time::advance(Duration::from_millis(377)).await;
    let first = Sample::read(reply_after(stale, 1), reply_after(states[1].clone(), 15)).await;
    assert!(!first.learned_before("root", deadline));
    first.wait_next(deadline).await;
    let second = Sample::read(
        reply_after(states[0].clone(), 2),
        reply_after(states[1].clone(), 2),
    )
    .await;
    assert!(
        second.learned_before("root", deadline),
        "observer missed learned declarations: completed at {:?}",
        second.completed.duration_since(open)
    );
}

#[tokio::test(start_paused = true)]
async fn matching_reply_completed_at_contact_deadline_is_rejected() {
    let open = Instant::now();
    let deadline = open + Duration::from_millis(400);
    let [left, right] = learned_states();
    tokio::time::advance(Duration::from_millis(400)).await;
    let sample = Sample::read(std::future::ready(left), std::future::ready(right)).await;
    assert_eq!(sample.completed, deadline);
    assert!(!sample.learned_before("root", deadline));
    assert!(sample.learned_before("root", deadline + Duration::from_millis(1)));
}
