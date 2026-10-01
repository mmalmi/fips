//! Control-reply timing only; packet arrival is never a readiness observation.
use super::{AtomicBool, Bench, Duration, Instant, Ordering, Value};
use std::future::Future;

pub(super) struct Sample {
    pub started: Instant,
    pub completed: Instant,
    contact_up: bool,
    pub states: [Value; 2],
}

impl Sample {
    pub async fn read<M: Future<Output = [Value; 2]>>(
        left: impl Future<Output = Value>,
        right: impl Future<Output = Value>,
        contact: &AtomicBool,
        metadata: impl FnOnce([Value; 2]) -> M,
    ) -> Self {
        let started = Instant::now();
        let (left, right) = tokio::join!(left, right);
        let completed = Instant::now();
        let contact_up = contact.load(Ordering::Acquire);
        // Metadata still validates every observation, but its later reply is
        // not the time at which both actual tree snapshots were received.
        let states = metadata([left, right]).await;
        Self {
            started,
            completed,
            contact_up,
            states,
        }
    }

    pub fn learned_before(&self, root: &str, deadline: Instant) -> bool {
        self.contact_up
            && self.completed < deadline
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
    let contact = AtomicBool::new(true);
    let mut stale = states[0].clone();
    stale["remote_sequence"] = Value::Null;
    tokio::time::advance(Duration::from_millis(377)).await;
    let first = Sample::read(
        reply_after(stale, 1),
        reply_after(states[1].clone(), 15),
        &contact,
        std::future::ready,
    )
    .await;
    assert!(!first.learned_before("root", deadline));
    first.wait_next(deadline).await;
    let second = Sample::read(
        reply_after(states[0].clone(), 2),
        reply_after(states[1].clone(), 2),
        &contact,
        std::future::ready,
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
    let contact = AtomicBool::new(true);
    tokio::time::advance(Duration::from_millis(400)).await;
    let sample = Sample::read(
        std::future::ready(left),
        std::future::ready(right),
        &contact,
        std::future::ready,
    )
    .await;
    assert_eq!(sample.completed, deadline);
    assert!(!sample.learned_before("root", deadline));
    assert!(sample.learned_before("root", deadline + Duration::from_millis(1)));
}

#[tokio::test(start_paused = true)]
async fn learned_tree_replies_before_cut_survive_later_peer_metadata() {
    let open = Instant::now();
    let deadline = open + Duration::from_millis(400);
    let contact = AtomicBool::new(true);
    let [left, right] = learned_states();
    tokio::time::advance(Duration::from_millis(390)).await;
    let sample = Sample::read(
        reply_after(left, 2),
        reply_after(right, 2),
        &contact,
        |states| async {
            tokio::time::sleep_until(deadline).await;
            contact.store(false, Ordering::Release);
            tokio::time::sleep(Duration::from_millis(12)).await;
            states
        },
    )
    .await;
    assert!(Instant::now() > deadline);
    assert!(!contact.load(Ordering::Acquire));
    assert!(
        sample.learned_before("root", deadline),
        "metadata delayed a learned tree observation"
    );
    assert_eq!(
        sample.completed.duration_since(open),
        Duration::from_millis(392)
    );
}

#[tokio::test(start_paused = true)]
async fn matching_tree_replies_after_cut_or_with_closed_contact_are_rejected() {
    let open = Instant::now();
    let deadline = open + Duration::from_millis(400);
    let contact = AtomicBool::new(false);
    let [left, right] = learned_states();
    let sample = Sample::read(
        std::future::ready(left.clone()),
        std::future::ready(right.clone()),
        &contact,
        std::future::ready,
    )
    .await;
    assert!(!sample.learned_before("root", deadline));
    contact.store(true, Ordering::Release);
    tokio::time::advance(Duration::from_millis(401)).await;
    let sample = Sample::read(
        std::future::ready(left),
        std::future::ready(right),
        &contact,
        std::future::ready,
    )
    .await;
    assert!(!sample.learned_before("root", deadline));
}
