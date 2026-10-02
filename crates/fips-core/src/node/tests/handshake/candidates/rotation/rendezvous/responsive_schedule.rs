//! Keep the manual driver on production's fixed maintenance phase.
use super::*;
use futures::FutureExt;
use tokio::time::{Instant, Interval, MissedTickBehavior, interval_at};

const PERIOD: Duration = Duration::from_secs(1);

pub(super) struct Ticks {
    intervals: [Interval; 2],
    next: [Instant; 2],
    simultaneous: bool,
}

impl Ticks {
    pub(super) fn new(started: Instant, offset: Duration) -> Self {
        let next = [started, started + offset];
        Self {
            intervals: next.map(|at| {
                let mut timer = interval_at(at, PERIOD);
                timer.set_missed_tick_behavior(MissedTickBehavior::Skip);
                timer
            }),
            next,
            simultaneous: offset.is_zero(),
        }
    }

    pub(super) fn next(&self) -> [Instant; 2] {
        self.next
    }

    fn poll_one(&mut self, cohort: usize) -> bool {
        let Some(scheduled) = self.intervals[cohort].tick().now_or_never() else {
            return false;
        };
        // Only the interval decides readiness. Keep its next phase for the
        // existing diagnostic; Skip never schedules an overdue catch-up burst.
        let now = Instant::now();
        let missed = now.duration_since(scheduled).as_secs();
        self.next[cohort] = scheduled + PERIOD * (u32::try_from(missed).unwrap() + 1);
        true
    }

    pub(super) fn poll(&mut self) -> [bool; 2] {
        if self.simultaneous {
            let due = self.poll_one(0);
            self.next[1] = self.next[0];
            [due; 2]
        } else {
            std::array::from_fn(|cohort| self.poll_one(cohort))
        }
    }
}

#[tokio::test(start_paused = true)]
async fn late_maintenance_keeps_production_skip_phase() {
    let started = Instant::now();
    let mut ticks = Ticks::new(started, Duration::from_millis(500));
    assert_eq!(ticks.poll(), [true, false]);
    tokio::time::advance(Duration::from_millis(900)).await;
    assert_eq!(ticks.poll(), [false, true]);
    assert_eq!(
        ticks.next(),
        [started + PERIOD, started + Duration::from_millis(1_500)],
        "late maintenance must preserve the production interval phase"
    );
    tokio::time::advance(Duration::from_millis(100)).await;
    assert_eq!(ticks.poll(), [true, false]);
    tokio::time::advance(Duration::from_millis(500)).await;
    assert_eq!(
        ticks.poll(),
        [false, true],
        "late service must not defer the next discovery opportunity"
    );
}

#[tokio::test(start_paused = true)]
async fn skipped_maintenance_has_no_catchup_burst_or_phase_reset() {
    let started = Instant::now();
    let mut ticks = Ticks::new(started, Duration::from_millis(500));
    assert_eq!(ticks.poll(), [true, false]);
    tokio::time::advance(Duration::from_millis(3_750)).await;
    assert_eq!(ticks.poll(), [true, true]);
    assert_eq!(ticks.poll(), [false, false]);
    assert_eq!(
        ticks.next(),
        [
            started + Duration::from_secs(4),
            started + Duration::from_millis(4_500)
        ]
    );
    tokio::time::advance(Duration::from_millis(250)).await;
    assert_eq!(ticks.poll(), [true, false]);
    assert_eq!(ticks.poll(), [false, false]);
}
