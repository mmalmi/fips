//! One-shot, process-wide service-time attribution. Disabled unless the operator
//! sets FIPS_SERVICE_TIME_DIAGNOSTIC_START_UNIX_MS to an epoch 5..120s ahead
//! when the receive loop starts AND enables fips_core::service_time_diagnostic=info.
//! Wait for `ready`, then `open`; require the single `terminal` summary. Missing
//! markers, slot overflow, multiple receive loops, or an early
//! loop exit invalidate a complete-window claim. This is not an acceptance gate.
//! Boundary records expose timer lateness for the run owner to review.
//!
//! The scheduled epoch is converted once to a monotonic 15s window. A dedicated
//! timer emits boundaries even without traffic or while the async worker is busy.
//! No hot-path logs, peer data, wire indices, or unbounded storage are used.
//! Durations are inclusive wall time (including awaits), clipped to the window;
//! nested stages MUST NOT be added. Calls crossing the end are charged exactly
//! once at cutoff. Histograms include these partial calls, labeled separately.
//! Ended spans include cancellation. Fanout covers only refreshes ended inside
//! the window, not partial refreshes at cutoff. Armed-period spans are tracked
//! to include work already running when the window opens.
//! Owner-sync and refresh stages cover all callers; the explicit responder-rekey
//! owner-sync substage isolates the Msg1 path under investigation.

use serde::Serialize;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const ENV: &str = "FIPS_SERVICE_TIME_DIAGNOSTIC_START_UNIX_MS";
const WINDOW_MS: u64 = 15_000;
const SLOTS: usize = 64;
const STAGES: usize = 7;
const DURATION_UPPER_US: [u64; 7] = [10, 100, 1_000, 10_000, 100_000, 1_000_000, 10_000_000];
const FANOUT_UPPER: [u64; 7] = [0, 1, 4, 16, 64, 256, 1_024];
static SESSION: OnceLock<Option<Arc<Recorder>>> = OnceLock::new();

#[derive(Clone, Copy, Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Stage {
    SerialControl,
    Msg1Unclassified,
    Msg1Stranger,
    Msg1Established,
    FmpOwnerSync,
    FspRouteRefresh,
    Msg1RekeyOwnerSync,
}

const ALL_STAGES: [Stage; STAGES] = [
    Stage::SerialControl,
    Stage::Msg1Unclassified,
    Stage::Msg1Stranger,
    Stage::Msg1Established,
    Stage::FmpOwnerSync,
    Stage::FspRouteRefresh,
    Stage::Msg1RekeyOwnerSync,
];

struct Plan {
    epoch_ms: u64,
    start: Instant,
    end: Instant,
}

impl Plan {
    fn parse(raw: &str, epoch_now_ms: u64, now: Instant) -> Result<Self, &'static str> {
        let epoch_ms = raw.parse::<u64>().map_err(|_| "invalid_start_epoch")?;
        let delay_ms = epoch_ms.checked_sub(epoch_now_ms).ok_or("start_is_past")?;
        if !(5_000..=120_000).contains(&delay_ms) {
            return Err("start_must_be_5_to_120_seconds_ahead");
        }
        let start = now + Duration::from_millis(delay_ms);
        Ok(Self {
            epoch_ms,
            start,
            end: start + Duration::from_millis(WINDOW_MS),
        })
    }
}

#[derive(Clone, Copy)]
struct Active {
    stage: Stage,
    start: Instant,
    fanout: Option<(u64, u64)>,
}

#[derive(Clone, Copy, Default, Debug, Serialize)]
struct Aggregate {
    ended: u64,
    cutoff: u64,
    carried_in: u64,
    inclusive_wall_ns: u64,
    max_clipped_wall_ns: u64,
    duration_histogram: [u64; 8],
}

#[derive(Clone, Copy, Default, Debug, Serialize)]
struct Fanout {
    ended_refreshes: u64,
    destinations_scanned: u64,
    destinations_refreshed: u64,
    refreshed_histogram: [u64; 8],
}

struct State {
    active: [Option<Active>; SLOTS],
    aggregates: [Aggregate; STAGES],
    fanout: Fanout,
    slot_overflow: u64,
    rx_loops_started: u64,
    rx_loop_exited_early: bool,
    closed: bool,
}

impl State {
    fn new() -> Self {
        Self {
            active: [None; SLOTS],
            aggregates: [Aggregate::default(); STAGES],
            fanout: Fanout::default(),
            slot_overflow: 0,
            rx_loops_started: 0,
            rx_loop_exited_early: false,
            closed: false,
        }
    }

    fn begin(&mut self, plan: &Plan, stage: Stage, now: Instant) -> Option<usize> {
        if self.closed || now >= plan.end {
            return None;
        }
        let Some(slot) = self.active.iter().position(Option::is_none) else {
            self.slot_overflow = self.slot_overflow.saturating_add(1);
            return None;
        };
        self.active[slot] = Some(Active {
            stage,
            start: now,
            fanout: None,
        });
        Some(slot)
    }

    fn finish(&mut self, plan: &Plan, slot: usize, now: Instant) {
        if let Some(active) = self.active[slot].take() {
            self.record(plan, active, now);
        }
    }

    fn classify_msg1(&mut self, plan: &Plan, slot: usize, now: Instant, established: bool) {
        if now < plan.end
            && let Some(active) = self.active[slot].as_mut()
        {
            active.stage = if established {
                Stage::Msg1Established
            } else {
                Stage::Msg1Stranger
            };
        }
    }

    fn record(&mut self, plan: &Plan, active: Active, now: Instant) {
        if now <= plan.start || active.start >= plan.end {
            return;
        }
        let elapsed = now
            .min(plan.end)
            .saturating_duration_since(active.start.max(plan.start));
        let ns = elapsed.as_nanos().min(u128::from(u64::MAX)) as u64;
        let cutoff = now >= plan.end;
        let aggregate = &mut self.aggregates[active.stage as usize];
        if cutoff {
            aggregate.cutoff += 1;
        } else {
            aggregate.ended += 1;
        }
        aggregate.carried_in += u64::from(active.start < plan.start);
        aggregate.inclusive_wall_ns = aggregate.inclusive_wall_ns.saturating_add(ns);
        aggregate.max_clipped_wall_ns = aggregate.max_clipped_wall_ns.max(ns);
        aggregate.duration_histogram[bucket(ns / 1_000, &DURATION_UPPER_US)] += 1;
        if !cutoff && let Some((scanned, refreshed)) = active.fanout {
            self.fanout.ended_refreshes += 1;
            self.fanout.destinations_scanned =
                self.fanout.destinations_scanned.saturating_add(scanned);
            self.fanout.destinations_refreshed =
                self.fanout.destinations_refreshed.saturating_add(refreshed);
            self.fanout.refreshed_histogram[bucket(refreshed, &FANOUT_UPPER)] += 1;
        }
    }

    fn close(&mut self, plan: &Plan) -> bool {
        if self.closed {
            return false;
        }
        self.closed = true;
        for slot in 0..SLOTS {
            self.finish(plan, slot, plan.end);
        }
        true
    }
}

fn bucket(value: u64, bounds: &[u64; 7]) -> usize {
    bounds.iter().position(|upper| value <= *upper).unwrap_or(7)
}

struct Recorder {
    plan: Plan,
    state: Mutex<State>,
    closed: AtomicBool,
}

impl Recorder {
    fn new(plan: Plan) -> Self {
        Self {
            plan,
            state: Mutex::new(State::new()),
            closed: AtomicBool::new(false),
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, State> {
        self.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn run_timer(&self) {
        sleep_until(self.plan.start);
        let opened_late_us = micros(Instant::now().saturating_duration_since(self.plan.start));
        tracing::info!(target: "fips_core::service_time_diagnostic", parent: None,
            stage = "open", start_unix_ms = self.plan.epoch_ms, window_ms = WINDOW_MS,
            opened_late_us, "Service time diagnostic");
        sleep_until(self.plan.end);
        let summary = {
            let mut state = self.lock();
            if !state.close(&self.plan) {
                return;
            }
            self.closed.store(true, Ordering::Relaxed);
            Summary {
                schema: 1,
                start_unix_ms: self.plan.epoch_ms,
                window_ms: WINDOW_MS,
                opened_late_us,
                terminal_late_us: micros(Instant::now().saturating_duration_since(self.plan.end)),
                slot_overflow: state.slot_overflow,
                rx_loops_started: state.rx_loops_started,
                rx_loop_exited_early: state.rx_loop_exited_early,
                duration_histogram_upper_us: DURATION_UPPER_US,
                fanout_histogram_upper: FANOUT_UPPER,
                stages: std::array::from_fn(|i| StageSummary {
                    stage: ALL_STAGES[i],
                    aggregate: state.aggregates[i],
                }),
                fanout_ended_within_window: state.fanout,
                accounting: "inclusive_nested_wall_time_do_not_sum_stages;histograms_include_clipped_cutoffs;last_bucket_overflow",
            }
        };
        // Serialization is bounded and happens once, outside the hot-path lock.
        match serde_json::to_string(&summary) {
            Ok(summary) => {
                tracing::info!(target: "fips_core::service_time_diagnostic", parent: None,
                stage = "terminal", summary = %summary, "Service time diagnostic")
            }
            Err(_) => tracing::warn!(parent: None, reason = "summary_encoding_failed",
                "Service time diagnostic failed"),
        }
    }
}

#[derive(Serialize)]
struct StageSummary {
    stage: Stage,
    #[serde(flatten)]
    aggregate: Aggregate,
}

#[derive(Serialize)]
struct Summary {
    schema: u8,
    start_unix_ms: u64,
    window_ms: u64,
    opened_late_us: u64,
    terminal_late_us: u64,
    slot_overflow: u64,
    rx_loops_started: u64,
    rx_loop_exited_early: bool,
    duration_histogram_upper_us: [u64; 7],
    fanout_histogram_upper: [u64; 7],
    stages: [StageSummary; STAGES],
    fanout_ended_within_window: Fanout,
    accounting: &'static str,
}

fn micros(duration: Duration) -> u64 {
    duration.as_micros().min(u128::from(u64::MAX)) as u64
}

fn sleep_until(deadline: Instant) {
    while let Some(remaining) = deadline.checked_duration_since(Instant::now()) {
        std::thread::sleep(remaining);
    }
}

fn activate() -> Result<Option<Arc<Recorder>>, &'static str> {
    let raw = match std::env::var(ENV) {
        Ok(raw) => raw,
        Err(std::env::VarError::NotPresent) => return Ok(None),
        Err(_) => return Err("invalid_start_epoch"),
    };
    if !tracing::enabled!(target: "fips_core::service_time_diagnostic", tracing::Level::INFO) {
        return Err("info_target_required");
    }
    let epoch_now_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| "clock_before_epoch")?
        .as_millis();
    let epoch_now_ms = u64::try_from(epoch_now_ms).map_err(|_| "clock_out_of_range")?;
    let recorder = Arc::new(Recorder::new(Plan::parse(
        &raw,
        epoch_now_ms,
        Instant::now(),
    )?));
    let worker = Arc::clone(&recorder);
    let dispatcher = tracing::dispatcher::get_default(|dispatcher| dispatcher.clone());
    std::thread::Builder::new()
        .name("fips-service-time".into())
        .spawn(move || {
            tracing::dispatcher::with_default(&dispatcher, || worker.run_timer());
        })
        .map_err(|_| "timer_start_failed")?;
    Ok(Some(recorder))
}

pub(crate) struct RxLoopGuard(Option<Arc<Recorder>>);

pub(crate) fn initialize_rx_loop() -> RxLoopGuard {
    let session = SESSION.get_or_init(|| match activate() {
        Ok(session) => session,
        Err(reason) => {
            tracing::warn!(parent: None, reason, "Service time diagnostic rejected");
            None
        }
    });
    if let Some(recorder) = session
        && !recorder.closed.load(Ordering::Relaxed)
    {
        let mut state = recorder.lock();
        state.rx_loops_started += 1;
        if state.rx_loops_started == 1 {
            tracing::info!(target: "fips_core::service_time_diagnostic", parent: None,
                stage = "ready", start_unix_ms = recorder.plan.epoch_ms, window_ms = WINDOW_MS,
                "Service time diagnostic");
        }
    }
    RxLoopGuard(session.clone())
}

impl Drop for RxLoopGuard {
    fn drop(&mut self) {
        if let Some(recorder) = &self.0
            && !recorder.closed.load(Ordering::Relaxed)
        {
            let mut state = recorder.lock();
            if Instant::now() < recorder.plan.end {
                state.rx_loop_exited_early = true;
            }
        }
    }
}

pub(crate) struct Span {
    recorder: Option<Arc<Recorder>>,
    slot: usize,
}

impl Span {
    pub(crate) fn start(stage: Stage) -> Self {
        if let Some(Some(recorder)) = SESSION.get()
            && !recorder.closed.load(Ordering::Relaxed)
        {
            let slot = recorder.lock().begin(&recorder.plan, stage, Instant::now());
            if let Some(slot) = slot {
                return Self {
                    recorder: Some(Arc::clone(recorder)),
                    slot,
                };
            }
        }
        Self {
            recorder: None,
            slot: 0,
        }
    }

    // Reclassification preserves time spent before the pre-crypto class check.
    pub(crate) fn classify_msg1(&mut self, established: bool) {
        if let Some(recorder) = &self.recorder
            && !recorder.closed.load(Ordering::Relaxed)
        {
            recorder
                .lock()
                .classify_msg1(&recorder.plan, self.slot, Instant::now(), established);
        }
    }

    pub(crate) fn fanout(&mut self, scanned: usize, refreshed: usize) {
        if let Some(recorder) = &self.recorder
            && !recorder.closed.load(Ordering::Relaxed)
        {
            if let Some(active) = recorder.lock().active[self.slot].as_mut() {
                active.fanout = Some((scanned as u64, refreshed as u64));
            }
        }
    }
}

impl Drop for Span {
    fn drop(&mut self) {
        if let Some(recorder) = &self.recorder
            && !recorder.closed.load(Ordering::Relaxed)
        {
            recorder
                .lock()
                .finish(&recorder.plan, self.slot, Instant::now());
        }
    }
}

#[cfg(test)]
mod tests;
