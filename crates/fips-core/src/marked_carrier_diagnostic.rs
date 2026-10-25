//! Temporary diagnostic, never an admission or authentication input.
//!
//! Enable the INFO target plus FIPS_MARKED_CARRIER_START_UNIX_MS (5..120s
//! ahead at RX-loop start) and FIPS_MARKED_CARRIER_TOKEN (32 lowercase hex
//! characters). Only upgrades with exactly one `fips_trace=<token>` query
//! field are selected. Neither the token nor addresses/headers/payloads are
//! emitted. The original path check and all transport/protocol limits remain.
//! Wait for `open` before starting the marked probe; require `terminal` and
//! every numbered carrier record. The fixed window is 30s, with at most eight
//! marked generations and 48 events each. Overflow or unfinished work at the
//! cutoff is explicit. Closed carriers stay indexed until cutoff for queued
//! Msg1s. Times are monotonic wall time, not CPU. Socket-write completion is
//! local completion, not proof of remote receipt.
//! Admission entry and FIFO-turn acquisition split the pre-handler wait.
//! Queue counts are independent relaxed observations, not a consistent snapshot.
//! Window totals cover all Msg1 limiter starts, including unmarked transports;
//! an accepted start is only limiter admission, not authenticated peer admission.

use crate::node::wire::{Msg1Header, Msg2Header};
use crate::transport::{TransportAddr, TransportId};
use serde::Serialize;
use std::io::{self, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const WINDOW_MS: u64 = 30_000;
const CARRIERS: usize = 8;
const EVENTS: usize = 48;
// Eight <=7KiB carrier payloads + <=2KiB terminal + two tiny boundaries.
const CARRIER_BYTES: usize = 7 * 1024;
const TERMINAL_BYTES: usize = 2 * 1024;
static SESSION: OnceLock<Option<Arc<Recorder>>> = OnceLock::new();

struct Plan {
    token: String,
    epoch_ms: u64,
    start: Instant,
    end: Instant,
}

impl Plan {
    fn parse(
        token: String,
        epoch: &str,
        epoch_now: u64,
        now: Instant,
    ) -> Result<Self, &'static str> {
        if token.len() != 32
            || !token
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err("invalid_token");
        }
        let epoch_ms = epoch.parse::<u64>().map_err(|_| "invalid_start")?;
        let delay = epoch_ms.checked_sub(epoch_now).ok_or("start_in_past")?;
        if !(5_000..=120_000).contains(&delay) {
            return Err("start_must_be_5_to_120_seconds_ahead");
        }
        let start = now + Duration::from_millis(delay);
        Ok(Self {
            token,
            epoch_ms,
            start,
            end: start + Duration::from_millis(WINDOW_MS),
        })
    }

    fn matches(&self, query: Option<&str>) -> bool {
        let mut fields = query
            .unwrap_or("")
            .split('&')
            .map(|field| field.split_once('=').unwrap_or((field, "")))
            .filter(|(key, _)| *key == "fips_trace");
        fields.next().is_some_and(|(_, value)| value == self.token) && fields.next().is_none()
    }
}

#[derive(Serialize)]
struct Event {
    us: u64,
    stage: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    index: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    seq: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    detail: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    class: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    carrier: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    queue: Option<QueueObservation>,
}

#[derive(Serialize)]
struct QueueObservation {
    reserved: usize,
    queued: usize,
}

#[derive(Clone, Copy, PartialEq, Serialize)]
pub(crate) struct LimiterParameters {
    pub(crate) stranger_burst: u32,
    pub(crate) stranger_rate: f64,
    pub(crate) established_burst: u32,
    pub(crate) established_rate: f64,
    pub(crate) max_pending: usize,
}

#[derive(Clone, Copy)]
pub(crate) enum StartResult {
    Accepted,
    RateLimit,
    PendingLimit,
}

#[derive(Default, Serialize)]
struct StartCounts {
    attempts: u64,
    accepted: u64,
    rate_limit: u64,
    pending_limit: u64,
}

#[derive(Default, Serialize)]
struct Msg1Starts {
    stranger: StartCounts,
    established_link: StartCounts,
    parameters: Option<LimiterParameters>,
    parameters_changed: bool,
    counter_overflow: bool,
}

impl Msg1Starts {
    fn parameters(&mut self, parameters: LimiterParameters) {
        match self.parameters {
            None => self.parameters = Some(parameters),
            Some(first) => self.parameters_changed |= first != parameters,
        }
    }

    fn record(&mut self, established: bool, result: StartResult, parameters: LimiterParameters) {
        self.parameters(parameters);
        let counts = if established {
            &mut self.established_link
        } else {
            &mut self.stranger
        };
        let outcome = match result {
            StartResult::Accepted => &mut counts.accepted,
            StartResult::RateLimit => &mut counts.rate_limit,
            StartResult::PendingLimit => &mut counts.pending_limit,
        };
        for counter in [&mut counts.attempts, outcome] {
            if let Some(next) = counter.checked_add(1) {
                *counter = next;
            } else {
                self.counter_overflow = true;
            }
        }
    }

    fn incomplete(&self) -> bool {
        self.parameters.is_none() || self.parameters_changed || self.counter_overflow
    }
}

#[derive(Serialize)]
struct Carrier {
    id: usize,
    generation: u64,
    #[serde(skip)]
    transport: TransportId,
    #[serde(skip)]
    addr: TransportAddr,
    events: Vec<Event>,
    event_overflow: u64,
    correlation_overflow: bool,
    terminal: Option<&'static str>,
    at_close: Option<Pending>,
    admissions_active: usize,
    handlers_active: usize,
    writes_active: usize,
    #[serde(skip)]
    pending_msg1: Vec<(u32, u32)>,
    pending_msg1_count: usize,
    msg2_queued: u64,
    msg2_started: u64,
    msg2_not_started_at_cutoff: u64,
    incomplete: bool,
    #[serde(skip)]
    sequence: u32,
}

impl Carrier {
    fn record(&mut self, event: Event) {
        if self.events.len() < EVENTS {
            self.events.push(event);
        } else {
            self.event_overflow = self.event_overflow.saturating_add(1);
        }
    }

    fn cutoff(&mut self) {
        self.pending_msg1_count = self.pending_msg1.len();
        self.msg2_not_started_at_cutoff = self.msg2_queued.saturating_sub(self.msg2_started);
        self.incomplete = self.terminal.is_none()
            || self.event_overflow != 0
            || self.correlation_overflow
            || self.admissions_active != 0
            || self.handlers_active != 0
            || self.writes_active != 0
            || self.pending_msg1_count != 0;
    }
}

#[derive(Serialize)]
struct Pending {
    admissions: usize,
    handlers: usize,
    writes: usize,
    msg1_not_handled: usize,
    msg2_queued: u64,
    msg2_started: u64,
}

#[derive(Default)]
struct State {
    carriers: Vec<Carrier>,
    carrier_overflow: u64,
    selected_outside_window: u64,
    rx_loops: u64,
    early_exit: bool,
    msg1_starts: Msg1Starts,
}

struct Recorder {
    plan: Plan,
    state: Mutex<State>,
    closed: AtomicBool,
}

impl Recorder {
    fn lock(&self) -> std::sync::MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|error| error.into_inner())
    }

    fn in_window(&self, now: Instant) -> bool {
        !self.closed.load(Ordering::Relaxed) && now >= self.plan.start && now < self.plan.end
    }

    fn event(
        &self,
        stage: &'static str,
        index: Option<u32>,
        seq: Option<u32>,
        detail: Option<&'static str>,
    ) -> Event {
        Event {
            us: micros(Instant::now().saturating_duration_since(self.plan.start)),
            stage,
            index,
            seq,
            detail,
            class: None,
            carrier: None,
            queue: None,
        }
    }

    fn timer(&self) {
        sleep_until(self.plan.start);
        let open_late_us = micros(Instant::now().saturating_duration_since(self.plan.start));
        tracing::info!(target: "fips_core::marked_carrier_diagnostic", parent: None,
            stage = "open", window_ms = WINDOW_MS, open_late_us, "Marked carrier diagnostic");
        sleep_until(self.plan.end);
        let (carriers, mut summary) = {
            let mut state = self.lock();
            self.closed.store(true, Ordering::Relaxed);
            for carrier in &mut state.carriers {
                carrier.cutoff();
            }
            let incomplete = state.carriers.is_empty()
                || state.carriers.iter().any(|c| c.incomplete)
                || state.carrier_overflow != 0
                || state.selected_outside_window != 0
                || state.rx_loops != 1
                || state.early_exit
                || state.msg1_starts.incomplete();
            let summary = Summary {
                schema: 2,
                start_unix_ms: self.plan.epoch_ms,
                window_ms: WINDOW_MS,
                open_late_us,
                terminal_late_us: micros(Instant::now().saturating_duration_since(self.plan.end)),
                carriers: state.carriers.len(),
                carrier_overflow: state.carrier_overflow,
                selected_outside_window: state.selected_outside_window,
                rx_loops: state.rx_loops,
                early_exit: state.early_exit,
                encoding_overflow: false,
                incomplete,
                msg1_starts: std::mem::take(&mut state.msg1_starts),
            };
            (std::mem::take(&mut state.carriers), summary)
        };
        for carrier in carriers {
            match bounded_json(&carrier, CARRIER_BYTES) {
                Ok(json) => {
                    tracing::info!(target: "fips_core::marked_carrier_diagnostic", parent: None,
                    stage = "carrier", id = carrier.id, record = %json, "Marked carrier diagnostic")
                }
                Err(_) => {
                    summary.encoding_overflow = true;
                    summary.incomplete = true;
                    tracing::info!(target: "fips_core::marked_carrier_diagnostic", parent: None,
                        stage = "carrier", id = carrier.id, encoding_overflow = true, "Marked carrier diagnostic");
                }
            }
        }
        match bounded_json(&summary, TERMINAL_BYTES) {
            Ok(json) => {
                tracing::info!(target: "fips_core::marked_carrier_diagnostic", parent: None,
                stage = "terminal", summary = %json, "Marked carrier diagnostic")
            }
            Err(_) => tracing::info!(target: "fips_core::marked_carrier_diagnostic", parent: None,
                stage = "terminal", incomplete = true, encoding_overflow = true, "Marked carrier diagnostic"),
        }
    }
}

#[derive(Serialize)]
struct Summary {
    schema: u8,
    start_unix_ms: u64,
    window_ms: u64,
    open_late_us: u64,
    terminal_late_us: u64,
    carriers: usize,
    carrier_overflow: u64,
    selected_outside_window: u64,
    rx_loops: u64,
    early_exit: bool,
    encoding_overflow: bool,
    incomplete: bool,
    msg1_starts: Msg1Starts,
}

fn bounded_json(value: &impl Serialize, limit: usize) -> Result<String, serde_json::Error> {
    struct Limited {
        bytes: Vec<u8>,
        limit: usize,
    }
    impl Write for Limited {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            if bytes.len() > self.limit.saturating_sub(self.bytes.len()) {
                return Err(io::Error::other("diagnostic byte cap"));
            }
            self.bytes.extend_from_slice(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    let mut writer = Limited {
        bytes: Vec::with_capacity(limit),
        limit,
    };
    serde_json::to_writer(&mut writer, value)?;
    Ok(String::from_utf8(writer.bytes).expect("JSON is UTF-8"))
}

fn micros(duration: Duration) -> u64 {
    duration.as_micros().min(u128::from(u64::MAX)) as u64
}
fn sleep_until(deadline: Instant) {
    while let Some(delay) = deadline.checked_duration_since(Instant::now()) {
        std::thread::sleep(delay);
    }
}

fn activate(parameters: LimiterParameters) -> Result<Option<Arc<Recorder>>, &'static str> {
    let epoch = match std::env::var("FIPS_MARKED_CARRIER_START_UNIX_MS") {
        Ok(value) => value,
        Err(std::env::VarError::NotPresent) => return Ok(None),
        Err(_) => return Err("invalid_start"),
    };
    if !tracing::enabled!(target: "fips_core::marked_carrier_diagnostic", tracing::Level::INFO) {
        return Err("info_target_required");
    }
    let token = std::env::var("FIPS_MARKED_CARRIER_TOKEN").map_err(|_| "missing_token")?;
    let epoch_now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| "clock_before_epoch")?
        .as_millis();
    let plan = Plan::parse(
        token,
        &epoch,
        u64::try_from(epoch_now).map_err(|_| "clock_out_of_range")?,
        Instant::now(),
    )?;
    let mut state = State::default();
    state.msg1_starts.parameters(parameters);
    let recorder = Arc::new(Recorder {
        plan,
        state: Mutex::new(state),
        closed: AtomicBool::new(false),
    });
    let worker = Arc::clone(&recorder);
    let dispatcher = tracing::dispatcher::get_default(|dispatcher| dispatcher.clone());
    std::thread::Builder::new()
        .name("fips-marked-carrier".into())
        .spawn(move || {
            tracing::dispatcher::with_default(&dispatcher, || worker.timer());
        })
        .map_err(|_| "timer_start_failed")?;
    Ok(Some(recorder))
}

pub(crate) struct RxLoopGuard(Option<Arc<Recorder>>);
pub(crate) fn initialize_rx_loop(parameters: LimiterParameters) -> RxLoopGuard {
    let session = SESSION.get_or_init(|| match activate(parameters) {
        Ok(session) => session,
        Err(reason) => {
            tracing::warn!(parent: None, reason, "Marked carrier diagnostic rejected");
            None
        }
    });
    if let Some(recorder) = session {
        let mut state = recorder.lock();
        state.rx_loops = state.rx_loops.saturating_add(1);
        state.msg1_starts.parameters(parameters);
        if state.rx_loops == 1 {
            tracing::info!(target: "fips_core::marked_carrier_diagnostic", parent: None,
                stage = "ready", start_unix_ms = recorder.plan.epoch_ms, window_ms = WINDOW_MS,
                max_carriers = CARRIERS, max_events_per_carrier = EVENTS,
                max_payload_bytes = 65536, "Marked carrier diagnostic");
        }
    }
    RxLoopGuard(session.clone())
}
impl Drop for RxLoopGuard {
    fn drop(&mut self) {
        if let Some(recorder) = &self.0
            && Instant::now() < recorder.plan.end
            && !recorder.closed.load(Ordering::Relaxed)
        {
            recorder.lock().early_exit = true;
        }
    }
}

pub(crate) fn matches_query(query: Option<&str>) -> bool {
    SESSION
        .get()
        .and_then(Option::as_ref)
        .is_some_and(|r| !r.closed.load(Ordering::Relaxed) && r.plan.matches(query))
}

pub(crate) fn register(transport: TransportId, addr: &TransportAddr, generation: u64) {
    let Some(recorder) = SESSION.get().and_then(Option::as_ref) else {
        return;
    };
    recorder.register(transport, addr, generation);
}
impl Recorder {
    fn register(&self, transport: TransportId, addr: &TransportAddr, generation: u64) {
        let mut state = self.lock();
        if !self.in_window(Instant::now()) {
            state.selected_outside_window = state.selected_outside_window.saturating_add(1);
            return;
        }
        if state.carriers.len() == CARRIERS {
            state.carrier_overflow = state.carrier_overflow.saturating_add(1);
            return;
        }
        let id = state.carriers.len() + 1;
        let mut carrier = Carrier {
            id,
            generation,
            transport,
            addr: addr.clone(),
            events: Vec::with_capacity(EVENTS),
            event_overflow: 0,
            correlation_overflow: false,
            terminal: None,
            at_close: None,
            admissions_active: 0,
            handlers_active: 0,
            writes_active: 0,
            pending_msg1: Vec::with_capacity(EVENTS),
            pending_msg1_count: 0,
            msg2_queued: 0,
            msg2_started: 0,
            msg2_not_started_at_cutoff: 0,
            incomplete: false,
            sequence: 0,
        };
        carrier.record(self.event("open", None, None, None));
        state.carriers.push(carrier);
    }
}

#[derive(Clone)]
struct Handle {
    recorder: Arc<Recorder>,
    slot: usize,
}
fn lookup(transport: TransportId, addr: &TransportAddr) -> Option<Handle> {
    let recorder = SESSION.get()?.as_ref()?;
    recorder.lookup(transport, addr)
}

fn observing() -> bool {
    SESSION
        .get()
        .and_then(Option::as_ref)
        .is_some_and(|r| r.in_window(Instant::now()))
}
impl Recorder {
    fn msg1_start_result(
        &self,
        established: bool,
        result: StartResult,
        parameters: LimiterParameters,
    ) {
        if !self.in_window(Instant::now()) {
            return;
        }
        let mut state = self.lock();
        if self.in_window(Instant::now()) {
            state.msg1_starts.record(established, result, parameters);
        }
    }

    fn lookup(self: &Arc<Self>, transport: TransportId, addr: &TransportAddr) -> Option<Handle> {
        if !self.in_window(Instant::now()) {
            return None;
        }
        let state = self.lock();
        let slot = state
            .carriers
            .iter()
            .position(|c| c.transport == transport && c.addr == *addr)?;
        Some(Handle {
            recorder: Arc::clone(self),
            slot,
        })
    }
}

pub(crate) fn msg1_start_result(
    established: bool,
    result: StartResult,
    parameters: LimiterParameters,
) {
    if let Some(recorder) = SESSION.get().and_then(Option::as_ref)
        && !recorder.closed.load(Ordering::Relaxed)
    {
        recorder.msg1_start_result(established, result, parameters);
    }
}
impl Handle {
    fn update(&self, f: impl FnOnce(&mut Carrier, &Recorder)) {
        let mut state = self.recorder.lock();
        if self.recorder.in_window(Instant::now())
            && let Some(carrier) = state.carriers.get_mut(self.slot)
        {
            f(carrier, &self.recorder);
        }
    }
}

pub(crate) fn terminal(transport: TransportId, addr: &TransportAddr, reason: &'static str) {
    if let Some(handle) = lookup(transport, addr) {
        handle.terminal(reason);
    }
}
impl Handle {
    fn terminal(&self, reason: &'static str) {
        self.update(|c, r| {
            if c.terminal.is_none() {
                c.terminal = Some(reason);
                c.at_close = Some(Pending {
                    admissions: c.admissions_active,
                    handlers: c.handlers_active,
                    writes: c.writes_active,
                    msg1_not_handled: c.pending_msg1.len(),
                    msg2_queued: c.msg2_queued,
                    msg2_started: c.msg2_started,
                });
                c.record(r.event("terminal", None, None, Some(reason)));
            }
        });
    }
}
pub(crate) struct ConnectionGuard(Option<Handle>);
pub(crate) fn connection_guard(transport: TransportId, addr: &TransportAddr) -> ConnectionGuard {
    ConnectionGuard(lookup(transport, addr))
}
impl Drop for ConnectionGuard {
    fn drop(&mut self) {
        if let Some(handle) = &self.0 {
            handle.terminal("task_aborted");
        }
    }
}

#[derive(Clone, Copy)]
enum Operation {
    Admission,
    Handler,
    Write,
}
pub(crate) struct Span {
    handle: Handle,
    operation: Operation,
    index: u32,
    seq: Option<u32>,
    done: bool,
}
impl Span {
    pub(crate) fn admission_point(&self, turn_acquired: bool, reserved: usize, queued: usize) {
        self.handle.update(|c, r| {
            let stage = if turn_acquired {
                "turn_acquired"
            } else {
                "admission_enter"
            };
            let mut event = r.event(stage, Some(self.index), self.seq, None);
            event.queue = Some(QueueObservation { reserved, queued });
            c.record(event);
        });
    }

    pub(crate) fn finish(mut self, detail: &'static str) {
        self.end(detail, None, None);
    }
    pub(crate) fn decision(
        mut self,
        class: &'static str,
        reason: &'static str,
        carrier: &'static str,
    ) {
        self.end(reason, Some(class), Some(carrier));
    }
    fn end(
        &mut self,
        detail: &'static str,
        class: Option<&'static str>,
        carrier: Option<&'static str>,
    ) {
        if self.done {
            return;
        }
        self.done = true;
        self.handle.update(|c, r| {
            let stage = match self.operation {
                Operation::Admission => {
                    c.admissions_active = c.admissions_active.saturating_sub(1);
                    if detail != "admitted" {
                        c.pending_msg1.retain(|(_, seq)| Some(*seq) != self.seq);
                    }
                    "admission_end"
                }
                Operation::Handler => {
                    c.handlers_active = c.handlers_active.saturating_sub(1);
                    "handler_end"
                }
                Operation::Write => {
                    c.writes_active = c.writes_active.saturating_sub(1);
                    "write_end"
                }
            };
            let mut event = r.event(stage, Some(self.index), self.seq, Some(detail));
            event.class = class;
            event.carrier = carrier;
            c.record(event);
        });
    }
}
impl Drop for Span {
    fn drop(&mut self) {
        self.end("cancelled", None, None);
    }
}

pub(crate) fn msg1_read(transport: TransportId, addr: &TransportAddr, data: &[u8]) -> Option<Span> {
    if !observing() {
        return None;
    }
    // Bulk records never take the recorder lock, even during a capture.
    let index = Msg1Header::parse(data)?.sender_idx.as_u32();
    let handle = lookup(transport, addr)?;
    let mut seq = None;
    handle.update(|c, r| {
        c.sequence = c.sequence.saturating_add(1);
        seq = Some(c.sequence);
        c.admissions_active += 1;
        if c.pending_msg1.len() < EVENTS {
            c.pending_msg1.push((index, c.sequence));
        } else {
            c.correlation_overflow = true;
        }
        c.record(r.event("msg1_read", Some(index), seq, None));
    });
    Some(Span {
        handle,
        operation: Operation::Admission,
        index,
        seq,
        done: false,
    })
}

pub(crate) fn handler_entry(
    transport: TransportId,
    addr: &TransportAddr,
    data: &[u8],
) -> Option<Span> {
    let handle = lookup(transport, addr)?;
    let index = Msg1Header::parse(data)?.sender_idx.as_u32();
    let mut seq = None;
    handle.update(|c, r| {
        if let Some(position) = c
            .pending_msg1
            .iter()
            .position(|(pending, _)| *pending == index)
        {
            seq = Some(c.pending_msg1.remove(position).1);
        } else {
            c.correlation_overflow = true;
        }
        c.handlers_active += 1;
        c.record(r.event("handler_entry", Some(index), seq, None));
    });
    Some(Span {
        handle,
        operation: Operation::Handler,
        index,
        seq,
        done: false,
    })
}

pub(crate) fn msg2_queued(
    transport: TransportId,
    addr: &TransportAddr,
    data: &[u8],
    result: &'static str,
) {
    if !observing() {
        return;
    }
    let Some(header) = Msg2Header::parse(data) else {
        return;
    };
    let Some(handle) = lookup(transport, addr) else {
        return;
    };
    handle.update(|c, r| {
        if result == "queued" {
            c.msg2_queued = c.msg2_queued.saturating_add(1);
        }
        c.record(r.event(
            "msg2_queue",
            Some(header.receiver_idx.as_u32()),
            None,
            Some(result),
        ));
    });
}

pub(crate) fn msg2_write(
    transport: TransportId,
    addr: &TransportAddr,
    data: &[u8],
) -> Option<Span> {
    if !observing() {
        return None;
    }
    let index = Msg2Header::parse(data)?.receiver_idx.as_u32();
    let handle = lookup(transport, addr)?;
    handle.update(|c, r| {
        // The writer can run on another worker before try_send's caller records
        // its result. Independent totals preserve that legitimate event order.
        c.msg2_started = c.msg2_started.saturating_add(1);
        c.writes_active += 1;
        c.record(r.event("write_start", Some(index), None, None));
    });
    Some(Span {
        handle,
        operation: Operation::Write,
        index,
        seq: None,
        done: false,
    })
}

#[cfg(test)]
pub(crate) mod tests;
