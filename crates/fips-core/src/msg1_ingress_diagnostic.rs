//! Temporary, opt-in WebSocket Msg1 ingress correlation.
//!
//! `fips_core::msg1_ingress=debug` observes a fixed process-wide monotonic
//! window, 30..75 seconds after its first valid WebSocket Msg1 read. Boundary
//! markers are traffic-driven; absence of an open marker does not qualify a
//! probe, and an absent closed marker does not prove observation past the end.
//! Disable the separate completion diagnostic during this observation.
//!
//! Indices are untrusted wire hints. Events are roots and contain no address,
//! identity, payload or inherited span fields. A record on one side of the
//! window can have no matching record on the other side. This changes neither
//! admission nor deadlines and creates no timer, task or operator setting.

use crate::node::wire::Msg1Header;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicU8, Ordering};
use std::time::Instant;

const OPEN_MS: u64 = 30_000;
const CLOSE_MS: u64 = 75_000;
static WINDOW: OnceLock<Window> = OnceLock::new();

struct Window {
    anchor: Instant,
    // 0: armed, 1: open observed, 2: closed observed.
    observed: AtomicU8,
}

impl Window {
    fn new(anchor: Instant) -> Self {
        Self {
            anchor,
            observed: AtomicU8::new(0),
        }
    }

    fn boundary(stage: &'static str, elapsed_ms: u64) {
        tracing::debug!(target: "fips_core::msg1_ingress", parent: None,
            stage = %stage, elapsed_ms, open_ms = OPEN_MS, close_ms = CLOSE_MS,
            "Msg1 window");
    }

    fn elapsed_in_window(&self, now: Instant) -> Option<u64> {
        let elapsed_ms = now.saturating_duration_since(self.anchor).as_millis() as u64;
        if elapsed_ms < OPEN_MS {
            return None;
        }
        if elapsed_ms >= CLOSE_MS {
            if self.observed.swap(2, Ordering::Relaxed) != 2 {
                Self::boundary("closed", elapsed_ms);
            }
            return None;
        }
        match self.observed.fetch_max(1, Ordering::Relaxed) {
            0 => Self::boundary("open", elapsed_ms),
            2 => return None,
            _ => {}
        }
        Some(elapsed_ms)
    }

    fn record(&self, stage: Stage, sender_index: u32, now: Instant, wait_us: Option<u64>) {
        let Some(elapsed_ms) = self.elapsed_in_window(now) else {
            return;
        };
        let stage = stage.label();
        if let Some(queue_wait_us) = wait_us {
            tracing::debug!(target: "fips_core::msg1_ingress", parent: None,
                sender_index, stage = %stage, elapsed_ms, queue_wait_us, "Msg1 ingress");
        } else {
            tracing::debug!(target: "fips_core::msg1_ingress", parent: None,
                sender_index, stage = %stage, elapsed_ms, "Msg1 ingress");
        }
    }
}

#[derive(Clone, Copy)]
enum Stage {
    Read,
    Admitted,
    HandlerEntry,
}

impl Stage {
    fn label(self) -> &'static str {
        match self {
            Self::Read => "read",
            Self::Admitted => "admitted",
            Self::HandlerEntry => "handler_entry",
        }
    }
}

pub(crate) fn enabled() -> bool {
    tracing::enabled!(target: "fips_core::msg1_ingress", tracing::Level::DEBUG)
}

pub(crate) struct Msg1Read {
    sender_index: u32,
    admission_started: Instant,
}

pub(crate) fn websocket_read(data: &[u8]) -> Option<Msg1Read> {
    if !enabled() {
        return None;
    }
    let sender_index = Msg1Header::parse(data)?.sender_idx.as_u32();
    let read_at = Instant::now();
    let window = WINDOW.get_or_init(|| {
        Window::boundary("armed", 0);
        Window::new(read_at)
    });
    window.record(Stage::Read, sender_index, read_at, None);
    // Retain the token even during warmup: admission may finish in the window.
    Some(Msg1Read {
        sender_index,
        admission_started: read_at,
    })
}

impl Msg1Read {
    pub(crate) fn begin_admission(&mut self) {
        // Exclude header parsing, the read event, and packet allocation.
        self.admission_started = Instant::now();
    }

    pub(crate) fn admitted(self) {
        let now = Instant::now();
        let wait_us = now
            .saturating_duration_since(self.admission_started)
            .as_micros();
        if let Some(window) = WINDOW.get() {
            window.record(
                Stage::Admitted,
                self.sender_index,
                now,
                Some(wait_us.min(u128::from(u64::MAX)) as u64),
            );
        }
    }
}

// The caller checks that this packet belongs to a WebSocket transport. Only
// a valid WebSocket read may arm the clock; handler entry never restarts it.
pub(crate) fn handler_entry(data: &[u8]) {
    if let (Some(window), Some(header)) = (WINDOW.get(), Msg1Header::parse(data)) {
        window.record(
            Stage::HandlerEntry,
            header.sender_idx.as_u32(),
            Instant::now(),
            None,
        );
    }
}

#[cfg(test)]
pub(crate) mod tests;
