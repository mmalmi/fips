//! Bounded observation of successful durable authorization increases.
//! These events have no financial authority and never contain payment material.

use super::monotonic_clock;
use serde::Serialize;
use std::{collections::VecDeque, sync::Mutex};

const CAPACITY: usize = 1024;
const MAX_CHANNEL_ID_BYTES: usize = 128;
static TRACE: Mutex<Trace> = Mutex::new(Trace::new());

#[derive(Debug, Clone, Serialize)]
pub struct Event {
    pub sequence: u64,
    pub channel_id: String,
    pub old_sat: u64,
    pub new_sat: u64,
    /// Contains atomic file publication and the successful durability syncs.
    pub started_ns: u64,
    pub finished_ns: u64,
}

#[derive(Debug, Serialize)]
pub struct Snapshot {
    pub version: u8,
    pub clock: &'static str,
    pub capacity: usize,
    pub measured_at_ns: Option<u64>,
    pub completed_sequence: u64,
    pub overwritten: u64,
    pub missing_intervals: u64,
    pub clock_failures: u64,
    pub aborted: u64,
    /// A boundary with pending persistence/insertion is incomplete.
    pub pending: u64,
    pub sequence_exhausted: bool,
    pub lock_poisoned: bool,
    pub events: Vec<Event>,
}

struct Trace {
    completed_sequence: u64,
    overwritten: u64,
    missing_intervals: u64,
    clock_failures: u64,
    aborted: u64,
    pending: u64,
    sequence_exhausted: bool,
    lock_poisoned: bool,
    events: VecDeque<Event>,
}

impl Trace {
    const fn new() -> Self {
        Self {
            completed_sequence: 0,
            overwritten: 0,
            missing_intervals: 0,
            clock_failures: 0,
            aborted: 0,
            pending: 0,
            sequence_exhausted: false,
            lock_poisoned: false,
            events: VecDeque::new(),
        }
    }

    fn begin(&mut self, started: Option<u64>) {
        self.pending = self.pending.saturating_add(1);
        self.clock_failures = self
            .clock_failures
            .saturating_add(u64::from(started.is_none()));
    }

    fn committed(&mut self, id: &str, old: u64, new: u64, start: Option<u64>, end: Option<u64>) {
        self.pending -= 1;
        let Some(sequence) = self.completed_sequence.checked_add(1) else {
            self.sequence_exhausted = true;
            self.missing_intervals = self.missing_intervals.saturating_add(1);
            return;
        };
        self.completed_sequence = sequence;
        self.clock_failures = self.clock_failures.saturating_add(u64::from(end.is_none()));
        let interval = start.zip(end).filter(|(a, b)| a <= b);
        if start.zip(end).is_some_and(|(a, b)| a > b) {
            self.clock_failures = self.clock_failures.saturating_add(1);
        }
        let Some((started_ns, finished_ns)) =
            interval.filter(|_| !id.is_empty() && id.len() <= MAX_CHANNEL_ID_BYTES && new > old)
        else {
            self.missing_intervals = self.missing_intervals.saturating_add(1);
            return;
        };
        if self.events.len() == CAPACITY {
            self.events.pop_front();
            self.overwritten = self.overwritten.saturating_add(1);
        }
        self.events.push_back(Event {
            sequence,
            channel_id: id.to_owned(),
            old_sat: old,
            new_sat: new,
            started_ns,
            finished_ns,
        });
    }

    fn snapshot(&mut self, measured_at_ns: Option<u64>) -> Snapshot {
        self.clock_failures = self
            .clock_failures
            .saturating_add(u64::from(measured_at_ns.is_none()));
        Snapshot {
            version: 1,
            clock: "CLOCK_MONOTONIC",
            capacity: CAPACITY,
            measured_at_ns,
            completed_sequence: self.completed_sequence,
            overwritten: self.overwritten,
            missing_intervals: self.missing_intervals,
            clock_failures: self.clock_failures,
            aborted: self.aborted,
            pending: self.pending,
            sequence_exhausted: self.sequence_exhausted,
            lock_poisoned: self.lock_poisoned,
            events: self.events.iter().cloned().collect(),
        }
    }
}

fn lock() -> std::sync::MutexGuard<'static, Trace> {
    TRACE.lock().unwrap_or_else(|error| {
        let mut trace = error.into_inner();
        trace.lock_poisoned = true;
        trace
    })
}

/// Register before persistence. No diagnostic lock survives this call.
pub(crate) fn begin() -> Commit {
    let mut trace = lock();
    let started = monotonic_clock();
    trace.begin(started);
    Commit {
        started,
        pending: true,
    }
}

pub(crate) struct Commit {
    started: Option<u64>,
    pending: bool,
}

impl Commit {
    /// Call only after successful persistence, before invoking the signer.
    pub(crate) fn committed(mut self, id: &str, old: u64, new: u64) {
        let ended = monotonic_clock();
        lock().committed(id, old, new, self.started, ended);
        self.pending = false;
    }
}

impl Drop for Commit {
    fn drop(&mut self) {
        if self.pending {
            let mut trace = lock();
            trace.pending -= 1;
            trace.aborted = trace.aborted.saturating_add(1);
        }
    }
}

pub(super) fn snapshot() -> Snapshot {
    let mut trace = lock();
    // Begin and insertion use this same lock. A persisted event waiting for
    // insertion remains pending; a later begin cannot precede this timestamp.
    trace.snapshot(monotonic_clock())
}

#[cfg(test)]
mod tests;
