//! Temporary, opt-in contact diagnostics. Never compiled into a normal library.
use crate::NodeAddr;
use serde::Serialize;
use std::sync::{Arc, Mutex};
use tokio::time::Instant;

#[derive(Clone, Copy, Debug, Serialize)]
pub(crate) struct Stamp {
    pub us: u64,
    pub native_ms: u64,
}

#[derive(Debug, Serialize)]
pub(crate) struct Record {
    stamp: Stamp,
    kind: &'static str,
    edge: Option<(usize, usize)>,
    fields: &'static [&'static str],
    values: [u64; 8],
}

#[derive(Clone, Copy, Debug)]
struct Snapshot {
    kind: &'static str,
    edge: (usize, usize),
    values: [u64; 8],
}

#[derive(Debug)]
struct Records {
    active: bool,
    entries: Vec<Record>,
    capacity: usize,
    overflow: usize,
    snapshots: [Option<Snapshot>; 12],
}

#[derive(Clone, Debug)]
pub(crate) struct Trace {
    started: Instant,
    ids: [NodeAddr; 4],
    addresses: [String; 4],
    originals: [&'static [u8]; 2],
    records: Arc<Mutex<Records>>,
}

impl Trace {
    pub(crate) fn new(
        started: Instant,
        ids: [NodeAddr; 4],
        addresses: [String; 4],
        originals: [&'static [u8]; 2],
        capacity: usize,
    ) -> Self {
        Self {
            started,
            ids,
            addresses,
            originals,
            records: Arc::new(Mutex::new(Records {
                active: false,
                entries: Vec::with_capacity(capacity),
                capacity,
                overflow: 0,
                snapshots: [None; 12],
            })),
        }
    }

    pub(crate) fn set_active(&self, active: bool) {
        self.records.lock().unwrap().active = active;
    }

    pub(crate) fn active(&self) -> bool {
        self.records.lock().unwrap().active
    }

    pub(crate) fn stamp(&self) -> Stamp {
        Stamp {
            us: self.started.elapsed().as_micros() as u64,
            native_ms: crate::time::now_ms(),
        }
    }

    pub(crate) fn edge_indices(source: usize, destination: usize) -> Option<(usize, usize)> {
        matches!(
            (source, destination),
            (0, 1) | (1, 0) | (0, 2) | (2, 0) | (1, 3) | (3, 1)
        )
        .then_some((source, destination))
    }

    pub(crate) fn edge(&self, source: &NodeAddr, destination: &NodeAddr) -> Option<(usize, usize)> {
        Self::edge_indices(
            self.ids.iter().position(|id| id == source)?,
            self.ids.iter().position(|id| id == destination)?,
        )
    }

    pub(crate) fn wire_edge(&self, source: &str, destination: &str) -> Option<(usize, usize)> {
        Self::edge_indices(
            self.addresses.iter().position(|id| id == source)?,
            self.addresses.iter().position(|id| id == destination)?,
        )
    }

    pub(crate) fn targets(&self) -> [NodeAddr; 2] {
        [self.ids[2], self.ids[3]]
    }

    pub(crate) fn original(
        &self,
        source: &NodeAddr,
        destination: usize,
        payload: &[u8],
    ) -> Option<usize> {
        [(2, 3), (3, 2)]
            .iter()
            .enumerate()
            .find_map(|(flow, &(from, to))| {
                (destination == to && *source == self.ids[from] && payload == self.originals[flow])
                    .then_some(flow)
            })
    }

    pub(crate) fn record_at(
        &self,
        stamp: Stamp,
        kind: &'static str,
        edge: Option<(usize, usize)>,
        fields: &'static [&'static str],
        values: [u64; 8],
    ) {
        let mut records = self.records.lock().unwrap();
        if !records.active {
            return;
        }
        if matches!(kind, "bloom-pending" | "bloom_incoming_snapshot") {
            let edge = edge.expect("directed snapshot");
            if let Some(previous) = records
                .snapshots
                .iter_mut()
                .flatten()
                .find(|s| s.kind == kind && s.edge == edge)
            {
                if previous.values == values {
                    return;
                }
                previous.values = values;
            } else if let Some(slot) = records.snapshots.iter_mut().find(|s| s.is_none()) {
                *slot = Some(Snapshot { kind, edge, values });
            } else {
                records.overflow += 1;
                return;
            }
        }
        if records.entries.len() == records.capacity {
            records.overflow += 1;
        } else {
            records.entries.push(Record {
                stamp,
                kind,
                edge,
                fields,
                values,
            });
        }
    }

    pub(crate) fn finish(&self) -> serde_json::Value {
        let mut records = self.records.lock().unwrap();
        records.active = false;
        serde_json::json!({"schema":1,"missing_value":u64::MAX,"overflow":records.overflow,
            "overflowed":records.overflow != 0,"records":records.entries})
    }
}

/// A wire key is diagnostic correlation only; no plaintext or packet is retained.
pub(crate) fn wire_key(data: &[u8]) -> [u64; 3] {
    let mut header = [0; 16];
    let count = data.len().min(header.len());
    header[..count].copy_from_slice(&data[..count]);
    [
        u64::from_le_bytes(header[..8].try_into().unwrap()),
        u64::from_le_bytes(header[8..].try_into().unwrap()),
        data.len() as u64,
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn disabled_and_overflow_are_explicit() {
        let ids = std::array::from_fn(|_| *crate::Identity::generate().node_addr());
        let trace = Trace::new(
            Instant::now(),
            ids,
            std::array::from_fn(|i| i.to_string()),
            [b"one", b"two"],
            1,
        );
        trace.record_at(trace.stamp(), "disabled", None, &[], [0; 8]);
        trace.set_active(true);
        trace.record_at(trace.stamp(), "kept", None, &[], [0; 8]);
        trace.record_at(trace.stamp(), "overflow", None, &[], [0; 8]);
        let result = trace.finish();
        assert_eq!(result["records"].as_array().unwrap().len(), 1);
        assert_eq!(result["records"][0]["kind"], "kept");
        assert_eq!(result["overflow"], 1);
        assert_eq!(result["overflowed"], true);
        assert!(!trace.active());
        let trace = Trace::new(
            Instant::now(),
            ids,
            std::array::from_fn(|i| i.to_string()),
            [b"one", b"two"],
            4,
        );
        trace.set_active(true);
        for value in [0, 0, 1, 1] {
            trace.record_at(
                trace.stamp(),
                "bloom-pending",
                Some((0, 1)),
                &["value"],
                [value; 8],
            );
        }
        for _ in 0..2 {
            trace.record_at(trace.stamp(), "exact-send", Some((0, 1)), &[], [0; 8]);
        }
        let result = trace.finish();
        let records = result["records"].as_array().unwrap();
        assert_eq!(
            records.len(),
            4,
            "initial+changed snapshots and both exact sends retained"
        );
        assert_eq!(records[0]["values"][0], 0);
        assert_eq!(records[1]["values"][0], 1);
        assert_eq!(result["overflowed"], false);
    }
}
