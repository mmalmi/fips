//! Temporary contact diagnostics; only compiled into unit tests.
use super::*;
use crate::test_trace::Trace;

const MISSING: u64 = u64::MAX;

fn membership(filter: Option<&BloomFilter>, targets: [NodeAddr; 2]) -> [u64; 2] {
    targets.map(|target| filter.map_or(MISSING, |filter| u64::from(filter.contains(&target))))
}

impl BloomState {
    pub(crate) fn set_diagnostic_trace(&mut self, trace: Option<Trace>) {
        self.diagnostic_trace = trace;
    }

    /// Read existing history only; never build a filter or advance its sequence.
    pub(crate) fn trace_pending_filter(&self, peer: &NodeAddr) {
        let Some(trace) = self
            .diagnostic_trace
            .as_ref()
            .filter(|trace| trace.active())
        else {
            return;
        };
        let Some(edge) = trace.edge(&self.own_node_addr, peer) else {
            return;
        };
        let stamp = trace.stamp();
        let bits = membership(self.last_sent_filters.get(peer), trace.targets());
        trace.record_at(
            stamp,
            "bloom-pending",
            Some(edge),
            &[
                "pending",
                "due_ms",
                "last_send_ms",
                "debounce_ms",
                "target_2",
                "target_3",
            ],
            [
                u64::from(self.needs_update(peer)),
                self.pending_peer_deadline_ms(peer).unwrap_or(MISSING),
                self.last_update_sent.get(peer).copied().unwrap_or(MISSING),
                self.update_debounce_ms,
                bits[0],
                bits[1],
                0,
                0,
            ],
        );
    }

    pub(crate) fn trace_filter_send(
        &self,
        peer: &NodeAddr,
        sequence: u64,
        due_before: Option<u64>,
    ) {
        let Some(trace) = self
            .diagnostic_trace
            .as_ref()
            .filter(|trace| trace.active())
        else {
            return;
        };
        let Some(edge) = trace.edge(&self.own_node_addr, peer) else {
            return;
        };
        let stamp = trace.stamp();
        let bits = membership(self.last_sent_filters.get(peer), trace.targets());
        trace.record_at(
            stamp,
            "bloom-send-completed",
            Some(edge),
            &[
                "sequence",
                "due_before_ms",
                "last_send_ms",
                "target_2",
                "target_3",
            ],
            [
                sequence,
                due_before.unwrap_or(MISSING),
                self.last_update_sent.get(peer).copied().unwrap_or(MISSING),
                bits[0],
                bits[1],
                0,
                0,
                0,
            ],
        );
    }

    pub(crate) fn trace_filter_received(
        &self,
        from: &NodeAddr,
        sequence: u64,
        tree_peer: bool,
        filter: Option<&BloomFilter>,
    ) {
        let Some(trace) = self
            .diagnostic_trace
            .as_ref()
            .filter(|trace| trace.active())
        else {
            return;
        };
        let Some(edge) = trace.edge(from, &self.own_node_addr) else {
            return;
        };
        let stamp = trace.stamp();
        let bits = membership(filter, trace.targets());
        trace.record_at(
            stamp,
            "bloom-received",
            Some(edge),
            &["sequence", "tree_peer", "target_2", "target_3"],
            [sequence, u64::from(tree_peer), bits[0], bits[1], 0, 0, 0, 0],
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn directed_filter_trace_preserves_deadlines_and_scope() {
        let ids = std::array::from_fn(|index| {
            let mut bytes = [0; 16];
            bytes[0] = index as u8 + 1;
            NodeAddr::from_bytes(bytes)
        });
        let trace = Trace::new(
            tokio::time::Instant::now(),
            ids,
            std::array::from_fn(|index| index.to_string()),
            [b"one", b"two"],
            8,
        );
        let mut state = BloomState::new(ids[0]);
        state.set_diagnostic_trace(Some(trace.clone()));
        state.trace_pending_filter(&ids[2]);
        trace.set_active(true);

        let mut filter = BloomFilter::new();
        filter.insert(&ids[2]);
        assert!(!filter.contains(&ids[3]));
        state.record_update_sent(ids[2], 100);
        state.record_sent_filter(ids[2], filter.clone());
        state.mark_update_needed(ids[2]);
        let original_sequence = state.sequence();
        state.trace_pending_filter(&ids[2]);
        assert_eq!(state.sequence(), original_sequence);
        assert_eq!(state.pending_peer_deadline_ms(&ids[2]), Some(600));
        assert!(state.needs_update(&ids[2]));
        assert!(!state.should_send_update(&ids[2], 599));
        assert!(state.should_send_update(&ids[2], 600));

        state.record_update_sent(ids[2], 600);
        state.trace_filter_send(&ids[2], 7, Some(600));
        assert!(!state.needs_update(&ids[2]));
        let mut receiver = BloomState::new(ids[2]);
        receiver.set_diagnostic_trace(Some(trace.clone()));
        receiver.trace_filter_received(&ids[0], 7, true, Some(&filter));
        receiver.trace_filter_received(&ids[3], 7, true, Some(&filter));

        let result = trace.finish();
        let records = result["records"].as_array().unwrap();
        assert_eq!(records.len(), 3, "disabled and unrelated edges stay absent");
        assert_eq!(result["overflow"], 0);
        assert_eq!(records[0]["kind"], "bloom-pending");
        assert_eq!(records[0]["edge"], serde_json::json!([0, 2]));
        assert_eq!(
            records[0]["values"],
            serde_json::json!([1, 600, 100, 500, 1, 0, 0, 0])
        );
        assert_eq!(records[1]["kind"], "bloom-send-completed");
        assert_eq!(
            records[1]["values"],
            serde_json::json!([7, 600, 600, 1, 0, 0, 0, 0])
        );
        assert_eq!(records[2]["kind"], "bloom-received");
        assert_eq!(records[2]["edge"], serde_json::json!([0, 2]));
        assert_eq!(
            records[2]["values"],
            serde_json::json!([7, 1, 1, 0, 0, 0, 0, 0])
        );
    }
}
