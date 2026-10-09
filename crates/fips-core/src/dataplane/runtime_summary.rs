#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct DataplaneRuntimeSummary {
    raw_ingress_dropped: usize,
    inbound_admitted: usize,
    inbound_dropped: usize,
    outbound_admitted: usize,
    outbound_dropped: usize,
    completions: usize,
    dispatched: usize,
    outputs: usize,
    outputs_sent: usize,
    outputs_dropped: usize,
    drops: usize,
}

impl DataplaneRuntimeSummary {
    pub(crate) fn raw_ingress_dropped(self) -> usize {
        self.raw_ingress_dropped
    }

    pub(crate) fn inbound_admitted(self) -> usize {
        self.inbound_admitted
    }

    pub(crate) fn inbound_dropped(self) -> usize {
        self.inbound_dropped
    }

    pub(crate) fn outbound_admitted(self) -> usize {
        self.outbound_admitted
    }

    pub(crate) fn outbound_dropped(self) -> usize {
        self.outbound_dropped
    }

    pub(crate) fn completions(self) -> usize {
        self.completions
    }

    pub(crate) fn dispatched(self) -> usize {
        self.dispatched
    }

    pub(crate) fn outputs(self) -> usize {
        self.outputs
    }

    pub(crate) fn outputs_sent(self) -> usize {
        self.outputs_sent
    }

    pub(crate) fn outputs_dropped(self) -> usize {
        self.outputs_dropped
    }

    pub(crate) fn drops(self) -> usize {
        self.drops
    }

    pub(crate) fn has_activity(self) -> bool {
        self.raw_ingress_dropped > 0
            || self.inbound_admitted > 0
            || self.inbound_dropped > 0
            || self.outbound_admitted > 0
            || self.outbound_dropped > 0
            || self.completions > 0
            || self.dispatched > 0
            || self.outputs > 0
            || self.outputs_sent > 0
            || self.outputs_dropped > 0
            || self.drops > 0
    }

    pub(crate) fn has_failures(self) -> bool {
        self.raw_ingress_dropped > 0
            || self.inbound_dropped > 0
            || self.outbound_dropped > 0
            || self.outputs_dropped > 0
            || self.drops > 0
    }

    fn absorb(&mut self, other: Self) {
        self.raw_ingress_dropped = self
            .raw_ingress_dropped
            .saturating_add(other.raw_ingress_dropped);
        self.inbound_admitted = self.inbound_admitted.saturating_add(other.inbound_admitted);
        self.inbound_dropped = self.inbound_dropped.saturating_add(other.inbound_dropped);
        self.outbound_admitted = self
            .outbound_admitted
            .saturating_add(other.outbound_admitted);
        self.outbound_dropped = self
            .outbound_dropped
            .saturating_add(other.outbound_dropped);
        self.completions = self.completions.saturating_add(other.completions);
        self.dispatched = self.dispatched.saturating_add(other.dispatched);
        self.outputs = self.outputs.saturating_add(other.outputs);
        self.outputs_sent = self.outputs_sent.saturating_add(other.outputs_sent);
        self.outputs_dropped = self.outputs_dropped.saturating_add(other.outputs_dropped);
        self.drops = self.drops.saturating_add(other.drops);
    }
}
