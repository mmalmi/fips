//! Opt-in wall-time milestones for infrequent channel transitions.
use std::time::Instant;

#[derive(Clone)]
pub(super) struct TransitionTiming {
    operation: &'static str,
    id: String,
    started: Option<Instant>,
}

impl TransitionTiming {
    pub(super) fn new(operation: &'static str, id: &str) -> Self {
        Self {
            operation,
            id: id.to_owned(),
            started:
                tracing::enabled!(target: "fips_relay::controller::renewal", tracing::Level::DEBUG)
                    .then(Instant::now),
        }
    }

    pub(super) fn mark(&self, phase: &'static str) {
        if let Some(started) = self.started {
            tracing::debug!(target: "fips_relay::controller::renewal",
                operation = self.operation, transition_id = self.id, phase,
                elapsed_us = started.elapsed().as_micros(), "Channel transition progress");
        }
    }
}
