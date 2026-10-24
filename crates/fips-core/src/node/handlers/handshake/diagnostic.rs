//! Optional, compact correlation for one completed Msg1 handler.
//!
//! Enable only `fips_core::msg1_diagnostic=debug`. The public wire index is an
//! untrusted correlation hint, never authenticated identity. No addresses,
//! identity keys, payloads, or inherited tracing span fields are recorded.

use super::Msg1Header;

pub(super) struct Msg1Diagnostic {
    enabled: bool,
    sender_index: u64,
    pub(super) class: &'static str,
    pub(super) reason: &'static str,
}

impl Msg1Diagnostic {
    pub(super) fn new(data: &[u8]) -> Self {
        let enabled =
            tracing::enabled!(target: "fips_core::msg1_diagnostic", tracing::Level::DEBUG);
        Self {
            enabled,
            // Invalid headers have a sentinel outside the public u32 index range.
            // Parsing for diagnostics must not reorder the actual admission gate.
            sender_index: if enabled {
                Msg1Header::parse(data)
                    .map(|header| u64::from(header.sender_idx.as_u32()))
                    .unwrap_or(u64::MAX)
            } else {
                0
            },
            class: "unchecked",
            reason: "unclassified",
        }
    }

    pub(super) fn finish(self, carrier: &'static str) {
        if self.enabled {
            // Exactly one record, including on early refusal. Cancellation before
            // handler completion emits none; close_requested is not delivery proof.
            tracing::debug!(target: "fips_core::msg1_diagnostic", parent: None,
                sender_index = self.sender_index, class = %self.class,
                reason = %self.reason, carrier = %carrier, "Msg1 decision");
        }
    }
}
