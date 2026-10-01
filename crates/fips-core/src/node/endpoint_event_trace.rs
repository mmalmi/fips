//! Temporary per-channel publication brackets for the contact diagnostic.
use super::*;
use crate::test_trace::{Stamp, Trace};

pub(super) struct Publication {
    trace: Trace,
    before: Stamp,
    destination: usize,
    flow: usize,
    constructed_ms: u64,
}

impl Publication {
    pub(super) fn finish(self, published: bool) {
        let after = self.trace.stamp();
        self.trace.record_at(
            after,
            if published {
                "endpoint_published"
            } else {
                "endpoint_rejected"
            },
            Some((if self.flow == 0 { 2 } else { 3 }, self.destination)),
            &["flow", "constructed_ms", "before_us", "after_us"],
            [
                self.flow as u64,
                self.constructed_ms,
                self.before.us,
                after.us,
                0,
                0,
                0,
                0,
            ],
        );
    }
}

impl EndpointEventSender {
    pub(crate) fn set_contact_trace(&self, trace: Option<(Trace, usize)>) {
        *self.ready.trace.lock().unwrap() = trace;
    }

    pub(super) fn publication_probe(&self, event: &NodeEndpointEvent) -> Option<Publication> {
        let (trace, destination) = self.ready.trace.lock().unwrap().clone()?;
        if !trace.active() {
            return None;
        }
        event.messages.iter().find_map(|message| {
            let flow = trace.original(
                message.source_peer.node_addr(),
                destination,
                message.payload.as_slice(),
            )?;
            Some(Publication {
                before: trace.stamp(),
                trace: trace.clone(),
                destination,
                flow,
                constructed_ms: message.enqueued_at_ms,
            })
        })
    }
}
