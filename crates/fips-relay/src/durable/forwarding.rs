//! Classify temporary allowance shortages without creating a reservation.
use super::*;

impl ForwardingPolicy for DurableRelay {
    fn admit(&self, request: &ForwardingRequest<'_>) -> Option<u64> {
        self.decide(request)
            .admission()
            .map(|admission| admission.token)
    }

    fn decide(&self, request: &ForwardingRequest<'_>) -> fips_core::node::ForwardingDecision {
        use fips_core::node::{ForwardingAdmission, ForwardingClass, ForwardingDecision};
        // Never wait for the disk-writing controller on the native node loop.
        let Ok(windows) = self.windows.read() else {
            return ForwardingDecision::Reject;
        };
        if !windows.ready {
            return ForwardingDecision::Reject;
        }
        let Ok(now) = SystemTime::now().duration_since(UNIX_EPOCH) else {
            return ForwardingDecision::Reject;
        };
        let Some(admission) = self.ledger.admit_with_windows(
            request,
            now.as_secs(),
            Some((&windows.ceilings, self.window_msat)),
        ) else {
            return ForwardingDecision::Reject;
        };
        match admission {
            Admission::Granted(token) => ForwardingDecision::Admit(ForwardingAdmission {
                token,
                class: ForwardingClass::Unspecified,
            }),
            Admission::CreditExhausted => ForwardingDecision::Retry,
            Admission::WindowExhausted => {
                crate::measurements::admission_denied(
                    crate::measurements::AdmissionDenial::DurableWindow,
                );
                self.window_blocked.store(true, Ordering::Relaxed);
                ForwardingDecision::Retry
            }
        }
    }

    fn complete(&self, token: u64, outcome: ForwardingOutcome) {
        // Completion never needs the controller gate. A pending outcome captured
        // before this completion remains conservatively unconfirmed on recovery.
        self.ledger.complete(token, outcome);
    }
}
