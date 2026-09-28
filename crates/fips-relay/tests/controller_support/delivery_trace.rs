use fips_core::node::{
    ForwardingAdmission, ForwardingOutcome, ForwardingPolicy, ForwardingRequest,
};
use fips_relay::buyer::PaidForwarder;
use sha2::{Digest, Sha256};
use std::{collections::VecDeque, sync::Mutex, time::Instant};

const CAPACITY: usize = 128;

#[derive(Debug)]
struct Record {
    elapsed_ms: u128,
    source: String,
    destination: String,
    ingress: String,
    next_hop: String,
    bytes: usize,
    digest: String,
    admission: Option<ForwardingAdmission>,
    outcome: Option<ForwardingOutcome>,
}

/// Failure-only evidence for the test's 1,000-byte payloads and larger records.
/// Hash the unchanged encrypted envelope so successive hops can be matched;
/// never retain its contents or change the real admission/scheduling decision.
#[derive(Debug)]
pub(crate) struct DeliveryTrace {
    inner: PaidForwarder,
    started: Instant,
    records: Mutex<VecDeque<Record>>,
}

impl DeliveryTrace {
    pub(crate) fn new(inner: PaidForwarder) -> Self {
        Self {
            inner,
            started: Instant::now(),
            records: Mutex::new(VecDeque::with_capacity(CAPACITY)),
        }
    }

    pub(crate) fn dump(&self, node: usize) {
        for row in self.records.lock().unwrap().iter() {
            eprintln!(
                "controller forwarding node={node} ms={} source={} destination={} ingress={} next={} bytes={} digest={} admission={:?} outcome={:?}",
                row.elapsed_ms,
                row.source,
                row.destination,
                row.ingress,
                row.next_hop,
                row.bytes,
                row.digest,
                row.admission,
                row.outcome,
            );
        }
    }
}

impl ForwardingPolicy for DeliveryTrace {
    fn admit(&self, request: &ForwardingRequest<'_>) -> Option<u64> {
        self.admit_classified(request)
            .map(|admission| admission.token)
    }

    fn admit_classified(&self, request: &ForwardingRequest<'_>) -> Option<ForwardingAdmission> {
        let admission = self.inner.admit_classified(request);
        if request.session_payload.len() >= 1_000 {
            let row = Record {
                elapsed_ms: self.started.elapsed().as_millis(),
                source: request.source.to_string(),
                destination: request.destination.to_string(),
                ingress: request.ingress.node_addr().to_string(),
                next_hop: request.next_hop.to_string(),
                bytes: request.session_payload.len(),
                digest: format!("{:x}", Sha256::digest(request.session_payload)),
                admission,
                outcome: None,
            };
            let mut records = self.records.lock().unwrap();
            if records.len() == CAPACITY {
                records.pop_front();
            }
            records.push_back(row);
        }
        admission
    }

    fn complete(&self, token: u64, outcome: ForwardingOutcome) {
        self.inner.complete(token, outcome);
        // Zero is shared by untracked admissions, so it cannot identify a row.
        if token != 0
            && let Some(row) = self.records.lock().unwrap().iter_mut().rev().find(|row| {
                row.admission
                    .is_some_and(|admission| admission.token == token)
            })
        {
            row.outcome = Some(outcome);
        }
    }
}
