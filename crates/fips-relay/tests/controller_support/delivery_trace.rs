use fips_core::node::{
    ForwardingAdmission, ForwardingOutcome, ForwardingPolicy, ForwardingRequest,
};
use fips_core::{NodeAddr, protocol::SessionHandshake};
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

#[derive(Debug)]
struct HandshakeLoss {
    peers: [NodeAddr; 2],
    dropped: [bool; 3],
    admitted_after_loss: [bool; 3],
}

impl HandshakeLoss {
    fn phase(&self, request: &ForwardingRequest<'_>) -> Option<usize> {
        if ![
            (self.peers[0], self.peers[1]),
            (self.peers[1], self.peers[0]),
        ]
        .contains(&(request.source, request.destination))
        {
            return None;
        }
        Some(
            match SessionHandshake::classify(
                request.session_payload,
                request.source,
                request.destination,
            )? {
                SessionHandshake::Setup => 0,
                SessionHandshake::Ack => 1,
                SessionHandshake::Finish => 2,
            },
        )
    }
}

/// Failure-only evidence for large payloads and native session handshakes.
/// Hash the unchanged encrypted envelope so successive hops can be matched;
/// only an explicitly armed handshake-loss window changes admission.
#[derive(Debug)]
pub(crate) struct DeliveryTrace {
    inner: PaidForwarder,
    started: Instant,
    records: Mutex<VecDeque<Record>>,
    handshake_loss: Mutex<Option<HandshakeLoss>>,
}

impl DeliveryTrace {
    pub(crate) fn new(inner: PaidForwarder) -> Self {
        Self {
            inner,
            started: Instant::now(),
            records: Mutex::new(VecDeque::with_capacity(CAPACITY)),
            handshake_loss: Mutex::new(None),
        }
    }

    pub(crate) fn assert_handshake_allowance_used(&self) {
        let stats = self.inner.bootstrap_stats().expect("free handshake tariff");
        assert!(stats.admitted_packets > 0 && stats.admitted_session_bytes > 0);
    }

    pub(crate) fn lose_rekey_handshakes(&self, peers: [NodeAddr; 2]) {
        let mut loss = self.handshake_loss.lock().unwrap();
        assert!(loss.is_none(), "each finite loss window is armed once");
        *loss = Some(HandshakeLoss {
            peers,
            dropped: [false; 3],
            admitted_after_loss: [false; 3],
        });
    }

    pub(crate) fn assert_handshakes_recovered(&self) {
        let loss = self.handshake_loss.lock().unwrap();
        let loss = loss.as_ref().expect("handshake loss must be armed");
        assert_eq!(loss.dropped, [true; 3], "drop every native handshake phase");
        assert_eq!(loss.admitted_after_loss, [true; 3]);
        eprintln!("routed rekey lost and subsequently admitted setup, ack and finish");
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
        let mut loss = self.handshake_loss.lock().unwrap();
        let phase = loss.as_ref().and_then(|loss| loss.phase(request));
        if let (Some(loss), Some(phase)) = (loss.as_mut(), phase)
            && !loss.dropped[phase]
        {
            loss.dropped[phase] = true;
            eprintln!(
                "routed rekey dropping native handshake phase={phase} elapsed_ms={}",
                self.started.elapsed().as_millis()
            );
            return None;
        }
        let admission = self.inner.admit_classified(request);
        if admission.is_some()
            && let (Some(loss), Some(phase)) = (loss.as_mut(), phase)
        {
            loss.admitted_after_loss[phase] = true;
        }
        drop(loss);
        if request.session_payload.len() >= 1_000
            || SessionHandshake::classify(
                request.session_payload,
                request.source,
                request.destination,
            )
            .is_some()
        {
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
