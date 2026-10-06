//! Optional local submission diagnostics, never routing or payment authority.

use super::{FipsEndpoint, FipsEndpointError, FipsEndpointOutboundDatagram};
use crate::node::EndpointDataPayload;
use portable_atomic::AtomicU64;
use serde::Serialize;
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

/// Maximum distinct services measured by one endpoint during its lifetime.
pub const SERVICE_CARRIER_DIAGNOSTICS_MAX_SERVICES: usize = 16;
static NEXT_COUNTER_ID: AtomicU64 = AtomicU64::new(1);
const TRANSPORTS: [&str; 9] = [
    "udp",
    "ethernet",
    "tcp",
    "tor",
    "websocket",
    "webrtc",
    "ble",
    "sim",
    "other",
];

/// Successful local transport submissions for one service and carrier type.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize)]
pub struct ServiceCarrierTransportSnapshot {
    pub transport: &'static str,
    /// Counts individual submitted fragments, including retransmitted service datagrams.
    pub submitted_packets: u64,
    /// Bytes accepted by the transport API, including FIPS encryption and fragment headers.
    pub fips_payload_bytes: u64,
    /// Ethernet's three-byte data prefix, separate from the submitted FIPS payload.
    pub ethernet_framing_bytes: u64,
}

/// Cumulative, process-local observations since this service was enabled.
///
/// Only locally originated service datagrams are attributed. Opaque transit,
/// shared handshakes, MMP and rekey traffic are outside these counters. UDP is
/// measured at its payload boundary; Ethernet excludes the OS header/padding;
/// TCP excludes kernel ACKs and retransmissions. Other carrier encapsulation
/// and radio airtime are not measured. Snapshots are not an atomic transaction.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ServiceCarrierSnapshot {
    pub service_port: u16,
    /// Both distinct endpoint ports matched enabled services; the source won.
    pub ambiguous_port_datagrams: u64,
    /// Sealed outputs discarded before complete submission, including unsent batch tails.
    /// Earlier admission or crypto failures are not observed here.
    pub discarded_outputs: u64,
    pub transports: [ServiceCarrierTransportSnapshot; 9],
}

#[derive(Debug, Default)]
struct TransportCounters {
    packets: AtomicU64,
    payload_bytes: AtomicU64,
    ethernet_framing_bytes: AtomicU64,
}

#[derive(Debug)]
struct ServiceCounters {
    id: u64,
    port: u16,
    ambiguous: AtomicU64,
    discarded: AtomicU64,
    transports: [TransportCounters; 9],
}

/// Stable handle to one endpoint's optional service counters; cloning shares them.
#[derive(Clone, Debug)]
pub struct ServiceCarrierDiagnostics(Arc<ServiceCounters>);

impl PartialEq for ServiceCarrierDiagnostics {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }
}

impl Eq for ServiceCarrierDiagnostics {}

fn add(counter: &AtomicU64, amount: u64) -> u64 {
    counter
        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
            Some(value.saturating_add(amount))
        })
        .expect("saturating counter update cannot reject")
        .saturating_add(amount)
}

impl ServiceCarrierDiagnostics {
    pub(crate) fn new(port: u16) -> Self {
        Self(Arc::new(ServiceCounters {
            id: NEXT_COUNTER_ID.fetch_add(1, Ordering::Relaxed),
            port,
            ambiguous: AtomicU64::new(0),
            discarded: AtomicU64::new(0),
            transports: std::array::from_fn(|_| TransportCounters::default()),
        }))
    }

    pub(crate) fn counter_id(&self) -> u64 {
        self.0.id
    }

    pub fn snapshot(&self) -> ServiceCarrierSnapshot {
        ServiceCarrierSnapshot {
            service_port: self.0.port,
            ambiguous_port_datagrams: self.0.ambiguous.load(Ordering::Relaxed),
            discarded_outputs: self.0.discarded.load(Ordering::Relaxed),
            transports: std::array::from_fn(|index| {
                let counters = &self.0.transports[index];
                ServiceCarrierTransportSnapshot {
                    transport: TRANSPORTS[index],
                    submitted_packets: counters.packets.load(Ordering::Relaxed),
                    fips_payload_bytes: counters.payload_bytes.load(Ordering::Relaxed),
                    ethernet_framing_bytes: counters.ethernet_framing_bytes.load(Ordering::Relaxed),
                }
            }),
        }
    }

    pub(crate) fn submitted(&self, transport: &str, payload_bytes: usize) -> u64 {
        let index = TRANSPORTS
            .iter()
            .position(|name| *name == transport)
            .unwrap_or(8);
        let counters = &self.0.transports[index];
        let packet_number = add(&counters.packets, 1);
        add(&counters.payload_bytes, payload_bytes as u64);
        if transport == "ethernet" {
            add(&counters.ethernet_framing_bytes, 3);
        }
        packet_number
    }

    /// Opt-in traces correlate encrypted submissions with independent captures.
    /// Hashing is disabled unless this target is enabled; no payload is logged.
    pub(crate) fn submitted_payloads<'a>(
        &self,
        transport: &str,
        bytes: usize,
        payloads: impl IntoIterator<Item = &'a [u8]>,
    ) {
        let packet_number = self.submitted(transport, bytes);
        // tracing evaluates fields only when this event is enabled.
        tracing::trace!(target: "fips_core::service_wire",
            process_id = std::process::id(), counter_id = self.counter_id(),
            service_port = self.0.port,
            packet_number, transport, payload_bytes = bytes,
            fingerprint = %{
                use sha2::{Digest, Sha256};
                let mut fingerprint = Sha256::new();
                for payload in payloads {
                    fingerprint.update(payload);
                }
                hex::encode(fingerprint.finalize())
            },
            "FIPS service packet submitted");
    }

    pub(crate) fn discarded(&self) {
        add(&self.0.discarded, 1);
    }
}

#[derive(Debug, Default)]
pub(super) struct ServiceCarrierRegistry {
    enabled: AtomicBool,
    services: Mutex<HashMap<u16, ServiceCarrierDiagnostics>>,
}

impl ServiceCarrierRegistry {
    fn enable(&self, port: u16) -> Result<ServiceCarrierDiagnostics, FipsEndpointError> {
        let mut services = self
            .services
            .lock()
            .map_err(|_| FipsEndpointError::Closed)?;
        if let Some(counters) = services.get(&port) {
            return Ok(counters.clone());
        }
        if services.len() >= SERVICE_CARRIER_DIAGNOSTICS_MAX_SERVICES {
            return Err(FipsEndpointError::ServiceCarrierDiagnosticsLimit);
        }
        let counters = ServiceCarrierDiagnostics::new(port);
        services.insert(port, counters.clone());
        self.enabled.store(true, Ordering::Release);
        Ok(counters)
    }

    pub(super) fn for_ports(
        &self,
        source: u16,
        destination: u16,
    ) -> Option<ServiceCarrierDiagnostics> {
        if !self.enabled.load(Ordering::Acquire) {
            return None;
        }
        // Diagnostics must never make a previously valid send fail.
        let services = self.services.lock().ok()?;
        let selected = services
            .get(&source)
            .or_else(|| services.get(&destination))?;
        if source != destination
            && services.contains_key(&source)
            && services.contains_key(&destination)
        {
            add(&selected.0.ambiguous, 1);
        }
        Some(selected.clone())
    }
}

pub(super) fn service_datagram_payloads(
    datagrams: Vec<FipsEndpointOutboundDatagram>,
    carrier: &ServiceCarrierRegistry,
) -> Result<Vec<EndpointDataPayload>, FipsEndpointError> {
    let max = crate::node::session_wire::fsp_service_datagram_max_body_len();
    let mut payloads = Vec::with_capacity(datagrams.len());
    for datagram in datagrams {
        let len = datagram.data.len();
        let Some(payload) = EndpointDataPayload::from_service_datagram(
            datagram.source_port,
            datagram.destination_port,
            datagram.data,
        ) else {
            return Err(FipsEndpointError::ServiceDatagramTooLarge { len, max });
        };
        payloads.push(payload.with_service_carrier(
            carrier.for_ports(datagram.source_port, datagram.destination_port),
        ));
    }
    Ok(payloads)
}

impl FipsEndpoint {
    /// Enable bounded local carrier diagnostics for one FSP service port.
    ///
    /// A datagram matches its source port first, then its destination port. If
    /// both different ports are enabled, only the source handle records sends,
    /// and its ambiguity counter advances. Loopback has no carrier submissions.
    /// Repeated calls return the same counters; no reset or unregister changes
    /// the counter identity retained by already queued packets.
    pub fn enable_service_carrier_diagnostics(
        &self,
        port: u16,
    ) -> Result<ServiceCarrierDiagnostics, FipsEndpointError> {
        self.service_carrier.enable(port)
    }
}

#[cfg(test)]
mod tests;
