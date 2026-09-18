//! Bounded operator traffic measurements at the local diagnostic service.
//! Explicitly armed echoes use ordinary priced data and never authorize payments.

use fips_core::{FipsEndpoint, FipsEndpointOutboundDatagram, PeerIdentity};
use serde::{Deserialize, Serialize};
use std::{
    sync::{Arc, Mutex},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::time::Instant;

const MAGIC: &[u8; 8] = b"FIPSPRB1";
const REPLY_MAGIC: &[u8; 8] = b"FIPSRPL1";
const RECEIVE_LIFETIME: Duration = Duration::from_secs(60);
const HEADER: usize = 40;
const MAX_PACKETS: u32 = 65_536;
const MAX_DURATION: Duration = Duration::from_secs(30);
const DATA_PORT: u16 = 44_740;
// The last bucket is unbounded. Percentiles from these counts are bounds, not
// interpolated samples. Actual extrema and sum are also retained.
const LATENCY_BOUNDS_US: &[u64] = &[
    100, 250, 500, 1_000, 2_000, 5_000, 10_000, 20_000, 50_000, 100_000, 250_000, 500_000,
    1_000_000,
];

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReceiveProbe {
    pub source: String,
    pub stream_id: String,
    pub packet_count: u32,
    pub payload_bytes: usize,
    #[serde(default)]
    pub measure_one_way_latency: bool,
    #[serde(default)]
    pub reflect: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SendProbe {
    pub destination: String,
    pub stream_id: String,
    pub packet_count: u32,
    pub payload_bytes: usize,
    pub packets_per_second: u32,
    #[serde(default)]
    pub measure_round_trip: bool,
}

fn stream_id(value: &str) -> Result<[u8; 16], String> {
    if value.len() != 32 || !value.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err("probe stream_id must be 32 hexadecimal characters".into());
    }
    Ok(u128::from_str_radix(value, 16)
        .map_err(|_| "invalid probe stream_id")?
        .to_be_bytes())
}

fn validate_shape(count: u32, bytes: usize) -> Result<(), String> {
    if !(1..=MAX_PACKETS).contains(&count) || !(HEADER..=1_000).contains(&bytes) {
        return Err("probe requires 1..65536 packets of 40..1000 bytes".into());
    }
    Ok(())
}

impl SendProbe {
    pub fn validate(&self) -> Result<(), String> {
        PeerIdentity::from_npub(&self.destination).map_err(|_| "invalid probe destination")?;
        stream_id(&self.stream_id)?;
        validate_shape(self.packet_count, self.payload_bytes)?;
        if !(1..=16_000).contains(&self.packets_per_second)
            || u64::from(self.packet_count) > u64::from(self.packets_per_second) * 30
        {
            return Err("probe rate must be 1..16000 packets/s and fit within 30 seconds".into());
        }
        Ok(())
    }
}

pub fn unix_micros() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_micros()
        .try_into()
        .unwrap_or(u64::MAX)
}

fn packet(id: [u8; 16], sequence: u64, bytes: usize, sent_us: u64) -> Vec<u8> {
    let mut payload = vec![0x5a; bytes];
    payload[..8].copy_from_slice(MAGIC);
    payload[8..24].copy_from_slice(&id);
    payload[24..32].copy_from_slice(&sequence.to_be_bytes());
    payload[32..40].copy_from_slice(&sent_us.to_be_bytes());
    payload
}

/// Encodes diagnostic application data, not a FIPS wire frame or payment claim.
pub fn encode_packet(
    id: &str,
    sequence: u64,
    bytes: usize,
    sent_us: u64,
) -> Result<Vec<u8>, String> {
    validate_shape(1, bytes)?;
    Ok(packet(stream_id(id)?, sequence, bytes, sent_us))
}

#[derive(Clone, Debug, Serialize)]
pub struct LatencyReport {
    pub samples: u64,
    pub invalid_timestamps: u64,
    pub min_us: Option<u64>,
    pub max_us: Option<u64>,
    pub sum_us: u64,
    pub bucket_upper_bounds_us: Vec<u64>,
    pub bucket_counts: Vec<u64>,
}

impl Default for LatencyReport {
    fn default() -> Self {
        Self {
            samples: 0,
            invalid_timestamps: 0,
            min_us: None,
            max_us: None,
            sum_us: 0,
            bucket_upper_bounds_us: LATENCY_BOUNDS_US.to_vec(),
            bucket_counts: vec![0; LATENCY_BOUNDS_US.len() + 1],
        }
    }
}

impl LatencyReport {
    fn record(&mut self, delay: u64) {
        self.samples += 1;
        self.sum_us += delay;
        self.min_us = Some(self.min_us.map_or(delay, |old| old.min(delay)));
        self.max_us = Some(self.max_us.map_or(delay, |old| old.max(delay)));
        let bucket = LATENCY_BOUNDS_US.partition_point(|bound| *bound < delay);
        self.bucket_counts[bucket] += 1;
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct ProbeReport {
    pub source: String,
    pub stream_id: String,
    pub expected_packets: u32,
    pub payload_bytes: usize,
    pub unique_packets: u64,
    pub unique_bytes: u64,
    pub missing_packets: u64,
    pub duplicate_packets: u64,
    pub out_of_order_packets: u64,
    pub ignored_packets: u64,
    pub invalid_packets: u64,
    pub receive_span_us: u64,
    pub latency: Option<LatencyReport>,
    pub round_trip_latency: Option<LatencyReport>,
    pub reflected_submitted_packets: u64,
    pub reflection_failed_packets: u64,
}

pub struct ProbeReceiver {
    source: PeerIdentity,
    id: [u8; 16],
    seen: Vec<u64>,
    largest: Option<u64>,
    first_received: Option<Instant>,
    report: ProbeReport,
    expires: Instant,
    reflect: bool,
    sent: Option<Vec<Option<(Instant, u64)>>>,
}

impl ProbeReceiver {
    pub fn new(request: ReceiveProbe) -> Result<Self, String> {
        let source =
            PeerIdentity::from_npub(&request.source).map_err(|_| "invalid probe source")?;
        let id = stream_id(&request.stream_id)?;
        validate_shape(request.packet_count, request.payload_bytes)?;
        Ok(Self {
            source,
            id,
            seen: vec![0; (request.packet_count as usize).div_ceil(64)],
            largest: None,
            first_received: None,
            expires: Instant::now() + RECEIVE_LIFETIME,
            reflect: request.reflect,
            sent: None,
            report: ProbeReport {
                source: source.npub(),
                stream_id: request.stream_id.to_ascii_lowercase(),
                expected_packets: request.packet_count,
                payload_bytes: request.payload_bytes,
                unique_packets: 0,
                unique_bytes: 0,
                missing_packets: u64::from(request.packet_count),
                duplicate_packets: 0,
                out_of_order_packets: 0,
                ignored_packets: 0,
                invalid_packets: 0,
                receive_span_us: 0,
                latency: request.measure_one_way_latency.then(LatencyReport::default),
                round_trip_latency: None,
                reflected_submitted_packets: 0,
                reflection_failed_packets: 0,
            },
        })
    }

    fn round_trip(request: &SendProbe) -> Result<Self, String> {
        let mut receiver = Self::new(ReceiveProbe {
            source: request.destination.clone(),
            stream_id: request.stream_id.clone(),
            packet_count: request.packet_count,
            payload_bytes: request.payload_bytes,
            measure_one_way_latency: false,
            reflect: false,
        })?;
        receiver.sent = Some(vec![None; request.packet_count as usize]);
        receiver.report.round_trip_latency = Some(LatencyReport::default());
        Ok(receiver)
    }

    /// Returns at most one same-size reply for an explicitly armed request.
    /// The authenticated source is supplied by the FIPS endpoint, not payload data.
    pub fn record(
        &mut self,
        source: PeerIdentity,
        payload: &[u8],
        received_us: u64,
    ) -> Option<Vec<u8>> {
        let magic = if self.sent.is_some() {
            REPLY_MAGIC
        } else {
            MAGIC
        };
        if source.pubkey() != self.source.pubkey()
            || payload.len() < HEADER
            || &payload[..8] != magic
            || Instant::now() >= self.expires
            || payload[8..24] != self.id
        {
            self.report.ignored_packets = self.report.ignored_packets.saturating_add(1);
            return None;
        }
        let sequence = u64::from_be_bytes(payload[24..32].try_into().unwrap());
        if sequence >= u64::from(self.report.expected_packets)
            || payload.len() != self.report.payload_bytes
            || payload[HEADER..].iter().any(|b| *b != 0x5a)
        {
            self.report.invalid_packets = self.report.invalid_packets.saturating_add(1);
            return None;
        }
        let round_trip_delay = if let Some(sent) = &self.sent {
            match sent[sequence as usize] {
                Some((started, stamp)) if payload[32..40] == stamp.to_be_bytes() => {
                    Some(started.elapsed().as_micros().try_into().unwrap_or(u64::MAX))
                }
                _ => {
                    self.report.invalid_packets = self.report.invalid_packets.saturating_add(1);
                    return None;
                }
            }
        } else {
            None
        };
        let word = sequence as usize / 64;
        let bit = 1u64 << (sequence % 64);
        if self.seen[word] & bit != 0 {
            self.report.duplicate_packets = self.report.duplicate_packets.saturating_add(1);
            return None;
        }
        self.seen[word] |= bit;
        if self.largest.is_some_and(|previous| sequence < previous) {
            self.report.out_of_order_packets += 1;
        }
        self.largest = Some(
            self.largest
                .map_or(sequence, |previous| previous.max(sequence)),
        );
        self.report.unique_packets += 1;
        self.report.unique_bytes += payload.len() as u64;
        self.report.missing_packets -= 1;
        self.report.receive_span_us = self
            .first_received
            .get_or_insert_with(Instant::now)
            .elapsed()
            .as_micros()
            .try_into()
            .unwrap_or(u64::MAX);
        if let Some(latency) = &mut self.report.latency {
            let sent = u64::from_be_bytes(payload[32..40].try_into().unwrap());
            if let Some(delay) = received_us
                .checked_sub(sent)
                .filter(|delay| *delay <= 60_000_000)
            {
                latency.record(delay);
            } else {
                latency.invalid_timestamps += 1;
            }
        }
        if let Some(delay) = round_trip_delay {
            self.report
                .round_trip_latency
                .as_mut()
                .unwrap()
                .record(delay);
        }
        self.reflect.then(|| {
            let mut reply = payload.to_vec();
            reply[..8].copy_from_slice(REPLY_MAGIC);
            reply
        })
    }

    pub fn report(&self) -> ProbeReport {
        self.report.clone()
    }
}

#[derive(Debug, Serialize)]
pub struct SendProbeReport {
    pub stream_id: String,
    pub requested_packets: u32,
    pub submitted_packets: u32,
    pub submitted_bytes: u64,
    pub elapsed_us: u64,
    pub stopped_reason: Option<String>,
}

pub(crate) type SharedReceiver = Arc<Mutex<Option<ProbeReceiver>>>;

/// Single receive-loop submission: no detached tasks, unbounded queues, or
/// payment capability. Enqueue success does not imply delivery or admission.
pub(crate) async fn reflect(
    endpoint: &FipsEndpoint,
    state: &SharedReceiver,
    source: PeerIdentity,
    payload: &[u8],
) {
    let reply = {
        let mut guard = state.lock().unwrap();
        guard.as_mut().and_then(|receiver| {
            receiver
                .record(source, payload, unix_micros())
                .map(|reply| (reply, receiver.expires))
        })
    };
    let Some((reply, expires)) = reply else {
        return;
    };
    let submitted = Instant::now() < expires
        && matches!(
            tokio::time::timeout_at(
                expires,
                endpoint.send_datagram(source, DATA_PORT, DATA_PORT, reply)
            )
            .await,
            Ok(Ok(()))
        );
    let mut guard = state.lock().unwrap();
    if let Some(receiver) = guard
        .as_mut()
        .filter(|receiver| receiver.expires == expires)
    {
        if submitted {
            receiver.report.reflected_submitted_packets += 1;
        } else {
            receiver.report.reflection_failed_packets += 1;
        }
    }
}

pub(crate) async fn send(
    endpoint: &FipsEndpoint,
    request: SendProbe,
    state: &SharedReceiver,
) -> Result<SendProbeReport, String> {
    request.validate()?;
    let remote =
        PeerIdentity::from_npub(&request.destination).map_err(|_| "invalid destination")?;
    let id = stream_id(&request.stream_id)?;
    if request.measure_round_trip {
        *state.lock().unwrap() = Some(ProbeReceiver::round_trip(&request)?);
    }
    let started = tokio::time::Instant::now();
    let deadline = started + MAX_DURATION;
    let mut report = SendProbeReport {
        stream_id: request.stream_id.to_ascii_lowercase(),
        requested_packets: request.packet_count,
        submitted_packets: 0,
        submitted_bytes: 0,
        elapsed_us: 0,
        stopped_reason: None,
    };
    while report.submitted_packets < request.packet_count {
        let sequence = report.submitted_packets;
        let due = started
            + Duration::from_nanos(
                u64::from(sequence) * 1_000_000_000 / u64::from(request.packets_per_second),
            );
        tokio::time::sleep_until(due).await;
        if tokio::time::Instant::now() >= deadline {
            report.stopped_reason = Some("duration limit reached".into());
            break;
        }
        // Keep a burst below one millisecond at high rates and one packet at
        // low rates, with a fixed maximum independent of the requested count.
        let batch_size = request
            .packets_per_second
            .div_ceil(1_000)
            .min(16)
            .min(request.packet_count - sequence);
        let datagrams = (sequence..sequence + batch_size)
            .map(|n| {
                let stamp = unix_micros();
                if request.measure_round_trip {
                    state
                        .lock()
                        .unwrap()
                        .as_mut()
                        .unwrap()
                        .sent
                        .as_mut()
                        .unwrap()[n as usize] = Some((Instant::now(), stamp));
                }
                FipsEndpointOutboundDatagram::new(
                    DATA_PORT,
                    DATA_PORT,
                    packet(id, u64::from(n), request.payload_bytes, stamp),
                )
            })
            .collect();
        if let Err(error) = endpoint
            .send_datagram_batch_to_peer(remote, datagrams)
            .await
        {
            if request.measure_round_trip {
                state
                    .lock()
                    .unwrap()
                    .as_mut()
                    .unwrap()
                    .sent
                    .as_mut()
                    .unwrap()[sequence as usize..(sequence + batch_size) as usize]
                    .fill(None);
            }
            report.stopped_reason = Some(error.to_string());
            break;
        }
        report.submitted_packets += batch_size;
        report.submitted_bytes += u64::from(batch_size) * request.payload_bytes as u64;
    }
    report.elapsed_us = started.elapsed().as_micros().try_into().unwrap_or(u64::MAX);
    Ok(report)
}

#[cfg(test)]
mod tests;
