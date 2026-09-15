//! Bounded operator traffic measurements at the local diagnostic service.
//! These records never authorize payments and never generate replies.

use fips_core::{FipsEndpoint, FipsEndpointOutboundDatagram, PeerIdentity};
use serde::{Deserialize, Serialize};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const MAGIC: &[u8; 8] = b"FIPSPRB1";
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
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SendProbe {
    pub destination: String,
    pub stream_id: String,
    pub packet_count: u32,
    pub payload_bytes: usize,
    pub packets_per_second: u32,
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
}

pub struct ProbeReceiver {
    source: PeerIdentity,
    id: [u8; 16],
    seen: Vec<u64>,
    largest: Option<u64>,
    first_received: Option<Instant>,
    report: ProbeReport,
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
            },
        })
    }

    pub fn record(&mut self, source: PeerIdentity, payload: &[u8], received_us: u64) {
        if source.pubkey() != self.source.pubkey()
            || payload.len() < HEADER
            || &payload[..8] != MAGIC
            || payload[8..24] != self.id
        {
            self.report.ignored_packets = self.report.ignored_packets.saturating_add(1);
            return;
        }
        let sequence = u64::from_be_bytes(payload[24..32].try_into().unwrap());
        if sequence >= u64::from(self.report.expected_packets)
            || payload.len() != self.report.payload_bytes
            || payload[HEADER..].iter().any(|b| *b != 0x5a)
        {
            self.report.invalid_packets = self.report.invalid_packets.saturating_add(1);
            return;
        }
        let word = sequence as usize / 64;
        let bit = 1u64 << (sequence % 64);
        if self.seen[word] & bit != 0 {
            self.report.duplicate_packets = self.report.duplicate_packets.saturating_add(1);
            return;
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
                latency.samples += 1;
                latency.sum_us += delay;
                latency.min_us = Some(latency.min_us.map_or(delay, |old| old.min(delay)));
                latency.max_us = Some(latency.max_us.map_or(delay, |old| old.max(delay)));
                let bucket = LATENCY_BOUNDS_US.partition_point(|bound| *bound < delay);
                latency.bucket_counts[bucket] += 1;
            } else {
                latency.invalid_timestamps += 1;
            }
        }
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

pub async fn send(endpoint: &FipsEndpoint, request: SendProbe) -> Result<SendProbeReport, String> {
    request.validate()?;
    let remote =
        PeerIdentity::from_npub(&request.destination).map_err(|_| "invalid destination")?;
    let id = stream_id(&request.stream_id)?;
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
                FipsEndpointOutboundDatagram::new(
                    DATA_PORT,
                    DATA_PORT,
                    packet(id, u64::from(n), request.payload_bytes, unix_micros()),
                )
            })
            .collect();
        if let Err(error) = endpoint
            .send_datagram_batch_to_peer(remote, datagrams)
            .await
        {
            report.stopped_reason = Some(error.to_string());
            break;
        }
        report.submitted_packets += batch_size;
        report.submitted_bytes += u64::from(batch_size) * request.payload_bytes as u64;
    }
    report.elapsed_us = started.elapsed().as_micros().try_into().unwrap_or(u64::MAX);
    Ok(report)
}
