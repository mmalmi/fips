//! Explicitly armed, fixed-duration TCP/FIPS byte checks on ordinary paid data.
//! Keep pumping after local completion so the other endpoint can recover lost ACKs.
use super::{bounded_duration, stream_id};
use fips_core::{FipsEndpoint, FipsEndpointError, Identity, PeerIdentity};
use fips_tcp::{Config, MarkerStatus, State};
use fips_tcp_endpoint::{AdapterError, FipsTcpEndpoint};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::{
    sync::watch,
    time::{Instant, MissedTickBehavior},
};

pub const PORT: u16 = 44_744;
const BUFFER: usize = 64 * 1024;
const CHUNK: usize = 4096;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StreamProbe {
    pub peer: String,
    pub stream_id: String,
    pub bytes: u64,
    pub bytes_per_second: u32,
    /// Includes connection setup, paced transfer and ACK drain. Both sides
    /// remain active until this bound, even after their local byte checks pass.
    pub duration_secs: u64,
    /// Exactly one endpoint initiates; the other only accepts the armed peer.
    pub connect: bool,
}

impl StreamProbe {
    pub fn validate(&self) -> Result<(), String> {
        PeerIdentity::from_npub(&self.peer).map_err(|_| "invalid stream probe peer")?;
        stream_id(&self.stream_id)?;
        bounded_duration(Some(self.duration_secs), 30, 300)?;
        if !(1..=64 * 1024 * 1024).contains(&self.bytes)
            || !(1..=16 * 1024 * 1024).contains(&self.bytes_per_second)
            || self.bytes > u64::from(self.bytes_per_second) * self.duration_secs
        {
            return Err("stream probe requires 1..64MiB at 1..16MiB/s within its duration".into());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct StreamReport {
    pub shape: StreamProbe,
    pub ready: bool,
    pub connected: bool,
    pub accepted_bytes: u64,
    pub received_bytes: u64,
    pub acknowledged_bytes: u64,
    pub received_sha256: String,
    pub partial_writes: u64,
    pub rejected_datagrams: u64,
    pub elapsed_us: u64,
    pub completed_us: Option<u64>,
    pub finished: bool,
    pub stopped_reason: Option<String>,
}

impl StreamReport {
    fn complete(&self) -> bool {
        self.accepted_bytes == self.shape.bytes
            && self.received_bytes == self.shape.bytes
            && self.acknowledged_bytes == self.shape.bytes
    }

    fn publish(&self, progress: &Mutex<Option<Self>>) {
        *progress.lock().unwrap() = Some(self.clone());
    }
}

/// One bounded duplex probe. No application prefix is offered again after TCP
/// accepts it; failed delivery stays failed when the adapter is dropped.
pub async fn run(
    endpoint: Arc<FipsEndpoint>,
    shape: StreamProbe,
    progress: &Mutex<Option<StreamReport>>,
    mut stop: watch::Receiver<bool>,
) -> Result<StreamReport, String> {
    shape.validate()?;
    let duration = Duration::from_secs(shape.duration_secs);
    let mut report = StreamReport {
        shape,
        ready: false,
        connected: false,
        accepted_bytes: 0,
        received_bytes: 0,
        acknowledged_bytes: 0,
        received_sha256: format!("{:x}", Sha256::digest([])),
        partial_writes: 0,
        rejected_datagrams: 0,
        elapsed_us: 0,
        completed_us: None,
        finished: false,
        stopped_reason: None,
    };
    report.publish(progress);
    let started = Instant::now();
    let result = tokio::select! {
        biased;
        _ = async {
            while !*stop.borrow_and_update() {
                if stop.changed().await.is_err() { break; }
            }
        } => Err("stream probe cancelled".to_owned()),
        _ = tokio::time::sleep_until(started + duration) => Ok(()),
        result = drive(endpoint, &mut report, progress, started) => result,
    };
    report.elapsed_us = started.elapsed().as_micros() as u64;
    report.finished = true;
    report.stopped_reason = result.err().or_else(|| {
        (!report.complete())
            .then(|| "stream probe deadline reached before exact delivery and ACK".into())
    });
    report.publish(progress);
    match &report.stopped_reason {
        Some(reason) => Err(reason.clone()),
        None => Ok(report),
    }
}

async fn bind(endpoint: Arc<FipsEndpoint>) -> Result<FipsTcpEndpoint, String> {
    let seed = u64::from_le_bytes(
        Identity::generate().node_addr().as_bytes()[..8]
            .try_into()
            .unwrap(),
    );
    let until = Instant::now() + Duration::from_secs(3);
    loop {
        let config = Config {
            send_buffer: BUFFER,
            max_connections: 1,
            max_connections_per_peer: 1,
            ..Config::default()
        };
        match FipsTcpEndpoint::bind(endpoint.clone(), PORT, config, seed).await {
            Ok(tcp) => return Ok(tcp),
            // The native maintenance tick removes a previous probe's closed
            // receiver. Only this transient registration state is retried.
            Err(AdapterError::Fips(FipsEndpointError::ServicePortAlreadyRegistered { .. }))
                if Instant::now() < until =>
            {
                tokio::time::sleep(Duration::from_millis(25)).await
            }
            Err(error) => return Err(error.to_string()),
        }
    }
}

fn fill(bytes: &mut [u8], offset: u64, id: &[u8; 16]) {
    for (index, byte) in bytes.iter_mut().enumerate() {
        let position = offset + index as u64;
        *byte = (position % 251) as u8 ^ id[(position % id.len() as u64) as usize];
    }
}

async fn drive(
    endpoint: Arc<FipsEndpoint>,
    report: &mut StreamReport,
    progress: &Mutex<Option<StreamReport>>,
    started: Instant,
) -> Result<(), String> {
    let peer =
        PeerIdentity::from_npub(&report.shape.peer).map_err(|_| "invalid stream probe peer")?;
    let id = stream_id(&report.shape.stream_id)?;
    let mut tcp = bind(endpoint).await?;
    report.ready = true;
    report.publish(progress);
    let mut connection = if report.shape.connect {
        Some(
            tcp.connect(peer, started.elapsed().as_millis() as u64)
                .await
                .map_err(|e| e.to_string())?,
        )
    } else {
        None
    };
    let mut ticker = tokio::time::interval(Duration::from_millis(10));
    ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);
    let mut connected_at = None;
    let mut marker = None;
    let mut digest = Sha256::new();
    let mut body = vec![0; CHUNK];
    loop {
        let now = started.elapsed().as_millis() as u64;
        tokio::select! {
            received = tcp.receive_report_filtered(now, |source| source.pubkey() == peer.pubkey()) => {
                report.rejected_datagrams += received.map_err(|e| e.to_string())?.rejected() as u64;
            }
            _ = ticker.tick() => tcp.poll(started.elapsed().as_millis() as u64).await.map_err(|e| e.to_string())?,
        }
        if connection.is_none() {
            connection = tcp.accept();
        }
        let Some(connection) = connection else {
            report.publish(progress);
            continue;
        };
        if tcp.state(connection) != Some(State::Established) {
            if report.connected {
                return Err("stream probe lost its original TCP connection".into());
            }
            continue;
        }
        if tcp.peer(connection).map(|identity| identity.pubkey()) != Some(peer.pubkey()) {
            return Err("stream probe accepted another peer".into());
        }
        report.connected = true;
        let pace_start = *connected_at.get_or_insert_with(Instant::now);
        let now = started.elapsed().as_millis() as u64;
        if let Some(ref marker) = marker {
            match tcp.marker_status(marker) {
                MarkerStatus::Acked => report.acknowledged_bytes = report.accepted_bytes,
                MarkerStatus::Pending => {}
                _ => return Err("stream probe lost its accepted-byte ACK boundary".into()),
            }
        }
        let due = (pace_start.elapsed().as_micros() * u128::from(report.shape.bytes_per_second)
            / 1_000_000)
            .min(u128::from(report.shape.bytes)) as u64;
        let offered = due.saturating_sub(report.accepted_bytes).min(CHUNK as u64) as usize;
        if offered > 0 {
            fill(&mut body[..offered], report.accepted_bytes, &id);
            let (accepted, boundary) = tcp
                .write_with_marker(connection, &body[..offered], now)
                .await
                .map_err(|e| e.to_string())?;
            report.partial_writes += u64::from(accepted < offered);
            report.accepted_bytes += accepted as u64;
            if accepted > 0 {
                marker = Some(boundary);
            }
        }
        let received = tcp
            .read(connection, CHUNK, now)
            .await
            .map_err(|e| e.to_string())?;
        if report.received_bytes + received.len() as u64 > report.shape.bytes {
            return Err("stream probe received extra application bytes".into());
        }
        fill(&mut body[..received.len()], report.received_bytes, &id);
        if received != body[..received.len()] {
            return Err("stream probe received different application bytes".into());
        }
        if !received.is_empty() {
            digest.update(&received);
            report.received_bytes += received.len() as u64;
            report.received_sha256 = format!("{:x}", digest.clone().finalize());
        }
        report.elapsed_us = started.elapsed().as_micros() as u64;
        if report.complete() && report.completed_us.is_none() {
            report.completed_us = Some(report.elapsed_us);
        }
        report.publish(progress);
    }
}
