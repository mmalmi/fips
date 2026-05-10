//! Runtime perf profiler for the FMP/FSP hot path.
//!
//! Avoids external dependencies (`perf`, samply, etc.) by instrumenting
//! the key stages directly with `AtomicU64` ns counters and packet
//! counts. A background task prints a per-stage breakdown every
//! `FIPS_PERF_INTERVAL_SECS` seconds when `FIPS_PERF=1` is set.
//!
//! Enabling adds a single `Instant::now()` + `fetch_add` per stage
//! per packet (~25ns each), so the measured numbers are slightly
//! pessimistic vs production — but the *relative* picture (which
//! stage dominates) is accurate enough to drive design decisions.
//!
//! Stages tracked, inbound:
//!   * `UDP_RECV` — recvmmsg syscall + per-message buffer copy
//!   * `FMP_DECRYPT` — outer AEAD open + replay window
//!   * `LINK_DISPATCH` — `dispatch_link_message` excluding FSP work
//!   * `FSP_DECRYPT` — inner AEAD open + replay window
//!   * `TUN_WRITE` — IPv6 shim decompress + tun_tx.send
//!
//! Stages tracked, outbound:
//!   * `FSP_ENCRYPT` — inner AEAD seal (`send_session_data`)
//!   * `FMP_ENCRYPT` — outer AEAD seal (`send_encrypted_link_message`)
//!   * `UDP_SEND` — sendmmsg flush

use std::sync::atomic::{AtomicU64, Ordering::Relaxed};
use std::time::Instant;

/// Number of measurement buckets. Indices match `Stage`.
const N_STAGES: usize = 8;

/// Stage identifier. `as usize` indexes into the counter arrays.
#[derive(Copy, Clone, Debug)]
#[repr(usize)]
pub enum Stage {
    UdpRecv = 0,
    FmpDecrypt = 1,
    LinkDispatch = 2,
    FspDecrypt = 3,
    TunWrite = 4,
    FspEncrypt = 5,
    FmpEncrypt = 6,
    UdpSend = 7,
}

impl Stage {
    const fn name(self) -> &'static str {
        match self {
            Stage::UdpRecv => "udp_recv",
            Stage::FmpDecrypt => "fmp_decrypt",
            Stage::LinkDispatch => "link_dispatch",
            Stage::FspDecrypt => "fsp_decrypt",
            Stage::TunWrite => "tun_write",
            Stage::FspEncrypt => "fsp_encrypt",
            Stage::FmpEncrypt => "fmp_encrypt",
            Stage::UdpSend => "udp_send",
        }
    }
}

static TOTAL_NS: [AtomicU64; N_STAGES] = [
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
];

static COUNT: [AtomicU64; N_STAGES] = [
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
];

/// True iff `FIPS_PERF=1` is set. Read once at startup so the
/// per-packet check is a single relaxed atomic load.
fn enabled() -> bool {
    static ENABLED: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ENABLED.get_or_init(|| {
        std::env::var("FIPS_PERF")
            .map(|s| s == "1" || s.eq_ignore_ascii_case("true"))
            .unwrap_or(false)
    })
}

/// Record `elapsed_ns` for the given stage. No-op when disabled.
pub fn record(stage: Stage, elapsed_ns: u64) {
    if !enabled() {
        return;
    }
    let idx = stage as usize;
    TOTAL_NS[idx].fetch_add(elapsed_ns, Relaxed);
    COUNT[idx].fetch_add(1, Relaxed);
}

/// RAII timer — `drop` records the elapsed time into the stage.
/// Use:
/// ```ignore
/// let _t = profile::Timer::start(Stage::FmpDecrypt);
/// // ... AEAD work ...
/// ```
pub struct Timer {
    stage: Stage,
    start: Option<Instant>,
}

impl Timer {
    #[inline]
    pub fn start(stage: Stage) -> Self {
        let start = if enabled() {
            Some(Instant::now())
        } else {
            None
        };
        Self { stage, start }
    }
}

impl Drop for Timer {
    fn drop(&mut self) {
        if let Some(t0) = self.start {
            let ns = t0.elapsed().as_nanos() as u64;
            record(self.stage, ns);
        }
    }
}

/// Spawn a background task that prints a per-stage breakdown every
/// `FIPS_PERF_INTERVAL_SECS` seconds (default 5). Idempotent — only
/// the first call spawns. No-op when `FIPS_PERF` isn't set.
pub fn maybe_spawn_reporter() {
    if !enabled() {
        return;
    }
    static STARTED: std::sync::OnceLock<()> = std::sync::OnceLock::new();
    if STARTED.set(()).is_err() {
        return;
    }
    let interval = std::env::var("FIPS_PERF_INTERVAL_SECS")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(5)
        .max(1);
    tokio::spawn(async move {
        let mut prev_total = [0u64; N_STAGES];
        let mut prev_count = [0u64; N_STAGES];
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(interval)).await;
            let mut line = format!("[perf {}s]", interval);
            for i in 0..N_STAGES {
                let t = TOTAL_NS[i].load(Relaxed);
                let c = COUNT[i].load(Relaxed);
                let dt = t.saturating_sub(prev_total[i]);
                let dc = c.saturating_sub(prev_count[i]);
                prev_total[i] = t;
                prev_count[i] = c;
                let stage = match i {
                    0 => Stage::UdpRecv,
                    1 => Stage::FmpDecrypt,
                    2 => Stage::LinkDispatch,
                    3 => Stage::FspDecrypt,
                    4 => Stage::TunWrite,
                    5 => Stage::FspEncrypt,
                    6 => Stage::FmpEncrypt,
                    7 => Stage::UdpSend,
                    _ => unreachable!(),
                };
                let avg_ns = if dc > 0 { dt / dc } else { 0 };
                let pps = if interval > 0 { dc / interval } else { 0 };
                line.push_str(&format!(
                    " {}={}ns×{}/s",
                    stage.name(),
                    avg_ns,
                    pps,
                ));
            }
            // eprintln so it always lands regardless of RUST_LOG.
            eprintln!("{}", line);
        }
    });
}
