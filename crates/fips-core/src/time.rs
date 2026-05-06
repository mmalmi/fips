//! Time helpers used by protocol state machines.
//!
//! Normal builds use wall-clock Unix time. The in-process sim transport uses a
//! Tokio-clock anchor so paused-time simulations can advance discovery,
//! retransmit, and timeout state without waiting on wall time.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

#[cfg(feature = "sim-transport")]
use std::sync::OnceLock;

#[cfg(not(feature = "sim-transport"))]
pub(crate) type Instant = std::time::Instant;

#[cfg(feature = "sim-transport")]
pub(crate) type Instant = tokio::time::Instant;

#[cfg(feature = "sim-transport")]
struct ClockAnchor {
    started_at: Instant,
    started_unix_ms: u64,
}

pub(crate) fn instant_now() -> Instant {
    Instant::now()
}

pub(crate) fn now_ms() -> u64 {
    #[cfg(feature = "sim-transport")]
    {
        static ANCHOR: OnceLock<ClockAnchor> = OnceLock::new();
        let anchor = ANCHOR.get_or_init(|| ClockAnchor {
            started_at: instant_now(),
            started_unix_ms: wall_now_ms(),
        });
        let elapsed_ms = instant_now()
            .duration_since(anchor.started_at)
            .as_millis()
            .min(u128::from(u64::MAX)) as u64;
        anchor.started_unix_ms.saturating_add(elapsed_ms)
    }

    #[cfg(not(feature = "sim-transport"))]
    {
        wall_now_ms()
    }
}

pub(crate) fn now_secs() -> u64 {
    now_ms() / 1_000
}

fn wall_now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_millis()
        .min(u128::from(u64::MAX)) as u64
}
