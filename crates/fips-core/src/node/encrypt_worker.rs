//! Off-task FMP encrypt + UDP send worker.
//!
//! **Unix only** — the per-worker send loop issues direct
//! `sendmmsg(2)` / `sendmsg(2)+UDP_GSO` calls on raw file descriptors
//! via `AsRawFd`. On Windows the worker pool isn't spawned (see
//! `lifecycle.rs`) and the rx_loop's tokio-based send path remains
//! the canonical outbound route.
//!
//! The sender hot path of FIPS used to do every step of an outbound
//! packet — session lookup, FSP encrypt, datagram serialise, link
//! lookup, FMP encrypt, UDP `sendto` — sequentially on the single
//! `rx_loop` tokio task. At line rate that task pegs at 99.9% CPU on
//! one core while five other tokio workers sit at 6–40% each. The
//! send pipeline's measured cost breakdown (FIPS_PERF stats on AMD
//! Ryzen 7 7700, single-stream TCP at ~91 kpps):
//!
//! ```text
//! endpoint_send  ≈ 2170 ns/pkt   (whole handle_endpoint_data_command)
//!   fsp_encrypt  ≈  550 ns/pkt
//!   fmp_encrypt  ≈  550 ns/pkt
//!   udp_send     ≈  150 ns/pkt   (amortised sendmmsg)
//!   "other"      ≈  920 ns/pkt   (dispatch + state ops)
//! ```
//!
//! The two AEADs + the syscall are pure CPU work that can run on
//! another core; only the "other" 920 ns is genuinely serial because
//! it mutates per-session / per-peer state. Splitting the pipeline at
//! the FMP layer hands the rx_loop ~700 ns back per packet — at
//! 100 kpps that's ~70 ms/s of one core, which is exactly what we
//! need to unstick the single-task bottleneck.
//!
//! The worker takes a pre-cooked [`FmpSendJob`] (pre-reserved counter,
//! a fully-built wire buffer `[16-byte FMP header][inner plaintext]`
//! with TAG_SIZE trailing capacity, a cloned cipher, an `AsyncUdpSocket`
//! handle, and the destination `SocketAddr`) and does the AEAD
//! `seal_in_place_separate_tag` + a single `sendmsg(2) + UDP_SEGMENT`
//! (Linux GSO) or `sendmmsg(2)` fallback. It never touches `Node`
//! state, so any number of these can run in parallel against the same
//! peer.
//!
//! **UDP_GSO note** — the GSO path is verified end-to-end via a
//! loopback round-trip unit test (see `tests::gso_roundtrip_loopback`).
//! On a docker veth/bridge the perf gain from GSO is muted because the
//! kernel does software segmentation on egress and the veth peer-skb
//! cost dominates; on a real NIC (or `--network=host` benches) the
//! single skb walk through the TX stack lands the expected win.

// On Windows nothing inside this module is called (the pool isn't
// spawned in lifecycle::start). Silence the cascade of dead-code
// warnings rather than gate every function individually.
#![cfg_attr(not(unix), allow(dead_code))]

include!("encrypt_worker/send_batch.rs");
include!("encrypt_worker/queues.rs");
include!("encrypt_worker/pool_macos.rs");
include!("encrypt_worker/worker_flush.rs");
include!("encrypt_worker/backpressure_linux.rs");
include!("encrypt_worker/unix_tests.rs");
include!("encrypt_worker/mac_queue_tests.rs");

#[cfg(all(test, unix, not(target_os = "macos")))]
mod fair_queue_tests {
    use super::*;

    include!("encrypt_worker/fair_queue_tests/core.rs");
    include!("encrypt_worker/fair_queue_tests/dispatch.rs");
}

include!("encrypt_worker/linux_tests.rs");
include!("encrypt_worker/unix_raw_send.rs");
