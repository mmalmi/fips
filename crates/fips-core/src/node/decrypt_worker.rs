//! Off-task FMP + FSP decrypt + delivery worker.
//!
//! Incremental data-plane shard restructure: each worker owns its hot receive
//! state directly in local `HashMap`s, with no `Arc<RwLock<HashMap>>` cache on
//! the Node side and no `Arc<Mutex<ReplayWindow>>` shared with the rx_loop.
//! FMP state is keyed by the link receiver session; local established FSP
//! state is keyed by the end-to-end source peer so path drift does not split
//! replay ownership.
//!
//! Dispatch is **deterministic by registered owner**: before a session is
//! registered the rx_loop falls back to the session-key hash; once
//! `RegisterSession` is queued, per-packet jobs and unregisters use that
//! explicit owner. FMP and local FSP receive ownership are source-affine by
//! default so path drift does not split replay ownership.
//!
//! Worker messages travel through two bounded per-worker lanes:
//!
//! - **`RegisterSession`** — sent when an FMP session is promoted or
//!   rekeyed. Hands the worker an owned snapshot of the recv cipher,
//!   replay window, and authenticated source peer for the FMP layer.
//!   It uses the priority lane.
//! - **`Job`** — per-packet FMP decrypt. Large packets use the bulk lane;
//!   small control-shaped packets use the priority lane so
//!   heartbeats/MMP/rekey-sized traffic is not trapped behind a full bulk
//!   queue. Local established FSP session datagrams are handed to the FSP
//!   owner shard; other link messages fall back to the rx loop.
//! - **`UnregisterSession`** — sent on rekey / peer drop so the worker
//!   releases the owned cipher + replay state. It uses the priority
//!   lane.
//!
//! Direct-hop FSP data no longer carries payload bytes back through rx_loop:
//! the worker authenticates, admits replay, queues a compact receive commit to
//! rx_loop, then delivers the already-decoded payload to the configured TUN or
//! external packet sink once that commit is accepted. Transit-delivered data
//! still returns to rx_loop so reverse-route learning happens before local
//! delivery.
//!
//! This is the FIPS equivalent of WireGuard-go's packet mover shape: packets
//! are grouped by the peer/session owner, FSP bulk AEAD opening may happen on
//! opener workers, and every FSP completion returns through the source-peer
//! ordered owner before replay acceptance or TUN/endpoint delivery. Returned
//! open-worker completions are observable pressure events, not alternate replay
//! owners.

// **Unix only at the call sites.** On Windows nothing constructs an
// `OwnedSessionState` or spawns the pool (see `lifecycle.rs`), so
// every field + function in here becomes dead. Silence the warnings
// rather than gate them individually.
#![cfg_attr(not(unix), allow(dead_code))]

include!("decrypt_worker/core.rs");
include!("decrypt_worker/fallback_channels.rs");
include!("decrypt_worker/queue.rs");
include!("decrypt_worker/pool.rs");
include!("decrypt_worker/runtime.rs");
include!("decrypt_worker/return_batch.rs");
include!("decrypt_worker/shard.rs");

#[cfg(test)]
mod tests {
    include!("decrypt_worker/tests/support.rs");
    include!("decrypt_worker/tests/fsp_delivery.rs");
    include!("decrypt_worker/tests/fallback_queue.rs");
    include!("decrypt_worker/tests/direct_endpoint.rs");
    include!("decrypt_worker/tests/replay_failures.rs");
}
