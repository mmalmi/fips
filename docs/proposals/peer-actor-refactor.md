# Peer-actor refactor (in progress)

## Goal

Move per-packet receive-side work off the rx_loop's single thread by
giving each peer its own task — wireguard-go's
`RoutineSequentialReceiver` pattern. Today the rx_loop is single-
threaded and pegged at 99.9% on one core during bench runs, which
caps single-stream TCP throughput around ~1.5 Gbps on Apple Silicon
Docker. The architectural endpoint is:

```
[1 receive routine]    drains UDP, parses common prefix, dispatches
       │
       ▼
[N AEAD workers]       run FMP `open()` (and optionally FSP) in
       │               parallel; pure functions over Arc<LessSafeKey>
       ▼
[1 sequential receiver per peer]   replay accept, MMP record, link
                                   stats, dispatch, TUN write —
                                   owns the per-peer state
```

Inspired directly by `~/src/wireguard-go/device/{receive.go,peer.go}`.
The wg-go code is the reference implementation worth re-reading
before each step.

## Status (2026-05-10)

### Done

* **Step 1 (3f36532)** — `LinkStats` counters atomicized.
  `record_recv` / `record_sent` take `&self` via `AtomicU64::fetch_add`.
* **Step 2 (ba98b06)** — `NoiseSession::replay_window` under
  `std::sync::Mutex`. `decrypt_with_replay_check[_and_aad]`,
  `check_replay`, `accept_replay`, `reset_replay_window`,
  `highest_received_counter` all take `&self`. The AEAD `open` round
  runs *outside* the lock.
* **Step 3 (3200839)** — `consecutive_decrypt_failures` and
  `replay_suppressed_count` → `AtomicU32`. Increment / reset / read
  through `&self`.
* **Step 4a (4cc80fe)** — `last_seen` → `AtomicU64`, `connectivity` →
  `AtomicU8` (+ `repr(u8)` on `ConnectivityState` and a `from_u8`
  decoder). `touch`, `mark_*`, `idle_time` all `&self`.
* **Step 4b (ea8f2a4)** — `transport_id` and `current_addr` bundled
  into one `Mutex<Option<(TransportId, TransportAddr)>>`. `transport_id`,
  `current_addr` (cloned), `transport_pair`, `set_current_addr` all `&self`.
* **Step 4c (e35b8be)** — `mmp` field wrapped in
  `Option<Mutex<MmpPeerState>>`. `mmp()` / `mmp_mut()` return
  `Option<MutexGuard<'_, MmpPeerState>>`, both `&self`. The
  `handle_receiver_report` path was restructured to drop the mmp
  guard before re-borrowing `self.peers` for the first-RTT parent
  eval.

After step 4c, **every per-packet mutation that the FMP receive
fast path runs is `&self`-callable**: LinkStats counters, replay
window, decrypt/replay-suppressed counters, last_seen / connectivity,
transport_id / current_addr, MMP receiver+spin_bit. ActivePeer is
"interior-mutable for the entire receive hot path."

Bench check after step 4c (TCP single stream, 20s, 2-node Docker):
1506 / 1529 / 1516 Mbps — flat with the pre-refactor baseline
(~1530 mean), confirming no regression. The performance win still
requires the rest of the refactor (steps 5+) — the rx_loop is still
the only task doing the receive work.

### Remaining

#### Step 5 — Move peers behind `Arc<RwLock<ActivePeer>>`

```rust
// Today:
peers: HashMap<NodeAddr, ActivePeer>,

// Target:
peers: HashMap<NodeAddr, Arc<RwLock<ActivePeer>>>,
```

* Hot-path call sites (everything that's `&self` on ActivePeer after
  step 4) take `peer.read()` and call methods through the read
  guard. Multiple readers are fine.
* Cold-path call sites that still need `&mut ActivePeer` (handshake
  rekey, tree/bloom updates, `set_link_id`, etc.) take `peer.write()`.
  In production these are rare (timer ticks, handshake completions),
  so write contention against many concurrent readers is low.
* `self.peers.get(&addr)` → `self.peers.get(&addr).map(|p| p.read())`
* `self.peers.get_mut(&addr)` → `self.peers.get(&addr).map(|p| p.write())`
* Iteration: `self.peers.iter()` returning `(&NodeAddr, &Arc<...>)`,
  caller pulls `.read()` / `.write()` per peer.
* The HashMap itself (insert/remove) still goes through `&mut Node`
  on the rx_loop's existing `&mut self`.

This is mechanically large — hundreds of call sites. The recommended
sequence is:

  5a. Add `Arc<RwLock<>>` wrapper. Keep getter methods on Node that
      return guards to ease migration: `fn peer(&self, addr) -> Option<RwLockReadGuard<ActivePeer>>` etc.
  5b. Migrate the rx_loop hot path (`handle_encrypted_frame`,
      `apply_decrypted_elem`, `handle_session_datagram`, ...) first.
  5c. Migrate handlers: handshake, mmp, dispatch, forwarding, rekey, etc.
  5d. Migrate timer/tick handlers: `check_link_heartbeats`,
      `check_mmp_reports`, `purge_idle_*`, etc.
  5e. Migrate control queries.
  5f. Migrate stats history / snapshots.

After this step, peers can be cloned-Arc-passed to other tasks
(step 6).

#### Step 6 — Spawn per-peer actor task

For each peer, on establishment, spawn a `tokio::spawn` task:

```rust
async fn peer_inbound_task(
    peer: Arc<RwLock<ActivePeer>>,
    mut inbound_rx: mpsc::Receiver<InboundJob>,
    shared: Arc<SharedNodeState>,
) {
    while let Some(job) = inbound_rx.recv().await {
        // Decrypted FMP frame → dispatch link message + write to TUN.
        // Writes to peer state through peer.read() / peer.write().
    }
}
```

`InboundJob` carries the FMP-decrypted plaintext (or pre-decrypted
elem from the AEAD pool). The rx_loop's role becomes:

```
rx_loop:
  drain UDP → classify → dispatch to peer's inbound_tx
```

`SharedNodeState` is an `Arc<RwLock<...>>` (or per-shard `Arc<DashMap>`)
holding state the peer task needs to reach but doesn't own:

* `sessions: HashMap<NodeAddr, SessionEntry>` — for FSP-decrypt
  lookups (until step 7)
* `coord_cache`, `tree_state`, `bloom_state` — read-mostly during
  packet processing
* `transports: HashMap<TransportId, TransportHandle>` — for forwarding
* `tun_tx`, `endpoint_event_tx` — for delivering plaintext

Concurrency wins from this step:

* For 1 peer (our 2-node bench): the peer task runs on a different
  core from the rx_loop; the rx_loop only does UDP drain + classify.
  Estimated ~2× single-stream throughput gain.
* For N peers in a real mesh: each peer task on its own core, scaling
  linearly up to CPU count.

#### Step 7 — Per-session FSP actor (or fold into peer task)

`SessionEntry` plays the same role for end-to-end (FSP) sessions as
`ActivePeer` plays for link-layer (FMP) state. Same atomicization +
Arc wrapping treatment. For our 2-node case where each peer has at
most one session, a session can live inside its peer's task. For
mesh forwarding (peer A → peer B's session via a transit node), the
session needs its own task or shared state.

#### Step 8 — Re-enable batched AEAD worker pool

The experimental `aead_pool` from the parallel-decrypt branch
(htree://self/fips@parallel-decrypt) had a negative result on its
own — the pool's overhead exceeded the AEAD savings because the
rx_loop was bottlenecked on dispatch work, not AEAD work. After
step 6 the rx_loop is thin; the AEAD pool then has a fast peer
task to deliver to and the architecture matches wireguard-go.

* Workers receive `Vec<AeadInboundElem>` containers (not single
  packets) — preserves recvmmsg's batch advantage through the queue.
* On completion the worker Unlock()s the container; the per-peer
  receiver Lock()s it (waits if the worker is still running) and
  drains. Mirrors wireguard-go's `QueueInboundElementsContainer`
  + Mutex pattern.

#### Step 9 — Bench end-to-end

* TCP single stream — expect ~3-5 Gbps single-peer (was 1.5).
* UDP receiver ceiling — expect 3-4 Gbps (was 1.3).
* Multi-peer — should scale ~linearly with CPU count.
* Compare against boringtun-`--threads=4` (3.2 Gbps single-stream
  baseline that the architecture was originally measured against).

## Pitfalls observed during the work

* **MutexGuard borrow extension** — when `peer.mmp_mut()` returns a
  guard, the guard transitively borrows `self.peers`, so the same
  function can't re-borrow `self.peers.iter()` while the guard is
  alive. Fix: scope the guard inside a block that returns extracted
  data; drop the guard; then re-borrow. See `handle_receiver_report`
  for the canonical pattern.
* **Arc<RwLock<T>>'s read guard is `&T`, not `&mut`** — methods
  reachable through read() can only be `&self`. After step 4 every
  receive-hot-path method on ActivePeer is `&self`, so the read
  guard suffices. Verify each new mutator gets a write() before
  calling.
* **Don't confuse ActivePeer's MMP with SessionEntry's MMP** —
  different types (`MmpPeerState` vs `MmpSessionState`), different
  call sites. Step 4c only addressed peer-MMP; session-MMP gets the
  same treatment in step 7.
