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

## Status (2026-05-11)

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

* **Step 5 (bca3230)** — `Node.peers` field type flipped to
  `HashMap<NodeAddr, ActivePeerSlot>` where
  `ActivePeerSlot = Arc<RwLock<ActivePeer>>`. New `peer_read(slot)`
  / `peer_write(slot)` helpers in `crates/fips-core/src/peer/mod.rs`.
  All ~200 call sites migrated:
  - hot-path sites (encrypted.rs, mmp.rs, etc.) take `peer_read`
    (after step 4 the receive path mutations are all `&self`-callable
    via interior mutability, so multiple readers can coexist with no
    write contention)
  - cold-path sites (handshake.rs, rekey.rs, tree.rs, bloom.rs, etc.)
    take `peer_write` for the residual `&mut self` ActivePeer methods
  - public Node API (`get_peer` / `get_peer_mut` / `peers()` /
    `remove_peer`) returns guards or slots; `find_next_hop` returns
    `Option<NodeAddr>` (callers already used the address only)
  Bench (TCP single stream, 20s): 1551 / 1556 / 1555 Mbps — slightly
  *better* than the ~1530 pre-step-5 baseline. The 25 file diff is
  large but mechanical; the borrow-extension pitfall noted in the
  earlier "Pitfalls" section was hit several times and worked around
  with scoped guard blocks.

* **Step 6 (f11b6a8)** — Per-peer actor task. New `crate::peer::actor`
  module defines `PeerActorHandle` and a per-peer task body that
  consumes `PeerInboundJob::Decrypted` items from an mpsc inbox.
  `promote_connection` spawns the task (via
  `PeerActorHandle::spawn(...)`) and stores the handle on
  `ActivePeer`. After FMP decrypt, the rx_loop hands the per-peer
  state mutations off via the actor inbox; the actor pushes the
  link-message body back through a shared
  `peer_link_dispatch` channel so the rx_loop's central dispatch
  arm can run `dispatch_link_message` (which still needs
  `&mut Node`). Gated by `node.peer_actor_enabled` (default
  `false`) — tests stay on the legacy inline path because the
  actor's two extra channel hops trip timing-sensitive fixtures
  (spanning-tree convergence, etc.). Bench A/B is flat at this
  step (~1500 Mbps both modes) — the actor only relieves a few
  hundred ns/pkt of per-peer mutations; the dispatch chain
  (FSP decrypt + handle_session_datagram + TUN write) is still
  on the rx_loop. Step 7+ moves that.

* **Step 7a (7b63904)** — `Node.sessions` field type flipped to
  `HashMap<NodeAddr, SessionEntrySlot>` where
  `SessionEntrySlot = Arc<RwLock<SessionEntry>>`. New helpers
  `session_entry_slot(entry)` / `session_read(slot)` /
  `session_write(slot)` in `crate::node::session`. All ~150 call
  sites in handlers (session, rekey, mmp, timeout, dispatch,
  discovery), control queries, and tests migrated.

  Hot-path callers take `session_read(slot)` for `&self` access;
  mutation paths clone the slot then take `session_write(&slot)` so
  the borrow on `self.sessions` is released before re-borrowing
  `&mut self` for downstream sends. Several handlers had to be
  restructured to avoid holding a guard across `.await`
  (RwLockWriteGuard is not Send): `handle_session_setup` now
  snapshots the existing entry's state into a local enum, drops
  the read guard, then drives the rekey / re-establishment path.

  Tests: 1092 passed, 0 failed. Step 7a only flips the storage
  type; FSP decrypt + dispatch is still on the rx_loop.

* **Step 7b-1 (1fa33b8)** — `consecutive_decrypt_failures` → `AtomicU32`,
  `mmp` → `Option<Mutex<MmpSessionState>>`. After this all per-packet
  receive-side mutations on `SessionEntry` are `&self`-callable.
* **Step 7b-2 (6fb2f8c)** — `handle_encrypted_session_msg` hot path now
  runs from a read lock on `SessionEntrySlot`. K-bit flip is hoisted
  into a separate cold-path block that takes a write lock on its rare
  path. `state()` is no longer `#[cfg(test)]`-gated.
* **Step 7b-3 (84f13fe)** — single Arc clone + read-lock acquisition per
  packet (was two — one for K-bit detect, one for hot path).

  Bench (TCP single stream, 20s, 2-node Docker, peer_actor=disabled):
  ~1459 Mbps — within noise of pre-step-7 baseline. With
  peer_actor=enabled ~1342 Mbps — a ~10% regression from the actor's
  channel-hop overhead, since the dispatch chain (FSP decrypt + TUN
  write) is still on the rx_loop and the actor's channel work now adds
  net latency without offloading useful work. Step 7c is what makes
  the actor-enabled path pay off.

#### Step 7c — pure channel-based actor for FSP decrypt (next, no Arc<RwLock>)

After step 7a/7b the FSP receive path *can* run from a read lock on
`Arc<RwLock<SessionEntry>>`, but the lock + atomic + mutex overhead is
visible at line rate (~5% regression observed). And philosophically,
adding more `Arc<RwLock<…>>` to thread state into the actor pushes us
further into shared-state-with-locks territory rather than the
wireguard-go-style "owned by one task, message-passed" model the
proposal opens with.

7c pivots: drop the `Arc<RwLock<SessionEntry>>` layer and have the peer
actor *own* `Option<SessionEntry>` directly. Lifecycle is driven by
channel messages:

```rust
pub enum PeerInboundJob {
    Packet(ReceivedPacket),                 // raw packet, actor does FMP
    TakeSession(Box<SessionEntry>),         // Node hands ownership over
    RemoveSession,                          // Node tells actor to drop
    Decrypted(Box<DecryptedJob>),           // legacy step-6 path (kept
                                            // until 7c migration is done)
}

pub enum PeerOutboundEvent {
    SessionStatsSnapshot {                  // periodic push for control
        last_activity_ms: u64,              // queries / idle timeout /
        traffic_counters: (u64, u64, u64, u64),
        ...
    },
    DecryptFailureThresholdExceeded {       // ask Node to re-init session
        remote_pubkey: PublicKey,
    },
    NeedsCentralDispatch(PeerLinkDispatch), // current step-6 path,
                                            // for non-data-fast-path msgs
}
```

The hot path stays *fully inside* one actor task: receive raw packet →
FMP decrypt with owned `ActivePeer` → if SessionDatagram-for-me with
`msg_type == DataPacket`, FSP decrypt with owned `SessionEntry` → IPv6
shim decompress → `tun_tx.send(...)`. No locks, no Arc, no channel hops
back to rx_loop on the data plane.

Cold paths (handshake setup/ack/msg3, rekey msg1/2/3 + cutover, idle
purge, MMP report send, control queries that read session state) stay
on the rx_loop with `&mut Node`, but interact with peer actors purely
via `PeerInboundJob` messages. Sessions live in exactly one place at
any moment: either in `Node.sessions` (during handshake / rekey
transient state) or in the peer actor (Established).

For mesh forwarding cases where this node is transit (no FSP keys
held), no session ownership is involved — the actor just emits
`NeedsCentralDispatch` for the SessionDatagram and rx_loop routes it
onward as today. For sessions where `session.remote_addr` isn't also a
direct peer (rare 3+-hop case where we're an endpoint), the session
stays in `Node.sessions` and falls back to the legacy path.

This sequence keeps step 7a/7b's groundwork (helpers, atomic counters,
Mutex MMP) — the pieces that make `&self` receive callable still apply
once the entry moves into the actor. We just stop wrapping it in
`Arc<RwLock<…>>` for sharing.

### Remaining

#### Step 5 — Move peers behind `Arc<RwLock<ActivePeer>>` (DONE — bca3230)

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
