# FIPS Experiments

## 2026-05-14 - macOS Wi-Fi sender burst pacing

- Observation: after the daemon bookkeeping stall was fixed, MacBook-to-mini
  TCP still lagged behind Tailscale and could collapse badly in some windows.
  An instrumented 20 second run showed about 37 Mbit/s with 1194 retransmits.
- Correlation: `FIPS_PERF=1` showed crypto was not the bottleneck. The sender
  had multi-millisecond `fmp_worker_queue_wait` intervals and occasional
  hundred-millisecond `udp_send` outliers, while the receiver path was mostly
  clean. The shape pointed at Darwin UDP burst pacing/queueing on the Wi-Fi
  sender, not AEAD cost or MTU.
- A/B: with connected UDP enabled and no perf logging, 20 second forward runs
  were in the same band for small batches: batch 8 about 215 Mbit/s, batch 32
  about 214 Mbit/s, and batch 2 about 210 Mbit/s in the final same-window sweep.
  Earlier in the same session batch 1-2 recovered a collapsed 37 Mbit/s run to
  roughly 219-237 Mbit/s, so the safe conclusion is "avoid large Darwin bursts",
  not "one exact batch value is universally best".
- Connected UDP remained important: disabling it with the same batch setting
  fell to about 149 Mbit/s. Ordered-sender mode stayed around 218 Mbit/s with
  more retransmits. `SO_NET_SERVICE_TYPE=rd/vi` was inconclusive and remains
  opt-in.
- Fix: lower the compiled macOS direct-worker drain default from 32 to 8. Darwin
  has no sendmmsg/GSO equivalent for this path, so a large worker batch becomes a
  tight send/sendto burst. Batch 8 trims burst size without forcing one worker
  wake per datagram, while preserving `FIPS_MACOS_WORKER_BATCH` for local tuning.

## 2026-05-14 - macOS reconnect drop during stale FMP packets

- Observation: a macOS peer briefly dropped an interactive connection after the remote peer logged `Excessive decryption failures, removing peer`.
- Correlation: the warning happened in the same minute as the reconnect. Recent sleep/wake had left stale encrypted FMP packets in flight.
- Root cause: FSP session AEAD failures already triggered an in-place recovery rekey, but FMP/link AEAD failures still used the older threshold path that removed the peer after 20 failures. The production decrypt worker also dropped FMP tag failures silently, so rx_loop could not start recovery from that path.
- Fix: report worker FMP AEAD failures to rx_loop, and make the FMP decrypt-failure threshold start a link recovery rekey before falling back to peer removal.
- Regression tests: `cargo test -p fips-core decrypt_failure`, `cargo test -p fips-core decrypt_worker`, and full `cargo test -p fips-core` all passed locally.

## 2026-05-14 - Docker throughput regression smoke

- Question: whether the current FMP/rekey changes caused a broad throughput regression, and whether release gating catches catastrophic performance drops.
- Method: rebuilt the Linux Docker test image from the current tree, then ran the static mesh ping and iperf harness locally.
- Result: static mesh ping passed 20/20. Five iperf paths reported 2.05-2.24 Gbit/s aggregate sender bandwidth across direct and multi-hop routes.
- Release-gate follow-up: added `static-mesh-perf`, a short Docker iperf smoke with configurable `FIPS_IPERF_MIN_MBPS` and a conservative default floor of 250 Mbit/s in CI/local release gating. This is intended to catch severe packet-path regressions, not to benchmark macOS Wi-Fi behavior.

## 2026-05-14 - Reply-learned lookup blackhole with stale tree candidates

- Observation: after deploying the macOS sender pacing fix, the MacBook saw all
  nvpn peers online, but the mini stayed at 6/8 and never learned the
  ubuntu-dev and hashtree-node VM peers. The MacBook could reach both VMs via
  public UDP, so this was not a missing identity or GUI-only problem.
- Correlation: mini logs showed repeated NAT traversal failures and recovery
  rekeys for those two VM peers. That topology can make direct mini-to-VM
  traversal fail while another neighbor already has a working path.
- Root cause: `ReplyLearned` lookup discovery only flooded live peers when
  there were no tree/bloom candidates. If any stale or bad candidate existed,
  lookup traffic followed only that candidate and never asked the working
  intermediary.
- Fix: in `ReplyLearned` mode, both lookup originators and transit forwarders
  now treat tree/bloom reachability as a hint and also send the lookup to other
  live peers. Normal tree candidates are still used first; the fanout just
  prevents first-contact discovery from getting stuck behind stale reachability
  claims.
- Regression tests: added origin and transit fanout cases where a tree/bloom
  match exists and a live non-tree peer must still receive the lookup.
