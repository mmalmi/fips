# FIPS Experiments

## 2026-05-14 - Restart stale pending sessions after discovery

- Observation: mini and win11-dev could exchange lookup/discovery traffic, and
  discovery learned a relayed route, but the data session stayed `fips link
  pending` and traffic blackholed. The same network still showed most peers
  reachable, which pointed at first-contact session setup rather than global
  mesh failure.
- Root cause: `retry_session_after_discovery` returned when a non-established
  session entry already existed. That left an initiating `SessionSetup` encoded
  against stale or placeholder coordinates from before the LookupResponse
  refreshed the coord cache and reverse route.
- Fix: after discovery completes, established sessions are left alone, but
  stale initiating/awaiting sessions are removed and re-initiated so the fresh
  `SessionSetup` uses the newly learned route.
- Verification: added
  `test_discovery_restarts_stale_pending_session_with_fresh_coords`; local
  focused, discovery, and full `fips-core --lib` test runs passed. Unpublished
  nvpn builds from this tree were deployed to the MacBook, mini, Linux hosts,
  and win11-dev; MacBook, mini, ubuntu-dev, hashtree-node, vader, and win11-dev
  all reported 8/8 mesh readiness after restart.
- Real-device result: mini-to-win11-dev over the relayed path completed a
  90-packet ping with 0% loss. win11-dev-to-mini no longer blackholed but still
  showed about 1% ICMP loss in two long ping runs, so this fix is verified for
  the pending-session blackhole but not a final reliability/performance release
  gate by itself.
- Release policy note: keep this unpublished until the residual relayed-path
  loss is either fixed or deliberately accepted after more device testing.

## 2026-05-14 - Ignore stale previous-epoch FSP drain failures

- Observation: after `fips-core` 0.3.6 was deployed, all nvpn peers reported
  8/8 mesh readiness and 150-180 second routed ping tests stayed at 0% loss, but
  logs still showed occasional FSP AEAD recovery rekeys shortly after a peer
  failed NAT traversal and fell back to routed FIPS.
- Root cause: post-rekey drain keeps the previous FSP session so old-epoch
  packets can still authenticate after cutover. If an old-epoch packet was a
  duplicate or too old for the retained replay window, both the current and
  previous sessions rejected it and the code counted that as current-session key
  divergence.
- Fix: while the drain window is active, packets that explicitly carry the
  previous K-bit are treated as stale drain noise when both decrypt attempts
  fail. Current-epoch failures still increment the recovery counter.
- Verification: added
  `stale_previous_epoch_failure_is_ignored_only_during_drain`; `cargo fmt
  --all --check`, `cargo test -p fips-core decrypt_failure -- --nocapture`,
  `cargo test -p fips-core --lib`, and `cargo test -p fips-endpoint` passed
  locally.
- Release policy note: do not publish another FIPS crate version for this fix
  until nvpn has been built against this exact FIPS tree and verified on the
  real mesh devices.

## 2026-05-14 - FSP rekey final-msg3 loss recovery

- Observation: 90 second nvpn continuity tests across the Pi/Windows VM path
  still showed occasional packet loss and clustered AEAD recovery churn near the
  default 120 second FSP rekey interval, even after stale FMP session failures
  were suppressed during fresh-session drain.
- Root cause: initial XK establishment retained the final `SessionMsg3` for
  resend, but the FSP rekey path sent the final rekey `SessionMsg3` once and
  immediately installed a pending new session. If that packet was lost or
  delayed, the initiator could cut over and emit new-session traffic while the
  responder still had only the old session.
- Fix: rekey initiators now store the encoded final `SessionMsg3` in the same
  resend machinery used by initial establishment. The retained payload is
  cleared only after pending rekey cutover has completed and authentic traffic
  arrives on the current K-bit session, so old-session drain traffic cannot
  accidentally cancel the repair path.
- Regression tests: added a two-node rekey test that keeps old-session traffic
  flowing while the final rekey message is pending, proves the retained payload
  survives that traffic, and verifies the resend path gives the responder a
  pending new session. `cargo test -p fips-core decrypt_failure`,
  `cargo test -p fips-core test_rekey_initiator_resends_final_msg3_until_responder_has_pending_session -- --nocapture`,
  and full `cargo test -p fips-core --lib` passed locally.

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
- Deployment follow-up: once the VM daemons were rebuilt against
  `fips-core`/`fips-endpoint` 0.3.3 and restarted, mini recovered from 6/8 to
  8/8 peers and mini-to-VM pings succeeded with 0% loss. Product version alone
  was not enough to distinguish the stale core because all daemons still
  reported `nvpn` 4.0.15.

## 2026-05-14 - Stale NAT traversal churn for already-routed peers

- Observation: after the VM daemons were updated, mini usually saw all 8 peers
  but still logged repeated `NAT traversal failed` lines for ubuntu-dev,
  hashtree-node, and win11-dev, followed by `Session AEAD failures exceeded
  threshold; starting recovery rekey`. A 90 second mini-to-ubuntu ping still
  lost 1/90 packets and saw a 250 ms spike, while MacBook-to-mini stayed at 0%
  loss.
- Correlation: those peers were already reachable over FIPS when stale Nostr
  traversal events arrived. The failure handler logged and attempted fallback
  dialing before checking whether the peer had become active; the success path
  could also adopt a traversal socket for an already-active peer.
- Fix: stale Nostr traversal successes/failures now no-op when the peer is
  already connected or has a handshake in progress. This keeps direct-path
  probing from racing the mesh route and producing duplicate handshakes/rekey
  recovery for peers that are already online.
- Regression tests: added coverage for ignored handoffs and ignored fallback
  address attempts after a peer is already active, plus kept the reply-learned
  first-contact route test green.

## 2026-05-14 - Fresh FMP session stale-packet drain

- Observation: after all peers were on the stale-traversal fix, mini still
  logged worker FMP AEAD recovery rekeys for VM peers shortly after reconnect.
  These were clustered around restart/rejoin windows rather than steady-state
  throughput runs.
- Correlation: at the same time, raw LAN and Tailscale pings from the MacBook
  to mini stayed healthy with 0% loss and single-digit millisecond averages,
  while the pre-restart nvpn path briefly hit multi-second ping queues. That
  separates general Screen Sharing/Wi-Fi stutter from an nvpn-specific stale
  session drain problem.
- Root cause: a newly registered worker-owned FMP session starts with an empty
  replay window. Stale encrypted datagrams from the previous link session can
  pass the replay-window precheck, fail AEAD, and reach the recovery threshold
  before the first clean packet on the new session resets the failure streak.
- Fix: worker decrypt-failure reports now include the worker replay-window
  highest accepted counter. During a bounded 30 second fresh-session window,
  failures are ignored while that highest counter is still zero. Once any
  packet authenticates, or once the grace window expires, the normal threshold
  rekey/removal recovery path applies.
- Regression tests: added coverage that fresh worker failures are suppressed,
  that failures count normally after an authenticated counter, and that the
  fresh-session grace is bounded.
