# FIPS Experiments

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
