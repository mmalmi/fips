# Paid-relay cadence experiment

The analyzer accepts the loopback experiment (schema 2) and the guarded
three-router Wi-Fi experiment (schema 3) described below. Both use the same
payment, delivery and financial acceptance checks.

The loopback experiment runs the production relay executable as five separate processes,
with three paid forwarding hops, loopback UDP links and an isolated simulated
mint. It reuses the existing service test helpers and operator probe API. It does
not alter live routers, home networking or saved accounts.

Run alone, after compilation has finished. Do not run other tests or compilation
concurrently with a measurement. Normal host activity still affects the result;
retain host load, architecture, compiler and executable digest alongside it.

```sh
python3 -m unittest discover -s testing/relay-cadence -p 'test_*.py'
cargo test -p fips-relay --release --features measurements \
  --test cadence_benchmark --no-run
FIPS_CADENCE_REPORT=/absolute/new-report.jsonl \
  cargo test -p fips-relay --release --features measurements \
  --test cadence_benchmark matched_cadence_matrix -- --ignored --exact --nocapture
python3 testing/relay-cadence/analyze.py /absolute/new-report.jsonl > summary.json
python3 testing/relay-cadence/analyze.py /absolute/new-report.jsonl --markdown > summary.md
```

The output must not already exist. Each trial uses new isolated accounts; no
financial state is reset or reused to remove debt. The comparison order is
250/500/1000/2000 ms, then the reverse order. Every policy uses a 50% value trigger,
4,000-msat durable window, 8,000-msat grace, 256-sat channel capacity and the same
one-msat/KiB per-relay tariff. These terms are fixed before every run; they are
not enlarged to hide loss. Renewal is disabled to isolate cadence cost. Both
sending directions are independently funded to retain the historical comparison.
The original run predated bounded return-bootstrap support and required this
reverse funding; unfunded recipient setup now has separate acceptance coverage.
This experiment measures the same two funded directions throughout.

Each trial records bounded setup/warmup attempts separately, followed by:

| Workload | Offered application traffic |
| --- | --- |
| Idle | Four seconds with no diagnostic traffic |
| Bursty | Eight bursts of 64 × 1,000-byte packets at 1,000 packets/s, 800 ms after every burst |
| Steady | 3,200 × 1,000-byte packets at 400 packets/s (3.2 Mbps) |
| High rate | 32,000 × 1,000-byte packets at 4,000 packets/s (32 Mbps) |

Measured packets are never retried. The receiver drains for at most two seconds
per stream. All policies get a common three-second tail for outstanding automatic
payments, which is included in the reported observation window. No explicit
flush forces a particular result. Sender partial submission, delivery loss,
duplicates, rejected timestamps and controller errors remain in the raw data.
The loopback processes share a host clock, but invalid one-way timestamps are
still reported rather than converted into fabricated samples.

The six paid channels must settle and all five accounts must end empty after
their balances are collected into the isolated redemption wallet. Each trial
records issued/collected totals and the test network's conservation assertion.
An incomplete run without those records is not an accepted matrix. Schema 2
requires all six paying channels at both boundaries: acknowledged credit must
cover current local usage and signed liability, with no payment job in flight.
Each boundary has two complete sampling passes; progress, payment counters and
journal counters must remain unchanged between them. This catches provider work
finishing after an earlier provider snapshot but before a later buyer snapshot,
including at the last workload. Unknown acknowledgments, changed membership, and
work observed between workload windows reject the comparison. The tail remains three seconds for every policy;
no flush or selective extension makes a slow policy look complete.

The clean-link validator also rejects partial submission, packet loss, duplicates,
invalid data or timestamps, controller errors, and payment or journal activity
while idle. Reordering remains visible. It rejects counter resets, restarted
processes, changed link epochs, missing CPU samples and mismatched trial ordering.
Raw failed reports remain available; a valid JSON report alone is not acceptance.
Two repetitions show variation but are not enough for statistical claims of an
optimal policy. Historical schema-1 results lack the payment-boundary evidence
and must be analyzed with their original analyzer revision.

## Hardware report contract (schema 3)

The hardware runner uses three router service processes, one paid relay, two
funded directions, two active channels, and native Ethernet over 802.11s. Each
trial uses fresh isolated accounts: 128 test sats per router, 32-sat channels,
`forwarding_data` billing, and a 16,777,216-unit quote allowance. The value trigger,
window, grace, tariff, two repetitions and policy order match schema 2. Every
trial must settle both channels and collect all 384 issued test sats. Analyzer
support and synthetic tests alone do not establish a physical benchmark result.

Run the existing guarded Wi-Fi lifecycle from `testing/chaos`:

```sh
python3 -m sim.wifi_cadence \
  --inventory /absolute/router-inventory.json \
  --binary /absolute/measurement-release/fips-relay \
  --provenance /absolute/measurement-release/provenance.json \
  --mint-binary /absolute/linux-arm64/fips-relay-test-mint \
  --mint-host /absolute/mint-host.json --mint-address PRIVATE_MINT_IPV4 \
  --output /absolute/new-pilot-directory --pilot
```

The router inventory is the same explicit inventory used by `sim.paid_wifi`.
The mint-host JSON supplies `host`, `state_parent`, and optional `ssh_config` for
the existing guarded `RemoteMint` adapter. Its assigned LAN address must be
reachable from every router. The release provenance must bind the supplied
binary digest to a successful, unchanged-source ARM64 musl build with
`--release` and the `measurements` feature. The runner retains this provenance,
platform/load information and exact harness hashes beside private evidence.

Start with `--pilot`: one 250-ms trial runs all four workloads and the same
strict measurement and financial checks. It always reports
`comparison_complete: false`. Omit `--pilot` and select a new output directory
for the complete eight-trial matrix. Each trial restores the original router
baselines and stops its fully collected mint before the next starts. The saved
radio profile, management LAN and original service accounts are preserved.

Raw `measurements.jsonl` is written incrementally. Workload failure attempts
settlement/collection while management and ownership guards remain healthy;
uncertain funding or failed guards retain the original mint/accounts for
deliberate recovery. The trial deadline is canceled before collection, whose
remote operations retain individual timeouts. Failed measurements never trigger
payload retries, selective tail extension or replacement of snapshots. Analysis
runs after collection, so rejected measurements still retain financial evidence.
`summary.json` is emitted only after validation; `result.json` distinguishes
completed trials, accepted measurements and a completed policy comparison.

Schema 3 retains the same workload/boundary row structure, with these changes:

- High rate offers **8,000** packets at 4,000 packets/s. Idle, bursty and steady
  counts and rates remain as above. Every one of the eight bursts includes its
  final 800 ms sleep. Metadata records the exact `workload_schedule` and
  `common_tail_ms: 3000`; each probe records its `packets_per_second` and
  `after_sleep_ms`. Offered elapsed time must cover idle duration or sequential
  sender durations plus sleeps. These records establish the declared schedule,
  not exact packet-by-packet pacing.
- Every snapshot includes the service `npub` and `host_process`: `host` (`n01`,
  `n02` or `n03`), `pid`, `start_ticks`, `rss_kib`, `peak_rss_kib`, `read_bytes`,
  `write_bytes`, `rchar`, `wchar`, `syscr`, `syscw`, and explicit `io_available`.
  When `io_available` is false, all six I/O counters must be null; when true,
  each must be a nonnegative integer. Availability must remain stable throughout
  each trial. The PID must match the
  service's measurement PID. Host, node and process start identity must remain
  stable across all guards and workload windows. Equal PIDs on different hosts
  are valid; a duplicate host or node identity is not.
- Independent router clocks do not establish one-way latency. Metadata must
  state `one_way_latency: false`, and every receiver's `latency` must be null.
  Delivery counts, bytes, duplicates and reordering still use the existing probe
  evidence. Mean and percentile one-way latency remain null in summaries.
- Radio traffic can cause paid work during application-idle windows. Such work
  is included and reported; it is not subtracted as a baseline. Both channels
  must still be fully acknowledged with no job in flight at every boundary.
  The same double guards and gap checks reject payment or relay-journal work
  outside measured windows, including work after the final snapshot.

JSON summaries retain total and per-node CPU seconds, CPU seconds/MiB, payment
spans and control-record bytes, relay journal bytes/writes/commits/syncs, plus
end-to-end goodput. Each node's normalized CPU uses the same delivered application
bytes as the total, with null ratios when no data is delivered. Current RSS is
reported before and after each window. `process_lifetime_peak_rss_kib` is a
cumulative process high-water mark, not a window peak; summed node peaks need not
have occurred simultaneously.

Goodput divides delivered application bits by `offered_elapsed_ms`, including
controller/SSH probe setup, status polling, bounded receive drain, and burst
sleeps; it excludes the common three-second tail. It is not sender-only pacing
or a link-capacity measurement. CPU and overhead include the common tail.
Workloads within one trial share the original channel and prepaid credit.
Earlier payments can cover later traffic: zero payment updates in a workload
does not mean forwarding was free or unbilled. Setup/warmup is recorded separately
and excluded from workload cost windows; the sequence is fixed for every trial.

`os_io` contains separate process counter deltas when the kernel exposes them.
If `/proc/PID/io` is absent, the node's `os_io` is null. The total is also null
unless all three nodes provide I/O counters; `os_io_observed_nodes` records the
coverage. Missing I/O is never replaced with zeros, and unreadable or malformed
files are errors rather than evidence of unsupported counters. There is no OS
I/O measurement claim for kernels without these counters. CPU, RSS and logical
relay journal metrics remain independently available.

When present, `read_bytes`/`write_bytes` are
OS-accounted storage I/O; `rchar`/`wchar` are read/write character counts including
other I/O; `syscr`/`syscw` count read/write system calls. They cover the whole relay
process and **are not payment-attributed**. They are not the logical journal
counters, physical media wear, or per-payment SQLite attribution. Counter resets
and process replacement invalidate the comparison. OS I/O during status sampling
can advance without becoming a payment/durability gap violation.

A bounded pilot validates only trial 0 at 250 ms, with all four workloads and
the same strict guards, schedule, delivery and 384-sat collection requirements.
Both `metadata.pilot: true` and explicit analyzer opt-in are required:

```sh
python3 testing/relay-cadence/analyze.py /absolute/pilot.jsonl --pilot
```

A pilot is not a complete comparison (`comparison_complete` remains false in
the runner's result). Full analysis rejects pilot reports; pilot mode rejects a
full matrix, missing conservation or invalid boundaries. Pilot output is JSON
only; Markdown comparison output is rejected.

## Measurement boundaries

Build the relay with the optional `measurements` feature. The private local
`status` response then contains cumulative process-local diagnostics; normal
builds return `measurements: null` and do not read CPU clocks or update these
counters. They are never serialized into financial journals and cannot authorize
forwarding, payments or spending.

- **Process CPU:** OS process CPU clock, covering all threads of one service.
  It includes data/control work, scheduling, status queries and instrumentation.
  Sum services once; the mint, test harness and kernel work charged elsewhere
  are outside this metric.
- **Payment CPU:** OS thread CPU clock around synchronous signing (including
  signer load and buyer authorization), usage handling, and balance updates
  (including receiver verification and synchronous durability). No span crosses
  an async wait. CPU time excludes sleeping and network waits. CPU sample counts
  expose unsupported/failed clocks; elapsed nanoseconds are a separate field.
  These spans exclude control-envelope JSON processing outside the spans,
  payment scheduling, TCP/FIPS work,
  and work done by another thread. They are not total payment-induced CPU.
- **Storage:** successful complete writes, written bytes, successful sync calls
  and durable commits through the relay journal writer. A normal commit has one
  logical write and two sync calls. Counts are attributed to the enclosing
  synchronous operation; independent window checkpoints have their own category.
  SDK client JSON snapshot writes, receiver/wallet SQLite writes, partial failed
  writes, filesystem metadata,
  write amplification and physical device bytes are not counted.
- **Traffic:** per-payment-service application record bytes, plus separately
  reported aggregate native link counters. Sum sent bytes once; summing sent
  and received double-counts them. Record bytes omit TCP/FIPS/carrier framing,
  acknowledgments and retries. Aggregate link counters include other native
  traffic and do not isolate payments. Neither metric measures Wi-Fi airtime.

Clock support is currently implemented for Linux, Android and macOS using the
OS thread/process CPU clocks. Other targets expose missing CPU samples. The
clock semantics are documented in the [Linux manual](https://man7.org/linux/man-pages/man3/clock_gettime.3.html).
`payment_progress` is an optional read-only observation of the scheduler and
current buyer state. It is neither an atomic financial snapshot nor payment
authority. Unknown state stays unknown after scheduler teardown or restart.
Snapshots bracket a quiescent workload; they do not freeze packet processing.
Normalized payment CPU, journal bytes and record bytes use delivered application
bytes. CPU per update includes usage polls and signing in the same window, not
only the receiver's update handler.

Synchronous spans may nest; their CPU/elapsed totals are inclusive and must not
be blindly summed across overlapping categories. Current production payment
and checkpoint instrumentation uses non-overlapping spans.

## Remaining comparison work

This matrix provides the repeatable clean-link baseline. It does not fulfill
the full production-readiness benchmark. Still required: impaired links using
the existing FIPS simulation/chaos facilities, payment-specific complete carrier
bytes, SDK snapshot and receiver SQLite storage measurements, profiler attribution outside
the synchronous spans, and complete controlled ARM64/router/phone comparisons.
The guarded three-router 250-ms pilot passed all four workloads and financial
recovery; the complete hardware cadence matrix remains pending. Performance changes
need a matched baseline with instrumentation cost held constant. No production
default is selected solely from this loopback experiment.

For ordinary cumulative payments, signing rewrites the SDK's client snapshot;
receiver updates use Spilman's SQLite database. Both execute synchronously inside
the existing signing/update CPU spans. Main-wallet funding and settlement occur
outside these windows. Storage instrumentation must count successful snapshot
writes and committed SQLite changes separately; a same-balance replay may update
zero rows. Per-file syscall write lengths measure filesystem writes, not physical
media wear, and should be collected in a separate traced run.

Payment-control ports identify inner TCP segments locally, including their
handshakes, acknowledgments and retransmissions. They are encrypted within FIPS
on the carrier. Complete carrier cost needs local attribution through actual
submission or an isolated payment-only capture with a matched idle baseline.
Subtracting that baseline estimates incremental cost; it does not establish exact
per-payment attribution during mixed data traffic or measure radio airtime.
