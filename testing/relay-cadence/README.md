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

Alternatively, run the mint on the controller: replace `--mint-host` and its
address with `--mint-ssh-forward --mint-address 127.0.0.1`, and supply a native
controller `--mint-binary`. This reuses the paid Wi-Fi loopback forwards, checks
all three connections before issuing funds, and preserves them if recovery is
incomplete. Choose exactly one mint mode. Every trial keeps the selected mode;
`mint_connection` records it in the measurement metadata. Keep the same mode
throughout a matched comparison.

Start with `--pilot`: one 250-ms trial runs all four workloads and the same
strict measurement and financial checks. It always reports
`comparison_complete: false`. Omit `--pilot` and select a new output directory
for the complete eight-trial matrix. Each trial restores the original router
baselines and stops its fully collected mint before the next starts. The saved
radio profile, management LAN and original service accounts are preserved.

The priority-enabled router build passed a 500-ms controller-SSH pilot on
2026-09-18: all 11,712 payload packets arrived, all 384 test sats were collected,
and original baselines were restored with 258 management checks and no errors.
The forwarding router ran separately from the traffic-generating endpoint.
Its observed cost, including sampling and the common three-second tail, was:

| Workload | Forwarding-router CPU seconds | CPU seconds per delivered MiB |
| --- | ---: | ---: |
| Idle | 0.129 | — |
| Bursty | 0.598 | 1.224 |
| Steady | 2.624 | 0.860 |
| High rate | 2.109 | 0.276 |

Idle produced no payment updates, payment records or payment journal writes.
This single-policy pilot does not establish a cadence winner, sustained link
capacity, or mixed free/paid performance. Keep the 500-ms default until a matched
comparison supports changing it. The earlier remote-mint matrix and this pilot
use different mint connections and cannot isolate a scheduler optimization.

The subsequent matched eight-trial comparison on the same priority-enabled
router build and controller-SSH mint also passed. It delivered all 93,696
payload packets (81 reordered, none missing, duplicated or invalid), collected
all 3,072 test sats, and restored every original baseline with 2,055 successful
management checks and no cleanup errors. The following high-rate results average
two repetitions; payment totals cover all three processes:

| Maximum payment age | Updates | Payment CPU (ms) | Payment record bytes | Payment journal bytes | Forwarding-router CPU s/MiB |
| --- | ---: | ---: | ---: | ---: | ---: |
| 250 ms | 4 | 208.18 | 3,281 | 45,526 | 0.276 |
| 500 ms | 3 | 163.94 | 2,463 | 31,919 | 0.277 |
| 1 s | 2 | 102.11 | 1,642 | 22,247 | 0.261 |
| 2 s | 2 | 105.70 | 1,642 | 20,370 | 0.269 |

Idle windows did no payment polling, signing, updates or journal writes. Bursts
fit within existing acknowledged credit; steady windows needed three updates
at every policy. The 1-s policy reduced measured payment CPU by about 38% and
record bytes by 33% versus 500 ms in this high-rate workload. These are partial
payment costs, and the workload does not establish maximum throughput. Two
repetitions on a stable topology, without competing free load or measured
hardware latency, do not justify changing the 500-ms default. The earlier
three-packet-loss matrix remains a failed result with an unresolved loss cause.

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
reported before and after each window. `reported_vmhwm_after_kib` retains the
kernel-reported VmHWM at the end snapshot. Each node's `vmhwm_samples_kib` preserves
the named raw boundary samples; `maximum_observed_vmhwm_kib` is their maximum,
not a proven lifetime or window peak. `vmhwm_decreases` records each observed
decrease with its host, boundaries, raw values and amount. Summed node values
need not have occurred simultaneously.

Linux's reported VmHWM is not a strict monotonic counter: the reported current
RSS can include per-CPU counts that were absent when the stored high-water mark
was updated. Reading the report does not store that observed maximum. See the
[Linux 6.12.94 proc reader](https://github.com/gregkh/linux/blob/v6.12.94/fs/proc/task_mmu.c#L35-L68)
and [RSS/high-water helpers](https://github.com/gregkh/linux/blob/v6.12.94/include/linux/mm.h#L2645-L2727).
A decrease alone therefore does not invalidate a run or prove a reset. Raw
values remain unchanged, and each snapshot must still have nonnegative values
and RSS no greater than VmHWM. Process identity and all actual CPU, I/O, payment
and journal counter checks remain required.

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

A bounded pilot validates only trial 0 (250 ms by default), with all four workloads and
the same strict guards, schedule, delivery and 384-sat collection requirements.
Both `metadata.pilot: true` and explicit analyzer opt-in are required:

```sh
python3 testing/relay-cadence/analyze.py /absolute/pilot.jsonl --pilot
```

A pilot is not a complete comparison (`comparison_complete` remains false in
the runner's result). Full analysis rejects pilot reports; pilot mode rejects a
full matrix, missing conservation or invalid boundaries. Pilot output is JSON
only; Markdown comparison output is rejected.

`sim.wifi_cadence --pilot --pilot-delay-ms 2000 --native-counters` runs the same
four workloads at one explicitly selected supported age limit. It preserves
the original spending caps, workload sizes, fixed tail and collection checks.
It cannot establish a policy comparison or repair a previously rejected matrix.
The metadata records `pilot_delay_ms`; a full matrix cannot override its schedule.

The optional native observations use the existing private `show_status` and
`show_routing` requests inside the same executable/command/PID/start-time guard
as each resource sample. Native status must identify that same process and node.
Both raw replies are retained in each snapshot's `native` field. Analyzer output
reports forwarding/drop, congestion and error-signal counter deltas per node,
plus separate `native_gap_counters` for guards and inter-window gaps. Missing or
changed groups, a failed reply, an identity change or a counter reset invalidate
both strict and diagnostic analysis. There are no invented zero counters.

The analyzer recognizes the historical forwarding layout and its extension with
both `drop_background_full_packets` and `drop_background_full_bytes`. It preserves
those counters when present and rejects partial or changing layouts between
native queries, sample boundaries and inter-window gaps. Historical reports keep
the counters absent.

These counters cover native traffic in aggregate, including control traffic.
They can identify recorded forwarding-policy, route, MTU or local-send failures;
they do not identify a particular application packet or prove the cause of
unrecorded radio/driver, cryptographic or endpoint loss. Native observations are
sequential, not atomic with financial or process-cost samples. The additional
queries cost CPU/time, so a diagnostic run with them is not a matched performance
comparison against a run without them. No payment or routing messages are added.

The first native-counter pilot exposed a coverage limit: successful optimized
endpoint traffic did not advance the node's legacy received/delivered counters.
The middle router did count forwarded traffic. Consequently, zero endpoint
counts or drop counters cannot rule out a failure on those optimized paths.
Even the legacy delivered counter records session-layer handoff before full
application delivery. Ethernet currently supplies no kernel receive-drop signal
to `TransportHandle::congestion`, so zero `kernel_drop_events` does not establish
zero Ethernet/kernel loss. Existing dataplane debug drop events provide a
separate observation path for raw ingress, crypto, output and endpoint failures.

Add `--dataplane-drop-logs` to enable those existing debug events for the isolated
candidate. Its exact filter is
`warn,fips_core::node::handlers::rx_loop::dataplane=debug`; other targets retain
warning-level logging. The launcher exports it only to the candidate. Every
guarded sample verifies the candidate's `RUST_LOG` value without returning its
other environment variables, then records the cumulative `process.log` byte
length. Missing or changed filters and shrinking logs invalidate analysis.
Metadata declares `dataplane_drop_log_filter`, raw snapshots retain
`dataplane_log`, and per-window summaries expose `dataplane_log_ranges` for all
boundaries and the preceding guard. Normal cleanup preserves the full log
under each router's private output directory.

Use the recorded byte offsets to distinguish workload, guard-gap, setup and
cleanup events. A record spanning a byte boundary has uncertain window
attribution and should be retained as such. Logs describe local drop reasons;
they are not per-packet delivery receipts. Logging adds work when an event is
emitted, so comparisons need the same filter and counter sampling on every
trial. Empty matching logs cannot establish absence of losses that have no
event at these observation points.

For a complete but rejected matrix, diagnostic JSON can retain cost observations
and identify each missing-delivery window:

```sh
python3 testing/relay-cadence/analyze.py /absolute/measurements.jsonl --diagnostics
```

This mode emits `diagnostic: true` and `accepted: false`, and exits unsuccessfully
when delivery is incomplete. It preserves every other validation requirement,
including complete submission, packet identity/counts, duplicate/invalid rejection,
financial conservation, process identity, quiet boundaries and durable counters.
Malformed or unreconciled evidence still fails without a summary. Diagnostic
output cannot be combined with Markdown comparison output, and must not replace
the original rejected result or be presented as an accepted comparison.

For a fresh Wi-Fi loss investigation, add `--post-gap-probes` to `sim.wifi_cadence`.
After each existing 800-ms burst gap, this reads the same receive stream once,
before the next stream is armed. The original two-second drain result stays in
`receiver`; `post_gap_observation` contains the supplemental result. Both reads
have controller-monotonic nanosecond intervals. Explicit metadata distinguishes
these diagnostic runs, and the analyzer validates matching stream/source,
nondecreasing receive counts and observation order. Its `post_gap_probes` summaries
report additional packets, remaining missing packets and status-read duration.
The observation span must fit the measured workload window. These captures use
JSON output; Markdown comparison export is rejected.
Late arrivals never repair the original acceptance result, and no payload is resent.

The extra reads add control work and delay the next burst; do not compare their
costs directly with captures that omit them. A 62-to-64 change establishes
reception between the two receiver snapshots, bracketed by controller request
intervals. It does not establish exact arrival times, arrival specifically during
the 800-ms sleep, or where packets were delayed. An unchanged count only rules
out arrival between those snapshots. Neither
result explains a past capture that did not retain this observation.

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
  traffic and do not isolate payments. The hardware run also exposed source
  peer sent-byte counters that omitted some application traffic; summing these
  observations is not complete carrier accounting. Neither metric measures Wi-Fi airtime.

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
bytes, impaired-link and long-running storage comparisons, profiler attribution outside
the synchronous spans, and complete controlled ARM64/router/phone comparisons.
The guarded three-router 250-ms pilot passed all four workloads and financial
recovery. The subsequent eight-trial hardware matrix collected all windows and
recovered all funds, but its strict clean-link gate rejected three missing
packets out of 93,696 submitted. The failed result remains failed; the saved
evidence does not establish the loss cause. Performance changes
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

### Local payment-service carrier capture

New Wi-Fi captures set `payment_service_carrier: true` in report metadata and
require a measurement build exposing `control_traffic[].service_carrier` for
port 44743. The four existing application counters keep their meaning. Absent
instrumentation is unavailable, not zero; historical reports without this
metadata retain `payment_service_carrier: null` in their summaries.

The analyzer records successful local submissions per node and transport,
including inner TCP handshakes, ACKs and retransmissions associated with that
service. It reports FIPS payload bytes and Ethernet's three-byte prefix
separately. Counts from requests and replies are added at their sending nodes;
received bytes are not added again. These observations exclude opaque transit,
shared FIPS handshake/MMP/rekey traffic, OS/link encapsulation and radio airtime.
Outer TCP kernel retransmissions are also outside the transport API boundary.
They are not complete physical wire usage or the complete marginal cost of a
payment. The quote and agreement ports retain their separate application counts.

Snapshots are not atomic across counters. Each counter must remain monotonic
within the same process and service identity; missing, saturated, ambiguous or
malformed evidence rejects a claimed capture. Discarded sealed outputs are
reported separately; their already-submitted fragment prefixes still cost bytes.
Each window retains its per-node/transport deltas and bytes per delivered
application byte. Zero-delivery ratios remain null.

TCP activity may continue after a payment is acknowledged. The analyzer reports
the before/after guard gaps and the gap between successive workloads separately,
without extending the three-second tail or subtracting a background estimate.
Every adjacent interval is counted once. An idle window can therefore show
transport bytes with zero new payment records. Existing payment, storage,
delivery and financial-conservation acceptance rules still apply; carrier
diagnostics cannot turn a failed workload into an accepted comparison.

### Separate storage syscall diagnostics

For an isolated capture through the production payment path, run from
`testing/chaos` with explicitly supplied Linux ARM64 binaries and an existing
ARM64 image containing Python and `strace`:

```sh
python3 -m sim.paid_storage --binary-dir /absolute/linux-arm64 \
  --image LOCAL_DIAGNOSTIC_IMAGE_ID --output /absolute/new-private-capture
```

This reuses the paid Ethernet fixture, with three relays, two original channels,
and a private mint capped at 384 test sats. No image or binary is built or pulled.
Both directions warm up before tracing. Stable double samples require the
original paying channels' acknowledged credit to cover usage and signed
liability, with no payment in flight. The capture covers six eight-packet probes
(12,288 delivered application bytes), automatic payment reconciliation, and a
second stable boundary. It excludes channel funding and settlement and must not
be used for timing comparisons.

Each owned container supervises its tracer, checks the exact relay executable
and command line through a pidfd, verifies attachment to every current thread,
and bounds the capture to 90 seconds and 64 MiB. Deliberate SIGINT detach may
return zero or signal status; acceptance separately requires the relay to remain
alive and untraced, with empty tracer stderr. The parser still validates all
records. The run requires writes from both buyer SDKs and the receiver SQLite
store, rejects failed file/directory syncs and funding-wallet writes, and retains
unmatched and unattributed operations separately. SDK temporary-file attribution
is scoped to this ordinary-payment workload, not inferred from arbitrary files.

The same original channels are settled and all test money collected even if the
capture is rejected. The workload alarm is disabled before financial closure;
individual operations retain their own timeouts. If funding or collection is
uncertain, the original containers and accounts remain available and the run
fails. Never reset, replace, or repeat these accounts to hide incomplete recovery.

An initial Linux ARM64 capture on 2026-09-18 delivered all 48 payload packets and
reconciled 17 automatic payments. The separate syscall totals were:

| Category | Successful write bytes | File syncs |
| --- | ---: | ---: |
| Buyer SDK private snapshots | 256,950 | 17 |
| Receiver SQLite and journal | 287,708 | 51 |
| Relay journals | 156,224 | 68 |

There were another 102 parent-directory syncs, no failed file operations, no
funding-wallet writes and no unmatched file paths. The SDKs performed 17 snapshot
writes alongside 17 signing operations; the receiver recorded 17 update
operations. All three tracers detached cleanly, all 384 test sats were collected,
and owned resources were removed. These counts expose storage omitted by the
relay journal counters. They are one workload's filesystem syscall costs, not
flash wear, SQLite changed-row counts or a timing benchmark. Snapshot size also
depends on retained account history; this small fresh-account result cannot
establish long-running storage cost.

### Matched storage cadence capture

The separate storage driver reuses the hardware comparison's finite idle,
bursty, steady and high-rate workloads. Run one pilot before the eight-trial
policy sequence; each trial funds fresh accounts and collects its complete
384-test-sat issuance before the next can start:

```sh
python3 -m sim.storage_cadence --binary-dir /absolute/linux-arm64 \
  --image LOCAL_DIAGNOSTIC_IMAGE_ID --output /absolute/new-private-pilot \
  --pilot --pilot-delay-ms 500
```

Omit both pilot options for the 250/500/1000/2000 ms sequence and its reverse.
The tariff is 1 msat/KiB and the quote allowance is 16 MiB; channel capacity,
wallet limits and disabled renewal remain those of the paid Ethernet fixture.
Both directions use that fixture's existing warmup before tracing. This is a
within-fixture storage comparison: its virtual Ethernet carrier, platform and
warmup differ from the physical Wi-Fi experiment.

Each workload has its own named trace and a three-second payment tail. Evidence
records scheduling slack and boundary sampling separately, rejecting more than
250 ms of tail slack or two seconds of sampling. Strict double samples never
retry an unfinished payment. Payment counters and all operation buckets'
durability counters must remain unchanged across tracer attachment/detachment
gaps. Already-credited metered usage may increase across a quiet boundary, but
authorization and acknowledged credit must stay fixed. Each window separately
reports usage before its workload and after its final sample; the next window
starts from the post-detachment sample to avoid counting the same gap twice.
No payment or storage cost is subtracted. Every payload must arrive, and source
usage must cover at least its payload-derived tariff. Prepaid traffic need not cause another signature, but
must still advance usage. Idle windows require no payment or tracked storage
work; zero-write traces still require verified attachment and clean detachment.
Idle metered usage can advance without an application probe or another payment;
that background usage remains reported and is never subtracted from other windows.
Unmatched file operations, including failed operations, reject the window.
An explicitly detached eight-byte event-counter write may lack a return value;
after verified tracer shutdown, it is counted separately without inventing
successful bytes. Incomplete file writes and unknown descriptors still reject.

Summaries separate SDK snapshots, receiver SQLite, funding-wallet files, relay
journals and directory syncs. CPU counters collected under tracing are labeled
partial and unsuitable for timing comparisons. Successful syscall bytes are
not physical media writes. A pilot validates one policy only; it cannot establish
which payment cadence is preferable.

The accepted eight-trial comparison delivers all 93,696 packets, collects all
3,072 test sats and independently reproduces all raw trace summaries. At high
rate the 1-second pair performs two updates versus three at 500 ms, reducing
SDK snapshot and receiver SQLite writes. Independent checkpoint costs remain
separate; neither this comparison nor its traced CPU values establishes a best
default. See the [paired results and limits](../../crates/fips-relay/CADENCE-RESULTS.md#matched-storage-syscall-comparison--19-september-2026).

`storage_trace.py` summarizes an isolated Linux `strace` capture by explicit file
categories. Use a fresh private output directory and the options returned by
`storage_trace.trace_options()`: follow threads, always show their IDs, suppress
signals and buffer contents (`--string-limit=0`), decode descriptor paths, and
trace only `write`, `writev`, `pwrite64`, `pwritev`, `pwritev2`, `fsync` and
`fdatasync`. Never enable read/write data dumps. A Linux synthetic check covered
scalar/vector writes, an invalid descriptor and real SQLite writes; buffer
sentinels were absent while paths and successful byte counts remained available.

Provide a private JSON object mapping labels to absolute file globs, including
temporary snapshots and SQLite journal/WAL files as applicable. For example:

```json
{"sdk_snapshot": ["/private/run/wallet/client.json*"],
 "receiver_sqlite": ["/private/run/receiver/*.sqlite*"]}
```

Use the actual paths from the owned workload. Overlapping categories fail;
unmatched paths and operations without a file path retain separate totals.
Directory syncs may need their own category. Raw traces and path maps remain
private; the summary contains category labels and counts without raw paths.

```sh
python3 testing/relay-cadence/storage_trace.py /private/capture.trace \
  --paths /private/paths.json > /private/storage-summary.json
```

Counts use successful returned bytes, separately record failed calls and syncs,
and reassemble interleaved unfinished/resumed calls by thread. The analyzer
rejects exposed buffers, unknown formats and dangling calls. A trace truncated
after a completed line cannot be detected from its contents: `capture_complete`
stays null. Record successful tracer exit, workload completion and the enclosing
test's financial recovery independently before accepting the capture.

`partial_scalar_writes` covers only `write` and `pwrite64`; suppressed vector
arguments do not expose their total requested bytes. These observations exclude
mapped/asynchronous I/O, filesystem metadata, physical-media amplification and
SQLite committed-row counts. They do not identify which payment caused a write
without an isolated, verified workload boundary. Run tracing separately from
timing comparisons and retain the ordinary ownership and settlement guards.
The production payment-storage trace is still required; the synthetic check
establishes only the capture and analysis mechanism.
