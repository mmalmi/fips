# Paid-relay cadence measurements

## Accepted client-storage-budget comparison — 24 September 2026

The existing optimized five-process, three-paid-hop loopback matrix passes on
FIPS `1bb0171c7`, SDK `8a98b94`, Spilman `2c6c916` and CDK `b1bc86e6`.
This includes client-file completion reservations and bounded wallet inventory.
All 285,696 original payloads arrive: no loss, duplicates, invalid data or rejected
timestamps; 15 packets arrive out of order. All eight trials settle six channels
each and recover all 40,960 test sats. The strict analyzer passes, and all 2,624
source/dependency inputs still match after measurement. Its Python implementation
and tests are unchanged from the accepted 120-test analyzer verification below.

The workload, prices, credit limits, two opposite-order repetitions and common
three-second tail are unchanged. Costs sum all five service processes; each row
is the mean of two workload windows. Per repetition, bursty delivers 512 packets,
steady 3,200 and high rate 32,000, each with a 1,000-byte payload.

| Workload | Limit ms | Payment CPU ms | Process CPU ms | Updates | Records KiB | Payment journal KiB | Local carrier KiB | Mean delay ms |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| idle | 250 | 0.00 | 466.55 | 0.0 | 0.00 | 0.00 | 0.00 | — |
| idle | 500 | 0.00 | 316.12 | 0.0 | 0.00 | 0.00 | 0.00 | — |
| idle | 1000 | 0.00 | 394.39 | 0.0 | 0.00 | 0.00 | 0.00 | — |
| idle | 2000 | 0.00 | 437.84 | 0.0 | 0.00 | 0.00 | 0.00 | — |
| bursty | 250 | 32.77 | 1013.61 | 2.0 | 1.60 | 18.06 | 4.61 | 0.761 |
| bursty | 500 | 39.06 | 1124.79 | 2.0 | 1.60 | 18.06 | 4.61 | 0.822 |
| bursty | 1000 | 24.47 | 849.07 | 2.0 | 1.60 | 18.06 | 4.61 | 0.674 |
| bursty | 2000 | 33.24 | 1032.19 | 2.0 | 1.60 | 18.05 | 4.61 | 0.981 |
| steady | 250 | 240.87 | 4247.77 | 19.0 | 15.19 | 175.68 | 43.77 | 0.931 |
| steady | 500 | 211.35 | 3732.68 | 19.0 | 15.19 | 175.83 | 43.77 | 0.800 |
| steady | 1000 | 163.43 | 3465.73 | 14.0 | 11.19 | 130.24 | 32.25 | 0.800 |
| steady | 2000 | 120.07 | 3782.97 | 10.0 | 8.00 | 94.06 | 23.04 | 0.945 |
| high_rate | 250 | 575.02 | 7247.74 | 59.0 | 47.53 | 562.71 | 136.26 | 0.705 |
| high_rate | 500 | 417.58 | 7432.41 | 44.0 | 35.46 | 419.53 | 101.63 | 0.726 |
| high_rate | 1000 | 452.42 | 8053.11 | 40.0 | 32.24 | 375.27 | 92.39 | 0.769 |
| high_rate | 2000 | 398.22 | 6897.34 | 40.0 | 32.24 | 375.26 | 92.39 | 0.920 |

All eight idle windows have zero payment polling, signing, updates, records,
attributed payment carriers and relay-journal writes. The unchanged
`prepaid-usage-v1` contract retains 15 disjoint intervals per trial, with exact
first-to-last reconciliation. Complete observed process CPU is 101,179.190 ms;
the guards/gaps contribute 190.621 ms and 584 aggregate link bytes. These costs
are retained separately from the workload rows, without subtracting a baseline.

At high rate, the 500-ms policy costs 13.68 ms of measured payment CPU per delivered
MiB and 0.244 total process CPU-seconds/MiB. Its payment carrier submissions are
0.325% of delivered application bytes. Independent window checkpoints add
50.02 ms of CPU and 151.47 KiB of relay-journal writes per high-rate window;
these are already included in process CPU and total journal counters, but not in
the payment columns above. The 1-s policy uses 9.1% fewer updates/carrier bytes
than 500 ms while measuring 8.3% more payment CPU. The two high-rate payment CPU
samples are 412.09/423.08 ms at 500 ms and 433.32/471.52 ms at 1 s. High-rate p95
delay histogram bounds are 2 ms, except one 2-s-policy trial with a 5-ms bound.
The 500-ms default remains unchanged; this is not evidence of a consistent CPU
winner or an optimal cadence.

Payment CPU includes signer loading and the new storage checks inside existing
synchronous spans. Journal bytes exclude SDK client snapshots, SQLite and
physical writes. Carrier bytes include locally attributed inner TCP segments,
acknowledgments and retransmissions; they exclude opaque transit, shared native
control, kernel encapsulation and radio airtime. Fresh profiles and offered load
do not establish sustained-history cost, maximum capacity or router performance.
The run does not isolate storage-check overhead from other changes since the
older comparison, and no optimization is justified by that historical difference.

Compilation finishes before measurement; no task builds/tests run concurrently.
The matrix takes 431.43 seconds including setup and financial cleanup, on macOS
ARM64 with 14 logical CPUs and Rust 1.96.0. Shared-host load averages fall from
19.72/10.74/7.58 to 4.25/5.51/6.10, limiting causal attribution. The release
executable SHA-256 is
`14cbb80447ed0df12b265b75ffa812445a7ce3a32d97712d1d973ec3b8bfeb7b`;
the raw report SHA-256 is
`f0ffd040e80b298ad8d53774f11d1c26cfa03f7c99415d010502ba246feff13f`.
Reproduce with the existing [loopback experiment](../../testing/relay-cadence/README.md)
and matching [development dependencies](FUNDING-COSTS.md).

## Accepted loopback comparison — 23 September 2026

Five optimized relay processes run three paid forwarding hops over loopback UDP,
with both directions funded. The four policies run twice in opposite order.
All 285,696 original payloads arrive, with no loss, duplicates, reordering, invalid
packets or rejected timestamps. All eight trials settle six channels each and
collect all 40,960 test sats. Source, dependency, lock, analyzer and executable
guards pass unchanged throughout the build and measurement.

Costs below sum the five relay processes. Payment CPU covers synchronous signing,
usage and update spans; process CPU includes their other work. Relay journal I/O
is logical and excludes Cashu SQLite and physical writes. Payment-record bytes
exclude their carrier. Locally attributed payment-service carrier submissions
include inner TCP segments, acknowledgments and retransmissions, but exclude
opaque transit, shared native control, kernel encapsulation and radio airtime.
They are not complete network or physical-wire bytes.

| Workload | Limit ms | Delivered / submitted | Payment CPU ms | Process CPU ms | Updates | Records KiB | Payment journal KiB | Local carrier KiB | Mean delay ms |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| idle | 250 | 0 / 0 | 0.00 | 446.65 | 0.0 | 0.00 | 0.00 | 0.00 | — |
| idle | 500 | 0 / 0 | 0.00 | 451.46 | 0.0 | 0.00 | 0.00 | 0.00 | — |
| idle | 1000 | 0 / 0 | 0.00 | 440.91 | 0.0 | 0.00 | 0.00 | 0.00 | — |
| idle | 2000 | 0 / 0 | 0.00 | 392.13 | 0.0 | 0.00 | 0.00 | 0.00 | — |
| bursty | 250 | 1024 / 1024 | 26.56 | 979.88 | 2.0 | 1.60 | 18.02 | 4.61 | 0.978 |
| bursty | 500 | 1024 / 1024 | 23.13 | 1010.46 | 2.0 | 1.60 | 18.05 | 4.61 | 0.904 |
| bursty | 1000 | 1024 / 1024 | 29.16 | 1048.83 | 2.0 | 1.60 | 18.11 | 4.61 | 0.866 |
| bursty | 2000 | 1024 / 1024 | 27.04 | 960.26 | 2.0 | 1.60 | 18.12 | 4.61 | 0.871 |
| steady | 250 | 6400 / 6400 | 228.72 | 3797.88 | 19.0 | 15.19 | 175.39 | 43.77 | 0.928 |
| steady | 500 | 6400 / 6400 | 226.63 | 3773.42 | 19.0 | 15.19 | 175.66 | 43.77 | 0.919 |
| steady | 1000 | 6400 / 6400 | 162.17 | 3446.81 | 14.0 | 11.19 | 130.75 | 32.25 | 0.894 |
| steady | 2000 | 6400 / 6400 | 118.64 | 3471.00 | 10.0 | 8.00 | 94.50 | 23.04 | 0.828 |
| high_rate | 250 | 64000 / 64000 | 527.73 | 6607.76 | 60.5 | 48.74 | 572.56 | 139.73 | 0.735 |
| high_rate | 500 | 64000 / 64000 | 359.62 | 6206.70 | 44.0 | 35.46 | 414.91 | 101.63 | 0.729 |
| high_rate | 1000 | 64000 / 64000 | 327.42 | 5897.56 | 40.0 | 32.24 | 374.97 | 92.39 | 0.726 |
| high_rate | 2000 | 64000 / 64000 | 357.53 | 6498.45 | 40.0 | 32.24 | 376.59 | 92.39 | 0.769 |

Delivery totals combine both repetitions; other values are means per workload
window. All windows include the same three-second payment tail; idle also
includes four quiet application seconds. These are offered workloads, not maximum
capacity. The eight idle windows produce no payment polling, signing, updates,
payment records, attributed payment carriers or relay-journal writes.

### Complete observation boundaries

This run explicitly declares `boundary_accounting: "prepaid-usage-v1"`.
Each trial retains 15 disjoint intervals from the first idle guard through the
final high-rate guard. Per-node and total integer counters reconcile exactly
with the first-to-last readings. Setup, funding and settlement stay outside
these observation bounds. Snapshots are non-atomic observations.

Between workload windows, only monotonic usage already covered by unchanged
acknowledged credit is permitted; authorization, acknowledgments and membership
must remain unchanged, with no payment in flight. All payment/open/stop operations
and journal changes remain rejected. Delivery, credit limits and the common tail
are unchanged. Original reports without this contract retain strict equality.
Hardware reports retain their existing validation and cannot opt into this
schema-2 contract. JSON retains the complete costs; the old Markdown generator
rejects this contract rather than omit its additional intervals.

| Policy ms | Complete observed process CPU ms | Guard/gap CPU ms | Guard/gap link bytes |
| --- | ---: | ---: | ---: |
| 250 | 11856.829 | 24.654 | 0 |
| 500 | 11467.135 | 25.096 | 0 |
| 1000 | 10855.390 | 21.277 | 334 |
| 2000 | 11345.270 | 23.420 | 0 |

These are means per complete trial. Across eight trials the guards and gaps add
188.895 ms of process CPU and 668 aggregate link bytes. They contain no payment
carrier or prepaid-usage increments in this fresh run; the separate native idle
diagnostic below and boundary tests exercise covered usage growth. Complete
observed process CPU totals 91,049.249 ms. Payment CPU is part of process CPU,
and journal details are already included in operation totals; do not add them
again. The 120 analyzer tests and an independent static review pass.

### Conclusions and limits

At high rate the 500-ms policy averages 44 updates, 359.62 ms of measured payment
CPU and 101.63 KiB of locally attributed payment carrier submissions. The 1-s
policy averages 40 updates, 327.42 ms and 92.39 KiB: about 9% fewer updates/carrier
bytes and 9% less measured payment CPU in this workload. The corresponding total
process costs are 0.203 and 0.193 CPU-seconds per delivered MiB, including the
common tail and all five processes. This does not establish a router cost.

The 250-ms policy uses 60/61 high-rate updates; both 1-s and 2-s runs use 40.
All high-rate p95 one-way delay histogram bounds are 2 ms. Monetary thresholds
can trigger before the maximum payment age; a 2-s policy does not imply waiting
two seconds under growing debt. Hard credit and spending bounds stay unchanged.

| Maximum age | Payment CPU ms, two runs | Process CPU ms, two runs | All journal writes, two runs |
| --- | --- | --- | --- |
| 250 ms | 533.17 / 522.30 | 6,681.43 / 6,534.09 | 284 / 283 |
| 500 ms | 360.61 / 358.64 | 6,171.45 / 6,241.96 | 236 / 236 |
| 1000 ms | 301.70 / 353.13 | 5,485.77 / 6,309.36 | 221 / 221 |
| 2000 ms | 340.21 / 374.84 | 6,144.33 / 6,852.57 | 222 / 221 |

The run uses macOS ARM64, 14 logical CPUs and Rust 1.96.0. Compilation completes
before measurement, with no concurrent tests/builds from this task. Unrelated
host activity remains: initial load averages are 14.75/7.95/6.31, falling to
4.19/5.29/5.61. Two repetitions on a shared host do not establish an optimal
policy or attribute changes since the older build to an individual optimization.
The 500-ms production default remains unchanged. Physical-device performance,
impaired-link costs and complete payment wire attribution remain separate work.

The matrix takes 432.97 seconds including setup and financial cleanup. Executable
SHA-256: `36f174e1dc5ab04e2ece5b643f015b63db8f5e9249b36b722fc74080e206b5b8`.
Raw report SHA-256:
`81cb100ef84abafd0ba06be7fe1aeb2e632392bd32866e10699e53e453b99189`.
This replaces the 17 September loopback table; its historical raw evidence and
prior document revision remain retained. Unfunded return bootstrap has separate
acceptance coverage.

## Rejected loopback refresh — 22 September 2026

The refresh on the integrated routing fixes **failed strict measurement
acceptance**. All 285,696 original payloads arrived and all 40,960 test sats were
collected, but the report omitted the metadata declaration for payment-service
carrier counters already present in its snapshots. The harness now declares
that instrumentation and its local-submission scope. The original raw report
remains unchanged and rejected.

A diagnostic replay with only that declaration supplied still fails: buyer
usage evidence advances by one msat between idle and bursty in trials 4 and 6.
Payment-port traffic and payment-operation counters do not change across either
gap. Periodic end-to-end path-MTU checks are a source-level candidate: they use
billed session envelopes, and their ten-second interval coincides with setup
plus idle and its tail. The aggregate snapshots do not identify those packets,
so the exact cause in that untraced report remains unconfirmed. Neither replay
alters its raw evidence or rejected status. The subsequent comparison above
declares its accounting contract before measurement and uses fresh accounts.

A 23 September native idle diagnostic reproduces this kind of accounting change.
Each endpoint completes 216 tracked session bytes: a 36-byte path-MTU
confirmation, an 80-byte sender report and a 100-byte receiver report. Across
137 observations over sixteen seconds, three buyers consume one additional msat
of previously acknowledged credit. Authorizations and acknowledgments remain
unchanged, as do all payment records, attributed carriers, measured operations
and journal counters. All six channels settle and all 5,120 test sats are
collected. This trace identifies actual billable upkeep in the diagnostic; it
does not identify the packets in the earlier untraced report or retrospectively
accept that matrix. The reproducible command is in the
[experiment instructions](../../testing/relay-cadence/README.md#native-idle-control-diagnostic).

## Hardware comparison — 18 September 2026

The full three-router comparison **failed strict clean-link acceptance**. All
eight trials and 32 workload windows were collected, but only 93,693 of 93,696
submitted application packets arrived. The original failed result and raw
measurements are retained; no packets were resent and no workload, allowance or
settling window was enlarged to hide the loss.

| Trial, zero-based | Maximum age | Workload | Submitted | Delivered | Missing |
| --- | ---: | --- | ---: | ---: | ---: |
| 4 | 2,000 ms | High rate | 8,000 | 7,998 | 2 |
| 5 | 1,000 ms | Steady | 3,200 | 3,199 | 1 |

All other workload payloads arrived. Across the matrix, 40 packets arrived out of
order; there were no duplicate or invalid packets. The deficits persisted through
the three-second tail and final guard. Payment acknowledgments covered recorded
liability, and the failed windows had no controller error, process restart or
measured-link epoch change. Existing logs and aggregate counters do not identify
a precise loss cause. They do not establish that payment cadence caused the loss.

Each trial settled both original 32-sat channels and collected all 384 issued
test sats: 3,072 in total. Every test mint stopped and all original router
baselines were restored. All 2,175 management observations passed; no cleanup
error was recorded. The preceding single 250-ms pilot passed strict validation,
delivered all 11,712 packets and collected its separate 384 test sats. That pilot
does not replace the failed full comparison.

The devices were three Cudy TR3000 v1 routers running OpenWrt 25.12.5 on ARM64.
An optimized Rust 1.96.0 musl build with the measurements feature used native
Ethernet over a forced two-hop 802.11s path. Both directions were funded, with
one paid middle router. The fixed hardware workload offers 8,000 high-rate
packets, rather than the loopback fixture's 32,000; results are not directly
comparable across those topologies and workloads. Executable SHA-256:
`bea373ae88988a04f4fa48607eefebb67b265c10546f41461571cf12c31fda79`.

Separate router clocks leave application one-way latency unmeasured. Saved
neighboring-link smoothed RTT estimates ranged from 3 to 6 ms across boundaries.
They use local timestamp echoes, include earlier traffic, and lack sample-age
information in these snapshots; they are not end-to-end latency or percentiles.
These kernels omit `/proc/PID/io`, so OS process I/O is explicitly unavailable,
not zero. Logical relay journal counts retain their narrower documented scope.
Exposed source peer sent-byte counters also omit some application traffic in
these observations; their aggregate cannot establish complete carrier bytes.

One guard pair reported VmHWM and RSS falling from 24,592 to 24,576 KiB with the
same process identity. Linux's RSS/high-water sampling permits such a decrease;
the specific cause in this kernel build is unproven. The analyzer retains both
raw values and the decrease rather than treating this gauge as a monotonic
integrity counter. The three missing packets still reject the comparison.

### Diagnostic costs from the rejected matrix

Diagnostic replay retains all 32 workload windows and exits unsuccessfully with
`accepted: false`. It permits reporting the measured costs of the two lossy
windows while retaining every other validation requirement. These observations
do not establish an accepted clean-link comparison or an optimal policy.

The table shows high-rate observations, summing CPU across all three routers.
Delivery totals combine both repetitions; paired CPU values retain the two
observations in trial order. Update, record and payment-journal counts were the
same in both repetitions of each policy.

| Maximum age | Delivered / submitted | Payment CPU ms, two runs | All relay CPU ms, two runs | Updates per run | Payment records KiB per run | Payment journal writes per run |
| --- | ---: | --- | --- | ---: | ---: | ---: |
| 250 ms | 16,000 / 16,000 | 206.50 / 208.14 | 5,670.35 / 5,633.01 | 4 | 3.20 | 16 |
| 500 ms | 16,000 / 16,000 | 159.50 / 158.71 | 5,507.53 / 5,669.84 | 3 | 2.41 | 12 |
| 1,000 ms | 16,000 / 16,000 | 104.57 / 105.05 | 5,620.27 / 5,566.03 | 2 | 1.60 | 8 |
| 2,000 ms | 15,998 / 16,000 | 103.28 / 101.76 | 5,681.32 / 5,661.20 | 2 | 1.60 | 8 |

All eight steady windows used three payment updates and twelve payment-journal
writes, with mean payment CPU between 154.25 and 154.89 ms across policy pairs.
Idle and bursty windows recorded no payment updates, payment CPU or payment
journal writes. Bursty traffic consumed existing prepaid credit from setup;
these zero incremental payments do not mean free forwarding. Workload CPU
includes the common three-second tail. Record bytes exclude transport/carrier
framing; journal counts exclude SDK/SQLite and physical storage writes. The
saved diagnostic JSON retains per-node CPU per delivered MiB, goodput, raw
memory readings and all individual window results.

No production default or optimization is selected from this rejected matrix.
The follow-ups below add native counters and existing dataplane drop logs to
distinguish recorded failure classes. Neither automatically identifies a radio
or driver fault.

## Hardware diagnostics

### Native-counter diagnostic follow-up

A separate 2,000-ms pilot retained the same four hardware workloads and captured
the existing native status/routing counters inside every process-identity guard.
All 11,712 submitted packets arrived and strict pilot validation passed. Its
two channels settled, all 384 test sats were collected, the mint stopped and
router baselines were restored. All 264 management observations passed with no
cleanup errors. This single trial does not replace the rejected matrix or prove
that its intermittent loss is resolved.

The middle router counted 534, 3,222 and 8,011 forwarded native packets in the
bursty, steady and high-rate windows respectively, including control traffic.
No recorded forwarding-drop/error reason advanced in the windows or guard gaps.
However, endpoint received/delivered counters remained zero despite successful
application delivery, and source-originated counters omitted most application
traffic. These native counters do not cover the optimized endpoint path. The
Ethernet transport also provides no kernel receive-drop signal to the native
congestion API. Neither zero can establish absence of loss. The following
comparison enables existing dataplane drop events to observe failures on paths
these counters miss.

### Full comparison with pinned drop logs

A separate eight-trial comparison passed strict validation with all **93,696 of
93,696** submitted packets delivered. There were 53 out-of-order packets, no
duplicates or invalid packets, and no controller errors. Every trial reconciled
its two original channels and collected all 384 issued test sats: 3,072 in total.
All mints stopped, all router baselines were restored, and all 2,157 management
observations passed without cleanup errors.

This retained the preceding matrix's optimized binary, topology, workloads,
funding bounds, policy order and three-second tail. Every trial used the same
native counter sampling and pinned dataplane debug filter. No compilation or
other tests from this task ran during measurement. Process checks attested the filter;
recorded byte offsets place each saved log relative to the measurement windows.
All 112 recorded harness-file hashes matched the unchanged source after the run.

No native drop, congestion or error counter advanced during the windows or
their guarded gaps. No log bytes were added from each trial's first measurement
guard to its last. After those spans, the saved logs contain 14 `SourcePolicy`
packet-drop events and eight `Unrouted` raw-ingress events. They demonstrate
active logging, but cannot explain the earlier matrix's missing packets. This
clean run does not erase that rejected result or establish the cause of its
intermittent loss. Unobserved radio/kernel loss remains outside these counters.

High-rate costs below sum all three router processes. CPU values retain both
repetitions; updates and logical payment-journal writes were identical across
each pair. Every high-rate window delivered all 8,000 packets.

| Maximum age | Payment CPU ms, two runs | All relay CPU ms, two runs | Updates per run | Payment records KiB per run | Payment journal writes per run |
| --- | --- | --- | ---: | ---: | ---: |
| 250 ms | 198.21 / 206.47 | 5,457.46 / 5,730.38 | 4 | 3.20 | 16 |
| 500 ms | 156.98 / 157.10 | 5,712.79 / 5,446.54 | 3 | 2.41 | 12 |
| 1,000 ms | 104.32 / 101.32 | 5,634.87 / 5,516.32 | 2 | 1.60 | 8 |
| 2,000 ms | 101.24 / 103.24 | 5,562.07 / 5,712.76 | 2 | 1.60 | 8 |

At high rate, 1 s and 2 s halve payment updates and their attributed journal
writes relative to 250 ms. Attributed payment CPU is about 1.8% of all measured
relay CPU, versus about 3.6% at 250 ms. Total CPU ranges overlap; this does not
demonstrate a reduction in total forwarding cost. All measured CPU, including
the common tail, ranges from 0.714 to 0.751 CPU seconds per delivered MiB across
these high-rate windows. These are offered-load observations, not capacity.

All steady windows used three payment updates. Idle and bursty windows recorded
no payment CPU, updates, records or payment-journal writes; bursty traffic used
existing prepaid credit. Record bytes still exclude TCP/FIPS/carrier framing,
and journal counts exclude SDK/SQLite and physical storage writes. Separate
router clocks still leave one-way application latency unmeasured. Two raw
VmHWM decreases were retained without weakening process or counter checks.

The 500-ms default remains unchanged. Two repetitions with diagnostic sampling
establish this bounded comparison, not an optimal universal payment age or
proof that the earlier packet loss is resolved.

## Matched storage syscall comparison — 19 September 2026

The separate Linux ARM64 storage comparison passes all eight trials: maximum
payment ages of 250/500/1000/2000 ms followed by the reverse order. All 93,696
application packets arrive, with 101 out of order and no duplicates or invalid
packets. Each trial settles its original two 32-sat channels and collects all
384 test sats; the complete matrix conserves 3,072 sats. Independent replay of
all 96 raw traces matches the saved summaries, settlement and wallet equations
reconcile, and all 40 owned containers/networks are absent after cleanup.

The fixture uses three relay processes and native Ethernet over virtual links,
with the same finite workloads as the hardware comparison and a fixed three-second
tail. The tariff is 1 msat/KiB. The optimized relay executable is unchanged during
measurement (SHA-256 `9a17f2df6a147028ad894724e2d0dcd89a39ab8deb93e4c214f39a7e89ca1ce2`).
No task builds or tests run concurrently. These are successful syscall write
lengths and sync calls, not physical media writes or flash wear. Tracing changes
execution cost; its CPU/timing observations are not compared with the untraced
Wi-Fi experiment. The virtual carrier, platform and warmup also differ.

All eight idle and all eight bursty windows have zero payment updates, file
writes and syncs. Bursty traffic consumes already-paid credit; its metered usage
still increases. Every steady window delivers 3,200,000 bytes, performs three
updates and 42 syncs, and writes between 140,225 and 140,655 bytes. Each high-rate
window delivers 8,000,000 bytes. The pairs below retain both repetitions in trial
order; file writes include independent allowance checkpoints as well as payments.

| Maximum age | Updates | SDK snapshot bytes | Receiver SQLite bytes | Relay journal bytes | Total file bytes | File/directory sync calls |
| --- | --- | --- | --- | --- | --- | --- |
| 250 ms | 3 / 4 | 45,344 / 60,459 | 50,772 / 67,696 | 51,606 / 53,154 | 147,722 / 181,309 | 46 / 58 |
| 500 ms | 3 / 3 | 45,344 / 45,344 | 50,772 / 50,772 | 45,444 / 52,439 | 141,560 / 148,555 | 46 / 46 |
| 1,000 ms | 2 / 2 | 30,229 / 30,229 | 33,848 / 33,848 | 30,952 / 31,434 | 95,029 / 95,511 | 34 / 34 |
| 2,000 ms | 2 / 2 | 30,229 / 30,230 | 33,848 / 33,848 | 36,557 / 55,105 | 100,634 / 119,183 | 34 / 44 |

Funding-wallet SQLite files have zero writes or syncs in every workload window.
The 1-second high-rate pair writes about 0.0119 file bytes per delivered application
byte, versus 0.0177–0.0186 at 500 ms. Fewer updates reduce SDK/receiver writes;
independent checkpoints and snapshot lengths also affect the total. Two seconds
does not consistently reduce total writes further. These two traced repetitions
do not establish an optimal policy; the production default remains 500 ms.

Every boundary verifies unchanged authorization, acknowledged credit, payment
activity and all durable-operation counters. Already-covered usage may advance
without another payment: six msat of such usage appear outside the workload
windows and are reported separately, never subtracted from workload cost. Five
explicit tracer detach events interrupt event-counter writes; they are counted
separately without inventing successful bytes. All file operations are complete
and attributed, and all traced processes survive clean detachment.

The preceding matrix attempt stopped on its fourth trial because its guard
incorrectly required already-covered usage to remain fixed between windows.
It remains an incomplete result; all 1,536 test sats from its four trials were
collected. The corrected guard permits only monotonic covered usage, preserving
all payment, credit and durability checks. A fresh pilot and this complete matrix
pass that guard. See the [capture contract](../../testing/relay-cadence/README.md#matched-storage-cadence-capture).

## Payment connection costs on Wi-Fi — 19 September 2026

The new eight-trial capture retains **93,694 of 93,696** delivered application
packets. It fails strict clean-link acceptance: the first 64-packet burst in the
first 1-second trial delivers 62 packets. All other workload packets arrive,
with 50 reordered packets and no duplicates, invalid packets or controller
errors. Diagnostic analysis preserves this rejection while checking the other
measurement and financial requirements; it does not convert the matrix into a
passing comparison. No measured packet is retried.

All 3,072 test sats are collected, all original router baselines are restored,
and all 2,064 management observations pass. The original profiles match across
all eight trials. All 32 owned local mint/forwarding processes are absent after
cleanup. Independent replay matches every local payment-carrier total and guard
gap, as well as the delivery rejection and terminal financial evidence. The
preceding 500-ms pilot separately delivers all 11,712 packets, collects its 384
test sats and passes 258 management observations.

This uses the same three-router native Ethernet/802.11s fixture, workload sizes,
opposite-order repetitions and fixed three-second tail. The optimized ARM64 musl
relay is built from `6024f980` with Rust 1.96.0 and `measurements`; executable
SHA-256 is `36fb95e2200eb5aaf45b0b343d7cd11f16e9338df7ec2d88dd62c77a2b902583`.
Matching relay/mint inputs and artifacts remain unchanged during the run. No
task compilation or tests run concurrently with the measurement.

The new counters attribute local submissions to payment service 44743. They
include its TCP/FIPS segments, connection setup/close, acknowledgments and
retransmissions, with the three-byte Ethernet transport prefix added separately.
They exclude opaque transit, shared native handshakes/MMP/rekeys, kernel/link
encapsulation and retries, and radio airtime. These are local payment-connection
bytes, not complete physical wire bytes. The analyzer requires positive
cumulative Ethernet evidence for each node with recorded payment-service sends;
zero activity within an idle window remains valid.

Each high-rate window delivers 8,000,000 application bytes. Costs sum the three
service processes; paired values retain both repetitions in trial order.

| Maximum age | Updates | Payment CPU ms | All relay CPU ms | Local payment packets | Local payment bytes | Payment journal bytes |
| --- | ---: | --- | --- | ---: | --- | --- |
| 250 ms | 4 | 200.41 / 213.60 | 5,476.88 / 5,737.63 | 104 | 9,753 / 9,755 | 46,543 / 49,732 |
| 500 ms | 3 | 160.85 / 156.86 | 5,789.39 / 5,721.32 | 78 | 7,317 / 7,317 | 32,658 / 29,345 |
| 1,000 ms | 2 | 108.64 / 109.26 | 5,875.55 / 5,603.02 | 52 | 4,878 / 4,878 | 21,630 / 21,047 |
| 2,000 ms | 2 | 101.31 / 104.23 | 5,605.90 / 5,693.97 | 52 | 4,878 / 4,878 | 20,348 / 19,485 |

At high rate, 1 second uses one-third fewer payment-connection bytes and about
31% less synchronous payment CPU than 500 ms in these observations. Total relay
CPU ranges overlap. Local payment bytes equal about 0.0915% of delivered bytes
at 500 ms and 0.0610% at 1 second; application records alone are only 2,463 and
1,642 bytes respectively. Logical payment-journal writes are 16/12/8/8 per
window across the four ages, with twice as many attributed syncs. They exclude
SDK/SQLite and physical writes; payment CPU retains its synchronous-span limits.

Every steady window uses three updates, 2,454 payment-record bytes and 7,308
local payment-connection bytes. Idle and bursty windows have zero payment
requests, records, carrier submissions and payment-journal writes. Bursts consume
existing acknowledged credit. No payment-carrier discards or carrier activity
appear in the guarded gaps.

The lost burst has no payment activity, native drop/error increment or new drop
log bytes. These observations do not identify the loss cause: optimized endpoint
and kernel/radio loss remain outside the legacy native counters. A separate,
fully delivered burst in the second 500-ms trial records 129 congestion marks
at the middle router. Neither observation establishes payment cadence as the
cause of the missing packets. The 500-ms default remains unchanged. This rejected
matrix, two stable-topology repetitions and unmeasured hardware one-way latency
do not establish an optimal policy, maximum capacity or seamless mobility.

## Supplemental burst observation — 20 September 2026

A fresh 1-second pilot reuses the exact `6024f980` relay and matching test mint
above, with a separately verified newer harness. This investigates that historical
build; it is not acceptance evidence for newer native code. The optional
`--post-gap-probes` mode reads each burst's receiver once more after its existing
800-ms quiet gap and before arming the next stream. Original delivery results
remain unchanged, and no payload is resent.

The pilot **fails strict acceptance at 11,711 of 11,712 packets**. The sixth burst
delivers 63 of 64 packets, and the supplemental snapshot still reports 63. Its
request starts 810.12 ms after the primary response returns and finishes another
164.10 ms later. These controller intervals bracket receiver snapshots, not exact
packet arrival times. All other bursts and all 11,200 steady/high-rate packets
arrive. All eight supplemental reads report zero additional packets. Thus this
reproduced deficit persists beyond the quiet gap; this does not locate the loss
or retroactively explain the earlier failed matrix.

The burst window has no payment activity, payment-service submissions, controller
errors, native drop/error/congestion increments or new dataplane log bytes. The
middle router's 534 received and 534 forwarded packets include control traffic
and cannot identify the missing payload. Endpoint/kernel counter coverage remains
incomplete, so zero counters do not prove delivery at those layers.

All 384 test sats are collected, 264 management checks pass, and independent live
reads match every original router field plus the fuller pretrial radio-limit
snapshot. The mint and three forwarding processes are absent after cleanup.
The harness passes 65 focused Linux tests and the analyzer passes 99, including
late-arrival cases that preserve strict rejection. Eight extra status reads total
1.475 seconds of controller wall time; their control work and added spacing make
this a diagnostic capture, not a matched cost comparison with earlier runs. The
500-ms production default and both failed measurement results remain unchanged.

## Socket and data-service observation — 20 September 2026

A fresh 1-second pilot uses a matched `62a639370` router/test-mint pair, with
all 1,800 recorded source inputs matched to the preceding verification gates.
The `740c2308` harness adds `show_transports` inside each existing process-bound
sample. It retains complete adapter replies alongside the existing data-service
carrier and application counters. This adds 48 adapter queries across the four
workloads; the eight supplemental burst observations remain enabled. Per-burst
reads still contain probe results only, so adapter/carrier attribution is limited
to the workload boundaries and guarded gaps.

The pilot **passes strict acceptance with all 11,712 packets delivered**:

| Workload | Probe packets submitted / received | Source Ethernet submissions | Destination application packets | Socket drops, all nodes |
| --- | ---: | ---: | ---: | ---: |
| Idle | 0 / 0 | 0 | 0 | 0 |
| Bursty | 512 / 512 | 512 | 512 | 0 |
| Steady | 3,200 / 3,200 | 3,200 | 3,200 | 0 |
| High rate | 8,000 / 8,000 | 8,000 | 8,000 | 0 |

Every adapter sample reports an available cumulative socket-drop count and an
effective `SO_RCVBUF` of 425,984 bytes (416 KiB). No socket drops, data-carrier
discards, data-service submissions or application receptions occur in the guarded
gaps. The forwarding-only middle router and passive destination record no locally
originated data-service submissions. Socket drops also remain zero throughout all
workload windows. Equal source submissions and receiver counts are consistent
with this clean run; successful source submission alone would not prove delivery.

All 384 test sats are collected, every test wallet is empty, and all 267 management
checks pass without cleanup errors. Independent live reads match all original
router baselines and confirm Internet/DNS access. The mint and three forwarding
processes are absent, and source, inventory and executable hashes remain unchanged.
The updated capture passes 65 Linux harness tests and 101 analyzer tests; historical
two-reply native snapshots remain readable without inventing socket measurements.

This is one clean diagnostic pilot on newer code, not a reproduction or explanation
of the historical intermittent loss. The earlier rejected captures remain unchanged.
The new build and additional adapter queries preclude a matched cost comparison
with those captures. No cadence default, receive-buffer optimization, capacity
claim or mobility claim follows from this result.

### Full socket-observed comparison

The subsequent eight-trial comparison uses the same matched `62a639370` binaries
and capture code, in forward/reverse order: 250, 500, 1,000, 2,000, 2,000, 1,000,
500 and 250 ms. No builds, tests or simulations ran concurrently. It **fails
strict delivery acceptance**: 93,332 of 93,696 packets arrive. The first 250-ms
steady stream receives 2,836 of 3,200 packets; every other stream, including the
second 250-ms trial, is complete. There are 55 out-of-order packets and no
duplicates or invalid packets. This establishes intermittent loss in this run,
not a causal relationship with payment cadence.

All 32 workload windows have source data-service Ethernet submissions equal to
probe submissions, and destination application counts equal to probe reception.
All recorded socket-drop counts remain zero, with the effective receive buffer
unchanged at 416 KiB. In the failed steady window, the middle-to-destination peer
counters show 3,234 packets sent versus 2,870 received: a 364-packet, 404,040-byte
deficit. Adapter frame totals independently differ by 364 frames and 405,132
bytes, including the three-byte Ethernet transport prefix. Adapter totals on
the incoming leg balance. These are aggregate, non-atomic observations, not
per-packet delivery receipts.

The middle router records 805 congestion markings and one matching warning,
with no reported native drops or receive-socket overflow. The same steady probe
still reports 2,836 packets over 3.76 seconds after the primary observation,
before the next stream is armed. This narrows the discrepancy to middle output
through destination ingress; it does not identify a transmit queue, driver or
radio cause. The congestion markings alone do not establish causality.

Diagnostic costs below sum all three processes across each trial's four workload
windows, including the common tails and excluding setup and settlement. They
remain part of a rejected delivery comparison. Carrier bytes count local payment
service submissions, including TCP/FIPS framing and Ethernet prefixes, but not
opaque transit or physical radio overhead. Journal bytes are attributed logical
writes, excluding SDK snapshots, SQLite and physical storage writes.

| Trial | Maximum age ms | Packets received / submitted | Payment CPU ms | Updates | Payment carrier KiB | Payment journal KiB |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| 1 | 250 | 11,348 / 11,712 | 369.88 | 7 | 16.66 | 70.46 |
| 2 | 500 | 11,712 / 11,712 | 317.10 | 6 | 14.28 | 61.33 |
| 3 | 1,000 | 11,712 / 11,712 | 258.59 | 5 | 11.90 | 45.31 |
| 4 | 2,000 | 11,712 / 11,712 | 252.53 | 5 | 11.90 | 46.74 |
| 5 | 2,000 | 11,712 / 11,712 | 257.64 | 5 | 11.90 | 50.81 |
| 6 | 1,000 | 11,712 / 11,712 | 272.53 | 5 | 11.90 | 47.24 |
| 7 | 500 | 11,712 / 11,712 | 321.18 | 6 | 14.28 | 61.94 |
| 8 | 250 | 11,712 / 11,712 | 355.67 | 7 | 16.66 | 72.58 |

Every trial collects all 384 issued test sats before the next starts: 3,072 total,
with every test wallet empty. All 2,091 management checks and cleanup checks pass.
Independent final reads match the original router configurations, accounts and
radio state, with Internet/DNS available; all owned local mint and forwarding
processes are absent. Source, inventory, executable and earlier raw-capture hashes
remain unchanged. The strict rejection is retained, and the 500-ms default is
unchanged. The follow-up below adds bounded station retry/failure, interface-drop
and available queue observations; reproducing loss with these observations remains
necessary to distinguish the remaining possibilities.

### Link-counter pilot

A fresh 250-ms pilot uses the same matched `62a639370` binaries and the
`674fe5e1a` harness with optional `--link-loss-counters`. It passes strict
acceptance: all 11,712 packets arrive across idle, bursty, steady and high-rate
workloads. No builds, tests or simulations ran concurrently. The capture adds
bounded station, interface and available queue reads on the middle router and
destination inside the existing process-bound workload/guard snapshots. All
15 compared workload/gap windows retain comparable interface and station epochs.

Middle-to-destination station `tx retries` and `tx failed` increase equally:
4 during idle, 142 during bursts, 587 during steady traffic and 446 at high rate.
These driver counters include other traffic and are not independent counts of
missing application packets: every application packet arrives in this pilot.
Both routers' interface transmit/receive drop and error deltas remain zero in
the four workload windows, as do recorded receive-socket drops. The queue tool
`tc` is absent, so queue statistics are explicitly unavailable; no package is
installed. Cross-router reads are not simultaneous and do not identify individual
packet outcomes.

A subsequent read-only inspection reports mt7915e/mt76 package revision
`39c960c3-r2` and the `wed_enable` parameter set to `N`. The matching
[non-WED transmit-completion code](https://github.com/openwrt/mt76/blob/39c960c3ada558b4c2e7915772483d3731573d09/mt7915/mac.c#L914-L929)
adds retries to both counters, then adds the failure-status bit to `tx_failed`.
This explains why equal increments can coexist with complete delivery. The
post-run parameter read is not a historical offload-state trace, and the counter
relationship does not locate the earlier missing packets.

All 384 test sats are collected and every wallet is empty. All 261 management
checks pass, cleanup has no errors, and independent final reads match every
original router baseline with Internet/DNS available. The mint and forwarding
processes are absent. Source, executable, inventory and prior-capture hashes
remain unchanged. The optional capture passes 82 Linux harness and 101 analyzer
checks. This clean pilot validates the added observations but does not reproduce
or explain the preceding 364-packet deficit. Strict rejection of that comparison
and the 500-ms production default remain unchanged.

### Software-queue observation pilot

A subsequent 250-ms pilot uses the same matched `62a639370` binaries and the
`840c31ee5` harness with `--link-loss-counters --aqm-counters`. All 11,712 packets
arrive and strict acceptance passes. The optional AQM capture passes 90 Linux
harness and 101 analyzer checks. The recovery changes integrated into the newer
source are not present in these frozen executables; this experiment does not
verify those changes on hardware.

The middle router's raw per-destination mac80211 queue table is available and
untruncated at all four steady-workload boundaries. Interface, radio and station
association identity remain stable. Across all 16 traffic identifiers, each
snapshot has zero queued bytes/packets and RUN flags. During the measured steady
window, traffic identifier 0 adds 3,259 transmitted packets, 3,717,631 transmitted
bytes and 3,249 new flows; drops, marks, overlimit events and collisions do not
increase. The before/after guard gaps add no table-counter changes. These tables
include other traffic, and their packet/byte counts are not application delivery
receipts. Boundary snapshots cannot exclude transient queueing between reads or
loss later in the driver, firmware, radio or receiver.

All 384 test sats are collected and every wallet is empty. All 258 management
checks pass; cleanup has no errors. Independent final reads match the original
router settings, accounts and radio state, with Internet/DNS available and owned
processes absent. Source, inventory, artifact and earlier-capture hashes are
unchanged, and no builds, tests or simulations ran during measurement. This
validates bounded queue observation on the hardware, but the earlier intermittent
364-packet loss was not reproduced. Its cause and strict rejection remain open;
the 500-ms default is unchanged. The added observations are diagnostic overhead,
not a matched performance improvement.

### Full software-queue observed comparison

The eight-trial AQM comparison uses the same frozen `62a639370` binaries and the
`c87c3059` harness. It repeats 250, 500, 1,000 and 2,000-ms policies in forward and
reverse order. All 93,696 packets arrive and strict acceptance passes. All 3,072
test sats are collected, every test wallet is empty, and all 2,091 management
checks pass. Independent final reads verify restored router baselines and
Internet/DNS, with owned processes absent and no cleanup errors. Source, artifact
and prior-capture hashes remain unchanged; no builds, tests or simulations run
concurrently with the measurements.

All 32 steady-boundary queue captures are usable, retaining stable observed
interface, process and association identity within each trial. TID0 advances by
3,254–3,262 packets and 3,716,892–3,718,082 bytes per steady window; other TIDs
remain unchanged. Drops, marks and overlimit counters stay zero. Every snapshot
shows zero backlog and RUN, without STOP. Three steady windows each add one
flow-hash collision; these are not evidence of radio collisions. Some guard
gaps add 1–7 queue packets, so the observations include other traffic.

The earlier 364-packet deficit is not reproduced or explained. Boundary snapshots
can miss transient queueing or stoppage, and these queue totals are not delivery
receipts. This clean comparison does not establish a performance improvement,
seamless mobility or hardware acceptance of later recovery changes. The earlier
strict rejection is retained, and the production default remains 500 ms.

## Reproduction and remaining evidence

See the [experiment instructions](../../testing/relay-cadence/README.md) for fixed
terms, workloads, report validation and measurement boundaries. Setup and settlement
are excluded; the identical three-second payment tail is included. Application
packets are never retried. Financial conservation is required for every trial.
The report also retains normalized CPU, logical journal bytes and payment record
bytes per delivered byte, plus CPU per completed update within each window.

Synchronous payment CPU includes signing and synchronous SDK/receiver persistence,
but excludes scheduling, control-envelope serialization outside the spans and
transport work. Logical journal counters exclude SDK JSON snapshots and
receiver/wallet SQLite; the separate syscall comparison above measures those
file operations, still excluding physical storage writes. Framed payment records
exclude TCP/FIPS/carrier headers, acknowledgments and retransmissions; the local
payment-service counters above add those submissions within their stated scope.
Aggregate link bytes cannot establish payment-specific wire overhead. Broader
impairment/device acceptance, actual radio airtime and complete CPU/storage/wire
attribution remain work for production readiness.

The earlier 16 September schema-1 result remains in repository history. It reported
complete delivery and conservation but did not verify payment boundaries; it must
not be retroactively treated as passing the schema-2 checks or directly compared
as a performance baseline across the changed build and dependencies.
