# Paid-relay cadence measurements

## Accepted loopback comparison — 17 September 2026

Optimized build: **True**. Two opposite-order repetitions; five real service processes and three paid relays over loopback UDP.

All costs below sum the five service processes. CPU is measured CPU time. Payment CPU covers synchronous signing, usage handling and balance update handling; it excludes scheduler, control-envelope serialization outside those spans, and transport CPU. Storage is logical relay journal I/O, excluding Cashu SQLite and physical writes. Record bytes exclude TCP/FIPS/carrier overhead. These are offered workloads, not maximum throughput.

| Workload | Limit ms | Delivered / submitted | Payment CPU ms | All CPU ms | Updates | Payment records KiB | Payment journal writes | Mean delay ms |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| idle | 250 | 0 / 0 | 0.00 | 355.77 | 0.0 | 0.00 | 0.0 | — |
| idle | 500 | 0 / 0 | 0.00 | 349.91 | 0.0 | 0.00 | 0.0 | — |
| idle | 1000 | 0 / 0 | 0.00 | 365.48 | 0.0 | 0.00 | 0.0 | — |
| idle | 2000 | 0 / 0 | 0.00 | 373.68 | 0.0 | 0.00 | 0.0 | — |
| bursty | 250 | 1024 / 1024 | 31.68 | 953.90 | 2.0 | 1.60 | 8.0 | 0.828 |
| bursty | 500 | 1024 / 1024 | 32.34 | 884.70 | 2.0 | 1.60 | 8.0 | 0.736 |
| bursty | 1000 | 1024 / 1024 | 32.70 | 892.82 | 2.0 | 1.60 | 8.0 | 0.819 |
| bursty | 2000 | 1024 / 1024 | 29.20 | 917.43 | 2.0 | 1.60 | 8.0 | 0.749 |
| steady | 250 | 6400 / 6400 | 229.44 | 3241.05 | 19.0 | 15.19 | 76.0 | 0.739 |
| steady | 500 | 6400 / 6400 | 228.57 | 3281.94 | 19.0 | 15.19 | 76.0 | 0.741 |
| steady | 1000 | 6400 / 6400 | 151.80 | 3105.35 | 14.0 | 11.19 | 56.0 | 0.748 |
| steady | 2000 | 6400 / 6400 | 105.50 | 3202.93 | 10.0 | 8.00 | 40.0 | 0.753 |
| high_rate | 250 | 64000 / 64000 | 463.01 | 5634.83 | 59.0 | 47.53 | 236.0 | 0.592 |
| high_rate | 500 | 64000 / 64000 | 423.98 | 6669.71 | 44.0 | 35.46 | 176.0 | 0.746 |
| high_rate | 1000 | 64000 / 64000 | 315.20 | 5422.73 | 40.0 | 32.24 | 160.0 | 0.623 |
| high_rate | 2000 | 64000 / 64000 | 359.65 | 6278.98 | 40.0 | 32.24 | 160.0 | 0.698 |

Delivery totals combine both repetitions; other values are arithmetic means per observation window. Idle includes 4 seconds plus the common 3-second tail. Other windows include traffic, a bounded receive drain and the same tail. Raw trial summaries retain loss, CPU/GiB, timing quality and aggregate link counters. Impaired links, complete payment wire attribution and physical device performance remain separate work.

## Verified payment boundaries

This schema-2 experiment includes two complete status passes at every boundary.
All six paying channels were reconciled, with no in-flight payment and no unknown
acknowledgment. No payment activity or journal counter changes appeared between
the guarded snapshots or workload windows. Every policy retained the same three-second tail;
there was no forced flush or selective extension. The validator rejects incomplete
delivery, controller errors, counter resets and unexpected idle work.

All 285,696 measured packets (285,696,000 application bytes) arrived, with no
observed duplicates, reordering, invalid packets or rejected timestamps. There
were no controller errors. All eight idle windows had zero payment requests,
updates, payment record bytes and journal writes. Each trial settled six channels
and collected all 5,120 test sats; the complete matrix conserved 40,960 test sats.

## Conclusions and limits

Both high-rate repetitions used 59 updates at 250 ms, 44 at 500 ms and 40 at
1 s or 2 s. The 1 s/2 s runs therefore used about 32% fewer payment updates and
attributed payment journal writes than 250 ms. Total journal writes fell less,
because independent durable-window checkpoints still preserve allowance.
Monetary thresholds can trigger before the age limit; two seconds does not imply
waiting two seconds under high debt growth. Hard credit and spending bounds are
unchanged.

CPU varied substantially between repeats. Preserve the ranges instead of treating
the averages as evidence of an optimal policy:

| Maximum age | Payment CPU ms, two runs | All service CPU ms, two runs | All journal writes, two runs | p95 one-way delay upper bound, two runs |
| --- | --- | --- | --- | --- |
| 250 ms | 379.05 / 546.97 | 4,484.63 / 6,785.03 | 281 / 279 | 1.00 / 2.00 ms |
| 500 ms | 397.71 / 450.25 | 6,286.49 / 7,052.94 | 237 / 236 | 2.00 / 2.00 ms |
| 1000 ms | 226.33 / 404.07 | 3,945.14 / 6,900.32 | 223 / 223 | 1.00 / 2.00 ms |
| 2000 ms | 367.25 / 352.06 | 6,486.43 / 6,071.53 | 220 / 223 | 2.00 / 2.00 ms |

This was macOS ARM64 on a 14-logical-CPU host, Rust 1.96.0, using an optimized
release build with optional measurements. The run started after compilation,
without concurrent builds or tests from this task. Unrelated host activity
remained; initial one/five/fifteen-minute load averages were 9.29/7.64/6.36.
Two repetitions on a shared host do not establish statistical significance or
router performance. The 500-ms production default remains unchanged.

The executable and all five repository input trees were unchanged throughout
build and measurement. Executable SHA-256:
`f6ae0d23196543351a82dbd477f4d8ec8ba650fd4dee1445e97ce2c794b755b9`.
The matrix took 440.01 seconds including setup, warmup, observations and financial
cleanup. Both directions were explicitly funded to keep the historical workload
matched. Unfunded recipient bootstrap has separate acceptance coverage.

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

All 384 test sats are collected and every wallet is empty. All 261 management
checks pass, cleanup has no errors, and independent final reads match every
original router baseline with Internet/DNS available. The mint and forwarding
processes are absent. Source, executable, inventory and prior-capture hashes
remain unchanged. The optional capture passes 82 Linux harness and 101 analyzer
checks. This clean pilot validates the added observations but does not reproduce
or explain the preceding 364-packet deficit. Strict rejection of that comparison
and the 500-ms production default remain unchanged.

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
