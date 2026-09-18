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
A separate diagnostic should capture the existing native forwarding/drop
counters at the same boundaries before another comparison. That can distinguish
policy denial, local send failure, missing routes and other recorded drop classes;
it will not automatically identify a radio or driver fault.

## Reproduction and remaining evidence

See the [experiment instructions](../../testing/relay-cadence/README.md) for fixed
terms, workloads, report validation and measurement boundaries. Setup and settlement
are excluded; the identical three-second payment tail is included. Application
packets are never retried. Financial conservation is required for every trial.
The report also retains normalized CPU, logical journal bytes and payment record
bytes per delivered byte, plus CPU per completed update within each window.

Synchronous payment CPU includes signing and synchronous SDK/receiver persistence,
but excludes scheduling, control-envelope serialization outside the spans and
transport work. Journal counters exclude SDK JSON snapshots, receiver/wallet
SQLite and physical storage writes. Framed payment records exclude TCP/FIPS/carrier
headers, acknowledgments and retransmissions. Aggregate link bytes cannot establish
payment-specific wire overhead. Impairment, physical devices, actual radio airtime
and complete CPU/storage/wire attribution remain work for production readiness.

The earlier 16 September schema-1 result remains in repository history. It reported
complete delivery and conservation but did not verify payment boundaries; it must
not be retroactively treated as passing the schema-2 checks or directly compared
as a performance baseline across the changed build and dependencies.
