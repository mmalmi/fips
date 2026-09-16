# Clean-link cadence results — 16 September 2026

Optimized build: **True**. Two opposite-order repetitions; five real service processes and three paid relays over loopback UDP.

All costs below sum the five service processes. CPU is measured CPU time. Payment CPU covers synchronous signing, usage handling and balance update handling; it excludes scheduler, serialization and transport CPU. Storage is logical relay journal I/O, excluding Cashu SQLite and physical writes. Record bytes exclude TCP/FIPS/carrier overhead. These are offered workloads, not maximum throughput.

| Workload | Limit ms | Delivered / submitted | Payment CPU ms | All CPU ms | Updates | Payment records KiB | Payment journal writes | Mean delay ms |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| idle | 250 | 0 / 0 | 0.00 | 530.85 | 0.0 | 0.00 | 0.0 | — |
| idle | 500 | 0 / 0 | 0.00 | 331.01 | 0.0 | 0.00 | 0.0 | — |
| idle | 1000 | 0 / 0 | 0.00 | 544.26 | 0.0 | 0.00 | 0.0 | — |
| idle | 2000 | 0 / 0 | 0.00 | 564.76 | 0.0 | 0.00 | 0.0 | — |
| bursty | 250 | 1024 / 1024 | 29.92 | 1150.06 | 2.0 | 1.60 | 8.0 | 0.840 |
| bursty | 500 | 1024 / 1024 | 20.92 | 769.70 | 2.0 | 1.60 | 8.0 | 0.669 |
| bursty | 1000 | 1024 / 1024 | 35.38 | 1234.63 | 2.0 | 1.60 | 8.0 | 0.897 |
| bursty | 2000 | 1024 / 1024 | 36.98 | 1281.09 | 2.0 | 1.60 | 8.0 | 0.865 |
| steady | 250 | 6400 / 6400 | 234.65 | 4575.30 | 19.0 | 15.19 | 76.0 | 0.996 |
| steady | 500 | 6400 / 6400 | 157.51 | 2870.23 | 19.0 | 15.19 | 76.0 | 0.907 |
| steady | 1000 | 6400 / 6400 | 185.04 | 4817.25 | 14.0 | 11.19 | 56.0 | 1.076 |
| steady | 2000 | 6400 / 6400 | 134.69 | 4805.63 | 10.0 | 8.00 | 40.0 | 1.087 |
| high_rate | 250 | 64000 / 64000 | 538.16 | 7572.47 | 60.0 | 48.34 | 240.0 | 0.802 |
| high_rate | 500 | 64000 / 64000 | 311.57 | 5553.66 | 44.0 | 35.46 | 176.0 | 1.447 |
| high_rate | 1000 | 64000 / 64000 | 339.85 | 6728.87 | 40.0 | 32.24 | 160.0 | 0.733 |
| high_rate | 2000 | 64000 / 64000 | 384.75 | 7435.93 | 40.0 | 32.24 | 160.0 | 0.857 |

Delivery totals combine both repetitions; other values are arithmetic means per observation window. Idle includes 4 seconds plus the common 3-second tail. Other windows include traffic, a bounded receive drain and the same tail. Raw trial summaries retain loss, CPU/GiB, timing quality and aggregate link counters. Impaired links, complete payment wire attribution and physical device performance remain separate work.


## Conclusions and limits

All 285,696 measured packets (285,696,000 application bytes) arrived, with no
observed duplicates, reordering, invalid packets or rejected timestamps. No
controller error was reported in the measured snapshots. All eight idle windows
had zero payment requests, balance updates, payment record bytes and attributed
payment journal writes. Every trial settled six channels and collected all 5,120
issued test sats; the eight isolated trials conserved 40,960 test sats in total.

The busy-stream update counts repeated exactly: 60 at 250 ms, 44 at 500 ms and
40 at both 1 s and 2 s. Monetary thresholds can trigger before the age limit;
selecting two seconds does not mean waiting two seconds under high debt growth.
The 1 s/2 s runs used one-third fewer payment updates and payment journal writes
than 250 ms in this workload. Total journal writes fell less, because independent
window checkpoints still preserve forwarding allowance when usage polls are less
frequent. Neither cadence nor profiling changes the hard credit/spending bounds.

CPU time varied substantially between repetitions. Retain these high-rate ranges
instead of treating the averages as proof of a winning policy:

| Maximum age | Payment CPU ms, two runs | All service CPU ms, two runs | All journal writes, two runs | p95 one-way delay upper bound, two runs |
| --- | --- | --- | --- | --- |
| 250 ms | 541.25 / 535.07 | 7,610.27 / 7,534.66 | 286 / 283 | 2 / 2 ms |
| 500 ms | 387.51 / 235.64 | 7,218.28 / 3,889.03 | 233 / 238 | 2 / 20 ms |
| 1 s | 295.84 / 383.87 | 5,967.44 / 7,490.30 | 222 / 223 | 2 / 2 ms |
| 2 s | 380.91 / 388.60 | 7,447.53 / 7,424.33 | 221 / 221 | 2 / 2 ms |

This was macOS ARM64 on a 14-logical-CPU host, Rust 1.94.1, an optimized release
build with optional measurements enabled. It was run after compilation, without
concurrent test/build jobs from this task. Unrelated host activity remained; the
initial one/five/fifteen-minute load averages were 12.16/11.00/8.55. These loops
are not isolated-core or router benchmarks, and two repetitions do not establish
statistical significance. The 500-ms production default remains unchanged.

Executable SHA-256:
`4688676741366d05c854fcbeb56ae8f27bb81a0bb69f250f9223e235a417e36f`.
The binary digest was unchanged across the matrix. The complete matrix took
507.27 seconds including setup, warmup, measurements and financial cleanup.

## Bootstrap finding

Both sending directions were explicitly purchased, although measured application
traffic went in one direction. The current policy bills FSP session setup and its
reverse reply as session envelopes. A forward-only purchase failed six warmup
attempts over 60 seconds, before any measurement. Independent reverse funding
allowed the warmup to succeed. This is a limitation to resolve in the bounded
bootstrap design, not an implicit license to spend the recipient's wallet or
make arbitrary session traffic free.

## Reproduction and remaining evidence

See the [experiment instructions](../../testing/relay-cadence/README.md) for the
fixed financial terms, matched workloads, strict report validator and exact
measurement boundaries. Setup and settlement are excluded from the cost windows;
a common three-second payment tail is included. Measured application packets
are not retried. Financial conservation is a prerequisite for accepting a trial.

This result does not cover impaired links, residual allowance after crashes,
renewal/expiry, mobile discovery, hardware/Pixel regression or real radio airtime.
Synchronous payment CPU excludes scheduling, JSON and transport work; journal
counts exclude Cashu SQLite and physical writes; framed payment bytes exclude
TCP/FIPS/carrier overhead. The separate native link-counter snapshots must not
be substituted for complete payment wire attribution. Those requirements remain
part of the production-readiness goal.
