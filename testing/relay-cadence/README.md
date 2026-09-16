# Paid-relay cadence experiment

This experiment runs the production relay executable as five separate processes,
with three paid forwarding hops, loopback UDP links and an isolated simulated
mint. It reuses the existing service test helpers and operator probe API. It does
not alter live routers, home networking or saved accounts.

Run alone, after compilation has finished. Do not run other tests or compilation
concurrently with a measurement. Normal host activity still affects the result;
retain host load, architecture, compiler and executable digest alongside it.

```sh
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
sending directions are independently funded, as required by the current tariff:
FSP handshake replies are session envelopes and need the reverse paid route even
when diagnostic data is sent in only one direction. A forward-only setup failed
to deliver its warmup in six attempts over 60 seconds. This limitation is retained
for the bounded-bootstrap work; the benchmark does not establish free return
handshakes or service to an unfunded recipient.

Each trial records bounded setup/warmup attempts separately, followed by:

| Workload | Offered application traffic |
| --- | --- |
| Idle | Four seconds with no diagnostic traffic |
| Bursty | Eight bursts of 64 × 1,000-byte packets at 1,000 packets/s, 800 ms between bursts |
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
An incomplete run without those records is not an accepted matrix. Analysis
also rejects counter resets, restarted processes, changed link epochs, missing
CPU samples and mismatched trial ordering. Two repetitions show variation but
are not enough for statistical claims of an optimal policy.

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
  These spans exclude JSON decoding/encoding, payment scheduling, TCP/FIPS work,
  and work done by another thread. They are not total payment-induced CPU.
- **Storage:** successful complete writes, written bytes, successful sync calls
  and durable commits through the relay journal writer. A normal commit has one
  logical write and two sync calls. Counts are attributed to the enclosing
  synchronous operation; independent window checkpoints have their own category.
  Cashu wallet/receiver SQLite writes, partial failed writes, filesystem metadata,
  write amplification and physical device bytes are not counted.
- **Traffic:** per-payment-service application record bytes, plus separately
  reported aggregate native link counters. Sum sent bytes once; summing sent
  and received double-counts them. Record bytes omit TCP/FIPS/carrier framing,
  acknowledgments and retries. Aggregate link counters include other native
  traffic and do not isolate payments. Neither metric measures Wi-Fi airtime.

Clock support is currently implemented for Linux, Android and macOS using the
OS thread/process CPU clocks. Other targets expose missing CPU samples. The
clock semantics are documented in the [Linux manual](https://man7.org/linux/man-pages/man3/clock_gettime.3.html).
Synchronous spans may nest; their CPU/elapsed totals are inclusive and must not
be blindly summed across overlapping categories. Current production payment
and checkpoint instrumentation uses non-overlapping spans.

## Remaining comparison work

This matrix provides the repeatable clean-link baseline. It does not fulfill
the full production-readiness benchmark. Still required: impaired links using
the existing FIPS simulation/chaos facilities, payment-specific complete carrier
bytes, Cashu SQLite/physical storage measurements, profiler attribution outside
the synchronous spans, and controlled ARM64/router/phone runs. Performance changes
need a matched baseline with instrumentation cost held constant. No production
default is selected solely from this loopback experiment.
