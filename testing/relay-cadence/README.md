# Paid-relay cadence experiment

This experiment runs the production relay executable as five separate processes,
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
the synchronous spans, and controlled ARM64/router/phone runs. Performance changes
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
