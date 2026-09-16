# Paid forwarding performance

Measured 16 September 2026 on three Cudy TR3000 ARM64 OpenWrt routers.
The retained implementation is the size-oriented OpenWrt build with the existing
four-worker runtime. Two tuning experiments were rejected: neither established a
reliable reduction in CPU cost. No speedup is claimed.

## Method

Two isolated endpoints on the same host used the exact five-node line:

```text
source -- UDP -- relay 1 -- native Wi-Fi -- relay 2 -- native Wi-Fi -- relay 3 -- UDP -- destination
```

Both inter-router links carried native FIPS on unbridged 802.11s interfaces with
lower-layer mesh forwarding disabled. The middle relay had no UDP transport.
Both directions purchased the complete path; six neighbor channels exchanged
payments. A verified warm-up preceded each measured stream. Directions ran
separately, with 1,000-byte application payloads at 1,000 packets/second: 8 Mbit/s
offered. Each unprofiled stream contained 12,000 packets, lasting about 12 seconds.

The main cost metric is:

```text
process CPU seconds / (successfully delivered application bytes / 2^30)
```

CPU includes user and system time from the same process, checked against its
PID and start time. All devices reported 100 process clock ticks per second.
Sampling brackets the stream and includes some control/measurement overhead;
this is neither whole-device energy nor CPU spent exclusively forwarding data.
Memory is sampled resident memory, not an exact peak. Endpoints share one clock
for application latency. Raw records retain offered/submitted/delivered counts,
loss, duplicates, reordering, latency buckets, process samples, peer graphs,
control counters and financial statuses.

## Matched observations

Every stream below delivered all 12,000 packets with no duplicates.

| Build and direction | Mean one-way delay | CPU seconds/GiB: relays 1 / 2 / 3 | Largest sampled relay RSS |
|---|---:|---:|---:|
| Baseline forward | 6.894 ms | 879.6 / 855.4 / 736.4 | 18.67 MiB |
| Baseline reverse | 6.618 ms | 745.4 / 856.3 / 894.8 | 18.70 MiB |
| Speed-oriented compiler, forward | 6.081 ms | 862.6 / 880.5 / 776.7 | 19.73 MiB |
| Speed-oriented compiler, reverse | 5.897 ms | 756.1 / 849.2 / 853.6 | 19.82 MiB |
| CPU-sized runtime, forward | 6.401 ms | 900.2 / 872.4 / 778.5 | 18.47 MiB |
| CPU-sized runtime, reverse | 6.142 ms | 799.9 / 866.2 / 901.0 | 18.54 MiB |
| Restored baseline forward | 6.735 ms | 913.6 / 928.8 / 820.5 | 17.24 MiB |
| Restored baseline reverse | 6.585 ms | 841.1 / 901.0 / 917.2 | 17.34 MiB |

Baseline CPU use was 62.8–78.6% of one core over the observation windows.
Baseline sampled RSS ranged from 16.09 to 18.70 MiB across routers/runs. A few
packets arrived out of order (up to seven per unprofiled stream).
These are short offered-rate observations, not a maximum-throughput result or
proof of continuous lossless service during renewal.

The compiler experiment raised optimization to level 3 for the relay and core,
retaining thin LTO and one codegen unit. The executable grew from 20,127,824 to
26,367,872 bytes, about 31%, without consistent CPU savings in both directions.
The runtime experiment used two workers on these two-core routers, retaining
the existing crypto worker policy. It also failed to establish a saving.
The later baseline's total router CPU cost was roughly 7% above the initial
baseline. That variation, evolving account history and the small sample count
prevent attributing small differences to either tuning. Both changes were
reverted; original binaries were restored before the final measurements.

Binary provenance: the baseline was `7538992d`; compiler candidate `95efcc61`
and runtime candidate `432c5720` also included the policy-refusal diagnostics
from `065279e9`. They are not otherwise identical source snapshots to r6.
The refusal counters only increment on policy rejection, but this additional
difference is another reason not to interpret small timing changes as a speedup.

## Profiling and overhead

One additional instrumented 6,000-packet forward stream delivered every packet.
Together with the table, 102,000 measured application packets arrived. Existing
`FIPS_PERF=1` / `FIPS_PERF_INTERVAL_SECS=5` instrumentation was used only for the
profiling run, and was disabled for comparison runs.

Observed timers put AEAD open around 16–19 microseconds, seal around 15–16,
decode around 0.2, and warm route-cache access around 0.8. Data-plane turns and
submission spans were larger. These spans overlap and may include waiting;
they cannot be added or presented as CPU percentages. Paid-policy admission
and completion are not separately timed by these existing spans. A future
optimization should measure those costs before changing accounting or concurrency.

During baseline streams, each relay sent approximately 23–35 KB in the three
application control streams for 12 MB delivered. A transmitting mesh interface
reported roughly 1.166–1.172 times the application bytes. Interface counters
also include background/link traffic; they omit some radio overhead and cannot
be interpreted as complete Wi-Fi airtime or a precise encryption expansion ratio.

Two aborted harness attempts are preserved separately from the table: one
failed executable discovery before traffic; another rejected a historical status
warning after warm-up, before a measured stream. Process discovery now verifies
the executable and configuration rather than assuming a fixed binary basename.
The controller retains its last error after recovery. Comparison runs explicitly
recorded the known reconnect warnings while requiring the exact peer graph,
successful warm-up, complete traffic results and final settlement. No account
was reset to clear a warning or improve a result.

## Settlement and restoration

The run reused settled accounts and their remaining lifetime budgets. Each
participant received 256 test sats, totaling 1,280. Intermediate settlement
reused the same wallet funds for the second comparison round. Final balances
before collection were 90 / 362 / 358 / 362 / 108 sats along the five-node line:
relay net earnings were 106 / 102 / 106 test sats. All 1,280 were collected;
cumulative historical test issuance and collection both reached 12,800.

The saved empty customer accounts, exact customer network configuration and
normal router services were restored. Existing Wi-Fi/Internet and host web
services passed checks. Temporary candidates were removed after process and
checksum verification; accounts, limits, backups and private measurement records
were retained. The original test-mint process stayed running. No real-money
transaction, publication or external deployment was performed.

## Repeat and improve the measurement

1. Build and hash the exact binary using [the package guide](openwrt/README.md).
   Record toolchain, hardware, tariff, price, window, grace, channel capacity,
   payment interval and remaining lifetime budget. Keep financial terms fixed.
2. Use isolated endpoints and verify the exact connected peer graph. Capture
   native traffic on both intended links; exclude management-network shortcuts.
3. Fund bounded test channels, warm up the session, then use the service's
   [probe controls](SERVICE.md) for matched payload/count/rate in each direction.
   Count delivery at the receiver; queue acceptance is insufficient.
4. Bracket the stream with process tick/RSS and control/interface counters.
   Keep the same PID/start time. Calculate CPU cost per delivered GiB, and
   report latency, loss, reordering, memory and overhead alongside it.
5. Profile separately. Compare one small change at a time against bracketing
   baselines; repeat enough trials to distinguish the effect from drift. Include
   binary size and memory. Reject changes whose benefit is not demonstrated.
6. Settle every channel, collect the exact remaining balances, verify conservation
   and each relay's net earnings, then restore the saved service configuration.
   Keep failures in the record. Never erase financial history to repeat a test.
