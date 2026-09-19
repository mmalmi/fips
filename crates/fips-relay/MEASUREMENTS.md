# Measuring a paid relay path

The local operator controls can generate paced diagnostic datagrams and track a
specific stream at its destination. Both use the production FIPS service and
payment admission path. They do not create accounts, fund channels, authorize
routes, inspect transit payloads or send delivery receipts. Receiver statistics
and control-traffic counters are volatile measurements, separate from durable
financial accounting.

## Prepare the path

Back up existing stopped accounts. Use explicit test-mint grants, prices,
spending limits, working-capital limits and unpaid exposure appropriate for the
amount of traffic. Preserve historical accounts; changing saved prices to make a
benchmark cheaper is rejected. A separate test account can use a smaller byte
price while keeping a nonzero fee at every hop.

Verify the exact connected native peer graph before and after each run. Disable
kernel mesh forwarding and keep the FIPS interfaces outside the management
bridge. Give endpoint adapters only their intended adjacent peer. Purchase each
traffic direction explicitly, warm up the actual endpoint session with a small
packet, and verify delivery before starting a measured stream.

## Arm a receiver and send a stream

Send each example as one JSON request through `fips-relay ctl CONFIG.json`.
On the destination:

```json
{"type":"receive_probe","probe":{"source":"REPLACE_WITH_SOURCE_NPUB","stream_id":"3be81368471f470ebc95079d2213e0f2","packet_count":1200,"payload_bytes":1000,"measure_one_way_latency":false}}
```

On the source:

```json
{"type":"send_probe","probe":{"destination":"REPLACE_WITH_DESTINATION_NPUB","stream_id":"3be81368471f470ebc95079d2213e0f2","packet_count":1200,"payload_bytes":1000,"packets_per_second":120}}
```

Choose a fresh random 128-bit stream ID for each experiment. The example submits
1.2 MB of application data over approximately ten seconds. The sender allows one
active stream, at most 65,536 packets of 40–1,000 bytes, a rate of 1–16,000
packets/second and a scheduled duration of at most 30 seconds. Batches are bounded
to at most 16 packets. A slow run stops at the duration limit and reports partial
submission; there is no automatic retransmission. Other operator queries remain
available while the stream runs.

The sender reports `submitted_packets`, `submitted_bytes`, elapsed time and a
possible stop reason. Submission to the endpoint API does not establish wire
transmission or delivery. The destination's `status.probe` reports unique bytes
and packets, missing sequence numbers, duplicates, out-of-order packets, and
ignored/invalid input. It accepts measurements only for the configured
authenticated source, stream ID, payload size and sequence range. The receiver
allocates at most 8 KiB for duplicate tracking. Arming another stream explicitly
replaces the previous measurement; a restart also clears it.

Compare sender submission counts with receiver unique counts, after allowing a
bounded drain period. If the sender stopped early, distinguish unsubmitted
packets from missing submitted packets. Report observed goodput against the
offered rate and elapsed window. Do not call an offered-rate-limited run the
maximum capacity of the link. Per-application duplicate sequence detection is
not a test of encrypted FIPS wire replay rejection; exercise wire replay
separately when verifying billing under duplicated traffic.

## Latency and overhead

The optional `measurements` build feature adds process CPU, synchronous payment
thread CPU and attributed logical relay-journal counters to the private status
response. It is disabled in normal builds. For definitions, exclusions and the
matched four-policy experiment, see the [cadence benchmark](../../testing/relay-cadence/README.md)
and [clean-link results](CADENCE-RESULTS.md). Elapsed span time is separate from
CPU time; framing counters and logical writes are not complete wire or physical
storage measurements.

Enable `measure_one_way_latency` only when the operator can establish the clock
relationship. Two isolated processes on the same host share a kernel clock and
are suitable for the first bench measurement. Different devices require a
separate clock-error bound; NTP merely being active is insufficient for precise
one-way latency. The implementation timestamps before endpoint submission and
when the diagnostic application consumes a packet, so delay includes endpoint
queues and application scheduling. It excludes negative timestamps and delays
over 60 seconds from latency samples while retaining their valid packet counts.

Reports contain latency sample count, sum, extrema and fixed histogram buckets.
There is one more count than upper bound: the final bucket is unbounded.
Percentiles inferred from these buckets are upper bounds. They are not exact
sample percentiles or a round-trip measurement. The diagnostic receiver sends
no reply and never purchases reverse service.

`status.control_traffic` exposes per-service counters for quotes, acceptance and
payments (ports 44741–44743). Stream-byte counts include the four-byte record
framing and bytes accepted/read by the TCP adapter. They exclude TCP/FIPS/link
headers, acknowledgments and retransmission overhead. Count transmitted bytes
once across nodes; summing both sent and received double-counts the same exchange.
Measure setup, steady traffic and settlement separately. Peer byte-counter
deltas provide an additional aggregate transport measurement, with their own
framing boundary; they do not isolate payment messages or Wi-Fi airtime.

With `measurements`, the port 44743 entry also exposes `service_carrier`, a
separate snapshot of locally originated TCP/FIPS service submissions. The
handle is registered once before service startup and retained for that endpoint
lifetime. Ports 44741/44742, and every entry in ordinary builds, report `null`:
instrumentation is unavailable, not a measured zero. No additional services are
registered by status requests; the endpoint's registry is bounded to 16 ports.

The snapshot contains `service_port`, `ambiguous_port_datagrams`,
`discarded_outputs`, and nine fixed `transports` buckets (`udp`, `ethernet`, `tcp`,
`tor`, `websocket`, `webrtc`, `ble`, `sim`, `other`). Each bucket contains
`submitted_packets`, `fips_payload_bytes` and `ethernet_framing_bytes`. Counts
include TCP/FIPS SYN, ACK, FIN and retransmitted segments, FIPS encryption and
fragment headers, and individually submitted fragments even when a later
fragment fails. `discarded_outputs` counts sealed outputs not completely
submitted; it does not include earlier admission or encryption failures.
Ambiguous matches between different registered source/destination ports are
attributed once to the source and explicitly counted. Treat such samples as
ambiguous rather than exclusively payment traffic. Port 44743 can also carry
quotes, so its totals describe that service, not a payment-only message class.

These are local transport-API submissions, not delivery receipts, financial
authority, all-hop totals or radio airtime. Opaque transit and shared FIPS
handshake/MMP/rekey traffic are excluded; loopback has no carrier submissions.
UDP bytes stop at its payload boundary. Ethernet's proprietary three-byte
prefix is separate; OS headers, padding and radio overhead are excluded. Outer
TCP excludes kernel ACKs/retransmissions, independently of the measured inner
TCP/FIPS segments. Peer counters remain the separate aggregate observation;
do not subtract these differently framed totals to infer unclassified bytes.
Count each node's sends once. Snapshots read separate cumulative atomics: sample
after quiescence, retain guard-gap traffic, and reject unavailable, reset,
saturated or ambiguous evidence when claiming attributed overhead.

Record process CPU and memory, host load and interface counters alongside each
run. Check process identity/start time when comparing counters across samples;
a respawn starts a new measurement epoch. Record endpoint CPU too, so a small
endpoint host is not mistaken for a router bottleneck. Keep unrelated host
services available and include their competing load in the results.

For efficiency, divide process user-plus-system CPU seconds by GiB successfully
delivered at the destination. Obtain Linux clock ticks per second from
`sysconf(_SC_CLK_TCK)` or `AT_CLKTCK`; do not assume a tick frequency. Retain
offered rate, goodput, loss, latency, memory and the exact observation window.
CPU per delivered byte includes wasted work on lost traffic and fixed control
costs. Keep those conditions comparable before attributing a difference to an
optimization. Process CPU excludes kernel work charged elsewhere on the host.

The [r5 accounting measurements](WIRELESS-ACCOUNTING.md) report this metric on
the physical three-relay wireless line, beyond the earlier packet-history cutoff.

## Native topology controls

The existing native FIPS operator socket is at `STATE_DIRECTORY/native.sock`,
inside the accounting directory that must remain private. Use the bounded
`fips-relay native CONFIG.json` wrapper to send one native JSON command, such as:

```json
{"command":"show_status"}
```

The existing `connect` and `disconnect` commands permit deliberate topology
experiments. Keep the financial service's configured-neighbor list consistent
with the intended candidates. A native connection does not grant forwarding
credit or authorize spending. These are local administrator controls; never
expose this socket or wrapper as the public customer payment interface.

Software checks cover attributed packet counting, limits, explicit latency
assumptions, paced traffic through five paid service processes, sender exclusion,
live operator queries, private native controls and control-stream byte counts.
Physical measurements for this build must be reported separately with their
actual rate, topology, funding and limitations.

## Physical wireless result (2026-09-15)

Application revision `835726a` was built with the `openwrt` profile and installed
as local APK revision r4 on three ARM64 Cudy TR3000 v1 routers running OpenWrt
25.12.5. The executable is 19,989,912 bytes; the APK is 9,316,455 bytes. Existing
accounts were backed up and preserved. Upgrading each stopped r3 service retained
its stopped state; an explicit start restored the same account and budget.

Five separate accounts each received 512 test sats from the existing isolated
mint. Each channel had 128-sat capacity, a two-hour lifetime and an 8,000-msat
grace limit; the durable window was 4,000 msat. Every router charged 1 msat per
1,024 metered bytes. Source watches authorized each direction with an aggregate
ceiling of 3 msat per 1,024 bytes. These were new accounts with explicit test
funding, not edits to the saved terms or balances of earlier hardware runs.

The initial graph was endpoint A–relay 1–relay 2–relay 3–endpoint B. Endpoint
links used UDP; both inter-router links used native FIPS Ethernet transport over
isolated encrypted 802.11s Wi-Fi, with kernel mesh forwarding disabled. The
middle router had no UDP transport. Exact connected peer sets were checked
before and after every measured stream. Both endpoint processes ran on one
Raspberry Pi 4, sharing its kernel clock; unrelated host services remained up.

Each ordinary stream sent 1,200 distinct 1,000-byte application datagrams at
120 packets/second, approximately 0.96 Mbps for ten seconds. A fresh one-packet
warmup arrived on its first attempt before every stream. Receiver statistics
did not produce payment receipts or authorize return traffic.

| Path and direction | Received / submitted | Mean one-way delay | p95 upper bound | Maximum observed |
| --- | ---: | ---: | ---: | ---: |
| Three relays, A to B | 1,200 / 1,200 | 5.297 ms | 10 ms | 31.165 ms |
| Three relays, B to A | 1,200 / 1,200 | 5.606 ms | 20 ms | 29.146 ms |
| Two relays, A to B | 1,200 / 1,200 | 4.208 ms | 10 ms | 21.893 ms |
| Two relays, B to A | 1,200 / 1,200 | 4.190 ms | 10 ms | 24.617 ms |

All four streams had zero observed missing, duplicate, invalid or out-of-order
application packets. Delay includes application queues and scheduling. The p95
values are histogram bucket bounds. This verifies an offered rate, not maximum
throughput, sustained service or performance on other OpenWrt hardware.

### Persistent channels across a route change

After the two initial streams, only the middle relay's FIPS service was stopped.
The operator explicitly established the already configured manual native link
between relays 1 and 3. Both source watches accepted the alternate route without
another purchase command. Observed stop-to-accepted-route time was 11.82 seconds,
including orchestration and polling. No continuous packet stream measured the
outage itself, and the new radio adjacency was operator-triggered.

Both sources retained their original channel IDs and received new route
agreements at 2 msat per 1,024 bytes. Only the two new neighbor payment directions
needed funding. The two subsequent streams verified actual delivery over the
shortened graph. Old financial relationships remained retained while the middle
service was offline. Relays 1 and 3 reported an unavailable-provider error for
those old purchases even while the alternate data path worked; that diagnostic
was recorded rather than treated as an alternate-path failure or erased.

### Resource and control measurements

Process counters were compared only across unchanged process IDs/start times.
CPU percentages below express a fraction of one CPU core. Sampling intervals
were about 11.6–11.8 seconds for each ten-second stream. Memory is the largest
sampled resident set, not a guaranteed instantaneous peak.

| Window | Relay CPU range | Relay sampled memory range | Control stream bytes transmitted across active nodes |
| --- | ---: | ---: | ---: |
| Three relays, A to B | 19.1–22.4% | 18.0–19.0 MiB | 75,788 |
| Three relays, B to A | 27.9–32.3% | 18.6–19.7 MiB | 76,090 |
| Two relays, A to B | 36.3–42.8% | 20.7–20.9 MiB | 50,322 |
| Two relays, B to A | 45.0–49.8% | 21.3 MiB | 48,334 |

The endpoint processes used 13.1–14.9% of one core and 18.1–18.6 MiB sampled
memory. Host utilization also included SSH observation and unrelated services.
Control counts span the before/after snapshots, including the bounded drain;
they include periodic quote/payment polling, not only traffic-triggered updates.
They include record framing but exclude transport headers and retransmissions.
These are not Wi-Fi airtime or complete wire-overhead measurements. History and
CPU grew over successive runs; this experiment did not isolate their causal
contributions or establish steady-state resource use.

### Confirmed accounting cutoff

A final forward stream offered 5,000 packets at 250 packets/second (2 Mbps).
All 5,000 reached the local submission API, but the destination received 2,820
over approximately 11.28 seconds, with 2,180 missing and one out-of-order packet.
The two participating sellers reached exactly 4,096 retained attempts on the
active forward contract, including traffic preceding this stream. Each recorded
4,178,719 submitted metered bytes, well below the 128-MiB contract allowance.

This was not channel exhaustion. The upstream seller had reserved 11,826 msat
and received 12,000 msat against 128,000-msat capacity; the downstream seller had
reserved 4,081 msat and received 5,000. Their persisted admission ceilings were
15,826 and 8,081 msat. Source lifetime budget was still 500 sats. Accounting
rejected new attempts at the retained-history limit. The seller journals had
grown to about 1.31 MB; sampled relay memory reached 22.94 MiB, and relay CPU
averaged up to 69.2% of one core during the longer observation window.

This limit had to be addressed before claiming long-lived paid forwarding. Merely
increasing the packet cap or resetting a contract would not establish bounded
memory, replay safety or preserved spending/exposure limits. The subsequent
[r5 experiment](WIRELESS-ACCOUNTING.md) verifies compact completed-packet totals
under an explicit forwarding-attempt tariff. Safe retirement of route and
closed-channel history remains implementation work.

### Settlement and restoration

Source watches were paused, the middle service restarted and its original
financial neighbors reconnected. All eight channels settled. Final balances
were 500, 520, 514, 521 and 505 test sats for A, relays 1–3 and B respectively:
all three routers retained positive margins, and the total remained 2,560.
Every final balance was exported and redeemed, leaving the five test wallets
empty. Total collection across hardware phases reached 6,400 test sats.

The original router accounts were restored on r4 with their prior identities,
histories and remaining budgets. New and old test endpoints were stopped. The
installed binary hashes, boot enablement, native neighbors, stable mesh addresses,
AP interfaces and DNS/HTTPS checks passed on all routers. Network, Wi-Fi, DHCP
and firewall files matched the pre-test backups; the existing host web service
returned HTTP 200. The
mint was kept alive; its simulated Lightning backend was not restarted. These
measurements do not establish customer onboarding, Pixel operation, encrypted
wire replay handling, interrupted renewal/funding recovery or full-router reboot
recovery with active financial operations.
