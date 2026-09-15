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

Record process CPU and memory, host load and interface counters alongside each
run. Check process identity/start time when comparing counters across samples;
a respawn starts a new measurement epoch. Record endpoint CPU too, so a small
endpoint host is not mistaken for a router bottleneck. Keep unrelated host
services available and include their competing load in the results.

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
