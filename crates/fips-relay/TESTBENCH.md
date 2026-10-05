# Isolated hardware test mint and wallet funding

For the current completed prototype scope and later phone/performance evidence,
see [the acceptance report](PROTOTYPE-RESULTS.md). Earlier run sections below are historical.

`fips-relay-test-mint` runs a genuine local CDK mint with a simulated Lightning
backend. Its tokens have no external backing. Only the private administrator
socket can issue a bounded test grant; the HTTP listener exposes the ordinary
mint protocol. The relay executable does not include this funding capability
in its normal build.

## Build and start

Build the relay normally, and select the explicit test feature for the mint:

```sh
cargo build -p fips-relay --bin fips-relay
cargo build -p fips-relay --features testbench --bin fips-relay-test-mint
```

Both also cross-build with the ARM64 musl command in [SERVICE.md](SERVICE.md).
Use `--features testbench --bin fips-relay-test-mint` for the mint executable.

Example mint configuration:

```json
{
  "state_directory": "/var/lib/fips-bench/run1/mint",
  "bind": "127.0.0.1:30338",
  "max_issued_sat": 100000
}
```

Create the parent directory, then run:

```sh
fips-relay-test-mint run /absolute/path/mint.json
```

For a hardware bench, choose an assigned private LAN address reachable from the
routers. Wildcard, multicast and public binds are rejected. The TCP proxy has a
fixed loopback CDK upstream, at most 32 active connections, and a 45-second
inactivity limit. Active HTTP connections can carry successive refund requests.
Funding controls use a separate private Unix socket. All
participants must use the same advertised mint URL, including its port.

Each mint process requires a new state directory. The simulated Lightning
network has in-memory state; existing directories are neither reset nor silently
resumed. Keep this mint process alive across the relay restart tests. Settle and
collect the run's balances before ending it. SIGTERM/Ctrl-C ends the fixture;
this tool does not claim production mint restart support.

### Interrupt a committed mint reply

The private administrator socket can hold the next successful swap response
after the real mint commits it. This reuses the SDK's response barrier; no fault
controls are exposed through mint HTTP or a normal relay build. Send these
requests through `fips-relay-test-mint ctl`:

```json
{"type":"fault","command":{"action":"arm_swap_reply"}}
{"type":"fault","command":{"action":"status"}}
{"type":"fault","command":{"action":"release","generation":1}}
```

Use the generation returned by the arm request. Status reports `idle`, `armed`,
`held` or `released`, plus cumulative swap-attempt, successful-swap and restore
counters. Interrupt the link only after `held`, then release that generation
and restore the link. This distinguishes a committed response lost in transit
from a request that never reached the mint.

Only one barrier can be active. Issuance and collection are refused while it is
armed or held; status remains available. Release before `held` or with another
generation fails. Releasing the same completed generation again is harmless.
After an interrupted test, preserve the original mint and financial operation
until recovery and collection finish. Do not issue replacement funds.

## Mint HTTP over FIPS

The relay library exposes `mint_mesh::MeshMintBridge`: `serve`
connects one FIPS service port to a fixed loopback mint socket; `connect` binds
a loopback client listener to that server's authenticated FIPS identity. It
carries ordinary HTTP bytes over existing TCP/FIPS, without HTTP request replay,
new payment messages, remote proxy destinations or access to the issuance socket.
Each adapter has eight connection slots, four TCP connections per peer, 16 KiB
buffers per direction and a 45-second inactivity limit. Useful byte progress
extends that limit; empty packets do not. Local sockets wait
up to three seconds for a TCP slot before any request bytes are read.
Shutdown explicitly resets retained streams before stopping the native endpoint,
so reopening the same identity does not inherit abandoned TCP connections.

The adapter grants no forwarding exemption. An operator must explicitly arrange
bounded bootstrap access using existing route pricing and free-bandwidth
controls. An empty customer wallet must be able to reach the
mint before buying paid service. A client requests a zero-price route when an
HTTP connection arrives, through the existing bounded quote cache. It never
opens a paid channel to obtain mint access and does not poll for routes while
idle. The focused native check is:

```sh
cargo test -p fips-relay --features testbench --lib mesh_mint_tests:: -- --test-threads=1
```

The case restarts the mint gateway after a committed funding reply is lost.
During settlement, it removes the transit relay after the close swap commits,
then starts a different relay while the original stays offline. At both losses,
it also kills the CDK mint subprocess and reopens its original SQLite database
and keys behind the same URL. Background recovery must activate the original
channel, then finish its payout and refund through the replacement path without
another swap or wallet spend. All 16 originally issued test sats must reach the
collector. The subprocess fixture permits no new simulated funding after a
restart; it covers Cashu proof-state durability, not recovery of a Lightning
backend. The hardware test mint still requires a new directory per process.

The handover cases keep all nodes alive while the provider's mint route moves
through its former customer. They cover a disconnected edge and persistent
packet loss in either direction of an enabled edge. Simulated discovery also
suppresses advertisements in the fully lossy direction. The failed direction
stays broken throughout recovery. Superseded cached free quotes are refetched
without reviving their old allowances; no additional
swap or wallet spend is allowed during recovery. After normal workers settle the
original channel, the fixture redeems all 16 test sats through the remaining
mint-side FIPS endpoint. See the bounded evidence in [READINESS.md](READINESS.md).

### Client configuration and wallet lifetime

Configure fresh accounts before initialization:

| Setting | Meaning |
| --- | --- |
| `terms.controller.mint_url` | Fixed numeric loopback HTTP URL, such as `http://127.0.0.1:3338`. |
| `terms.mint_mesh.npub` | Authenticated FIPS identity of the mint's adapter. |
| `terms.mint_mesh.service_port` | Its FIPS service port; `44745` is available for this experiment. |

The mint identity and port are saved with the immutable financial terms. Customer
profiles accept the same `mint_mesh` object alongside `mint_url`. Omit it to keep
ordinary mint access. Mesh access requires forwarding-data billing; reserved
relay service ports, non-loopback URLs and an occupied local listener are refused.

While running, the mint adapter uses the relay's native endpoint. Import/export
under the stopped wallet's exclusive root lock temporarily opens a mint-only
endpoint with the **same** FIPS identity and configured links. It negotiates only
free routes and rejects all transit. Balance reads and export-history
acknowledgments do not start networking. Normal shutdown closes the adapter and
endpoint before releasing the root lock; an active paid service still prevents
offline wallet commands.

The mint and every client's adapter must use the same wallet URL. A test mint can
bind its own loopback port and clients can use that same loopback port locally,
with TCP/FIPS connecting them. Do not rewrite a saved wallet's mint URL to adopt
another adapter.

### Mint host configuration

Run the test mint on its own loopback listener, for example `127.0.0.1:3338`.
The ordinary relay daemon on that host can expose it using this top-level field
in its existing service configuration:

```json
"mint_export": {
  "backend": "127.0.0.1:3338",
  "service_port": 44745
}
```

Initialize a fresh relay account, then run it normally. Its saved FIPS identity
is the `terms.mint_mesh.npub` that clients pin. Use forwarding-data billing and
the same `http://127.0.0.1:3338` mint URL; omit `terms.mint_mesh` on the mint host.
Client and server adapters cannot be enabled together. The export accepts only
a fixed loopback TCP backend and a distinct, non-reserved FIPS service port. It
shares the relay endpoint and its shutdown; the mint's private issuance socket
is never exported. No additional proxy process or mint protocol is needed.
Service-port registrations last for the native endpoint's lifetime; restart the
complete relay service to restart an adapter, preserving its saved account.

This configuration does not grant bootstrap traffic automatically. Give the mint
destination a zero-price offer with bounded `free_bandwidth` on forwarding
relays. Enable `return_allowance` on those relays to let admitted requests earn
small replies along the reverse path. No client-specific tariff or mint-side
return watch is then needed. The adapter uses small TCP segments so
acknowledgments can sustain that earned credit. The default 1,024-unit/s neighbor
reply budget is intended for small replies; the full mint lifecycle can exceed
metadata request deadlines at that rate. For this bench, explicitly configure:

```json
"return_allowance": true,
"return_bandwidth": {
  "global_bytes_per_second": 32768,
  "global_burst_bytes": 65536,
  "peer_bytes_per_second": 8192,
  "peer_burst_bytes": 16384
}
```

This changes only operator-selected rate/burst limits. [Earned credit, path
binding, state bounds and paid-route precedence](RETURN-ALLOWANCE.md) stay fixed.
It is still a bounded bootstrap tier, without a delivery or fairness guarantee
under contention. A changed or asymmetric response path needs matching
forward admission on its edges; this does not establish general mobile bootstrap.

Fresh router accounts pass the complete mint lifecycle over UDP and over two
discovered open Wi-Fi mesh hops, without known-client return entries. The native
case also recovers lost committed funding and settlement replies; the routers
complete settlement after an interrupted radio path rejoins, without another
mint swap. Saved hardware accounts retain their original mint URLs; Android
mint integration remains pending. Current acceptance and its limits are recorded in
[READINESS.md](READINESS.md).

The recorded live-edge handover now also passes: the provider reaches the mint
through its former customer while the old edge stays blocked. Its original
administrative request times out; background recovery completes the saved
settlement without another swap, and all test funds are collected. This specific
symmetric topology change does not establish arbitrary or asymmetric mobility.
The subsequent device case with persistent loss only in the old edge's return
direction fails to recover settlement within its bounded window, even after
the replacement topology appears. Its original funds are recovered separately
on the original path. Treat asymmetric handover as outstanding acceptance;
do not bypass it by granting unlimited mint forwarding or issuing new funds.

## Fund a relay

Initialize the relay as described in SERVICE.md, then leave it stopped. Request
a grant through the mint's local control socket:

```sh
printf '%s\n' '{"type":"issue","id":"router-1","amount_sat":512}' |
  fips-relay-test-mint ctl /absolute/path/mint.json
```

The response names a private export file, its amount and operation ID. It does
not print bearer tokens. Repeating an ID with the same amount returns that same
export; changing its amount fails. At most 64 grants can reserve the configured
issuance limit. A failed or interrupted grant keeps its reserved amount.

Transfer the export privately to the target. Build an import request from its
`token` field and send it on standard input to:

```sh
fips-relay wallet /absolute/path/relay.json
```

The request shape is `{"type":"import","token":"ENCODED_TOKEN"}`. This command
accepts only sat tokens from the relay's saved mint. It acquires the same
exclusive state lock as the service, so it refuses to race a running relay.
While the original receive receipt is retained, retrying the same token returns
the original result without redeeming it again. Its returned amount is not new
wallet credit.
Adding wallet funds does not change the lifetime spending budget, signed
evidence, existing channel limits or seller credit. Never initialize a new
relay directory as a substitute for reconciling an existing account.

## Collect and verify

After requesting settlement through the running relay's private control socket,
stop the relay. Query and export its remaining wallet balance:

```sh
printf '%s\n' '{"type":"balance"}' | fips-relay wallet /absolute/path/relay.json
printf '%s\n' '{"type":"export","id":1,"amount_sat":512}' |
  fips-relay wallet /absolute/path/relay.json
```

Use the actual balance rather than the example amount. Export IDs are positive
integers: keep the number for retries and increase it for each new return. This
is a fresh-profile protocol; old named export requests are not converted.
Export writes a new private file inside the saved state directory; the result
contains only its
path, amount and operation ID. Reusing the ID checks the saved export against
the original SDK result through a read-only lookup. A cached file without a
completed result for its exact request, or with conflicting payment fields, is
refused and preserved for reconciliation. Validation never starts or recovers
a wallet send. If the file is missing, the SDK resumes the
original wallet request and publishes its token atomically; it never substitutes
a new send. A changed amount or mint is refused. Keep the saved wallet evidence
and retry with the original ID, rather than inventing another ID.

Export requests retain their original identity and result in the shared SDK send
journal, which permits at most 128 retained requests and 4 MiB, with a 64 KiB
limit per record. Other pending sends use the same capacity; these are upper
bounds, not a guarantee of 128 exports. The private export directory also permits
128 retained files; unknown files consume capacity and are preserved. Capacity
exhaustion refuses a new request before sending.
Do not delete the journal to reclaim space. An older `.intent` reservation
also requires reconciliation of the original wallet activity: that marker
cannot identify a recoverable SDK request.

Send `{"type":"collect","token":"ENCODED_TOKEN"}` to the mint's private
control socket to redeem each return. `{"type":"report"}` reports reserved
issuance, collected balance and simulated settlement conservation. A complete
run also checks every old wallet is empty, the final collected balance matches
actual funding, and each router's final balance includes its positive net
forwarding margin before collection. Conservation alone is not evidence that
traffic used the intended wireless path.

After collecting every export through a given number, or durably retaining their
complete tokens in another trusted wallet workflow, release that prefix locally:

```sh
printf '%s\n' '{"type":"acknowledge_exports","through":1}' |
  fips-relay wallet /absolute/path/relay.json
```

This is a custody acknowledgement, not a delivery receipt or peer message.
It permanently closes **every** number through the supplied value, including
unused numbers. Never acknowledge tokens that exist only in the export directory.
The SDK refuses unfinished sends, retains cumulative gross amounts and fees, and
commits the retired-number limit before files are deleted. Conflicting cached
results are preserved and refused. If cleanup is interrupted, retry the same
acknowledgement; totals are not counted twice. A new export also completes cleanup
of already acknowledged files. Old numbers cannot spend again, even with changed
terms or missing files. Unknown files are never deleted. No spending limit resets.
This bounds export cache and send-request retention; it does not establish bounded
lifetime storage for every other native wallet record.

## Verification

The regular `bench` suite uses three real exports to check custody, capacity,
interrupted cleanup, cumulative costs and replay refusal. The same fixture has
an explicit sustained case with 131 exports, exceeding the retained-request
limit. Run it separately with the accepted dependency configuration:

```sh
cargo test -p fips-relay --all-features --test bench \
  acknowledged_exports_outlive_the_request_limit_without_reusing_spends -- --ignored
```

```sh
cargo test -p fips-relay --features testbench --test bench
```

Tests exercise real mint funding, wallet import retries without double credit, an active
relay's exclusive lock, retained spending state, private idempotent export and
redemption, lost-file recovery without another debit, issuance bounds, refused
public binds, and both command-line tools through the private mint control socket.
The command-line fixture also recovers a lost export file across separate process
invocations and verifies that the wallet was debited only once. These supplement
the native paid forwarding tests; they do not replace hardware path or
customer-flow checks.

## Holding a committed acceptance response

An explicitly `testbench`-enabled relay build exposes three additional requests
on its existing private operator socket. Normal builds reject them. They add no
peer protocol message, spending authority or persistent configuration.

- `test_accept_barrier_arm` takes `buyer` and `destination` npubs,
  `trial_max_units`, and `hold_ms` in `1..=180000`.
- `test_accept_barrier_status` reports waiting/held replies, the captured offer
  and purchase, release counts and any terminal reason.
- `test_accept_barrier_release` forwards the original held reply bytes and ends
  interception. Rearming is rejected for the rest of that process's lifetime.

The real controller handles and commits each request first. Only a successful
acceptance for the selected buyer/destination with quota above the trial cap is
held. Configure the full offer above that cap; ordinary trial replies and
nonmatching replies pass through. Payment and quote services remain separate.
A matching request counter alone is not proof of commitment: require an active
barrier with a held reply and a captured purchase, and match that purchase to the
provider's durable active record before injecting the fault.

At most eight replies may be waiting or held, with a 16-request forwarding queue
and a 30-second response wait. Expiry, capacity failure and shutdown release held
replies; their reason remains visible and late replies cannot arm a new fault.
Forwarded-reply counts mean delivery to the local transport responder, not receipt
by the remote buyer. Use this instrument only in an isolated test run, not for
performance comparisons with ordinary builds.

Using the development dependencies in [FUNDING-COSTS.md](FUNDING-COSTS.md), run:

```sh
cargo test -p fips-relay --all-features --lib service::accept_barrier::tests
cargo test -p fips-relay --all-features --test service mixed_transport::accept_barrier::
cargo test -p fips-relay --no-default-features --lib service::tests::production_admin_rejects_test_accept_barrier_commands
```

The daemon test observes the real provider's committed purchase while the buyer
still waits, releases the reply, and verifies the same purchase, paid delivery,
settlement and conservation of 384 test sats. It establishes the barrier boundary;
it does not establish physical interrupted-promotion recovery.

## First hardware result

An isolated run used two endpoint processes on one ARM64 Linux host and three
ARM64 OpenWrt routers as distinct paid relays. Each endpoint had only its
adjacent router as a UDP peer. Inter-router FIPS peers used native Ethernet
frames over encrypted 802.11s interfaces, with mesh forwarding disabled and
management Ethernet outside those interfaces. The middle relay had no UDP
transport. Live peer snapshots matched only the configured five-node line.

Three 959-byte application payloads in each direction arrived on their first
attempt and matched the receiving endpoint's digest. Captures on the middle
router confirmed native FIPS frames in both directions on both Wi-Fi hops.
Captures include routing and payment traffic; packet totals are not application
throughput measurements.

| Participant | Initial test sats | After settlement | Net |
| --- | ---: | ---: | ---: |
| Endpoint A | 512 | 493 | -19 |
| Relay 1 | 512 | 525 | +13 |
| Relay 2 | 512 | 524 | +12 |
| Relay 3 | 512 | 525 | +13 |
| Endpoint B | 512 | 493 | -19 |

All six channels settled. Every final balance was exported and redeemed into
the test mint's collector wallet: 2,560 test sats, with all participant wallets
empty afterward. Prices were artificial test prices; billing covered opaque
FIPS session envelopes, including session control traffic, rather than only
the 5,754 application bytes.

This establishes basic bidirectional paid forwarding on hardware. Hardware
renewal, restart and route-change exercises, resource/performance measurements,
the public customer entry and phone flow remain separate acceptance work.

## Hardware recovery and renewal run

A second run reused the same saved identities, accounts and financial limits,
with another 256 test sats per participant. A fresh purchase after confirmed
refund replaced the explicitly closed channels. The middle physical router
then passed an orderly process restart and a forced process kill followed by
supervisor restart. The same six funded channels and retained spending limits
survived, and traffic resumed in both directions.

Longer traffic exposed a buyer/provider accounting gap after the crash: a
provider retained a submission that the buyer had lost from its checkpoint.
The controller now pays only the portion supported by its own evidence, so
later known submissions can continue earning payments. The unsupported
remainder stays unpaid and consumes the existing exposure allowance. This was
reproduced in a native mint-backed integration test and corrected on the same
funded hardware accounts. A simultaneous service restart also needed native
session recovery time; instantaneous or lossless recovery is not claimed.

With renewal paused, both directions stopped at their source channels' credit
limits while lifetime budgets remained positive. Enabling renewal replaced all
six starting channels, confirmed their refunds and restored both directions.
The renewal script matched 60 application payload digests across its phases
and observed four delivery gaps during automatic replacement. Additional
restart probes also verified both directions. These orchestration observations
are not throughput or packet-latency measurements.

| Participant | Second grant | After settlement | Net |
| --- | ---: | ---: | ---: |
| Endpoint A | 256 | 85 | -171 |
| Relay 1 | 256 | 368 | +112 |
| Relay 2 | 256 | 371 | +115 |
| Relay 3 | 256 | 375 | +119 |
| Endpoint B | 256 | 81 | -175 |

All 16 channels opened in the second run settled, including automatic
replacements. All 1,280 second-run test sats were collected, bringing total
collection across both runs to 3,840; every participant wallet was empty.
Routers retained home LAN management, client Wi-Fi and ordinary Internet access.

At that phase, physical route changes and performance had not been measured.
The later r4 experiment is documented below. Duplicate/unsolicited-traffic
exercises and the public customer/phone flow remain separate acceptance work.

## Persistent OpenWrt package and boot recovery

The three ARM64 routers subsequently installed a local APKv3 package on OpenWrt
25.12.5. The size-oriented static executable is 19,943,000 bytes; the archive is
9,292,518 bytes. This application build includes automatic source route refresh,
but paid hardware demonstrations above used the earlier, larger executable.
The size comparison does not establish forwarding performance.

Existing UCI paths and complete settled accounts were retained. A running r1 to
r3 package upgrade stopped and restarted the process with identical identity,
purchase history and remaining budget. The startup wrapper was exercised under
the real supervisor with a missing clock marker, an unreachable mint and a
bridged native-interface probe. It waited without loading a new account or
changing the live radio configuration.

Each router passed a real reboot, established by changed boot IDs. Final checks
confirmed the saved accounts, exact expected native neighbour connections, live
MAC addresses, clock synchronization, isolated mesh interfaces and disabled mesh
forwarding. An AP interface remained active; DNS and HTTPS Internet requests from
each router succeeded. Existing network files matched the final pre-reboot
configuration. The isolated mint process and existing host web service survived.
Final observed reboot-to-check-completion times were about 105 seconds per router;
this is service recovery timing, not a network latency benchmark.

The tests exposed automatically assigned virtual mesh MACs changing after boot
on two radios. A one-sided connection initially concealed one stale configured
peer address. After both radios rebooted, their accounts loaded but native peering
failed. Pinning the affected mesh interfaces to their intended addresses and
repeating their reboot checks restored stable peering. The LAN/AP configuration
was retained. See [openwrt/README.md](openwrt/README.md) for the configuration
requirement and package procedure.

At the end of the r3 phase the packaged router services ran idle with boot
startup enabled. Test endpoints were stopped, wallets empty and prior channels
settled. These checks
do not establish reboot recovery during an unfinished financial operation, paid
traffic on the new profile, other CPU architectures, firmware sysupgrade or old
opkg/IPK packaging. Those claims need separate evidence.

## r4 traffic measurements and physical route change

The subsequent `835726a` application build adds bounded operator probes,
control-stream counters and a private wrapper for native topology controls.
Three r4 upgrades preserved stopped-service state and existing accounts. Five
new funded accounts then exercised both directions over the wireless line and
over an explicitly established alternate wireless link after the middle service
stopped. Source watches changed route agreements automatically while preserving
their original Spilman channels. Four streams each delivered all 1,200 packets
at 0.96 Mbps; mean one-way delays were 4.2–5.6 ms on the shared-clock endpoints.

A longer stream confirmed the 4,096-attempt accounting cutoff despite available
credit. This is an explicit sustained-service limitation, not channel exhaustion.
After the middle service reconnected, all eight channels settled. Each relay
retained positive net income, all 2,560 new test sats were collected, and total
collection reached 6,400. Original router accounts were restored on r4; isolated
endpoint processes stayed stopped. See [MEASUREMENTS.md](MEASUREMENTS.md) for
packet counts, resource use, control-counter boundaries and remaining limitations.

## r5 forwarding-attempt accounting

New explicitly funded accounts on r5 carried 6,000 and 12,000 packets per
direction over all three wireless relays at offered rates of 2–8 Mbit/s. Those
streams had no missing packets and the accounting files stayed compact.
Source channels renewed automatically under further traffic, with packet loss
during the handover and successful subsequent delivery. All eight channels
settled; relay net earnings were 75, 74 and 75 test sats. All 2,560 new test sats
were collected, bringing cumulative collection to 8,960. Original router
accounts and ordinary services were restored and verified on r5.
See [WIRELESS-ACCOUNTING.md](WIRELESS-ACCOUNTING.md) for precise counts, CPU cost,
memory, package provenance and limitations.
