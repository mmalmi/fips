# Stochastic Network Simulation

Automated network testing for FIPS. Generates random or explicit
topologies, spins up Docker containers, and applies configurable
stressors (network impairment, link flaps, traffic generation, node
churn) over a timed simulation run. Scenarios cover general stress
testing, cost-based parent selection, mixed link technologies
(fiber/Bluetooth/WiFi), and transport-specific validation (UDP, TCP,
Ethernet). Logs are collected and analyzed automatically.

## Prerequisites

- Docker with the compose plugin
- Rust toolchain (for building the FIPS binary)
- Python 3 with `pyyaml` and `jinja2` packages

## Quick Start

```bash
./testing/chaos/scripts/build.sh
./testing/chaos/scripts/chaos.sh smoke-10
```

## Paid Ethernet acceptance

The focused three-node line uses the production relay and a local test mint,
with native Ethernet beacon discovery and no configured peer identities or
addresses. It requires an existing Linux ARM64 `fips-test` image containing
`ip`, `nsenter`, `tc` with kernel netem support, and Python 3.9+ with SQLite
and Linux pidfd support, plus freshly built Linux ARM64
`fips-relay` and `fips-relay-test-mint` executables. The harness never builds or
pulls images. Its Python 3.9+ entry point needs only the standard library.

From the repository root, set `BINARIES` to the directory containing those two
executables, then run:

```sh
umask 077
run="$(mktemp -d /tmp/fips-paid.XXXXXXXX)"
mkdir "$run/bin"
cp "$BINARIES/fips-relay" "$BINARIES/fips-relay-test-mint" "$run/bin/"
cd testing/chaos
python3 -m sim.paid_relay --binary-dir "$run/bin" --output "$run/result" \
  --image fips-test:latest
```

Use a fresh output directory. Only the two executable files and configuration/
log directories are bind-mounted. State and control sockets stay inside Linux;
host-shared filesystems on Docker Desktop may not support Unix sockets. The
mint uses a Docker-allocated private address on an internal network and issues
exactly 384 disposable test sats. No host LAN or Wi-Fi configuration is changed.

The acceptance checks:

- Discovery leaves wallet balances and funding authority unchanged.
- Unpaid application traffic is denied before either source authorizes a buy.
- Paid traffic arrives in both directions and automatic payments reach the relay.
- A link outage evicts the neighbor using production timeouts; beacon discovery
  reconnects it with the same funding operations, channels, and capital budget.
- Traffic and payments resume without resetting the lifetime buyer budget.
- Each direction experiences 80-ms delay, a short 100% loss interval, and
  reordering (`delay 80ms reorder 100% gap 2`) on the relay's outgoing veth.
  Raw traffic-control counters and probe reports must show the intended effect:
  observed delay, eight submissions with zero received during loss, or actual
  out-of-order delivery. Route accounting must advance while loss is active;
  aggregate link counters do not identify individual encrypted probe packets.
- A fresh stream delivers all eight packets after the faults; automatic payment
  reconciliation retains the original channels, quotes and spending limits.
- Both channels settle while the services are live. After verified graceful
  shutdown, all node balances are exported and redeemed by the test collector.
  All 384 issued sats must be collected, with zero spendable balance on each node.

Each probe submits eight 256-byte payloads. Delay/reordering probes use 40 packets
per second; other probes use four. Both directions keep the original 32-sat
channel capacity and 30,000-unit quote limit. Billing counts locally submitted
opaque session envelopes, including attempts later dropped by the impaired
link; received payload bytes are reported separately. Lost datagrams are not
replayed to manufacture complete delivery. The mint's separate interface is
never impaired. Collection redeems Cashu into the collector wallet; it is not a
Lightning withdrawal.

Payment checks freeze a supported cumulative claim once the affected route's
accounting advances, then wait for that claim to be credited. FIPS background
traffic can keep accumulating usage; the test does not demand zero outstanding
credit. Each seller journal must retain the original capacity and grace bounds,
and a later durable buyer authorization must cover its recorded credit. The
last financial sample, fixed validation error, and sampling times are retained
on failure so a deadline does not hide an accounting assertion.

The quote-only financial invariant is covered separately by the production
controller integration tests. This three-node run checks native discovery and
one forwarding hop; it does not establish Wi-Fi behavior, throughput, or scaling.
Faults have fixed parameters and must be observed, but packet scheduling is not
claimed deterministic. Payment reconciliation after data faults alone does not
prove recovery from an interrupted payment reply.
The corrected Linux ARM64 fixture passed all 16 phases in about 140 seconds.

To also interrupt payment control, build both executables with
`--features testbench,measurements` and add `--payment-faults` to the command
above. This optional phase drops the relay-to-buyer carrier direction while a
fresh paid data stream continues in the other direction. It requires observed
carrier drops, a new payment-port request, and repeated observations of an
unacknowledged payment. Restoring the carrier must let the automatic scheduler
reconcile a fixed supported balance on the original channel, then pay for a
further healthy stream. The original capacity, quote limits and lifetime budgets
remain in force, followed by the same settlement and complete test-fund collection.

This short carrier fault can interrupt a connection or a Usage exchange before
an Update is accepted. It does not identify a lost encrypted reply. Exact
post-acceptance reply loss is covered by the relay controller integration test
`slow_neighbor_payment_and_settlement_do_not_stall_healthy_channels` with
`--all-features`: a test proxy discards one real payment handler's successful
reply after the seller has saved the credit. Recovery must use the automatic
scheduler, preserve funding and budgets, and leave another neighbor able to pay.
Neither recovery phase manually flushes payments or settles channels.
The same controller scenario without `measurements` delays a request before its
handler instead; both feature modes retain the interrupted-settlement check and
the original spending limits.
The optional Linux ARM64 run passed all 20 phases in about 176 seconds, including
both short carrier interruptions and collection of all 384 test sats. The two
observations recorded no completed Update handlers; they establish interrupted
control and automatic reconciliation, while the proxy test establishes the
separate post-acceptance reply-loss boundary.

The scenario has a 15-minute deadline. Individual Docker commands are bounded,
and cleanup continues independently of that deadline. Run-scoped names refuse
collisions; cleanup checks exact resource IDs, ownership labels, and interface
aliases. Impairments require an alias-verified owned veth with its default queue;
an existing or changed traffic-control queue is never replaced or removed. The
result JSON records binary hashes, exact owned resource IDs, traffic-control and
probe reports, aggregate financial evidence, and cleanup errors; it excludes
private keys and token contents. Live wallet
totals come from a read-only SQLite transaction inside each container, without
copying a live database. Logs and results remain in the output directory;
containers, their private state, veth pairs, and the internal network are removed.

Ownership and cleanup regressions run without Docker mutations:

```sh
python3 -m unittest discover -s testing/chaos/tests -v
```

## Physical Wi-Fi discovery acceptance

`sim.wifi_discovery` exercises three explicitly supplied OpenWrt routers with an
existing 802.11s radio triangle. It starts fresh, unfunded profiles beside the
original services on experimental EtherType `0x88b5`. The original services must
use a different EtherType and have no active purchases or source watches. No
package, saved account, UCI network configuration or mint is changed. Account
state uses persistent storage; the candidate executable uses `/tmp`.

Supply a private JSON inventory with a `nodes` array of three records, ordered
first leaf, middle, second leaf. Each record contains:

| Field | Meaning |
| --- | --- |
| `host` | Existing SSH alias with administrative access; host-key checking remains enabled |
| `ssh_config` | Optional absolute path to the operator's SSH configuration |
| `interface` | Existing unbridged mesh interface on a dedicated radio, with no IP and `mesh_fwding=0` |
| `management_interface` | Separate working management interface with a default gateway |
| `original_binary`, `original_config` | Exact executable and JSON configuration of the existing relay |
| `state_parent` | Existing writable persistent directory for fresh test profiles |
| `expected_board` | Expected `ubus system board` board name |
| `expected_mesh_mac` | Independently verified current mesh interface address |

The routers need `nft` with netdev ingress support, `jsonfilter`, `flock`, `setsid`,
`iw`, `sha256sum`, a supplicant control object and the normal OpenWrt clock-readiness
marker. The mesh radio must have no other interfaces, including access points.
Its sole saved supplicant network must be the current SAE mesh, with a fixed
frequency and saved `mesh_fwding=0`. The harness derives its network ID and records
the interface index, address and mesh profile; it does not copy the SAE key.
Management must remain reachable when this interface leaves the mesh. The supplied static
Linux ARM64 relay should be built from the verified source and dependency graph
with `testbench,measurements`; the harness does not build or install packages.

```sh
cd testing/chaos
python3 -m sim.wifi_discovery \
  --inventory /private/operator/wifi-inventory.json \
  --binary /private/artifacts/fips-relay \
  --output /private/results/new-wifi-run
```

The run verifies authenticated beacon discovery without a FIPS peer roster,
then excludes the leaf-to-leaf shortcut using temporary, owned `nft` tables that
match only the experimental EtherType. Both directions must deliver fresh streams
through the middle router, with observed middle-router admission and shortcut
drop counters. Free-only source watches authorize this traffic without monetary
journal changes. The second leaf then leaves the mesh through supplicant's
`MESH_GROUP_REMOVE` until peers are actually evicted. `MESH_GROUP_ADD` rejoins
the same saved network without recreating its interface. Discovery and delivery
must recover without changing identities, peer lists or source authority.

Independent management probes continue during the run and restoration. Each
router also runs a lease-based cleanup guard: lost controller contact restores an
owned mesh departure, removes only the owned table and stops only the candidate
process. Guard cleanup and disruptive actions share a kernel lock so a late
command cannot recreate an outage after cleanup. Existing tables are refused
before deletion is armed. A mesh restore acknowledgment is insufficient: the
guard retains its recovery marker until carrier, supplicant state, interface
identity and forwarding policy are verified. Shutdown allows 65 seconds for
in-flight control work to finish; a forced stop is recorded as a failure even
after safe cleanup. Normal completion verifies the original configuration,
account hashes, budget and peer graph. Fresh test profiles are retained; temporary
candidate executables are removed. Inspect the private `result.json` for every
phase, management sample and cleanup result.

This is free forwarding and controlled split/rejoin acceptance. It does not prove
paid channel recovery on radio links, arbitrary physical mobility, congestion
fairness or permissionless radio joining: an existing SAE-protected mesh still
requires its shared key. It runs the service directly; OpenWrt's package startup
wrapper and power-loss recovery have separate acceptance scopes.

The optional `--open-mesh` mode prepares an owned, temporary open 802.11s profile
on the same dedicated interface; it leaves the saved SAE network and UCI settings
intact. Two nodes must discover each other before the third radio joins. The
candidate still authenticates FIPS neighbors and requires explicit free-route
authority. This mode needs both nft netdev ingress and egress support: it isolates
the original service's EtherTypes in both directions before changing the radio.
It caps radio peers at eight and inactivity at 60 seconds, verifies those actual
limits after convergence/rejoin, and restores the exact saved limits/profile.
Management and APs must remain separate. An ambiguous untagged network, changed
owner or failed restoration leaves recovery markers and original-service
isolation in place; cleanup fails rather than deleting an unowned profile or
exposing original accounts. No shared SAE key is used by the temporary profile.
Its zero-funded physical acceptance passes on three ARM64 OpenWrt routers:
two-node discovery followed by a late third-node join, 40/40 fresh packets,
two-hop delivery in both directions before and after leave/rejoin, unchanged
financial journals and exact restoration. All 285 management checks pass, as do
the 56 Linux guard tests. Paid open joining has separate acceptance below;
arbitrary physical mobility, hostile-load tolerance and automatic channel choice
remain unverified.

Before hardware use, run `python3 -m unittest discover -s tests -p 'test_wifi_*.py' -v`
from `testing/chaos` on Linux with `flock`. The guard tests use real process ownership and file locks,
with isolated fake interface/firewall commands; Linux-only tests explicitly skip
on other hosts. They cover expired leases, late commands, table collisions,
concurrent cleanup, exact candidate termination, changed mesh profiles and
failed restoration. A raw `ip link down/up` is unsuitable for this test: it can
leave supplicant's mesh state inconsistent with the kernel. The mesh-specific
commands explicitly leave/rejoin the retained network. See the
[hostap control implementation](https://w1.fi/cgit/hostap/tree/wpa_supplicant/ctrl_iface.c?id=ca266cc24d8705eb1a2a0857ad326e48b1408b20#n3321).

For simultaneous streams, a runner can register auxiliary relay profiles on a
router before preparing its guard. Each has fresh persistent accounts and its
own launcher, PID and log, while sharing the staged executable and recovery
lease. Cleanup signals all registered profiles before waiting under one shutdown
deadline, retains their accounts, and refuses late or duplicate launches. This supports
independent endpoints on the same three-router bench; it does not itself prove
paid/free priority on the physical wireless links.

### Competing wireless provider topology

`sim.wifi_diamond` checks the topology for a client with two relay choices before
introducing funds. Inventory entries one and two are providers; entry three hosts
the destination and a separate auxiliary source identity. The source uses UDP
bound to entry three's existing management IPv4 address and reaches both providers
on their observed ephemeral listeners. Providers reach the destination only over
native Ethernet frames on Wi-Fi. Owned experimental-EtherType filters remove the
provider-to-provider radio shortcut. The source has no Ethernet adapter, the
destination has no UDP adapter, and exact peer sets exclude a same-host shortcut.

```sh
python3 -m sim.wifi_diamond \
  --inventory /private/operator/wifi-inventory.json \
  --binary /private/artifacts/fips-relay \
  --output /private/results/new-wifi-diamond --open-mesh
```

The supplied ARM64 executable needs `measurements`. Each management interface must
already have one unambiguous private IPv4 address; addresses and firewall policies
are not changed. Direct diagnostic streams check both client-to-provider links
and both provider-to-destination links. An unfunded end-to-end stream must remain
undelivered while native application-send and provider policy-denial counters
advance. These are bounded phase aggregates, not matched packet receipts. All
four accounts must retain empty wallets, unchanged financial journals and no
source watches. No mint runs and no funds are imported or issued. The existing
guard restores the radio profiles and stops both profiles on the third router.

This unfunded fixture establishes the physical topology. Source/destination
co-location shares CPU resources, and the source's first hops use the management
LAN. The funded extension below independently checks automatic provider choice.

### Automatic paid selection between wireless providers

`sim.paid_diamond` reuses that topology and its original-state restoration guard:

```sh
python3 -m sim.paid_diamond \
  --inventory /private/operator/wifi-inventory.json \
  --binary /private/artifacts/fips-relay \
  --mint-binary /private/artifacts/fips-relay-test-mint \
  --output /private/results/new-paid-diamond --open-mesh
```

Only the source receives 128 test sats, with at most two 64-sat channels and no
renewal. The owned mint uses private SSH loopback forwards. A single watch
compares provider tariffs of 128/160 msat per KiB under a 192-msat ceiling. The
normal selector defaults remain intact, including the 32-KiB trial and 60-second
retry cooldown. Each phase allows at most sixteen 16-packet, 256-byte bursts,
spaced across a 180-second window. The harness never forces a route or payment.

Acceptance requires a fresh trial, promotion, complete new payload delivery,
carrier-specific native quality and an advancing acknowledged payment for the
cheaper provider, the alternative after radio loss, and the recovered cheaper
provider. Raw journal anchors retain the original funding operations across
zero, one and two channels. Closure pauses purchases, settles once, stops all
four profiles before wallet export, and verifies exact per-wallet conservation.
Uncertain operations retain their original accounts and mint for recovery.

The 2026-09-18 run passes all three stages with 2/5/2 bursts. Of 144 submitted
packets, 96 arrive; the 48 missing packets occur during failover. Each accepted
stage ends with a complete 16-packet burst and fresh healthy feedback. The same
two channels settle 3/2 sats to the providers and refund 123 sats to the source;
all 128 sats are collected and all four wallets end empty. All 486 management
checks and original-state restoration pass. The focused Linux suite has 107
passing checks. An earlier attempt rejected an inconsistent source tariff before
issuing funds; all four corrected configs were then initialized with the actual
ARM64 executable in isolated temporary accounts before this run.

This is one controlled wireless provider-loss/rejoin test. The radio cut removes
onward reachability and quotes as well as delivery quality, so it does not
isolate quality ranking. Explicit peer-eviction waits and paced confirmation
prevent interpreting its elapsed time as a failover latency measurement. Moving
mesh merge/split, fast roaming, contention and sustained performance remain open.

#### Failover with traffic during the radio cut

Add `--active-failover` to cut the cheaper provider's radio during an in-flight
paid burst, after verifying payload arrival and its unchanged full agreement.
The alternative phase uses up to eight 32-packet bursts at two packets per second,
with a half-second receive drain and no deliberate inter-burst spacing. It keeps
the same 180-second deadline, total payload allowance and financial limits. The
sender is drained exactly once, including failures; the interrupted burst cannot
satisfy the replacement route's complete-burst acceptance check. Exact peer
eviction is checked after working-route confirmation. Saved membership at that
confirmation distinguishes connected, disconnected and absent departing edges.

The first active-cut run on 2026-09-18 did **not** pass the complete cycle. Initial
delivery passed 32/32. The alternative delivered 60/96 during the transition and
ended with a complete 32/32 burst, native quality and automatic payment. That
confirmation occurred 50.05 seconds after the cut request; this is a controller
confirmation upper bound, not a measured packet outage. The departing wireless
edge was already absent at acceptance, so the result does not isolate quality
detection from peer removal.

After rejoin, the cheaper provider delivered 100/256 attempts, but its loss
estimate remained unknown despite fresh RTT and delivery feedback. Its trial
stalled at 32,752/32,768 billed bytes, with too little allowance for another
payload, and selection did not fall back. This exposes separate loss-evidence
and exhausted-trial recovery gaps. All 128 test sats were collected, all wallets
ended empty, all 600 management checks passed, and original router settings were
restored. The combined Linux harness suite passes 164 checks; that software
coverage does not turn the failed hardware cycle into acceptance.

### Paid Wi-Fi recovery

`sim.paid_wifi` reuses the same inventory, guard and radio lifecycle. It needs a
native `fips-relay-test-mint` executable on the controller and an assigned private
controller address reachable from all three routers. The mint binds that address
on an allocated port, caps issuance at 384 test sats, and checks reachability from
every router before funding three fresh accounts with 128 sats each.
If inbound controller LAN access is unavailable, use `--mint-address 127.0.0.1
--mint-ssh-forward` instead. This uses the supplied inventory's SSH settings and
one dedicated, non-multiplexed reverse tunnel per router; every router sees the
same loopback mint URL. No host or router firewall setting changes are needed.
The harness refuses occupied ports or additional configured forwarding rules,
checks the actual listeners are exclusively IPv4/IPv6 loopback, and verifies
`/v1/info` through all three tunnels before issuing any test funds.

```sh
python3 -m sim.paid_wifi \
  --inventory /private/operator/wifi-inventory.json \
  --binary /private/artifacts/fips-relay \
  --mint-binary /private/artifacts/controller/fips-relay-test-mint \
  --mint-address "$CONTROLLER_LAN_ADDRESS" \
  --output /private/results/new-paid-wifi-run
```

Add `--open-mesh` to use the same guarded temporary open radio profile and late
third-node join as the free acceptance. All three accounts are funded while the
candidate services are stopped, before any temporary radio join. A radio failure
restores the original profile when ownership and state are provable, while
retaining funded accounts and the original mint/SSH forwards until the test funds
are reconciled. Open radio admission does not change payment terms or authorize
free transit. Combined paid/open physical acceptance passes all 28 phases on
three ARM64 OpenWrt routers: 32/32 paid packets, zero of four unpaid probes,
automatic payment recovery on the original channels after leave/rejoin, all
384 test sats collected, and exact restoration without management or cleanup
errors. See [readiness](../../crates/fips-relay/READINESS.md#physical-wi-fi-discovery-and-free-recovery)
for scope and remaining checks.

After verifying unpaid forwarding is denied, each endpoint buys the route through
the middle router. Fresh streams must cause matching buyer/provider usage and
automatic signed payments before and after radio leave/rejoin. The original two
32-sat channels, funding operations, route agreements and lifetime budgets must
survive; recovery does not issue another purchase command. These checks reuse the
paid Ethernet accounting and settlement validators. Routers need no SQLite CLI:
wallet balances are checked offline before launch and after settlement; live
observations use accounting journals and bounded authorization, credit and
exposure, without claiming a live wallet snapshot.

Completion requires the middle router to earn both endpoints' payments, settlement
of both original channels, collection of all 384 sats, empty test wallets, and the
same restoration checks as the free run. The mint stops only after conservation
and complete collection are confirmed. If a financial operation is uncertain, the
run fails and preserves the original mint process, persistent accounts and private
export records for deliberate reconciliation. Do not restart or replace that mint:
its simulated Lightning state is in memory. Issuance, import, export and collection
are never automatically retried. Keep the controller online until reconciliation
is complete. The output path must fit the local Unix socket's length limit.
SSH mode also preserves surviving owned tunnels when funds or cleanup are
uncertain, with private process/configuration evidence in the run directory.
It never replaces a failed tunnel during a funded run. Tunnels are stopped only
after complete collection (or zero issuance), and their listener removal is
checked before stopping the mint. A failed cleanup is reported as a failed run.

Run the Wi-Fi, financial, fault and settlement tests on Linux before hardware use;
include `tests` in `PYTHONPATH` for the existing payment-fault test imports.

Add `--active-outage` to `sim.paid_wifi` to leave the radio mesh while an
explicitly funded round-trip stream is still sending. The fixture waits for
partial replies, removes leaf n03 from the radio mesh by default, observes actual peer
eviction, and requires missing replies from the original finite stream. It
requires the cut to complete before the earliest final paced send, using a
controller-side duration bound; a pending management response is insufficient.
Reply counts must remain unchanged during a two-second isolated window.
The radio then rejoins automatically; a distinct eight-packet round-trip stream
must complete, followed by the existing bidirectional payment checks. Return
allowances are disabled so both directions require the original paid channels.

Use `--active-outage --outage-node n02` to remove the middle router instead;
add `--open-mesh` to use the existing temporary open-radio lifecycle. This bridge
case requires every router's full FIPS peer list to become empty, including removal
of stale disconnected entries. Rejoin must restore exactly n01↔n02↔n03. The
result records the selected radio and all three rosters, retains the same process
epochs and financial authority, then requires fresh replies, both-direction paid
progress, and the existing 384-test-sat collection. `--outage-node` is valid only
with `--active-outage`; `n03` explicitly selects the default leaf case.

The bridge case exercises an actual radio departure and FIPS graph partition with
emulated range constraints: the existing experimental-EtherType filter excludes
the n01↔n03 shortcut, while management Ethernet remains available. It does not
exercise physical movement or merge two multi-router networks.

The test retains the original processes (including their start times), financial
identities, funding operations, channels, route agreements and lifetime budgets.
Once the two channels are known, a failed radio or delivery check still attempts
ordinary settlement and collection; uncertain funding retains the original
accounts and mint. The active stream is never resent. Radio restoration uses the
existing ownership guard, including when an observation fails during the outage.

The reported recovery upper bound runs from the rejoin request through observed
peer convergence and completion of the fresh diagnostic stream. It includes
controller polling and probe time, so it is not an exact first-packet convergence
time. This controlled cut does not guarantee interruption at a particular payment
message, arbitrary physical movement or selection among competing paid routes.

The first leaf active-outage run on the temporary open mesh (2026-09-18) passed.
The cut completed 1.72 seconds after dispatch, before the earliest final paced
send at 11.5 seconds. The interrupted stream delivered three of 24 replies;
21 were missing, and counts stayed unchanged during the isolated observation.
Actual peer eviction was observed 30.82 seconds after the completed cut. After
rejoin, all eight fresh round trips completed with a 6.31-ms mean RTT. The
request-to-complete-recovery upper bound was 9.75 seconds. Subsequent ordinary
streams delivered and advanced payments in both directions on the original
channels, with all three process epochs unchanged. The middle router earned
24 test sats; all 384 issued sats were collected. Original radio settings and
router baselines were restored, the mint and its forwards stopped, and all
312 management checks passed without cleanup errors.

The first middle-router active-outage run on the temporary open mesh
(2026-09-19) also passed. The cut completed 1.16 seconds after dispatch, before
the earliest final paced send at 11.5 seconds. Two of 24 replies arrived; 22
were missing, and counts stayed unchanged during the isolated observation.
All three full FIPS peer lists were empty 57.47 seconds after the completed
cut. Rejoin restored exactly n01↔n02↔n03 on the original processes and payment
channels. All eight fresh round trips completed with an 11.10-ms mean RTT;
the request-to-complete-recovery upper bound was 26.70 seconds. Subsequent
streams delivered and advanced payments in both directions. The middle router
earned 20 test sats, all 384 issued sats were collected, and every test wallet
ended empty. All 417 management checks passed, original router baselines and
radio profiles restored, and the mint and its forwards stopped without cleanup
errors. This recovery bound starts at the rejoin request, after the deliberate
wait for full peer eviction; it excludes that wait and is not an exact packet
outage duration.

### Paid/free Wi-Fi priority

`sim.wifi_priority` reuses the paid Wi-Fi lifecycle and adds two unfunded
loopback endpoints. The free source enters the middle router locally; paid
traffic arrives from the first router. Both then leave the middle router toward
the last router over the same wireless link. The free destination has an explicit
zero fee, and return allowances are disabled. Auxiliary processes share their
hosting router's ownership and recovery guard.

From `testing/chaos`, first check the guarded topology without issuing funds:

```sh
python3 -m unittest tests.test_wifi_priority -v
python3 -m sim.wifi_priority \
  --inventory /private/routers.json --binary /private/fips-relay \
  --mint-binary /private/fips-relay-test-mint \
  --mint-address 127.0.0.1 --mint-ssh-forward \
  --output /private/topology-run --topology-only
```

Use an optimized, measurement-enabled ARM64 router binary and a native controller
test-mint binary. For the funded test, omit `--topology-only` and use a new output
directory. It retains the ordinary three funded accounts, two paid channels and
384-test-sat collection. Default traffic is 64,000 free packets of 1,000 bytes
at 4,000 packets/s, with 24 paid packets of 128 bytes at 4 packets/s. The middle
router limits free forwarding to 4 MiB/s with a 256 KiB burst; workload options
remain bounded by the production diagnostic service.

Acceptance requires middle-router background queue overflow between observations
made while paid delivery is still incomplete, all paid packets delivered without
duplicates or invalid data, and advancing automatic payment acknowledged while
the free sender is active. Free admissions must advance after paid delivery, stay
within the configured allowance, and recover for a fresh stream after congestion.
All five identities, peer transports and loopback addresses are checked. The
unfunded wallets and financial journals must remain unchanged.

No pressure or insufficient overlap fails acceptance. Once both ordinary paid
channels exist, failed load checks still attempt settlement and complete test-fund
collection before reporting failure; uncertain financial operations retain the
original mint and accounts for recovery. A topology-only pass does not count as
paid-priority acceptance. This experiment does not measure relay CPU efficiency
(the free source shares its CPU), synchronized one-way latency, or radio airtime
fairness.

Add `--round-trip --payment-delay-ms 500` to measure paid application round trips
before, during and after the free load. The sender records monotonic send times
and measures matching replies on its own clock; router clock synchronization is
unnecessary. Both directions use ordinary paid forwarding with the original two
channels. Both endpoints must acknowledge advancing payments while free traffic
is active. The three-phase fixture accepts at most 24 packets of 128 bytes per
phase, leaving the original 32-sat channels room for warmup and control traffic.
Larger RTT workloads fail before setup rather than enlarging financial terms.

The receiver is explicitly armed with `receive_probe.reflect=true`; the source
uses `send_probe.measure_round_trip=true`. Defaults remain disabled. Reflection
accepts only a matching authenticated source, fresh stream and unseen valid
sequence, and the arm expires after 60 seconds. Replies have a distinct
application marker and never cause more replies. No route is purchased by the
diagnostic. Re-arming a receiver while a probe sender runs is rejected.

`round_trip_latency` contains samples, extrema, a sum and histogram counts;
the existing `latency` field remains exclusive to one-way measurements. Summary
percentiles are histogram upper bounds, with null for an unbounded tail or empty
sample set. `reflected_submitted_packets` and `reflection_failed_packets` describe
local enqueue outcomes; only validated replies prove round-trip completion.
This includes application processing and both network directions. It does not
measure radio airtime, one-way delay or a maximum sustainable traffic rate, and
one small before/during/after sequence does not establish a production latency
guarantee.

The first three-router hardware run (2026-09-18) passed at the default workload:
all 24 paid packets arrived while middle-router background overflow increased,
and an automatic payment was acknowledged before the free sender finished.
The overloaded free stream delivered 28,626 of 64,000 packets; a fresh four-packet
free stream then delivered completely. All 384 test sats were collected, both
unfunded wallets stayed empty, and original router baselines were restored with
261 management checks and no errors. Throughput and long-running reliability
still need separate measurement.

The first round-trip run (2026-09-18) passed with a 500 ms maximum payment age
and the default workload. All 24 paid requests and replies completed in each
phase, with no missing, duplicate or invalid replies:

| Free load | Mean RTT | Maximum RTT | p95 histogram upper bound |
| --- | ---: | ---: | ---: |
| Before | 5.13 ms | 15.61 ms | 20 ms |
| During | 24.30 ms | 47.41 ms | 50 ms |
| After | 4.60 ms | 10.10 ms | 10 ms |

During partial paid round-trip progress, the middle router recorded 1,711
additional background queue drops. Payments advanced and were acknowledged in
both directions while the free sender remained active. The overloaded free
stream delivered 29,086 of 64,000 packets; the fresh four-packet recovery stream
delivered completely. Both original channels settled, all 384 test sats were
collected, and both unfunded wallets remained empty. The original router baselines
were restored, the mint and its forwards stopped, and 279 management checks
recorded no errors. This is one short stationary run, not evidence of mobile
route selection, sustained throughput or a latency guarantee.

### Phone acceptance helpers

`sim.remote_mint.RemoteMint` gives routers and a phone one explicit private mint
URL. The mint host requires Linux, Python with pidfd support, and the supplied
static ARM64 test-mint binary; the routers do not need Python. Every run uses
fresh persistent state and an issuance cap of at most 512 test sats. Money
requests are recorded before submission and never automatically replayed. The
mint stays running while funds are outstanding; terminal cleanup needs a fresh
conserved collection report and the exact child process's clean exit. Missing
supervisor evidence requires deliberate reconciliation with all state retained.

`sim.wifi_customer.CustomerAccess` adds three narrowly scoped rules under the
existing router lease. Lease expiry removes the customer UDP entry; access to
the pinned mint remains until `release_mint` receives that terminal proof. No
persistent network configuration, host route or proxy is introduced.

`sim.phone_customer.PhoneCustomer` drives only the separate acceptance app on an
explicit device. Keep one operator and its private evidence directory throughout
the run. `launch` and `open_setup` preview only; setup, import, purchase and export
still use the app buttons. Every click archives its old completion marker and
saves an intent before tapping. An uncertain action blocks further actions;
`reconcile` observes it without tapping again. `stage_funds` creates one private
input without importing it. Use the matching explicit `billing` in the
[customer profile](../../crates/fips-relay-app/README.md).

The [physical phone acceptance](../../crates/fips-relay/READINESS.md#physical-phone-customer-across-the-wireless-mesh)
using these composed helpers delivered eight packets, advanced all four paying
hops, and recovered all 512 test sats after the recorded checker correction.
The generic CLI wrapper below has focused tests; it has not been rerun on new
accounts.

`sim.paid_phone` composes these helpers for one acceptance phone and the same
three-router inventory. Install the verified isolated acceptance APK first,
leave it foreground and unlocked, and select the guest Wi-Fi yourself. The
harness checks the installed APK hash and original app's private-file hashes;
it neither installs apps nor changes the phone's Wi-Fi selection.

```sh
python3 -m sim.paid_phone \
  --scenario /private/operator/phone-scenario.json \
  --inventory /private/operator/wifi-inventory.json \
  --binary /private/artifacts/fips-relay \
  --mint-binary /private/artifacts/fips-relay-test-mint \
  --output /private/results/new-paid-phone-run
```

The private scenario JSON has `version: 1` and these required objects:

- `phone`: absolute `adb` path, exact `serial`, preserved private `evidence_dir`,
  and the verified acceptance artifact's `apk_sha256`.
- `customer`: existing guest `interface`, router address/prefix in `cidr`, unused
  `entry_port`, exact `ssid`, and one to four `denied_tcp` objects containing
  `label`, numeric IPv4 `address`, and `port`. Choose known reachable services
  outside the permitted mint access. No target is inferred from the inventory.
- `mint`: `address` assigned to the explicit Linux host, plus `ssh_spec` with
  `host`, `state_parent`, and optional `ssh_config`, as used by `RemoteMint`.

Add `--open-mesh` for the existing guarded temporary open profile and late third
router join. Before issuance, the phone must reach the exact mint before and
after the explicit denied TCP probes. A missing completion marker, ADB failure,
or tool/bind error is an unknown outcome and fails the run, not proof of denial.
These probes establish only the specified target/port observations.
They do not prove that a denied target's service was listening or establish an
exhaustive firewall policy.

This fixed fixture issues 128 test sats to each of four fresh accounts, uses
32-sat channels and 64-sat lifetime buyer budgets, and checks four fresh
1,000-byte payloads in each direction along phone → entry → middle → leaf.
Automatic payments must advance at all four paying hops before settlement.
The separate journal validator matches original funding operations, buyer and
seller terminal reports, retained authorization, per-wallet earnings/refunds,
and all 512 sats before collection. Completion requires full collection, four
empty wallets, terminal mint exit, and original phone/router restoration.
Uncertain actions retain their one-shot intents, accounts and required mint
access; the harness does not clear them or automatically resume the run.
This phone fixture does not add a radio partition or prove general Internet
access. Its reusable lifecycle/probe/financial tests are:

```sh
python3 -m unittest discover -s testing/chaos/tests -p 'test_paid_phone*.py' -v
```

## Available Scenarios

### General stress tests

Random topologies with increasing stressor intensity.

| Scenario | Nodes | Topology         | Duration | Netem | Link Flaps | Traffic | Node Churn | Bandwidth |
| -------- | ----- | ---------------- | -------- | ----- | ---------- | ------- | ---------- | --------- |
| smoke-10 | 10    | random_geometric | 60s      | --    | --         | --      | --         | --        |
| chaos-10 | 10    | random_geometric | 120s     | yes   | yes        | yes     | --         | --        |
| churn-10 | 10    | random_geometric | 600s     | yes   | yes        | yes     | yes        | --        |
| churn-20 | 20    | erdos_renyi      | 600s     | yes   | yes        | yes     | yes        | yes       |

- **smoke-10**: Baseline sanity check. No stressors, just verify tree convergence.
- **chaos-10**: Network degradation (5-50ms delay, 0-2% loss), link flaps (max 2
  down, 10-30s), and iperf traffic (max 3 concurrent). Netem mutates 30% of
  links every 15-30s between normal and degraded policies.
- **churn-10**: Extended run with node churn (1 node down at a time, 30-90s).
  Tests tree re-convergence after node departure/rejoin.
- **churn-20**: Aggressive scale test. Erdos-Renyi topology, up to 5 nodes down
  simultaneously, bandwidth tiers (1/10/100/1000 Mbps), `protect_connectivity`
  disabled (partitions allowed).

### Cost-based parent selection

Explicit topologies with heterogeneous link types (fiber, Bluetooth, WiFi) to
test that the spanning tree selects optimal parents based on link cost.

| Scenario          | Nodes | Shape           | Link types               | Duration | What it tests                                                       |
| ----------------- | ----- | --------------- | ------------------------ | -------- | ------------------------------------------------------------------- |
| cost-avoidance    | 4     | Diamond         | Fiber + Bluetooth        | 120s     | n04 picks fiber parent (n03) over Bluetooth parent (n02)            |
| depth-vs-cost     | 4     | Linear tree     | Fiber + Bluetooth        | 120s     | Cost tradeoff: depth vs. Bluetooth link quality                     |
| bottleneck-parent | 10    | Tree with BT    | Fiber + Bluetooth        | 120s     | n06 avoids Bluetooth bottleneck via n02, picks fiber via n03        |
| cost-mixed-7node  | 7     | Multi-type tree | Fiber + Bluetooth + WiFi | 180s     | n06 prefers fiber (n03) over WiFi (n04)                             |
| cost-reeval       | 4     | Diamond         | Fiber (mutated)          | 180s     | Periodic re-evaluation triggers parent switch (reeval_interval=15s) |
| cost-stability    | 4     | Diamond         | WiFi (all)               | 180s     | Hysteresis prevents flapping when costs vary within 20% band        |

- **cost-avoidance**, **depth-vs-cost**: Minimal scenarios validating the core
  cost formula. Bluetooth (L2CAP) links use 15-40ms delay and 2-8% loss;
  fiber uses 1-5ms delay and 0-1% loss.
- **bottleneck-parent**: Larger topology where some nodes have both fiber and
  Bluetooth paths to choose from, and one node (n09) is stuck with Bluetooth
  (no alternative).
- **cost-mixed-7node**: Three link technologies in one mesh. Traffic enabled.
- **cost-reeval**: Netem mutation (50% fraction, every 12-18s) degrades random
  links. FIPS override sets `reeval_interval_secs=15` so periodic re-evaluation
  catches cost asymmetry. Look for `trigger=periodic` in logs.
- **cost-stability**: All links are WiFi. Mutation swings costs between
  `slightly_better` and `slightly_worse` — within the hysteresis band. Expect
  ≤ 5 parent switches over 180s.

### Mixed-technology

Larger explicit topologies combining multiple link technologies.

| Scenario         | Nodes | Link types               | Duration | Netem mutation | What it tests                                    |
| ---------------- | ----- | ------------------------ | -------- | -------------- | ------------------------------------------------ |
| mixed-technology | 10    | Fiber + Bluetooth + WiFi | 180s     | 20%/30-60s     | Tree convergence across heterogeneous link types |

### Transport-specific

Explicit topologies exercising non-UDP transports.

| Scenario      | Nodes | Transport      | Shape | Duration | Netem | Link Flaps | What it tests                              |
| ------------- | ----- | -------------- | ----- | -------- | ----- | ---------- | ------------------------------------------ |
| ethernet-only | 4     | Ethernet       | Ring  | 90s      | yes   | --         | AF_PACKET transport with beacon discovery  |
| ethernet-mesh | 6     | UDP + Ethernet | Mesh  | 120s     | yes   | yes        | Mixed UDP/Ethernet, netem mutation + flaps |
| tcp-only      | 4     | TCP            | Ring  | 90s      | yes   | --         | TCP transport with static peer config      |
| tcp-chain     | 4     | TCP            | Chain | 90s      | yes   | --         | TCP multi-hop routing through chain        |
| tcp-mesh      | 6     | UDP + TCP      | Mesh  | 120s     | yes   | yes        | Mixed UDP/TCP plus TCP-over-FIPS iperf3    |

- **ethernet-only**: 4-node ring on raw Ethernet (AF_PACKET). Peers discovered
  via beacons, not static config. Minimal netem (1-5ms delay).
- **ethernet-mesh**: Mirrors `tcp-mesh` topology but with Ethernet instead of
  TCP. UDP edges use static config; Ethernet edges use beacon discovery.
- **tcp-only**: 4-node ring using TCP on port 8443. Tests connect-on-send,
  FMP framing over TCP, and reconnection. Netem enabled (1-10ms delay, 0-1%
  loss).
- **tcp-chain**: 4-node linear chain, all TCP. Tests multi-hop routing over
  TCP-only mesh.
- **tcp-mesh**: 6-node mesh with 4 UDP and 3 TCP edges. Both transports use
  static peer config. Netem mutation (30% fraction, every 20-40s), link
  flaps (1 link max, 10-20s down), and real kernel TCP traffic through the
  FIPS IPv6 adapter via `iperf3`.

### Congestion and ECN

Scenarios testing ECN congestion signaling and transport-level congestion
detection.

| Scenario           | Nodes | Topology | Duration | What it tests                                              |
| ------------------ | ----- | -------- | -------- | ---------------------------------------------------------- |
| congestion-stress  | 10    | Tree     | 120s     | CE marking under kernel drops and MMP loss detection       |
| ecn-ab-on / ecn-ab-off | 6 | Tree     | 120s     | A/B throughput comparison: ECN enabled vs disabled          |

- **congestion-stress**: 10-node tree with 1 Mbps egress bandwidth caps,
  5-10% netem loss, and heavy iperf3 traffic. Ingress policing (1000 kbps)
  and small `recv_buf_size` (4 KB) trigger both MMP loss detection and
  `SO_RXQ_OVFL` kernel socket drops. Validates end-to-end CE propagation:
  transit nodes detect congestion, set CE flag, destinations receive
  CE-marked packets, `ecn_ce_count` reported in MMP.
- **ecn-ab-on / ecn-ab-off**: Paired scenarios with identical conditions
  (6-node tree, 10 Mbps egress, 1000 kbps ingress policing, 10ms link
  delay, 8 KB recv buffer) differing only in `ecn.enabled`.
  `ecn-ab-test.sh` runs both and compares throughput and congestion
  counters. Initial results: +10.2% recv throughput with ECN enabled.

### Ingress Traffic Control

Scenarios can include `ingress` configuration to simulate upstream bandwidth
bottlenecks using tc ingress policing:

```yaml
ingress:
  enabled: true
  tiers_kbps: [1000]         # per-peer rate limit in kbps
  burst_bytes: 10000         # policer burst allowance
```

Per-peer u32 filters on the ingress qdisc (`parent ffff:`) rate-limit
inbound packets. Combined with small `recv_buf_size`, this reliably triggers
`SO_RXQ_OVFL` kernel socket drops for congestion detection testing.

### iperf3 JSON Capture

Traffic sessions capture iperf3 results using `--json` output. Results are
collected per-session from containers and saved as `iperf3-results.json` in
the scenario output directory, enabling automated throughput analysis across
scenario runs.

## CLI Options

| Option            | Description                          |
| ----------------- | ------------------------------------ |
| `-v`, `--verbose` | Enable debug logging                 |
| `--seed N`        | Override the scenario's random seed  |
| `--duration secs` | Override the scenario's duration     |
| `--list`          | List available scenarios             |

The scenario argument accepts either a name (`churn-10`) or a file
path (`scenarios/churn-10.yaml`).

## Scenario YAML Format

Annotated example based on `churn-10.yaml`:

```yaml
scenario:
  name: "churn-10"
  seed: 42                          # deterministic RNG seed
  duration_secs: 600                # total simulation time

topology:
  num_nodes: 10
  algorithm: random_geometric       # or erdos_renyi, chain
  params:
    radius: 0.5                     # algorithm-specific parameter
  ensure_connected: true            # retry until graph is connected
  subnet: "172.20.0.0/24"
  ip_start: 10                      # first node gets .10

netem:
  enabled: true
  default_policy:
    delay_ms: { min: 5, max: 50 }
    jitter_ms: { min: 1, max: 10 }
    loss_pct: { min: 0, max: 2 }
  mutation:
    interval_secs: { min: 20, max: 45 }  # re-roll interval
    fraction: 0.3                         # fraction of links mutated
    policies:                             # named policy profiles
      normal:
        delay_ms: [5, 20]
        loss_pct: [0, 1]
      degraded:
        delay_ms: [50, 100]
        jitter_ms: [10, 30]
        loss_pct: [3, 8]

link_flaps:
  enabled: true
  interval_secs: { min: 30, max: 60 }
  max_down_links: 2
  down_duration_secs: { min: 10, max: 30 }
  protect_connectivity: true        # never partition the graph

traffic:
  enabled: true
  max_concurrent: 3
  interval_secs: { min: 10, max: 30 }
  duration_secs: { min: 5, max: 15 }
  parallel_streams: 4

node_churn:
  enabled: true
  interval_secs: { min: 60, max: 180 }
  max_down_nodes: 1
  down_duration_secs: { min: 30, max: 90 }
  protect_connectivity: true        # never kill the last path

bandwidth:
  enabled: false                    # per-link HTB rate limiting
  tiers_mbps: [1, 10, 100, 1000]   # each link randomly assigned a tier

logging:
  rust_log: "debug"
  output_dir: "./sim-results"
```

## Topology Algorithms

| Algorithm        | Parameters           | Description                                             |
| ---------------- | -------------------- | ------------------------------------------------------- |
| random_geometric | radius (default 0.5) | Place nodes in unit square, connect pairs within radius |
| erdos_renyi      | p (default 0.3)      | Include each edge independently with probability p      |
| chain            | --                   | Linear chain: n01--n02--...--nN                         |
| explicit         | adjacency list       | Hardcoded edges with optional per-edge transport type   |

When `ensure_connected` is true (default), the generator retries up to
50 times to produce a connected graph.

### Directed Outbound Configs

The config generator assigns each static-config edge (UDP or TCP) to
exactly one node for outbound connection using a BFS spanning tree rooted
at the lowest node ID. Tree edges are assigned parent-to-child; non-tree
edges are assigned from the lower node ID to the higher. This eliminates
the dual-connect race condition where both sides initiate simultaneously,
and creates a clear "owning side" for each link — relevant for
auto-reconnect testing. Ethernet edges are excluded from static config
since they use beacon discovery.

## Output

Results written to `sim-results/` (configurable via
`logging.output_dir`):

- `analysis.txt` -- Summary: panics, errors, sessions, metrics
- `metadata.txt` -- Seed, node count, edges, adjacency list
- `runner.log` -- Orchestration events (topology, netem, churn, traffic) with timestamps
- `fips-node-nXX.log` -- Per-node log output

Exit code 0 on success, 2 if panics detected.

## Creating Custom Scenarios

1. Copy an existing scenario from `scenarios/`.
2. Adjust topology size, algorithm, and stressor parameters.
3. Run with `./testing/chaos/scripts/chaos.sh path/to/custom.yaml`.
