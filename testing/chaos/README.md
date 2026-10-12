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
and Linux pidfd support, plus Linux ARM64 `fips-relay` and matching
`fips-relay-test-mint` executables. Use the relay extracted from the package being
accepted and build the test mint from that package's exact source bundle. The
harness never builds or pulls images. Its Python 3.9+ entry point needs only the
standard library.

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
The exact r32 package passes all 16 phases in 105.2 seconds with its matching
test mint, using the existing assertions and timeouts. Both original channels
settle, all 384 test sats are collected, and every node wallet is empty before
ownership-checked cleanup. Source and executable hashes remain unchanged. The
source reference, build record, binaries and result are retained in
`work/paid-relay-verification/2026-09-29-ethernet-r32`.

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
renewal. The owned local mint uses private SSH loopback forwards. Alternatively,
pass both `--mint-host /private/operator/mint-host.json` (the shared remote-mint
host specification) and `--mint-address` with that host's assigned private LAN
IPv4 address. This runs the supplied ARM64 or x86-64 Linux mint there with a
128-sat issuance cap; the binary architecture must match the host.
The host JSON contains `host`, `state_parent`, optional `ssh_config`, and optional
integer `port` (0–65535). Omitting `port` or setting it to zero lets the host pick
a port; an explicit port can use an existing permitted LAN ingress rule. The
fixture checks reachability before issuing test money.
All three routers must reach it before the single source grant. A single watch
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

#### Connected paths with degraded delivery

Use `--loss-failover` instead of `--active-failover` to retain both wireless
paths while dropping every second experimental frame from the cheaper provider
at the destination. Only that directed test edge is impaired. The original
watch, tariffs, channel limits, finite traffic allowance and selector defaults
stay the same. The source samples native quality during each impaired burst,
because a switch may finish before an after-burst observation.

Acceptance additionally requires fresh loss above the configured threshold on
the unchanged cheaper full agreement, working paid delivery through the
alternative, and return to the cheaper provider after filter removal. Native
peer authentication times and link IDs must remain unchanged at the observation
points. Failed or uncertain fault installation is reconciled and cleared before
financial collection. The current physical result and its limits are recorded
in [relay readiness](../../crates/fips-relay/READINESS.md).

This remains a finite functional test. The filter affects native control frames
as well as data; it does not isolate control loss, continuously measure link
availability, or establish lossless handover, throughput or mobile convergence.

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

Use `--streams` with a measurement-enabled relay for reliable TCP/FIPS delivery
before, during and after controlled frame loss. Each 30-second window sends
512 KiB in each direction at 32 KiB/s over the authenticated two-hop radio line.
Both endpoints must acknowledge every byte and report the expected payload
digest. The middle window drops every twentieth experimental EtherType frame
arriving from the middle router at each leaf; actual drop counters must advance.
The final window runs after both owned rules are removed, using the same
processes and payment channels. Local fees are 1 msat/KiB so this finite workload
fits the original spending and channel limits; return allowances are disabled.

This mode shares the phone's stream dispatcher and validator, preserves both
endpoint outcomes when observation fails, and uses the existing 384-sat
settlement/collection and restoration checks. Resource snapshots include the
whole relay process and diagnostic overhead; they are not a matched cadence or
unloaded performance benchmark. Frame-loss and radio-departure modes are separate.

Use `--carrier-pressure-port PORT` instead of `--streams` to test rejected TCP
connections while the same paid radio line forwards exact TCP/FIPS streams.
The port must be unused and unprivileged; only the temporary middle-router
profile listens there, on its private management address, with eight inbound
slots. Four workers send complete invalid Noise initiations, unsolicited replies
and unknown-index encrypted records, at most 16 connections/s and 4,096 total.
Each socket read waits at most two seconds for closure. Native receive/accept
counters must match the records,
without capacity rejection or first-frame timeouts, and the pool must end empty.
Two 30-second windows each deliver and acknowledge 4 MiB per direction at
256 KiB/s, during pressure and after it ends. Fees are 1 msat/KiB, with the
existing 32 MiB quote bound. The original channels, automatic payment, test-fund
collection, management checks and restoration remain mandatory. Process and RSS
samples include diagnostic overhead; this finite test is not sustained DoS
qualification. Run `python3 -m unittest tests.test_carrier_pressure` with the
shared Wi-Fi/settlement checks before using hardware. An optional `--mint-host`
JSON inventory selects the existing remote Linux test-mint adapter; set its `port`
when the host firewall allows only a fixed test port.

Add `--carrier-pressure-transport websocket` to use the same paid scenario for
discovery-only WebSocket connections. The controller needs Python `websockets`
15.x; it is not a router dependency. Each client first verifies a nonce-bound key
hint, then sends pings, pongs, repeated hint requests or unsolicited hint replies
every 50 ms. The listener uses a five-second first-record deadline with idle and
ping timers disabled. A client must observe closure between 4.5 and seven seconds;
early resets and its own timeout fail the test. At least 24 connections must close,
native open/close counters must agree, and no FIPS data frames, capacity rejection
or occupied slots may remain. The shared duplex, accounting and restoration checks
apply unchanged. This tests startup expiry alongside radio forwarding, not paid
forwarding over the WebSocket listener itself.

Use `--carrier-pressure-transport udp` for two paced rejection windows at 2,000
and 10,000 packets/s, followed by a quiet recovery window. Each carries the same
4 MiB paid stream in both directions. One controller worker uses 64 source ports
on its existing address, mixes invalid Noise initiations, unsolicited replies
and unknown-index records, with a 45-second deadline and a 450,000-packet ceiling. It
does not add addresses or spoof sources. The middle router's temporary UDP
listener must be unused beforehand. Native receive counters must confirm that
at least half the submitted packets reached FIPS, and actual submission must
reach 75% of the target rate. Paid bytes must advance in both directions across
multiple live samples. The original process must retain two peers, at most eight
pending connections and a 64 MiB observed RSS high-water ceiling. These are finite
trial thresholds, not general resource bounds or Sybil-fairness guarantees.
Exact delivery, automatic credit, settlement and network restoration remain
mandatory. Native transport samples retain kernel-drop and error counters.

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
Build the relay with `--features measurements` for this mode: its process checks
require the live measurement counters. The test mint is a separate build with
`--features testbench`.

Use `--active-outage --outage-node n02` to remove the middle router instead;
add `--open-mesh` to use the existing temporary open-radio lifecycle. This bridge
case requires every router's full FIPS peer list to become empty, including removal
of stale disconnected entries. Rejoin must restore exactly n01↔n02↔n03. The
result records the selected radio and all three rosters, retains the same process
epochs and financial authority, then requires fresh replies, both-direction paid
progress, and the existing 384-test-sat collection. `--outage-node` is valid only
with `--active-outage`; `n03` explicitly selects the default leaf case and `n01`
selects the source radio.

Use `--active-outage --root-outage` to select the currently elected routing root
automatically. The fixture binds signed native tree observations to the three
saved identities and verifies the selected root immediately before the cut.
After peer eviction, every surviving connected component must replace that root
with loop-free coordinates using only its remaining links. Rejoin must restore
the original root and two-hop tree before fresh paid replies can qualify.
Processes, channels and spending limits remain unchanged. This mode cannot be
combined with a fixed `--outage-node`, `--brief-outage`, `--streams` or
`--interrupted-promotion`.

Use `--crowded-rejoin` as a separate scenario, optionally with `--open-mesh`.
It caps the middle router at two FIPS peers with two-second idle/rotation
settings. After the leaf radio leaves and is evicted, an unfunded fourth identity
on the leaf's host fills the spare slot over management-bound UDP. Continuous
ordinary application data protects the other radio neighbor, including during
paid probes and financial observations. The returning leaf
must replace the idle peer, retain the useful peer's authentication time and
deliver paid traffic on the original channels. The auxiliary process stays alive;
it cannot provide an onward path. Existing guards restore all three routers and
the normal settlement collects all 384 test sats. This is a neighbor-admission
check, not a radio-congestion or throughput benchmark.

Add `--crowded-newcomer` to one `--crowded-rejoin`, with an explicit
`--mint-host`, to replace the departed buyer with a fresh radio identity. Four
independent accounts receive 128 test sats each; the idle competitor stays
unfunded. The original buyer stops with its channel unsettled. The newcomer
must replace the idle competitor, retain the useful incumbent, reject unpaid
forwarding, then buy and automatically pay for both directions over radio.
The incumbent reuses its original channel for the new destination. Finally,
the original buyer returns, both original directions deliver again, and the
shared collector verifies every wallet and collects all 512 test sats.
Stopped-account observations require unchanged durable financial authority;
they do not open a second service or wallet owner. This mode cannot be combined
with `--crowded-pressure`. It tests one newcomer in a fixed radio layout, without
a fairness, movement or throughput claim.

Use `--crowded-rejoin 3` for three departures and returns on the same funded
accounts. The idle competitor remains running and may refill the slot immediately
after each departure. Every round must retain the original useful peer and relay
processes; both directions pay on the original channels between rounds. Each
round's bounded observations are saved in `crowded_rejoins`. The same 900-second
trial deadline, original spending limits and 384-test-sat issuance cap apply.
Each departure requires two recently confirmed unique useful payloads sent after
that round begins. The useful sender uses the existing ordinary-data command,
with 128-byte payloads capped at four sends per second and 3,600 sends per trial;
it stops before settlement. `useful_packets` records submission and observed
payload hashes independently of the strict paid probes. Failed probes retain
partial delivery counts and service observations; cleanup preserves the first
failure while still restoring the radio and stopping the sender.

Use `--crowded-pressure 4` for four successive groups of seven fresh identities
plus the original idle candidate. Each group stops before the next starts, keeping
at most eight candidates running. All 29 distinct accounts remain unfunded and
retain their financial journals. This mode runs five minutes of paid traffic;
every fresh candidate must send join traffic across three observations, including
an actual startup counter reading before its retry backoff grows. The
same original payment channels, capital limits and cleanup guard remain in use.
Its 120,000-byte quote at 256 msat/KiB has the same 30-sat maximum charge as
the single-group quote, allowing for the longer stream and charged FSP overhead.

Add `--crowded-pressure` to one `--crowded-rejoin` for eight unfunded identities
retrying the middle router over management-bound UDP while the original radio
route carries 120 40-byte paid packets in each direction at one per second.
Seven additional profiles share the existing guards; every fresh candidate must
send UDP join traffic across at least three observations, while the original idle candidate
keeps its existing retry backoff. All eight must remain unfunded. The two-minute
stream must overlap at least 90 seconds of observed join pressure, retain
the original authenticated peers and processes, and deliver every paid packet.
Samples check the two-peer cap, at most eight native connections and a 64 MiB
provider RSS high-water ceiling. These are finite trial checks, not proof of
long-term memory bounds or resistance to arbitrary identity floods. Fresh quotes
allow 60,000 bytes at 512 msat/KiB; the original 32-sat channels, spending and
issuance limits apply. Candidate observations survive assertion failures, and
the provider's authenticated roster determines which peers occupy its slots.
Competitors stop before settlement, which still collects all 384 test sats.
Both incumbent radio neighbors receive the same bounded ordinary application
traffic through the accounting checks and competitor shutdown, so those checks
do not leave a deliberately idle slot for candidates to replace.
This mode uses fixed
identities and a fixed radio layout, without a throughput or mobility claim.

Add `--brief-outage` to restore after the finite 24-packet stream and the
two-second quiet observation. At two packets per second, the stream spans at
least 11.5 seconds; the actual outage also includes radio commands and serial
observations, and is recorded by the controller's monotonic clock. The departing
radio must have no associated stations while all original FIPS peers
remain present; their connectivity may be stale during the cut. After fresh
replies arrive, every neighbor must be connected again, with its original
identity and authentication timestamp. Rekeying and link rebinding preserve that
timestamp, so link IDs and Noise session indices are retained as diagnostics
and may change. Together with unchanged process identities, this checks observed
peer retention in the controlled trial; wall-clock timestamps are not unique
peer incarnation identifiers under clock rollback.
Original processes, funding, automatic payments and full collection must also
pass. This controlled interruption does not establish physical mobility or
lossless handover.

Add `--recovery-timing` to retain bounded controller-clock observation intervals,
the departing router's native Ethernet adapter counters and Wi-Fi station dumps,
and per-router wall-clock/uptime anchors for the scoped native logs. The result
separately times profile checks, process checks, probe arming and paced sending.
The original partition, recovery, accounting and restoration checks still apply.
Sequential reads are not a simultaneous topology snapshot. Received beacon
counters include frames before parsing and do not prove neighbor authentication;
radio station membership may also include the filtered FIPS shortcut. Clock
alignment requires consistent anchors and must retain their resolution and read
uncertainty. These observations bound recovery; the final eight-packet probe
does not measure the instant of the first usable route or first reply.

With `--recovery-timing`, `--beacon-interval-secs 10` or `30` selects the existing
native Ethernet discovery interval on each temporary profile. Omission preserves
the native default. The result records the requested interval; check each native
startup log for the effective value. Scoped rekey trace logs retain resend events
needed to distinguish discovery delay from the separate peer-removal grace.
These diagnostic runs do not establish a latency guarantee or a performance win
from a single favorable position within the periodic beacon schedule.

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

#### Interrupted trial promotion

Add `--interrupted-promotion --promotion-provenance /private/artifacts/build.json`
to the paid Wi-Fi command above for one live, same-provider setup interruption.
Use an ARM64 artifact built with both `testbench` and `measurements`; the recorded
build manifest must bind those features, its successful unchanged-source build,
and the exact executable hash. The harness also checks the running provider's
[private acceptance barrier](../../crates/fips-relay/TESTBENCH.md#holding-a-committed-acceptance-response).
This mode is separate from the other outage modes and is not a performance run.

One source Watch uses the default price selector. Real native feedback must
qualify a partly consumed trial before the middle provider commits a full
agreement. The barrier holds that successful reply while the source has retired
its trial. After an idle feedback window, the harness removes the middle radio,
requires actual native peer eviction and normal Watch withdrawal, releases the
stale reply, and rejoins the same processes. Fresh round trips must then arrive
under a new full agreement with qualifying feedback and an advancing acknowledged
payment. No replacement Watch, rescue Buy or explicit payment flush drives that
recovery. The reverse sending direction has its own initial authorization.

Original trial consumption, funding operations and lifetime budgets remain
anchored throughout. Recovery may open one replacement 32-sat source channel
only after the original channel has a verified refund; its trial must use the
exact remaining allowance. The reverse channel remains original. A dedicated
validator handles these retained refunds before using the shared collection
procedure. Completion still requires all 384 issued test sats to be collected,
empty test wallets and the existing management and original-profile restoration
checks. Uncertain financial state retains its accounts and mint for recovery.

Add `--promotion-restart-source` to crash the entire source process with SIGKILL
at the held commitment, before removing the middle radio. The harness verifies
the original pending acceptance in the stopped profile, then restarts that same
profile while the provider radio is absent. This makes withdrawal observable
without assuming that a restart alone invalidates an already authorized purchase.
The source must retain its identity, Watch, trial consumption and spending limits;
only its process epoch may change. The other two processes remain unchanged.
Recovery still uses the original Watch and the same financial closure checks.
The exact process is checked under the existing cleanup lease before it is
signalled. An uncertain kill or launch restores source control for cleanup without
reissuing the fault; financial uncertainty keeps the original accounts and mint.

Run the affected local checks before a separately authorized hardware run:

```sh
PYTHONPATH=testing/chaos:testing/chaos/tests python3 -m unittest \
  tests.test_paid_settlement tests.test_paid_wifi tests.test_paid_wifi_open \
  tests.test_paid_wifi_forwarding tests.test_wifi_active_outage \
  tests.test_wifi_recovery_timing tests.test_wifi_promotion \
  tests.test_wifi_promotion_checks tests.test_wifi_promotion_finances \
  tests.test_wifi_promotion_restart tests.test_wifi_restart
```

These tests use local fakes to check orchestration, authority, evidence and failure
cleanup. Run them on Linux to include the real guarded-process crash and ownership
checks; those cases skip on other hosts. The [readiness assessment](../../crates/fips-relay/READINESS.md#physical-wi-fi-discovery-and-free-recovery)
records the passing same-process and full source-process restart hardware runs
and their limits. Whole-router power loss and arbitrary mobile mesh encounters
remain separate checks.

### Router wallet snapshot failure

`sim.wifi_signer_storage` binds one fresh test wallet's snapshot onto itself on
the router's flash. Reads, locks and unrelated writes remain available; atomic
snapshot replacement fails with `EBUSY`. An unfunded preflight proves the fault
and restoration before any test money is issued. The existing lease guard
restores the owned mount if the controller disappears.

```sh
python3 -m sim.wifi_signer_storage \
  --inventory /private/operator/wifi-inventory.json \
  --binary /private/artifacts/fips-relay \
  --mint-binary /private/artifacts/fips-relay-test-mint \
  --mint-host /private/operator/mint-host.json \
  --mint-address 192.0.2.10 \
  --output /private/results/new-router-snapshot-fault
```

Six 1,024-packet streams cover both directions before, during and after the
fault. Acceptance requires an unchanged saved snapshot, retained pending
authorization, continued payment by the opposite buyer and automatic retry
after unmount. Both original channels, spending limits and relay processes must
survive, every payload must arrive once, and all 384 test sats must be collected.
For real `ENOSPC` on a wallet filesystem, add `--volume-image` pointing to a fresh
8 MiB journaled ext4 image. Create it on Linux, then copy it to the controller:

```sh
image="$(mktemp /tmp/fips-wallet-volume.XXXXXX)"
truncate -s 8M "$image"
mkfs.ext4 -q -F -m 0 -b 4096 \
  -E lazy_itable_init=0,lazy_journal_init=0 "$image"
```

The fixture copies the fresh, unfunded wallet onto that volume and verifies every
file by hash before funding. The image lives on router flash; bounded random
writes fill only its filesystem. A final one-byte write must also fail, and the
parent filesystem must remain writable with at least 8 MiB free. The same payment
and delivery checks then require recovery after deleting only the owned filler.
The lease guard frees that filler if the controller disappears. Normal cleanup
unmounts the stopped wallet and retains its image and file hashes for independent
inspection and archival before removing the closed test profile.

To check an actual SQLite write while full, also pass `--sqlite-probe` with the
ARM64 `funding_costs` test executable built from the same frozen dependency graph.
The fixture initializes a 64 MiB logical wallet allowance through normal service
setup. The helper runs on the stopped, funded wallet before relay startup. It opens the
real database, fills the marked wallet filesystem, and requires SQLite's disk-full
error for a 256 KiB write that fits the logical allowance. The failed key must be
absent; every proof record and the storage charge must remain unchanged. Freeing
the filler must allow the identical write and readback, then removing the key must
restore the original accounting. The ordinary relay then runs the six-stream
payment/recovery scenario and collects all test funds. The helper is a test
executable with development features; it does not replace the ordinary relay.

These finite wallet-commit checks leave whole-router filesystem exhaustion,
read-only-wallet operation, slow storage and electrical power cuts as separate
qualifications. The signer-volume case does not restart the relay; its optional
SQLite check runs before routing starts.

Use `sim.wifi_full_state` with the same required arguments and `--volume-image`
to place the middle relay's entire account on the dedicated flash-backed volume.
After paid traffic in both directions, it fills that volume, requires a controller
journal write to fail with `ENOSPC`, and crashes the owned relay. Startup must exit
with a storage failure while the volume remains full; controller, buyer and seller
journal hashes must remain unchanged. The guard keeps the normal router filesystem
writable. Removing the filler must allow the same account and two original channels
to recover with exactly the unbilled exposure predicted by the stopped journal.
Four 1,024-packet streams, automatic payments after recovery and collection of all
384 test sats are required. The stopped account image is retained for independent
filesystem and file-hash verification. This still does not exercise system-wide
router exhaustion, a SQLite write while full or electrical power loss.

Focused Linux checks: `python3 -m unittest tests.test_wifi_signer_storage
tests.test_wifi_full_state tests.test_wifi_discovery tests.test_remote_mint
tests.test_wifi_restart` from `testing/chaos`.

### Router load, restart and frame loss

`sim.wifi_restart_load` reuses the guarded three-router lifecycle and a capped
remote test mint. Each of six rounds sends 4,000 1,000-byte payloads in each
direction at 200 packets/s. After the third round, the middle candidate is
force-killed and its persistent profile reopened. Original channels, budgets
and the exact stopped journal's unbilled exposure must survive.

```sh
python3 -m sim.wifi_restart_load \
  --inventory /private/operator/wifi-inventory.json \
  --binary /private/artifacts/fips-relay \
  --mint-binary /private/artifacts/fips-relay-test-mint \
  --mint-host /private/operator/mint-host.json \
  --mint-address 192.0.2.10 \
  --output /private/results/new-router-load --frame-loss
```

The optional `--frame-loss` drops every twentieth test-EtherType frame from the
middle router at both receivers during the second and fifth rounds. Rules live
inside the existing owned table and expire with its recovery guard; original
traffic is outside their match. Payments must advance while loss is still
enabled. Impaired streams require at least 90% delivery, nonzero missing payloads
and counted drops at least as large as that loss. Drop counters include control
frames; they do not prove individual payload attribution. Healthy and subsequent
recovery streams still require complete delivery. Financial closure collects
all 384 test sats. This finite workload does not establish maximum throughput,
physical power-loss recovery or delivery while the process is stopped.

Use `--active-restart` instead of `--frame-loss` to crash the middle process
during the fourth round's forward stream. Fresh delivery must resume within
that same 20-second paced send, without rearming the receiver or resending the
probe. Only that interrupted stream permits loss; the other eleven streams
still require full delivery. The sender is drained before financial recovery
and settlement, including after an uncertain crash response.

Focused checks: `python3 -m unittest tests.test_wifi_restart_load
tests.test_wifi_restart tests.test_wifi_discovery.AcceptanceTests` from `testing/chaos`.

Use `sim.wifi_kernel_restart` with the same required arguments and without the
optional fault flags to reset the middle router's kernel between the third and
fourth rounds. Linux SysRq `b` reboots without syncing or unmounting storage.
This interrupts that router's Wi-Fi and management connection; both other
routers remain monitored. The fixture requires a changed boot ID, restored
original LAN/Wi-Fi/service, unchanged candidate identity and configuration, and
the original paid accounts before staging a new RAM executable. It never
reinitializes the accounts or repeats an uncertain reset. Full stream delivery,
bounded unbilled exposure and collection of all 384 test sats remain required.
This checks physical-router kernel/cache loss with electrical power present;
it does not qualify flash power interruption or unattended service recovery.
Include `tests.test_wifi_kernel_restart` in the focused Linux checks.

Use `sim.wifi_boot_restart` instead to exercise the installed init/UCI service.
Its binary, startup wrapper and clock hook must match the tested sources. Before
traffic, the fixture saves the middle router's UCI file and selects the fresh paid
profile for its next boot. After reset, it must observe that exact account running
under procd before staging observation tools; it issues no relay start or init.
The pre-reset journal independently predicts the recovered unbilled allowance.
Collection requires the supervised process to exit, then cleanup restores the
original UCI file and service. Changed configuration or service ownership stops
restoration instead of overwriting another owner. If the controller disappears
during reboot, preserve the selected paid profile for deliberate recovery; no RAM
lease survives the reset. This mode uses test funds and pauses offered traffic.
Include `tests.test_wifi_boot_restart` and `tests.test_wifi_measurements` in the
focused checks; physical power cuts remain separate.

Add `--repeat-restarts` to `sim.wifi_boot_restart` for three unsynced boots before
rounds 2, 4 and 6. Each direction sends 2,000 packets per round at the original
rate, leaving capacity for the lost durable windows within the same two channels.
All six rounds must deliver completely and advance automatic payments. Every
boot must follow the preceding completed recovery, reopen the same paid account
through the installed service, and retain cumulative unbilled exposure plus at
most one additional durable window per channel. Funding, capital and lifetime
spending limits remain unchanged. Traffic pauses at each reset; this is separate
from the mint-outage and active-traffic restart experiments.
The earlier r399 trial rejected incomplete delivery after two lost 4,000-msat
windows consumed its 8,000-msat relationship grace despite remaining channel
funds. Adaptive durable windows pass the same workload and limits in r403: all
24,000 packets arrive across three boots, with cumulative loss of 4,000, 6,000
and 7,000 msat per original channel. All test funds are collected. The test still
requires complete delivery and exact retained loss; renewing a channel does not
erase it. Finite allowance can still run out. This does not qualify indefinite
restart continuity or electrical power cuts.

Use `sim.wifi_boot_mint_outage` to repeat that paid boot with an unresponsive mint.
After the first three paid cohorts, the owned Linux mint is suspended before
reboot and stays suspended through the remaining traffic. Each router must fail
its mint HTTP probe before reset and after boot; process observations also verify
the outage throughout paid traffic. An independent host worker resumes the exact
mint on release, error or a 420-second deadline. Cleanup resumes it before
settlement; a run that relies on deadline recovery cannot pass. Include
`tests.test_remote_mint` in the focused checks. This covers saved funded channels,
not new funding or settlement while the mint is unavailable.

### Router funding and settlement interruption

`sim.wifi_settlement` uses the same three-router inventory, ordinary
measurement-enabled relay, remote test mint and guarded persistent profiles.
After bidirectional paid delivery, it holds a committed settlement reply at the
mint and kills the three owned relay processes. The provider starts first and
must restore the original mint result while its buyer remains stopped. Mint
restore counters must advance without another swap or swap attempt. The buyer
then restarts and must finish its original refund and release automatically,
without another settlement request or new funding. The shared settlement checks
finally collect all 384 test sats and restore the original router state.

The opposite buyer stays stopped until the provider closes its channel at service
expiry. With a 180-second channel lifetime, service expires after 90 seconds.
The fixture observes the completed report without a cooperative payment before
restarting that buyer. Recovery must return the same report, refund the original
buyer and release the channel automatically, without new funding or another
payment. The final journals must retain that original report and signed balance.

Use `sim.wifi_funding` with the same arguments to interrupt renewal instead.
It withholds one committed successor-funding reply while both original routes
continue carrying paid traffic, then kills and restarts all three relay
processes. Recovery must reuse the saved request, channel and wallet operation,
activate exactly one successor, and refund its predecessor. Three pairs of
opposing streams must deliver all 7,680 payloads before funding, while its reply
is held and after restart; the final collection closes three channels and
returns all 384 test sats. This shares the guest scenario's financial checks through
`sim.renewal_interruption` and the settlement scenario's guarded process controls.

Add `--initial` to `sim.wifi_funding` to interrupt the first purchase before any
paid route exists. Unpaid traffic must remain blocked while the committed mint
reply is held. All three relays restart, with the provider and destination first;
the original purchase must then recover and activate without another buy request
or funding reservation. Only afterward is the reverse route purchased. Both
1,280-packet streams must deliver and pay, and the two channels must settle and
return all 384 test sats. First-purchase and renewal cases share the same durable
funding checks in `sim.funding_checks`. The first-purchase case also requires the
exact requested offer in the provider's durable quote journal before interruption
and while stopped. The recovered buyer/provider contracts must use that original
offer and channel, including unchanged pricing, expiry and allowance.

```sh
python3 -B -m sim.wifi_settlement \
  --inventory /private/operator/wifi-inventory.json \
  --binary /private/artifacts/fips-relay \
  --mint-binary /private/artifacts/fips-relay-test-mint \
  --mint-host /private/operator/mint-host.json \
  --mint-address 192.0.2.10 \
  --output /private/results/new-router-settlement
```

This shares the committed-reply and automatic-recovery assertions with the guest
power-loss scenario below. It preserves the router kernels and management
network, so neither case establishes physical power-loss or flash-cache recovery.
Focused checks from `testing/chaos`: `PYTHONPATH=.:tests python3 -B -m unittest
tests.test_committed_settlement tests.test_paid_settlement tests.test_settlement_fixture`.

### Guest kernel and filesystem power loss

`sim.guest_powerloss` runs three relay accounts inside a disposable x86-64 KVM
guest, with a separate host test mint. It needs existing QEMU/KVM access, BusyBox,
Debian-style OpenSSH tools, `cpio`, `gzip` and `mkfs.ext4`, plus a readable Linux
kernel with built-in virtio block/network, ext4 and gzip initramfs support.
Supply matching native relay and test-mint executables from the locked source
graph; build the relay without optional features and the mint with `testbench`.
The harness records their hashes and copies their existing runtime libraries.

From `testing/chaos`, with `KERNEL`, `BINARIES` and `REVISION` set to those inputs:

```sh
run_parent="$(mktemp -d /tmp/fips-power.XXXXXXXX)"
python3 -B -m sim.guest_powerloss --kernel "$KERNEL" \
  --binary-dir "$BINARIES" --source-revision "$REVISION" \
  --output "$run_parent/case"
```

The output must be new and short enough for the mint's 100-byte control-socket
limit. The guest uses two vCPUs, 1.5 GiB RAM, an owned 128 MiB ext4 image and
loopback-only SSH forwarding. It mounts no host directory and changes no host
network or service configuration. The mint URL stays identical across boots
through a pinned SSH tunnel; the mint itself stays alive.

After funding and bidirectional paid delivery, the default `--cut-at traffic`
case kills the UUID/image-verified QEMU process during an active stream.
A fresh kernel mounts
the same disk; original accounts, funding, spending limits and exact unbilled
crash exposure must survive. Subsequent streams require complete delivery, then
the existing settlement checks collect all 384 test sats and stop the guest,
tunnel and mint. The interrupted stream is not replayed. A funded failure keeps
its original disk and mint for recovery; do not rerun initialization or replace
that mint. Logs and process identities remain in the output directory.

Use `--cut-at settlement` with a fresh output directory to cut the guest after
the host mint commits a settlement swap but before its reply reaches the relay.
The existing test-mint barrier pins this boundary; the relay needs no test
feature or injected hook. Before restarting services, the recovered filesystem
must retain the original funding and pending settlement. The provider starts
alone and must restore the committed response and finish its payout without
the buyer. Then the buyer must recover its original refund automatically,
without a new settlement request. Final idempotent settlement and collection
must reconcile all 384 sats. This case does not offer traffic after closing the
interrupted channel.

Use `--cut-at renewal_funding` to interrupt the next committed mint swap while
preparing one replacement channel. Only one buyer has automatic renewal enabled;
its original channel must keep delivering and paying in both directions while
the funding reply is held. The test records whether that swap belongs to wallet
preparation or channel opening, rather than claiming both boundaries were hit.
After reboot, the saved funding intent and pending SDK operation must match
before services start. Recovery must finish exactly one successor, preserve the
original spending limits and channel funding, and refund the predecessor. For a
saved channel opening, the successor must also retain its exact channel and
wallet-operation identifiers. Fresh traffic must pay on the successor; the
shared settlement checks reconcile all three channels and collect all 384 sats.

This covers guest kernel/page-cache loss with QEMU's direct host I/O and ext4
journal recovery. It does not simulate a physical flash-controller failure,
host/mint power loss or radio interruption. The existing restart/settlement
checks and the wrong-process refusal test run with
`python3 -B -m unittest tests.test_guest_system tests.test_wifi_restart_load tests.test_paid_settlement`.

Add `--write-iops 20` to limit the account disk to 20 write operations per second
on both boots, including funding, paid traffic, crash recovery and settlement.
The default `0` leaves writes unlimited. Before funding, 64 direct 4-KiB writes
must reach that disk, and their elapsed time must demonstrate the requested
throttle. The result records this probe and the guest block counters; every boot
records its exact QEMU drive settings. Use separate fresh outputs for unlimited
and throttled cases. The same financial and delivery checks apply to both; this
finite storage-pressure case is not a flash endurance or throughput benchmark.

### Continuous paid Wi-Fi renewal

`sim.wifi_renewal_load` runs two simultaneous five-minute streams through one
paid middle router: 42,000 packets per direction, 1,000 bytes each, at 140
packets/s. Use the same three-router inventory and owned remote test mint as
`sim.paid_wifi`, and a verified ARM64 measurements build supporting the bounded
`max_duration_secs` and `lifetime_secs` diagnostic options:

```sh
PYTHONPATH=testing/chaos python3 -B -m sim.wifi_renewal_load \
  --inventory /private/routers.json --binary /private/verified/fips-relay \
  --mint-binary /private/verified/fips-relay-test-mint \
  --mint-host /private/mint-host.json --mint-address PRIVATE_MINT_IPV4 \
  --output /private/new-renewal-run
```

The tariff is 1 msat/KiB and each quote allows 32 MiB. Automatic renewal uses
80% of channel capacity or allowance, with a 30-second expiry lead. The original
32-sat channels, 64-sat lifetime buyer budgets, 128-sat wallet exposure limits,
64-sat locked-capital limits, 8,000-msat grace and 4,000-msat durability window
remain unchanged. Each router receives 128 test sats; all 384 must be collected.
Quote lifetime remains 1,200 seconds; channel service ends after 900 seconds,
with the immutable mint refund deadline at 1,800 seconds.

Add `--expiry-renewal` to use 180-second quotes, an eight-second expiry lead and
100% capacity/allowance thresholds. Traffic, prices, spending and channel deadlines
stay as above. Acceptance requires replacement funding to start inside the expiry
lead window, before the old grant expires, with its signed balance below 32 sats
and observed bytes below the original quote allowance. This distinguishes expiry
renewal from the default capacity case without adding another workload.

Use `--expiry-renewal 3` for three consecutive replacements per direction with
90-second quotes during the same five-minute streams. Acceptance checks one
connected chain of four distinct channels and requires live delivery and growing
credit on every successor before its next replacement. The observer retains all
earlier usage, refunds and funding operations; lifetime spending and capital
limits are the same. This mode also accepts `--frame-loss`.

Add `--windows 2` to `--expiry-renewal 3` for ten minutes of offered traffic at
the same rate, using two consecutive five-minute windows and 180-second quotes.
The same processes and accounts span both windows; every successor must show
delivery and growing credit within an active window. The gap between windows is
measured and limited to 30 seconds. Fresh profiles declare 128-sat lifetime signing
limits before funding, while channel capacity, wallet exposure, locked capital,
prices and the total 384-test-sat issuance cap remain as above. Every original
packet in both windows must arrive. This mode excludes injected frame loss and
does not claim uninterrupted traffic across the measured gap.

Expired, closed routes may be compacted by the ordinary runtime. The finite
observer keeps earlier purchases in memory and verifies the native retirement
fence, exact retained byte costs and terminal refund before accepting removal.
It marks successor lineage reconstructed from that history with
`retirement_reconstructed`; the delivery and live-payment requirements still
apply. This observer retention changes no router journal or financial limit.

Both receivers are armed before either sender starts. Each sender runs once,
without pauses around renewal or payload retries. Default acceptance requires every
packet, unchanged service processes, one actual refunded predecessor and one
accepted successor in each direction, and fresh delivery plus increased
successor credit while the continuous sends remain active. Raw failed or partial
streams remain evidence. After the exact sends finish, cleanup removes any test
loss filters, pauses renewals,
verifies all retained channel settlements and uses the shared wallet collector.
Unresolved funding retains the original accounts and mint for recovery.

Add `--frame-loss`, independently or with `--expiry-renewal`, to drop every
twentieth test-EtherType frame from the middle relay at both receivers throughout
the continuous streams. The existing leased filter leaves ordinary LAN and
Internet traffic outside its match. Each direction must deliver at least 90% of
its originals, with no duplicates or invalid data and missing packets no greater
than observed dropped frames. The same filters must remain active while successor
delivery, automatic credit and drop counts all advance. After removal, each
direction must deliver all 64 fresh recovery packets. Spending limits remain
unchanged. Counters include control frames and cannot identify the cause of every
missing payload; this is bounded impaired-link acceptance, not loss attribution.

The diagnostic sender is bounded at 300 seconds, receiver at 360 seconds and
individual remote send call at 330 seconds. These explicit bounds do not change
the existing 30-second/60-second probe defaults or the short cadence matrix.
This finite renewal regression is not a cadence comparison, physical power-loss
test or maximum-throughput qualification.

The existing status reads also retain up to 800 neighbor observations, bracketed
by the same host monotonic clock used for traffic dispatch and receiver samples.
Each observation records the process ID when available, fixture peer labels,
connection/link identifiers, packet counters and RTT. Backend errors are reduced
to `provider_unavailable`, `other`, or no error; wallet fields and unknown peer
identities are omitted. A full capture sets `neighbor_observations_truncated`
without interrupting status reads or financial cleanup. Polls can miss short gaps
and do not identify the exact time of a link transition. Focused renewal, rekey,
retry and link logs are enabled without packet tracing; their router wall-clock
timestamps are not interchangeable with the host monotonic observation bounds.

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
sequence, and the arm expires after 60 seconds by default. Replies have a distinct
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
matching ARM64 or x86-64 Linux test-mint binary; the routers do not need Python.
The harness checks the binary and host architecture before creating remote state.
Every run uses
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
Later runs and their exact source/workload limits are recorded in that readiness
document; use the matching artifact and private scenario for each run.

`sim.paid_phone` composes these helpers for one acceptance phone and the same
three-router inventory. Install the verified isolated acceptance APK first,
leave it foreground and unlocked, and select the guest Wi-Fi yourself. The
harness checks the installed APK hash and all other installed bench accounts' private-file hashes;
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
  and the verified acceptance artifact's `apk_sha256`. Optional `instance` must
  match the named isolated APK build; omit it for the original acceptance package.
- `customer`: existing guest `interface`, router address/prefix in `cidr`, unused
  `entry_port`, exact `ssid`, and one to four `denied_tcp` objects containing
  `label`, numeric IPv4 `address`, and `port`. Choose known reachable services
  outside the permitted mint access. No target is inferred from the inventory.
- `mint`: `address` assigned to the explicit Linux host, plus `ssh_spec` with
  `host`, `state_parent`, and optional `ssh_config`, as used by `RemoteMint`.

Use `--transit` for Cudy → phone → Cudy → Cudy over UDP on the existing LAN.
Supply `customer.interface` as the entry's management bridge, its existing LAN
address/prefix as `customer.cidr`, and the phone's current `ssid`. Omit
`denied_tcp` and add `router_addresses`, mapping `n01`, `n02` and `n03` to their
distinct numeric addresses on that LAN. The verified APK and router executable
must both enable `measurements`. This mode uses the same capped mint, durable
accounts, settlement, collection and router restoration helpers. It makes no
network configuration changes and does not test public customer isolation.

Transit checks the exact authenticated four-node line, unpaid denial, then
512 KiB of acknowledged, digest-verified traffic in each direction at 32 KiB/s
within each 30-second foreground/background window. The phone must earn provider
credit and buy onward forwarding within its immutable budget. Read-only status
and journal observations work while the app is hidden; UI and probe mutations
still require the unlocked foreground app. Add `--screen-off` only with an
operator available to unlock afterward for settlement. The recorded Android
state distinguishes sleep from the always-on ambient display. USB/ADB observations
and process CPU include diagnostic overhead; they do not measure unplugged
battery life, Android deep idle or payment-specific CPU. Physical results remain
separate from harness tests.

Use `--compare-transit-rates` with `--transit` to run two healthy background
windows at 32 then 256 KiB/s per direction. Each offers four MiB per direction
and lasts five minutes, retaining the original channels, tariffs and spending
limits. The reduced per-window payload reserves channel capacity for both rates
and their onward charges. This mode runs separately from fault, renewal,
screen-off and forced-idle cases.

The fixture records payment and CPU counters for all four participants. After
the run succeeds, analyze the saved result with:

```sh
python3 testing/relay-cadence/phone_rates.py /private/results/phone-rates/result.json
```

The analyzer validates full acknowledged delivery, matched workloads, unchanged
channel terms and counter epochs, and advancing payments at every paying hop.
Completion times distinguish achieved throughput from the offered rate. The
probes keep pumping until the fixed deadline to recover late acknowledgments,
so full-window CPU includes different idle tails and diagnostic work. One
ordered pair does not establish a throughput ceiling or an optimization.

Add `--forced-idle` to `--transit` for one controlled Android Doze window.
It requires an initially active phone and a temporary acceptance app without a
battery-optimization exemption. After the paid background window, force deep
idle for at least 45 seconds and require 512 KiB of acknowledged, digest-verified
delivery in each direction. Verify that Android's network policy allows the
foreground routing service despite Doze, without a battery exemption. A
device-side 90-second watchdog restores normal idle policy even if the controller
disappears. Then require fresh paid
delivery with the same app process, channel identities, terms and lifetime
budgets, without another purchase. This mode cannot be combined with
`--screen-off` or `--sustained-transit`. This finite, USB-powered test measures
forced-idle continuity; it does not measure natural sleep, battery life or
recovery from a network outage.

Use `--phone-outage` with `--transit` to interrupt the phone's UDP link to the
middle router after paid background delivery. An exact address/port filter
blocks both directions under the existing router cleanup lease; normal LAN
traffic remains allowed. Require fresh zero-delivery probes, real drop counters,
disconnection at both ends and continued connectivity on the other two links.
Remove the filter, then require fresh acknowledged traffic without another
purchase or a process restart. The same channel terms and lifetime budgets must
survive. This mode runs separately from idle, screen-off and sustained transit;
it tests a link outage, not physical movement or address changes.

Use `--transit --phone-expiry` to force-stop the paid phone after foreground and
background transit. Wait for its route quote and the channels it sold to expire,
then restart the phone while its own buyers remain stopped. Require both of the
phone's seller reports before reconnecting the original parties. Its buyers
recover those same reports, while the phone automatically settles its expired
route before the underlying channel expires. No settlement request or new funding
is issued by the fixture during recovery. Final collection verifies
all four accounts and 512 test sats. Only the restarted phone's UDP discovery
address changes; immutable profiles, funding and lifetime budgets stay intact.
This mode runs separately from renewal, outage and sustained-load variants.

Use `--phone-renewal` with `--transit` to reconnect Android Wi-Fi during
automatic expiry renewal. The provider issues 180-second quotes; the phone and
reverse endpoint renew with the existing 80%/30-second policy. The isolated mint
holds only the original phone channel's committed close reply, selected by hashes
of its funding inputs. Other funding and settlement requests continue normally.
After the successor activates, a USB-controlled Wi-Fi reconnect must change the
native UDP socket without restarting any paid participant. A device timer restores
Wi-Fi independently of the controller. Require another MiB of fresh, acknowledged
traffic in each direction and increased successor payment and provider credit
while the original refund remains unresolved. Then release the reply, pause
renewals, settle all six channels and collect all 512 test sats. The original
identity, terms and lifetime budgets remain unchanged. This workload runs
separately from other transit variants and tests one reconnect on the configured
LAN, not arbitrary mobile mesh movement.

Use `--transit --phone-renewal sustained` for two consecutive five-minute
background TCP/FIPS windows, each carrying nine MiB per direction at 32 KiB/s.
The middle router issues 300-second quotes; ordinary 80%/30-second renewal also
applies to the endpoints. Downstream expiry bounds the upstream quote, so the
three affected buyers must each renew at least twice. Capacity can trigger an
additional renewal, including on the fourth purchase; each participant may fund
at most four channels in this bounded workload.
Each successor must show increasing acknowledged payment and received bytes in
both directions during the same active stream. Retain the original identities,
processes, 32-sat channel size, 64-sat lifetime budgets and configured capital
limits. Restore the app's foreground activity and pause renewals after the
second window, settle every observed funded channel and
collect all 512 test sats. This workload changes no network settings and uses no
mint fault or manual successor purchase. It tests paced LAN transit while the
app is in the background; saturation, natural Android deep idle and moving-radio
handover require separate workloads.

Add `--impaired-transit` to `--transit --sustained-transit` for five minutes of
paid background forwarding with one in twenty UDP packets dropped in each
direction on the phone-to-middle-router link. The exact address/port rules use
the same cleanup lease as the outage test. Require complete delivery and ACKs,
observed matched/drop counters, unchanged processes and original channel terms,
then fresh paid delivery after removing the filter. This mode runs separately
from idle, screen-off, outage and renewal workloads. It tests packet loss on the
existing LAN, not physical radio movement or Android network suspension.

Use `--impaired-transit corrupt` for the same workload with eight consecutive
established FMP frames corrupted out of every 100 matches in each direction.
The filter flips a ciphertext bit and disables the IPv4 UDP checksum so native
AEAD verification sees the damage. Scoped router logs must show an eight-frame
failure burst without triggering recovery. Both mature peers must retain their
keys through that first burst; the five-minute window allows normal scheduled
key rotation but requires unchanged peer identity, link and authentication time.
Filter counters, full stream delivery, payment progress and cleanup remain
required. This modifies real peer packets; it does not send spoofed IP packets.

Add `--phone-restart` to split the same eight-packet workload into two cohorts,
each with two packets in each direction. After the first cohort is delivered
and paid, the harness records the app process identity, force-stops that exact
Android package once, verifies process absence and reopens it. Connect resumes
the saved account; no second Buy or manual payment flush occurs. The second
cohort must deliver and advance every paying channel on the original terms and
lifetime budgets, followed by the same settlement and collection checks. An
uncertain force-stop is retained and never dispatched again. This tests an
Android process interruption, not physical power loss or traffic during the stop.

Use `--load` instead of `--phone-restart` for three simultaneous bidirectional
100-second windows at 40 packets/s, with 4,000 originals of 1,000 bytes per
direction in each window. The middle window drops every twentieth experimental
EtherType frame from the middle router at each leaf; the surrounding healthy
and recovery windows require complete delivery. All windows require delivery,
buyer authorization and provider credit to advance while sending. The existing
app-private control and native diagnostic sockets are checked on the empty
account before issuance; they use a non-PTY ADB shell for binary or newline JSON
input/output. No app or protocol extension is needed. Existing phone and router
status, routing, transport and session diagnostics
are retained before and after every window, including failed windows, so loss
can be investigated after cleanup. Router fees are 1 msat/KiB with 32-MiB quote
limits; the same channel capacity and lifetime buyer budgets apply. Whole-app
CPU/RSS observations include control sampling. This finite workload does not measure maximum throughput or
payment-specific phone CPU cost, and failed originals are never replayed.

Add `--open-mesh` for the existing guarded temporary open profile and late third
router join. Before issuance, the phone must reach the exact mint before and
after the explicit denied TCP probes. A missing completion marker, ADB failure,
or tool/bind error is an unknown outcome and fails the run, not proof of denial.
These probes establish only the specified target/port observations.
They do not prove that a denied target's service was listening or establish an
exhaustive firewall policy.

This fixed fixture issues 128 test sats to each of four fresh accounts, uses
32-sat channels and 64-sat lifetime buyer budgets. The default case checks four fresh
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
python3 -m unittest discover -s testing/chaos/tests -p 'test_*phone*.py' -v
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
