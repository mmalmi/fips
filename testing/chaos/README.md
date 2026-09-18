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
