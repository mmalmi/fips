# Paid-relay v1 readiness

**Status: active; production readiness is not established.** Reviewed on
14 October 2026. Runtime `d6874c3bf` includes the r523 control idle-expiry fix.
Physical r520/r521 results use runtime `711b68a3d` with the subsequent wallet
changes qualified in r519/r520 below. The accepted graph
includes Cashu service `6a90ccc40da2` and CDK `04c37d5a152a`. Use the complete
[source-bundle procedure](FUNDING-COSTS.md#portable-development-source-bundle),
including Spilman and the lockfile, rather than reconstructing it from these IDs.

This document is the current assessment, not a chronological run log. Detailed
historical narratives remain in Git at `e100c6bc7:crates/fips-relay/READINESS.md`;
private raw evidence remains in the named `work/` bundles. Failed attempts retain
their original verdicts. A later pass does not turn an earlier failure into a pass.

## Scope and outstanding acceptance

The goal remains sender-funded, best-effort FIPS forwarding across supported
links, with automatic neighbor payments, permissionless authenticated discovery,
bounded financial/resource exposure and recovery. It includes simulations,
controlled router/Pixel acceptance, measured overhead, operational documentation
and the local TollGate proposal. This assessment does not narrow that goal to the
latest passing test or require an unlimited sequence of longer repetitions.

Current implementation and deployment boundaries:

- The service accepts UDP, TCP, native Ethernet and WebSocket, including TLS.
  Its [configuration validation](src/service/network.rs) rejects Tor, WebRTC and
  BLE. Shared FIPS forwarding policy is transport-neutral; enabling another
  adapter requires auditing its paths and exercising the same paid invariants.
- Physical router evidence uses ARM64 OpenWrt and standard interfaces, including
  one-hop 802.11s adjacency. There are no Cudy-specific forwarding rules. Other
  OpenWrt architectures need their own build/runtime qualification.
- Linux process/virtual-link tests complement physical radio tests. Neither
  emulation nor process interruption establishes physical flash power-loss safety.
- The Android app embeds the same service and has customer and transit evidence.
  It remains an arm64 bench app, not a production wallet or general Internet VPN.
  The r520 router and r521 phone use the same runtime/dependency graph; outstanding
  acceptance below still prevents treating it as a qualified production release.
- Acceptance uses fresh profiles and test money. Legacy profile migration is
  outside this greenfield scope. Existing operator accounts must be preserved.
- Public release, deployment, real-money operation and contacting upstream are
  separate authorization decisions. They are not prerequisites for local testing.

### Acceptance checklist

“Covered” below means the named tests or historical runs provide evidence for
that requirement on their recorded builds. It does not certify a newer binary.
Final sign-off requires the exact source/dependency/features and target artifacts,
closed financial recovery and the remaining observations listed here.

| Requirement | Existing evidence and canonical contract | Required to close v1 |
| --- | --- | --- |
| Adaptive payments, idle suppression and independent checkpoints | [Cadence](CADENCE.md): cumulative payments per neighbor and paying direction, triggered by priced usage/remaining allowance or maximum age; separate checkpoints and renewal. Matched 250/500/1000/2000-ms comparisons in [results](CADENCE-RESULTS.md) retain spending/exposure bounds. | Qualify the final candidate under idle, bursty and high-rate traffic, including payment/renewal progress during faults; retain the same financial terms across comparisons. |
| CPU, storage, wire and delivery costs | Separate untraced CPU, packet-capture and storage-syscall matrices; per-delivered-byte costs, counters and latency limits are reported in [measurements](MEASUREMENTS.md). | Reconcile final candidate coverage after subsequent runtime/SDK changes. Report scoped payment costs and excluded shared work explicitly; do not claim complete attribution from partial counters. |
| Every supported forwarding path | The [native path inventory](ACCOUNTING.md#native-path-inventory) maps individual/batched/deferred sends and source observations to shared admission/completion. r528 passes 438 current-graph contract/startup checks. r529 qualifies seven current-graph paid carrier scenarios across UDP, TCP, Ethernet and WebSocket/TLS. | The current carrier matrix is covered below. Finish reconciling remaining admission/negative scenarios with the final graph. Unsupported adapters cannot silently bypass validation or be advertised as qualified. |
| Bounded free bootstrap, ordinary priced quotes and configured free destinations | [Bootstrap](BOOTSTRAP.md), [return allowance](RETURN-ALLOWANCE.md), [destination pricing](DESTINATION-PRICING.md), current r528 quote/admission contracts and r531 native quote/free-route cases. | Complete current-graph funded bootstrap/return and mixed paid/free contention checks listed below. Negative checks must reject unpaid transit, unauthorized reverse spending and quote-port bypass while allowing bounded joining/payment progress. |
| Permissionless mobile admission and spending policy | Authenticated adjacency, open-radio joining, merge/split and crowded-neighbor simulations; physical root replacement, newcomer admission and controlled channel handover. | Close physical mobile encounter/rejoin acceptance and record admission/resource bounds. Automatic channel selection and unrestricted-identity fairness are not established. |
| Useful routes selected by price and quality | [Price selection](PRICE-SELECTION.md): real quotes, native feedback, trial quotas, loss/delay/partition/rejoin tests and physical alternative-path selection. r521 qualifies 28 selector checks and eight native paid scenarios on the r519 dependency graph before the r523 runtime fix, including delayed funding/renewal and merge/split. | Complete the remaining admission reconciliation and physical mobile observations with the final graph. No global-optimality claim. |
| Financial crash and failure recovery | Real funding/settlement/refund interruptions, mint outages, full-filesystem recovery, guest kernel loss and physical process loss; [funding costs](FUNDING-COSTS.md). | Physical router power-cut qualification at original funding, committed settlement and history handoff boundaries, preserving the original evidence and test-fund conservation. |
| Bounded lifetime history and useful progress | [History](HISTORY.md), SDK wallet capacity/admission, exact retirement plans, three real wallet lifecycle cycles and physical full-wallet/retirement-contention runs. | Finish the workflow/store/query resource audit, including aggregate pressure, maintenance duration and completion capacity. Finite cycles alone do not prove bounded indefinite operation. |
| Reproducible target operation | Relocatable offline source bundles, [OpenWrt packaging/recovery](openwrt/README.md), [service operation](SERVICE.md), [test funding/collection](TESTBENCH.md) and [Android lifecycle](../fips-relay-app/README.md). | Freeze and qualify a common final graph on the intended targets. Exercise install/reopen/recovery with preserved accounts and remove owned test resources. Natural Android deep idle is still unqualified. |
| Threat model and integration proposal | [Threat model below](#boundaries-and-threats), explicit mint trust and [local TollGate proposal](TOLLGATE.md). | Review these contracts against the final implementation. The deliverable is a proposal; actual TollGate interoperability needs its separate acceptance before it is claimed. |
| Maintainability and simulation reuse | Existing SimNetwork/chaos facilities, shared Cashu logic, source-size gate and focused production-path regressions. | Retain the 600-line relay/Android and 1000-line integration limits; remove superseded code/tests without losing distinct failure coverage. |

The remaining native admission requalification uses four existing scenarios:
both `bootstrap_service` tests (unfunded recipient across restart and earned
quality-report return), `mixed_transport::newcomer` (fresh identity while the
disconnected buyer retains funds) and `destination_service::concurrency` (paid
progress during free traffic). The r528 contract checks and r529/r531 carrier,
quote and free-route results cover the other mapped paths; physical mobility and
target acceptance remain separate checklist requirements.

The wallet resource audit has closed the custody archive's native completion-space
gap. The r527 retained-receipt benchmark now measures one collection call through
actual admission refusal at the 16 MiB logical limit, preserving referenced coins
and progressing without unreserved growth space. Large individual proof records,
unfinished-operation scans, full capture traversal and the remaining workflows
still need aggregate resource qualification. A page-size limit does not by itself
bound a whole maintenance call; reuse the existing harness for admission, rollback
and reserved completion-capacity checks.

### Evidence and stopping rules

1. Bind each acceptance result to its source bundle, dependency graph, features,
   executable hashes, workload, limits and target. A docs-only change does not
   require another full Rust build; a runtime change needs its affected checks.
2. Every financial scenario must check payer authority, capital/lifetime limits,
   exact original recovery identities and test-fund conservation. Preserve failed
   runs; close or explicitly retain every unfinished financial owner.
3. Use bounded, specified fault cases and observation windows. Extend them for a
   concrete uncovered invariant or observed failure, not merely because any finite
   run could have been longer. Simulated loss, forced Doze and process termination
   must keep their labels; none is physical movement, natural sleep or a power cut.
4. Preserve the management LAN, normal Wi-Fi/Internet, existing accounts and other
   services. Restore and independently verify each controlled device change.
5. Close every checklist row before claiming v1 readiness. Limitations of optional
   integrations and unqualified platforms remain explicit instead of becoming
   accidental claims or silently disappearing from the assessment.

## Current verified checkpoint

| Evidence | What it establishes | Limit |
| --- | --- | --- |
| r529 paid carriers | Runtime `d6874c3bf` passes seven existing native scenarios: mixed UDP/TCP, configured and URL-seeded WebSocket, self-signed and CA-validated TLS, and sustained UDP/Ethernet loss. Paid/unpaid boundaries, exhaustion, renewal, restart and final conservation pass; successful cases recover 2,688 test sats. Both five-minute loss cases observe three renewals per direction, key rotation and no disconnected-neighbor samples. Strict service lint, formatting and source-size checks pass. | Linux process/virtual-link evidence with unchanged runtime and accepted dependencies. Ethernet runs in an isolated namespace. CA injection is limited to the generated-CA fixture. Loss tests deliver 39,895–39,914 of 42,000 payloads per direction while counting every-twentieth-frame loss; they do not measure maximum throughput or physical mobility. |
| r531 quotes and free routes | Six existing cases pass on the current graph: paid/free quote composition over native neighbor control, an explicitly free destination across three relays, arbitrary free destinations, free price-selection recovery and rejection of a paid prefix under a zero-price ceiling. The ordinary daemon's free-route cases preserve monetary journals through restart and make no mint requests. | Unchanged production and test source. Linux loopback evidence without funded wallets; it does not replace the four funded admission scenarios above. Artifact/log hashes, stopped processes and removal of successful temporary state are verified in the private `work/admission-current-r531` bundle. |
| r527 retained-receipt pressure | SDK `c6db9e4` adds an opt-in native SQLite benchmark; all 12 optimized Linux runs pass. Queue/archive collection preserves every referenced original and makes progress at full logical capacity, including 11,070/11,400 retained receipts. Full workspace verification passes 443 tests (two opt-in tests ignored), plus strict all-target lint. | Storage-only fixtures, unchanged production code. At the full 16 MiB admission limit, a call takes 59–103 ms and reported process VmHWM stays below 28 MiB. These are x86-64 wall-time/kernel observations with small proof records, not CPU attribution, hard memory bounds, router or physical-storage qualification. |
| r528 accounting paths | Current runtime/dependency graph passes 58 core forwarding/admission checks, 336 relay unit checks, 37 bootstrap/buyer/ledger/durable checks and five service-startup checks. Failed-bind, replay, completion, source authority and bounded-wait coverage are checked by exact test names. The stale buyer fixture now gives its history/pending checks a 20-sat channel while retaining the 10-sat spending budget; strict affected lint, formatting and source-size checks pass. | Runtime unchanged. The original 11-pass/one-failure buyer run remains rejected; only its fixture needed correction. This covers contract/startup paths, not the complete mixed paid-carrier or physical acceptance matrix. |
| r526 Wi-Fi cadence | The corrected `d6874c3bf` ARM64 build passes all eight trials over native Ethernet/802.11s: all 93,696 payloads arrive, all 16 channels settle, all 3,072 test sats are collected and 2,109 management checks pass. Strict delivery/accounting/cost validation and independent restoration/archive checks pass. [Current radio costs](CADENCE-RESULTS.md#wi-fi-matrix-with-the-control-expiry-fix--14-october-2026) cover all four policies. | Two repeats per policy on three stationary routers with one paid relay. Scoped CPU, logical journal writes and local carrier bytes exclude shared/physical costs. No one-way latency, maximum-throughput or power-cut claim. |
| r524 native cadence | Runtime `d6874c3bf` passes the unchanged eight-trial comparison and strict delivery/accounting/cost validation. All 285,696 payloads arrive and all 40,960 test sats are collected. Processes stop and original settled profiles are retained. [Current native costs](CADENCE-RESULTS.md#native-matrix-with-the-control-expiry-fix--14-october-2026) cover idle, bursty, steady and high-rate workloads. | Two repeats per policy on clean Linux loopback links. Scoped CPU, logical relay writes and local payment-service transport counters exclude shared/physical costs. |
| r523 control expiry | A native TCP/FIPS regression fails on the old code when idle expiry discards a queued request. The fix passes 17 control unit and 16 integration tests, strict affected-target lint, formatting, source-size checks and an ordinary Linux build. Empty expired streams still close. | Fixes the demonstrated buffered-request race; does not prove it caused the r522 failure. The r525 hardware pilot and full r526 Wi-Fi comparison pass. |
| r515, runtime `711b68a3d` | 335 relay unit checks, strict all-target lint, three real wallet-retirement cycles and an ordinary ARM64 build. Three regressions fail under the prior controller locking; stale receiver planning is revalidated. | Wallet work remains serialized; pending retirement still fences journal mutations. |
| r519 SDK/CDK | Native custody reservations pass 443 SDK workspace tests (one existing ignored), 198 SQL wallet tests, strict affected-target lint and a three-cycle FIPS wallet lifecycle. Interrupted and full-capacity captures preserve their original coins, checkpoints and promised space. | Logical storage accounting; unrelated workflows and physical storage retain their separate acceptance requirements. The full CDK workspace was not run. |
| r520, r519 ordinary ARM64 artifact | All 2,048 paid payloads arrive across three routers with 16 MiB native wallet limits. Six controller reads take 165–208 ms while sender/receiver SQLite writers are held. Two sender and two receiver records retire with original budgets; 384/384 test sats are collected; 282 management checks pass. Archived database inspection verifies the limits and sender custody reservations. | A finite contention scenario, not a power cut, throughput benchmark or flash-endurance result. Receivers use the existing release queue; senders use custody archive format 5. |
| r518 SDK | Unspent-only collection skips unrelated ownership scans; 442 workspace tests and strict lint pass. An eight-visit, 256-receipt fixture falls from 9,774 to 1,474 µs for the archive and 8,540 to 1,055 µs for the queue. | Fixture elapsed time, not CPU attribution or device throughput. Spent candidates still require full ownership checks. |
| r513 SDK / r514 routers | Unchanged single-page custody maintenance stops rewriting the page; the updated SDK passes physical wallet-full refusal/recovery with all 6,144 payloads and all 384 test sats recovered. | Does not prove total wallet CPU, flash life or every workflow's storage bound. |
| r521 routes | 28 selector checks and eight existing native scenarios pass: blackhole, directional loss/delay, automatic quality recovery, exhausted trials, mobile channel reuse, pending encounter funding, slow renewal and mesh merge/split. Original authority and test-fund conservation are checked. | Software topology changes, not physical movement. The first runner lost its output connection after mobility passed; only the three unreached scenarios were resumed, retaining the original failed runner receipt. |
| r521 phone | Same FIPS runtime and SDK/CDK graph as the r520 routers. Four MiB delivered, including during 47.57 seconds of forced Doze; all four original paid channels advance, 512 test sats collected and 587 management checks pass. Android build, strict lint and ten lifecycle tests pass. | Externally powered/ADB-observed; does not qualify natural deep idle or battery use. |
| r511 radio mobility | Controlled open-radio channel change and return preserve paid connections; all 64 probes and financial recovery pass. | No actual movement or automatic channel-selection result. |

The r529 fixtures now allow an earlier refund to finish during a fixed paid cohort
without permitting new wallet debits or reservations. Renewal checks include the
already signed whole-sat amount, bounded by the rounded local traffic evidence.
Both corrections follow existing runtime behavior. Setup/workload/settlement
failures retain original mint and daemon accounts; successful fixtures clean up
only after conservation checks. The two earlier failed attempts remain rejected,
with their original financial owners and verified archives retained. They are
excluded from the successful-case total above. The private
`work/mixed-carriers-r529` bundle binds sources, artifacts, logs and retention;
postflight checks confirm all owned processes have stopped.

The r525 ARM64 relay used by r526 has SHA-256
`fa9e61ed6dfe641b70eb04eab568e51857e3660ccffa8a46e86a245da94e2fcf`.
It uses the same SDK/CDK graph as r524, core default features and no wallet
simulation. Original services and accounts are restored. All 24 settled router
profiles are archived and checked before removal; owned mint executables are
removed while their financial evidence remains. The private
`work/cadence-router-r526` bundle binds the full comparison to source, binary,
harness, analysis and cleanup hashes. The r525 pilot separately passes with
11,712 payloads and 384 recovered test sats. Its initial unreachable-mint-port
attempt stopped before funding; that failure and cleanup evidence remain intact.

The earlier r519 ordinary ARM64 relay SHA-256 is
`00f4829cad636e0fea7984f442b53293d5bdc8cc565fdbbdc088e5345e7decbf`.
The r520 harness uses that executable without wallet simulation; only the test
mint simulates money. Original router services/accounts were restored, owned
processes stopped and settled profiles archived before removal. The device test
is reproducible through [the chaos harness](../../testing/chaos/README.md#controller-reads-during-wallet-retirement).

### Controller reads during wallet retirement

Sender and receiver SDK work runs outside the controller journal mutex. The
wallet owner remains held, and final journal writes recheck the exact saved plan
and current accounting. Receiver planning revalidates reports after returning
from wallet work; concurrent changes are not overwritten. An unresolved durable
intent still blocks conflicting journal mutations. Reads stay available, but
funding is not promised to bypass wallet serialization or a pending intent.

The physical helper takes an actual SQLite writer transaction without changing
rows. Its deadline, signal handler and independent device guard release it.
See [history coordination](HISTORY.md) and
[the shared test](../../testing/chaos/sim/wifi_retirement.py).

## Performance acceptance

The [cadence results](CADENCE-RESULTS.md) already contain the requested four-age
matrices in forward/reverse trial order, with unchanged tariffs, allowance,
checkpoint limits and explicit idle/bursty/high-rate workloads. The documented
500-ms default remains unchanged: one second reduced scoped payment CPU and
storage cost in recorded comparisons, but did not establish a general optimum.

Keep the three measurements distinct:

- Untraced process CPU and payment spans report CPU per delivered payload byte.
  Scheduler, shared core and transport work outside those spans is not attributed
  to payments. Wall-clock spans are not CPU time.
- Independent packet captures reconcile instrumented encrypted submissions.
  Service-local counters exclude opaque transit and shared traffic; count sends
  once and report unattributed traffic instead of assigning it to payments.
- Storage traces report successful file-write lengths and sync calls, separating
  relay journals, SDK snapshots, receiver databases and wallet shared memory.
  Logical bytes/syscalls do not measure physical media wear or mmap writes.

The corrected candidate passes the r524 native and r526 Wi-Fi comparisons.
Complete shared-work attribution remains open and is required before claiming
total payment overhead. Radio airtime, battery life, flash
endurance and maximum throughput are separate experiments; their absence cannot
be concealed by a passing paced workload. Detailed methods and commands belong
in the existing [benchmark runbook](../../testing/relay-cadence/README.md).

The r522 comparison on the accepted r519 dependency graph is rejected: one
high-rate window reports `control stream ended before its record`. All eight
trials finish, all 285,696 probe packets arrive and all 40,960 test sats are
collected, but the strict analyzer correctly refuses the controller error.
Original results and settled profiles are retained; owned processes are stopped.
These failed measurements are not accepted performance evidence.

The r523 focused regression reproduces a receiver discarding a queued request
when its idle deadline has elapsed. The candidate reads the record prefix and
enters fresh admission before expiring an empty stream; timeout and connection
limits stay unchanged. The traced matrix repeat delivers all packets and recovers
all test funds without reproducing the original error. That diagnostic run does
not establish the cause of r522 or qualify the corrected build's performance.
The ordinary corrected build subsequently passes r524 with no controller errors;
that result qualifies its scoped native costs while preserving the earlier failures.

## Authenticated adjacent neighbors

No fixed operator roster is required in authenticated-adjacent mode. Discovery
finds candidates; FIPS identity authentication, bounded neighbor/control admission
and explicit onward price/capital/lifetime policy determine what they may do.
Inbound customers and discovered peers do not gain authority to spend the wallet.
Quote caching and aggregate rate/concurrency limits apply across identities;
forwarded quote traffic has ordinary negotiated accounting. See
[peer protocol and limits](README.md#peer-protocol) and [customer entry](CUSTOMER-ENTRY.md).

### Physical Wi-Fi discovery and free recovery

Open 802.11s supplies local adjacency with compatible mesh ID and overlapping
channel; FIPS owns multi-hop forwarding, with kernel mesh forwarding disabled and
management outside the test interface. Existing hardware evidence covers open
joining, root loss/replacement/rejoin, free-destination recovery, fresh paying
neighbors at capacity and controlled channel handover. Software merge/split cases
cover independently formed components meeting, separating and rejoining without
resetting channels or lifetime budgets.

Actual mobile encounters and automatic channel selection remain unqualified.
L2 adjacency is sufficient; no new physical-layer protocol is needed. Different
radio neighborhoods can use different channels or link types when a compatible
bridge is available. That is a connectivity condition, not seamless roaming or
an RF anti-jamming guarantee.

### Physical phone customer across the wireless mesh

The Pixel has acted as both customer and transit router using the shared service.
Recorded cases include background traffic, route/socket loss and rebind,
renewal, corrupted/lost traffic, and forced Doze with continuing payments.
The latest phone checkpoint is r521 above. Natural deep idle, battery cost and
actual moving-radio behavior remain unqualified. The production-wallet/VPN
capabilities of a phone app are not supplied by the bench UI.

## Cheapest routes that work

The selector compares authenticated adjacent-provider quotes using estimated
cost per delivered byte, with configured latency/loss limits, bounded trial
allowances and cooldown. Native FIPS quality evidence comes from the existing
monitoring path; encrypted upper-layer payload is not inspected. Free targets
and return allowances keep their explicit policy, quota and authority boundaries.

Existing paid diamond and merge/split tests exercise cheaper failed paths,
asymmetric loss, delay, provider departure/rejoin, root changes, trial exhaustion,
renewal and recovery of original channels. Physical r446 checks a connected cheap
path becoming lossy and selection of a healthy alternative. These support local
policy behavior, not a globally optimal path or proof that a recipient accepted
an application payload. Optional financial delivery receipts are not required by
the current best-effort tariff. See [selection contract](PRICE-SELECTION.md).

## Wallet bounds and recovery

Channel, route and receipt retirement retain original ownership evidence until
all dependent operations are durably complete or transferred. Gross debits,
refunds, signed charges and reserved capital stay distinct. Retiring detailed
history cannot reset lifetime authority or admit an old request again.

Current checks cover exact saved-operation recovery, seed/database identity,
missing/corrupt wallet evidence, mint outages, fee-bearing funding/refunds,
capacity exhaustion and concurrent channel work. Fresh configured wallets have
native storage admission and reserved completion capacity. Three real lifecycle
cycles check reopen, retirement and refusal of a further purchase at the original
lifetime limit. They do not prove a whole-wallet storage plateau indefinitely.

Custody archive format 5 reserves its pages, native ownership metadata and maximum
cursor growth in the same transaction as its exact registry checkpoint. Other
writes cannot consume an admitted capture's remaining allowance. A failed write
or stale comparison rolls back both; acknowledgment releases unused space. The
full-capacity regression completes two overlapping captures across reopen while
unrelated writes fill the remaining wallet. This reserves logical native payload,
not filesystem blocks. Receiver proof release retains its separate bounded queue.

The remaining audit must include all reachable workflows/stores/queries and
aggregate memory, disk and maintenance work. Proof capture and owner/receipt scans
can traverse many bounded pages in one call; r515 removes the controller lock
from that work but does not make the work constant-time. The r527 experiment
measures retained-receipt scans without claiming those other workloads are bounded.
See [history](HISTORY.md) and the matching SDK's `docs/wallet-history.md` for exact
ownership/limit contracts and the reproducible pressure command. Private evidence
in `work/history-pressure-r527` binds the measurements, source graph and gates;
the earlier fixture that attempted to exceed capacity retains its rejected result.

### Recovery record read bounds

The accepted SDK/CDK graph provides bounded recovery, selected-proof, transaction,
quote and metadata reads, including SQL projection limits before decoding.
Unsupported database callbacks fail instead of falling back to unbounded reads.
Per-record/page ceilings are not aggregate database, memory or workflow bounds.
This is why replacing the accepted graph with a registry version requires
compatibility and recovery acceptance, not merely a successful compile.

### Atomic issue ownership

Mint issuance keeps the exact original operation, outputs and completion capacity
through recovery. Retirement/release must not discard an unfinished owner or
credit a result twice. Existing issue-ownership tests belong to the shared wallet
implementation; relay code must reuse it. Melt, incoming receipt, external proof
and other owners still require their own audit. [History](HISTORY.md) describes
the caller's durable handoff and recovery obligations.

## Boundaries and threats

Assets are wallet coins/keys, signed payment authority, lifetime/capital limits,
original financial evidence, useful forwarding capacity and the management LAN.
Untrusted parties include adjacent relays, customers, discovered identities,
transport senders, quoted setup data and remote mint responses. The local operator,
selected wallet implementation and accepted mint are explicit trust dependencies.

| Threat or boundary | Required defense and evidence | Residual limit |
| --- | --- | --- |
| Forged identity or relayed local customer | FIPS authentication and actual adjacent transport binding; customer-subnet checks cannot replace identity. | Authentication establishes a key holder, not honesty. |
| Malicious usage claims, replay or unsolicited transit | Original submitted-byte evidence, immutable terms, shared forwarding policy, durable exposure/credit and replay checks. | A valid payment buys best-effort service, not delivery. |
| Peer discovery or quote spam | Shared admission/rate/connection/record budgets and bounded quote cache; failed authentication releases unowned carriers. | Arbitrary Sybil fairness and RF anti-jamming are not established. |
| Free-control bypass | Strict bootstrap shapes/limits, explicit free destinations and earned return allowance; quote payloads remain ordinarily accounted. | Configuration may deliberately authorize free service. |
| Unexpected onward spending | Separate price, capital, lifetime and provider policies; customer/peer input never grants wallet authority. | Accepted mint solvency/correctness remains trusted. |
| Crash, full disk, lost reply or incomplete retirement | Durable exact intents, original costs/refunds, reserved completion capacity, retained owners and fail-closed recovery. | Lost/corrupted original evidence cannot be invented; physical power-cut acceptance remains open. |
| Slow or vanished peer/mint | Independent channel workers, bounded trials/timeouts and retained recovery ownership. | A stuck financial owner can retain capacity; arbitrary stalls cannot guarantee progress. |
| Unauthenticated ciphertext or transport prelude | Carrier ownership checks, authenticated liveness and fixed startup deadlines; native and finite physical pressure tests. | Tested ingress rates/windows do not prove unlimited DoS tolerance. |
| Self-signed WebSocket certificate | Explicit `tls_verification: fips` preserves FIPS identity authentication; normal certificate verification remains available. | It does not authenticate an HTTPS operator or strengthen mint trust. |
| Hostile discovery/portal profile | Validate input and limits; expose only approved setup data, never private operator status, secrets or spending controls. | Independent portal/client interoperability remains untested. |
| Management or ordinary Internet bypass | Separate test/customer interfaces and explicit firewall policy; device baseline checks before and after faults. | Paying FIPS does not grant ordinary Internet entitlement. |

The [TollGate proposal](TOLLGATE.md) keeps ordinary Internet and FIPS purchases
separate, including access to FIPS payment/bootstrap before buying Internet.
No adapter implementation or upstream interoperability is claimed.

## Reproducible acceptance and engineering constraints

Use existing tools instead of copying accounting logic into a new test runner:

- [Portable source bundle](FUNDING-COSTS.md#portable-development-source-bundle):
  verify the full offline dependency graph before building native/router artifacts.
- [Core/paid process tests](tests/): library accounting and control bounds;
  `service` for mixed carriers/restart/renewal; `funding_costs` for real wallet
  failure/recovery; `priced_paths` for native quality, churn and merge/split.
- [Chaos harness](../../testing/chaos/README.md): actual link impairment, kernel
  loss, storage pressure, independent conservation, guarded router/phone changes
  and restoration. Keep simulation features in the test mint, not the daemon.
- [Cadence suite](../../testing/relay-cadence/README.md): matched policies,
  independent CPU/wire/storage analysis and rejection of incomplete evidence.
- [OpenWrt guide](openwrt/README.md) and [Android guide](../fips-relay-app/README.md):
  architecture-specific packaging, lifecycle checks and ordinary executable use.

Simulations use real FIPS endpoints and policy over existing SimNetwork or the
chaos harness. The earlier hashtree review found useful production-router/codec
patterns in topology/recovery tests; its retired mesh simulator is not a second
payment model to revive. Keep simulated routing time distinct from mint expiry.

Run focused affected regressions and required repository gates. Source modules
in relay/Android stay within 600 lines; integration files stay within 1000, checked
by `scripts/check-rust-file-lines.sh`. Reuse shared FIPS/Cashu logic, keep regressions
for distinct failures, and remove redundant code/tests when reliability is retained.
After a verified change, integrate locally and remove only its clean, merged
worktree. Keep private profiles, tokens, device details and raw evidence out of
published artifacts. No runtime, acceptance result or readiness status changes
merely because this assessment is shorter.
