# Paid-relay v1 readiness

**Status: active; production readiness is not established.** Reviewed on
22 October 2026.

## Current state

The scheduling correction is `0eed2f3c2`, with SDK `9d6722a` and CDK `92ab6a37`.
It retains bounded outgoing control-rate waiting and priced-usage age while whole-sat
credit covers sends. Successful payment leaves newer sends with their own age;
unpaid older usage and failure retry bounds remain intact. The regression fails
before the correction and passes afterward. Runtime and dependencies remain fixed
unless a demonstrated failure or unmet requirement needs a change.

The local successor also reuses one capacity-checked wallet per offline command.
Its ordinary native/static ARM builds and custody checks pass with the same
dependencies. [Preparation measurements](MEASUREMENTS.md#offline-wallet-preparation)
cover small native samples; router timing and full-history preparation remain
unqualified for these new artifacts.

| Evidence | Verified result | Boundary |
| --- | --- | --- |
| `work/payment-cohort-regression-1` | 180 controller tests, formatting, strict library lint, feature-disabled check, ordinary Linux/ARM builds and the 1,101-file size gate pass. Source/dependency/artifact checks and stopped owners are independently verified. Four buyer and 19 transport-unit results are explicitly reused; 16 existing transport-integration tests also pass. | Software qualification does not establish router timing. The user's lockfile remains unchanged. |
| `work/payment-phase-trace-1` | A paused-clock regression verifies channel attribution and completed-phase durations; it fails against the old code. All 181 controller tests pass with the required private directory permissions. Formatting and strict library/test lint pass after correcting a stale handshake-loss fixture's exhaustive match. Sources, dependencies, logs, executable identity and stopped owners are verified. | Optional local diagnostics only; no stalled phase has yet been identified. The old red wrapper's stale assertion, initial fixture-permission failures and initial integration compile failure remain recorded. No new hardware acceptance is claimed. |
| `work/payment-phase-artifacts-1` | Ordinary Linux and static ARM builds of the diagnostics integrated in `7639b8739` pass with the same dependencies and shared build cache. Compiler records, executable hashes, source inventories, normal waits and stopped owners are independently verified. | These artifacts enable the next investigation; they do not establish that the two-second hardware requirement passes. |
| `work/payment-phase-current-capacity-1` | One actual 26,704,824-byte ARM copy is staged on each router. All unchanged full-history flash and RAM floors pass with those copies present. The copies are then removed; normal baselines, actual waits and absent owners are independently verified. | Allocation check only: no daemon starts, payments or acceptance traffic. The remaining relay delay still requires investigation. |
| `work/wallet-open-reuse-1`, `work/payment-failure-diagnostics-1` | Wallet reuse passes 364 library tests and two existing custody/CLI cases. The baseline 64-receipt paid case passes; the first optimized case fails awaiting an automatic payment acknowledgement. A fresh diagnostic passes with 3,501 completed payment phases captured. The existing payment deadline now retains its last observed state on failure; fixture formatting, typechecking and strict lint pass. | The intermittent timeout remains unexplained. Independent audits conserve the interrupted runs' original 3,328 test sats and the passing diagnostic's separate 3,072 originals. Failed verdicts remain preserved. These smaller native runs are not full-history hardware acceptance. |
| `work/wallet-open-reuse-final-1`, `work/wallet-prefix-completion-recovery-1` | Final ordinary Linux/static ARM builds, strict ordinary/test lint, feature-disabled check, formatting and the 1,101-file size gate pass. The existing 131-export case passes with unchanged mint pacing. The final ordinary binary preserves the permanent floor, rejects replay and retains 131 requests/256 sats of gross spending. An independent audit checks all 328 proof rows and conserves all 256 originals with no incomplete wallet operations. | The initial compiler-cache failure and first issuer-audit failure remain recorded. A dedicated Zig cache repairs missing objects; ordinary SDK recovery reconciles the test issuer's already-spent grant without new issuance. All 1,753 source files, 18 dependency trees, executable identities and stopped build owners are independently checked. This accepts offline-wallet reuse, not a router timing fix. |
| `work/wallet-runtime-qualification-1`, `work/wallet-phase-installed-check-2`, `work/wallet-phase-current-capacity-1` | The actual wallet/phase graph passes its explicit qualification and eleven rejection checks. The unfunded installed reader records 4,707 samples, passes its overhead limit and independently restores all baselines. The actual 26,699,912-byte ARM copy fits on all three routers with unchanged full-history floors; copies and exact owners are independently absent afterward. | The first capacity preflight stops before activation. Preserving every byte and metadata of one inactive closed snapshot in verified archives recovers 9,113,600 RAM bytes. These checks authorize investigation; they supply no paid forwarding or radio acceptance. |
| `work/payment-cohort-native-cadence-matrix-1` | Eight trials and 32 windows pass; all 285,696 packets arrive, 48 channels close and 40,960 original test sats reconcile across 96 SQLite sets and 872 archived members. | See [performance scopes](#performance-acceptance); no general optimum or total-overhead claim. |
| `work/payment-cohort-android-build-1` | Current source/dependencies, compiler input, normal features, native/package/signature identity and actual stopped build owners are verified. The unchanged 21 app files retain ten lifecycle tests. | The controlled Pixel case below supplies physical evidence for this package; production-wallet/VPN behavior remains outside scope. |
| `work/wallet-phase-android-macos-1/verified-artifacts` | The wallet/phase Android engine compiles locally with actual compiler records confirming measurement features and no simulation. Package assembly, strict lint, signature, SDK/ABI and exact stripped-library checks pass. Source inputs remain unchanged; the unchanged Java shell retains its recorded lifecycle evidence. | The initial compiler-launcher failure and both packaging-verifier failures remain preserved. The final audit uses the actual compiler records and minimum-SDK field. This is software qualification; the new package's controlled phone acceptance remains pending. |
| `work/payment-cohort-source-reconciliation-1` | The 1,753-file qualified inventory and 1,754 canonical paths have 1,731 identical entries, including 641 production code/manifest files. All differences are classified. | Differences include six Rust fixtures and six phone-tooling files, documentation, the protected user lock, relocated build configuration and three script execute bits. No physical acceptance follows from source identity. |
| `work/payment-cohort-phone-harness-check-1` | 32 focused Linux checks pass with zero skips; original owners/groups are gone. | Local fixtures and mocks operate no devices or funds. |
| `work/payment-cohort-phone-controlled-4`, `work/payment-cohort-phone-controlled-4-close-resumption-1` | The preceding cohort's ARM/Android artifacts pass unpaid denial and 4 MiB of foreground/background/forced-idle routing, including 48.30 seconds of forced idle. The original four channels and all 512 test sats independently reconcile; accounts/Wi-Fi/baselines are restored and the owned app is removed. The unchanged 223 harness files reuse 176 Linux checks. | The first install used a stale expected package name; the corrected case adopts the same owned, pristine APK before any funding. The original closer fails its separate 8 MiB space check; read-only archival and the original financial authority then complete under a new owner. Both failures remain preserved. The newer synchronized diagnostic-artifact capacity check passes. |
| `work/payment-cohort-canonical-fixture-build-1`, `work/payment-cohort-large-export-check-2` | Both canonical integration targets compile. The explicit large-export case passes in 299.24 seconds: admission refuses at 20,875,237 charged bytes within the 20 MiB cap, retains 79 exports, continues spending and collects all 1,024 original test sats. All 32 original files have a verified archive; the test owner and child are absent. | The other 34 listed cases have not run. The first launch failed before mint creation because the fixture socket path exceeded the existing limit; the passing launch uses a short, private persistent directory and the same executable. The 17.09-second offline reopen/ack observation is not a hardware timing guarantee. |
| `work/payment-cohort-installed-check-2`, `work/payment-cohort-current-capacity-1` | Unfunded current-artifact reader and independent staged-capacity checks pass all unchanged floors; temporary copies are removed. | Preflight evidence does not replace paid hardware acceptance or a fresh post-run capacity check. |

### Current router run

The last genuine-history router attempt fails the unchanged two-second
progress requirement. All 84 packets arrive; cleanup takes 24.639534 seconds,
within 35 seconds and before traffic ends at 28.278187 seconds. Relay authorization
has a confirmed minimum gap of 2.208247159 seconds and maximum 2.245729648 seconds;
downstream provider credit also fails. Delivery, source authorization and first
provider credit pass. This remains a functional failure.

`work/current-device-sequences/full-history-7-final-recovery-4` independently
verifies 5,480 genuine receipts, all 31 settlements, recovery of all 3,072 original
test sats, empty guarded wallets, stopped mint and restored baselines. Its 11,868
resource samples have no capture errors and five useful all-five-profile cycles.
The final audit and resource collection have normal waits and absent owners.
Missing local connection files interrupted the earlier collectors; resumption
reverified the completed original collection and ran the original audit body.
All earlier failed local owners and empty audit directories remain preserved.
The workload was not replayed and funds were not replaced. Resource evidence and
financial closure do not qualify this failed window or authorize the radio case.

Future trace boundaries also retain the validated CPU and payment-operation
counters already returned by the same status calls. This adds no observer round
trip or payment behavior. All 26 focused trace/window checks pass. The existing
trace proves the gap but does not identify which preceding payment phase caused
it; slow database commits in the cleanup log alone do not establish that cause.

`work/payment-io-diagnostic-1` isolates scratch SQLite WAL work from 2 KiB atomic
journal writes on the middle router, without payments or financial profiles.
Journal maxima are 4.56 ms at idle, 24.61 ms with the default 1,000-frame checkpoint
threshold and 70.34 ms at 128 frames. The corresponding commit maxima are 314.69
and 134.74 ms. This limited probe does not reproduce the full-run delay or justify
changing SQLite policy. Existing baselines are unchanged; only the owned scratch
databases and tool are removed after checking open references. Measured cleanup
recovers 4,669,440 flash bytes and 1,130,496 RAM-backed temporary bytes.

`work/full-history-7-archived-representation-1` preserves all 98 closed profile
files and 147 archive members, including original metadata, in verified private
and Linux archives plus a RAM archive on each router. Exact owner, open-reference,
mount and quiet-interval checks precede removal of only the redundant expanded
forms. The operation exits normally and measures 20,889,600 recovered flash bytes.
Independent archive readback confirms every original byte and restored baselines.
Although the operation's final space check passes, a later unsynchronized readback
falls below the unchanged full-history flash floors. Flushing pending filesystem
work restores the reported space. The subsequent synchronized check in
`work/payment-phase-current-capacity-1` passes with the actual diagnostic binary
staged on all three routers, without further profile removals. This capacity
observation does not resolve the timing failure or authorize the radio case.

The preceding runtime's genuine-history window also fails the
unchanged timing requirement: authorization gaps have a confirmed minimum
2.219443538 seconds and maximum 2.227160741 seconds. Signing and second-provider
credit also fail; delivery timing remains unqualified. All 84 packets arrive and
cleanup takes 25.581999 seconds, within 35 seconds and before traffic ends at
28.333736 seconds. `work/current-device-sequences/full-history-4-final` independently
verifies all 31 settlements and 3,072 original sats, empty wallets, stopped mint,
restored baselines, actual local waits and absent owners. Its 11,940 resource samples
have no errors and six useful all-five-profile cycles, but establish no hard bound.
Financial closure does not turn this failed functional result into a pass.

The one-receipt rehearsal remains historical observer qualification, not acceptance
of genuine pressure or a changed runtime. The original rate-limit cost failure and
its 48 channels/40,960 sats remain closed and rejected; both subsequent accepted
native matrices retain separate evidence. Preserve all failed attempts and their
original financial records.

Closed FULL4 storage is independently preserved in `work/prepaid-capacity-prep-1`:
98 files/147 members retain verified private/Linux archives. Its unsynced flash-floor
failure remains recorded. `work/sqlite-helper-headroom-2` removes seven proven-inactive
regenerable helpers and measures 16,027,648 recovered RAM bytes. A subsequent synced
observation and the current staged-capacity check pass. Before any further cleanup,
recheck exact custody, actual owners/open references and normal baselines; never
replay an old removal list or use an idle timestamp as authority.

Radio preparation in `work/current-radio-autonomous-v12` and its reviewed
`work/current-radio-sequence-owner-v4` verify the current runtime/resource-harness
bindings and retain the original collector failures. Read-only checks reject the
active collector, incomplete full result and known failed predecessor before
allocation. Execution still requires the actual full pass, original financial
closure, normally closed recovered collectors/final owner and useful resource
capture. No radio case has been staged or funded.

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
  The rebuilt capacity-limited app passes controlled foreground/background and
  forced-idle transit on its recorded graph; earlier cost observations retain their
  original builds. These controlled Pixel cases and independent recovery
  are complete for their recorded graph. Natural off-charge idle, physical movement
  and battery cost remain
  unqualified capabilities; they do not require further operator actions.
  The app remains a bench tool, and router/history acceptance below is still open.
- Acceptance uses fresh profiles and test money. Legacy profile migration is
  outside this greenfield scope. Existing operator accounts must be preserved.
- Public release, deployment, real-money operation and contacting upstream are
  separate authorization decisions. They are not prerequisites for local testing.

### Acceptance checklist

“Covered” below means the named tests or historical runs provide evidence for
that requirement on their recorded builds. It does not certify a newer binary.
Final sign-off requires the exact source/dependency/features and target artifacts,
closed financial recovery and the remaining controlled observations listed here.
An explicit unqualified capability is a limit on claims, not an added requirement
for manual testing or an unlimited sequence of longer runs.

| Requirement | Existing evidence and canonical contract | Required to close v1 |
| --- | --- | --- |
| Adaptive payments, idle suppression and independent checkpoints | [Cadence](CADENCE.md): cumulative payments per neighbor and paying direction, triggered by priced usage/remaining allowance or maximum age; separate checkpoints and renewal. The preceding native four-age matrix passes all 32 workload windows, and seven paid-carrier scenarios cover fault progress. The current worker regression proves debt age survives an in-flight exchange without duplicate or idle work. | The current native cost comparison is complete. Finish router acceptance with unchanged financial terms. Retain historical target evidence within its recorded graph. |
| CPU, storage, wire and delivery costs | The preceding candidate's native matrix and earlier recorded-graph Wi-Fi CPU, local payment-service packet captures, ARM64 storage syscalls and controlled phone-rate costs are reconciled in [results](CADENCE-RESULTS.md); [measurements](MEASUREMENTS.md) defines attribution limits. | Complete for these recorded scopes. Requalify affected observations if runtime/SDK changes; retain excluded shared work, physical-media/airtime and battery limitations rather than claiming complete attribution. |
| Every supported forwarding path | The [native path inventory](ACCOUNTING.md#native-path-inventory) maps individual/batched/deferred sends and source observations to shared admission/completion. r528 passes 438 recorded-graph contract/startup checks. The current session-recovery graph passes all seven paid carrier scenarios across UDP, TCP, Ethernet and WebSocket/TLS, with independent 2,688-sat conservation; r531/r532 cover unchanged native quote/admission contracts. | Recorded Linux carrier reconciliation is complete. Physical target acceptance remains below. Unsupported adapters cannot silently bypass validation or be advertised as qualified. |
| Bounded free bootstrap, ordinary priced quotes and configured free destinations | [Bootstrap](BOOTSTRAP.md), [return allowance](RETURN-ALLOWANCE.md), [destination pricing](DESTINATION-PRICING.md), r528 quote/admission contracts and r531/r532 native free/funded cases. Unpaid transit and unauthorized spending remain rejected while bounded joining/payment progress succeeds. | Recorded native checks are complete. Preserve these boundaries in final target/device acceptance; local free-traffic scheduling does not reserve radio airtime. |
| Permissionless mobile admission and spending policy | Authenticated adjacency, open-radio joining, merge/split and crowded-neighbor simulations; physical root replacement, newcomer admission and controlled channel handover. | Qualify controlled open-radio departure/rejoin, root replacement and route recovery on the final graph, recording admission/resource bounds. Actual movement, seamless roaming, automatic channel selection and unrestricted-identity fairness are not established. |
| Useful routes selected by price and quality | [Price selection](PRICE-SELECTION.md): real quotes, native feedback, trial quotas, loss/delay/partition/rejoin tests and physical alternative-path selection. r521 qualifies 28 selector checks and eight native paid scenarios on the r519 dependency graph before the r523 runtime fix, including delayed funding/renewal and merge/split. | Complete current physical-radio route-recovery observations and final target reconciliation. No global-optimality claim. |
| Financial crash and failure recovery | Real funding/settlement/refund interruptions, mint outages, full-filesystem recovery, guest kernel loss and physical process loss; [funding costs](FUNDING-COSTS.md). | The captured first-funding cut recovers with controller intervention in the [recorded checkpoints](#recorded-verification-checkpoints). Unattended recovery with the corrected runner and committed settlement/history handoff cuts remain unqualified. Additional manual cuts are cancelled; continue automated recovery checks without substituting them for physical evidence. Preserve originals and test-fund conservation. |
| Bounded lifetime history and useful progress | [History](HISTORY.md), SDK wallet capacity/admission, exact retirement plans, three real wallet lifecycle cycles and physical full-wallet/retirement-contention runs. Recorded source reconciliation matches all 34 catalog and 43 export review entries; the reachable service roles and exclusions are mapped below. | Complete current full-history pressure/progress and aggregate process-resource observation. Finite cycles do not establish an indefinite physical-storage plateau, hard RSS ceiling or generic whole-call deadline. |
| Reproducible target operation | Relocatable offline source bundles, [OpenWrt packaging/recovery](openwrt/README.md), [service operation](SERVICE.md), [test funding/collection](TESTBENCH.md) and [Android lifecycle](../fips-relay-app/README.md). | The final candidate passes Linux/OpenWrt builds and Android compile/package verification. Finish router and affected controlled phone acceptance, final reconciliation and cleanup with preserved accounts. Controlled Pixel installation/recovery and owned-app removal remain accepted for their recorded graph; natural Android deep idle remains an explicit limitation. |
| Threat model and integration proposal | [Threat model below](#boundaries-and-threats), explicit mint trust and [local TollGate proposal](TOLLGATE.md). r618 checks the current interfaces against the proposal and its pinned upstream specifications, including price/quality trials and raw mint-bridge limits. | Recheck affected contracts if the final runtime changes. The deliverable is a proposal; actual TollGate interoperability needs its separate acceptance before it is claimed. |
| Maintainability and simulation reuse | Existing SimNetwork/chaos facilities, shared Cashu logic, source-size gate and focused production-path regressions. | Retain the 600-line relay/Android and 1000-line integration limits; remove superseded code/tests without losing distinct failure coverage. |

## Completion sequence

1. **Native cadence comparison: complete for the current candidate.**
   `work/payment-cohort-native-cadence-matrix-1` passes all eight forward/reverse
   trials at 250/500/1000/2000 ms and all 32 windows: 285,696 packets arrive,
   48 channels close, 40,960 original test sats reconcile, and 96 complete SQLite
   sets and all archives are independently verified. The corrected baseline's
   separate accepted matrix remains valid, and the original rate-limit failure
   in `work/prepaid-native-cadence-matrix-1` remains preserved and financially
   closed. Reuse this evidence for unchanged inputs; another complete matrix is
   required only for an affected change or concrete unresolved failure.
   Measurements retain their actual quiescence, cache lock and two-core quota.
   Preserve earlier graphs and attribution limits in
   [the results](CADENCE-RESULTS.md); keep the 500 ms default unless measurements
   justify changing it. Never replace a failed case's grants or replay financial
   work. Device tests and competing builds run separately from this measurement.
2. **Genuine-history router successor: failed timing; financially closed.** The rounded-credit
   and payment-cohort regressions are reproduced and fixed. Current source,
   dependency, feature, artifact and stopped-build evidence, affected harness
   checks, unfunded installed-reader acceptance and staged capacity are bound to
   the completed original attempt. Collection and independent audit recovered from local connection
   failures without restarting the workload or replacing its funds. The relay still
   exceeds two seconds. The next diagnostic must capture completed payment phases
   on the routers under the same genuine pressure. The historical rehearsal qualifies
   the observer only. Require a meaningful qualified runtime or diagnostic change
   before a new paid attempt; a logging change supplies no presumption of a timing
   fix. Do not relabel historical hardware evidence or silently remove an
   equality check. Reuse unchanged SDK/CDK, observer, archive and workload evidence
   within its actual scope.

   Preserve verified archives before removing only proven-inactive expanded
   duplicates. Select targets from current custody; never replay an old cleanup
   list. Full history requires synced flash floors of 8/24/8 MiB and strictly
   more than 100 MiB RAM on every router, including the actual candidate copy.
   One-receipt capacity does not authorize this workload. Original financial
   bytes, saved accounts and artifacts stay protected.

   Keep the 20 MiB wallet, 5,480 genuine receipts, original channel prices,
   capacities and lifetime limits, 31 settlements and 3,072-test-sat cap. Keep the
   original 84-packet, 1,000-byte, 3-packet/s stream, two-second conservative
   delivery/authorization/signature/provider-credit requirement, 35-second
   cleanup bound and traffic coverage through cleanup. The detailed setup and
   observation contract is in [router retirement](#router-retirement-diagnostic).
   Closed histories, mint rollback, spent-original recreation, synthetic ballast
   or reset budgets cannot create a fresh fixture.

   Keep the six-hour preparation bound, eight-hour absolute workload budget and
   nine-hour independent closer. After returning the circulating sat, rearm only
   the time remaining in that workload budget; recover before failure if it is
   exhausted. The closer does not terminate a live financial owner. Use the
   durable local supervisor so actual waits survive a chat interruption.
   The five-profile read-only recorder samples about every five seconds on this
   same run; reconcile useful coverage of all five profiles, exact identities,
   missed epochs and endpoints. Its errors cannot block recovery or relax timing.
   Report sampled CPU/RSS/HWM and headroom without claiming hard resource bounds.

   Reserve 20 GiB diagnostic space, 4 GiB archive space and 256 MiB temporary
   work plus staging bytes on Linux. Preserve the 20 MiB wallet, per-snapshot and
   512 MiB recovery limits. Collection requires stopped exact producer/supervisor
   owners, sealed Linux originals, one verified expanded local copy and a verified
   compressed mirror, with expanded-plus-compressed space and 2 GiB local headroom.
   Preserve partial/uncertain transfers and reconcile an existing completed
   archive instead of rewriting it.

   Accept only the actual functional pass, all 31 independently verified
   settlements, conservation of the 3,072 original sats, stopped original
   producer/supervisor/root children, restored baselines and complete archives.
   A failed window may release devices after financial closure; it cannot release
   radio or qualify forwarding. Both failed runs remain closed in
   `work/current-device-sequences/full-history-4-final` and
   `work/current-device-sequences/full-history-7-final-recovery-4`.
3. **Complete controlled radio recovery after that full pass and closure.** Bind
   the current-runtime preparation in `work/current-radio-autonomous-v13`, using
   `work/current-radio-sequence-owner-v5`, to the actual accepted full run. Six
   software checks validate the current wallet/phase graph, reject the old
   resource manifest and failed FULL7 verdict, and refuse a live predecessor.
   The owner preserves its existing always-close path and refuses missing review
   or full-result bindings. This candidate uses the normal completion path;
   historical collection failures remain preserved. Execution still requires the
   actual functional pass, original-fund closure and stopped owners. Retain its 384-sat cap, two original 32-sat channels,
   original accounting and fresh all-router capacity including the ARM copy.
   Verify the complete helper graph, nested manifests, current sources and useful
   all-five-profile resource summary before staging. The existing owner records
   actual child waits and attempts the original closer once after launch,
   including a failed launch reply. Test stationary open-radio departure/rejoin,
   root replacement and route recovery. Preserve the distinction from physical
   movement, fading, seamless roaming and automatic channel selection.
4. **Reconcile affected targets and recovery.** The current wallet/phase Android
   graph compiles and packages successfully; its controlled phone regression is
   pending. Source preparation in `work/wallet-phase-phone-controlled-1` binds the
   current ARM/APK and preserves the controlled USB workload. Eight source checks
   pass; dispatch remains refused until the actual full-history run's financial
   release is independently reviewed and bound. The preceding cohort graph's
   controlled USB regression retains its
   independent financial closure and owned-app removal. Retain its
   recorded space failure: archive observations are 5,288/14,432/5,580 KiB on the
   three routers, below the archiver's 8 MiB floor on two. No databases or financial
   histories were deleted to clear it. New paid router work still needs fresh
   passing capacity; copy-only financial recovery does not need new-run headroom.
   Reuse unchanged Java lifecycle and recorded physical evidence within scope.
   No operator-assisted pairing, phone movement, unplugging or further
   power cuts are scheduled. Controlled link loss/rejoin, forced idle and process
   interruption keep those labels; none proves natural off-charge idle or physical
   flash power-loss safety. Existing mint-over-FIPS lifecycle/recovery evidence in
   [TESTBENCH.md](TESTBENCH.md#mint-http-over-fips) is separate from the storage
   fixture's LAN mint and does not qualify Android mint-over-FIPS integration.
5. **Complete the requirement-by-requirement reconciliation.** Check every row of
   the [acceptance checklist](#acceptance-checklist) against final sources,
   dependencies, features, artifacts, target evidence, threat model, operation and
   recovery documentation, and the local TollGate proposal. Current fixes are
   integrated locally; final affected-target acceptance remains required. Preserve
   the management LAN, normal Wi-Fi/Internet, services and saved accounts. Close
   or explicitly retain every unfinished financial owner, without fabricating a
   funded outcome for an unfunded refusal.
6. **Clean only completed owned fixtures.** Verify inactivity and recovery before
   removing test installations. Use managed archival only for finished,
   integrated, inactive task-owned worktrees; preserve active/shared work,
   unmanaged checkouts, unmerged history and operational state. Revoke only this
   job's temporary authorizations after its last device case. Private keys remain
   on their owning host. Public release, deployment, real-money operation and
   upstream contact retain their separate authorization boundary.

The old synthetic profile's erased admission cannot be reconstructed. Its
original funds are reconciled, but its unfunded controller record remains pending;
that profile is not reused. Preserve `work/harness-local-integration` and
`work/cleanup-history-gate-2`. Detailed superseded plans and their original
acceptance terms remain at `12ce1af4d:crates/fips-relay/READINESS.md`.

### Router retirement diagnostic

The hardware contract remains a 20 MiB wallet, 5,480 genuine retained receipts
for full pressure, original channel capacities/prices/lifetime limits, and one
84-packet stream of 1,000-byte payloads at 3 packets/s. Delivery, authorization,
completed signatures and provider credit must meet the unchanged two-second
conservative progress bound; cleanup and fresh complete post-terminal custody
must finish within 35 seconds while the original traffic covers cleanup. Setup
uses at most six fresh billable warmup probes, corrected calibration and at most
32 packets/s; losses and uncertain sends are recorded and never replayed. The
one-receipt rehearsal retains the full 31-channel workload and original 3,072-sat
cap, but cannot qualify history pressure. Its incoming channel lasts one hour and
its scenario is bounded to two hours; original onward terms and refund eligibility
remain in force.

The current observer samples each counter independently and retains every fresh
event through reader shutdown. It timestamps read start/end, distinguishes
completed signatures from authorization liability, and reconciles final numerical
values with acknowledged payment status. Cached values do not count as fresh
reads. Bounded custody queries run at most once per second; remote unavailability
is an explicit missing observation, while JSON/schema/count/identity failures are
fatal. Missing custody cannot prove cleanup overlap or completion. Ambiguous
counter intervals crossing two seconds remain unqualified, and fresh complete
custody is mandatory after all terminal payment observations within 35 seconds.
The four persistent numerical-reader sessions must close normally with exact
group absence. Their accepted synthetic smoke observes 3.1–6.3 ms steady reads;
it does not establish the paid window's timing.

## Performance acceptance

The [cadence results](CADENCE-RESULTS.md) retain matched 250/500/1000/2000-ms
comparisons, forward/reverse order, unchanged tariffs/allowances/checkpoints and
idle, bursty, steady and high-rate workloads. The current correction passes eight
native trials and all 32 windows, with independent original-fund closure. At the
unchanged 500-ms default, measured high-rate scoped payment CPU falls by 43% and
updates by 45%. These observations establish no general optimum or hard bound.

Keep measurement scopes separate:

- CPU covers exclusive payment spans, future polls and inherited blocking work,
  normalized by delivered payload. Shared core/TCP/transport work remains excluded;
  wall-clock spans are not CPU time.
- Current service counters count local FIPS payload submissions, not physical
  wire bytes. Earlier Ethernet captures match instrumented encrypted submissions,
  count sends once and retain unattributed traffic. They keep their recorded
  graphs and do not establish complete end-to-end or radio-airtime overhead.
- Storage traces distinguish journals, SDK snapshots, receiver databases and
  wallet shared memory. Logical bytes and successful syscalls do not measure
  physical-media wear or mmap writes.

Reuse valid evidence for unchanged inputs. Requalify affected observations after
an actual runtime/dependency change or for a concrete uncovered requirement;
there is no pending repeat of the already accepted current native matrix.
Complete shared-work attribution is required before claiming total payment
overhead. Radio airtime, battery life, flash endurance and maximum throughput
remain separate, unqualified claims. Methods belong in the existing
[benchmark runbook](../../testing/relay-cadence/README.md).

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

#### Current phone acceptance

The Pixel has served as both customer and transit router with the app hidden.
The recorded session-recovery graph passes unpaid denial and 4 MiB of controlled
foreground/background/forced-idle traffic, including 48.07 seconds of forced Doze.
A separate controlled disconnect/rejoin delivers 3 MiB with a 12.922-second owned
link interruption. Each case independently closes its four original channels and
512 test sats, stops its mint, restores accounts/Wi-Fi/router baselines and removes
its temporary app. Historical cost, renewal and corrupted/lost-traffic cases retain
their original graphs; they do not qualify a newer binary.

`work/payment-cohort-phone-controlled-4` passes that controlled regression on the
preceding cohort's ARM executable and matching Android package: 4 MiB delivered, including
48.30 seconds of forced idle, with the phone plugged in. The handoff preserves
the failed router verdict and its independently closed original funds. The same
223 frozen harness files reuse all 176 passing Linux checks. The corrected setup
uses the qualified APK's actual package and adopts its owned pristine install
after a pre-funding setup failure; it does not reinstall or reset an account.

`work/wallet-phase-phone-controlled-1` prepares the same workload for the newer
wallet/phase ARM executable and verified APK. Its eight source checks verify
artifact custody, reuse of all 176 harness checks, unchanged financial closure,
fresh absent-package installation and refusal before device operations while
the full-history run remains active. The mirrored preparation is unfunded and
has operated no devices. Its future release adapter remains unbound and must be
reviewed against actual original-funds closure, stopped owners and restored
baselines before dispatch; it is not phone acceptance.

The original closer passes functional postflight but fails a separate free-space
assertion. Its failure and partial archives are preserved. Read-only resumption
records the failed space floors, uses the unchanged financial authority to verify
all four channels and 512 original sats, mirrors the evidence and removes only
the owned temporary app. All resumption children exit normally; original accounts,
Wi-Fi, baselines and device financial records remain intact. This does not clear
the capacity failure or the router timing failure. No operator-assisted
pairing, movement, unplugging or further power cuts are scheduled. Controlled
faults do not prove natural off-charge idle, physical encounters, battery cost,
phone receiver-history pressure or production-wallet/VPN behavior.

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

Recorded checks cover exact saved-operation recovery, seed/database identity,
missing/corrupt wallet evidence, mint outages, fee-bearing funding/refunds,
capacity exhaustion and concurrent channel work. Fresh configured wallets have
native storage admission and reserved completion capacity. Three real lifecycle
cycles check reopen, retirement and refusal of a further purchase at the original
lifetime limit. They do not prove a whole-wallet storage plateau indefinitely.

Native capacity is required in saved service and customer profiles. Missing,
zero and oversized limits are rejected before initialization; fresh wallets always
use the bounded constructor. Profile, service terms and database capacity must
agree when reopening. Existing uncapped accounts are rejected without conversion.
The 20 MiB example value is explicit in generated profiles, not inferred from
missing saved data. These are logical storage reservations; filesystem/WAL
headroom and physical power-loss safety are not supplied by logical admission.

Custody archive format 7 reserves its pages, native ownership metadata and maximum
cursor growth in the same transaction as its exact registry checkpoint. Other
writes cannot consume an admitted capture's remaining allowance. A failed write
or stale comparison rolls back both; acknowledgment releases unused space. The
full-capacity regression completes two overlapping captures across reopen while
unrelated writes fill the remaining wallet. This reserves logical native payload,
not filesystem blocks. Receiver proof release retains its separate bounded queue.

The recorded source reconciliation matches all 34 catalog and 43 export review entries
to their recorded bytes. The configured service's open/balance, funding, incoming
payment, settlement, retirement and offline-token paths retain their documented
admission, count/byte and ownership bounds. The catalog uses bounded projections
and scalar SQL balance sums; recurring payment updates do not reopen the wallet.
This is source evidence, not a new whole-call timing or memory result. The receipt
is in `work/current-resource-source-reconciliation.json`.

`work/current-resource-final-reconciliation-1` rebinds all 77 catalog/export
entries to the current qualified sources: 71 runtime entries are unchanged,
five changed entries cover four reviewed runtime files, and one entry is the
explicit test-fixture exception. Seven additional reachable helper/wiring/test
sources are checked. The reference reader retains the 128-row, 4-MiB full
stored-receipt budget; matching ownership still receives ordered full validation
under the wallet operation lock before collection. Unrelated reference projection
is deliberately not a general metadata/curve/canonical-ID integrity scan.
Four existing focused regression results are reused with verified source/log
bindings. This adds no test execution, device acceptance or performance claim.

Paid forwarding and retirement still need aggregate current-target resource and
progress acceptance. Proof capture and ownership/receipt scans can traverse many
bounded pages in one call; removing a controller lock does not make them constant
time. Finite native/ARM lifecycle, refund, large-export and logical-pressure cases
retain their exact sources and scopes in [history](HISTORY.md) and
[funding/recovery](FUNDING-COSTS.md). The current runtime's physical full-history
window remains the outstanding combined observation.

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
implementation; relay code must reuse it. Existing incoming-receipt and
external-proof owners retain their durable handoff and recovery obligations.
The source reviews above cover the reachable relay roles; generic SDK workflows
outside them, including Lightning melt creation, need their own audit before
being added. [History](HISTORY.md) retains the caller's original-evidence duties.

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
| Cheap quote with dropped payloads or misleading quality | [Source selection](PRICE-SELECTION.md) uses native end-to-end feedback, capped trials, price/loss/RTT limits and provider cooldowns; local quote/payment success cannot qualify delivery. | Quality is an estimate, not a financial receipt or proof against a dishonest endpoint. Trial traffic may be paid and lost; lifetime and capital limits still apply. |
| Peer discovery or quote spam | Shared admission/rate/connection/record budgets and bounded quote cache; failed authentication releases unowned carriers. | Arbitrary Sybil fairness and RF anti-jamming are not established. |
| Free-control bypass | Strict bootstrap shapes/limits, explicit free destinations and earned return allowance; quote payloads remain ordinarily accounted. | Configuration may deliberately authorize free service. |
| Unexpected onward spending | Separate price, capital, lifetime and provider policies; customer/peer input never grants wallet authority. | Accepted mint solvency/correctness remains trusted. |
| Provider offline past refund eligibility | Persist original payment authority and preserve signed lifetime charges separately from realized payouts and refunds. The ninth diagnostic retains 31 sats of unclaimed credit without resetting its buyer's authority. | Signed credit remains conditional until claimed. An offline provider can miss its claim deadline and lose that income while the sender recovers the deposit. Channel terms and operational availability must allow time for settlement and recovery. |
| Crash, full disk, lost reply or incomplete retirement | Durable exact intents, original costs/refunds, reserved completion capacity, retained owners and fail-closed recovery. | Lost/corrupted original evidence cannot be invented; the captured initial-funding cut does not qualify settlement/retirement cuts or flash-write atomicity. |
| Slow or vanished peer/mint | Independent channel workers, bounded trials/timeouts and retained recovery ownership. | A stuck financial owner can retain capacity; arbitrary stalls cannot guarantee progress. |
| Unauthenticated ciphertext or transport prelude | Carrier ownership checks, authenticated liveness and fixed startup deadlines; native and finite physical pressure tests. | Tested ingress rates/windows do not prove unlimited DoS tolerance. |
| Self-signed WebSocket certificate | Explicit `tls_verification: fips` preserves FIPS identity authentication; normal certificate verification remains available. | It does not authenticate an HTTPS operator or strengthen mint trust. |
| Hostile discovery/portal profile | Validate input and limits; expose only approved setup data, never private operator status, secrets or spending controls. | Independent portal/client interoperability remains untested. |
| Mint bootstrap used as an unrestricted proxy | A pinned FIPS identity and fixed loopback backend, explicit free-route/return budgets and bounded bridge connections/buffers. The private issuance socket is not exported. | The bridge does not filter HTTP API calls; authorization belongs to the mint. Byte progress extends its idle timeout, so it is not a whole-request size or duration bound. |
| Management or ordinary Internet bypass | Separate test/customer interfaces and explicit firewall policy; device baseline checks before and after faults. | Paying FIPS does not grant ordinary Internet entitlement. |

The [TollGate proposal](TOLLGATE.md) keeps ordinary Internet and FIPS purchases
separate, including access to FIPS payment/bootstrap before buying Internet.
No adapter implementation or upstream interoperability is claimed.

## Recorded verification checkpoints

The complete prior evidence catalog, historical failures, source bindings, resource
observations and recovery narratives remain in Git at
`bca17833f:crates/fips-relay/READINESS.md` and their named private bundles. This
consolidation removes repeated milestone narratives, not their records or scope.
Historical acceptance always belongs to its recorded source/dependency/artifact
and workload; it cannot certify a newer binary. Earlier clean-checkout statements
retain their observation dates. This assessment grants no cleanup, replay or
replacement-funding authority.

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
After a verified change, integrate locally. Use managed archival only for finished,
integrated, inactive task-owned worktrees; never manually delete checkouts.
Keep private profiles, tokens, device details and raw evidence out of
published artifacts. No runtime, acceptance result or readiness status changes
merely because this assessment is shorter.
