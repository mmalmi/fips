# Paid-relay v1 readiness

**Status: active; production readiness is not established.** Reviewed on
19 October 2026.

## Current state

The current candidate combines FIPS runtime `ab2b9246`, SDK `715969e` and CDK
`4f03d81b`. Ordinary Linux, ARM64 OpenWrt and Android builds pass verification.
The latest CDK production change fixes cancellation after a failed local write
before send confirmation; the regression also verifies that an uncertain write
which committed confirmation retains its original coins for recovery. FIPS,
SDK, Spilman, forwarding and cadence code are unchanged by this correction.

Accepted evidence:

- CDK's new regression fails before the fix and passes after fresh compilation.
  All 561 wallet tests pass, as do formatting and strict lint. Evidence in
  `work/cdk-confirmation-cancel/gate-1` retains the initial stale executable and
  wrapper metadata failures alongside their independently verified resolution.
- The ordinary Linux relay passes strict lint, compilation, production-feature
  and source checks in `work/confirmation-native/gate-1`. It recovers both failed
  export originals with their mints stopped. Independent stopped-copy audits
  reconcile all 2,048 original test sats as spendable, preserve coin identities,
  receipts, cached exports, mint ledgers and buyer budgets, and find no unfinished
  wallet owners. No mint starts or new funding occurs; the original test verdicts
  remain failed in `work/export-original-recovery/run-1`.
- The larger-token case in `work/export-payload/gate-3` passes pressure, refusal,
  recovery, acknowledgment and continued spending at 20 MiB, then collects all
  1,024 test sats. Its 79 exports occupy 1,477,458 bytes. Whole offline reopen and
  acknowledgment takes 13.627 seconds on Linux. Controlled test-mint request
  pacing reduces the complete case from 1,008 to 137 seconds without changing
  production defaults. Large-payload device costs remain open.
- `work/confirmation-device-builds` preserves independently verified ordinary
  router and Android artifacts on CDK `4f03d81b`. Android target lint, ten Java
  lifecycle tests, Android lint, signature and packaged-native checks pass.
  The five unchanged customer-profile tests are reused. These are build results;
  physical acceptance of the updated artifacts is pending.
- The genuine 5,480-receipt native workload passes at 20 MiB in
  `work/receiver-history-native/run-8`, on the preceding CDK `bb9b87d8` graph.
  All 28 onward openings, settlements and both retirement cohorts complete.
  The independent audit reconciles all 3,072 original test sats as spendable,
  with no unfinished financial owners. All five delivery/payment counters
  advance; the largest observed gap is 1.398 seconds against the two-second
  limit. Cleanup finishes about 1.043 seconds after writer release while traffic
  continues. This is not evidence of multiple interior cleanup-overlap samples.

The third router history attempt is running with the same 5,480 receipts, 20 MiB
limit and two-second progress requirement. Its longer preparation allowance
follows measured device speed. The preceding device attempt's 3,072 sats are
fully collected, its original profiles and mint are archived, and baselines are
restored. The current run retains its recorded CDK `bb9b87d8` graph; it will not
be presented as execution of the newer binary.

The phone fixture now binds the matching corrected artifacts and reuses all 158
unchanged harness checks. The updated isolated APK is installed, visually checked,
empty and stopped; original accounts, normal Wi-Fi and foreground are preserved.
Its old empty data and the rejected debug-signature update are retained in
`work/receiver-history-phone`, together with the completed installation checks.
Funded execution waits for closure of the active router case. Physical mobile
encounter/rejoin, natural Android deep idle, remaining resource reconciliation
and final local integration are still open.

The candidate also removes 338 lines of superseded synthetic-capacity helpers;
focused checks pass in `work/cleanup-history-gate-2`. Original failed fixtures
remain preserved. In particular, the earlier synthetic capacity probe's erased
admission cannot be reconstructed: its original funds are reconciled, but its
unfunded controller record stays pending and that profile will not be reused.
Earlier run narratives remain in Git at `69aa4072d:crates/fips-relay/READINESS.md`
and in the evidence table below. The [acceptance checklist](#acceptance-checklist)
remains the full completion boundary.

## Completion sequence

Keep the current candidate fixed while closing the existing acceptance checklist.
Change it only to fix a demonstrated failure or an unmet requirement. Reuse valid
checks for unchanged inputs; rerun affected checks after a change. Avoid repeating
full suites or creating additional reports without a concrete verification need.

1. The genuine 5,480-receipt Linux workload and original-fund reconciliation are
   complete on build 14; reuse this evidence while its inputs remain unchanged.
2. Matching OpenWrt and Android builds are complete. Independent builds may run
   alongside setup where host capacity permits, outside timed observations.
3. Complete the affected router/phone, recovery and resource checks, combining
   compatible scenarios to avoid repeated setup. Close the existing mobility and
   natural-idle requirements; retain the documented physical power-loss limits.
4. Reconcile the checklist, threat model, operating/recovery documentation and
   local TollGate proposal. Integrate verified changes and remove only completed,
   owned test installations and clean merged worktrees.

The checklist below remains the completion boundary. This sequence adds no feature
scope and does not convert an unverified requirement into a passing result.

## Implementation and recovery evidence

Acceptance applies to each recorded source/dependency graph, workload and target.
The latest accepted graph is identified in [Current state](#current-state); older
results below provide regression evidence, not acceptance of a newer binary.

| Evidence | Verified result | Remaining boundary |
| --- | --- | --- |
| Latest native artifacts, `work/receiver-history-native/build-11` and `build-14` | Build 11's ordinary daemon, test mint and both test executables pass formatting, size, strict lint, four mint tests and four controller-cancellation tests on SDK `715969e`. The sparse-proof payout/export case passes. Build 14 reuses the exact daemon, mint and bench binaries; only the observer test changes, with focused build/lint/format/size checks passing. Run 8 qualifies the complete corrected workload. | Matching OpenWrt and Android build verification is complete; final device acceptance remains pending. |
| Genuine history, `work/receiver-history-native/run-8` | The complete corrected case passes at 20 MiB with 5,480 genuine receipts. All 3,072 original test sats are independently reconciled as spendable. All delivery/payment counters advance with a maximum observed gap of 1.398 seconds; cleanup finishes about 1.043 seconds after writer release while the traffic window continues. | Native process evidence, not physical storage, mobile or power-loss qualification. No multiple-interior-sample cleanup-overlap claim. |
| Genuine history, `work/receiver-history-native/run-6` and `run-7` | Each run retains 5,480 ordinary receipts, completes 28 onward channels and retires both cohorts at 20 MiB. Each independent stopped-original audit reconciles 3,072 spendable test sats without unresolved operations. Run 7 records successful cleanup, a 75,660-microsecond held inspection and 73 of 84 delivered packets. | Both runs retain their failed verdicts. Run 7 confirms that the outgoing channel has only 25 seconds left when the approximately 28-second stream begins. Build 14 corrects this schedule; the separate run-8 result above closes the native workload and progress acceptance. |
| Dependency checks, `work/cdk-sparse-selection/gate-6` | CDK `bb9b87d8` passes 560 wallet tests; SDK `8855afe` passes 454 workspace tests, with three existing optional measurements ignored. Both selection regressions fail before the fix and pass afterward; lint, formatting and the wallet-only build pass. | These checks qualify dependencies, not the complete relay workload. |
| Activity completion space, `work/activity-storage/gate-9` | SDK `16a80cee` has 457 passing workspace tests and three existing optional tests ignored; lint, formatting, source size, documentation and the wallet-only build pass. Coverage combines 378 unchanged passing tests from gate 6 with 79 rerun or previously unreached tests. The corrected fault targets the refund owner's release; production code is unchanged between those runs. | The original full invocation remains recorded as failed. SDK verification and local integration are complete; relay history-pressure and device qualification remain pending. |
| Rejected first wallet write, `work/rejected-admission/gate-1` through `gate-3` | The new regression fails before the correction with missing cancellation evidence. SDK `715969e` passes the complete workspace invocation: 458 tests, zero failures and three existing optional tests ignored. Formatting, strict lint and the wallet-only build pass; the exact verified fix is integrated locally. | Native build checks pass; live-workload and device qualification remain pending. The fix cannot reconstruct the erased admission from the old failed profile. |
| Failed native preparations, `work/receiver-history-native/build-6` through `build-8` | Original recovery audits reconcile all 3,072 test sats from each run without new funding. The original mint policy and financial evidence remain retained. | Token-size, collection-time and sparse-selection failures retain their failed verdicts. The later build does not change them. |
| Latest capacity probe, `work/receiver-history-native/capacity-2` | Incoming payout and four onward channel settlements succeed at 20 MiB. Original recovery completes the native send and retires four paid channels. The independent partial-recovery audit conserves 3,072 spendable test sats, unchanged mint financial records and the 128-sat lifetime debit. | The fifth channel is refused and its unfunded controller request remains pending after its admission record was removed. Synthetic ballast retains the old starting charge and does not qualify genuine receipt history or sustained forwarding. The preceding capacity-1 failure remains fully recovered. |
| Genuine history, `work/receiver-history-native/run-2` through `run-4` | All 5,480 original receipts remain preserved. Separate recovery audits reconcile all 3,072 test sats from each failed run. The latest completes two paid channels before the third opening is refused. | The complete cleanup/forwarding observation has not passed. Replacing genuine receipts with ballast or raising capacity would not close it. |
| Initial-funding physical cut, `work/power-cut-sender-handoff-attempt3` | The captured cut preserves original funding authority. A continuation recovers the original channels, delivers 1,280 payloads in each direction and collects all 384 test sats; normal baselines are restored. | Recovery required controller intervention after the runner lost its SSH connection. It does not establish unattended recovery, flash-write atomicity or settlement/retirement power-loss safety. Further manual cuts are cancelled. |
| Paid carriers, r613 | Seven recorded-graph cases cover TCP, configured/seeded WebSocket, self-signed/CA-validated TLS and sustained UDP/Ethernet loss. Independent audits conserve all 2,688 test sats with no unfinished operations. | Native processes and virtual links; no physical mobility or final-device claim. |
| Native/router costs, r613/r620 and the ARM64 storage comparison | [Cadence results](CADENCE-RESULTS.md) retain the matched four-policy matrices, independently reconciled payment-service captures and storage traces, including failed attempts and original financial closure. | Shared/opaque traffic, physical media, airtime and battery costs remain outside the reported attribution. The 500-ms default is unchanged; no general optimum is established. |
| Phone transit and costs, r615/r621 | Foreground/background and forced-Doze transit pass on their recorded graph. The cost comparison delivers all 17 MiB in its two background windows. Original funds are reconciled and owned temporary apps/profiles are removed. | Natural deep idle, physical mobility and the final dependency graph remain unqualified. USB power and unequal idle tails do not establish battery cost or an optimum rate. |
| Paid cleanup and renewal, r624/r626 | Original delivery, authorization and credit advance during fragmented cleanup; the renewal case funds exactly one successor. Both reconcile their 384 test sats and restore normal device baselines. | These are bounded observations on their recorded graph. They do not close the aggregate history/resource audit or physical power-loss gaps. |

Current fixes retain the original request identities, financial ownership,
lifetime totals and configured storage limits. Completion allowances are admitted
before financial work; retirement releases only space whose original ownership
has been verified. The [wallet bounds](#wallet-bounds-and-recovery),
[resource observations](#router-wallet-resource-observations) and
[acceptance checklist](#acceptance-checklist) describe the remaining requirements.
Fresh profiles are required; legacy profile migration is outside this greenfield
scope.

Detailed earlier narratives remain in Git at
`38be67fb4:crates/fips-relay/READINESS.md` (and the preceding historical assessment
at `e100c6bc7`). Private raw evidence remains in the named `work/` bundles. Failed
attempts keep their original verdicts and financial records. Use the complete
[source-bundle procedure](FUNDING-COSTS.md#portable-development-source-bundle),
including Spilman and the lockfile, rather than reconstructing a build from commit
IDs in this assessment.

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
  original builds.
  Natural idle and physical mobility remain open. Outstanding acceptance below
  prevents treating it as a qualified production release.
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
| CPU, storage, wire and delivery costs | Current-graph native/Wi-Fi CPU, local payment-service packet captures, ARM64 storage syscalls and controlled phone-rate costs are reconciled in [results](CADENCE-RESULTS.md); [measurements](MEASUREMENTS.md) defines attribution limits. | Complete for these recorded scopes. Requalify affected observations if runtime/SDK changes; retain excluded shared work, physical-media/airtime and battery limitations rather than claiming complete attribution. |
| Every supported forwarding path | The [native path inventory](ACCOUNTING.md#native-path-inventory) maps individual/batched/deferred sends and source observations to shared admission/completion. r528 passes 438 recorded-graph contract/startup checks. r613 qualifies seven paid carrier scenarios across UDP, TCP, Ethernet and WebSocket/TLS on the current graph; r531/r532 close recorded-graph native quote/admission reconciliation. | Native reconciliation is complete on the recorded graphs. Final target-artifact reconciliation remains below. Unsupported adapters cannot silently bypass validation or be advertised as qualified. |
| Bounded free bootstrap, ordinary priced quotes and configured free destinations | [Bootstrap](BOOTSTRAP.md), [return allowance](RETURN-ALLOWANCE.md), [destination pricing](DESTINATION-PRICING.md), r528 quote/admission contracts and r531/r532 native free/funded cases. Unpaid transit and unauthorized spending remain rejected while bounded joining/payment progress succeeds. | Current native checks are complete. Preserve these boundaries in final target/device acceptance; local free-traffic scheduling does not reserve radio airtime. |
| Permissionless mobile admission and spending policy | Authenticated adjacency, open-radio joining, merge/split and crowded-neighbor simulations; physical root replacement, newcomer admission and controlled channel handover. | Close physical mobile encounter/rejoin acceptance and record admission/resource bounds. Automatic channel selection and unrestricted-identity fairness are not established. |
| Useful routes selected by price and quality | [Price selection](PRICE-SELECTION.md): real quotes, native feedback, trial quotas, loss/delay/partition/rejoin tests and physical alternative-path selection. r521 qualifies 28 selector checks and eight native paid scenarios on the r519 dependency graph before the r523 runtime fix, including delayed funding/renewal and merge/split. | Complete physical mobile observations and final target reconciliation. No global-optimality claim. |
| Financial crash and failure recovery | Real funding/settlement/refund interruptions, mint outages, full-filesystem recovery, guest kernel loss and physical process loss; [funding costs](FUNDING-COSTS.md). | The captured first-funding cut recovers with controller intervention as described above. Unattended recovery with the corrected runner and committed settlement/history handoff cuts remain unqualified. Additional manual cuts are cancelled; continue automated recovery checks without substituting them for physical evidence. Preserve originals and test-fund conservation. |
| Bounded lifetime history and useful progress | [History](HISTORY.md), SDK wallet capacity/admission, exact retirement plans, three real wallet lifecycle cycles and physical full-wallet/retirement-contention runs. | Finish the workflow/store/query resource audit, including aggregate pressure, maintenance duration and completion capacity. Finite cycles alone do not prove bounded indefinite operation. |
| Reproducible target operation | Relocatable offline source bundles, [OpenWrt packaging/recovery](openwrt/README.md), [service operation](SERVICE.md), [test funding/collection](TESTBENCH.md) and [Android lifecycle](../fips-relay-app/README.md). | Freeze and qualify a common final graph on the intended targets. Exercise install/reopen/recovery with preserved accounts and remove owned test resources. Natural Android deep idle is still unqualified. |
| Threat model and integration proposal | [Threat model below](#boundaries-and-threats), explicit mint trust and [local TollGate proposal](TOLLGATE.md). r618 checks the current interfaces against the proposal and its pinned upstream specifications, including price/quality trials and raw mint-bridge limits. | Recheck affected contracts if the final runtime changes. The deliverable is a proposal; actual TollGate interoperability needs its separate acceptance before it is claimed. |
| Maintainability and simulation reuse | Existing SimNetwork/chaos facilities, shared Cashu logic, source-size gate and focused production-path regressions. | Retain the 600-line relay/Android and 1000-line integration limits; remove superseded code/tests without losing distinct failure coverage. |

Native admission reconciliation is complete for the recorded graph: r528 covers
contract/startup boundaries, r613 supported carriers, r531 quote/free-route cases
and r532 the four funded bootstrap, return, newcomer and contention scenarios.
Physical mobility, resource and target acceptance remain separate requirements.

The manual power-cut harness supports both initial funding and committed
settlement, sharing operator confirmation, outage/boot evidence and original
account recovery. Its settlement mode cuts the provider and restores both
forwarding links. All 74 focused Linux harness checks pass; this adds no physical
acceptance result. The original initial-funding device attempt remains separate.

The wallet resource audit has closed the custody archive's native completion-space
gap. The r527/r530/r533 benchmark covers retained receipts, unfinished-operation
scans, near-4-MiB plain secrets and parsed P2PK conditions at the 16 MiB logical
limit. Collection preserves original ownership and progresses without unreserved
growth space. r533 also observes both traversals of the shared capture routine,
including reservation and all appends, with bounded native source lookup.
r534 exposed repeated source validation in actual native retirement, reaching
about 144 s for 7,680 originals. Capture-scoped source reuse reduces that case to
4.312–4.314 s in r535, with comparable peak memory and live ownership/coin checks.
r539 adds the changed-keyset regression; r555 qualifies three real FIPS retirement
cycles on SDK `6a025d0`. r557 replays paid forwarding and contended retirement on
three routers, with scoped process resource observations. r541 extends the
large-refund regression through full sender retirement and observes it in a fresh
process. r549 covers aggregate refunds at native and client-store admission
saturation across distinct neighbors. r562/r565 qualify both profiles on one
ARM64 router: six 256-sat channels under a 16 MiB native allowance, and four
1,024-sat channels under a 64 MiB native allowance and unchanged 32 MiB client
budget. Exact coins and lifetime totals survive retirement, reopen and replay.
This covers completion reservations, not a literally full 32 MiB client file.
r550/r554 cover synthetic retirement, collection and capture on the router;
identity reuse reduces large-history retirement to 68.346 seconds. Remaining
reachable workflows, maintenance interference and physical-storage behavior
still need qualification. A page-size limit does not itself bound a whole call.
Reuse the existing harness for admission, rollback and reserved completion checks.

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

## Recorded verification checkpoints

The zero-refund fix reproduces a fully paid channel whose original native send
remains nonterminal after settlement. The SDK now verifies and completes that
exact send before retirement; partial-refund behavior and original ownership
checks remain covered. The native relay regression conserves all 384 test sats,
retires 480 refund coins and observes paid progress through cleanup. Two new
purchase attempts are refused during the held plan, then exactly one purchase
succeeds after cleanup. These are native results, not device or power-loss
qualification. The affected relay format, size and strict-lint gates pass;
whole-workspace formatting still reports unrelated changes in two core tests.

| Evidence | What it establishes | Limit |
| --- | --- | --- |
| Control reuse after r611 | Runtime `1b948a688` fixes two demonstrated TCP/FIPS races: a responder's idle timer closes a connection still reusable by the requester, and connection-pressure eviction discards an already buffered request. Both fail before the fix; 18 control unit and 16 integration tests pass with strict affected lint, formatting and source-size gates. Shared setup avoids duplicating the native connection fixture. | No-money regressions; the matching stream error does not prove the exact r611 trigger. Idle entries retain the existing eight-entry/per-peer bounds, requester expiry and peer-FIN cleanup; arbitrary eviction or network failure can still fail an exchange. No transmitted request is replayed. Exact sources, failures and successful gates remain in `work/control-reuse-r611`; r613 reconciles paid carriers and native/router cadence; r615 reconciles controlled phone transit. Natural Android idle remains open. |
| r611 rejected native cadence | All 285,696 payloads arrive and independent original-state audits conserve 40,960 test sats across 48 closed channels. Sources/artifacts are unchanged; all 872 original files and 96 complete SQLite sets remain retained, with owned processes/file handles absent. | The strict analyzer rejects a usage-request stream error in trial 5. Later payment progress does not clear the historical failure. No overhead comparison is accepted; no retries, replacement grants or device runs follow. Raw evidence and closure remain in `work/cadence-final-r611/native`. |
| r607 common graph and paid carriers | FIPS `718cfe5be`, SDK `dad0fc3` and Spilman `669fbdd943` pass all seven existing paid carrier scenarios with canonical manifests. Credit exhaustion, renewal, restart and settlement preserve the tested limits. Both five-minute loss cases observe three renewals per direction, key rotation and no disconnected-neighbor samples; 39,899–39,914 of 42,000 payloads arrive per direction under counted every-twentieth-frame loss. Independent original mint/wallet checks conserve all 2,688 test sats, with no unfinished operations or duplicate/mint-spent live coins. Ordinary Linux/ARM64 builds, affected strict lint and size checks pass. | Linux processes and virtual links; no device, physical power-loss, mobility or throughput claim. Only the generated-CA case uses the dedicated test-root daemon. Original coin identities, all 445 archived files, source/artifact bindings and stopped processes/file owners are verified in `work/current-carriers-r607/attempt-2`; no retries or replacement funding. The earlier attempt remains an unfunded native-build-only result. |
| r610 bounded settlement replies | Spilman `669fbdd943` shares one streaming reader across metadata, restore and swap responses. Swap success/error bodies are limited before parsing, using declared length and streamed bytes; each request has a 30-second deadline. The baseline accepts an oversized signed reply and waits beyond the test's 35-second guard. The fix passes 15 networking, closing and restore checks, including the actual deadline and preservation of original funding, payment signature and blinded outputs across retry. | Loopback HTTP and synthetic signed recovery, not a new real-mint spent-input recovery result. A full close can make several requests. Production lint is strict; unit-test lint permits only the repository's existing `unwrap` convention. The isolated test copy omits an inactive optional axum/macros resolver request; active features and all selected package versions/checksums match the accepted graph, and canonical manifests are unchanged. Setup and initial lint failures remain preserved in `work/settlement-http-r610`. r613 qualifies the common native and router graph; r615 adds controlled phone transit. The remaining resource and recovery acceptance is separate. |
| r609 bounded receiver retirement | Three individually valid 400-proof payouts reproduce the aggregate 1,024-coin handoff refusal. Runtime `718cfe5be` starts one eligible channel per upkeep, ordered by refund deadline then ID, while preserving saved-plan recovery. All 15 seller-history checks, strict library lint, focused formatting and size gates pass; the regression preserves cumulative totals and unrelated authority through each retirement and reload. | Storage-only proof identities exercise the real controller and SDK plan validation; no mint funds or devices are involved. Existing pending plans resume unchanged. The two-second upkeep cadence adds roughly up to 32 seconds for 16 eligible channels, plus processing and retries; this is not a measured completion bound. Receiver pressure, concurrent forwarding and final target acceptance remain open. Sources and both red/green receipts remain in `work/receiver-bounds-r609`. |
| r606 new purchase during retirement | The existing ordinary Linux fixture adds a distinct provider with no initial funds. With 480 refund coins and one pending cleanup plan, two Buy requests reject in 33/26 ms without funding, reservation or route changes; original paid delivery continues. After cleanup, exactly one new 32-sat channel funds, with both routes delivering and earning credit. All 5,249 originals arrive. Build, strict affected lint, formatting and size checks pass. Independent wallet/mint and native authority audits conserve all 384 test sats, retire 15 old channels and close both remaining channels at 21/1 sats paid and 11/31 refunded. Lifetime debit/refund remain 544/522, with zero locks, reservations or unfinished operations. | Test-only changes on runtime `4cb34fe19`, SDK `dad0fc3`; loopback links and deliberate SQLite contention. The first attempt completed behavioral and settlement checks but failed its final empty-wallet query; its failed verdict and independently closed originals are retained. The corrected helper skips only the empty query. This qualifies native contention, not hardware new purchases, physical power loss, signing latency or performance. Sources, stopped archives and both audits remain in `work/purchase-retirement-r606`. |
| r605 idle recovery after key change | Runtime `d0a29e889` tracks whether application data used the current epoch before retrying unanswered-data recovery. Lifetime delivery history, pending exchanges and explicit decrypt-failure recovery remain intact. The real 45-second drain regression fails on the baseline and passes with the fix, including seven idle seconds and recovery/delivery after fresh demand. Ten relevant compatibility checks pass. The ordinary native paid fixture observes 7,026 ms with unchanged endpoint epochs, per-channel priced evidence and all five payment request counters; 16/16 fresh packets, restart/reverse boundaries, three settlements and 1,024-sat conservation then pass. Strict affected lint, focused formatting and size gates pass. | The focused regression is native UDP only; final router/phone reconciliation remains. The earlier accelerated-drain candidate failure remains unexplained and preserved. Full-tree formatting still differs in two untouched core test files. Successful-fixture financial evidence is source/output assertions with normal cleanup, not an independent post-success SQLite audit. The long core regression is opt-in and was explicitly run; no longer-window zero-cost claim follows. Exact sources and receipts remain in `work/idle-recovery-r605`. |
| r624 router delivery during retirement | Ordinary ARM64 runtime `1b948a688` with SDK `dad0fc3` repeats r604's workload with 480 real refund coins in a 1,649,458-byte client store. All 4,609 original packets arrive: one warmup, 512 while the writer is held and 4,096 after release. Both stages observe new authorization, provider credit and delivery during one contiguous pending retirement plan; all 15 old channels finish retiring. The original active channel closes with 19 sats paid and 13 refunded. Independent checks of all nine complete SQLite sets reconcile the original 384 sats into the collector, with no duplicate/mint-spent live funds or pending mint operations. All 2,394 management checks pass; normal baselines are restored and the stopped test profiles are archived and removed. | This reconciles the accepted r604 cleanup/delivery case on the current graph. It is not a physical power cut, maximum-throughput test, CPU attribution, signing-latency bound or hardware renewal/new-purchase qualification. Four completed export records retain 129 pending-spent proofs worth 192 sats, all proven spent at the original mint; they carry no outstanding value. Failed r601 evidence is preserved. Current source, artifact, archive, audit and cleanup bindings remain in `work/retirement-current-r624`; the earlier accepted result and cleanup remain in `work/cudy-retirement-r604`. |
| r626 router renewal during retirement | The same ordinary ARM64 runtime and dependency graph retains 480 refund coins from 15 old channels. Both held stages advance authorization, provider credit and delivery; the due-renewal stage preserves the selected predecessor and original funding authority. After cleanup, exactly one 32-sat successor funds automatically and delivers 64 packets for 1 sat. All 1,089 original packets arrive. Independent audits of nine complete SQLite sets close all 17 originals and conserve the original 384 sats; lifetime debit/refund are 544/538, with zero final locks, reservations or unfinished operations. All 2,395 management checks pass and normal network baselines are restored. | This qualifies hardware renewal deferral/resumption on runtime `1b948a688`, SDK `dad0fc3`, without a held successor mint reply. It does not qualify hardware new purchases, maximum resource costs, physical power loss or a later SDK runtime. All four original archives and mint recovery identity are retained; the stopped test profiles are archived and removed. Evidence remains in `work/retirement-renewal-r626`. |
| r603 one-way key confirmation | Runtime `4cb34fe19` adds a fixed 28-byte authenticated rekey proof within the existing handshake limits. It reserves nonce zero before exposing the new epoch and retries identical bytes, preserving replay authority and MMP counters. Seven focused core checks cover confirmation, malformed/replayed/wrong-key traffic, response gates, dropped handshake/proof retry and ordinary-report recovery. Both ordinary native fixtures pass, including 16/16 fresh packets after a real drain with `return_allowance=false`, restart, reverse-payment limits and 1,024-sat conservation per fixture. Strict affected lint, format, size and ordinary ARM64 build checks pass. | The original runtime's 0/16 failure is preserved. The first fixed fixture delivers 16/16 but fails an idle assertion placed after the new long workload; the final fixture restores the original idle check's placement and accepts a drain already in progress. Both failed originals are independently reconciled. The latter's signed payments 13/9/5 and refunds 19/23/27 are recovered into wallets `[243,260,260,261,0]`; retained grace debt is 3,012/3,008/3,004 msat. Successful-fixture evidence is source/output verification, not a post-success database audit. [Wire format and upgrade requirements](../../docs/design/fips-wire-formats.md#sessionconfirm-phase-0x4) apply; r604 separately qualifies the three-router cleanup case, and r605 qualifies a bounded idle window after full drain; mixed-version operation and longer-term control costs remain open. Exact evidence stays in `work/one-way-rekey-r603`. |
| r602 renewal during retirement | The existing ordinary-process fixture now also makes renewal due while 15 closed channels retain 480 refund coins. Across 32 status samples, payments and delivery advance while retirement prevents new funding IDs or reservations. After release, exactly one successor reserves 32 sats; payments on the predecessor continue while its mint reply is held. The original successor completes automatically with preserved lifetime totals. The new case and original payment case pass, and independent SQLite checks conserve all 768 test sats without pending operations or duplicate/mint-spent live coins. Build, strict affected lint, formatting and size checks pass. | Test-only changes on the current ordinary Linux runtime, with `return_allowance=false`. This qualifies the recorded native renewal/retirement overlap; hardware renewal, signing-latency and performance acceptance remain separate. r606 closes native new-purchase contention; r603/r604 close the recorded session regression. Both setup-only failures are preserved with zero issuance. Sources, logs and original stopped fixtures are bound in `work/renewal-retirement-r602`. |
| r601 fragmented-router attempt | The ordinary ARM64 build includes runtime `2aaef7cc8` and SDK `dad0fc3`. Corrected fixture qualification passes six native mint cases, 43 harness checks and strict affected lint/format/size checks. Three routers retain 480 original refund coins, then submit 512 paid packets while cleanup is held. Signing and provider credit advance, but all six receiver samples report zero delivery and the destination reports session decryption failures. Normal closure retires all 15 old channels and collects all 384 original test sats; independent checks cover all nine databases and preserve lifetime debits/refunds. | **Delivery acceptance failed; post-release traffic was not reached.** One warmup packet arrived. The 2,354 management checks pass, normal services/accounts are restored, and closed profiles are archived before removal. r603 separately reproduces the session failure without wallet maintenance; this is not evidence that payment signing caused it. Failed results and exact source/artifact/archive bindings remain in `work/cudy-retirement-r601`. |
| r599 completed handover recovery | The regression reproduces a reload rejection after expiry converts a completed cooperative handover's predecessor settlement. Runtime `2aaef7cc8` permits that completed transition while preserving its refund, report, payment and successor authority; nine corruption cases are rejected. All 25 affected preopening, retirement, settlement and expiry checks pass, with strict library lint and source-size checks. The ordinary Linux daemon recovers the two original r529 failures: 768 test sats remain in their wallets, with zero channels or pending wallet/mint operations. | Exact identities, keysets, issuance, configurations and funding sequences are unchanged. The original failed r529 verdicts and intermediate r598 failure remain preserved. Independent archive/SQLite checks cover all 126 recovered original files in `work/handover-expiry-r599/recovery`. r600/r601 qualify its ordinary ARM64 build; final physical acceptance remains open. |
| r566/r576 sender retirement | The existing interrupted-handoff regression fails before the fix and passes with SDK `dad0fc3`: an unrelated funded channel pays successfully, and its saved balance survives resumed cleanup. All 444 workspace tests pass, with strict all-target lint and formatting. The existing lock test now allows bounded fork/exec descriptor-release latency; the earlier failed full run is retained. | Three opt-in tests remain excluded from the default suite. No new wire messages, lock files or store versions. [Paired router observations](#payments-during-sender-retirement) establish sampled availability, not live payment latency during a large cleanup. Funding and renewal still share the wallet owner. |
| r572/r577/r578 ordinary relay | Three Linux wallet-retirement cycles conserve all 384 test sats including mint fees. The ordinary ARM64 build delivers all 2,048 paid packets across three routers, retires two sender and two receiver channels, and collects all 384 test sats. Six controller reads take 166–179 ms during SQLite writer contention; all 282 management checks pass. Original services/accounts are restored and closed profiles are archived before removal. | Small-channel forwarding and recovery on the same production SDK graph, not concurrent paid forwarding during large-history cleanup. Physical power loss and final broader target reconciliation remain open. Source/artifact/log bindings are retained in `work/retirement-relay-r572`, `work/retirement-arm-r577` and `work/retirement-router-r578`. |
| r592 paid retirement liveness | Three ordinary Linux processes deliver all 4,609 original packets with 480 real refund coins retained. After the external writer is released, adjacent observations show new provider credit and destination deliveries during the same pending retirement plan. Independent mint/wallet checks account for all 384 test sats; the existing three-cycle case separately accounts for 384 sats including 13 in fees. Formatting, strict affected-target lint and source-size checks pass. | Linux loopback liveness, not uninterrupted native execution, signing-latency bounds, CPU attribution or router performance. Original fixtures and source/artifact/log bindings are preserved in `work/live-retirement-r592`. Funding and renewal still share the wallet owner. |
| r615 current Android | Runtime `1b948a688` and SDK `dad0fc3` pass the ordinary arm64 build, strict target lint, ten Java tests, Android lint, signature and packaged-native checks; 153 Linux harness checks pass without skips. The Pixel rejects unpaid transit and forwards 4 MiB across foreground, background, forced Doze and after idle, using the same process and four original paid channels. All 594 management checks pass. Independent audits of 11 complete SQLite sets, including four native receiver stores, account for all 512 test sats in the collector and preserve the original spending limits. | Controlled LAN/UDP adjacency on the charging, ADB-connected phone; forced Doze lasts 47.949 seconds. Natural idle, battery life, performance and physical mobility remain unqualified. The r617 mint's private recovery record matches the original database identity and all six cached public keysets; no mint restart is performed. Five completed export records retain 100 `PENDING_SPENT` rows, all proven spent at the original mint with zero outstanding value. Sources, artifacts, stopped originals and audits remain in `work/android-current-r615` and `work/phone-current-r615`. |
| r597 paid carriers | Runtime `d6874c3bf` with SDK `dad0fc3` passes the same seven scenarios as r529: mixed UDP/TCP, configured and URL-seeded WebSocket, self-signed and CA-validated TLS, and sustained UDP/Ethernet loss. Paid/unpaid boundaries, exhaustion, renewal, restart and final conservation pass. Independent mint/wallet checks account for all 2,688 test sats, with no unfinished wallet operations or duplicate/mint-spent live coins. Both five-minute loss cases observe three renewals per direction, key rotation and no disconnected-neighbor samples. Strict service lint and source-size checks pass. | Linux process/virtual-link evidence; Ethernet runs in an isolated namespace. Only the generated-CA case uses the explicit test-root executable. Loss cases deliver 39,900–39,905 of 42,000 payloads per direction while counting every-twentieth-frame loss; they do not measure maximum throughput or physical mobility. All 445 original files and 13 command logs are retained and hash-verified in `work/carriers-current-r597`. |
| r531 quotes and free routes | Six existing cases pass on their recorded graph: paid/free quote composition over native neighbor control, an explicitly free destination across three relays, arbitrary free destinations, free price-selection recovery and rejection of a paid prefix under a zero-price ceiling. The ordinary daemon's free-route cases preserve monetary journals through restart and make no mint requests. | Unchanged production and test source. Linux loopback evidence without funded wallets; it does not replace the four funded admission scenarios above. Artifact/log hashes, stopped processes and removal of successful temporary state are verified in the private `work/admission-current-r531` bundle. |
| r532 funded admission | Both unfunded-recipient bootstrap/earned-return cases, fresh paying-neighbor admission under full-wallet pressure, and mixed free/paid contention pass on the current ordinary runtime. All 2,816 test sats are conserved. The contention case delivers all 24 paid payloads and reconciles payment while the free stream is active; background-queue overflow is observed and free traffic resumes after refill. Strict affected-target lint, formatting and source-size checks pass. | Test-state retention is shared and extended; runtime unchanged. Linux loopback contention is pinned to two CPUs with mandatory observed background pressure. This establishes local scheduling, not Wi-Fi airtime or unrestricted-identity fairness. Sources/artifacts/logs and successful cleanup are verified in `work/funded-admission-r532`. |
| r534/r535 native retirement; r539 source checks | SDK `28630d4` integrates the whole-retirement benchmark and capture-scoped reuse. Six profiles pass, preserving exact originals and lifetime totals through reopen and later collection. All 443 workspace tests pass (two opt-in tests ignored), plus strict all-target lint and 19 focused source contracts on identical production code. Changed journal/keyset data triggers full validation; native owners and requested coins remain live checks. | 256 / 2,048 / 7,680 originals now take 0.137–0.149 / 0.994–1.008 / 4.312–4.314 s. The largest baseline was 143.911–143.993 s: at least 33.36 times faster, with peak VmHWM 67.18 / 67.14 MiB before/after. Linux wall-time observations, not CPU attribution, hard heap bounds or router qualification. The failed r536 fixture setup is retained; r539 adds its missing mint parent. Sources, hashes and logs remain in the matching `work/native-retirement-r534`, `work/capture-cache-r535` and `work/capture-cache-keysets-r539` bundles. |
| r555 FIPS retirement on SDK `6a025d0` | The ordinary Linux daemon passes three channel settlement/expiry/restart cycles at 16 MiB native capacity, preserving original refunds and refusing another purchase at the original lifetime limit. Strict affected lint and source-size checks pass. Independent mint/wallet accounting finds 371 test sats in wallets and 13 in mint input fees, accounting for all 384 issued sats without duplicate or mint-spent wallet originals. | Existing test assertions are unchanged; its original fixture is retained and hash-verified in `work/identity-relay-r555`. Source/dependency identities and stopped processes are verified. This checks actual FIPS integration, not physical power loss, router resource use or the remaining Spilman refund scaling audit. |
| r556/r557 ARM64 retirement on SDK `6a025d0` | The ordinary ARM64 build passes the existing three-router paid retirement scenario: all 2,048 payloads arrive, two sender and two receiver channels retire, original budgets survive wallet contention, and all 384 test sats are collected. Six controller reads take 0.155–0.161 s while the writers are held; all 282 management checks pass. Archived wallets retain the 16 MiB limit and the expected sender/receiver custody formats. | The release-to-retirement observation window is 2.784 s; candidate processes consume 0.337–0.474 CPU seconds each and peak at 23.13–27.76 MiB RSS over their lifetimes. These include background work and status sampling, not isolated cleanup cost, CPU-per-byte attribution or a before/after comparison. This small-channel scenario does not qualify large wallet-pressure cases or physical power loss. Original services/configuration are independently verified, stopped test profiles are archived and removed, and the test mint is closed. Evidence is bound to source/artifact hashes in `work/identity-arm-r556` and `work/identity-router-r557`. |
| r541 sender refunds | SDK `39d25170deb6` extends the existing real-mint regression through retirement of 1,023 refund coins. The fragmented case retains coverage of 2,049 native originals plus 31 refund coins. All four observed runs preserve exact custody, costs, reopen and replay rejection; an independent archived-wallet audit conserves 6,144 test sats with no pending wallet operations. All 444 workspace tests and strict all-target lint pass; two opt-in tests are ignored by the default suite. | Whole-call observations, including wallet open, take 0.675–0.678 s / 0.726–0.784 s, with maximum process VmHWM 31.92 / 22.63 MiB. These use fresh processes on shared x86-64 Linux, default native wallets without configured capacity, and one channel per case. They do not qualify a full 16 MiB wallet, aggregate refunds, hard heap/deadline bounds or routers. Existing child-process helpers are shared; production code is unchanged. Original fixtures, hashes and stopped-process checks remain in `work/refund-retirement-r541`. |
| r549 distinct-neighbor refund pressure | SDK `4a069bb` reuses the aggregate fixture with separate receivers and two admission profiles. Native pressure admits six 256-sat channels; client pressure admits four 1,024-sat channels. Each refuses and cancels the next request, finishes admitted refunds and retires the full prefix without changing its budgets or lifetime totals. All three runs preserve exact originals; independent audits account for all 36,864 test sats with no unfinished wallet operations. All 444 workspace tests, strict all-target lint and formatting pass (three opt-in tests ignored by default). | The native case retires 1,559 originals in 0.696 s with peak VmHWM 32.40 MiB; two client cases retire 4,097 originals in 2.663–2.685 s with peak up to 56.75 MiB. The client case has a 64 MiB native allowance and a 10,903,407-byte client file: it fills admission reservations, not a literal 32 MiB file. Shared x86-64 observations do not qualify device memory or physical disk exhaustion. Original fixtures, stopped processes and source/artifact/log hashes are verified in `work/aggregate-neighbors-r549`; production code is unchanged. |
| r562/r565 real router refunds | The unchanged production SDK passes both admission-pressure profiles with real test-mint funding, refunds and whole-prefix retirement. Six 256-sat and four 1,024-sat channels preserve 1,559 and 4,097 original coins respectively. Independent mint/wallet audits conserve all 20,480 test sats, with no unfinished wallet operations or duplicate live coins. | [Measurements below](#real-refunds-under-admission-pressure) include whole calls and process memory. The client fixture uses a six-minute real expiry to accommodate device setup; financial limits are unchanged. These are isolated SDK tests on one ARM64 router, not concurrent daemon traffic or flash/power-loss qualification. Successful originals are archived before scratch removal. r594 separately recovers the failed earlier fixture; its test verdict remains failed. |
| r550 router storage pressure | Five existing SDK cases pass on one ARM64 Cudy with unchanged production sources, original ownership/capacity assertions and no mint or monetary operations. All 81 management checks pass; no memory-limit or OOM event occurs. Independent postflight verifies unchanged accounts/network configuration, stopped test processes, restored resource settings and archived diagnostics before removing 30,388 KiB of owned scratch data. | [Measurements below](#router-wallet-resource-observations) cover synthetic SQLite histories on `/tmp`, not flash, concurrent paid forwarding or large real refunds. Retiring 7,680 originals takes 72.315 s; this remains an unresolved router maintenance cost. Artifact/source/log hashes and the separately preserved failed launcher attempt remain in `work/router-pressure-r550`. |
| r558/r559 Android on SDK `6a025d0` | The current ordinary runtime and optimized SDK build for arm64 Android with core defaults, measurements and no wallet simulation. Strict target lint, all ten Java lifecycle tests, Android lint, APK signature and packaged-native checks pass. Physical r559 rejects unpaid transit and delivers four MiB while foreground, background and in 48.98 seconds of forced Doze, using the same process and four original paid channels. All 512 test sats are collected and 600 management checks pass. | Controlled LAN/UDP adjacency on the charging, ADB-connected phone. Natural deep idle, battery use and physical mobile encounters remain unqualified. Independent postflight verifies original accounts, normal Wi-Fi and router baselines; closed profiles are archived and the temporary app removed. Artifact/source hashes remain in `work/android-identities-r558`; device and financial closure remains in `work/phone-identities-r559`. |
| r533 capture and decoded conditions | SDK `d3b98e4` extends the existing benchmark with 16 passing profiles; 443 workspace tests pass (two opt-in tests ignored), with strict all-target lint. Shared capture preserves 16,384 originals across 128 pages, finishes at its admitted limit, survives reopen and retains exact ownership/totals. Full-history P2PK collection preserves protected originals and progresses without extra capacity. | Production source unchanged. Shared capture takes 1.59 s with peak reported VmHWM 25.96 MiB; 50,000-key conditions peak at 77.50 MiB. Timings exclude caller send-plan and refund verification. Finite x86-64 observations, not hard heap bounds or router qualification. Source/artifact/log hashes and stopped processes are verified in `work/history-resources-r533`. |
| r527/r530 collection pressure | The existing native SQLite benchmark now covers receipts, unfinished-operation ownership and large plain-secret originals. SDK `d7ac1a7` adds only test/fixture changes; all 22 r530 profiles pass alongside the earlier 12 receipt profiles. Protected originals and exact owners survive full logical capacity; eligible originals collect without raising limits or resetting lifetime totals. Required workspace verification passes 443 tests (two opt-in tests ignored), plus strict all-target lint. | At the 16 MiB admission limit, full unfinished-operation histories take 363–464 ms per call with reported VmHWM below 30 MiB. Near-4-MiB plain-secret profiles peak at 65.70 MiB. These are finite x86-64 wall-time/kernel observations, not CPU attribution, hard heap bounds, parsed-condition expansion, full-capture, router or physical-storage qualification. Private evidence remains in `work/history-resources-r530`. |
| r528 accounting paths | The recorded runtime/dependency graph passes 58 core forwarding/admission checks, 336 relay unit checks, 37 bootstrap/buyer/ledger/durable checks and five service-startup checks. Failed-bind, replay, completion, source authority and bounded-wait coverage are checked by exact test names. The stale buyer fixture now gives its history/pending checks a 20-sat channel while retaining the 10-sat spending budget; strict affected lint, formatting and source-size checks pass. | Runtime unchanged. The original 11-pass/one-failure buyer run remains rejected; only its fixture needed correction. This covers contract/startup paths, not the complete mixed paid-carrier or physical acceptance matrix. |
| r526 Wi-Fi cadence | The corrected `d6874c3bf` ARM64 build passes all eight trials over native Ethernet/802.11s: all 93,696 payloads arrive, all 16 channels settle, all 3,072 test sats are collected and 2,109 management checks pass. Strict delivery/accounting/cost validation and independent restoration/archive checks pass. [Recorded radio costs](CADENCE-RESULTS.md#wi-fi-matrix-with-the-control-expiry-fix--14-october-2026) cover all four policies. | Two repeats per policy on three stationary routers with one paid relay. Scoped CPU, logical journal writes and local carrier bytes exclude shared/physical costs. No one-way latency, maximum-throughput or power-cut claim. |
| r524 native cadence | Runtime `d6874c3bf` passes the unchanged eight-trial comparison and strict delivery/accounting/cost validation. All 285,696 payloads arrive and all 40,960 test sats are collected. Processes stop and original settled profiles are retained. [Recorded native costs](CADENCE-RESULTS.md#native-matrix-with-the-control-expiry-fix--14-october-2026) cover idle, bursty, steady and high-rate workloads. | Two repeats per policy on clean Linux loopback links. Scoped CPU, logical relay writes and local payment-service transport counters exclude shared/physical costs. |
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
with their original financial owners and verified archives retained. r599 closes
both owners using the corrected ordinary recovery path, conserving their separate
768 test sats without new issuance, channel creation or identity replacement.
They remain excluded from the successful-case total above. The private
`work/mixed-carriers-r529` bundle binds sources, artifacts, logs and retention;
postflight checks confirm all owned processes have stopped.

r597 repeats those seven scenarios on SDK `dad0fc3`, retaining successful
original accounts as well. Its fixture-only overlay disables deletion after
success and leaves all assertions unchanged. The earlier r596 build was stopped
before any financial case to correct archive access for namespace-owned files;
it issued no funds and is not counted as a passing run.

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

SDK `dad0fc3` releases the client-store lock during wallet reads, capture and
cutoff work. [Payment signing](src/controller/payments.rs) can use unrelated
active channels even with a pending sender intent. Each retirement write reloads
and validates current state, preserving payments saved in between. Client loads,
validation and writes still hold the lock. r592 demonstrates Linux delivery and
payment progress during pending retirement. r604 establishes concurrent paid
forwarding during large-history router cleanup on the recorded ARM64 build;
signing-latency bounds and isolated CPU/storage costs remain unqualified.

The physical helper takes an actual SQLite writer transaction without changing
rows. Its deadline, signal handler and independent device guard release it.
See [history coordination](HISTORY.md) and
[the shared test](../../testing/chaos/sim/wifi_retirement.py).

### Router wallet resource observations

r550 cross-builds the existing SDK pressure test from `4a069bb` for ARM64 musl.
It uses the relay's wallet/Spilman feature set plus the test's required
`credit-store` feature, with no mint simulation. Each case constructs synthetic,
unsigned storage records, then measures the production maintenance call in a
fresh process. Original-owner preservation, reopen/replay and eventual collection
assertions remain unchanged. These are SDK tests, not the ordinary relay daemon.

| Workload | Measured maintenance, s | Process peak VmHWM, MiB |
| --- | ---: | ---: |
| Retire 256 originals across two sends | 2.011 | 13.75 |
| Retire 7,680 originals across 60 sends | 72.315 | 50.83 |
| Collect with 8,083 unfinished operations at native capacity | 11.377 | 20.96 |
| Collect a 50,000-key proof with 4,301 receipt owners at native capacity | 8.248 | 51.58 |
| Capture 16,384 originals across 128 pages | 22.651 | 18.23 |

The native allowance is 16 MiB. Collection fixtures fill admission and then set
the limit to their original charged size; capture removes unreserved headroom
only after reserving its complete output. The separate test-process group has a
192 MiB guard including fixture construction and child processes; it records no
limit hits or OOM events. Management checks take at most 0.216 s and observed
available system memory stays above 236 MiB. These observations establish useful
progress for these five cases, not a hard time or memory bound.

SQLite files use `/tmp` on the router. Timings exclude fixture construction and
later assertion/cleanup work; process peak memory includes startup and wallet
open. They do not establish flash durability, flash performance, battery cost or
paid forwarding under contention. The 72-second whole retirement call remains
an open router maintenance cost.

Temporary stage timers in r551/r552 locate that cost on Linux and the Cudy.
The router's 72.607-second diagnostic call spends 55.816 seconds capturing
history. That includes 10.930 seconds reading the source journal/keysets,
17.208 seconds validating the source and native operations, and 15.017 seconds
reading and checking coin pages. These inner stages are included in the capture
time. All 32 management checks pass, and independent postflight verifies the
original configuration and removal of the test resources. The timers stay in
private frozen source copies; these diagnostic wall times do not attribute CPU.

SDK `6a025d0` reuses identities already verified within a coin page;
live coin, ownership, scope and recovery checks remain in place. Its paired,
uninstrumented Cudy run reduces 256-original retirement from 1.996 to 1.873
seconds and 7,680-original retirement from 72.394 to 68.346 seconds (5.6%).
Large-case peak VmHWM is 50.74 / 50.96 MiB before/after. All four cases retain
their custody, capacity and reopen assertions; all 63 management checks pass.
Independent postflight verifies unchanged configuration, stopped processes and
removal of 60,464 KiB of owned scratch data. This modest measured saving leaves
the whole-call maintenance cost open. Shared Linux measurements overlap and
establish no consistent speedup there.

r553 passes all 444 SDK workspace tests, strict all-target lint and formatting;
three opt-in resource tests remain excluded from the default suite. The existing
source-contract test also rejects a changed secret paired with its old identity.
r555 passes three ordinary Linux daemon retirement cycles, affected strict lint
and source-size checks. Independent accounting conserves all 384 test sats:
371 remain in the original wallets and 13 are mint input fees, with no duplicate
or mint-spent wallet originals. The complete original fixture is preserved and
hash-verified. The same frozen graph passes r557's three-router forwarding and
retirement scenario and r559's four paid phone-transit windows. r558 qualifies
the Android build and lifecycle checks. These close the immediate target
rebuild/regression gap, with resource, physical power-cut, mobility and natural
idle acceptance still open.

### Real refunds under admission pressure

r562/r565 run the existing aggregate-refund fixture on one Cudy using production
SDK `6a025d0`. Mint simulation is confined to the disposable test-mint fixture.
Each profile refuses and cancels its next request at the original admission
limit, finishes admitted refunds, then retires the entire prefix in a fresh
process. Original custody, capacity, lifetime totals, reopen and replay assertions
remain unchanged.

| Admitted channels | Native allowance, MiB | Original coins | Whole retirement, s | Process peak VmHWM, MiB |
| --- | ---: | ---: | ---: | ---: |
| Six × 256 sats | 16 | 1,559 | 10.455 | 25.76 |
| Four × 1,024 sats | 64 | 4,097 | 41.394 | 40.76 |

These times include wallet open. The full fixture groups, including parent,
child and mint, peak at 52.01 / 111.42 MiB below their 192 MiB guard, with no
memory-limit or OOM events. All 116 management checks pass, taking at most
0.198 seconds. Client files reach 4,161,457 / 10,903,407 bytes under the unchanged
32 MiB budget; admission reserves future completion space. Independent audits
account for 4,096 / 16,384 issued test sats entirely in the buyer and seller
wallets, with no pending mint inputs or unfinished wallet operations. Original
accounts/network configuration and restored resource settings are verified.
The closed fixtures are hash-archived before their temporary files are removed.

The first client attempt, r563, used a three-minute lifetime; its fourth provider
payment was rejected as “expiry too soon.” Its original failed snapshot accounts
for 15,360 test sats in wallets and 1,024 in the unclosed channel. r594 subsequently
recovers that exact channel after expiry using the original mint and identities:
16,381 sats are in the buyer wallet and 3 in the seller wallet, with no pending
wallet operations or remaining channels. The failed test verdict is unchanged.
The fresh r565 run uses the bounded, test-only six-minute lifetime option and
still waits for actual expiry. Production code and financial/resource assertions
are unchanged. SDK `0eff9b4` contains that fixture option and its documentation;
r564 passes all 444 workspace tests, strict all-target lint and formatting
(three opt-in tests are excluded from the default suite). A separate preflight
refusal created no funds; removing a stopped, locally preserved executable met
the original memory threshold.

Evidence, source/artifact hashes, audits and cleanup checks remain in
`work/router-refunds-r562`, `work/router-refunds-r563`,
`work/refund-device-lifetime-r564` and `work/router-refunds-r565`. These SQLite
fixtures use router RAM storage. The 41-second call leaves concurrent payment
progress and flash behavior as explicit remaining checks.

r594 also closes the four interrupted native fixtures r543/r544/r545/r548.
The first two already held all their funds and needed terminal-history cleanup;
the others needed original expiry refunds and native reconciliation. Independent
audits account for all 69,632 test sats across these four and r563, with no new
issuance, changed identities/keysets, duplicate live coins or unfinished wallet
operations. Original failed evidence and complete before/after archives remain in
`work/historical-recovery-r594`. Recovery runs on Linux using production SDK
APIs; it does not qualify the original failed tests or physical power loss.

### Payments during sender retirement

r575/r571 compare the earlier SDK with `dad0fc3` using the same four-channel,
1,024-sat real-refund fixture on one ARM64 router. A read-only kernel observer
samples the original measurement process's wallet and client-store locks once
per second. Each build has one observed run; these are instrumented whole-call
measurements, not an untraced performance comparison or a payment-latency bound.

| Build | Client unlocked while wallet held | Whole retirement, s | Process peak VmHWM, MiB |
| --- | ---: | ---: | ---: |
| Earlier SDK, r575 | 0 / 37 samples | 41.492 | 40.87 |
| SDK `dad0fc3`, r571 | 34 / 47 samples | 48.919 | 52.16 |

The fix removes continuous exclusion by the client-store lock. The observed
whole call is 17.9% longer and process peak memory is higher; fresh reads and
validation preserve updates made during wallet work. Both full fixture groups
remain below the unchanged 192 MiB guard, peaking at 111.90 / 115.21 MiB without
memory-limit or OOM events. All 155 management checks pass, taking at most
0.205 seconds. Independent audits conserve all 32,768 test sats with no unfinished
wallet operations or duplicate live coins. Originals are archived and the
stopped temporary fixtures removed after baseline checks.

The SDK regression separately demonstrates an accepted payment during an
interrupted durable handoff and retention of that balance after recovery. The
[ordinary-process regression](HISTORY.md) adds real paid forwarding in r592:
15 settled channels retain 480 one-sat refund coins in a 1,641,733-byte client
store, while a separate active channel carries traffic. All 512 packets arrive
and payments are acknowledged while an external SQLite writer holds cleanup.
After release, all 4,096 further packets arrive; two adjacent observations within
the same pending plan add 60 deliveries and 3,000 msat of provider credit.
Including the single prerequisite packet, all 4,609 originals arrive. Cleanup
finishes without replacing the active funding record or resetting lifetime
debits. Independent accounting finds 109 / 147 / 128 test sats in the original
wallets, no unfinished wallet operations and no duplicate or mint-spent originals.

The 1.341-second observed maintenance window includes release, status sampling,
scheduling and multiple retirement calls. A pending plan does not prove continuous
native execution, and this is not a CPU or throughput measurement. r602 adds
native automatic renewal across the same maintenance boundary and a held mint
reply; r604 qualifies the recorded router forwarding/cleanup overlap below.
r606 also verifies native new-purchase rejection during the same pending plan,
then one successful purchase after cleanup with original route payments intact.
Signing delays remain open; r626 qualifies the recorded hardware renewal case.
Wallet ownership still serializes maintenance
and funding; this change promises neither constant-time work nor uninterrupted
traffic.

The hardware new-purchase case on SDK `9626cd1` delivers all 5,633 original
packets. Signing, provider credit and delivery advance during both held-writer
and released-writer cleanup of 480 refund coins. Two new purchases refuse while
the original plan is pending; exactly one 32-sat channel funds afterward, and
both routes deliver fresh traffic. The original route uses the three routers'
radio links; the second provider and destination are separate profiles using
management-LAN UDP. This does not qualify a second all-radio route or performance.
Independent checks of 13 complete SQLite sets and seven wallets account for all
384 test sats and 17 channels, with 15 old channels retired. All 2,434 management
checks pass. Five retained export records remain nonterminal bookkeeping, with
their exact proofs spent at the original mint; export retirement is not claimed.
The postflight validator's renewal-state expectation was corrected to match
ordinary settlement, which pauses renewal. The original failed check is retained;
the device run was not repeated. Normal baselines are restored, stopped test
profiles removed, and original archives retained in `work/retirement-purchase`.

r601 reaches the corresponding physical fixture with 480 real refund coins in a
1,649,458-byte client store. Its held traffic fails delivery before the release
phase; the destination reports decryption failures and evicts the session.
Financial closure succeeds with the original 16 channel identities: 15 retire,
the active channel settles for 3 sats, lifetime debits/refunds remain 512/509,
and the remaining buyer budget is 253 sats. All 384 original sats are collected.
Retained export bookkeeping is checked against the original mint's spent proofs.
This is a failed forwarding test with verified cleanup, not router liveness
qualification or evidence that payment signing caused the session failure.

Earlier r595/r600 device setup attempts fail respectively at the durable token
size bound and the old setup-time/export assumptions. Their original 128/384
test sats are recovered and collected without new issuance or identities.
The corrected fixture uses bounded grants/exports and measured setup margins;
production storage and mint-output limits are unchanged. The first failed r600
native grant fixture separately retains 128 uncollected test sats in its archived
original issuer/export state; its in-process mint is gone. It is not counted as
successful collection. Original failed verdicts remain preserved in their named
private bundles.

Five interrupted setup/probe fixtures retain their failed verdicts. Normal expiry
recovery and settlement close their original financial state without replacement
funding or new identities; independent checks account for all 7,680 issued test
sats. Failed originals and recovered archives remain in `work/recover-live-r588`
and `work/recover-live-r591`. This does not close other historical failures.

The earlier r570/r573 observers failed to find the hidden fixture directory and
to use the router's supported sleep interval respectively. Their failed verdicts
remain separate; their completed financial fixtures were independently audited,
archived and closed. The corrected observer was checked on the actual router
before r575/r571. Sources, originals, lock samples and reconciliation are retained
in `work/retirement-locks-r569`, `work/retirement-locks-before-r575` and
`work/retirement-locks-after-r571`.

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
The latest controlled expiry check uses SDK `1a558a9` on the phone and all three
routers. Unpaid transit is denied; all 2 MiB of paid duplex traffic arrive across
foreground and background windows. The original channels recover their refunds
after a controlled app stop and reopen, without replacement purchases. All 753
management checks pass. Independent original-state audits reconcile four channels
and all 512 test sats into the collector, preserving original accounts and normal
Wi-Fi. Native receiver-history retirement, natural deep idle, battery cost and
actual moving-radio behavior remain unqualified. The production-wallet/VPN
capabilities of a phone app are not supplied by the bench UI.
The archived temporary app and closed router test profiles have been removed;
the original app, accounts and mint recovery evidence remain preserved.

The ordinary Android build passes native/feature/lint checks, ten Java tests,
package and signature verification, and embedded-library identity checks. The
three rendered screens match r615. Sources and build owners are reconciled in
`work/android-rejected-funding`; the phone originals and acceptance evidence are
in `work/phone-expiry-rejected-funding`. An app restart lost the local supervisor's
exit status; the original runner continued once, and its terminal result, device
closure and process absence were verified separately. The original postflight
also rejected a retained expired-route fence. A separate validator proves it
belongs to the one original settled purchase, with unchanged funding and an
inactive quote; the failed check remains preserved. Neither issue caused the
funded workload to be repeated.

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

Native capacity is required in saved service and customer profiles. Missing,
zero and oversized limits are rejected before initialization; fresh wallets always
use the bounded constructor. Profile, service terms and database capacity must
agree when reopening. Existing uncapped accounts are rejected without conversion.
The 20 MiB example value is explicit in generated profiles, not inferred from
missing saved data. These are logical storage reservations; filesystem/WAL
headroom and physical power-loss acceptance remain separate requirements.

Custody archive format 7 reserves its pages, native ownership metadata and maximum
cursor growth in the same transaction as its exact registry checkpoint. Other
writes cannot consume an admitted capture's remaining allowance. A failed write
or stale comparison rolls back both; acknowledgment releases unused space. The
full-capacity regression completes two overlapping captures across reopen while
unrelated writes fill the remaining wallet. This reserves logical native payload,
not filesystem blocks. Receiver proof release retains its separate bounded queue.

The remaining audit must include reachable workflows/stores/queries and aggregate
memory, disk and maintenance work. Proof capture and owner/receipt scans can
traverse many bounded pages in one call; r515 removes the controller lock from
that work but does not make the work constant-time. r527/r530/r533 measure receipt
and operation scans, decoded large originals and shared capture. r534/r535 measure
actual native sender retirement and reduce repeated source authorization through
capture-scoped reuse. r541/r549 measure sender refunds through full retirement,
including saturation of native and client admission budgets. r562/r565 qualify
both aggregate profiles on one ARM64 router. r592 verifies Linux paid progress
during fragmented retirement; r624 reconciles r604's three-router overlap on the
current runtime and dependency graph. r626 adds automatic router renewal after
that cleanup, with continued predecessor payments while renewal is deferred.
The paired receiver admission check below covers logical storage pressure. The
latest run 8 also passes genuine retained-receipt pressure and paid progress at
20 MiB, preserving all 5,480 receipts and all original value. Its observed receiver
cleanup takes about 1.043 seconds after writer release, with sampled peak RSS of
124,392 KiB for the whole relay process. Device costs, other reachable workflows
and physical-storage acceptance remain open.

The remaining resource audit follows these production entry points. Shared SDK
limits apply on every wallet open; a bounded record or page does not establish
the total cost of the caller below.

Receiver cleanup selects one oldest eligible channel per upkeep. Its SDK handoff
admits at most 1,024 payout proofs and releases them in batches of 128 into a
1,024-entry queue. Each release is preceded by collection and also collects within
the release call. Unspent coins stay queued without scanning receipt/operation
owners; deleting spent coins requires those paged owner scans. Thus r628's unspent
maximum payout does not measure the worst spent-history scan cost. A full queue
retains the saved retirement plan for retry; it does not authorize deletion of
unspent coins or reset earned balances. The native case below verifies paid
progress while the wallet writer is held and exact spent-coin ownership through
cleanup. The controller wallet lock spans the handoff and final collection.
Existing payment updates and forwarding use separate locks; new funding and
refund work can wait behind it. The saturated profiles below measure individual
collection calls, not the complete handoff. The native case below measures
payment-progress gaps across actual cleanup using genuine payout originals.
It has one active receipt/operation, so it does not close saturated live-history
acceptance. Synthetic unfinished operations remain isolated storage fixtures;
inserting them into a live wallet would change recovery and final audit obligations.

The existing full-queue regression preserves the saved handoff and original coins
across reopen, then resumes after entries become collectible. This is safe
backpressure: a completed payout does not imply that all history can immediately
retire while its coins remain unspent or owned by another operation. Repeating
larger finite histories would not remove that condition.

**Saturated owner scans.** SDK `954c955` fixes an aggregate receipt-page failure
reproduced with valid retained rows: a 128-row page exceeded the database's 4 MiB
limit and prevented cleanup. The shared reader also preserves continuation after
a full reduced page. Existing owner, incoming and outgoing lifecycle regressions
cover the fix; no database limit is enlarged.

The extended existing storage fixture fills 20/64 MiB profiles until native
admission refuses another record, then tightens the collection limit to charged
bytes so cleanup starts with zero spare capacity. One guarded collection retires
one of 1,024 candidates. After explicit owner release, eight calls retire the
other 1,023; every unrelated owner remains exact and the lifetime count stays
1,033. Native and ARM64 cases all pass on the same SDK/CDK/Spilman source graph.
These are synthetic storage records, without financial value or mint traffic.

SDK `033eea6` uses CDK `c203b84f613d` to fetch at most 128 operations and
4 MiB of stored payload per statement, with the existing individual record limit.
Reduced pages continue until empty. Full checkpoint references, supplemental
mutable-row ownership and the wallet lock remain; no owner cache survives a call.
The existing owner regression now crosses both byte and row boundaries. The
candidate passes the same four native and ARM64 profiles without changing their
capacity, coin, ownership or lifetime-count assertions.

| Router profile / owners | Owner rows | First call before → after, s | Eight-call drain before → after, s | Cgroup peak before → after, MiB |
| --- | ---: | ---: | ---: | ---: |
| 20 MiB / receipts | 8,200 | 2.346 → 1.978 | 10.565 → 8.993 | 51.01 → 50.99 |
| 20 MiB / operations | 6,719 | 9.969 → 3.797 | 70.709 → 21.536 | 43.59 → 44.03 |
| 64 MiB / receipts | 26,744 | 4.575 → 3.718 | 28.416 → 23.513 | 135.51 → 135.37 |
| 64 MiB / operations | 22,130 | 29.479 → 9.066 | 228.464 → 63.757 | 111.79 → 112.02 |

These are single observations per case on the same router. Receipt-only control
cases are also faster (1.17–1.21 times), so these are observed ratios rather
than stable performance guarantees. Collection wall time excludes setup; cgroup
memory includes fixture construction, temporary storage and measurement together.
All cases stay inside the 192 MiB guard without memory-limit events. All 63
candidate management checks pass, normal network/accounts and resource settings
are verified restored, and archived temporary files are removed (30,444 KiB).
The baseline's 108 checks and separate diagnostic's 22 checks also remain accepted.
`/tmp` measurements do not qualify flash endurance, power loss, concurrent daemon
forwarding or worst-case cost for every admitted record shape. Candidate evidence
is in `work/saga-batches`; baseline and diagnostic evidence is in `work/receipt-pages`.

The separate diagnostic clone of the baseline times one 20 MiB operation case.
Across its eight-call drain, 53,744 individual saga reads and decoding take
57.10 of 71.74 seconds (79.6%); reference extraction takes 7.66 seconds (10.7%).
These wall-time components motivated bounded batching; they are not CPU costs.
Instrumentation is excluded from production source. Batching is retained after
the matched comparison above. The native case below checks complete cleanup
with a genuine payout; saturated handoffs and device interference remain open.

The [spent-payout forwarding fixture](HISTORY.md) passes with the ordinary Linux
relay rebuilt against SDK `033eea6`, CDK `c203b84f613d` and Spilman `669fbdd943`.
A genuine incoming payout supplies 1,023 one-sat coins to the relay. Cleanup
removes 960 spent originals in eight batches, preserves 32 still owned by an
active outgoing channel until its retirement, and leaves 31 unspent originals
unchanged. Both hops advance payment authorization and provider credit while the
wallet writer is held; all 128 held-writer and 512 released-writer packets arrive.
Independent stopped-copy audits conserve all 3,072 test sats with no unfinished
native operations, pending controller plans or open financial obligations. One
completed channel remains as ordinary expiry history, with its 687-sat payout
and 337-sat refund imported and unspent.

The existing fixture now samples through complete cleanup and the live stream's
final acknowledged payments. Its five-second observation records maximum gaps
of 0.929 s for delivery, 0.902/0.804 s for the two authorization counters and
0.904/0.803 s for provider credits, all below the two-second acceptance limit.
The 500 ms payment cadence and financial terms are unchanged. A focused observer
regression rejects stalled hops, late catch-up and an idle tail; it also preserves
the distinction between progress across cleanup and samples strictly inside it.
Only the first hop advances between unfinished-cleanup samples in this run;
progress on both hops strictly inside cleanup is not established.
These are gaps between observed cumulative-counter advances, including observer
delay; they are not packet latency or a protocol-wide guarantee.

Release to collection takes 0.687 seconds and 0.86 process CPU-seconds; sampled
RSS peaks at about 84.2 MiB. These observations include the whole relay process
on a shared Linux host, not isolated cleanup work. The actual wallet charge is
14,743,653 of 67,108,864 bytes (21.97%), with one active receipt/operation; this
is neither history saturation nor a device resource bound. Formatting, strict
affected-target lint, source-size checks, the observer regression and the full
813-second funded scenario pass. Original evidence, runtime/source bindings and
both audits remain in `work/cleanup-progress/run-1`; the preceding accepted run
remains in `work/spent-payout-native/attempt-5`. The initial build caught an unused
test variable before any funding; its output remains in `work/cleanup-progress/build-1`.

Earlier failed attempts retain their verdicts and original evidence. The third
exposed a refused purchase whose failed-send cleanup removed SDK admission while
retaining an unprepared request. SDK `1a558a9` requires that exact request,
matching channel metadata and no native operation before durable cancellation;
missing/conflicting evidence stays unresolved. Its regression covers interrupted
write, reopen, replay refusal, retirement and conservation. One original startup
recovers all 2,048 test sats without new funding or mint startup; one inert
withdrawn routing marker remains for ordinary upkeep.

The fourth attempt waited for a saved receiver plan while holding the wallet
writer, which also blocks preparation before the plan is saved. Original recovery
conserves all 3,072 sats, retains the exact 31 unspent coins and retires 992 spent
originals with no pending financial owners. Issuance and melt are disabled, with
no replacement funding. The accepted fixture instead checks the original eligible
settlement and coin custody during the hold. Recovery alone does not establish
forwarding or performance acceptance. These failed/recovered originals remain in
`work/spent-payout-native` and `work/rejected-funding-retirement`.

| Reachable work | Production entry point | Resource acceptance to reconcile |
| --- | --- | --- |
| Initialize/open and read balance | [Service](src/service.rs), [local wallet commands](src/wallet_tools.rs) | r608 traces the configured-mint path through bounded catalog reads and SQL balance sums. Device reopen cost at retained-history limits and physical storage behavior remain open. |
| Fund or recover an outgoing channel | [Purchase](src/controller/purchases.rs), [original funding recovery](src/controller/funding.rs) | Input/output limits, native and client completion reservations, interrupted funding and aggregate pressure. r602 covers native renewal deferral/resumption through sender retirement and a held mint reply; r606 covers rejection/resumption of a distinct new purchase. r626 adds hardware renewal deferral/resumption; the SDK `9626cd1` router case above closes new-purchase refusal/resumption on its recorded candidate. |
| Accept and update an incoming payment | [Wallet admission](src/payment_control/wallet.rs), [payment control](src/payment_control.rs) | r619 checks paired receiver/native reservations at full logical capacity: admitted work completes and rejected admissions preserve both stores. SDK `ef294e5` adds the maximum 1,024-proof payout through reopen, import and retirement at full logical capacity. r628 measures the same four-case regression on one ARM64 router. Aggregate costs under concurrent forwarding and final relay acceptance remain open. |
| Settle and recover refunds | [Cooperative settlement](src/controller/settlement.rs), [expiry recovery](src/controller/unilateral.rs) | r610 bounds settlement replies and preserves original closing authority on refusal/retry. Sender refund profiles pass r562/r565; receiver completion on devices and aggregate costs under concurrent forwarding still need resource reconciliation. |
| Retire and collect history | [History coordination](src/controller/channel_history.rs), [receiver handoff](src/payment_control/retirement.rs) | r609 closes oversized aggregate receiver handoffs with one oldest eligible channel per upkeep. r624 verifies payment and forwarding progress during the 15-channel fragmented sender retirement case on three routers. The native spent-payout case preserves exact active/unspent owners and bounds observed delivery/payment gaps at its recorded history size. The synthetic full-capacity observation below measures the complete receiver wallet handoff. Whole sender calls and aggregate device progress/memory acceptance remain open. |
| Import/export and acknowledge local tokens | [Wallet commands](src/wallet_tools.rs), [export handoff](src/wallet_tools/history.rs) | r614/r616 accept full 128-export caches on Linux and one ARM64 router, including refusal, acknowledgement and continued spending; the router acknowledgment takes 29.75 s. The larger-token case in `work/export-payload/gate-3` fills the 20 MiB store after 79 exports and passes refusal, recovery, acknowledgment and continued spending on the corrected CDK; Linux reopen/acknowledgment takes 13.627 s. Large-payload device costs remain open. These are exclusively owned offline commands, so their duration is administrative downtime. |

These are the relay's wallet entry points, not every generic SDK API. The local
import/export/acknowledgment commands require the relay to be stopped: the CLI
acquires its exclusive root lock, and the customer API rejects wallet actions
while its service is running. Concurrent-forwarding acceptance applies to the
automatic channel/history maintenance paths above, which run in the service.
This distinction follows the existing interfaces; it adds no runtime restriction.
The local `recover` command calls shared SDK startup recovery under the exclusive wallet
owner lock and configured mint-request pacing. It resumes original receipt/send
work, checks existing pending melts and paid mint quotes, and releases cancelled
custody. The relay exposes no commands to create Lightning invoices or payments.
A successful recovery pass can retain an unclaimed export; its report does not
mean every financial owner has retired. The existing export-recovery regression
preserves that original send and its proofs. Whole-pass costs still depend on the
retained work, so per-record read limits alone do not establish a duration bound.

One opt-in Linux observation measures the complete receiver wallet handoff at
the full logical limit within a 20 MiB profile with 5,480 operation owners. All
eight release batches and admission cleanup take 2.0853 seconds wall time and 2.08 CPU-seconds;
resident memory rises from 25,408 to 36,760 KiB. It retires 1,022 of 1,024 original
proof records, preserving one live-owned spent record, one unspent record and
all 5,479 unrelated owners. Reopening and repeating the handoff changes nothing.
The test uses synthetic storage records after an authenticated-plan/receiver-deletion
boundary, with no mint or monetary value. It excludes plan validation, receiver
deletion, concurrent forwarding, ARM timing and physical flash. The two-second
forwarding-progress target is not a wallet-call deadline; this observation alone
does not establish forwarding blockage. The recorded artifact uses SDK `9254b4e`;
the handoff implementation is unchanged in `03e6b50`. Source, artifact, original
output and independent acceptance are retained in
`work/receiver-handoff-pressure/native-1`.

The same workload on an ARM64 router, built from SDK `03e6b50` with release
optimization, takes 31.407 seconds wall time and 30.68 CPU-seconds. Process RSS
rises from 12,880 to 22,308 KiB; the whole fixture's cgroup peaks at 36.04 MiB
under its 192 MiB guard, without limit events. All ownership, capacity and reopen
assertions pass. Twelve management observations remain responsive; the slowest
takes 185 ms. The original daemon, boot and network configuration are preserved,
and complete archives precede removal of the owned scratch directory. A local
closure-directory error is corrected without repeating the measurement. Evidence
remains in `work/receiver-handoff-pressure/arm-2`. This does not measure paid
forwarding during cleanup or physical flash behavior. The native and ARM builds
use different optimization profiles, so they do not establish a speed ratio.

A subsequent measured candidate removes the reserved receiver's preliminary
collection before each release batch. Admission already promises every queue
slot, and release performs its own bounded collection with fresh ownership checks
under the wallet lock. Unreserved release and ordinary archive upkeep remain.
Matched release-profile observations retain the same workload, dependencies,
original owners, capacity and reopen assertions:

| Target | Whole handoff wall time, before → after | Process CPU, before → after |
| --- | --- | --- |
| Linux, shared host | 1.917 → 1.099 s | 1.91 → 1.10 CPU-s |
| ARM64 router | 31.407 → 18.258 s | 30.68 → 17.82 CPU-s |

Each target has one observation per variant; this is a measured CPU reduction,
not a latency distribution. The candidate router fixture peaks at 36.13 MiB;
all ten management checks complete within 196 ms. Original services, boot and
network settings remain intact, and archived temporary files are removed.
Source bindings, raw observations and independent acceptance remain in
`work/reserved-receiver-handoff/native-pair-1` and
`work/reserved-receiver-handoff/arm-candidate-1`. The synthetic operation owners
are not valid funding or recovery records for a live wallet. Paid forwarding and
payment progress throughout a financially valid full-history cleanup still need
device acceptance; these measurements do not close that gap.

r619 strengthens the existing SDK receiver-retirement regression in `c079bde`;
production code and dependencies are unchanged. A receiver-store refusal leaves
the wallet's original reservation and admission journal intact. The admitted
channel then updates, closes and imports its 3-sat payout after wallet reopen at
the unchanged full native limit, with the sender recovering 29 sats. Retirement
releases receiver capacity but retains earned coins and their history: a new
paired admission still lacks native space and is safely refused. A separate
receiver-only, zero-paid admission checks reuse of the retired receiver space.
All 444 workspace tests, strict affected-package lint and formatting pass; three
existing opt-in measurements are skipped. This checks logical admission and
completion, not device performance or physical disk exhaustion. Private evidence
is retained in `work/receiver-resource-r619/attempt-4`.

The same parameterized capacity test covers 129 one-sat proofs across the
128-proof retirement boundary and the maximum 1,024-proof payout. The maximum
case exposed missing completion space: retirement stalled during its fourth
batch after 384 proofs were queued. SDK `ef294e5` reserves the existing 4 MiB
proof-history journal allowance once per wallet before accepting receiver
funding. That shared allowance remains charged for later retirements; a budget
too small for it rejects new funding. The native maximum is not enlarged.
All payout cases now preserve exact coins, earned balance and original funds
through full-capacity reopen, duplicate import and repeated retirement.

The SDK workspace gate covers all 55 targets: 444 tests pass, three existing
opt-in measurements are ignored and no unignored tests are filtered. After a
test-only pressure-fixture correction, nine unchanged completed targets were
reused and the edited target plus all remaining targets were run. Documentation
targets, strict all-target lint, formatting and size checks pass. Failed runs
remain retained in `work/receiver-payout-limit`; the earlier 129-proof evidence
remains in `work/receiver-payout-129`.

Ordinary Linux and ARM64 relay builds with SDK `ef294e5` pass. The mixed-role
16 MiB fixture refused an outgoing reclaim reservation after charging 12,689,211
bytes: its remaining space was smaller than the next 4 MiB keyset allowance.
The shared test setup now allows 20 MiB for both roles, while pressure stages
still fill every unreserved byte. Four ordinary-daemon checks pass: restart at
full capacity, paid-fee settlement, three expiry/retirement cycles and paying
newcomer admission. The separate fault-hook renewal/refund/restart case also
passes, with strict affected-target lint, formatting, size checks and 11 Python
harness tests. Relay production code and spending limits are unchanged. Source
bindings and original failures remain in `work/receiver-history-relay`.

r628 runs the same four payout cases in one fresh ARM64 router process, with a
test-only change retaining its original files. The whole test takes 95.49 seconds
wall time and 93.74 seconds CPU time, with maximum RSS of 52,772 KiB. This includes
the in-process simulated mint/proxy and all setup, import and retirement work;
it does not isolate the 1,024-proof case. No memory-limit or OOM events occur
under the 192 MiB guard. All 20 management checks pass and normal baselines stay
unchanged. Independent checks of the four original fixtures account for all
2,688 test sats and preserve the 1,024 distinct earned coins. One sender
`token_created` record remains: its three exact, operation-owned originals are
already spent at the original mint, with no unspent external proof obligation.
Receiver wallets have no unfinished operations. This qualifies receiver payout
resource use, not sender retirement, concurrent forwarding or physical flash
recovery. The initial audit's zero-saga assumption and the corrected audit remain
with the original archives in `work/receiver-payout-arm64`. The stopped test
files are removed, recovering 42.1 MiB; original router accounts and normal
network baselines remain unchanged.

r608 verifies the configured-mint open/balance paths against the qualified source
inventory: at most 32 mint/unit wallets, 256 retained keysets per cache and 4 MiB
metadata projections before SQL decoding. Receiver refresh uses one configured
mint, at most 64 active keysets and a shared 1 MiB response/snapshot budget, with
the relay's 10-second outer deadline and one-second retry cache. Balance uses an
indexed SQL sum without decoding the proof inventory; its work still grows with
unspent rows. Current saved profiles require native capacity; its logical bound
does not reserve filesystem space. This closes source coverage for these paths,
not device reopen latency or peak memory at their limits. Existing tests were
inspected, not rerun. The current-graph reconciliation in
`work/catalog-bounds-r608/current-graph.json` verifies all 34 source bindings
against build 14: 24 are unchanged and ten changed files have been reviewed at
their catalog/open/balance boundaries. This includes the actual qualified
Spilman source, whose shared bounded body reader preserves the metadata limits.
No new catalog invariant gap was found. The original audit remains separate;
this review adds no device-performance result or full export/custody acceptance.
Settlement reply bounds are a separate path with their own qualification.

r612 finds no violation of the reviewed local export size/custody contracts.
Ownership scans and incomplete-operation recovery traverse retained history, so
page limits do not bound whole-command work. Required native capacity bounds
charged logical history. These are exclusive local wallet commands, not anonymous
forwarding requests. The 36 source bindings and
existing tests inspected, without rerunning them, remain in
`work/export-bounds-r612`.

r614 exercises the existing opt-in export fixture on the current runtime/SDK
graph. It retains 128 real exports, refuses a further request without changing
the cache or spending state, acknowledges the full prefix, then exports the
remaining balance. The whole offline reopen/acknowledgement takes 1.328 seconds
for 65,664 cached bytes under a 16 MiB logical wallet allowance. Default mint
request pacing remains in place; sequential setup and final checks make the test
body take 1,564 seconds. This single Linux observation is not a hard deadline,
router result, maximum-size token case or full wallet/journal/archive saturation.

Formatting, source-size, focused build and strict lint gates pass. Independent
auditing of five complete SQLite sets reconciles the single 256-sat grant into
the collector, with zero unaccounted value or duplicate live proofs. The relay's
lifetime totals record 131 requests and 256 sats debited through closed number 132,
with no pending export or retirement work. It retires 188 coins and preserves
21 spent coins owned by the original incoming receipt. The issuer's completed
grant still retains 21 native `PENDING_SPENT` rows, all confirmed spent at the
original mint; these carry no outstanding value. This fixture explicitly runs
online startup recovery and 64 collection passes before the final audit; its
native-history result is not a promise made by offline acknowledgement alone.
Original fixtures, recovery records, source/build bindings and the audit remain
in `work/export-pressure-r614`.
The [test-bench instructions](TESTBENCH.md#verification) give the reproducible
command and retention rules. Production forwarding code is unchanged.

r616 exercises the ordinary wallet commands on one ARM64 router with the same
runtime graph and a recoverable test mint. Its 128-file cache holds 67,200 bytes;
the next export is refused without changing the cached tokens or request prefix.
Whole local acknowledgement takes 29.75 seconds, including reopen, validation
and cleanup. Balance takes 0.12 seconds and full-cache refusal 0.28 seconds, at
10 ms clock resolution. Paced setup takes 1,924 seconds; the complete run takes
2,008 seconds. These are single wall-time observations, not CPU/RSS, saturated
throughput, maximum-size tokens, full filesystem or physical power-loss results.

Independent auditing of 11 complete SQLite sets accounts for all 256 test sats
in the original collector. The empty export cache/request journal retains
lifetime totals of 129 requests and 256 sats debited through closed number 130.
Acknowledgement retires 127 earlier outgoing records; the next export's normal
online reconciliation releases the previous last send. The final send remains
locally pending with three mint-spent coins and one acknowledged custody page,
all matched to its completed collector receipt. There is no unresolved value,
but native storage is not empty. Charged logical storage falls from 1,153,482 to
204,763 bytes within the unchanged 16 MiB allowance. The original failed audit
assumed zero native owners; its preserved amendment checks their exact ownership
and progress instead. Original archives, recovery records and the amended audit
remain in `work/router-export-pressure-r616`. All recorded test processes stop
and normal router baselines remain intact; device scratch cleanup is separate.

See [history](HISTORY.md)
and the matching SDK's `docs/wallet-history.md` for exact ownership/limit contracts
and the reproducible pressure command. Private evidence in the named resource
bundles binds sources, measurements and gates; failed profiles retain their
original rejected results.

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
| Cheap quote with dropped payloads or misleading quality | [Source selection](PRICE-SELECTION.md) uses native end-to-end feedback, capped trials, price/loss/RTT limits and provider cooldowns; local quote/payment success cannot qualify delivery. | Quality is an estimate, not a financial receipt or proof against a dishonest endpoint. Trial traffic may be paid and lost; lifetime and capital limits still apply. |
| Peer discovery or quote spam | Shared admission/rate/connection/record budgets and bounded quote cache; failed authentication releases unowned carriers. | Arbitrary Sybil fairness and RF anti-jamming are not established. |
| Free-control bypass | Strict bootstrap shapes/limits, explicit free destinations and earned return allowance; quote payloads remain ordinarily accounted. | Configuration may deliberately authorize free service. |
| Unexpected onward spending | Separate price, capital, lifetime and provider policies; customer/peer input never grants wallet authority. | Accepted mint solvency/correctness remains trusted. |
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
