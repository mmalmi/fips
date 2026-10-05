# Paid-relay v1 readiness work

This extends the completed bounded prototype. Production readiness is not yet
claimed. The target is sender-funded FIPS forwarding across supported transports,
with permissionless discovery and bounded financial/resource risk. Publication,
real-money operation and public deployment are separate authorization decisions.

Acceptance targets fresh wallet/controller profiles. Migrating legacy profiles
is outside this greenfield scope; historical migration notes below do not add a
requirement to the current milestone. Existing accounts remain untouched.

## Scope and outstanding acceptance

Each linked result applies to its recorded revision and workload. Earlier router
and phone demonstrations do not accept the latest software for deployment.

Mint access must also work through FIPS, independently of a management-LAN HTTP
route. Acceptance must start with an empty client wallet, exercise funding and
settlement across intermediate relays, and cover interruption/recovery with no
direct-network fallback or duplicate financial operation. Bootstrap access is an
explicit bounded operator policy, including the response direction; it must not
require the credit it is needed to obtain. A stable mint identity and URL must
survive path changes. Ordinary TCP/FIPS and existing forwarding limits should
carry these requests without a new payment-message family.

The relay's payment boundary is the Cashu mint API. Acceptance exercises real
mint proof storage, channel funding, settlement, refunds and recovery from lost
replies or mint restarts. A compatible mint's backing and Lightning operation
remain the mint operator's responsibility. A persistent Lightning regtest is an
optional integration check for operating a mint, not a relay-v1 release gate.

Current device evidence covers steady mesh funding, paid delivery, settlement,
an earlier symmetric edge handover, and persistent one-way return-loss handover
on `a3adbfca3`. The latter follows a reduced routing regression and passes in
`work/mesh-mint-radio-r7`, collecting all 16 test sats over the replacement path
without another settlement swap. The earlier failed run and separate recovery
remain preserved. This accepts the recorded bounded topology changes, not
arbitrary mobile bootstrap or production readiness.

Physical Android mint access also passes on `381eb0bce`: empty-wallet funding,
paid delivery, settlement while the activity is hidden, and stopped-wallet fund
return all use the mesh-only mint. A second case also recovers the original
settlement across controlled radio return-path loss, with no second mint swap.
Each collects all 16 test sats. A subsequent forced-idle characterization on
`a49e01ae2` also closes financially, but Android permits foreground-service
networking throughout it. Natural movement and recovery from Android suspending
network access remain unverified.

Mint-process restart recovery also passes on the existing ARM64 mint host with
persistent ext4 storage, using `71d6eba90`. Funding and settlement each cross a
forced process crash, preserve the original database/keyset and collect all 16
test sats. This case uses local FIPS nodes over loopback UDP; combining mint
crashes with physical radio faults and sudden power loss remains unverified.

The first native mint-over-FIPS check passes on `0388b2c12`: a fresh empty wallet
funds 16 test sats through client → relay → mint TCP/FIPS streams, transfers them,
and collects all 16 in the isolated collection wallet. Only the client adapter's
URL reaches wallet code. Both directions use explicit zero-price destination
offers under the middle relay's shared bandwidth limits; no paid channel opens
and its buyer/seller journals remain unchanged. A request with write-half closure
also returns the complete mint response. The initial candidate reached the mint
but refused a later wallet connection while prior TCP entries were closing;
bounded pre-request queuing fixes that case without replaying HTTP requests.
Strict affected-target lint, a normal build without test features, and the source
size check pass. Evidence is under `work/mesh-mint-r1` (failure) and
`work/mesh-mint-r2` (pass) in the private recovery bundle. This verifies the
[test-library adapter](TESTBENCH.md#mint-http-over-fips), not device configuration,
permissionless bootstrap policy, interrupted financial recovery or Spilman
settlement over mesh. Those remain required before accepting mesh-only mint access.

The extended native case on `8881ace09` also passes after holding its original
HTTP request across 600 ms of denied forwarding at the intermediate relay. The
mint listener stays live; no response arrives during that outage, then the same
request returns a complete parsed mint-info document. The actual `CustomerClient`
refuses import while running, imports after stopping, survives start/stop and
reopen with the same identity and profile, and retains the original export for a
repeated operation ID. Both source and phone wallets end empty and the collector
holds all 16 test sats. Its mint adapter belongs to the independent network
fixture; this proves that lifecycle arrangement, not Android wiring. The focused
case, lint and normal build pass, with evidence in `work/mesh-mint-r3`.

On `dd8256871`, the same native case additionally opens an eight-sat Spilman
channel from the funded customer to its entry relay, then cooperatively settles
it through the mesh mint. The saved buyer settlement is released and refunded;
all eight locked sats return, and the existing export/reopen checks collect the
original 16 sats. This is a zero-use channel: it verifies funding and refund HTTP
over FIPS, without claiming paid-payload settlement or interruption during a
financial request. The focused case passes in 16.61 seconds; evidence is in
`work/mesh-mint-r4`. Device integration and permissionless bootstrap policy remain
outstanding.

The runtime-integrated case on `240b437ea` passes in 44.88 seconds. The customer
now owns its pinned mint adapter while running and temporarily starts the same
native identity for stopped-wallet import/export. It rejects an occupied adapter
listener, preserves the active-wallet guard, and retains its identity, terms and
original export across reopen. A paid payload arrives and automatic payment
credits the provider; cooperative settlement redeems those earnings and refunds
the unused channel capacity. The collector recovers all 16 originally issued test
sats, leaving the source, customer and provider wallets empty. Provider collection
uses the remaining native fixture endpoint after the provider stops; no wallet
receives a direct mint-backend URL. Explicit known-client return pricing and a
free-route watch remain part of this test's bootstrap policy.

This extension caught abandoned TCP streams across repeated wallet shutdowns.
The adapter now resets retained connections before endpoint shutdown; failed
startup also waits for endpoint cleanup before releasing ownership. The earlier
zero-use lifecycle then passed on `0d81caed6`, followed by the paid case above.
All 32 related target/profile/wallet/service checks, strict library lint, the
normal library build and the source-size gate pass. Logs and independent process
and cache-lock closure are retained under `work/mesh-mint-r8`; the earlier failure
and repair remain in `work/mesh-mint-r5` through `r7`. This is native Linux
acceptance, not Android/OpenWrt deployment, permissionless return bootstrap or
interruption during a financial mint request.

On `655344ade`, the native case uses the normal relay's `mint_export`
configuration instead of separately constructing the mint-side bridge. The paid
lifecycle and complete 16-sat collection pass again in 44.79 seconds, together
with 33 related checks, strict library lint, a normal library/daemon build and
the source-size gate. The same frozen source also builds as a static ARM64 Linux
executable. Verified logs, hashes and independent process/cache closure are in
`work/mesh-mint-r9` and `work/mesh-mint-arm-r1`. The existing test-mint executable
can now remain loopback-only while an ordinary relay exports that listener;
[server configuration](TESTBENCH.md#mint-host-configuration) documents the setup.
This build check does not remove explicit return bootstrap; the device result
below has its own limited scope.

The same ARM64 executable also passes a fresh physical mint-access check on two
Cudy routers and a Linux mint host: client router → forwarding router → mint,
over authenticated FIPS UDP links on the existing LAN. The mint HTTP listener
binds only to its host's loopback address; the client wallet uses its own pinned
loopback adapter. After stopping the empty client service, ordinary offline wallet
commands import eight test sats and export them again through both FIPS hops.
All eight are collected, the client wallet ends empty, and the forwarding
router's buyer/seller/controller journals remain unchanged. Its bounded free
route counters record actual transit; no paid channel opens for bootstrap.

The test uses one explicit zero-ceiling return watch for the known client. All
58 management checks pass. Independent postflight checks confirm both original
router baselines restored, temporary router executables removed, and the owned
mint and export-relay processes exited cleanly. The run completes in 69.105
seconds including cleanup; this is not a throughput benchmark. Evidence and
closure are retained under `work/mesh-mint-physical-r1`. The carrier is UDP on the
existing LAN: this does not accept radio-mesh discovery, Android wiring, paid
payloads on this device run, or interrupted financial HTTP recovery. Existing
saved accounts and the earlier retained phone test mint are unchanged.

A second two-router wallet check on `d532a4e0b` removes every known-client
return tariff and the mint's return watch. Only the mint destination has a free
offer; relays reuse the existing `return_allowance` without changing its credit,
rate or state limits. Eight test sats again traverse both FIPS hops for offline
import/export and are collected in full. Return-admission counters confirm use
of earned reply credit, and monetary relay journals stay unchanged. All 94
management checks and independent router/process cleanup checks pass. Evidence
is in `work/mesh-mint-physical-r2`, with its exact static ARM64 build in
`work/mesh-mint-arm-r2`. This accepts wallet bootstrap on the configured UDP
links; it does not establish paid settlement, radio discovery, arbitrary
asymmetry or mobile handover for this revision.

The full native lifecycle on `fc3249e17` passes in 31.42 seconds without
client-specific return tariffs or mint-side watches. An authenticated adjacent
customer starts empty, imports through its own adapter, funds an eight-sat
channel, sends a delivered paid payload, settles provider earnings and its
refund, and collects all 16 original test sats. Both adapter sides and the
ordinary test-mint upstream proxy participate. The existing metadata request
deadline remains ten seconds. The case explicitly configures reply budgets of
8,192 units/s per returning neighbor and 32,768 units/s in aggregate; default
reply rates, exact-path credit, state bounds and paid-route precedence remain
unchanged. Default-rate wallet bootstrap passed above, but full settlement at
that rate was unreliable because mint metadata exceeded its deadline.

This work also found a fixed connection lifetime cutting off active refund
requests. The adapters now expire inactive streams, while preserving bounded
slots and buffers, explicit shutdown and the rule against HTTP request replay.
The test-mint proxy shares the same idle-lifetime behavior; its focused check
covers half-closed requests, continuing responses and idle expiry. All 66 related
checks, strict library Clippy, normal library/daemon checks and the source-size
gate pass. Verified logs and independent native process/cache closure are in
`work/mesh-mint-r18`; failed investigations are retained in `r10` through `r17`.
This does not accept interrupted financial HTTP recovery, arbitrary asymmetric
return paths, mobile handover or hostile-contention fairness.

The same revision passes a paid hardware case on all three Cudys and the Linux
mint host. The empty client imports 16 test sats over two FIPS hops, funds one
eight-sat channel to the middle router, and delivers a paid payload to the third
router. Settlement pays the provider one sat and refunds seven to the client;
the client and provider then export their balances through FIPS and all 16 sats
are collected. There are no client-specific free return entries or mint-side
watches. The configured reply limits match the native case above.

All 132 management checks pass. Independent postflight checks confirm original
router baselines restored, candidate executables removed, matching released
buyer/provider settlement records, and clean exits of the owned mint and export
relay. Evidence is in `work/mesh-mint-physical-r3`, with exact static ARM64 relay
and test-mint builds in `work/mesh-mint-arm-r5` and `work/mesh-mint-test-arm-r3`.
The run takes 106.462 seconds including setup and cleanup, not a throughput
benchmark. It uses FIPS/UDP over the existing LAN; radio-mesh, Android and
interrupted financial mint requests remain separate acceptance work. Existing
saved accounts and the earlier retained phone test mint remain unchanged.

The same executables also pass the full mint lifecycle over the actual radio
mesh. Three Cudys temporarily join an open 802.11s network and discover their
authenticated FIPS neighbors without a router peer roster. The empty client's
only carrier is its mesh interface. Test-only EtherType filters require two
radio hops to the far router, which alone has the UDP link to the mint host;
native transport observations and shortcut-drop counters verify this topology.
The mint HTTP backend remains loopback-only. Import, one eight-sat channel, paid
delivery, provider redemption, refund and both wallet exports all succeed with
the same bounded bootstrap policy. The provider receives one sat, seven channel
sats are refunded, and all 16 originally issued sats are collected.

All 279 management checks pass, and independent postflight verifies restored
original radio profiles, network settings, accounts and services, matching
settlement records, removed candidate executables and clean mint/export-relay
exits. Evidence is in `work/mesh-mint-radio-r1`. Cleanup needed an ordering
correction: both remaining owned radio guards were invoked before the runner
could verify the first router's original peers. This assistance is recorded in
the closure; the financial run required no retry. This accepts radio transport
for the mint lifecycle, not interruption during a financial request, mobile
handover or Android mint integration. The earlier phone mint remains unchanged.

The native case on `c006e168d` recovers lost committed replies during both
channel funding and settlement. It reuses the SDK's response barrier, matching
the saved opening request or the original channel's funding proofs. Funding
recovery restarts the mint's FIPS gateway after the real swap succeeds but before
its outputs arrive. Settlement instead removes the transit relay while keeping
the gateway alive. A different relay, with its own identity and empty wallet,
then supplies the replacement path; the failed relay stays offline. The original
Buy/Finish calls fail while their only path is absent. The HTTP mint stays alive
throughout, with the same pinned FIPS identity and wallet URL.

Journal and status reads observe normal background workers recovering and
activating the original funding, then later completing its provider payout,
buyer refund and channel release. No repeated Buy/Finish/Settle call drives
recovery. All swap submissions are rejected during each recovery window, and
their counter proves none was attempted. The original wallet operation, funding
authority, lifetime spending policy, eight-sat debit and single channel remain
unchanged. Paid delivery succeeds between the two interruptions, and the full
lifecycle collects all 16 original test sats. Both ends connect to the alternate
relay, whose counters record forwarded requests and earned reply traffic. No
client-specific return tariff, mint-side watch or new channel is needed there.

The case passes in 115.32 seconds, along with strict library lint, formatting
and the source-size gate. Verified logs and independent process/cache closure
are in `work/mesh-mint-r24`. Earlier same-gateway recovery checks remain in
`r20` through `r22`. This extends the existing lifecycle test; production code
and the accepted router executable are unchanged. It verifies a configured
native UDP path replacement, without accepting physical mobile handover,
arbitrary asymmetric bootstrap, mint-process restart or Android integration.

The test mint on `11dbda7d2` exposes the same SDK response barrier through its
private control socket for hardware tests. The existing real-mint bench test
verifies that an import waits for release, duplicate arms and incorrect releases
fail, and issuance/collection cannot interfere while the barrier is active.
That check and the normal library/daemon build without test features pass in
`work/mesh-mint-r22`; the static ARM64 test-mint build and closure are in
`work/mesh-mint-test-arm-r4`. No production payment protocol or fault control
is added.

The same production router executable and the new test mint also pass a
settlement interruption on the three-router open radio mesh. After the original
channel-close swap commits, the private barrier holds its response. Taking the
far router's mesh interface down removes its radio stations; releasing the
response then leaves both settlement records incomplete for a measured 2.95
seconds. Restoring the original radio path lets the original settlement call
finish, without another administrative request or mint swap attempt. The same
funding authority, spending policy and channel remain in force. Provider payout
and buyer refund agree, and all 16 original test sats are collected.

The 168.971-second run, including setup and cleanup, passes all 216 management
checks. Independent postflight confirms restored original router profiles and
services, removed candidate executables, matching released settlement records,
and clean mint/export-relay exits. Cleanup restores every radio before checking
their original peers and needs no manual assistance. Evidence is in
`work/mesh-mint-radio-r2`. This accepts a temporary departure and return on the
same radio path during committed settlement; it does not establish alternate-path
handover, mint-process restart, physical power-loss recovery or Android mint
integration. Existing saved accounts and the retained earlier phone mint are
unchanged.

An initial hardware path-change case does **not** pass. After the close swap
commits, test-EtherType filters cut the provider-to-mint-side radio edge in both
directions. The response stays blocked for 3.02 seconds. Opening the previously
excluded customer-to-mint-side edge produces the exact replacement topology,
with the old edge still blocked. The provider must now reach the mint through
the customer router. Settlement does not complete within its 100-second recovery
window. The provider reports a failed mint restore request; a diagnostic snapshot
shows no admitted free forwarding traffic or incoming free lease on the new
transit router. This exposes a gap beyond the
native case above, which replaces an entire transit relay and shares one local
mint-client adapter between wallets.

The failed run preserves its original accounting and passes all 396 management
checks, with no cleanup errors. Recovery reopens the same saved router and
gateway accounts on the original radio path, keeping the original mint process
and URL. Background workers finish the original settlement without another
Settle request or mint swap; funding authority remains unchanged and all 16 test
sats are collected. Independent postflight confirms matching released buyer and
seller records, restored original device state, and clean exits of the mint and
both gateway processes. Recovery passes all 117 management checks. Evidence is
in `work/mesh-mint-radio-r3`, including its failed result and separate recovery
closure. That original path-change result remains failed.

The follow-up four-node `SimNetwork` case keeps every router alive and gives
the provider its own configured mint adapter. It exposes a stale free-quote
cache entry: a request on behalf of a customer can replace the provider's own
outgoing grant, while a different loop-context cache entry still returns the
superseded identity. `e845962d1` shares the live grant book with the cache and
refetches these obsolete offers. It does not revive retired allowances, change
paid authority, add protocol messages or poll idle routes. The new cache check,
36 quote/cache tests and 24 free-route tests pass. The actual settlement handover
passes in 79.319 seconds, conserving all 16 simulated sats in the wallets and
retaining the original funding authority without another mint swap. Evidence is
in `work/mesh-mint-r28` and `work/mesh-mint-r29`.

The extended handover fixture on `793248a25` also passes with persistent packet
loss in either direction of the former provider-to-mint-side edge. The link
remains enabled, but simulated discovery advertisements are also suppressed in
the fully lossy direction; neither failed direction is repaired.
Both cases and the original full-disconnection case observe the replacement
topology, recover the original settlement through ordinary workers without
another swap or wallet spend, and confirm actual mint transit through the former
customer. Each then redeems all 16 original test sats into a collection wallet,
leaving buyer and provider wallets empty. All three pass in 337.913 seconds;
strict library Clippy and the source-size check pass. Logs, source hashes and
independent process/cache closure are verified in `work/mesh-mint-r34`. This
accepts those controlled transport failures; physical radio asymmetry,
interference and moving-router handover remain separate acceptance work.

The existing funding-and-alternate-relay settlement regression passes on
`19feea4a3` in 121.158 seconds and collects all 16 simulated sats. Strict library
Clippy and the source-size check pass. Three consecutive fresh runs of that
exact diagnostic executable then pass in 117.136, 128.437 and 115.866 seconds,
each collecting all 16 simulated sats. Their logs, source hashes and independent
process/cache closure are verified in `work/mesh-mint-r31`; no rebuild or lint
rerun was needed. An earlier attempt reached the 30-second pre-fault
funding-commit deadline; its failed result is retained in `work/mesh-mint-r29`.
Stage diagnostics were added without changing that deadline. The later passes
in `work/mesh-mint-r30` and `r31` do not establish the cause of that timeout or
prove it fixed.

On `53a005847`, that same lifecycle also kills the real CDK mint subprocess with
SIGKILL after both the funding swap and the settlement swap commit. Each restart
reopens the original SQLite database and keyset behind the same URL. Ordinary
workers recover the saved operations through FIPS without another swap or wallet
spend, and all 16 originally issued sats are collected. The test passes in
120.778 seconds; strict library Clippy and the source-size gate pass. Verified
logs, source hashes and independent process/cache closure are retained in
`work/mesh-mint-r32`. This replaces the earlier lifecycle fixture rather than
adding a duplicate scenario. The closed-loop subprocess refuses new funding
after restart; this accepts Cashu proof-state recovery, not persistence of its
in-memory simulated Lightning network or a production Lightning backend. The
hardware test mint still requires a fresh state directory per process.

The same `19feea4a3` ARM64 runtime then passes the physical edge-handover case
in `work/mesh-mint-radio-r4`. The original financial reply stays blocked for
2.96 seconds with the path absent. After the customer-to-mint-side radio edge
opens, the old provider edge remains blocked. The original administrative
request times out, but ordinary workers finish the saved settlement about
102 seconds after the replacement topology is observed. Mint swaps and attempts
stay at three after the held close; restores increase from two to 38. The
provider receives one sat, seven sats are refunded, funding authority is
unchanged, and all 16 sats are collected by 207.52 seconds. All 303 management
checks pass. Independent postflight confirms restored original router settings
and services, removed candidate executables, matching released settlement
records and clean mint/export-relay exits, without cleanup assistance.

The same runtime fails the subsequent persistent return-loss case in
`work/mesh-mint-radio-r5`. Only mint-side-to-provider test-EtherType frames are
dropped; the opposite direction remains unfiltered, and the alternative edge
opens. Empty-wallet funding and paid delivery succeed, and the replacement
peer topology appears at 119.63 seconds. However, the committed settlement does
not recover within the bounded observation window. Provider logs record quote
timeouts and unsuccessful mint streams; replacement transit records six free
packets and no admitted return packets. These observations do not establish the
root cause. All 438 management checks pass and automatic device cleanup succeeds.

The original mint and accounts are retained for recovery. After restoring the
original radio path, ordinary workers release the original channel and refund
seven sats; the provider receives one sat. Mint swaps and attempts stay at three,
and all 16 original sats are collected. Recovery passes 108 management checks;
independent postflight verifies unchanged funding authority, matching released
settlement records, restored device state and clean exits of the mint and both
export-relay processes. The failed result and separate recovery closure are
preserved. Its complete frozen harness/archive (146 files) also matches the
recorded hashes. Recovery does not turn the failed handover into a pass.

The instrumented follow-up in `work/mesh-mint-radio-r6` uses the same runtime,
financial limits and deadlines. It records routing-tree, session and forwarding
state without issuing a probe, quote or financial request. This run passes:
the replacement neighbor topology appears at 125.19 seconds, the saved
settlement completes at 200.03 seconds, and all 16 sats are collected by
249.58 seconds. The old return direction remains blocked. Mint swaps and
attempts remain at three; restores increase from two to 38. All 396 management
checks and independent postflight pass, including restored original settings,
removed candidate executables and clean mint/export-relay exits. All 146 frozen
harness files and the archive match their recorded hashes.

The observations show temporarily different routing roots after the link loss,
then a common tree before financial recovery. Node identities are freshly
generated, so this run has a different routing-tree root from the failed case.
Neither that difference nor the passing result establishes the cause of the
earlier failure. The handover simulation now uses fixed routing identities and
verifies the customer-root baseline; its ordinary initialization path still
generates a fresh identity. The return-loss case on `b124da7f9` passes in
79.323 seconds and collects all 16 sats, with strict library Clippy and the
source-size check passing. Verified source/log/process evidence is in
`work/mesh-mint-r35`. This makes the routing arrangement reproducible; it does
not establish a fix for the failed device run. The same executable then fails
the full-disconnection case in `work/mesh-mint-r36` after 138.909 seconds.
Its final snapshots show a converged routing tree but stalled mint quotes and
no free-data transit through the former customer. The remaining cases in that
run are not executed after the failure. Logs, source hashes and process/cache
closure are verified; this preserves the native failure for comparison below.

The reduced core regression in `work/mesh-mint-r37` exposes a routing dead end:
an unrelated live neighbor counts as a discovery alternative and suppresses a
session-degraded direct route, even when it cannot route to the destination.
On `a3adbfca3`, actual usable alternatives still take priority, but the direct
carrier remains a last resort when it is healthy and has no evidence of
unanswered payload on that carrier. Stale links and paths with unanswered data
retain their recovery restrictions; degradation state is not cleared by this
fallback. The link-dead retry fixture now marks its peer stale as the production
handler does. Existing fallback, loss, retry and replacement checks remain green.

The same fixed-identity handover fixture now passes all three cases: disconnected
edge, forward-only loss and return-only loss. Normal workers settle the original
channels without another swap, and all 48 test sats are collected. The combined
run takes 287.441 seconds. Its 26 service checks and strict library Clippy also
pass. Core verification covers 109 checks plus strict library Clippy; source-size
and affected-file formatting checks pass. Independent source/log/process closure
is retained in `work/mesh-mint-r40`, `work/mesh-mint-core-extra-r1` and
`work/mesh-mint-r41`. The same source builds as the standalone static ARM64
runtime in `work/mesh-mint-arm-r8`. The subsequent source formatting changes only
whitespace.

The ARM64 runtime then passes the matched three-router return-loss case in
`work/mesh-mint-radio-r7`. This uses the failed run's original log level without
the periodic diagnostic observer. Empty-wallet funding, paid delivery and the
committed-reply interruption all use the mesh-only mint. The replacement topology
appears at 122.265 seconds; ordinary workers complete settlement at 162.128
seconds while the old return direction remains blocked. The provider receives
one sat and the customer receives the seven-sat refund. Swaps and attempts stay
at three; restore requests increase from two to 39. All 16 original sats are
collected by 243.279 seconds, and cleanup finishes at 273.435 seconds.

All 360 management checks and independent postflight pass: original router
settings are restored, candidate executables are removed, and the mint and its
export relay exit cleanly. The complete 146-file frozen harness and archive also
match their hashes. This is controlled FIPS-frame loss over real Wi-Fi links,
not natural RF interference or physical movement.

The Android build from `381eb0bce` passes native compilation, Android-target
Clippy, all six JVM lifecycle tests, Android lint and APK signature/manifest
checks. The packaged native library exactly matches the stripped library from
that build. Verified source, artifacts and build closure are retained in
`work/android-current-r17`. The second named package in `work/android-current-r18`
reuses that exact native library and source, with fresh assembly, lint, signature
and manifest checks. Both pass empty startup before funding.

Both physical cases use that Android runtime and the accepted ARM64 router
runtime above. The initial path is phone → entry router over UDP, two discovered
open radio hops, then UDP to the mint gateway. Its HTTP listener remains
loopback-only. Bounded free requests and earned replies fund the empty wallet
with 16 test sats. The phone opens an eight-sat channel and delivers a fresh
1,000-byte payload; the entry records provider credit. Settlement with the app
hidden pays the provider two sats and refunds six. Stopped-wallet export returns
the phone's remaining 14 sats; the provider exports two. Each collects all 16.
Times below are elapsed from run start and include setup and UI actions.

| Physical Android case | Settlement verified | All funds collected | Cleanup complete | Management checks |
| --- | ---: | ---: | ---: | ---: |
| Steady path, `work/mesh-mint-phone-r1` | 268.817 s | 326.325 s | 443.523 s | 465 passed |
| Return-loss handover, `work/mesh-mint-phone-r2` | 274.576 s | 348.413 s | 383.780 s | 495 passed |

In the second case, the mint close commits before its reply is held. Blocking
only the old edge's return direction leaves settlement pending; opening another
radio edge restores a working path while the original direction stays blocked.
The initial administrative call does not confirm completion. Ordinary background
workers recover the saved operation without another settlement request, swap or
increase in funding authority. Swaps and attempts stay at three after commitment;
restore requests increase from two to 37. The phone's process remains alive and
its activity hidden throughout recovery.

Independent postflight passes for both cases: topology and filters are verified,
unfunded routers' financial journals are unchanged, original phone accounts and
normal Wi-Fi are preserved, router settings are restored, and owned mint/export
processes exit cleanly. Completed phone test installations are subsequently
removed with verified recovery archives. These are controlled FIPS-frame tests;
they do not establish natural RF movement, deep idle, process restart or customer
Internet isolation.

The subsequent `work/mesh-mint-phone-r3` characterizes forced deep idle on the
physical Android 17/API 37 phone. Fresh Android and static ARM64 builds use
`a49e01ae2`; Android-target Clippy, six JVM lifecycle checks, Android lint and
packaged-library/signature checks pass. Sources and artifacts are retained in
`work/android-current-r19` and `work/mesh-mint-arm-r9`.

After the settlement swap commits, its held reply is released while Android is
forced into deep idle. All six observations over 43.525 seconds report `IDLE`,
but network policy permits the foreground service: its effective blocking reason
is `NONE`. The buyer has completed release and refund by the 8.696-second
observation, during idle. The original request succeeds, funding authority is
unchanged, and swap/attempt counts stay at three after commitment. Thus this
case **does not exercise recovery from Android blocking networking**; the
original interruption criteria and explicit `not_exercised` assessment remain
with the evidence. USB, charging and the screen stay active, so this is also not
natural suspend or a battery-cost measurement.

Independent financial and device closure passes: two sats reach the provider,
six return from the channel, all 16 test sats are collected, and all 459
management checks pass. Normal power state, Wi-Fi, router settings and original
accounts are restored; owned processes exit. The completed temporary app is
removed with verified account and APK recovery archives. No runtime change or
battery exemption was introduced for this characterization.

The existing mint-restart integration test also passes on the ARM64 mint host's
persistent ext4 filesystem in 165.282 seconds. The static test executable from
`71d6eba90` and its frozen dependency/source inputs are verified in
`work/mesh-mint-arm-test-r1`. It kills the actual mint worker after the funding
commit, reopens the same database and keys, then repeats that interruption after
the settlement commit. Original funding recovery completes without another wallet
spend; settlement recovers through the alternate FIPS relay without another swap.
All 16 test sats are collected. This reuses
`service::mesh_mint_tests::empty_wallet_funds_and_settles_over_mesh_without_a_direct_mint_url`
without modifying the test or its deadlines.

Independent closure in `work/mesh-mint-hardware-restart-r2` verifies stopped test
processes, removal of the temporary executable, closed isolated wallet state,
and preserved identities of the three existing host service processes. All 21
management checks pass. An earlier preflight fails before starting the test or
issuing funds because its monitor tries to read a protected system-process
executable link; checking PID/start time instead resolves that harness issue.
Its separate zero-issuance closure remains recorded.

This runs real mint/wallet code and FIPS nodes on the ARM host, with loopback UDP
links. It does not combine the crashes with physical radio links or remove power.
The standalone disposable hardware mint still requires a fresh state directory;
this test resumes only proof operations after initial issuance, not its simulated
Lightning state. Broader mobility/background behavior and financial power-loss
recovery still need their own acceptance.

The standalone `80bf5baec` ARM64 runtime passes the full matched
three-router cadence matrix: two opposite-order repetitions of the 250-ms,
500-ms, 1-s and 2-s policies, with default financial limits and persistent
overlay/UBIFS journals. All 93,696 payloads arrive; strict measurement validation
passes. All sixteen channels settle, all 3,072 test sats are collected, and all
2,142 management checks pass. Independent closure confirms restored router
state and stopped test services. See [the matched hardware results](CADENCE-RESULTS.md#matched-router-cadence-matrix--3-october-2026)
for payment CPU, journal and carrier costs and the retained evidence. The 1-s
and 2-s policies reduce measured payment overhead in the finite high-rate
workload; the 500-ms default remains unchanged pending sustained/impaired
comparisons. This does not accept a new package, physical power loss, mobile
handover, flash lifetime or production deployment.

The current r57 package contains the receiver-wallet and outgoing-wallet recovery
changes. It uses the identical accepted r56 ARM64 executable, built from private
FIPS integration `83cb4d7815db`, SDK `ff1678c2b6ca`, CDK `8de95a89c9e0` and
isolated bitreq cancellation commit `f59be760bcc5`. The complete portable source
bundle retains six clean Git inputs and vendored registry sources. Offline
all-feature metadata resolves 697 packages, including 676 registry packages;
this is dependency resolution, not all-feature compilation.

The r56 optimized static ARM64 executable was built offline after relocation
with an empty Cargo home and target directory. The r57 source bundle differs
only in packaging, tests and documentation and contains 36,133 files; Rust
sources, dependencies, lock and profile are unchanged. Fresh r57 extraction and
integrity checks pass for all eleven payload files and fifteen directory records,
including root ownership and a disabled service by default.

Using the actual extracted ARM64 daemon and CLI under QEMU, four unchanged cases
passed on r56: initialization safety; four-relay wallet fees, refunds, restart and lifetime
bounds; mixed UDP/TCP exhaustion, renewal and restart; and self-signed WebSocket
FIPS authentication, reconnect and restart. The native test harness and local
test mint are separate from the emulated executable. Two additional customer
cases pass against those packaged daemons, covering both billing modes, automatic
payment after an entry crash, immutable account terms across reopen, and
settlement/export that reconciles all 384 test sats per case. The customer client
is native Linux, not an Android/Pixel build. Recorded source inputs remained
unchanged; process groups, cgroups and target locks were verified closed.
Build and daemon evidence is retained in
`work/portable-r55/evidence/portable-r55` and
`work/portable-r55/evidence/arm-runtime-r56`, with customer evidence in
`work/customer-r56/evidence/customer-r56-r2` in the local recovery bundle.

The r57 wrapper removes the extra mint HTTP startup prerequisite and its unused
package dependency. Storage, account, clock and native-link guards remain.
Two shell regressions reproduce the old wrapper's outage block and pass on the
extracted r57 wrapper while retaining the clock control. These checks substitute
OpenWrt commands and the clock marker; actual device startup/outage recovery
remains pending. The consolidated current receipt is
`work/openwrt-offline-start/acceptance.json`. The six daemon/customer cases retain
their r56 execution provenance and apply to the identical binary in r57.

Two further existing test methods pass with the complete static ARM64
`priced_paths` executable and a local test mint under QEMU, built offline from
the unchanged r57 portable source. Their three simulated deployments cover
forward loss, forward delay, and loss with an alternative neighbor departing
and returning. Automatic selection moves to working alternatives and reuses
original channels after recovery, with the original delivery assertions,
deadlines and spending limits intact. All 36,133 source files remain unchanged;
owned processes and target locks are closed. The consolidated receipt is
`work/priced-r57/acceptance.json`. This is bounded local selection on simulated
links, not global route optimality, arbitrary churn or physical radio acceptance.

This accepts those six daemon/customer cases, two shell checks, two ARM64 price/quality
test methods and the portable offline build,
not the whole ARM suite, hardware, physical power-loss, performance or a
bit-identical rebuild. External Rust, Zig, cargo-zigbuild and APK tools remain
required. Earlier package results retain their original source and workload
scope. Those package tests did not install software on hardware, publish a
release or use real money.

The 3 October three-router regression passes on the newer standalone ARM64
runtime `6f97dfb03a41` (source `5b64cf8b184b`, measurements enabled), using
harness `09824d7aa746`. Native Wi-Fi discovery needs no configured peer roster;
unpaid transit is denied, and paid streams deliver in both directions through
the middle router. A leaf radio cut interrupts the active stream: one of 24
replies arrives, followed by no progress during isolation. Rejoin delivers all
eight fresh round trips on the same processes and channels, and automatic
payments continue. Full peer eviction is observed 95.13 seconds after the cut;
the rejoin-to-completed-probe bound is 20.68 seconds, including controller
observations and paced probing. This is recovery evidence, not fast roaming.

A second trial restores the radio after 16.96 seconds of absence, before peer
eviction. It retains the original authenticated peers, processes and channels.
All eight fresh round trips complete within 4.91 seconds of the rejoin request;
bidirectional automatic payments then advance on the original channels.

Each trial settles both channels and collects all 384 test sats. All 423 and 294
management checks pass respectively. Independent final checks confirm restored
router baselines, stopped candidate services and mints, and removed temporary
executables and filters. Closed receipts are under
`work/hardware-current-r1/{paid-current-r2,paid-current-brief-r1}/closure.json`
in the private recovery bundle. The initial failed attempt and its complete
test-fund recovery remain recorded separately. Sustained throughput, arbitrary
mobile encounters and physical power-loss acceptance remain outstanding; these
standalone tests do not replace the packaged-build evidence. Current Pixel
session acceptance is recorded below.

The same standalone ARM64 runtime subsequently passes a current 500-ms
three-router workload pilot with the default 4,000-msat durable window and
8,000-msat unpaid allowance. All 11,712 payload packets arrive across the fixed
idle/bursty/steady/high-rate sequence; both channels settle and all 384 test
sats are collected. Strict measurement validation and all 261 management checks
pass, and independent closure confirms restored baselines and stopped test
services. Candidate journals use persistent overlay/UBIFS storage, as confirmed
by the raw mount evidence and its retained storage-wording correction. See
[the pilot results](CADENCE-RESULTS.md#current-router-workload-pilot--3-october-2026)
and `work/hardware-current-r1/cadence-current-r1` in the private recovery bundle.
The two-second high-rate stream is finite workload acceptance, not a sustained
throughput, physical power-loss, flash-lifetime or matched cadence comparison.

A longer trial on that same ARM64 runtime delivers all 48,000 packets across
twelve alternating 20-second streams. A middle-relay process crash between the
third and fourth stream pairs retains both original channels and budgets.
Recovery records exactly the stopped journal's 4,000-msat unbilled exposure
per channel; fresh bidirectional probes and reconciliation complete within
24.95 seconds. All subsequent streams and automatic payments pass. Both
channels settle, all 384 test sats are collected, and all 606 management
checks pass. Independent closure confirms restoration of the normal router
setup. See [router load and recovery](CADENCE-RESULTS.md#router-load-and-process-recovery--3-october-2026).
This does not test physical power loss or offer traffic during the restart.

A follow-up on that executable passes the same load/restart workload with
deterministic frame loss in two stream pairs. Automatic payments continue while
loss is enabled, and all healthy/recovery streams deliver fully. Channels,
budgets and bounded unbilled exposure survive; all test funds are collected and
normal router state is restored. See [the injected-loss results](CADENCE-RESULTS.md#injected-frame-loss-before-and-after-restart)
for the delivery counts, exact impairment and scope limits.

The unchanged load/loss scenario also passes on `80bf5baec`: all 32,000 healthy
payloads arrive, and 15,201/16,000 arrive during the declared frame loss.
Automatic payments advance while loss is enabled before and after the middle
process restart; original channels and exact exposure bounds remain intact.
All 384 test sats are collected and all 612 management checks pass, with
independently verified device restoration. The loss filters are disabled during
restart. This adds finite impaired-load acceptance for the newer runtime.

The 4 October continuous-renewal experiment on `0ffdf4daa` does **not** pass
complete-delivery acceptance. Two simultaneous five-minute streams each submit
42,000 packets of 1,000 bytes through the paid middle router. They receive
41,783 and 41,752 packets respectively: 465 of 84,000 are missing, with no
duplicates or invalid packets. Both directions automatically replace one
channel, deliver fresh traffic and advance successor credit during the original
streams. Each authorizes 43 test sats within its unchanged 64-sat lifetime
budget; the 32-sat capacity and other exposure limits remain intact.

All four channels settle, all 384 test sats are collected, and all 654 management
checks pass. Independent closure verifies original router state restored and
test processes stopped. Source review confirms renewal settles and refunds the
predecessor before funding its successor, leaving an admission gap; this is
consistent with the loss but does not attribute every missing packet. Bounded
continuity through that transition remains outstanding. The experiment never
pauses or retries its measured payloads. Evidence is retained in
`work/hardware-current-r1/renewal-load-r1` in the private recovery bundle;
closure SHA-256 is
`c593047c72bd5858e83f7623d1dbc958e5052206e78dbdea498ad377d641dc4d`. The supporting bounded-probe changes pass nine native checks
and 83 focused harness checks; those checks do not turn this failed hardware
delivery experiment into production acceptance.

A focused source-side fix now passes 14 native checks: seven core ownership and
queue-bound checks, six buyer admission checks, and one real-controller renewal
regression. The regression offers eight distinct original datagrams after the
predecessor is sealed and its settlement reply is held. The prior runtime loses
all eight; bounded pre-seal waiting delivers each once after successor acceptance,
without changing predecessor usage, evidence, signed authority or lifetime
budgets. All 1,536 test sats are collected before the final delivery assertion.
Source holds expire after two seconds and do not replay submitted traffic or
repair incoming/in-flight renewal gaps. See [the bounds](PRICE-SELECTION.md#bounds-and-recovery).
Native evidence is retained under `renewal-wait-red-r1` and
`renewal-wait-green-r2` in the private payment-recovery bundle.

The unchanged five-minute router scenario on `92eed51fe` delivers 42,000 and
41,986 packets: 14 of 84,000 remain missing, with no duplicates or invalid
packets. This improves on the prior 465 missing payloads in this finite comparison,
but still fails complete-delivery acceptance. Both successors receive advancing
credit and fresh payload during the original streams; each source again
authorizes 43 test sats within its original 64-sat budget. The source carrier
submission deltas already contain the fourteen-packet shortfall and exactly
match receiver counts. The middle relay records no additional policy drops.
These aggregate counters point to a pre-transmission gap but do not distinguish
wait capacity, expiry or another source refusal; they do not establish its cause.

All four channels settle and all 384 test sats are collected. All 647 management
checks pass; independent closure verifies normal router state restored, isolated
filters removed and test processes stopped. Evidence is retained under
`work/hardware-current-r1/renewal-load-r2`; closure SHA-256 is
`56d23cbc9813f786681c09a52065a80490e1b13a298ac3ea6c8c6b736516f139`.
No measured payload was replayed, and neither spending limits nor stream shape
were widened to obtain the improvement. Sustained continuity remains outstanding.

A repeat with opt-in source-wait/drop diagnostics on `a05596c61` passes the same
finite scenario: all 84,000 packets arrive, with no duplicates or invalid packets
and 252/250 reordered payloads per direction. Both automatic successors receive
advancing credit and fresh payload during the streams; lifetime authorization is
43/44 test sats within the original 64-sat budgets. No source-wait or dataplane
packet drops are logged. All 384 test sats are collected and all 645 management
checks pass; independent closure verifies restoration and stopped test processes.
Evidence is under `work/hardware-current-r1/renewal-load-r3`; closure SHA-256 is
`becb8874702179e200a47810647a74b0b2822ec860828abfbf30ed46a4dedd17`.

The runtime difference adds diagnostics, and its seven source-admission checks
pass. Queue, traffic and financial limits are unchanged. This provides one
complete-delivery device result but does not reproduce or repair the previous
fourteen-packet loss. At 140 packets/s, the 256-packet next-hop cap covers about
1.83 seconds, less than the two-second age limit; capacity is a possible cause,
not an established attribution. Repeated/slow-renewal qualification remains open.

A subsequent change releases the source pause after all replacements have durable
provider acceptance and active routes, before the final renewal-completion write.
The existing three-process recovery fixture holds that last write and offers eight
original packets once. With the same fixture, the prior runtime delivers 0/8 and
the candidate delivers 8/8 without duplicates. Both recover the same replacement
after another buyer crash, preserve predecessor evidence and funding limits, and
conserve all 384 test sats across wallet balances and mint fees. Six buyer admission
checks and the earlier pre-acceptance eight-packet regression also pass. Core source
and queue bounds are unchanged; the preceding seven core checks remain applicable.

An initial candidate run failed its later one-shot delivery check after a rapid
restart, before financial conservation was verified; its stopped process fixture
and saved state remain retained. The updated fixture freezes the original delivery
report, then requires the destination's existing key epoch to finish draining before
the next crash. FIPS may drain for 45 seconds, longer than that delivery check's
20-second deadline. However, the passing comparison reports no active drain, so it
does **not** establish the cause of the earlier failure or qualify rapid successive
restarts. Native evidence is under `renewal-completion-red-r1` and
`renewal-completion-green-r1`/`r2` in the private payment-recovery bundle. This change
does not attribute the previous fourteen-packet physical loss.

The same five-minute router workload on `51f686cc5` delivers 42,000/42,000 and
41,998/42,000 packets, with no duplicates or invalid payloads and 251/253 reordered
packets. It still fails complete-delivery acceptance. Both automatic replacements
receive advancing credit and fresh traffic during the original streams; each
direction authorizes 43 test sats within its unchanged 64-sat lifetime budget.

This run identifies a concrete source limit: two capacity refusals occur with
256 packets held for the next hop, below the byte limit. They exactly account for
the source's two-packet carrier-submission shortfall, which matches the receiver
shortfall. No other source-wait or native packet-drop entries occur, and the middle
relay's policy-drop counter does not increase. At 140 packets/s the packet cap
covers about 1.83 seconds. This attributes the current two losses to bounded queue
capacity; the earlier fourteen losses remain unproven. Queue limits were not raised.

All four channels settle, all 384 test sats are collected, and all 639 management
checks pass. Independent closure verifies restored original router state, removed
test filters, stopped test processes and empty test wallets. Evidence is
under `work/hardware-current-r1/renewal-load-r4`; closure SHA-256 is
`44d691aa0161143694fb176538e32265672544ad10105e64d2ab121c93e0eabf`.

Buyer acceptance now skips journal writes for identical already-durable channels
and quotes. Funding previously saved the buyer channel, then purchase acceptance
saved it again. The existing filesystem-failure regression rejects that duplicate
write on the old implementation and passes on the candidate; after a genuine
write failure, both duplicate acceptance and signing still fail closed. All twelve
buyer integration tests, six source-admission checks and the real three-process
renewal/restart case pass. The latter delivers all eight held originals once and
conserves 384 test sats. Queue, financial and explicit checkpoint bounds are
unchanged. Opt-in monotonic phase logs measure the renewal pause; native evidence
is in `renewal-journal-red-r1` and `renewal-journal-green-r2` in the private
payment-recovery bundle. These checks do not attribute earlier physical loss or
the separate rapid-restart failure.

The unchanged five-minute router workload on `28e7a1254` delivers all 84,000
original packets, with no missing, duplicate or invalid packets and 238/252
reordered packets. Each direction has seven live successor observations with
advancing payment credit and delivery, and authorizes 43 test sats within the
original 64-sat budget. No source-wait drops occur; source carrier counts match
delivery, and measured forwarding-drop counters stay unchanged on all three
routers. One source-policy diagnostic remains in the full process log.

The two measured pauses are 1.693 and 1.804 seconds: settlement takes 0.873/0.903
seconds, replacement preparation 0.071/0.070 seconds and purchase acceptance
0.749/0.831 seconds. This is elapsed time, not CPU time. The longer pause is still
close to the approximately 1.83 seconds that the unchanged packet cap covers at
140 packets/s. There is no matched earlier pause-time measurement, so this single
pass does not establish a latency improvement or sufficient renewal headroom.
It does not erase the earlier losses. Four channels settle, all 384 test sats are
collected and all 645 management checks pass. Independent closure verifies normal
router-state restoration, stopped test processes and removed filters. Evidence is
under `work/hardware-current-r1/renewal-load-r5`; closure SHA-256 is
`f708fbf23ff76956cadcba931863ec3e74121b3b79e9b332f64c2df022dd85d7`.

Source waiting now derives packet limits from each priority lane's existing
admission capacity, preserving at least half its slots for progressing traffic.
At normal capacities, the bulk allowance is 2,048 packets overall and 1,024 per
next hop; priority and background retain independent smaller allowances. The
1 MiB total/512 KiB per-next-hop payload limits, two-second original age and
financial bounds remain unchanged. Eight focused checks pass, covering small
capacities, peer shares, healthy traffic, mixed-priority release, expiry and
cancellation. The old fixed 256-packet next-hop limit fails the same bulk-bound
regression. Evidence is in `source-wait-budget-red-r1` and
`source-wait-budget-green-r3` in the private payment-recovery bundle.

The same five-minute router workload on `2dbdbd5ad` delivers all 84,000 originals,
without missing, duplicate or invalid packets. Both successors advance credit and
delivery during seven live observations; each direction authorizes 43 test sats
within its unchanged 64-sat budget. Source carrier counts match delivery, no
source-wait drops occur, and measured forwarding-drop counters remain unchanged.
Two source-policy diagnostics remain in the full process logs. Renewal pauses
are 1.641 and 1.730 seconds. The middle relay uses 79.378 CPU seconds, or 0.991
CPU seconds per payload MiB, versus 79.431/0.992 in the preceding run; these two
finite runs do not establish a general performance improvement. Peak resident
memory at the middle remains 22,468 KiB. The larger queue limits still need
slow-renewal and higher-pressure qualification.

All four channels settle, all 384 test sats are collected, and all 648 management
checks pass. Independent closure verifies restored devices, stopped test services
and removed filters. Evidence is under `work/hardware-current-r1/renewal-load-r6`;
closure SHA-256 is
`d4ce39498e85294070823c12619e216f4ffaa56a54984563abc549477374811a`.

The broader native integration run records 2,793 core passes, 17 ignored tests
and four failures. Three permission/self-reexecution setup failures pass corrected
exact retries. The fourth recovers its queued original after rotation/rejoin, then
misses a later one-shot endpoint payload despite advancing receiver session
counters. One isolated diagnostic passes but does not explain or repair that loss.
Simulator 10, relay-library 310 and changed Python-harness 220 checks pass, as do
format, workspace compilation, file-length and strict lint checks. Exact revision
qualifications and the unresolved original failure are retained in
`work/payment-reply-recovery/native-integration-r2/closure.json`. These partial
gates do not establish production readiness or full integration acceptance.

The `f055e8153` cancellation fix retains authenticated ingress until the outer
pump can hand it back without awaiting another send. Three deterministic cases
fail before the fix and pass afterward; all 146 dataplane checks pass. The
combined candidate passes eight queue-bound, three cancellation and five real
rotation/rejoin checks. This establishes a concrete cancellation repair, without
attributing the earlier full-suite one-shot loss. The new full-core run records
2,790 passes, 17 ignored tests and eleven Unix-socket setup failures caused by
an overlong temporary directory. Each affected case receives one corrected
short-path retry: nine pass, while two expose actual routing failures during
short contacts, including the 400-ms cold-contact case. The original run remains
failed; the earlier rotation/rejoin one-shot case passes in this run. Source and
executable hashes are unchanged, and all test process groups are closed.
`ingress-integration-green-r1/core-qualification.json` retains both outcomes;
the two contact failures receive the focused repair below.

The `b9ef05a54` repair avoids spending the announcement interval on an obsolete
root while its better authenticated declaration awaits initial measurement. Valid
positive timestamp echoes that round to zero milliseconds now yield a 1-ms RTT;
missing, future and stale echoes retain their rejection rules. Two deterministic
cases fail before the repair; 110 focused checks pass afterward. The unchanged
400-ms contact test learns both current declarations in 165.075/165.336 ms at its
two starting phases, and the 750-ms bidirectional-contact test also passes.
`cold-contact-green-r2/handoff.json` records the evidence and a post-build
comment-only clarification. The old trace did not capture its RTT echo payload,
so it does not prove that particular historical failure used a zero-ms sample.
Combined candidate and device acceptance remain separate.

The combined `a7a94a0be` candidate also fixes late first payloads inheriting an
almost-expired probe-only lookup. The first queued payload takes ownership and
starts its bounded retry window once; later traffic cannot extend that window,
and retained request identifiers remain capped. The native regression fails
before this change and passes afterward. On the combined candidate, 38 focused
core checks pass, including the unchanged short-contact and rejoin cases.
Strict core/relay lint, formatting and source-size checks pass.

The unchanged renewal/refund/restart scenario also passes with a 16-MiB wallet
limit and two full-capacity recovery checkpoints. All eight tracked originals
arrive once, the final fresh payload arrives, and all 384 test sats reconcile.
New channel funding still requires a capacity reservation; this verifies logical
recovery headroom, not physical flash failure. Evidence is retained in
`work/payment-reply-recovery/combined-routing-green-r1/closure.json`, with the
financial test in `combined-routing-green-r3`. The `r2` invocation selected zero
tests without the required `testbench` feature and remains a failed setup record.

The complete core run on this same candidate records 2,803 passes, one failure
and 17 ignored tests in 2,311 seconds. Short Unix-socket paths avoid the earlier
setup failures. The remaining failure is
`same_path_rejoin::lifecycle::queued_original_delivers_once_after_real_rotation_and_rejoin`:
the queued original recovers within 771 ms, but a subsequent one-shot payload
from the useful neighbor is missing. Its authenticated receive counter advances;
the trace does not identify the later delivery/drop branch. The original two-second
assertion remains failed, with no retry. Source, executable and process closure
are verified in `combined-routing-green-r1/full-core-qualification.json`.
That candidate did not pass full-core acceptance despite its focused and device
passes.

The `180c52312` repair makes the shared synchronous-send helper retain every
completed dataplane turn before returning success/error or awaiting continuation.
Callers receive only receipt/error diagnostics, removing duplicate turn handling.
Turns containing only an FMP receive receipt also remain owned for bookkeeping.
Two deterministic cases reproduce discarded authenticated ingress before the
change and deliver it exactly once afterward, using identical real-crypto
fixtures. Seventeen focused checks, including the five unchanged rejoin cases,
and strict core lint pass. This proves the ownership defect independently of the
earlier sequence-126 trace, which did not identify its exact loss branch.
Evidence is `work/payment-reply-recovery/terminal-turn-green-r1/handoff.json`.

The complete core suite on this repaired candidate passes 2,806 tests, with zero
failures and 17 ignored, in 2,326 seconds. The unchanged rejoin case passes in
that run. There are no per-case retries. Independent closure verifies all 1,577
recorded source files and the executable remain unchanged, with the test process
group absent. The source-bound result is
`terminal-turn-green-r1/full-core-qualification.json`; the earlier failed run
remains recorded separately.

The matching static ARM64 build also passes the unchanged five-minute router
workload: all 84,000 originals arrive, with zero missing, duplicate or invalid
packets. Both successor channels advance delivery and payment during six live
observations; each direction authorizes 43 test sats within its 64-sat limit.
No source-wait drops or middle policy-drop increase occur. Renewal pauses are
1.736 and 1.567 seconds. The middle uses 79.406 CPU seconds, or 0.991 CPU seconds
per payload MiB, and peaks at 22,288 KiB resident memory. These are observations
from one finite run, not an established speedup. All four channels settle, all
384 test sats are collected, and all 648 management checks pass. Independent
closure verifies restored router state and stopped test services in
`work/hardware-current-r1/renewal-load-r8/closure.json`.

The strengthened renewal case offers 320 originals once while settlement is held.
The old runtime loses 67; the repaired candidate delivers all 320 exactly once,
with no premature delivery and unchanged financial assertions. Six buyer checks
also pass. Repeated UDP/self-signed-TLS renewal completes eight replacements,
including continued neighbor payment during a held settlement, and conserves all
384 test sats. A separate generated-CA test now explicitly enables
`test-native-roots`, replacing its accidental reliance on dependency feature
unification. Issuer/name rejection, paid forwarding, renewal, partition/restart
and conservation pass; default production trust is unchanged. Strict core/relay
lint passes. Evidence is in `ingress-integration-green-r1` through `r4`; the failed
CA setup remains recorded in `r2`.

The matching router runtime, recorded at `9b9a392b2`, delivers all 84,000 originals
in the same five-minute workload, with no missing, duplicate or invalid packets.
Both successor channels advance payment and delivery during six live observations;
each direction authorizes 43 test sats within its unchanged 64-sat limit. No source
wait drops occur; two source-policy diagnostics remain in the full logs. Renewal
pauses are 1.615 and 1.738 seconds. The middle uses 80.929 CPU seconds, or 1.010
CPU seconds per payload MiB, and peaks at 22,320 KiB resident memory. This finite
run does not establish a performance improvement. All 384 test sats are collected,
all 639 management checks pass, and independent closure verifies original-state
restoration. Evidence is `work/hardware-current-r1/renewal-load-r7`; closure SHA-256
is `0da2637ccd855929dda6c7e61099ef625c767483d088288720917ee9efe5e5c1`.

The same runtime also passes twelve router streams around a middle-relay process
crash. Healthy and recovery cohorts deliver 32,000/32,000; four cohorts with every
twentieth test frame deliberately dropped deliver 15,201/16,000, with automatic
payments advancing under loss. No duplicate or invalid payloads occur. The
original channels and 4,000-msat unbilled recovery allowance per channel persist.
All 384 test sats are collected and all 621 management checks pass; independent
closure verifies restoration and removal of the fault filters. Evidence is
`work/hardware-current-r1/restart-loss-r3`, closure SHA-256
`4856e941fd6d35fdcf7ff7d8e0f38b802c110a73a135728d7f6b6fc339128372`. Frame-drop counters include control traffic;
this does not attribute individual missing payloads or test physical power loss
or traffic during the crash.

An earlier ARM64 runtime also passes the three-router competing-provider cycle
with harness `f426a35cb`. One source watch selects the cheaper provider, switches
after an in-flight radio cut, and returns after that radio recovers. Every accepted
stage requires a complete fresh burst, healthy native delivery feedback and an
advancing acknowledged payment. The original two 64-sat channels and 128-sat
source budget remain intact; no extra watch or renewal is issued.

Delivery is 32/32 initially, 61/96 during failover and 80/160 during the return
phase. The 115 missing packets expose transition disruption despite eventual
recovery. Alternative-route confirmation takes at most 49.86 seconds including
paced probing and controller observations; this is not a measured packet outage.
Both providers settle (6/9 test sats), the source recovers 113, and all 128 test
sats are collected. All 546 management checks and independent device restoration
checks pass. The closed receipt is
`work/hardware-current-r1/diamond-active-r1/closure.json` in the private recovery
bundle. The source's first hops use management-LAN UDP, onward hops use native
Wi-Fi, and source/destination share a router. This saved-SAE test does not accept
fast roaming, isolated quality ranking, global cheapest routes or arbitrary
mobile encounters. Transition delivery and recovery time still need improvement.

The existing native recovery-timing simulation now follows both edge loss and
return, using one numbered stream per phase, the default selector policy and
the original channels. On baseline runtime `060f12a56bac`, it delivers 84/128
packets during loss and 255/256 after rejoin. The alternative first delivers
after 22.00 seconds and has fresh quality/payment evidence by 25.75 seconds;
the returning cheaper route has that evidence by 14.79 seconds. Complete-batch
confirmation takes 47.75 and 24.01 seconds respectively. All 259 test sats are
conserved. Five focused timeline checks also pass. The closed receipt is
`work/payment-reply-recovery/route-return-r2/closure.json` in the private recovery
bundle. This extends simulation coverage; it does not explain or resolve the
longer blackout observed on the physical return path.

Core revision `699840f52` fixes a separately reproduced FSP recovery failure:
after lost key-change confirmation, both endpoints could derive the same keys
but disagree about the epoch flag. Authentication now selects between at most
two keys during a transition, with replay accounting tied to the actual key.
Late draining packets cannot replace the current path or update its reports.
Stalled pending-key traffic cannot indefinitely suppress the existing recovery
retry when application traffic remains unanswered. The wire format, messages
and recovery timeouts are unchanged; normal steady-state traffic uses one key.

The candidate passes 723 focused core checks, including all 198 session checks,
the lost-confirmation regression and existing sparse/session-loss recovery cases;
one pre-existing unit test remains ignored. The source-file length gate passes.
The paid recovery simulation and five timeline checks also pass: 89/128 payloads
arrive during edge loss and 256/256 after return, using the original channels and
conserving all 259 test sats. The optimized static ARM64 build and emulated
startup pass. The closed receipt is
`work/payment-reply-recovery/epoch-recovery-green-r5/closure.json` in the private
recovery bundle. An earlier broad core run reached its 900-second bound during
lengthy neighbor-population scenarios; this result does not claim a complete
core-suite pass or production acceptance.

That candidate then passes the guarded three-Cudy provider-switching trial.
Delivery is 32/32 initially, 61/96 during the active cut and 32/32 after the
cheaper path returns. The return phase now completes in two bursts, compared
with ten bursts and 80/160 delivered on the earlier executable. A complete
return burst is observed 4.13 seconds after return probing starts, with fresh
quality/payment confirmation by 14.64 seconds (previously 54.17/94.71 seconds).
These bounds include paced probing and observations; this single comparison
does not isolate performance or prove a general roaming latency guarantee.

Failover still loses 35 packets and confirmation still takes up to 49.76 seconds.
The original channels and 128-sat budget remain intact: providers recover 5/4
test sats, the source recovers 119, and all funds are collected. All 426 management
checks pass. Independent closure verifies restored normal router state, stopped
test processes/mint, and removed temporary executables and filters. See
`work/hardware-current-r1/diamond-epoch-r1/closure.json` in the private recovery
bundle. Further failover disruption and the remaining production gates are open.

A follow-up on the identical executable changes only the selector feedback
window from 15 to 5 seconds. Initial and return phases both deliver 32/32;
failover delivers 80/96 instead of 61/96 in the preceding default-window trial.
Its three failover batches deliver 16/32, 32/32 and 32/32. The second batch is
complete but has no sufficiently fresh loss estimate at its observation, so full
quality/payment confirmation still takes 49.32 seconds. This is a confirmation
bound, not the duration of interrupted delivery. The same two channels and
128-sat limit survive; all funds are collected, all 426 management checks pass,
and independent closure verifies restored router state and stopped test services.
The receipt is `work/hardware-current-r1/diamond-feedback5-r1/closure.json` in
the private recovery bundle. This single local Wi-Fi comparison does not qualify
a shorter window for slow or impaired links; production defaults remain unchanged.

A subsequent active-restart trial on the same ARM64 executable fails. After
24,000/24,000 healthy payloads, the middle process restarts in 0.99 seconds
during a 20-second send. Only 224/4,000 payloads arrive, with no count increase
after the new process is observed. The restarted process initially has no peers;
neighbor/session recovery remains under investigation. All 384 test sats are
collected, all 432 management checks pass, and independent closure verifies
restored device state and stopped test services. See [the failed active-restart
result](CADENCE-RESULTS.md#active-stream-during-process-restart). Passing tests
that paused offered traffic during restart do not close this recovery gap.

The startup-discovery failure now has a native Linux reproduction and fix.
An Ethernet beacon received while the previous authenticated owner still looks
fresh was discarded before a retry became eligible. One expiring hint per current
neighbor now waits for a heartbeat opportunity plus a maintenance tick, uses the
existing admission limits, and is cancelled by authenticated link activity or an
owner/path change. The original connection remains until fresh authentication.
All 113 focused discovery/liveness/ownership checks and five real-veth Ethernet
tests pass on the frozen `discovery-restart-green-r3` source. These include a full
link budget and delayed healthy heartbeats.

The corresponding `80bf5baec` static ARM64 executable passes the unchanged
active-restart test on the three routers. Delivery resumes 14.12 seconds after
the middle process is killed, within the original 20-second sending window.
That stream delivers 1,290/4,000 payloads; the other eleven deliver all 44,000.
All six bidirectional rounds reconcile automatic payments using the original
channels and budgets. The two 4,000-msat unbilled exposure bounds remain exact,
all 384 test sats are collected, and all 573 management checks pass. Independent
closure verifies restored router state and stopped test services. The receipt
is `work/hardware-current-r1/restart-active-r2/closure.json` in the private
recovery bundle. This closes the recorded active process-restart failure for
this artifact and workload; physical power loss, longer soaks, mobile handover
and matched performance qualification remain open.

The newer `060f12a56bac` native runtime also passes the complete untraced
250/500/1000/2000-ms matrix on persistent SSD/ext4 at the default financial
limits. All 285,696 packets arrive; strict payment-boundary and whole-trial
accounting checks pass, all 48 channels settle and all 40,960 test sats are
collected. This closes that default-limit functional matrix for the recorded
storage/workload. Ordinary host activity prevents isolated performance claims;
the earlier HDD/XFS loss remains a storage-pressure limitation. See
[the accepted matrix](CADENCE-RESULTS.md#default-limit-native-matrix-on-ssd--3-october-2026).

The existing mixed UDP/TCP lifecycle also passes both opt-in payment-store
write failures on native Linux and the accepted ARM64 executable under QEMU.
After the native receiver accepts a payment, failed seller credit publication
keeps transit closed even when directory permissions are repaired. Restarting
only the middle daemon recovers the original channel, with cumulative payments
bounded by supported usage and exact buyer budget increments. Crash exposure
remains unbilled, subsequent renewal succeeds, and all 384 test sats are collected
in each run. The buyer-signature failure in the same lifecycle recovers without
a restart while the other payer continues. Only test sources differ from the
accepted ARM build. Formatting and file-length checks pass; this is focused
failed-write/process recovery, not a full workspace gate or physical flash,
ENOSPC or power-loss acceptance. See [the reproduction command](SERVICE.md#payment-store-write-failures)
and `work/payment-reply-recovery/storage-credit-r5/closure.json` in the private
recovery bundle.

The current Android source `d7b2f43f6a4d` passes native ARM64 release compilation,
APK assembly, strict Android lint, both activity tests and Android-target Rust
lint. Source, actual dependency paths, packaged native library and APK signature
are verified. A named test installation preserves both existing phone accounts;
52 focused phone-harness checks also pass.

That APK completes a physical Pixel session through the same three-router ARM64
runtime above. The phone uses the isolated customer AP and UDP entry, followed
by two native wireless hops. All eight fresh 1,000-byte payloads arrive in both
directions, automatic payments advance on all four paying channels, and all 512
test sats are collected after settlement. Both forwarding routers earn test
funds. Customer-network probes allow the mint and deny the tested management,
gateway and Internet endpoints. All 666 management checks pass; original router
state and both saved phone accounts remain unchanged, and normal phone Wi-Fi and
Internet access are restored. The stopped, empty test account remains saved.

The consolidated receipt is `work/android-device-r1/acceptance.json` in the
private recovery bundle. Independent closure retains an openwrt.org HTTPS
timeout and verifies HTTPS/DNS through another site with every device-state
equality check unchanged. This accepts the recorded paid phone session, not
Android crash/reopen recovery, physical power loss, throughput or an Internet VPN.

A second named APK, from `0323492960a3` with the same app/runtime code, passes
the same build gates and a physical Pixel force-stop/reopen session. The eight
payloads are split into two cohorts, each with two packets in each direction.
After the first cohort and automatic payments complete, Android force-stops
the app without its settlement or Stop actions. Reopening creates a new process
with the original identity and profile. Connect resumes forwarding without a
second purchase: all four later payloads arrive, all four payments advance,
and the original channels and spending budgets remain intact.

All four channels settle and all 512 test sats are collected. All 1,017
management checks pass; all three prior phone accounts and the original router
configuration and financial state remain unchanged. Normal phone Wi-Fi and
Internet access are restored. The original harness reports a restoration failure
because two original routers rediscover their mutual link, adding peers to the
initially incomplete connected-peer list. That failed result is retained.
Independent closure uses the regression-tested check at `7200514ea`: fixed
state and every prior link must match; additional native links must match another
original router's identity and verified mesh address. Eleven restoration/acceptance
checks pass, including the regression that fails before this correction; 57
focused phone-harness checks also pass. The consolidated receipt is
`work/android-restart-r1/acceptance.json` in the private recovery bundle. This
accepts one Android process restart with a pause in offered traffic, not physical
power loss, continuous traffic during recovery, throughput or an Internet VPN.

The 4 October matching APK passes its build, lint, activity and package checks,
but its new Pixel run aborts before paid purchases after simultaneous management
SSH timeouts and hostname-resolution failures. It does not accept the newer
phone runtime. All 512 test sats remain unspent and are subsequently collected;
independent closure verifies restored routers, normal phone Wi-Fi/Internet and
unchanged prior accounts. The stopped, empty test account is retained. Evidence
is `work/android-current-r1/failed-acceptance-closure.json` in the private bundle.

The subsequent Pixel run passes with both its named APK and router executable
built from `a7a94a0be`. The phone enters over UDP and traverses two native wireless
hops. All eight distinct payloads arrive across the before/after force-stop
cohorts, with automatic payment advancing in all four paying directions. Reopening
retains the original channels and budgets. All four channels settle, all 512 test
sats are collected, and all 744 management checks pass. Management uses resolved
addresses with the existing verified SSH host keys. Independent closure confirms
restored router state, normal phone Wi-Fi/Internet, unchanged prior accounts, and
a stopped empty test account. Evidence is `work/android-current-r2/acceptance.json`.
This accepts that finite paid session and app restart; physical power loss,
Internet VPN service and phone throughput remain separate acceptance targets.

The matching `180c52312` Pixel build repeats the same paid-session/restart case
successfully: eight originals arrive once, all four paying directions advance,
and the original channels and budgets survive the app restart. All four channels
settle, all 512 test sats are collected, and all 744 management checks pass.
Independent closure verifies restored router state, normal phone Wi-Fi and a
Wi-Fi-bound Internet probe, unchanged prior accounts, and the stopped empty test
account. The source-bound receipt is `work/android-current-r3/acceptance.json`;
the same finite-workload limits apply.

Longer Pixel trials expose a remaining delivery issue. In the first 100-second
bidirectional window, each endpoint submits 4,000 originals of 1,000 bytes at
40 packets/s, without deliberate frame loss. Phone-to-leaf delivery is 3,992 in
`android-current-r5`, 3,996 in the resumed `android-current-r6`, and 3,997 in
`android-current-r8`; reverse delivery is 4,000 in each. All four paying directions
advance, with no duplicate or invalid payloads. The complete-delivery check fails,
so the impaired and recovery windows do not run.

The uninterrupted `r8` trial captures both diagnostic interfaces on all four
devices. The phone's new end-to-end session counts 4,000 sent packets, while the
destination session receives 3,997. That send counter advances after source
admission and before encryption/output: it does not prove transmission. The two
forwarding routers each count 8,429 received and forwarded packets; all recorded
forwarding and transport drop/error counters stay at zero. This locates the gap
after source admission and before authenticated reception, but does not establish
its exact cause. Router warning logs do not expose all crypto/output drops.

The `r9` diagnostic trial keeps the same `180c52312` native runtime and enables
five-second Android `FIPS_PERF` reports plus router dataplane debug logging. All
8,000 originals arrive in the first healthy window. Deliberately dropping every
twentieth test frame then yields 3,796 and 3,799 deliveries. After removing the
filters, phone-to-leaf delivery is 3,995 and reverse delivery is 4,000, so recovery
still fails the complete-delivery check. All four paying directions advance
authorization and provider credit during every window. Each profiler capture
includes a fresh complete report after traffic drains; no recorded phone drop,
crypto-failure or replay event, router dataplane drop log, or transport error/drop
counter explains the five missing recovery packets. This trial alone does not
establish the loss boundary or make an uninstrumented performance claim.

The `r10` follow-up uses the identical native runtime and profiling settings,
adding four bounded captures of only test traffic. Healthy delivery is 4,000 in
each direction; deliberate-loss delivery is 3,798 and 3,801; recovery is 3,994
phone-to-leaf and 4,000 reverse. All four paying directions advance in every
window. Complete recovery delivery still fails.

All twelve directed router-link/window comparisons match their captured frames,
with zero kernel capture drops. The deliberate ingress drop filters act after
the observed receive capture point, so these matches do not imply that the
runtime received deliberately discarded frames. During recovery, six fewer
application-sized frames are already visible at the first router's mesh egress
than in the healthy window; length alone does not authenticate application
identity. This narrows the next investigation toward phone output, the phone-to-entry
link and entry processing, without establishing the cause. The guest capture
contains 312 unresolved UDP records consistent with receive-side batching;
its 128-byte snapshots omit headers needed for exact datagram reconstruction.
Android sends individual datagrams in this runtime; Linux entry-side GRO can
combine received datagrams. The next bounded diagnostic can use the existing
entry UDP debug log after GRO splitting and before fast ingress.

Capture shutdown itself fails: the router's sleep command rejects fractional
seconds, so supervisors exit before recording terminal receipts. All four raw
PCAP files and complete tcpdump footers are recovered, and capture/supervisor
absence is verified; the missing exit statuses remain unknown. Both packet
analysis and independent review preserve that failure separately from their
same-link observations. Evidence is under `work/android-current-r10`, including
`packet-analysis.json`, `packet-review.json` and `capture-recovery.json`. The
canonical guard-startup wait now uses a portable one-second delay; a focused
regression reproduces the integer-only-sleep failure and retains the missing-ack
rejection. All twelve focused acceptance checks pass. This does not accept
sustained Android delivery or uninstrumented performance.

The `r10` recovery also verifies an expiry boundary: three original router
purchases settle and retire into their retained lifetime totals, while the
longer-lived phone purchase closes cooperatively. Final stopped balances match
the original signatures, refunds and provider earnings; all 512 test sats are
collected and all four wallets are empty. The failed recovery attempts remain
separate evidence. Independent final checks verify restored routers, normal
phone Wi-Fi and Internet, unchanged prior accounts and the stopped diagnostic
process. All 153 final recovery management checks pass; the physical-device
reservation is released. The closed failed-run receipt is
`work/android-current-r10/failed-acceptance-closure.json`; packet observations
remain diagnostic evidence rather than successful delivery acceptance.

The `r12` entry-receive diagnostic retains runtime `180c52312`, adding the
existing post-GRO, pre-fast-ingress UDP log and 3,072-byte guest capture snapshots.
The first healthy window delivers 3,979 of 4,000 phone-to-leaf originals and all
4,000 reverse originals. Its complete-delivery assertion fails; impaired and
recovery windows do not run. All four paying directions advance. The failure
path now settles the original accounts immediately, before offline analysis;
all four channels settle, all 512 test sats are collected, and four wallets are
empty without new funding or wider budgets.

The guest capture, entry receive log and first mesh egress each contain 3,979
data-sized FMP records: 3,974 of 1,110 bytes and five of 1,194 bytes. The complete
guest capture and complete receive log retain the same data-size totals, so the
21-packet difference is not explained by their window boundaries. Every selected
guest FMP header matches the complete receive log and vice versa, preserving
duplicate counts. Full captured phone-to-entry payloads admit structural splitting with no
opaque or truncated records; classic PCAP still lacks GRO metadata, and
these headers and size classes do not authenticate application identity. All
four directed mesh comparisons match in both directions. The same entry UDP
socket reports zero drops, and the observed host UDP error counters do not
increase. This points toward phone output or the guest Wi-Fi/AP path before the
entry capture point; it does not yet distinguish those causes.

The phone transport counts 4,777 successful kernel UDP submissions across data
and control traffic, with zero send errors. Its session count of 4,000 advances
before encryption/output, and profiler output totals describe a different stage
and sampling interval. These aggregates cannot identify every submitted payload.
This motivated the phone-side FMP send-result observation below; finer mesh
captures would not resolve this remaining distinction.

All four captures close normally with zero kernel capture drops, verifying the
integer-only supervisor polling on the routers. All 759 management checks pass.
Independent closure verifies restored router state, normal phone Wi-Fi and
Wi-Fi-bound Internet, unchanged prior accounts, stopped test services and an
absent diagnostic app process; the physical-device claim is released. The
`r11` preflight had refused an oversized capture allocation before any funding;
its empty account and zero-issuance mint closure remain separate evidence.
The revised capture has explicit, separately checked RAM and temporary-storage
reserves. Fourteen focused private helper/parser checks pass. Evidence is under
`work/android-current-r12`: `device-closure.json`, `physical-session-closure.json`,
`packet-analysis.json`, `receive-analysis.json` and `packet-review.json`. Instrumentation changes
timing; this is loss-localization evidence, not sustained-delivery acceptance
or an uninstrumented performance measurement.

A separate scalar UDP send-error fix (`55eba04a6`) now preserves the successful
prefix assumed by forwarding/accounting completion. Previously Android/Windows
could send later packets after an earlier failure, making a total failure count
misidentify which packets were submitted. The loop now stops at the first error
and reports the remaining suffix as unsent. One real-socket regression covers
first failure, middle failure and all-success, including payloads and counters;
it fails before the fix and passes afterward. All fifteen UDP socket tests and
strict all-target/all-feature core lint pass. Linux executes the same scalar
helper for this check; there is no new Android device acceptance. This conditional
send-error fix does not explain the `r10` run's zero-error loss. Evidence is
`work/udp-prefix/acceptance.json` in the private recovery bundle.

The opt-in send diagnostic (`241bc6765`) records the public FMP header and actual
kernel result after each scalar UDP send, sharing one synchronous recorder across
both send paths. It adds no wire messages or delivery receipts. Android enables
the logger only through an explicit `RUST_LOG`; normal runs remain silent. The
two real-socket regressions fail before the change, and all 60 UDP tests pass
afterward, together with strict core lint, formatting and file-length checks.
The fresh Android JNI build passes strict Android lint, Rust lint and both
activity tests. Evidence is `work/udp-send-diagnostics-r13/closure.json` and
`work/android-current-r13/closure.json` in the private recovery bundle.

The `r14` device trial uses that JNI unchanged, with a fresh package/account and
the accepted `180c52312` router runtime. Its first healthy window delivers
3,996/4,000 phone-to-leaf originals and 4,000/4,000 in reverse. The original
complete-delivery assertion remains failed; later windows do not run. The phone
records 4,000 data-sized kernel submissions with no send errors. Exactly four
distinct 1,110-byte FMP headers are absent from the complete entry guest capture.
The comparison binds the destination endpoint and source socket port, retains
duplicates and uses process-bound log byte fences. There are no partial-fence or
opaque guest records, and every selected guest header has a matching phone send.

The guest capture, pre-fast-ingress log and first mesh egress each contain 3,996
data-sized records. All four directed mesh comparisons match; entry socket drops
and host UDP error counters do not increase. This locates the observed missing
datagrams after phone kernel acceptance and before entry capture. It does not
identify a kernel/driver/radio/AP cause or exclude capture blind spots: kernel
acceptance is not transmission, and public headers do not authenticate application identity. Instrumentation can
change timing; this is not a performance result or proof of lossless Wi-Fi.

Automatic authorization and provider credit advance on all four paying
directions. All four channels settle immediately after the failed window, all
512 test sats are collected, and all four wallets are empty. All 765 management
checks pass. Independent closure verifies restored router state, normal phone
Wi-Fi and Wi-Fi-bound Internet, unchanged prior accounts and an absent diagnostic
process; the actual phone claim is released. Evidence is under
`work/android-current-r14`: `send-analysis.json`, `receive-analysis.json`,
`packet-analysis.json`, `packet-review.json`, `payment-progress.json`, `device-closure.json` and
`physical-session-closure.json`. These results narrow the remaining client-link
investigation; they do not establish production readiness.

Phone transit is a separate required acceptance from those customer results.
Use isolated FIPS profiles to force Cudy → phone → Cudy → Cudy, with the application
sender and recipient on the outer routers. The additional onward relay is needed
to exercise the phone's purchase: a final recipient does not sell forwarding.
Verify the phone's actual forwarded bytes,
provider credit and onward payments, then repeat while the app is backgrounded
and the screen is off. Check link interruption/recovery, bounded spending,
settlement, CPU and battery cost without changing the management LAN. Direct
802.11s radio participation requires separate device support and verification;
FIPS forwarding over the phone's Wi-Fi connection does not prove it.

Android source `904a7f6aa` now keeps the native session in a user-started
`connectedDevice` foreground service. Screen destruction preserves the shared
session and Wi-Fi binding; notification Stop ends it. Failed stop retains the
binding and visible control, delayed old-service cleanup cannot stop its
replacement, and process death does not automatically restart spending.
All six JVM tests pass, including the existing wallet-return recovery cases,
screen recreation, notification Stop, permission refusal, stop failure and
service replacement. APK assembly and strict Android lint pass, and rendered
running/return screens were inspected. Evidence is in `work/android-background-r2`;
result digest is `47b51416493fde19e32fcff66b3976f042561c332031f0a0e900fbc72c1cb69d`.

That lifecycle-only build reused `241bc6765` JNI. The newer `r15` build compiles
the complete native Android library from `870dbf1d2`, with measurements enabled,
and packages the foreground service and explicit paid-transit admission policy.
All six JVM cases, Android-target Clippy, strict Android lint and APK verification
pass; running and wallet-return screens were inspected. The JVM cases still
isolate native commands and Wi-Fi. On the actual Pixel, the freshly installed APK
loads JNI and opens an empty setup screen. Closure confirms zero funds issued,
no saved profile or funding file, a stopped app, restored foreground, unchanged
other bench accounts and unchanged normal Wi-Fi. A runner's incorrect treatment
of an absent process was repaired with closure only, without replaying startup.
Evidence is `work/android-current-r15/result.json` and `empty-phone-closure.json`.

Native source `98750c929` adds the four-node transit acceptance using the exact
`CustomerClient` that JNI calls. Unfunded payloads are denied. After funding, both
endpoints deliver and acknowledge 128 KiB with matching digests; the phone records
two positive provider channels and one positive onward-payment channel. Settlement
reconciles all 512 test sats with no phone funds locked or pending. The focused
case, five profile-policy checks, strict affected-target lint and a build without
measurements pass. Three unchanged customer lifecycle cases passed on `870dbf1d2`;
only the new test's topology changes between these two revisions. The earlier
three-node attempt is retained: it delivered payloads and reconciled funds but
correctly had no onward purchase to a final recipient. Evidence is under
`work/phone-transit-r1` and `work/phone-transit-r2`.

A static ARM64 router build of `98750c929` also passes, recorded in
`work/phone-transit-arm-r1/result.json`. The first physical transit attempt with
that runtime and the r15 APK observes the exact four-node authenticated graph,
including the phone as an intermediate router. It stops at the unpaid probe:
the native diagnostic reports its expected incomplete-delivery deadline, but
the harness incorrectly requires a successful response. Final delivery counters
were not captured, so this run does not prove zero unpaid delivery. No route was
purchased. Recovery collects all 512 test sats, verifies four empty wallets and
restores the routers, phone and prior accounts. Evidence is under
`work/phone-transit-physical-r1`, including the original failure and separate
`collection/closure.json`.

The shared stream helper now accepts an expected denial only after reading fresh
final native counters with the exact probe identity, zero received/acknowledged
bytes and the expected deadline. It never resends the probe; paid probes still
require complete delivery. Both helper regressions and all 65 phone-harness
checks pass. The same helper supports the Cudy reliable-stream loss scenario,
whose corrected physical run remains outstanding.

The second physical phone run verifies unpaid denial and delivers/acknowledges
512 KiB in each direction in each of three windows: foreground, background and
screen-off. All six stream digests match, for 3 MiB of application payload over
the exact router → phone → router → router line. The phone has two credited
provider channels, one onward buyer channel and zero ordinary application-receive
packets. Its routing foreground service survives all windows without a process
change. Screen-off is observed as `Dozing` with USB/ADB attached; this does not
establish deep-idle reliability or battery cost.

The r16 APK uses the exact accepted r15 packaged JNI bytes, with a fresh test
account/package identity. Assembly, strict Android lint, signature/manifest
verification and an empty-account physical preflight pass; native/JVM provenance
remains r15's. Evidence is in `work/android-current-r16` and
`work/phone-transit-physical-r2`.

The physical run exceeds its operator-unlock deadline before settlement, so its
overall result remains failed. Recovery preserves the original four accounts and
mint. The first recovery cannot restore the former inbound-only entry link;
explicitly reconnecting that same authenticated peer restores the original line.
All four original channels then settle through existing local control APIs while
the phone remains locked, with payments of 5, 3, 5 and 3 test sats. Router wallets
hold 123, 133 and 123 sats. All original router baselines pass after cleanup, and
the settled phone app is stopped with unchanged financial journals. No funding,
purchase or payload probe is replayed. Separate settlement recovery evidence is
in `background-settlement-r2`.

These checks establish physical paid transit in the three observed phone states,
with financial closure completed separately after the Pixel is unlocked. The
original phone balance is 133 sats; the existing wallet UI exports it, and all
512 original sats are collected from the four settled wallets. Each wallet ends
empty, the original mint stops, and original router state, saved app accounts,
foreground app and normal Wi-Fi are restored. The collection performs no new
funding, purchase or payload probe. Evidence is in the original run's `collection`
directory. This closes the retained funds without rewriting the failed timed
acceptance result. Mobile/radio recovery, representative CPU and battery costs,
and mesh-only Android mint access remain outstanding. This phone run uses the
management-LAN mint.

The preceding `r13` attempt verifies the live logger but stops before funding
because retained captures consume its temporary-storage reserve. It closes with
zero issuance and restores the devices. Removing only two inactive remote PCAP
copies, verified against their retained local hashes, frees about 10.8 MiB.
The unchanged reserves then pass on every router in `r14`; all four captures
close normally with zero kernel capture drops. After closure, the same checks
permit removal of `r14`'s redundant entry capture copies, freeing another
10.8 MiB while retaining the complete local evidence. Both attempts remain recorded.

Preparatory failures remain distinct. The `r4` harness failed to transmit its
binary request through ADB `exec-out`; a controlled comparison justified
switching to `shell -T`. The first `r6` attempt and `r7` were interrupted by other
phone instrumentation taking the foreground. The `r7` event timeline confirms
the app stopped its client as designed while its process survived. Both phone
diagnostic sockets are now checked on an empty account before funding, and 62
focused harness checks pass. The `r8` run verifies the added phone counter capture;
it does not establish sustained delivery acceptance.

Each completed failed trial retains its original accounts, settles all four
funded channels where present, and collects all 512 test sats without new funding
or wider budgets. Independent closure verifies restored routers, normal phone
Wi-Fi/Internet and unchanged prior accounts. The `r9` recovery passes 201
management checks; the `r10` expiry recovery above passes 153. Source-bound receipts are the respective
`work/android-current-r4` through `work/android-current-r10` directories'
`failed-acceptance-closure.json` files in the private recovery bundle. The
instrumentation timeline is `android-current-r7/foreground-event-diagnosis.json`.

| Requirement | Evidence in place | Outstanding acceptance |
| --- | --- | --- |
| Payment cadence and overhead | Usage/age triggers, independent durable checkpoints, idle suppression, accepted default-limit SSD and three-router cadence matrices. The latest turn-retention runtime delivers all 84,000 router originals with 1.74/1.57-second renewal pauses and full closure; native checks cover 320 held originals and eight mixed-link replacements. Earlier failed runs remain recorded; only the two-packet loss is attributed to the former source packet cap. See [cadence results](CADENCE-RESULTS.md). | Qualify slower renewal near configured expiry, higher sustained pressure, rapid successive restarts, slow-storage limits, longer impaired runs and long-run overhead; physical wire cost remains distinct from local submission counters. |
| Shared forwarding and route policy | UDP, TCP, native Ethernet and WebSocket service paths, including local TLS certificate validation and explicit FIPS-authenticated self-signed TLS; paid/free destination policies, bounded bootstrap and price/quality selection; current ARM64 paid Wi-Fi leaf-outage recovery and current Pixel paid sessions through three routers, including force-stop/reopen. | Sustained and impaired Android/router workloads, remote WebSocket/TLS deployment, remaining delivery/payment timeouts and the rekey delay under CPU pressure described below, and acceptance before enabling additional core adapters. |
| Permissionless mobile neighbors | Authenticated adjacent admission, controlled open 802.11s joining, automatic bridging with full neighbor rosters and bidirectional service during finite software encounters. | Moving-radio/channel handover, sustained crowding and hostile physical load; bounded admission does not establish Sybil fairness. |
| Financial recovery | Actual process interruption during funding and after wallet payout/refund completion, automatic renewal across refund completion, provider outage and repeated buyer restart, unused-channel refund after original expiry, used/shared-channel expiry with each counterparty offline in turn, provider recovery after missing collection and buyer refund, exact cancellation across a mint key change, committed-send recovery, lost settlement replies across departure/rejoin, full-filesystem failure/recovery on disposable macOS HFS+ and Linux tmpfs volumes, refusal/retry of missing wallet files, missing/conflicting refund completion evidence or original funding-retry debit records, and current ARM64 middle-router process recovery on persistent overlay/UBIFS with exact bounded unbilled exposure. | Other missing or conflicting original native wallet records; broader combinations of interrupted transitions; physical power-loss and further router-filesystem failure checks. |
| Long-running history | Acknowledged export prefixes with native coin-history handoff, route/channel retirement, lifetime rollups, paged proof custody with whole-capture capacity reservations, receipts and unfinished operations, capped journal and individual service operation reads, request-journal recovery reservations, individual send-record limits, bounded wallet inventory/output planning, mint metadata projections and wallet counts, and client-file completion reservations retain unresolved ownership; fresh services can configure a fixed native wallet limit. Four outstanding channels settle under that limit, and concurrent settlement requests share a bounded relay wallet. See [history](HISTORY.md). | Remaining wallet workflows/stores and queries, other concurrent wallet workflows, aggregate resource pressure and physical recovery capacity. |
| Reproducible build and operation | Exact committed dependencies can be exported, relocated, built offline and exercised with test money; fresh-profile setup and recovery procedures exist. | Published dependency pins still lack required APIs; each deployment needs the matching source graph, native tools and current target acceptance. |
| Threats and integration | [Threat boundaries](#boundaries-and-threats), explicit mint trust, spending authority and resource limits are documented; the optional [TollGate adapter](TOLLGATE.md) remains a local design proposal. | Review the complete supported deployment and stable peer API; any deployment claiming TollGate compatibility needs client/adapter/server acceptance, which remains untested. |

## Verified implementation and test history

The earlier native x86-64 cadence matrix on `18110c330558` failed acceptance
after removal of the duplicate payment checkpoint. All eight trials settle 48
channels and reconcile 40,960 test sats, but 17,687 of 285,696 submitted packets
are missing across seven high-rate workloads. Both strict analysis and the
existing loss diagnostic reject local-evidence/payment boundary mismatches.
The worst trial again places loss at the first forwarding relay; slow durable
accounting remains a hypothesis. This run uses disk-backed XFS, unlike the earlier
accepted ARM64 memory-backed comparison. Sources and frozen executables remain unchanged;
all owned processes and locks are closed. See
[the rejected comparison](CADENCE-RESULTS.md#rejected-native-linux-comparison-after-checkpoint-fix--2-october-2026).
Both current rejected runs are preserved. Neither establishes a speedup,
optimal cadence or current-device acceptance; the default remains 500 ms.

A subsequent two-trial diagnostic reuses native forwarding counters with the
exact same daemon and unchanged workloads and financial limits. Its 10,758
missing application packets coincide with policy refusals at the first two
relays; no native route, MTU, decode, TTL or send-error counter increases. Native
refusals also include protocol traffic, so the second trial has two more
refusals than missing application packets. All 12 channels settle and all
10,240 test sats reconcile. The specific limiting admission predicate remains
unidentified. Build, focused lint, formatting, source-size and source/binary
integrity checks pass. See [drop attribution](CADENCE-RESULTS.md#native-forwarding-drop-attribution--2-october-2026)
and `work/forwarding-drops/acceptance.json` in the local recovery bundle. This
narrows the investigation; it adds no runtime fix or accepted performance result.

A follow-on diagnostic at `29ded47759ea` distinguishes the existing credit and
durable-window refusal branches with optional counters. Its high-rate trials
record 884 credit-limit and 679 durable-window refusal attempts, all at the first
relay; their sum matches its native policy refusals and the 1,563 missing
application packets in this run. Bursty and steady traffic deliver fully, and
all 12 channels settle with all 10,240 test sats reconciled. Attempts are not
generally unique packets, credit is checked first and earlier refusal branches
remain uninstrumented. Both bounds are reached, but the cause of slow
replenishment remains open. The existing 12 durable tests and strict all-feature
and default-feature lint pass; sources, binaries and evidence hashes verify and
owned processes and locks close. See [admission attribution](CADENCE-RESULTS.md#credit-and-durable-window-attribution--2-october-2026)
and `work/admission-bounds/acceptance.json`. This adds diagnostic evidence only;
there is no new forwarding fix, accepted cadence comparison or device result.

Window checkpoint jobs at `6d678ea9923b` recheck their scheduling hint under the
writer lock, so an intervening usage/payment checkpoint can make the job a no-op.
The existing regression reproduces the old journal replacement and verifies its
absence after the fix; all 12 durable tests, strict all-feature/default lint,
formatting and source-size checks pass. In the unchanged two-trial traffic
diagnostic, 139 completed window operations contain 110 journal commits, with
stable guard counters and no controller error. All 12 channels settle and all
10,240 test sats reconcile, but 24,056 packets are missing from the high-rate
workloads and both financial refusal branches remain active. Background compiler
activity is recorded in 21 of 36 host samples. This verifies skipped writes and
the recorded safety checks, not a throughput improvement, delivery fix or device
acceptance. See [checkpoint results](CADENCE-RESULTS.md#superseded-window-checkpoints--2-october-2026)
and `work/window-recheck/acceptance.json` in the local recovery bundle.

Native admission waiting at `c3ebe10ce63c` repairs the ordinary delivery failure
seen on the pre-cache baseline: a packet exceeded the unchanged credit limit
while a signed payment awaited acceptance. Explicitly temporary refusals now
wait without an accounting reservation, bounded to 512 packets/1 MiB globally,
128 packets/256 KiB per ingress neighbor, and a two-second lifetime. Retries
recheck the current route, peer authentication epoch and financial policy;
permanent window/capacity limits, including retired debt, still reject. Each
retry turn is capped at 32 packets and 50 ms. Maintenance and pending-root sends
yield at a waiting packet's retry deadline; expiry runs between RX turns.

All 25 focused Linux checks pass: six core admission checks, two real Sim/Noise
lookup cases, the unchanged no-waiter maintenance budget, retired-debt denial,
13 durable-accounting tests, and the unchanged slow-neighbor/lost-payment and
restored-buyer evidence-gap scenarios. The Sim regression first reproduces a
stalled lookup preventing the initial retry; the corrected run records actual
forwarding completion and expiry of the other waiting packet. Strict core/Sim
and relay all-feature/default lint, formatting and source-size checks pass.
Independent source review is clear, all 36,140 source inputs remain unchanged,
and owned processes and build locks close. Evidence is
`work/admission-wait/r4-green/acceptance.json` in the local recovery bundle.
The payment-reply cache candidate is excluded. This establishes scoped
functional correctness; high-rate delivery, cadence overhead and current-device
acceptance still require measurement and testing. The r57 package is unchanged.

A subsequent real-daemon diagnostic finds that `ServiceForwarder` collapses the
inner policy's temporary `Retry` into rejection. Its high-rate delivery and
payment-boundary checks remain rejected; the earlier 25 checks cover the inner
policies and controller paths, not this wrapper. Both a wrapper regression and
a real UDP/TCP daemon cohort reproduce the gap. See the
[service-wrapper diagnostic](CADENCE-RESULTS.md#service-admission-wrapper-diagnostic--3-october-2026).

The adapter correction at `ab2d76916a1d` delegates the full decision after the
existing readiness gate. Its wrapper regression checks temporary credit and
window shortages without reservations, replenishment, permanent rejection and
completion after readiness closes. The actual-daemon fixture at `450a9bb0b6c9`
buys both directions before measuring: opaque reverse session control also
needs its sender's paid route. The earlier one-way fixture could not establish
zero aggregate policy drops; its four observed drops remain unattributed.

The same corrected harness fails delivery on the old frozen daemon and passes
on the corrected daemon: 15 packets wait, all 16 original packets arrive, and
there are no duplicates, invalid packets or new policy drops after a further
2.1-second drain. It retains the 512-msat window, five-second receive deadline
and original one-way burst, with no application resend or explicit flush.
Recorded debt is paid and all 384 test sats reconcile; conservation does not
independently prove exact per-packet charging. The existing mixed UDP/TCP
exhaustion, renewal, restart and settlement scenario also passes. This is finite
service-path correctness, not high-rate, cadence-overhead or device acceptance.
Strict all-feature library/test and default-library lint, formatting and source
size checks pass. All 36,141 exported inputs and frozen executables retain their
hashes; owned process groups, cgroup and build locks close. The wrapper regression
reuses its recorded pass only after every relay library-source hash matches.
Evidence is `work/admission-service/green-r2/acceptance.json` in the local recovery
bundle. The payment-reply cache candidate and r57 hardware package are unchanged.
The subsequent unchanged 500-ms load diagnostic confirms active deferral but
still rejects high-rate delivery and payment boundaries. See
[the corrected-service load result](CADENCE-RESULTS.md#corrected-service-under-load);
finite service acceptance does not resolve those failures.

The `f3609ed433dd` counter diagnostic identifies waiting-queue overflow: all
8,079 high-rate policy drops are classified as full queues, matching missing
payload counts across two repeats. No wait expires or becomes invalid, no
explicit policy rejection occurs, and other recorded native drop/error counters
stay zero. The original queue and financial bounds remain unchanged. Six core
regressions, the running-daemon admission check, strict core/relay lint and all
121 analyzer tests pass; independent review and integrity/closure checks clear.
All 12 test channels settle and 10,240 sats reconcile, but high-rate delivery
and payment-boundary acceptance still fail. See
[overflow attribution](CADENCE-RESULTS.md#waiting-queue-overflow-attribution).
Investigating replenishment latency and measuring delivery/overhead remain
required; no cadence default or device acceptance changes.

Payment replies at `18110c330` now reuse the usage captured when verified credit
is durably saved. The former reply path immediately wrote a second checkpoint.
The existing mixed UDP/TCP service regression reproduces four ledger commits
and eight syncs for two updates before the fix, then passes its single-commit
check along with exhaustion, renewal and restart. The existing journal-failure
recovery case and all 12 durable-accounting tests pass on native Linux, as do
strict all-feature relay library/test lint, formatting and source-size checks.
All 36,135 source inputs remain unchanged during verification; the preserved
before/after evidence is `work/payment-checkpoint/acceptance.json` in the local
recovery bundle. This removes a redundant ledger write per update. The new
matched run above still fails delivery and boundary acceptance, so the source
fix does not establish a high-rate speedup or resolve that failure. The r57
package and device acceptance remain unchanged.

The later source-only setup correction publishes complete, synced customer
profiles and service manifests through the existing no-clobber temporary-file
helper. A real OS write-size failure reproduces the old truncated final file;
the fix leaves no final file and allows retry, while preserving existing regular
files, symlinks and private permissions. Five native Linux checks pass, including
the initialization guard and both customer payment/reopen/crash/settlement cases.
Strict all-feature relay library/test lint, formatting and source-size checks
pass; all 1,077 committed Rust/build inputs match the tested snapshot. Evidence
is `work/atomic-setup/acceptance.json` in the local recovery bundle. The accepted
r57 package is unchanged. Multi-file interrupted initialization remains
fail-closed with manual recovery; no hardware or power-loss acceptance is added.

Customer preview and setup now share validation of the generated service
configuration before saving the immutable profile. A rejected mint URL previously
left a saved profile that prevented correction; the regression reproduces that
failure and verifies corrected setup, reopen with the same identity and budget,
and no mint connection. Four profile cases and both existing customer payment
lifecycle cases pass on native Linux, with strict all-feature relay library/test
lint, formatting and source-size checks. All 1,077 committed Rust/build inputs
match the tested snapshot. Evidence is `work/customer-preflight/acceptance.json`
in the local recovery bundle. This is source acceptance only; r57 is unchanged,
and partial accounts still require manual recovery.

The corresponding Android source passes a fresh ARM64 JNI release build,
isolated APK assembly, strict Android lint, both existing JVM activity recovery
tests, and strict Android-target Rust lint. Updating only the Robolectric test
dependency from 4.15 to 4.17 resolved the recorded lint failure. The APK's native
library matches Gradle's stripped build output; all 1,077 Rust/build files and
18 Android files match the verified source. Evidence is
`work/android-current/acceptance.json` in the local recovery bundle. This accepts
compilation and JVM checks, not device execution, JNI runtime, radio behavior or
performance. The r57 package remains unchanged.

Wallet imports with SDK `ff1678c2b6ca` and CDK `8de95a89c9e0` can recover a
completed receive whose display-activity write failed. Retrying returns the
retained original result without redeeming again or adding balance. Native CDK
receive calls still reject duplicates unless the caller opts into this recovery.
All 437 standard SDK tests pass across source-identical Linux runs, with one
pre-existing storage soak ignored; the single full run reached its time limit,
so this is combined test coverage rather than a successful full command.

The saved-relay funding/export test passes on native x86-64 Linux with core
0.4.88 and private TCP checkout `6fe9fe951ca8`. It verifies that import retry
preserves the balance and buyer authorization before export, recovery and
redemption. The first build failed because its published TCP dependency lacked
the reservation API; adding the matching private stack and endpoint overrides
resolved that build error. Evidence is retained under
`work/paid-relay-verification/2026-10-02-import-recovery`. This source acceptance
does not update the r53 package or establish current-device acceptance.

Outgoing channel funding at `603db7280dd8`, integrated by `23f316590a8f`,
requires the original wallet database and seed. Previously, losing either during
live operation could initialize a replacement wallet and lose its saved capacity
policy and custody history. The change reuses the existing SDK recovery opener.

The unchanged optimized ARM64 Linux regression fails before the fix and passes
afterward. Removing the seed, database or complete wallet directory makes funding
fail without recreating the missing original. Restoring the files permits funding;
a repeated call returns the same result, preserves the 16 MiB capacity limit and
records only one debit. Native all-feature relay library/test lint, formatting and
source-size checks pass with matching source fingerprints. The exact private test
dependencies and original receipts remain under
`work/paid-relay-verification/2026-10-01-purchase-wallet-recovery`; the consolidated
receipt is `local-acceptance.json`. The commit retains the published lockfile.
The accepted r53 package remains unchanged and does not include this newer fix.

The unsigned r53 OpenWrt package at FIPS `15360c38b833` and SDK `8995f435abc6`
passes both customer billing modes, mixed UDP/TCP exhaustion and restart, and
explicitly configured self-signed WebSocket using its extracted optimized
executable on isolated ARM64 Linux. All eleven payload files and static ARM64
executables pass inspection. All eight build/runtime gates retain matching source
fingerprints; saved executable hashes are unchanged and all owned containers
are absent.

The frozen bundle changes six files from r52: payment control, its existing
payout regression, two documentation files and the SDK recovery opener's public
visibility. Sources match the receiver-wallet recovery acceptance below, apart
from its subsequent readiness update. Other dependency sources, the resolved
graph and lockfiles are unchanged. The 60-file evidence index is under
`work/paid-relay-verification/2026-10-01-arm64-r53`.

The r52 package, saved executables and prior evidence remain unchanged. These
checks do not attribute the historical 33-second delay or establish device
performance, physical power-loss recovery or production readiness. No hardware,
deployment or real-money operation was performed.

Payment control now opens only its initialized wallet, using the SDK's existing
recovery opener exposed at `8995f435abc6`. Funding admission, payout import
and retirement reject missing original database or seed files. Previously,
payout recovery could create a replacement database and lose its saved capacity
policy and custody history. Initial wallet creation remains in service setup.

The unchanged regression fails on the original implementation and passes on the
fix using optimized ARM64 Linux. It removes the seed, database and complete wallet
directory in turn. Recovery refuses each missing original without recreating it;
restoring the originals permits payout, duplicate import and the existing balance
and capacity assertions. All 436 native macOS ARM64 SDK tests pass, with one
existing opt-in storage soak excluded. Strict SDK and relay lint, formatting and
source-size checks pass; all eight accepted gates retain matching source hashes
within their respective build scopes.

The 183-file evidence index is under
`work/paid-relay-verification/2026-10-01-receiver-wallet-recovery`.
The tested private dependency resolutions are preserved; commits retain their
published lockfiles. Matching r53 package acceptance is recorded above; the r52
package and prior evidence remain unchanged. Physical power-loss recovery and
current-device checks remain pending. All owned containers are absent; no hardware, deployment or
real-money operation was performed.

The unsigned r52 OpenWrt package at FIPS `725d73d7b138` passes both customer
billing modes, mixed UDP/TCP exhaustion and restart, and explicitly configured
self-signed WebSocket using its extracted optimized executable on isolated ARM64
Linux. All eleven payload files and static ARM64 executables pass inspection.
All eight build/runtime gates retain matching source fingerprints; saved
executable hashes are unchanged and all owned containers are absent.

The frozen bundle changes six files from r51: the two retry implementations,
three regression files including one new module, and this readiness document.
All dependency sources, the resolved graph and lockfiles are unchanged. Source
files match the accepted session-retry and controller checks below, apart from
the subsequent readiness update. The 53-file evidence index is under
`work/paid-relay-verification/2026-10-01-arm64-r52`.

The r51 package, saved executables and prior evidence remain unchanged. These
checks do not attribute the historical 33-second delay or establish device
performance, physical power-loss recovery or production readiness. No hardware,
deployment or real-money operation was performed.

Scheduled session-handshake retries now count each due attempt before awaiting
local send completion. Previously, a failed or canceled send left the retry count
unchanged, allowing an established session's rekey to remain pending indefinitely.
Both ordinary handshake resends and the final rekey message use the existing
budget and backoff. The final reply window, current key and any completed pending
key remain intact; no retry, timeout or financial limit is increased.

Four regressions fail on the original runtime and pass unchanged with the fix.
They exercise stopped UDP and canceled completion after simulated delivery,
including five attempts, the final reply window, cleanup and subsequent
key cutover and fresh traffic. All twelve focused ARM64 Linux session cases pass,
as do strict core library/test lint, workspace formatting and source-size limits.

Four optimized five-node checks also pass: fully paid and bounded-free handshake
renewal at two CPUs and a quarter CPU, shared with the disposable mint. All ten
session directions rotate, forced handshake loss recovers, and existing delivery,
renewal, settlement, lifetime spending and balance assertions pass. Their workload,
deadlines and financial limits are unchanged. All twenty-one accepted gates retain
matching source fingerprints. The 674-file evidence index is under
`work/paid-relay-verification/2026-10-01-session-resend-budget`.

The r52 package acceptance is recorded above. The r51 package and earlier
evidence remain unchanged.
These results do not attribute the historical 33-second delay or establish device
performance or physical power-loss recovery. All owned test containers are absent;
no hardware, deployment or real-money operation was performed.

The unsigned r51 OpenWrt package at FIPS `2265c1077500` and SDK `0879189adab1`
passes both customer billing modes, mixed UDP/TCP exhaustion and restart, and
explicitly configured self-signed WebSocket using its extracted optimized
executable on isolated ARM64 Linux. All eleven payload files and the static ARM64
executables pass inspection. All eight build/runtime gates retain matching source
fingerprints; saved executable hashes are unchanged and all owned containers
are absent.

The frozen bundle differs from r50 in four files: this readiness document and
the SDK funding-retry implementation, regression and guide. FIPS runtime sources,
other dependency sources, the resolved graph and lockfiles are unchanged. SDK
sources match every file in the native acceptance below. Only the customer and
service test executables were built; earlier controller-pressure and embedded
refund checks retain their recorded source scope. The 55-file evidence index is
under `work/paid-relay-verification/2026-10-01-arm64-r51`.

The r50 package, saved executables and earlier evidence remain unchanged.
These checks do not establish current-device performance, physical power-loss
recovery or production readiness. No hardware, deployment or real-money operation
was performed.

SDK `0879189adab1` requires the original wallet debit before ordinary opening
retries resume mint funding. Previously, a retry could complete funding with no
recorded cost or change funding state before detecting a conflicting operation.
The regression removes the saved send entry or changes its operation identity;
both retries now preserve the opening and wallet journal without a mint swap or
restore request. Restoring the original journal permits one completion and
repeatable original cost. The unchanged regression fails on the prior source.

All 436 native macOS ARM64 SDK workspace tests pass, with one existing opt-in soak
excluded. Strict all-target SDK lint and changed-file formatting pass; all three
final gates retain identical source fingerprints. The published lockfile is
restored for the commit, and the exact private dependency inputs remain in the
51-file evidence index under
`work/paid-relay-verification/2026-10-01-funding-retry-evidence`.
The matching r51 package acceptance is recorded above. The r50 package and its
evidence remain unchanged. No hardware, deployment or real-money operation was
performed.

The unsigned r50 OpenWrt package at FIPS `1f53191a6a22` passes both customer billing
modes, mixed UDP/TCP exhaustion and restart, and explicitly configured self-signed
WebSocket using its extracted optimized executable on isolated ARM64 Linux.
All eleven package payload files and the static ARM64 executables pass inspection.
All eight build/runtime gates retain matching source fingerprints, executable
hashes remain unchanged, and all owned containers are absent.

The bundle changes thirteen files from r49. Dependency sources, resolved graph and
locks are unchanged; the prior native and embedded refund acceptance retains its
original source scope. Only the customer and service test executables were built.
The 52-file evidence index is under `work/paid-relay-verification/2026-10-01-arm64-r50`.
Prior package and handshake evidence remains unchanged. This does not attribute
the historical 33-second delay or establish hardware performance, physical
power-loss recovery or production readiness. No hardware, deployment or real-money
operation was performed.

The same r50 source also passes optimized five-node fully paid renewal at two and
quarter CPU. All ten controller fixture files match the prior FMP acceptance;
traffic, deadlines, fault injection and financial limits are unchanged. All ten
session directions rotate, forced handshake loss recovers, fresh traffic succeeds,
and renewal, settlement, lifetime limits and final balances pass.

| Shared CPU quota | Elapsed seconds | CPU seconds | Peak memory, MiB |
| --- | ---: | ---: | ---: |
| 2 cores | 45.117 | 10.553 | 97.3 |
| 0.25 core | 66.958 | 14.595 | 57.9 |

These measurements cover the whole harness and its test mint, not payment-only
overhead or router performance. The quarter-core run records 486 throttled periods;
neither run records a memory-limit event. All three build/runtime gates preserve
matching source fingerprints. The 25-file evidence index is under
`work/paid-relay-verification/2026-10-01-controller-pressure-r50`.
The r50 package and earlier evidence remain unchanged, and all owned containers
are absent. These passes do not attribute the historical 33-second delay.

Adjacent-link (FMP) rekey now retains its final reply window during both retry
cleanup and heartbeat liveness checks. Previously, either path could discard the
handshake or remove the peer immediately after the final allowed resend. Both now
honor the existing resend deadline. No retries, configuration options, protocol
messages or financial limits are added.

Two real UDP regressions drop the first Msg1 and hold the final retry's encrypted
Msg2 across maintenance. Both corrected fixtures fail on the original runtime and
pass unchanged with the fix. After releasing the reply, key cutover and all six
direct/routed application directions succeed. The heartbeat fixture consumes its
ordinary old-key heartbeat before observing the first new-key application frame;
the earlier observation failure remains in the evidence.

Fifteen focused ARM64 Linux core cases pass, including zero retries, backoff,
failed sends, packet loss, exact cleanup deadlines, crossed connections and
overlapping refreshes. With the default backoff and a controlled retry clock,
five resends occur at 1, 3, 7, 15 and 31 seconds; the final reply window ends at
63 seconds. Expiry releases pending dispatch, indexes, links and forwarding state
without another resend. Strict core library/test lint with simulated transport,
workspace formatting and the existing source-size limits pass.

Four optimized five-node controller checks pass: fully paid and bounded-free
handshakes at both two CPUs and a quarter CPU, shared with their test mint.
All ten session directions rotate; forced handshake loss recovers; fresh delivery,
automatic payments, renewal, settlement, lifetime limits and final balances pass.
The traffic, deadlines and financial limits are unchanged. These results do not
attribute the historical 33-second delay or establish hardware performance.

All 24 accepted gates retain identical candidate fingerprints. The 827-file
evidence index is under `work/paid-relay-verification/2026-10-01-fmp-final-reply`.
A cached baseline executable was excluded before runtime acceptance. Disk
exhaustion interrupted a build-result write after compilation succeeded; removing
inactive build caches allowed a successful check with unchanged executables.
A subsequent launch failed before creating a container while the local engine's
socket was unavailable; the four checks passed after it became available.
Discarded attempts are retained. The r49 package and its evidence are unchanged,
all owned test containers are absent, and no hardware, deployment or real-money
operation was performed.

Integration also preserves the concurrent UDP receive-error fix at `ac72b4d19555`.
Eight focused ARM64 Linux checks pass on the combined source: both final-reply
regressions, zero retries, failed-send and packet-loss cleanup, and UDP error
delay, reset and cancellation behavior through the production receive loop.
Strict core library/test lint, formatting and source-size checks pass. All twelve
gates retain identical source fingerprints; the 134-file evidence index is under
`work/paid-relay-verification/2026-10-01-fmp-udp-integration`.
The earlier four controller results retain their source scope before this UDP
integration. The r50 package checks above cover the combined source; current-device
acceptance remains pending.

Established end-to-end session handshakes now retain their state through the final
attempt's existing reply window. Previously, maintenance discarded rekey state as
soon as the retry count reached its limit, potentially before the last encrypted
reply arrived. Cleanup now also requires the recorded retry deadline to expire.
This adds no retries, timeout setting, wire message or financial limit. A zero-retry
configuration still allows the initial attempt's reply window.

The same regression body fails before the fix and passes afterward. Six focused
ARM64 Linux core cases pass, covering the last reply, exact cleanup deadline,
zero retries, late initial acknowledgement, final-message retransmission and a
peer with proactive rekey disabled. Strict core library/test lint with simulated
transport, workspace formatting and source-size checks pass.

Four optimized five-node controller checks pass: fully paid and bounded-free
handshakes at both two CPUs and a quarter CPU, shared with their test mint.
All ten session directions rotate; forced handshake loss recovers; fresh delivery,
automatic payments, renewal, settlement, lifetime limits and final balances pass.
Traffic, deadlines and financial limits are unchanged. These checks do not measure
hardware throughput or attribute the historical 33-second delay below.
That acceptance did not cover adjacent-link (FMP) retry cleanup; the later
acceptance above covers it.
All fifteen accepted gates preserve matching candidate fingerprints. The 185-file
evidence index is under
`work/paid-relay-verification/2026-10-01-handshake-final-retry`.
The r49 package and its evidence remain unchanged; all owned test containers are
absent. No hardware, deployment or real-money operation was performed.

SDK `832e48c639f7` prevents refund recovery from creating a replacement
for a missing original file-backed wallet. Wallet-funded openings, token openings
with a wallet admission, and completed refund records require the existing database
and seed. Funding restore and abandoned-funding recovery share that check. A first
refund of token-only funding without prior wallet ownership can still create a wallet.

The existing real-mint controller regression now removes completion/proof evidence,
contradicts its recorded amount, and removes the native wallet after an unrecorded
refund whose coins have already been spent. Each failure preserves the controller's
exact financial reservation and refund intent. Restoring the original evidence
allows one completion without reviving spent coins. The same regression fails on
the prior SDK because it creates a replacement native wallet before returning an
error. The SDK's existing settlement test also covers missing directory, seed and
database before the first refund and after completion, with no additional mint swap.

Native macOS ARM64 acceptance passes all 435 SDK workspace tests, 307 relay library
tests and seven routine wallet/customer cases. Strict SDK/relay lint, changed SDK
file formatting, relay formatting and source-size checks pass. Two existing opt-in
soaks remain excluded. The first customer run encountered SQLite I/O errors while
the shared filesystem had about 243 MiB free; after removing an unused build cache,
all three customer cases pass with unchanged sources. Failed runs are retained.
Eight final gates retain the same SDK source fingerprint. Evidence is indexed under
`work/paid-relay-verification/2026-10-01-refund-evidence-recovery`.

The unsigned r49 OpenWrt package includes the fix at FIPS `b33482cde416`.
Both customer billing modes, mixed UDP/TCP exhaustion and restart, and explicitly
configured self-signed WebSocket pass using the extracted optimized executable
on isolated ARM64 Linux. The refund-evidence regression passes in an embedded
relay test executable built from the same package source. Its native wallet
sources match the acceptance above.

The source bundle changes twelve files from r48; dependency versions, resolved
graph and locks remain unchanged. All eleven package payload files and static
ARM64 executables pass inspection. All nine build/runtime gates preserve matching
source fingerprints. Package and test executable hashes remain unchanged across
the runtime checks, and all owned containers are absent.
The 58-file evidence index is under
`work/paid-relay-verification/2026-10-01-arm64-r49`; prior native and r48 evidence
and package artifacts remain unchanged. No hardware, deployment or real-money
operation was performed. Other native-evidence recovery cases, timing failures
and current-device acceptance remain open in the table above.

The existing five-node controller fixture now covers automatic renewal with the
`forwarding_data` tariff as well as `forwarding_attempt`. The bounded-handshake
case passes at two and quarter CPU using a clean OpenWrt-profile ARM64 Linux
harness. All three relays use their unpaid handshake allowance, all ten session
directions rotate, each forced routed handshake loss recovers, and fresh delivery,
renewal, settlement, lifetime spending bounds and final wallet reconciliation pass.
The fully paid renewal case also passes at two CPUs. Both cases share the same
traffic, deadlines and financial limits; wallet collection remains one shared
check. Strict all-feature controller lint, formatting and source limits pass.

Two preceding instrumented quarter-CPU runs of the fully paid tariff pass.
The detailed trace matches a Setup refusal to the credit bound (12,342 proposed
versus 12,000 permitted msat) and a Finish refusal to an absent active contract
during renewal. Identical retries are admitted by the same relay 2.001 and 2.918
seconds later. Later refusals during another rotation and shutdown are retained
separately. No maintenance timeout is recorded in these traces. This establishes
those admission decisions and recoveries, not the cause of the earlier
uninstrumented 33-second gap or a matched performance comparison. That failure
remains open. Temporary runtime and test tracing was removed before the final
checks; production sources and the r48 package are unchanged. Evidence is indexed
under `work/paid-relay-verification/2026-10-01-controller-rekey-delay`.
All owned containers are absent; no hardware or real-money operation was performed.

Three further quarter-CPU runs reuse the saved instrumented runtime and all pass.
The setup-to-acknowledgement loss intervals are 8.004, 0.606 and 4.003 seconds.
The traces match credit-bound and absent-contract refusals to identical envelopes
accepted by the same relay 1.903–7.001 seconds later. The original 33-second gap
remains unattributed. This bounded replay adds historical diagnosis; it does not
accept the current runtime or measure an optimization. The 19-file evidence index
is under `work/paid-relay-verification/2026-10-01-rekey-delay-replay`.
All owned containers are absent, and the r52 package remains unchanged.

The renewal test now covers an observer starting during a setup rotation's
old-key drain. With the original observer, all eight adjacent directions already
had authenticated replacement keys, but none was counted because its first
snapshot arrived after cutover. The corrected observer recognizes that drain
state. Arming routed handshake loss still clears prior observations and requires
a subsequent rotation and fresh delivery; all ten directions remain required.
The same regression workload passes with the correction in both optimized and
development ARM64 Linux builds at two CPUs. Strict all-feature controller lint,
formatting and source limits pass. Production code and financial limits are
unchanged.

A corrected optimized quarter-CPU run completes delivery but fails the routed
handshake-loss assertion: setup is dropped at 6.779 seconds and acknowledgement
at 39.780 seconds, with no finish phase observed by the assertion. Final financial
collection is not reached. This separate delay remains open; the prior quarter-CPU
pass does not establish acceptance of this timing case. The original missing-key
failure lacked initial snapshots, so the controlled regression establishes the
observation gap without retroactively attributing every earlier failure.
Evidence, including an initial executable-permission failure, is retained under
`work/paid-relay-verification/2026-10-01-controller-rekey-boundary`.
All owned containers are absent. No hardware or real-money operation was performed.

Five-node controller pressure checks against the r48 runtime reproduce delivery
and startup timeouts in an unoptimized ARM64 Linux harness. All five nodes and
their disposable mint share a single CPU quota. Renewal and route change pass
with two CPUs. With a quarter CPU, renewal exceeds its 30-second delivery budget;
separate route-change runs time out during initial acceptance or lose an ordinary
packet before the topology change. In the captured startup failure, all six
neighbor purchases are accepted and funding is complete by the later diagnostic
snapshot. Two new half-CPU diagnostic runs match the lost packet to a first-hop
credit refusal: its proposed reservation exceeds paid credit plus grace while
payments are still progressing. The refused packet is not admitted or billed.
These traces identify those refusals, not every historical timeout. Temporary
payment-stage tracing shows signing and reply delays under this unoptimized,
shared CPU quota; it does not establish a matched performance ratio.

With the actual OpenWrt optimization profile, both instrumented route-change
checks pass at half and quarter CPU. After removing all temporary runtime tracing,
clean route-change checks pass at both quotas and automatic renewal passes at
quarter CPU. These three clean runs retain the original traffic, deadlines,
financial limits, reconciliation and rotation assertions. Source and executable
hashes remain unchanged across the checks, and owned containers are absent.
Evidence is indexed under
`work/paid-relay-verification/2026-10-01-controller-admission-observation`.
This is isolated ARM64 Linux acceptance with five nodes and a test mint sharing
the quota, not router throughput or physical-radio acceptance.

The existing controller tests now record bounded session and funding snapshots
after initial acceptance failure, each observed session's initial key/drain state,
and the final epochs on a failed rotation assertion. Final two-CPU renewal and
route-change checks, strict all-feature controller lint, formatting and source
limits pass. A proposed wait for simultaneous drain completion failed under CPU
pressure and was discarded. Original deadlines, traffic, financial limits and
rotation assertions remained unchanged in that investigation; the observation
gap is addressed above, while other historical timeouts remain unresolved.
Earlier evidence, including failed attempts, is retained under
`work/paid-relay-verification/2026-10-01-controller-rekey-observation` and the
original `2026-10-01-controller-pressure-r48` directory. Production sources and
the r48 package are unchanged; no hardware or real-money operation was performed.

CDK `7c250132ae57` closes the internal original-receipt read during
reclaim storage reservation. Both ordinary saga updates and atomic output
preparation apply the configured 4 MiB budget through the same receipt reader.
Oversized memo or metadata fields fail before projection and decoding, preserving
the original receipt, saga, coins, storage allowance, output keys and derivation
counter. Restoring the original receipt permits reclaim completion at the existing
capacity. Unconfigured native stores retain their prior behavior. No peer message,
database schema, dependency, wallet API or smaller admission limit is added.

The existing reclaim fixture fails on the prior runtime and passes unchanged with
the fix. All 186 SQLite wallet tests, 15 focused SDK reclaim/capacity/read checks,
307 relay library tests and seven routine wallet/customer cases pass. The existing
131-export soak is excluded. Native SQL, SDK and relay strict lint, formatting and
source-size checks pass; all eleven final gates preserve identical sources and
dependency fingerprints. SDK `8266ebb1865f` and FIPS runtime sources are unchanged;
the previous full SDK workspace suite retains its recorded scope.

Evidence is indexed under
`work/paid-relay-verification/2026-10-01-reclaim-read-bounds`.
This is native macOS ARM64 acceptance with core 0.4.88 and TCP endpoint 0.2.21.
The unsigned r48 OpenWrt package includes this fix at FIPS
`5069c35f1e96`. Its source bundle changes ten files from r47;
package dependency versions, resolved graph and locks remain unchanged. Both
customer billing modes, mixed UDP/TCP exhaustion and restart, and explicitly
configured self-signed WebSocket pass using the extracted optimized executable
on isolated ARM64 Linux. The internal reclaim regression passes with identical
CDK source and its recorded standalone wallet-test lock, separate from the
package dependency graph. The relay harnesses use the package's default features.

All eleven payload files and static ARM64 executables pass inspection. Source
and executable hashes stay unchanged across the accepted checks; all owned
containers are confirmed absent. Two earlier outer-workspace test-build failures
are retained; CDK's own workspace supplies the required test helpers.
Evidence is indexed under `work/paid-relay-verification/2026-10-01-arm64-r48`.
Prior native and r47 evidence remains unchanged. Remaining wallet
queries/workflows, aggregate resource pressure, current devices and physical
power loss remain open. No deployment, publication or real-money operation was
performed.

SDK `8266ebb1865f` and CDK `0defd5206d02` close an
ordinary exact receipt-read bypass of the service's existing 4 MiB budget.
Every wallet open enables the shared indexed reader, covering native completion
and terminal reclaim lookups before SQL projection or decoding. Oversized evidence is
retained, and restoring its original fields permits the same receipt to be read.
Unconfigured native databases retain their prior behavior. The change adds no
peer message, database schema or smaller admission limit.

The SDK regression fails on the original runtime and passes with the fix;
its only intervening test change is formatting. Native coverage includes reopened
readers, absent IDs, unrelated oversized rows and readable restored receipts.
All 186 SQLite wallet tests, 435 SDK workspace tests, 307 relay library tests and
seven routine wallet/customer cases pass. The existing opt-in storage test and
131-export soak remain excluded. Strict native SQL, SDK and relay lint, formatting
and source-size checks pass. All nine final gates preserve identical sources and
dependency fingerprints; standalone SQLite retains its separate native lock.

Evidence is indexed under
`work/paid-relay-verification/2026-10-01-receipt-read-bounds`.
This is native macOS ARM64 acceptance with core 0.4.88 and TCP endpoint 0.2.21.
The r47 result below adds matching Linux package acceptance. The r46 package and
CPU-pressure evidence remains unchanged with its prior wallet sources. Remaining
wallet queries/workflows, aggregate resource pressure, current devices and physical
power loss remain open.
These earlier sources leave the internal reclaim storage-reservation receipt
read unbounded; the later native fix above closes that separate path.
No deployment, publication or real-money operation was performed.

The unsigned r47 OpenWrt package combines FIPS `43206ca4b7e1` with the
accepted wallet changes above. Its source bundle changes exactly eight files from
r46; dependency versions, resolved graph and locks remain unchanged. Both customer
billing flows, mixed UDP/TCP exhaustion and restart, and explicitly configured
self-signed WebSocket pass using the extracted optimized package on isolated
ARM64 Linux. The ordinary receipt-read regression also passes using matching SDK
sources with all features. The relay harnesses use the package's default features.

All eleven payload files and the static ARM64 executable pass inspection. Source
and executable hashes remain unchanged across the checks, and all owned containers
are absent. Prior native and r46 evidence is unchanged. Evidence is indexed under
`work/paid-relay-verification/2026-10-01-arm64-r47`. This is local test-money
acceptance; no installation, physical-device or production-readiness claim follows.

Outgoing control now limits one neighbor to eight of the existing sixteen
queued/active request slots. Previously, one neighbor could occupy its four TCP
connections and fill the remaining outgoing allowance with queued requests;
another neighbor then failed immediately with outgoing capacity exhausted.
The existing real TCP/FIPS regression reproduces that failure and passes unchanged
with the per-neighbor bound. It retains pending-request cancellation, subsequent
queue recovery and exact request-count checks. Owned permits release on completion,
cancellation or timeout; the weak per-peer registry stays within the global bound.
No wire message, payment policy or request deadline changes.

All twelve control-transport integration tests pass in both feature modes on
isolated ARM64 Linux, along with 307 relay unit tests and the existing test-money
case that holds one neighbor's payment while healthy channels keep paying and
settling. Strict all-target relay lint with all features passes on native macOS;
changed-file formatting and the workspace source-size gate also pass. The same
regression source is retained for the failing and passing runs, and all final
gates use identical source/dependency fingerprints. Evidence is indexed under
`work/paid-relay-verification/2026-10-01-control-outbound-isolation`.
This fixes the reproduced outgoing-capacity starvation case without attributing
the older intermittent delivery/payment timeouts. Current-device acceptance remains
outstanding.

The unsigned r46 OpenWrt package includes that fix at FIPS `4f209a62d47e`,
with the exact r45 dependency sources and locks. Both customer billing flows,
mixed UDP/TCP exhaustion and restart, and explicitly configured self-signed
WebSocket pass using the extracted optimized package on isolated ARM64 Linux.
The outgoing-capacity regression also passes with matching embedded sources.
The harnesses use the package's default feature selection. All eleven payload
files and the static ARM64 executable pass inspection; source and executable
hashes remain unchanged across the checks, and all owned containers are absent.
Evidence is indexed under `work/paid-relay-verification/2026-10-01-arm64-r46`.
Broader unchanged scenarios retain their earlier recorded scope. This is local,
test-money acceptance; no installation or production-readiness claim follows.

SDK `948a93782f9b` and CDK `738e08534ce6` apply a
4 MiB stored-payload limit to ordinary exact wallet invoice reads and atomic
quote comparisons. Conditional SQL projection rejects oversized fields before
decoding and preserves original financial evidence. New quote writes and atomic
issue/melt admission reserve later scalar and owner growth plus the supported
64 KiB payment proof; an admitted near-limit quote completes and remains readable.
This adds no peer message, Wallet method or database schema change.

The unchanged SDK regression reproduces unchecked oversized reads on the original
source and passes with the configured reader. All 186 SQLite wallet tests and
434 SDK workspace tests pass; one existing opt-in SDK storage test is excluded.
The 307 relay library tests and seven routine wallet/customer cases pass, with
the existing 131-export soak excluded. Strict lint, formatting and source-size
checks pass. All nine final gates retain identical source/dependency fingerprints.
The standalone SQLite tests record their separate native dependency lock.

Evidence is retained under
`work/paid-relay-verification/2026-10-01-quote-record-bounds`.
That wallet milestone used native macOS ARM64 with FIPS core 0.4.87 and TCP
endpoint 0.2.20. The r45 acceptance below adds the combined core 0.4.88/endpoint
0.2.21 and matching Linux package. Legacy bulk quote APIs, remaining wallet
workflows, aggregate resource limits, current hardware and physical power-loss
checks remain open. No deployment, publication or real-money operation was performed.

The r45 candidate binds FIPS `a8b7e3bd6255`, SDK `948a93782f9b`, CDK
`738e08534ce6` and TCP endpoint `6fe9fe951ca89` to one frozen dependency graph.
Its combined native acceptance passes 329 tests: nine routing checks, 307 relay
library checks, seven wallet/customer cases, five mixed-link cases and the crowded,
lossy paid encounter. Strict lint and source-size checks pass. The accepted SDK
suite is reused with identical wallet sources and dependency graph.

Sixteen isolated ARM64 Linux cases pass: nine routing checks, the paid encounter,
both customer billing flows, the wallet command-line workflow, mixed UDP/TCP,
explicitly configured self-signed WebSocket and the exact wallet quote-read bound.
Customer, command-line and mixed-link cases execute the extracted packaged binary;
routing and wallet fixtures execute the matching embedded sources. The paid
encounter restores bidirectional delivery and all-hop credit after departure/rejoin
and reconciles all 1,536 test sats. The unchanged 131-export soak was not repeated;
its r44 evidence retains its earlier scope. These are finite acceptance scenarios,
not a timing guarantee or attribution of every historical stall.

The offline optimized build takes 394.97 seconds. The static binary is
25,485,240 bytes, SHA-256
`7cd5ff648ade90967748e77bc3963e52d1bf5f8ed21b84e05e445717a9245b37`.
The unsigned `0.1.0-r45` package is 11,670,716 bytes, SHA-256
`220d8e40d22f28114af8830980a0d7c201e1a6d9d01d204c9ee80dac5c3dac02`.
All eleven payload files, 36,273 source files and eight accepted executables retain
their verified hashes. Native and Linux source fingerprints match; only the
verification runner's cache-directory allowlist changed between phases. All owned
containers are absent, and the earlier wallet/native/r44 evidence remains intact.
The first Linux preflight stopped at the disk reserve before running a test;
removing the completed build cache restored space while preserving all executables.
The first mixed-link attempt expected optional measurement counters absent from
the default-feature package. Rebuilding the existing harness with matching features
preserves its payment/recovery assertions and passes; the failed attempt and original
harness remain archived. Runtime sources and the package are unchanged.
Evidence is indexed under `work/paid-relay-verification/2026-10-01-arm64-r45`.
No device installation, publication or real-money operation was performed.

Acknowledged exports now hand off exact native coin identities before releasing
their SDK send owners. One authenticated intent in the existing send journal
reserves recovery space and resumes capture, financial retirement and archive
acknowledgement after interruption. The shared paged archive retains unspent coins
and other recovery owners. An exported token may still await its recipient's
claim; its matching native operation keeps custody, while the pending handoff
fences reclaim of those originals. Imported originals require their separate
owner's release. The [export workflow](HISTORY.md#acknowledged-wallet-exports)
adds no peer messages or changes to gross costs and permanent replay cutoffs.

The strengthened real test-mint run completes 131 exports under the existing
16 MiB wallet limit and reconciles all 256 test sats. It ends with no retained
send requests or archived references, 188 collected coin records, and 21 remaining
coin records versus 42 before exporting. Original incoming receipt custody remains
intact. The shared three-export fixture also passes. Both cover acknowledgement
before token redemption, interrupted cache deletion, conflicting cached evidence,
full-cache refusal, permanent retirement of skipped IDs and unchanged buyer
authorization. The long test takes 1,609.69 seconds under the normal mint request
pacing; this is finite lifecycle acceptance, not a performance benchmark or a
bound on every wallet store.

All 433 SDK tests pass, with one existing opt-in storage test excluded. The 307
relay library checks, four routine bench cases and three customer cases pass.
Strict all-target SDK/relay lint, changed-file formatting and source-size checks
pass. All six final gates retain identical source and dependency fingerprints.
The full suite first caught an invalid-operation-ID error regression in the new
reclaim guard; the corrected guard reuses the existing validation, and the full
suite was rerun successfully. Earlier failures and read-only storage observations
are retained with the acceptance evidence under
`work/paid-relay-verification/2026-09-30-export-proof-retirement`.
This is native macOS ARM64 acceptance. The r44 result below adds matching Linux
package checks. Current hardware, physical power loss and the broader outstanding
requirements above remain open. No deployment, publication or real-money operation
was performed.

The r44 package binds FIPS `61a353a34f37` (core 0.4.87), SDK `05d0b6656876`
and TCP endpoint `5d4d0d7e8b02` (0.2.20) to the retained CDK/dependency closure.
Fifteen isolated ARM64 Linux cases pass: nine routing checks, the crowded/lossy
paid encounter, both customer billing flows, the wallet command-line workflow,
and the three- and 131-export custody fixtures. The customer and command-line
checks run the extracted packaged executable; routing and export fixtures use
the matching embedded sources. The paid encounter restores delivery and all-hop
credit after departure/rejoin and reconciles all 1,536 test sats.

The Linux 131-export case matches the native custody result under the fixed
16 MiB wallet limit: all 256 test sats reconcile, no send requests or archived
references remain, and 188 coin records are collected. The final 21 coin records
are below the initial 42. The test takes 1,588.81 seconds under normal mint
request pacing. Read-only aggregate observations are retained separately from
the test assertions. This remains finite lifecycle acceptance, not a performance
benchmark or a bound on every wallet store.

The offline optimized build takes 463.20 seconds. The static binary is
25,458,352 bytes, SHA-256
`e23c6d0db601fec0e9dfee697cd9d356ddc878dbebd79ba8b3944723bdb01511`.
The unsigned `0.1.0-r44` package is 11,661,691 bytes, SHA-256
`0b858723e9b0fdec13f81cdb0207850672c927b58a1f14794250b5b64bd52931`.
All eleven payload files, 36,271 source files and tested executables retain their
verified hashes. The relocated dependency graph matches native acceptance;
all owned containers are absent and the complete r43 directory is unchanged.
The 108 evidence files are indexed under
`work/paid-relay-verification/2026-09-30-arm64-r44`.

Package preflight initially mistook an independent core build's log for shared
inputs. The harness ownership check was restricted to this run's source and cache
directories before resuming; it revalidated toolchain metadata and retained the
successful production build. Original and amended runner hashes are preserved,
and the final verifier checks both. Runtime sources remained unchanged throughout.
No device installation, publication or real-money operation was performed.

Periodic tree and reachability repair now runs in the bounded liveness tick,
before optional discovery. A real encrypted-peer regression on core 0.4.86
reproduces starvation: a 25 ms optional-maintenance delay repeatedly exhausts
the 10 ms busy budget, so neither due tree nor filter refresh is sent. Moving
the existing checks preserves the liveness deadline, announcement rate limits,
pending-work ownership and wire protocol. Both refreshes then reach their peer
without changing authenticated owners or cascading unchanged filters.

The five refresh/cancellation checks pass. A related 81-check selection records
70 completed passes before a turn interruption stopped the process; the remaining
11 pass in a separate run. Source and dependency fingerprints are identical
across the interrupted interval and all completed gates. Strict all-target core
lint with simulation enabled, changed-file formatting and source-size checks pass.

The existing six-node paid mesh scenario also passes on this source: eight
competing neighbors, two-slot rosters, a 5% loss/10 ms/1 Mbps bridge, brief contacts
and a 31-second absence. Both sustained encounters resume bidirectional delivery
and increase credit on every original channel; collection reconciles all 1,536
test sats. The test takes 206.84 seconds, excluding compilation. This is native
macOS ARM64 simulation/loopback acceptance, not a timing guarantee or an
explanation of every historical stall. The r43 result below adds focused Linux
acceptance; current-device checks remain open. Failed reproductions, the
interrupted log and passing evidence are
retained in `work/paid-relay-verification/2026-09-30-periodic-routing-maintenance`.

The r43 package binds FIPS `7861ccdf592d` (core 0.4.86), SDK `b8da3c1a2bd4`
and TCP endpoint `a0f30384fcba` (0.2.19) to the retained CDK/dependency closure.
Twelve isolated ARM64 Linux cases pass: nine routing checks covering periodic
repair, cancellation, pacing, the maintenance deadline and short contacts; the
same crowded/lossy paid encounter; and both customer billing flows using the
extracted packaged executable. Both encounters restore delivery and all-hop
credit, and collection reconciles all 1,536 test sats. The paid encounter test
takes 230.39 seconds, excluding compilation and container setup; this is not a
performance guarantee. The unchanged wallet storage/recovery suites retain
their separately recorded revisions and scope.

The offline optimized build takes 377.21 seconds. The static binary is
25,315,872 bytes, SHA-256
`fbc60607102cd3885cd5b196b3ebab4428d40e8a9af3f246a713aff8967edba7`.
The unsigned `0.1.0-r43` package is 11,580,758 bytes, SHA-256
`5dc14f41516af1e18aaa252ef75c7b57f8165b235e70ba05d111d8e8ecb7d418`.
All eleven payload files, 36,267 source files and tested executables retain
their verified hashes. The relocated dependency graph matches native acceptance;
all owned containers are absent and r42 artifacts remain unchanged. The 83
evidence files are indexed under `work/paid-relay-verification/2026-09-30-arm64-r43`.
No device installation, publication or real-money operation was performed.

Numbered wallet exports now reuse the SDK's permanent retired-number limit.
A local custody acknowledgement releases a completed prefix only after the caller
has retained the complete tokens elsewhere or collected them. Unfinished sends
and conflicting cached results refuse retirement. Gross amounts and fees persist;
old and skipped numbers cannot become new sends. The durable limit commits before
cache deletion, and a retry or later export finishes interrupted cleanup. Unknown
files are preserved and count against the 128-file export limit. These are local
wallet/customer commands, with no new peer messages or SDK change.

A real test-mint run completes 131 exports with a fixed 16 MiB wallet limit,
collects all 256 test sats, retains no send requests and leaves buyer authorization
unchanged. It checks a deletion failure after retirement commits and rejects
retired requests while spendable funds remain. The routine fixture shares that
workflow with three exports and additionally checks full-cache refusal, unknown
file preservation and cleanup before a later export. Its four bench cases pass in
8.13 seconds; the 131-export case is now explicitly opt-in.

Both customer billing flows and the third customer case pass, as do 307 relay
library tests with all features and 293 with default features, strict all-target
lint, formatting and source-size checks. The phone saves increasing numeric IDs
and retains interrupted requests; its two activity tests and Android lint pass.
Pending/completed screens were inspected. A required packet-generator import was
restored after the first Android compile failed. Native relay runtime and SDK
sources remain identical across the long run and subsequent checks; the shared
test fixture/documentation changed after the long run. Evidence is retained in
`work/paid-relay-verification/2026-09-30-export-retirement`.
This is native macOS ARM64 and simulated Android-activity acceptance. The r42
result below adds Linux package acceptance. Current-device checks, physical power
loss and remaining native wallet stores, queries and aggregate resource limits
remain open.

The r42 package binds FIPS `d30985270489` to SDK `b8da3c1a2bd4` and the unchanged
CDK/dependency closure. Seven focused Linux cases pass: the packaged command-line
workflow and both customer billing flows, one mixed startup case, and three
embedded wallet cases covering recovery, ordinary retirement and the 131-export
soak. The command-line case collects the original export, acknowledges its prefix
twice without changing gross costs, and rejects retired and skipped IDs while
11 test sats remain. Its strengthened native check, strict lint, formatting and
source-size checks also pass without a runtime change.

The 131-export Linux case passes in 1,586.51 seconds under the same 16 MiB wallet
limit, reconciles all 256 test sats and retains no send requests. Its first run
hit the common ten-minute watchdog while continuing to advance. Read-only
observations showed queued CDK pacing under its default 20 requests per minute,
consistent with the earlier 1,589.34-second native run. The separate successful
run uses a thirty-minute watchdog; application code, assertions, wallet pacing,
container isolation and all other case deadlines remain unchanged. The original
failure is retained. These timings are not a performance benchmark.

The observations also retain the remaining storage limitation: between 71 and
124 acknowledged exports, spent relay-wallet coin records increase from 117 to
189 while logical storage charges increase from 207,396 to 294,487 bytes. Export
retirement does not authorize deleting every native coin record. Other custody
and recovery owners must release their evidence before that cleanup is safe.

The offline optimized build took 485.731 seconds. The static executable is
25,317,928 bytes, SHA-256
`5e28b8f2fd41da377a032bf5730c59d83598d086db411efa4be613b4c52ed540`.
The unsigned `0.1.0-r42` package is 11,580,075 bytes, SHA-256
`46810fbf812abf94f5e8731ae3e713774faa9c79e815b7902015d81a47da0568`.
Inspection verifies all eleven payload files and the extracted binary's identity.
All 36,264 source files and tested executables retain their verified hashes;
all owned containers are confirmed absent. The 74 retained r41 files remain
unchanged. The 91 new evidence files, including observer scripts and aggregate
storage observations, are indexed under
`work/paid-relay-verification/2026-09-30-arm64-r42`.
This run does not repeat the broader r38 suite or attribute the historical mesh
stalls. No device installation, publication or real-money operation was performed.

Cached wallet exports compare every payment field with the SDK's retained result
through a read-only lookup. Missing, unfinished or conflicting original results
refuse validation and preserve the cached file. Validation cannot start or recover
a wallet send. Missing-file recovery continues to use the original request ID.
The lookup shares the bounded journal and exclusive wallet ownership, without a
new dependency, journal format or peer message.

The existing test-mint fixture now includes an export attempted before funding,
followed by a conflicting cached file after funds arrive. The previous code
returned an error but still spent another 10 test sats, leaving 236 instead of
246. The fixed fixture preserves the balance and cached evidence, rejects the
existing four conflicting-field cases and absent request, recovers a missing
file, and ultimately redeems all 256 test sats. Existing SDK cases also verify
that result lookup leaves an interrupted preparation unfinished, returns its
completed result after reopening and rejects changed terms.

All 430 SDK tests pass, with the existing opt-in storage soak excluded. All three
bench cases, all three customer cases and 307 relay library tests pass. Strict
all-target SDK/relay lint with all features, changed-file formatting and source-size
checks pass. All nine passing gates retain identical source fingerprints.
The failed reproduction, tested locks, dependency graph and accepted sources are
retained in `work/paid-relay-verification/2026-09-30-cached-export-read`.
This is native macOS ARM64 acceptance. The r41 result below adds Linux-package
acceptance of that cached-export fix; current-device checks and physical
power-loss recovery remain open.

The existing command-line fixture also reproduces the unintended debit in a
separate process: the old export helper returns an error but leaves 6 of 16 test
sats, instead of 11 after one authorized 5-sat export. The fixed executable
preserves both balance and cached file, while missing-file recovery still reuses
the original token. The test keeps its original sixty-second deadline; no runtime
change accompanies it. All three bench cases, strict lint, formatting and
source-size checks pass.
Evidence is under `work/paid-relay-verification/2026-09-30-package-export-read-cli`.

The r41 package binds FIPS `d1411966b6c8` to SDK `b8da3c1a2bd4` and the unchanged
CDK/dependency closure. Five focused Linux cases pass: three run the extracted
production executable through the strengthened command-line check and both
customer billing flows, one mixes embedded startup with packaged command-line
checks, and one exercises the embedded wallet against a local test mint.
Both wallet cases reject an unfinished cached export without another debit.
The embedded case also checks conflicting payment fields and an absent original
request, preserves refused files, and redeems all 256 test sats after recovery.

The offline optimized build took 388.325 seconds. The static executable is
25,300,104 bytes, SHA-256
`885cc251b8101d4e3d06cfacaa3828ec3e226dcaa9dc2b1b851219854959bfb7`.
The unsigned `0.1.0-r41` package is 11,571,173 bytes, SHA-256
`671e3843ec00815fbdd8b99fc4b88c50dd088070d5facbe85b9c5f97cb9c1d64`.
Inspection verifies all eleven payload files and the extracted binary's identity.
All 36,263 source files and tested executables retain their verified hashes;
all owned test containers are confirmed absent after acceptance. The 79 retained
r40 artifact/evidence files remain unchanged. The 52 new evidence files are indexed
under `work/paid-relay-verification/2026-09-30-arm64-r41`.
This focused run does not repeat the broader r38 suite or attribute historical
stalls. No device installation, publication or real-money operation was performed.

Wallet exports now bind the caller's ID to the SDK's existing retained send
request. When the wallet send completed but its export file is missing, retrying
the same request recovers the original token and operation without another debit.
The amount and mint remain immutable. Publication uses the existing atomic,
private journal writer. No SDK, dependency or peer-message change is needed.

The strengthened existing real-mint fixture fails on the original implementation
and passes with the fix. It retains enough wallet balance for an accidental
second send, rejects a changed amount, compares the recovered token privately,
and redeems all 256 test sats. All three bench cases and both customer billing
flows pass, including saved-account restart and final export. Library checks
pass 307 tests with all features and 293 without optional features; strict
all-target lint in both profiles, changed-file formatting and source-size checks
also pass. The nine verification gates retain identical source fingerprints.
Exact inputs, the failed reproduction and passing results are preserved in
`work/paid-relay-verification/2026-09-30-export-recovery`.

This fixture models a missing publication after a completed send; it does not
kill the process during export or simulate physical power loss. Export records
share the SDK's 128-request, 4 MiB journal and 64 KiB per-record limit. At that revision, capacity exhaustion retained
financial evidence and refused a new send. Current numbered exports add the local
custody acknowledgements described above; a phone summary alone never releases
the wallet evidence. See [export recovery](TESTBENCH.md#collect-and-verify).
The r38 package predates this runtime change. The r39 result below accepts
the export helper on isolated ARM64 Linux; current-device acceptance remains open.

The r39 package binds FIPS `4e4a7005ef13` to the unchanged r38 dependency graph,
including SDK `e69538152a5e` and native CDK `418380651373`. Five focused Linux
cases pass. Three exercise the executable extracted from the package: wallet
export through separate command-line processes and both customer billing flows,
including saved-account restart and final export. Startup combines embedded
service loading with packaged command-line checks; the remaining case exercises
the embedded wallet against a local test mint.

The strengthened existing command-line fixture loses the published export file
between process invocations. The retry must return the original operation and
token, leaving 11 of the original 16 test sats after a single 5-sat export.
Restoring the old export implementation reproduces the failure with the same
fixture. Native bench, lint, formatting and source-size checks also pass, with no
new test case or longer deadline. The ARM64 fixture mounts the packaged executable
at the harness's compiled relay path and uses a separately hashed test-mint helper.
It retains the existing container isolation: no external network, an unprivileged
user, read-only inputs, dropped capabilities, two CPUs and 2 GiB of memory.

The offline optimized build took 446.296 seconds. Its static executable is
25,296,032 bytes, SHA-256
`1ec7e2f0a33f1c21d3856da302989ab62785b16854904527eb8f2a0f4dd5eeca`.
The unsigned `0.1.0-r39` package is 11,569,599 bytes, SHA-256
`edcc7b28b2109646b8ad7dbe8b626ef296cea02cefad0bdd7b2e04befcc23a65`.
Inspection verifies all eleven payload files and the extracted binary's identity.
The 36,262 source files and every executable remain unchanged through acceptance,
all owned containers are removed, and the r38 evidence remains unchanged.
Native reproduction and source inputs are under
`work/paid-relay-verification/2026-09-30-package-export-cli`; the package, five
runtime cases and 53 evidence hashes are under
`work/paid-relay-verification/2026-09-30-arm64-r39`.

These focused cases do not repeat the other r38 workloads or attribute the older
intermittent stalls. They do not establish physical power-loss behavior, current
radio/device acceptance or Android UI retry after restart. The separate Android
check below covers the activity flow with a simulated wallet. No device
installation, publication or real-money operation was performed.

The Android bench now saves the return ID and amount together before calling the
wallet. A pending request remains retryable after restart at zero or unknown
balance. Successful replies replace the request with its completed summary;
later returns read the current balance before allocating another ID. Private
file reads are bounded, and writes sync and verify the saved content before
authorizing an export. Incomplete saved evidence refuses a replacement request.

The original activity fails the interrupted-return regression because restart
at zero balance hides the retry. The fixed activity passes that flow, atomic-file
backup recovery, later funding, a failed post-export balance refresh and refusal
of incomplete evidence. Two activity tests, Android lint and source-size checks
pass; rendered pending/completed screens were inspected. The native wallet and
Wi-Fi are simulated in these tests: they do not run JNI or establish physical
power-loss behavior. Current Pixel acceptance remains outstanding. Sources,
failed reproduction, passing checks and images are retained in
`work/paid-relay-verification/2026-09-30-android-export`.

The existing crowded, lossy long-absence scenario now passes on FIPS `631165186977`
with the accepted dependency graph. Six paying nodes retain their eight original
channels while eight unfunded candidates compete for full two-neighbor rosters.
The inter-group link has 5% loss, 10 ms latency and a 1 Mbps limit. Short contacts
and a 31-second absence after bridge removal retain the existing 60-second recovery
deadline, spending authority and collection checks.

With extra timing queries disabled, delivery and all-hop credit recover after
23.809 and 44.615 seconds in the two encounters. Both independent local streams
deliver 160/160 packets without duplicates, and all 1,536 test sats are collected.
A diagnostic run also passes, with recovery at 18.824 and 54.901 seconds and
165/165 local deliveries per direction. Its second encounter spends 39.671 seconds
reacquiring the bridge, followed by coordinate lookup and application retries;
all-hop credit is observed 13 ms after the final fresh delivery. This run does not
show a payment-scheduler stall or establish the cause of the historical failures.

Cold short contacts deliver 0/17 ordinary and 0/18 diagnostic offers. Warm contacts
deliver 30/31 and 32/34 before their cuts. These finite cases do not guarantee cold
admission or lossless handover. Both use the same native macOS ARM64 all-features
harness and unchanged source; no runtime code or test deadline changes accompany
the result. High shared-host load and scheduling-dependent loss preclude timing
guarantees or a comparison of observer overhead. This is embedded SimNetwork and
test-mint evidence, not current-device or Linux package acceptance. Exact commands,
source fingerprints, timing traces, host samples and verified outcomes are under
`work/paid-relay-verification/2026-09-30-crowded-recovery`.

Final settlement signing now proceeds while an unrelated incoming payout owns
the local wallet. The existing channel guard and signing-store lock serialize
authorization; refund recovery still requires the exclusive wallet owner.
Removing the redundant wallet wait lets the other provider collect before the
local refund can be imported. SDK, CDK, message formats and journal formats are
unchanged.

The existing four-node funding/restart fixture holds a real incoming mint-close
reply. Its strengthened check requires the outgoing final payment and provider
report while the incoming report remains absent and the local refund remains
pending. Wallet storage capacity must stay unchanged. The original implementation
fails the existing fifteen-second observation window; the fix passes with all
features and without optional features. The fixture retains its fee, refund,
lifetime-budget and restart checks, with no additional test case or longer deadline.

Bidirectional UDP/TLS renewal and mint key rotation also pass in both feature
profiles. Relay library checks pass 307 tests with all features and 293 without
optional features; strict all-target lint in both profiles, formatting and
source-size checks pass. Exact source snapshots, the failed reproduction and
successful gates are retained in
`work/paid-relay-verification/2026-09-30-settlement-signing`.
This establishes the reproduced cross-channel settlement wait's cause. The older
intermittent delivery/payment failures remain unattributed. The r38 package below
includes this change; current-device acceptance remains open.

Automatic receiver refresh now handles mint key rotation without manual cache
updates. The previous 60-second successful-refresh cache rejected a new funded
buyer after rotation. A read-only SDK lookup now distinguishes retained funding
or cached issuing keys from missing keys. Known keys bypass refresh ownership;
missing keys trigger a serialized lookup of configured mints, with the existing
ten-second deadline and a one-second cooldown. Failed lookups remain cached during
that cooldown. Signature, payer and funding validation still run afterward; this
lookup grants no financial authority. No wire message, journal field or native
CDK change is introduced.

The existing bidirectional UDP/TLS process test rotates the mint keys after its
first buyer is accepted. The second buyer and all eight later replacement channels
use the new issuing keyset, while original accounts, spending bounds and all 384
test sats reconcile. Both relay feature profiles pass with their existing deadlines.
Restoring only the original FIPS refresh implementation reproduces the rejection
with the same strengthened test and SDK source. Focused checks also prove that
known keys bypass a held refresh owner, repeated failed lookups are paced, and a
missing receiver identity is not recreated by refresh.

All 430 SDK tests pass (one opt-in soak excluded), along with 307 relay library
tests with all features and 293 without optional features, strict SDK/relay lint,
changed-file formatting and source-size checks. The twelve final gates share
unchanged source fingerprints.
Exact sources, locks, failed reproductions and verification inputs are retained in
`work/paid-relay-verification/2026-09-30-automatic-key-rotation`.
The r38 ARM64 package acceptance below includes this fix. Current-device
acceptance and attribution of the other historical stalls remain outstanding.

Current source lets a watched route leave a disconnected provider while its
committed funding reply remains unresolved. The wallet worker retains ownership
and the original funding intent; another already-funded provider can resume
delivery and automatic payment without waiting for that wallet operation. New
funding still obtains wallet ownership before reserving capital. Retired cached
quotes cannot bind the watch, and route-stop notices progress independently of
financial recovery. This adds no wire message, journal field or dependency.

The real-mint diamond reproduces the old wait until mint timeout. With the fix,
fallback delivers and pays after 18.66 and 18.77 seconds in the two feature
profiles, while funding is still unresolved. Both original channel identities
survive departure/rejoin, locked capital stays at 128 sats, and collection after
reload accounts for all 259 test sats. These are simulated-carrier observations,
not physical-radio handover guarantees.

Broader verification also reproduced a pre-existing lost-acceptance recovery
failure on the base source. Recovery now uses the existing authenticated
stopped-route reply to confirm the provider's installed channel accounting;
unknown accounts remain retained and reusable. See [withdrawal before provider
acceptance](FUNDING-COSTS.md#withdrawal-before-provider-acceptance).
The final source passes 306 relay library tests with all features and 292 without
optional features, the funding-mobility case in both profiles, lost-settlement
recovery, all four slow renewal cases and pending encounter funding. The latter
collects all 1,536 test
sats; lost-settlement recovery collects all 259. Strict all-target relay lint,
formatting and source-size checks pass. Exact sources, tested locks, failed
reproductions and successful gates are retained in
`work/paid-relay-verification/2026-09-30-pending-route-funding`.
That mobile-funding change left SDK and CDK sources unchanged. The r38 package
includes it; current-device acceptance and the other historical stalls remain open.

Native CDK `418380651373` and SDK `66f5cf67dbc6` now bound each service
repository to 32 distinct mint/unit wallets. Admission holds the repository write
lock; startup checks every saved unit before constructing wallets. Existing
entries remain usable at capacity. Failed persistence releases only the newly
created in-memory entry, preserving prior wallets and stored evidence.

SQLite metadata reads admit at most 32 mint records, 256 keyset records per mint,
and 4 MiB of stored payload per getter before values cross the database driver.
The catalog budget covers the whole selected result; single mint, keyset and key
reads share the byte limit. Excess counts stop at the configured limit plus one.
A typed refusal cannot fall back to HTTP refresh and overwrite refused records.
These policies apply on every service open without a schema or wire change.

Each wallet cache still retains at most 256 keysets and 4 MiB of serialized
metadata, including inactive and omitted identities. Stored-byte read limits and
canonical cache limits are separate; neither is a process-memory ceiling or a
bound on SQL engine memory. SQLite capacity remains a separate storage policy.
Other wallet workflows and aggregate pressure remain outstanding.

The matching local checks pass 271 SQLite tests, 30 native cache/repository tests,
and the full 429-test SDK suite (one existing opt-in soak excluded). FIPS
fee-bearing process settlement and concurrent bidirectional UDP/TLS renewal also
pass. Native and SDK strict lint pass, as do native workspace formatting and
formatting of changed SDK files. Four unchanged SDK integration-test files still
differ from workspace formatter output. Controlled reversions of admission,
refresh-error propagation and failed-registration cleanup fail their regressions;
restoring the guards restores the passing source. Exact sources, tested locks,
negative-test recipes and 15 gate records are preserved in
`work/paid-relay-verification/2026-09-29-wallet-read-bounds`.

The r38 ARM64 package accepts FIPS `b3e60280b422`, native CDK
`418380651373` and SDK `e69538152a5e` from the verified offline source bundle.
It includes the original-authorization and coin-set recovery checks described
[below](#interrupted-send-debit-evidence), along with the previously accepted
forwarding, accounting, storage and settlement changes.

Seventeen isolated Linux cases pass. Fourteen run the executable extracted from
the APK: two storage/restart cases, four expiry/funding/retirement cases, six
mixed-transport/renewal cases and two customer-restart cases. They retain saved
budgets and cover full-filesystem recovery, ordinary TLS and explicitly enabled
FIPS-authenticated self-signed TLS. Renewal rotates mint keys between buyers;
the second buyer and all eight replacement channels use the new keys, with all
384 test sats reconciled. The TCP case also requires continued payment by another
buyer during signer-write failure and automatic recovery of the original channel.

The other three cases have distinct scopes. Initialization combines embedded
service loading with packaged command-line checks. Moving-route funding uses
embedded controllers and a local mint to check fallback, retained funding,
bounded capital and settlement. The SDK wallet case rejects sixteen conflicting
confirmations before mint submission, then recovers the original operation after
a lost reply. Its harness is bound to the exact SDK package, source target and
revision in the bundle. These embedded cases supply controller and wallet evidence;
current radio and device acceptance remain outstanding.

The offline production build took 728.081 seconds with
Rust 1.96.0, cargo-zigbuild 0.22.1 and Zig 0.15.2. The stripped static musl
executable is 25,297,952 bytes, SHA-256
`09d4fd4636a9b722a2efe9b47e36d2d1588f8d6654a53891ddfdf0b55f4713e4`.
The unsigned `0.1.0-r38` APK is 11,571,654 bytes, SHA-256
`594d38e913fc5b140dbba2a48566e57c823b1a1d83b5bc5da91bcc856bc87b30`.
Inspection verifies all eleven payload files, root ownership, lifecycle scripts,
the dependency set and ARM64 ELF structure without dynamic linking. The service
is disabled by default and the package contains no saved accounts. Installation
on OpenWrt still requires its separate acceptance.
The default package omits optional payment-stage measurements, which retain
their separate native acceptance below.

The bundle preserves the FIPS dependency graph and the SDK graph from native
acceptance, including the tested locks. Its added SDK test vendor crate is the
same `axum-macros 0.5.1` covered by the native vendor manifest. All
36,262 source files remain unchanged through the gates.
Final verification binds each result to its exact test, harness, execution kind
and read-only mounts. The earlier r37 package and evidence remain unchanged.
The new package, five harnesses, frozen runners and 112 evidence
files are retained in `work/paid-relay-verification/2026-09-30-arm64-r38`.

Every completed case uses a fresh, unprivileged, network-isolated ARM64 Linux
container and local test money. A stopped execution interrupted the first retirement
attempt without a test outcome. Its partial evidence is retained separately; the
child and owned container were confirmed absent before resuming that case. The six
completed results were preserved. All seventeen accepted cases finish within the
existing deadlines without watchdog expiry or cleanup errors; all owned containers
are removed. No package was installed or published and no physical device was
accessed. This supersedes r37 package acceptance. Current-device checks,
physical power loss, sustained
performance and the historical intermittent stalls remain outstanding.

Startup now binds the buyer journal's identity and lifetime spending budget to
the saved service terms before recovering either buyer or seller accounting.
It rejects mismatches without rewriting the buyer, seller or controller journals.
The existing funded restart case rejects an increased journal budget, restores
the original files, resumes paid delivery and completes settlement without resetting
lifetime limits. The initialization case rejects another identity even when the
buyer has no channels. Both regressions fail before the fix and pass afterward
with optional features enabled and disabled. All 304 relay unit tests, 12 buyer
tests, strict all-target relay lint, formatting and source-size checks pass.
This adds no journal field or protocol message and does not make every startup
failure transactional. Hardware acceptance and the historical stalls remain open.

The previous local verification directory is unavailable, including the r30
package and raw historical logs. Source commits survive. The native dependency
lock has been reconstructed with its original SHA-256
`8cc0797020e5259315c228bb8bbf3bf53ecf5045c94f5c7f534c79c6139662cc`.
Reconstructed bitreq source `b62b51a7aa88`, based on 0.3.7 source `2a3a3b852743`,
passes the cancellation regression and all three native CDK response-limit checks,
including rejection of oversized headers before reading a body byte. Its byte
identity with the missing earlier backport is not established. The startup checks
above use this reconstructed graph; the ARM64 results below remain historical.

The earlier r30 ARM64 sources at `3ad12adf7bd` include saved sender-identity
binding, sender-channel validation before accounting recovery, the sender-file
requirement after retirement, bounded asynchronous control admission,
payment rejection diagnostics, independent neighbor renewal workers,
[demand-driven local checkpoints](#packet-demand-before-the-checkpoint-threshold),
wallet main-file preservation, configurable funding request pacing, and withdrawal
recovery for unconfirmed channels and interrupted upgrades of shared channels.
See [funding and recovery](FUNDING-COSTS.md) for their focused regressions and limits.
All fourteen isolated Linux process cases pass against the exact packaged
executable, including eight automatic replacements across a shared provider.

A separate unfunded-profile check verifies wrong-seed rejection by both wallet
commands and service startup. It also preserves six incomplete database families:
each SQLite recovery-file kind with and without the seed. Stored bytes remain
unchanged and restoring the original files restores wallet access. Missing files
are rejected by the existing service profile preflight, before the SDK guard;
this does not replace the SDK's direct regression or prove financial reconstruction.
This supersedes r29 package acceptance; the intermittent recovery timeouts,
current-device checks and other outstanding requirements remain open.
Later WebRTC admission, handshake-recovery budget and carrier-handoff changes
through `a052606fc` are outside this package revision. Native ARM64 macOS checks
at `45e2f5a2688` pass the seeded-WebSocket loss/restart, TLS interruption/restart
and five-node automatic-renewal cases with optional features enabled and disabled
(six focused checks). They retain the existing workloads, deadlines, spending
limits and settlement checks; both renewal runs observe key rotation in all eight
adjacent session directions. This supplies focused relay regression evidence for
the newer core graph. It does not attribute the historical stalls, accept a new
carrier adapter or extend the r30 package and current-device acceptance.
The sender-identity binding uses fresh version-2 service profiles. The packaged
TCP case also verifies automatic recovery from a native signer-write failure.

The peer API uses eight requests across quote, controller and payment services.
Only the controller admits and seals channels; payment requests report usage or
update existing credit. The unused manual `Open` and `StopForwarding` operations
and their static approval map have been removed. The automatic five-node test
retains bidirectional settlement through three transit routers, including
wrong-buyer rejection and blocked delivery after closure. Receiver and buyer tests retain
funding-reservation, forged-payment and unsupported-claim checks. This replaces
the duplicate manually orchestrated settlement fixture.

Measurement snapshot version 2 removes the two unused lifecycle counters.
The cadence analyser still validates complete version-1 records for historical
results and rejects counter-version changes within an interval. Existing cadence
results predate this peer API simplification. The r20 ARM64 package includes it
and passes the twelve isolated Linux process cases below.

The matching graph passes 301 relay unit tests with all features,
287 without optional features, 12 buyer tests and all seven controller tests,
including six five-node scenarios. The focused receiver regression fails before
removal of the manual handlers and passes afterward. Strict all-target relay lint,
formatting and source size checks pass. All 121 cadence-analyser tests pass, including complete historical
and current counter sets and rejection of changed/missing counters. No wallet or
native CDK source, feature or dependency changes in this step. Current-device,
physical power-loss and complete deployment threat acceptance remain open.

Native CDK `1cce477c7166` quote and issuance receipt comparisons bound stored payloads
before SQL projection. The ceiling comes from the caller's original, with a 4 MiB
floor; existing larger originals remain usable. Issuance completion and cancellation
derive each receipt budget from the original journal and reuse the indexed reader
and exact conflict rules. Unexpected growth, including NUL-containing UTF-8 and
malformed numeric/optional fields, retains quotes, proofs, receipts and recovery
ownership. Completed matching receipts remain unchanged. The retirement plan
shares its canonical originals instead of allocating a second list of their IDs.

The 419 SQLite/shared database tests, 88 Redb compatibility tests, full 415-test
SDK suite (one opt-in soak excluded), 301 relay unit tests and the four-node
paid/restart/concurrent-settlement case pass. Strict native, SDK and relay lint
and native workspace formatting also pass. PostgreSQL has compile/lint coverage
only; relay runtime database acceptance uses SQLite. Other exact quote and
native recovery reads, SQL engine memory, overall storage and current-device
acceptance remain open. The r20 ARM64 package includes these native changes and
the expiry recovery below. It passes twelve isolated Linux transport,
customer-restart, storage-recovery and expiry cases. It has not been installed
on the routers.

SDK `695a52dc0552` expiry recovery reconciles a provider settlement that occurred before
recovery began, using the same complete, signature-verified output checks as the
existing settlement-race path. Spent funding alone cannot establish a refund or
create a new expiry intent. Verification precedes the signing fence and wallet
import; no replacement swap is sent for spent funding. The shared tests cover an
older redeemed payment, zero and full-capacity payments, rotated issuing keys, invalid
signatures, unchanged state on failure, conservation and replay after spending.
The new regression fails before the fix. All eight focused expiry tests, the full
416-test SDK suite (one opt-in soak excluded), 301 relay unit tests, the fee-bearing
paid settlement and interrupted-funding process cases, and strict SDK/relay lint
pass. The changed Rust files pass formatting and size checks. This adds no message,
journal field, feature or dependency. The r20 ARM64 package includes this SDK
extension and accepts the relay integration below in isolated Linux.

FIPS now coordinates automatic expiry for used channels, including channels shared
across destinations. The seller seals usage at service expiry and collects its
retained payment without a final buyer request. After original wallet expiry, the
buyer can recover a verified refund without the seller, preserving its highest
signed obligation, original funding identity and lifetime limits. Completed seller
reports can retire after immutable expiry without waiting for a departed buyer;
original payout custody and cumulative unpaid exposure still have to reconcile.
The four-daemon, fee-bearing case passes with optional features enabled and disabled:
the buyer is killed after the seller accepts a positive payment, the seller collects
and retires its report, and the buyer later recovers with the seller stopped. All
512 test sats are conserved including mint fees. The earlier implementation fails
because the absent buyer cannot initiate seller settlement. See [reproduction and
limits](FUNDING-COSTS.md). Missing or conflicting financial evidence and physical
power loss remain outside this acceptance. Recovery when the provider misses
collection is described below.
This shared-expiry change added no protocol message, journal field or dependency.
That revision passed 301 relay unit tests, both shared-expiry
feature profiles, ordinary fee-bearing settlement, interrupted unused-funding
recovery and strict all-target relay lint. SDK and dependency sources were unchanged
from the full 416-test SDK acceptance above.

Provider recovery now also reconciles a buyer refund after the provider misses
its collection deadline. A complete mint-issued, signature-verified zero-balance
distribution is required; spent funding, expiry or missing outputs alone cannot
prove a zero collection. Signed authorizations remain separate from actual
collection in close results, settlement reports and receiver/seller history.
The same retirement handoff verifies the empty receiver payout without erasing
the original usage or resetting lifetime spending limits. Receiver history uses
version 2; these record changes target fresh profiles. No request operation or
dependency is added. See [reproduction and limits](FUNDING-COSTS.md).

The matching graph passes 118 native tests, the full 417-test SDK suite
(one opt-in soak excluded), 301 relay unit tests, both missed-deadline
feature profiles, ordinary shared expiry, fee-bearing settlement, interrupted
unused-funding recovery and strict native/SDK/relay lint. The SDK regression
also covers key rotation, malformed restore evidence and replay after spending.
The r20 ARM64 package includes this extension and passes the missed-collection
case in isolated Linux, alongside ordinary shared expiry and interrupted-opening
recovery. Current-device and physical power-loss acceptance remain pending.

Customer entry recovery now has local process acceptance under both tariffs and
both relay feature profiles. The entry process is killed while the customer stays
live; fresh payloads and two advances of automatic payment recover without a new
purchase command or manual flush. Original identities, profiles, purchases and
spending limits survive, the entry earns, and all 384 test sats are collected.
A provider crash can leave local sends above its retained claim. Successful,
unchanged claims now use capped rechecks instead of perpetual fast polling;
evidence remains intact and late claims remain payable. New sends and failed
payments restore prompt checks. See [cadence](CADENCE.md) for the 30-second cap
and the distinction between an unclaimed gap and confirmed idle.

The focused regression fails before the fix. Final checks pass 301 relay unit
tests, both three-test customer profiles, the controller scenarios, the four-node
shared-wallet recovery case and strict relay lint, formatting and source-size
checks. These use the unchanged, previously accepted SDK and local test money.
Native priced background envelopes can advance during recovery; that period is
not assumed idle. The current ARM64 package also passes both customer restart
cases with these scheduler and SDK receipt changes. Current-device acceptance
remains outstanding.

Fresh services can opt into `terms.wallet_capacity_bytes` before initialization.
The SDK creates the limited wallet before admitting financial work; normal reopening
preserves its maximum. Service startup and offline wallet commands compare that
maximum with the saved terms. Existing or partial wallets cannot be adopted by
the fresh-wallet constructor, and changed or removed limits fail without resizing.
See [service configuration](SERVICE.md) for the configuration boundary.

Focused local acceptance covers initialization/mismatch rejection and offline
import/export, plus a four-node paid UDP line with 16 MiB per wallet. Its middle relay
buys onward forwarding and accepts two incoming channels through one wallet. With
all unreserved native space occupied, paid data crosses both relays and ordinary
restart preserves spending totals. The real mint then commits one incoming close
while its reply is held. Concurrent settlement requests must let that same relay
record its outgoing sealed usage before waiting for wallet access. Its native
capacity snapshot stays unchanged while the close is held. Releasing the reply
completes all four original settlements and reconciles funds, refunds, mint fees
and lifetime budgets. This passes with all features and with optional features
disabled; wallet writes remain deliberately serialized. The
three-node payout/refund crash case also passes with the limit fixed before init,
including original-proof recovery and actual-expiry retirement. These tests use
local test money and logical database pressure; they do not establish router
memory sizing, filesystem/WAL reservation or physical power-loss safety.
The SDK's existing 130-channel lifecycle check admits groups of four before
settling any channel, with both wallets fixed at 16 MiB. Four groups complete
after the receiver wallet reopens at capacity; released space is reoccupied before
each subsequent settlement. All payouts, refunds, expiry retirement and lifetime
totals remain checked. This covers overlapping funded channels and reservations;
the wallet calls themselves are sequential. Production code and dependencies are
unchanged, so this acceptance does not require a new router package.
The updated test passes in the full 412-test SDK workspace suite and under strict
lint for that integration test. Prior acceptance of the unchanged production
sources covers 296 relay unit tests, strict SDK/relay lint, the ordinary service
restart/retirement regression, and the focused configuration, offline-wallet,
shared-wallet and crash-recovery checks. One opt-in SDK storage soak is excluded
from the full-suite count; features and native dependencies are unchanged.

The opt-in [filesystem exhaustion regression](SERVICE.md#filesystem-exhaustion-regression)
reuses that four-node scenario on a 128 MiB HFS+ image on macOS arm64. Real writes
exhaust the volume containing one transit relay. Its controller journal update
fails with ENOSPC without replacing the saved journal; a 4 MiB wallet write that
fits the logical limit fails with SQLite's disk-full error, leaving no value or
capacity charge. After SIGKILL, startup also fails on the full volume. Removing
the test ballast preserves the exact original unspent proofs and permits wallet
writes again. Normal restart then delivers new paid traffic and completes the
same concurrent-settlement check, reconciles test funds and retains lifetime
spending limits. The ordinary
logical-capacity/restart case also passes with paid delivery after restart.

This is failed-write and process-recovery evidence, not physical power-loss,
router-filesystem or guaranteed settlement-while-full acceptance. The logical
wallet limit does not reserve filesystem blocks, SQLite WAL growth or journal
replacement space. This change adds shared test coverage and reproduction steps;
it changes no production code or dependency versions.

Incoming route admission checks capacity, existing bindings and replacement
ownership before invoking receiver funding persistence. The payment boundary
also rejects declared channel capacity above the agreed limit before native
validation can store funding, and rechecks the verified capacity afterward.
The controller holds its journal lock through that synchronous verification and
the local commit, so
competing acceptances cannot both consume the last route slot. Retained requests
can still retry when the route book is full, and failed verification leaves the
previous replacement route intact. This closes the rejected-route write path.

Receiver profiles now reserve logical completion space for admitted channels.
The SDK defaults to 32 MiB, including 16 MiB reserved for lifetime history, and
retains reservations through closure until validated retirement. New work fails
at capacity while existing settlement and refund records retain their allowance.
This does not allocate filesystem blocks or bound native wallet storage;
those limits and the crash boundary between separate stores remain outstanding.

Sender custody now has a default 64 MiB logical page budget, including reserved
space for each complete capture. Capacity exhaustion keeps the original plan and
financial owners. Existing captures resume within their reservation; collection
releases space only for eligible spent evidence. Retirement attempts one bounded
collection pass under pressure so it cannot prevent the cleanup needed to make
progress. Registry metadata and individual pages have separate limits. Related
custody changes commit together in SQLite. This does not bound the native wallet
database or reserve physical disk; see [custody storage](HISTORY.md#proof-custody-storage)
for the contract.
SDK `6578b4d` passes its full 373-test workspace suite, all 18 feature profiles,
strict lint and formatting. The matching FIPS graph passes 295 relay tests, five
opening-recovery process cases, the payout/refund crash case and sender retirement,
plus strict lint. All 2,673 recorded FIPS source/dependency inputs match. The focused
capacity checks cover reservation exhaustion, resumed completion and safe reuse of
collected space; the test-mint case retains every original owner at capacity and
then completes the same retirement after capacity is increased.

Native operation-proof pages now enforce a 4 MiB aggregate stored-payload limit
inside the indexed SQL read, before returning payloads to the driver. Sender
custody retries oversized pages with successively smaller row counts, at most
eight reads under the same wallet lock. The cursor advances only past consumed
coins and uses the actual requested count to detect further pages. Oversized
individual records and other read errors retain original owners and evidence.
The existing large-history splitting test reproduced the need for this retry;
its original assertions pass with the bounded reader. Exact-Y reads, total wallet
storage and physical recovery capacity remain separate requirements.
The matching graph passes 130 SQLite wallet tests, 158 shared-library tests,
the full 374-test SDK workspace suite and strict affected-database/SDK lint.
The real relay-process retirement case also passes: restart and expiry preserve
original coins and lifetime spending limits through channel cleanup. All 2,677
fingerprinted source/dependency inputs and both relay/test executable hashes stay
unchanged through that run. This is local test-money acceptance, not physical
power-loss or current-router validation.

The existing SDK storage soak now uses a fixed 16 MiB logical wallet capacity
through 300 numbered sends and receives. Every 75 cycles it interrupts an admitted
receive after mint commitment, fills unreserved space, rejects new spending and
reopens the wallet. Recovery finishes before removing pressure, without increasing
the limit. Exact custody and lifetime costs remain checked throughout. The workload
retains six accounting owners and 12 spendable proof rows, retires 312 spent rows,
conserves all 32 test sats and keeps a 300-sat lifetime gross debit. Financial and
accounting row counts stay fixed after warm-up. See the current acceptance below
and the SDK's wallet-history document for measurements and reproduction.

Collection now checks each unfinished operation's exact coin references and the
candidate rows' creator/spender ownership. Unrelated open sends no longer prevent
retirement. One operation record is inspected at a time within a 4 MiB stored-byte
bound, enforced before SQL payload projection; malformed or oversized records
stop collection and remain available to ordinary recovery. The real local-mint
regression preserves the unrelated open send and every other original coin,
performs no mint request during collection, and completes the send afterward with
its balance intact. Tests also retain checkpoint-only and creator/spender owners
beyond the first header page and across foreign mint/unit scopes. Total native
wallet admission, completion reservations and sustained overlapping-channel
storage acceptance remain separate requirements.
The matching graph passes 159 shared-library tests, 131 SQLite tests, the full
375-test SDK workspace suite and strict affected-database/SDK lint. The real
relay-process restart/expiry/retirement case also passes. All 2,680 fingerprinted
source/dependency inputs and both runtime executable hashes remain unchanged
through that check. These are local test-money results; current-router, physical
power-loss and total-storage acceptance remain open.

All wallet swaps share atomic output preparation. A private proposal's issuing
keys, exact derivation range and recovery plan commit together, including the
initial record for a standalone swap. Withdrawal change saves its pending wallet
receipt in the same transaction, using the existing receipt identity and status
rules. Single and batch issuance acquire their quotes, keys, one consecutive
derivation range, exact requests and pending receipts atomically. Rollback leaves
no proposal-owned keys or consumed counters; conflicting or uncertain writes
prevent mint submission and retain any committed recovery plan.
The withdrawal regressions interrupt both preparation boundaries twice with wallet
reopens, preserve the original 32 sats without submitting a swap or payment, then
complete the same 8-sat withdrawal with 24 sats remaining. Earlier send/receive and rotating-key
reclaim regressions also remain in the accepted suites. The single/batch issuance
regressions interrupt initial journal and receipt writes with reopens, retain the
original paid quotes and counters, then retry successfully for 8/16 test sats.
All swaps now construct private proposals; the obsolete eager-allocation and
nested standalone reservation paths were removed.

With SQLite capacity accounting enabled, standalone swaps now reserve their exact
input claims and peak output/checkpoint space inside that initial preparation
transaction. Rejection leaves the original coins, counters and storage claims
unchanged. Completion or cancellation releases unused allowance while retained
coins remain charged. The real-mint regressions recover at full capacity after a
lost reply and restart, including rotated keys and blinded recipient conditions;
all 32 test sats remain usable as 13 recipient sats and 19 change sats. Local
cancellation also preserves the exact originals at capacity without a mint swap.
Single and batch issuance now claim their original quotes and reserve their peak
ownership/state growth, exact output keys/counters, all output proofs and terminal
receipts in the initial transaction. Sizing shares the production record encoders.
Exact completion or cancellation releases unused allowance with proof publication,
receipt/quote updates and journal removal. The local-mint cases recover at full
capacity after a lost committed reply and reopen; another wallet redeems all 8 or
16 original test sats, including conditioned batch outputs. Injected terminal
release failure rolls back proofs, receipts and quote release together. Rejected
admission preserves original quotes/counters, and unsubmitted cancellation leaves
the paid quotes reusable.

Withdrawal admission now reserves cancellation space with initial input/quote
acquisition, replacement coins and their checkpoint before a preparatory swap,
and the paid receipt/change/quote before final payment. Failed admission rolls
back before that stage's mint request. If a preparatory swap has already spent
the originals, rejected payment admission releases only the replacement coins.
Terminal cancellation or completion releases unused allowance while retained
financial evidence remains charged. Five real-mint regressions cover full-capacity
cancellation, interrupted paid and swap replies, wallet reopen, failed allowance
and release writes, and capacity exhausted after the preparatory swap commits.
All 32 test sats remain accounted for as payment plus usable coins. Settlement
proof strings have a method-neutral 64 KiB UTF-8 limit; sizing includes worst-case
JSON escaping, and oversized results retain pending custody without truncation.
Those withdrawal checks did not establish whole-service capacity or physical
recovery acceptance.

The withdrawal acceptance used CDK `63655bfc` and SDK `7896de5`. It passed 819
native-library tests, 483 shared-library/storage tests, the full 404-test SDK suite,
strict affected-crate/SDK lint and formatting checks. The SDK run uses one worker;
one opt-in storage soak is excluded. All 1,691 recorded source/dependency inputs
match the integrated files. PostgreSQL has all-target compile/lint acceptance
only. This update adds SQLite withdrawal capacity admission through shared sizing
and reservation helpers; schemas, dependencies, feature settings and Wallet
methods are unchanged.

Two three-relay process regressions pass on this wallet graph. A kill after funding
commits, followed by offer expiry and ordinary restart, recovers the original funds
without replacement funding: 378 test sats remain spendable and 6 cover mint fees.
An unsubmitted plan survives a keyset change and a second kill after wallet
cancellation, then automatically retires the original funding intent without a
mint swap or fee; all 384 test sats remain spendable. All 2,718 recorded
source/dependency inputs and both executable hashes stay unchanged through these
runs. These local checks do not validate current routers, physical power loss or
complete wallet-capacity operation; see [history](HISTORY.md).

Receiver wallet admission now reserves payout proofs and shared bookkeeping
before retaining funding, including the original mint metadata for a cold wallet.
The bounded admission journal preserves the original allowance through partial
writes and rejects lost accepted funding instead of recreating it. At that revision,
FIPS automatic acceptance and preapproved opening used this admission with their
existing agreement checks; recurring payments require original funding without
reopening the wallet.
Settlement imports the original payout, including zero payouts, through its paired
wallet. No protocol message or payment cadence changes are introduced.

The receiver-admission graph passes all 408 SDK tests, all 18 feature profiles,
296 relay unit tests, strict SDK/relay lint and source formatting/length checks.
Preapproved native channels and automatic multi-hop purchases passed their live
scenarios. The three-relay settlement regression fills the seller wallet after
admission, then preserves paid and zero-payout handoffs through process kills,
ordinary restart, duplicate settlement and actual expiry/retirement. All 2,722
source/dependency inputs match; relay and test executable hashes stay unchanged
through the crash scenario. This accepts logical SQLite capacity with local test
money, not physical disk exhaustion, power loss or current-router operation.

Token-funded channels now reserve the buyer's native wallet refund allowance before
submitting funding. Wallet-bound intent and ready markers retain the original
allowance through interrupted admission and lost funding replies. Recovery rejects
missing or changed original wallet evidence instead of creating another allowance.
The SDK checks restore a lost funding reply without another swap, then import the
original 13-test-sat refund at full wallet capacity and skip duplicate imports.
They also cover rejected admission and a captured-snapshot simulation of interruption
between the native reservation and client marker writes.

SDK `c06d3e1` passes all 411 workspace tests, all 18 feature profiles, strict lint and
changed-source formatting. All 1,695 recorded SDK/dependency inputs match the
integrated files; one opt-in storage soak is excluded. These are SDK-level,
local test-money results. They add no FIPS process, current-router or physical
power-loss acceptance; token-funded history retirement and remaining wallet stores
were outside that checkpoint's service-level capacity coverage.

The SDK's direct mint calls for metadata, channel funding and settled/expiry
refund recovery now share a streamed 1 MiB response limit and a 30-second request
deadline. Non-success statuses reject without reading or echoing their bodies.
Oversized proof-state and restore replies preserve the original financial records;
an oversized reply after a committed expiry swap still recovers its original coins
without another swap. A stalled proof-state request releases the client store at
its deadline and permits ordinary retry.

SDK `af36c31` passes all 414 workspace tests, all 18 feature profiles, strict lint
and changed-source formatting. All 1,697 recorded SDK/dependency inputs match the
integrated files; one opt-in storage soak is excluded. These local test-money
checks establish per-request bounds, not whole-workflow deadlines, custom-transport
bounds, current FIPS process or hardware acceptance. Those results did not cover
service-level capacity configuration or the other storage and recovery requirements.

Numbered supplied-token channels with their original authenticated wallet refund
admission now retire through the existing custody handoff. Their original input
value and refunds stay separate from native wallet debits; shared capacity and
signed-payment totals include both funding sources. The regression preserves
original owners at archive capacity, rejects premature retirement and replay,
continues with wallet-funded channels in the same scope, and resumes an interrupted
cutoff write without changing saved totals. Profiles without that original wallet
admission retain their records. FIPS's wallet-funded retirement rejects nonzero
supplied-token totals rather than accepting unrelated financial evidence.

SDK `eca7752` passes all 415 workspace tests, all 18 feature profiles and strict
lint. FIPS `81345dfad` passes 296 relay tests, strict lint and the interrupted
pre-funding process case: ordinary restart cancels and retires the original
request, preserves all 384 test sats and creates no wallet debit or refund.
All 2,727 recorded source/dependency inputs and both process executable hashes
match the accepted graph. One opt-in SDK storage soak is excluded. These checks
do not establish sustained token-funded capacity, token-specific fee/power-loss
coverage or current hardware acceptance. That checkpoint did not configure
service-level capacity.

Fresh custody archive format 4 reserves bounded native charged bytes for rotating
counter widths and the longest registered scope cursor. An all-unspent page can
rotate at full native payload capacity without growing its storage charge. One
conditional SQLite transaction deletes eligible spent originals, writes residual
custody, advances the cursor and updates the proof-release journal's lifetime
count. Matching queue references disappear in that transaction; no intermediate
queue admission or separate SDK redo log is needed. Archive and queue collection
share a 128-coin/soft-4-MiB per-call limit and retain all local ownership checks.

Full-capacity regressions cover digit boundaries, differing scope lengths,
partial-page deletion, overlapping release paths and rollback at each proof,
page, cursor and checkpoint write. Reopening and retrying preserves unspent
originals and counts each deletion once without raising the capacity. New capture,
acknowledgment or release admission can still need space; refusal retains original
financial owners or client retry intent. Older archives require fresh profiles.
The proof-release journal remains format 3.

SDK `a7563f6` passes 27 focused proof-history checks, the full 411-test workspace
suite, all 18 feature profiles and strict lint. The unchanged native CDK
`9fb5b3c5` supplies the previously accepted shared proof/KV transaction. The matching
FIPS graph passes 296 relay tests, strict lint and the sender-retirement process
case: restart and actual expiry preserve original refund proofs and lifetime
spending limits. All 2,730 recorded source/dependency inputs and both process
executable hashes match. These are local test-money and logical SQLite-capacity
results; one opt-in SDK storage soak is excluded. Remaining wallet stores,
sustained aggregate storage pressure, physical disk/power loss and current
hardware acceptance remained outside that checkpoint, which did not configure
service-level capacity.


Incoming-history format 2 commits exact receipt deletion, release of unused native
completion allowance and cumulative received/refund totals in one conditional
SQLite transaction. It removes the pending redo log and retires receipts at full
configured payload capacity. Retained coins stay charged and unrelated storage
reservations remain intact. The caller keeps durable acknowledgment intent until
success; retries cannot count absent receipts again. Earlier journal formats
require fresh profiles under this greenfield scope.

Exact receipt batches and selected proof pages enforce the existing 128-record,
4-MiB stored-payload limits before crossing the SQL driver. Retirement streams the
complete original inputs under the same atomic ownership, spent-state and gross
value checks. Oversized groups retry smaller pages, at most eight reads from 128
inputs down to one; individually oversized or malformed evidence remains an error.
Incoming enumeration and outgoing recovery share native eligibility, replacing
the outgoing SDK's unbounded proof and recovery-record reads. Active-operation
existence checks do not load recovery payloads. Incoming acknowledgment leaves
its input checks to atomic retirement.
Read errors, stale records, failed writes and insufficient checkpoint space retain
the original receipts, coins and totals. These bounds do not cap all database
internal memory or physical storage.

Sender capture now uses the same bounded exact-Y reader for original inputs as
native retirement. Original and created-coin capture both retry smaller groups
without advancing past unchecked inputs. Missing or individually oversized
originals retain the send owners, cursor and wallet evidence.

Native atomic proof comparison now reads at most 128 identities within 4 MiB,
or one larger expected record alone. The production row encoder sizes that
record from the caller's original; stored growth cannot enlarge the ceiling.
Reads are gated before driver projection and decoding. Full typed comparison and
atomic proof/checkpoint rollback remain unchanged.

Exact saved-operation comparisons now share the bounded SQL projection in atomic
proof changes, output preparation, receipt publication, issuance retirement and
withdrawal completion. Production bindings size a larger caller-owned original;
unexpected stored growth cannot enlarge the 4 MiB or original-record ceiling.
Full typed equality, row locking and atomic writes remain unchanged. A required
absent operation is checked without loading its payload.

Initial swap admission and native send/receive/reclaim completion admission now
reuse the bounded proof comparator. Completion sizing retains references to the
verified originals instead of another decoded batch. Duplicate identities, exact
operation ownership and atomic storage claims remain checked. This does not bound
the initial operation or receipt reads used during admission.

Native CDK `ceb17370` passes 408 affected native tests, 14 focused
storage-admission checks and strict lint; SDK `99ed177` passes 411 workspace tests,
all 18 feature profiles and strict lint. The matching FIPS graph passes 296 relay tests,
strict lint and the actual-expiry/restart refund-retirement process. All
2,738 recorded source inputs and both executable hashes match. Local regressions
cover aggregate page overflow, smaller-page progress, late invalid inputs,
full-capacity rollback, reopening/retry and separate fee/refund totals. The outgoing
regression rejects oversized malformed inputs before decoding, preserves the
receipt and coins, and retries after reopening without resetting costs or making
another mint swap. Capture regressions cover oversized malformed originals and
created coins, then restore the records and verify unchanged custody and progress.
Large witness groups split without skipping coins. Atomic-comparison regressions
also retain earlier records and checkpoints when a later page is oversized, and
preserve larger caller-held originals and equivalent JSON encodings within the
read budget. SDK collection still accepts near-limit proofs with a 2048-byte mint
URL and later ownership metadata. Operation-record regressions reject malformed
stored growth before decoding and retain the original coins and checkpoint. They
also preserve larger expected records, stale-record rejection and equivalent JSON
within the read budget. Admission regressions reject unexpectedly enlarged stored
proofs before decoding, retain original proofs and storage allowances, and leave
new operation records, output keys and counters uncommitted. The standalone swap
case also admits a larger expected original. This is local test-money evidence;
one opt-in SDK storage soak is excluded. Initial collection/import reads, ordinary
recovery and two internal storage-reservation reads without an exact old snapshot
remain open,
along with remaining stores, sustained aggregate storage pressure, physical
disk/power loss and current device acceptance.
That checkpoint did not configure service-level capacity.


### Interrupted-send debit evidence

SDK `e69538152a5e` checks a native send's saved confirmation against the
original SDK authorization before recovery can submit another mint swap or
publish its result. It compares the original amount, maximum debit, keyset,
fee policy, memo, spending conditions and metadata, plus the distinct swap and
recipient-retained coin sets. Coin identity includes amount, keyset, secret and
mint signature; order and legitimate signing-evidence changes are allowed.
The previous implementation could spend a valid same-value coin outside the
original authorization before a later custody check rejected it.

The existing interrupted-funding fixture rejects sixteen missing/conflicting
confirmations, preserves both journals and makes no additional mint submission.
Substituted coins remain unspent. Restoring the original confirmation permits an
automatic retry of the unsubmitted operation, followed by recovery after the
successful mint reply is lost. The original source fails with the same fixture.

All 430 SDK workspace tests pass (one existing opt-in soak excluded), as do strict
all-target SDK lint and changed-source formatting. The full suite uses its
documented serial test setting; concurrency within individual cases remains.
FIPS fee-bearing settlement and interrupted funding recovery after route expiry
pass against the same candidate. Exact sources, tested locks, the failing
reproduction and passing results are retained in
`work/paid-relay-verification/2026-09-30-confirmation-inputs`.
No schema, dependency or protocol message changes. This preserves conflicting
authority; it does not reconstruct missing originals or reconcile arbitrary wallet
corruption. The r38 ARM64 package acceptance includes this fix and the same
SDK regression; current-device acceptance remains outstanding.

SDK `d0dae6f2a794` validates the original native debit before publishing an
unfinished numbered-send result. It reuses the existing 4-MiB bounded receipt
reader and checks the operation, amount, mint, sat unit, outgoing primary role,
nonfailed status and original token proofs. Proof order does not affect identity.

The existing fee/recovery fixture reproduced two faults: a conflicting incoming
transaction could complete the request, and an oversized receipt could advance
the SDK journal before a later read rejected it. The expanded fixture now rejects
missing receipts, changed direction, unit, mint or proofs, failed status and
oversized metadata. With the native send already complete, each rejection retains
the native operation and receipt and the pending SDK journal without another mint
swap. Restoring the original receipt recovers the original payment and cost.

The final source passes all 429 SDK workspace tests (one existing opt-in soak
excluded), strict all-target lint, changed-source formatting and whitespace checks.
Native FIPS fee-bearing settlement/restart and interrupted funding recovery after
route expiry also pass against the same source. The offline dependency graph
selects the candidate SDK explicitly; source and configuration fingerprints remain
unchanged throughout each gate. Baselines, patches, tested locks and results are
preserved in `work/paid-relay-verification/2026-09-30-native-debit-evidence`.

No schema, dependency or protocol message changes. Completed SDK results may still
outlive acknowledged native receipt retirement. This preserves uncertain evidence;
it does not reconstruct missing originals, reconcile arbitrary conflicting records
or attribute the historical payment stalls. The r35 package includes this fix
and passes the isolated Linux acceptance above; current-device and physical
power-loss acceptance remain outstanding.

### Missing withdrawal journals

Native CDK `5ff0b4b801ff` preserves withdrawal reservations whose original
operation journal is missing. Preparation saves the journal and reservation atomically, so absence is
not evidence that a payment was never submitted. Startup no longer bulk-loads all
withdrawal quotes or unlocks them on that assumption. A status check rejects a
missing, malformed or mismatched owner before querying the mint or changing
custody. Normal recovery with the original journal remains available.

Two regressions reproduced the old ownership loss/status acceptance. The fix
passes 548 wallet tests, including preservation of quotes across scopes,
original pending proofs and receipts, denial of a second preparation, and correct
completion after the original journal is restored. The existing paged-recovery
regression also forbids bulk withdrawal-quote reads. The full SDK suite passes
413 tests (one opt-in soak excluded), with 296 relay unit tests and the
four-node paid/restart/concurrent-settlement scenario; native, SDK and relay lint
and CDK formatting pass. No public signatures, schema or wire messages change.

This preserves uncertain evidence; it does not reconstruct missing journals or
provide general orphan detection/reconciliation. The ARM64 package below includes
this change and passes the isolated Linux checks below. Physical power-loss and
current-device acceptance remain open.

### Wallet seed and database identity

SDK startup now binds fresh databases to their wallet seed before loading the
wallet repository. File-backed and secure-store reopen checks reject a changed
seed or missing, mismatched or oversized identity; restoring the original
evidence permits reopening. Existing databases without this identity are not
automatically adopted. See the SDK's `docs/wallet-history.md` for the fresh-profile
boundary and backup requirements. The r22 packaged executable includes this check
and passes the twelve isolated Linux process cases below. On a separate unfunded
profile, both its offline wallet command and service startup reject a different
valid seed without changing stored files; restoring the original seed restores
wallet access and the original balance. Current-device acceptance remains pending.
This does not reconstruct lost financial evidence or establish physical durability.

The changed-seed regression fails before the check. Three focused tests cover
file-backed and secure seed stores, missing or invalid identity records, and
reopening after the original evidence is restored. The full SDK workspace passes
423 tests (one opt-in soak excluded), SDK and relay strict lint pass, and all 301 relay
unit tests pass against the same updated wallet source. The process-level paid
settlement/restart scenario and interrupted funding recovery after route expiry
also pass, preserving original charges, refunds and spending bounds.

Startup also refuses a missing main SQLite database when a WAL, shared-memory or
rollback-journal file remains. The check runs under the existing wallet writer
lock, before seed handling or SQLite access, so opening cannot recreate the main
file or alter the surviving recovery files. It adds no dependency, storage field
or protocol message.

The regression reproduces main-file creation before the fix. Its six cases cover
all three recovery-file types with both file-backed and secure-store seeds,
checking unchanged file bytes, an absent main database and unchanged seed stores.
All four focused seed-identity tests and the full 424-test SDK workspace pass
(one opt-in soak excluded). Strict SDK/relay lint, all 301 relay unit tests,
fee-bearing paid settlement/restart and interrupted funding recovery after route
expiry also pass against the same source graph. These tests preserve recovery
files; they do not demonstrate reconstruction of a valid financial WAL after
loss of its main database. The r23 package includes this additional check.
Its unfunded wallet-command and service-startup checks preserve all three remaining
recovery-file kinds, with the seed present and absent, and reopen the restored
original database. Those command-line checks stop at the earlier service profile
preflight; the direct SDK regression above exercises its main-file guard.
Current-device and physical power-loss acceptance remain pending.

Funded service startup now checks the wallet seed and saved receiver identity
before loading seller or buyer journals. Previously, seller recovery could persist
another forwarding allowance before a conflicting identity rejected startup.
The four-process paid restart fixture reproduces that mutation before the fix.
It now substitutes a different valid wallet seed and receiver key in turn, checks
each rejection leaves seller, buyer and controller journals byte-for-byte unchanged,
then restores the original identities and completes restart, bidirectional delivery
and concurrent settlement. Original lifetime budgets and wallet capacity remain
intact, with all 512 test sats accounted for, including mint costs.

The existing funded fixture passes with optional features enabled and disabled;
initialization guards, strict all-target lint, formatting and source-size checks
also pass. The fix only reorders existing validation and recovery: no protocol,
configuration, dependency or journal format changes. It does not make every later
startup failure transactional, reconstruct missing evidence, establish physical
power-loss safety or attribute the historical payment stalls. The r30 packaged
executable passes both the capacity and full-filesystem variants in isolated Linux.

Fresh service manifests now also bind the native payment sender's public identity.
The extended funded fixture first reproduced startup failing to reject another
valid sender key within its ten-second deadline. The service now checks the
validated sender key against the saved public identity before accounting recovery.
Substituting wallet seed, receiver key or sender key leaves the original seller,
buyer and controller journals byte-for-byte unchanged. Restoring the originals
allows restart, paid forwarding and final settlement of all 512 test sats.
Both feature profiles, initialization guards, strict all-target lint, formatting
and source-size checks pass on native macOS ARM64. The fresh-profile manifest is
version 2; no migration or saved-account rewrite is performed. Wire messages,
configuration terms and dependencies are unchanged. The r30 packaged executable
passes this extended check in both isolated Linux storage scenarios. This does not
reconcile conflicting channel evidence or attribute the historical stalls.

Startup also validates saved sender-channel data through the SDK's existing
reader before seller or buyer accounting recovery. Empty or whitespace-only
client files cannot become a fresh SDK store; malformed JSON and unsupported
store contents use the same reader's rejection path. An absent file remains
valid for fresh SDK setup, while the service's funded-profile preflight continues
to require the original file. Restoring original evidence permits reopening.

The existing funded restart fixture now replaces the client data with whitespace
and malformed JSON, checks rejection preserves all three accounting journals,
then restores the original and completes paid forwarding and settlement. The
SDK regression first reproduced empty-file acceptance; the process regression
first reproduced startup failing to reject whitespace within its deadline.
The full SDK workspace passes 424 tests (one opt-in storage soak excluded).
Both relay feature profiles pass the funded fixture, preserving all 512 test
sats, and initialization guards, strict SDK/relay lint, formatting and source-size
checks pass.

The service also retains the sender-file requirement after every completed
funding entry has retired. It uses the existing monotonic funding sequence;
retirement must not make a previously funded profile appear fresh. The extended
real-expiry regression first reproduced startup failing to reject the missing
file within ten seconds. Both relay feature profiles now reject it without
recreating the file or changing any of the three accounting journals. Restoring
the original permits restart, preserves lifetime spending and wallet balance,
and retains the original refund proofs in wallet custody. The ordinary funded
restart, fresh-initialization and strict all-target relay lint checks also pass.
The SDK is unchanged from its 424-test acceptance above.

The r30 package includes these guards and passes both funded storage cases and
the real-expiry retirement case in isolated ARM64 Linux. This adds no wire message
or storage format. It does not reconcile internally consistent conflicting
evidence, establish physical durability or attribute the historical stalls.

### Receipt completion read bounds

Native CDK `9a8e9792f98f` bounds operation receipt publication and final
withdrawal completion by reusing the indexed, bounded receipt reader. The
ceiling is 4 MiB or the larger caller-owned receipt, sized through the
production encoder and allowing status-only completion changes. Unexpected
stored growth fails before SQL payload projection or decoding, without
publishing a receipt or changing the original operation and quote. Large
legitimate receipts, typed conflicts and completed results on pending retries
remain supported. This changes no public API, storage schema or network message.

The regression reproduced decoding of an unexpectedly enlarged receipt before
the fix. The corrected graph passes all 168 SQLite wallet tests, including large
legitimate receipts, typed conflicts, failure without mutation and preservation
of completed results on pending retries. The full SDK workspace passes 413 tests
(one opt-in storage soak excluded), with 298 relay unit tests and the four-node
paid/restart/concurrent-settlement check. Affected native, SDK and relay strict
lint, CDK formatting and source-size checks pass.

Other operation-admission, quote and receipt reads remain separate work. The ARM64
package below includes this dependency change and passes the isolated Linux
transport, restart, settlement and storage-recovery checks recorded below.
Physical power-loss and current-device checks remain open.

### Receipt existence during issuance

Native CDK `4be21741c5eb` checks for an existing issuance receipt by its indexed ID,
without loading or decoding the payload. A normal duplicate or an oversized,
malformed duplicate rejects acquisition inside the same transaction; its saved
receipt, quotes, signing keys and counters remain unchanged. The extended
regression reproduced the unnecessary decode before the fix. This adds no API,
schema, network message or dependency and leaves full receipt reads unchanged.

The corrected graph passes all 168 SQLite wallet tests, the full 413-test SDK
workspace (one opt-in storage soak excluded), 298 relay unit tests and the
four-node paid/restart/concurrent-settlement scenario. Affected native, SDK and
relay strict lint, CDK formatting and the source-size check pass. The SDK tests
run serially. An initial two-worker run missed the refund fixture's 30-second
setup expiry before its recovery race; the unchanged case passed alone and the
full serial suite passed. The failed run remains recorded; this does not prove
an opening-latency bound under concurrent large cryptographic workloads.
Other quote, operation-admission and receipt reads remain open. The r13 ARM64
package below includes this dependency change and passes the isolated Linux
transport, restart, settlement and storage-recovery checks. The r12 cadence
measurements retain their earlier dependency revision; current-device and
physical power-loss acceptance remain open.

### Cross-mint journal admission

SDK `299b273b64f0` caps each cross-mint transfer journal at 4 MiB before database
payload projection and on writes. Before preparing a source payment, it sizes
the completed record with the actual quote IDs and invoice, including result
duplication and maximal later numeric fields. The shared result encoder keeps
admission and completion aligned. Rejection preserves the saved preflight,
original wallet balance and unreserved source quote; admissible large quotes
still complete. Oversized saved records fail without erasing their evidence,
and restoring the original completed record returns the same result without
another payment. No public signatures, record fields or dependency versions change.

The new checks fail on the previous implementation and pass with the fix. The
full SDK workspace passes 414 tests (one opt-in soak excluded), with 298 relay
unit tests and the four-node paid/restart/concurrent-settlement case. SDK and
relay strict lint, edited-source formatting and source-size checks pass. The
whole SDK format check still reports pre-existing differences in nine untouched
files, verified against the baseline; its failed result is retained. These are native
loopback results. The refreshed ARM64 package below includes this SDK change and
passes its Linux paid-forwarding and storage-recovery checks. Transfer counts, native
quote/transaction reads, total storage and physical recovery remain separate
limits; the record-size check does not reserve filesystem space.

### Exact cross-mint payment receipts

SDK `30a6e0d4f17d` binds each transfer to the native source-payment operation ID,
saved before confirming payment and included in completion-size admission.
Recovery uses the existing bounded receipt lookup for that exact operation,
with a 4 MiB stored-payload limit, instead of scanning outgoing history for a
matching quote ID. It validates the completed receipt's operation, mint, currency,
amount, quote, invoice and payment method. No CDK API or dependency changes are
needed. A paid quote without its original operation ID or matching receipt stops
recovery and retains the evidence rather than adopting another operation's fee.

The regression reproduces an incorrect fee when another stored payment shares
the quote ID. It now recovers the original fee and leaves the other receipt
untouched. A missing operation ID or a mismatched, pending or oversized receipt
prevents destination issuance; restoring the original record finishes the same transfer
without another source payment. The full SDK workspace passes 415 tests (one
opt-in soak excluded), alongside 298 relay unit tests, the four-node paid/restart/
concurrent-settlement case, strict SDK/relay lint, edited-source formatting and
source-size checks. Nine unrelated baseline formatting differences are unchanged.
The SDK checks use native loopback; the current ARM64 package includes this
revision and passes the transport, customer and storage cases below.
Other native recovery/quote queries, total wallet growth, physical recovery and
current-device acceptance remain separate requirements.

### Wallet read bounds

Native CDK `1a5f0caa569f` reads pending quotes for the selected mint and
currency, in indexed pages of at most 128 records and 4 MiB of stored payload. Oversized pages
shrink; a single oversized or corrupt selected record fails with evidence intact.
An unrelated malformed quote no longer blocks funded recovery. The local mint
regression recovers 16 test sats from two large records and verifies no duplicate
payout after reopening. This bounds this read path, not mint metadata loading,
legacy bulk listing, SQL engine memory or other wallet workflows. Matching ARM64 package and isolated Linux acceptance
are recorded below.
This revision passes 413 native database tests, the full 413-test SDK suite
(with one opt-in soak excluded), 296 relay unit tests, the four-node shared-wallet
paid/restart/concurrent-settlement scenario, and strict native/SDK/relay lint.

Output preparation bounds stored mint-key JSON before it reaches the SQL driver
or decoder. The ceiling is 4 MiB or the larger caller-owned original encoded by
production bindings. Typed equality, keyset identity checks and atomic ownership
remain unchanged. Rejection retains keys, metadata, counters, recovery records and
reserved space; equivalent encodings within budget and larger known originals
still work, including after reopening at full logical capacity.

Proof-history protection reads only candidate coin identities and creator/spender
operation UUIDs, in batches of 128. A 105-byte per-row stored-column limit precedes
SQL driver projection; malformed ownership rejects the page. This scan does not
decode proof witnesses or other payloads and grants no deletion authority. Full
original comparison, spent-state checks and atomic history deletion remain intact.

Outgoing receipt retirement now releases its completed operation's unused storage
allowance in the same SQLite transaction. Exact receipt, spent-input and inactive
operation checks still guard removal; refund receipts, original coins and unrelated
reservations remain. Failed release rolls back deletion. The sustained workload
reproduced one leaked reservation per completed send before this correction.

Earlier native CDK `e2a9cb49` passed 411 affected tests, five focused history checks and
strict lint. SDK `2f49ee1f` passes its full 411-test workspace suite, strict
all-target lint and the explicit 300-cycle pressure/recovery soak. The matching
graph passes 296 relay tests, relay lint and the actual-expiry, restart and
refund-retirement process. All 2,739 recorded source inputs and both runtime
executable hashes match. Features and dependencies did not change; no new
feature-matrix run is claimed.

The soak's 49.82-second local run reached 4,178 SQLite pages of 4096 bytes and a
20,291,032-byte peak WAL under synthetic pressure. Charged logical bytes were
103,906 at cycle 150 and 102,984 at cycle 300. These measurements do not reserve
physical disk or establish router memory, latency or power-loss behavior.

SDK `ae5250d1` extends the existing 130-channel lifecycle test with fixed 16 MiB
logical wallet limits at both endpoints, eight nonzero payouts and
four full-capacity settlement checkpoints after wallet reopen. Both endpoints
retire completed channels while preserving lifetime costs and refunds. Retained
custody stays bounded by actual coin records; unused reservations do not
accumulate. Its full 411-test SDK suite and strict lint pass. Production files and
dependency pins are unchanged. See the SDK's channel-history acceptance contract
for reproduction and limits.

These checks cover one mint's repeated send/receive overlap, recovery and settled
channel lifecycles at aggregate logical capacity. Broader overlapping channel
workloads, remaining wallet workflows and queries, physical storage/power loss,
current devices and remote deployment remain separate requirements. That SDK
checkpoint did not configure service-level capacity; fresh-profile relay
configuration is covered above.

### Earlier wallet and build evidence

The receive-replay regression first reproduced a collected spent token creating
another pending receive after its swap was rejected. Native admission now checks
unfamiliar coins through NUT-07 before acquisition. The replay adds no coin or recovery operation,
submits no swap and preserves the original wallet and lifetime costs. Malformed,
pending and unavailable state replies also stop acquisition. Submitted receives
keep their original ambiguous-error recovery; there is no new FIPS message or
per-coin tombstone. All 817 native CDK library tests pass, including 23 receive and
recovery cases. See the SDK `wallet-history.md` steady-state check for reproduction.
The matching graph also passes the full 374-test SDK workspace suite, strict
native/SDK lint and the real relay-process restart/retirement case. All 2,678
fingerprinted source/dependency inputs and both runtime executable hashes remain
unchanged through that process test. Previous accepted executables are preserved
separately. This is local test-money acceptance; no device or physical power-loss
acceptance is added.

The HTTP receiver also restores committed close outputs after a lost mint reply,
without depending on a swap replay cache. SDK regressions cancel the receiver
call after the real test mint commits, reopen the receiver, and recover its exact
payout and refund without another swap. They cover two intervening key rotations,
an empty active-key cache, truncated replies and invalid signatures; every case
conserves all 64 test sats. Restore failures retain the closing record and its
reservation. This exercises cancellation and reload, not physical power loss.
Mint restore support and retained historical signatures/keys remain requirements;
custom sync and JavaScript networking adapters still use their existing replay
hooks. See the SDK receiver recovery contract for those limits.
That receiver-close revision passed 117 native-library tests, the full 371-test
SDK workspace suite, all 18 SDK feature profiles, 295 relay unit tests, five
opening recovery process cases and the payout/refund crash case, with strict
native, SDK and relay lint. These results do not accept a new hardware deployment.

The source bundle at `3ad12adf7bd` includes SDK `ce8c0e0e874b` and CDK
`dd45a9c0861b`, contains 36,077 inventoried files and resolves 697 packages,
including 676 vendored registry packages. All 2,783
recorded source/dependency inputs match the accepted native graph, with the
explicit tested root lockfile substituted for the portable development lock.
The relocated bundle builds offline with Rust 1.96.0, Zig 0.15.2 and
cargo-zigbuild 0.22.1, using empty Cargo homes and new target directories. Build
sandboxes deny network access, original repositories, the registry cache and
previous build outputs. Exported revision metadata does not inherit the unrelated
parent repository. See the
[bundle workflow](FUNDING-COSTS.md#portable-development-source-bundle).

Its default-feature `aarch64-unknown-linux-musl` OpenWrt executable is 25,201,920
bytes, static and stripped. The unsigned APK is 11,536,408 bytes. Package integrity
and all 11 payload hashes verify the executable, exact source metadata, root
ownership and disabled default configuration. The builder rejects a mismatched
architecture. The executable starts in isolated ARM64 Linux; no package is
installed on a router.

The same packaged executable passes four expiry recovery process cases with the
matching funding harness. A killed buyer's used channel spans two destinations;
the seller collects a positive retained payment and retires without acknowledgment.
The buyer later restarts with the seller offline and restores its original refund.
The missed-collection case instead stops the seller until the buyers have recovered
their refunds after original expiry. Seller recovery verifies zero collection
while retaining accepted signed credit; retirement and buyer restart preserve
original obligations and lifetime limits. Both shared-channel cases reconcile all
512 test sats including fees. The separate interrupted-opening case conserves
384 test sats without replacement funding or route activation. The retirement
case waits for completed funding entries to retire, removes the saved sender
channel file and requires startup rejection without journal changes. Restoring
the original permits restart while preserving lifetime spending, balance and
refund proof custody. All four use the actual expiry clock and preserve source,
harness and daemon hashes. Reconciliation of missing or conflicting financial
evidence, physical power loss and current-router acceptance remain open.

The current packaged executable passes five mixed-transport process cases in
isolated ARM64 Linux: UDP-to-TCP, and UDP-to-WebSocket using configured peers,
URL-only plaintext bootstrap, ordinary TLS and explicit FIPS-authenticated
self-signed TLS. A separate harness with optional relay features disabled starts
the real default-feature production executable.
Each case verifies unpaid denial, paid delivery, allowance exhaustion, renewal,
middle-relay crash/restart, paid delivery after recovery and settlement conserving
all 384 test sats. The three seeded WebSocket cases also interrupt the physical
stream while every service stays running. Fresh authenticated connectivity,
bidirectional delivery and a new cumulative payment recover through the original
channels, preserving funding history and spending limits. The plaintext seed
also recovers from silent loss on retained sockets. The three seeded cases keep
the carrier unavailable across the middle-relay restart, require repeated rejected
reconnects without new funding or restored spending allowance, then recover fresh
authentication and paid traffic after the carrier returns. After that crash,
all five carrier cases automatically replace channels consumed by retained
crash exposure before the fixed round-trip cohort. The old exposure remains
recorded and unbilled, and the original spending limits stay in force. The TLS
cases reject untrusted issuers, wrong server names or forged handshake signatures
according to the selected policy before admission or spending. The source
manifest, harness and executable hashes remain unchanged.
All five containers use a read-only root, no external network or capabilities,
and only the two executables mounted from the host; all are removed afterward.
A sixth mixed-transport case runs the opt-in repeated-renewal fixture against
this exact packaged daemon. Eight automatic replacements preserve funding
identities and spending limits. With one shared-provider close reply held, the
other buyer advances paid credit before both signed settlements become pending;
final collection conserves 384 test sats. This adds finite ARM64 Linux acceptance,
not sustained hardware performance or attribution of the older stalls.
See the [TCP/WebSocket reproduction steps](openwrt/README.md#tcp-websocket-and-tls-with-the-packaged-executable).
The initial r13 attempt exposed an invalid snapshot assumption: automatic
recovery renewal can refund or replace a channel while aggregate counters are
being compared. The current fixture keeps renewals enabled throughout restart.
It preserves every original funding record and purchase, permits at most one
bounded replacement per buyer, and checks exact budget arithmetic, spending
limits and nonincreasing lifetime allowances. All five cases require
that replacement to occur. After settlement, each buyer's actual wallet balance
reconciles with its recorded exposure, alongside total fund conservation.
All five cases pass against this packaged executable. The source bundle now
includes the corrected fixture, so reproduction builds the harness and daemon
from the same archive. A later native configured-WebSocket repeat exposed
another fixture race: a small recovery warmup could leave the automatic replacement
until after the stable-history snapshot. Every carrier now sends the same 512-byte
recovery warmup and waits for that replacement before the fixed cohort. Both
failures remain recorded; these fixture corrections change no runtime policy,
timer or payment protocol.

The same package passes both customer entry-restart cases in isolated ARM64
Linux. The customer harness keeps its client running while the packaged entry
process is killed and reopened. Two fresh traffic cohorts deliver
and advance automatic payment without another purchase command or manual flush.
Original identities, profiles, purchases and spending limits survive; settlement
collects all 384 test sats per tariff with positive entry earnings. The harness,
daemon and source-manifest hashes remain unchanged, and both owned containers are
removed. See [customer recovery](openwrt/README.md#customer-entry-restart).

These passes do not explain the earlier intermittent delivery timeout or establish
radio performance, remote TLS deployment, physical power loss or current-device
acceptance.

The same current package passes the four-node funding/recovery fixture
in ARM64 Linux, including concurrent incoming and outgoing settlements. A separate
all-features test harness provides the local mint and test wallets; each child relay uses the default-feature OpenWrt binary.
Both the logical-wallet-limit case and the real Linux ENOSPC case pass, including
paid delivery after restart, original-channel settlement, fund reconciliation and
unchanged lifetime spending limits. In the latter case, only the transit relay's
128 MiB tmpfs fills; controller persistence and a SQLite write fail, startup
refuses the full volume, and freeing the test ballast permits recovery with the
original proofs. These are actual Linux process and filesystem errors, not flash
power-loss or OpenWrt service supervision checks. The container has no external
network, a read-only root, no capabilities and only the executables mounted from
the host. See the [process recovery recipe](openwrt/README.md#production-executable-and-storage-recovery).

The earlier `d75aae457` bundle's separate all-features routing harness passes
loss, delay and combined loss/neighbor-churn scenarios on ARM64 Linux. Native
feedback moves the purchase away from an impaired route and back to the recovered
cheaper provider. New paths first receive bounded trial agreements, and the
original channels survive reuse and controller/selector reload.

In the combined scenario, the healthy alternative leaves while the original
forward path still loses 35% of packets. The source falls back to that remaining
path, delivers traffic and advances payment on its original channel. When the
alternative rejoins, it also delivers and advances payment without refunding or
rebuying either account. Only the original two 64-sat channels are funded; the
source's wallet debit and locked capital remain 128 sats. The cheaper path is
then restored and selected again. Settlement conserves 259 test sats in each
scenario, 777 across all three.

These checks run real controllers and native FIPS feedback over simulated links.
They do not exercise the packaged daemon, physical radios or arbitrary network
topologies. Source-manifest and harness hashes remain unchanged afterward. Test
completion times do not establish router performance or optimal monetary routing
for every topology.

The fee-bearing process fixture sends SIGKILL after seller payout import and
again after buyer refund completion, before each controller records completion.
The buyer stays stopped during the seller restart, so ordinary seller upkeep
must record its original settlement without a peer retry. Read-only SQLite
observations preserve every original unspent proof row for the fixture mint/unit,
including the exact payout and fee reserve. The later receiver-close result must
contain precisely the payout coins captured at the crash, and those same wallet
rows survive actual-expiry history retirement.

Buyer restart retrieves that report and recovers the original refund. A second
buyer kill at its wallet/controller handoff leaves a spendable refund with
unfinished controller flags. Ordinary restart completes refund accounting and
both settlement-release acknowledgments before any administrative retry. The
original funding operation, channel, report, signed payment and lifetime debit
remain exact; neither payout nor refund is credited twice. A shared private
`testbench`-only barrier selects the stage and exact channel; no financial journals
are edited and no wire, admin operation or dependency is added. Reproduce with the corrected
dependencies using `cargo test -p fips-relay --all-features --test funding_costs
paid_fees:: -- --test-threads=1`.

Automatic renewal now has a three-daemon regression using that same refund
barrier. It kills the buyer after its wallet commits the refund, stops the
provider, then restarts the buyer alone. Ordinary upkeep records the refund
without duplicate credit or replacement funding while release remains pending.
After a second buyer kill and both peers restarting, the retained renewal
finishes with exactly one replacement channel. The original funding operation,
report, signed payment and policy survive; fresh payload delivery and automatic
payment on the replacement precede final settlement. Both spending limits remain
enforced, the remaining signature budget matches the settled payments exactly,
no capital remains pending or locked, and wallets plus mint fees total 384 test
sats. The native process case passes with all features and with measurements
disabled. It adds no runtime behavior and does not explain historical stalls or
establish physical power-loss recovery. Using the matching
[dependency overrides](FUNDING-COSTS.md), reproduce with:

```sh
cargo test --config /path/to/local-dependencies.toml -p fips-relay --all-features --test funding_costs renewal_refund_restart:: -- --test-threads=1
cargo test --config /path/to/local-dependencies.toml -p fips-relay --no-default-features --features testbench --test funding_costs renewal_refund_restart:: -- --test-threads=1
```

An unsubmitted preparation now cancels locally using its exact native authority.
The three-daemon regression kills the source after its plan is saved, changes the
mint keyset, then kills it again after wallet cancellation but before the relay
records completion. Ordinary restart and original-expiry retirement release the
reservation without replacement funding. All 384 test sats remain spendable,
the original coin rows are unchanged, and swaps, fees, debits and refunds remain
zero. Submitted sends still recover and revoke their original token with its
actual costs. Missing or conflicting native evidence keeps the reservation.
The matching source graph passes all 293 relay library tests, five pre-opening
process cases, the payout/refund crash case and strict all-target relay lint.
The wallet SDK passes its full 349-test workspace suite and strict lint.

New SDK requests and scopes reserve room for every unfinished request to reach
its existing 64-KiB record cap, plus lifetime-counter growth, within the existing
4-MiB journal cap. Pressure rejects new sends before coin reservation while
previously admitted sends still finish after reopening.

Each request also derives an input-proof byte allowance from its remaining record
space. The native wallet checks the serialized input array before saving the
operation or reserving coins, and again before confirmation. Both planned and
unplanned original authority fit alongside a cancellation outcome. Before any
spend, the SDK measures the retained token and reserves a conservative 1 KiB per
new plain token proof. Native proof-count checks cover the actual fresh split,
including keyset changes. Insufficient result space cancels the original
unsubmitted preparation and saves that outcome before releasing native evidence.
The existing record and journal caps are unchanged.

SDK `ea844ded` passes all 356 workspace tests and strict all-target lint; all
1,583 recorded inputs match its focused regression and encoding checks. CDK
`6de0a7ca` passes 425 affected send/shared/binding tests and strict all-target
lint. The five FIPS pre-opening process cases and payout/refund crash case also
pass with this exact dependency graph; all 2,606 recorded source and dependency
inputs match. These are logical send-record bounds. Initial native proof
enumeration, coin selection and denomination allocation remain separate, as do
the full wallet database, custody archive and physical disk space.

SDK `28c591d3` additionally pages outgoing receipts during cancellation recovery
and retirement, using the existing mint/unit/direction index with limits of 128
rows and 4 MiB of stored payload before decoding. Retirement keeps candidates
from one page at a time. Oversized evidence fails without skipping the record or
changing coins; restoring that record permits the original request to recover.
All 357 SDK workspace tests and strict all-target lint pass. The five FIPS
pre-opening cases and payout/refund crash case pass again against this dependency
graph, with all 2,606 recorded inputs unchanged. Paging bounds receipt-scan memory,
not full traversal time or total storage. Unfinished operations are covered below.

These process kills do not simulate loss of writes already acknowledged by
physical storage. Reconciliation of missing evidence, sustained aggregate storage
pressure and current-build hardware acceptance remain separate requirements.

SDK `b08ab23` bounds recovery of temporarily empty mint restore replies to three
lookups under the existing deadline, without another funding submission. CDK
`8b81aad7` fixes fee-split recursion that could overflow the stack and uses scalar
output counts while searching for a sufficient total. All 357 SDK and 1,719
native library tests pass, along with strict all-target lint. The five FIPS
pre-opening cases and payout/refund crash case pass on the combined graph; all
2,610 recorded source/dependency inputs match.

## Wallet planning bounds

CDK `b1bc86e6` and SDK `24b4247` cap each new mint or swap at 4,096 outputs,
including payment, change and every quote in a mint batch. Native scalar planning
checks the budget before creating secrets or advancing derivation counters.
Direct sends reuse existing coins, and submitted operations recover their
original outputs.

New send, melt and refill planning also admits at most 4,096 unspent proofs and
4 MiB of stored inventory payload per exact mint/unit scope. One indexed SQLite
statement checks both budgets before returning payloads for decoding. It returns
the complete selected inventory or an error; it does not truncate, skip corrupt
selected records or scan unrelated spent history. Send and melt selection reuse
that inventory's original derivation metadata instead of reading it again.
Already-submitted operations retain their original recovery inputs and outputs.

All 950 affected native, SQLite and binding tests, 358 SDK workspace tests and
strict all-target lint pass. The five FIPS pre-opening cases and payout/refund
crash case pass on the combined graph; all 2,620 recorded inputs match. These are
new-operation planning limits. Other wallet queries, individual recovery/result sizes,
total wallet/SDK/custody storage and physical disk reservations remain separate.

Sender plans retain denomination counts and share proof matching. A matched
local unoptimized planning measurement reduces a 65,536-entry buffer from 512 KiB
to 64 bytes. Small binary-denomination plans use 64 extra bytes, with lower
measured planning time. These figures describe the temporary plan, not full-send
memory or router performance.

## Client storage admission

Spilman `2c6c916` and SDK `8a98b94` add a 32 MiB client-file budget covering
stored bytes and reserved completion space. Wallet admission reserves space before
sending coins; saved openings use their original denominations to bound later
funding/refund proofs. Full future issuing-key metadata, payment/closure records
and lifetime retirement growth are included. Verified completion releases unused
headroom. Uncertain operations retain it, and bounded reads do not truncate or
evict evidence. The existing individual record and refund limits remain.

Both native token-opening paths now consult storage before mint submission.
Raw pending terms persist separately, and completion must match them. This adds
no peer messages; raw reservations alone do not add an automatic recovery workflow.
The relay continues to use the SDK's recorded opening and recovery paths. The SDK
also fixes a feature boundary so retirement can verify cancelled sends without
requiring its HTTP opener.

A test-mint storage-pressure case holds an admitted wallet send while other
reservations fill capacity. That send completes and reloads, new wallet/token
opens leave the original coins unchanged, and an existing refund completes after
a keyset change. All 361 SDK workspace tests, strict all-target lint and 18
production feature profiles pass. Native admission has 109 passing library tests
and strict lint. The five FIPS pre-opening process cases and payout/refund crash
case pass on the combined graph; all 2,624 recorded source/dependency inputs match.

The [24 September loopback cadence matrix](CADENCE-RESULTS.md#accepted-client-storage-budget-comparison--24-september-2026)
also passes on this graph: all 285,696 payloads arrive, all 40,960 test sats are
recovered and idle payment work remains zero. It measures fresh-profile CPU and
logical relay-journal/carrier costs; it does not isolate the added storage checks
or measure total disk writes. The 500-ms default remains unchanged.

This accepts fresh-profile logical client storage admission. It does not allocate
disk blocks, establish process memory or router capacity, bound the whole wallet
and custody archive, or accept the current build for hardware deployment. The
budget can reject new work before the 128-record ceiling. See the SDK's
`docs/wallet-history.md` for the storage contract and remaining ownership bounds.

## Wallet history enumeration

Proof-history transaction ownership uses bounded native pages across all mints,
units and directions, retaining only current candidate identities. Owners beyond
the first two pages and oversized evidence remain covered during collection and
interrupted-deletion recovery.

Unfinished operations now use pages of at most 128 creation-time/UUID headers,
loading one original recovery record at a time. Native recovery, pending send/melt
enumeration and SDK cancellation share this reader. A single header defers coin
collection without decoding recovery payloads. Global cancellation discovery still
rejects later duplicate or foreign preparations. Deleted cursor rows remain valid;
corrupt reads stop the scan without skipping evidence.

SDK `8174382` and CDK `8ccc0ac5` pass all 365 SDK workspace tests, 658 native
wallet/SQLite checks, seven focused pagination checks and strict all-target lint.
The real FIPS channel-retirement/restart case passes with all 2,636 recorded inputs
unchanged. PostgreSQL compilation passes; Supabase coverage uses mocked HTTP.
Neither is a deployed-server runtime acceptance claim.

Paging does not cap individual admitted recovery records, accumulated result lists,
full traversal time or total wallet/custody storage. The SDK keeps its existing
writer/money locks across scans; native recovery can complete earlier operations
before a later read fails. See [history ownership](HISTORY.md).

## Recovery record read bounds

SDK `f6c77c8` and CDK `1da778a6` enforce existing recovery-record limits before
payloads cross the SQL driver boundary. Byte counting and conditional payload
selection share one statement snapshot. Malformed stored values return errors,
not missing records. Redb checks its borrowed value before copying it; backends
without this contract return an unsupported error without an unbounded fallback.
Foreign database callbacks forward the same limit.

Send-request, incoming-receipt and proof-release journals keep their 4 MiB limits.
Custody registry, page and redo-log reads retain limits of 1 MiB, 4 MiB + 16 KiB
and 24 MiB. Archive read and write validation share their limit definitions.
Rejected reads leave financial evidence unchanged; restoring the original record
allows interrupted custody transfer to finish.

Four native boundary checks and two SDK recovery regressions pass, along with all
1,442 native tests, all 367 SDK workspace tests and six real FIPS funding/refund
process-crash cases. All 2,660 recorded relay source/dependency inputs match.
Strict native, SDK and relay lint, formatting, the source-size gate and PostgreSQL
compilation pass. PostgreSQL runtime and custom backend support are not accepted.

SDK send-operation reads used by request recovery, cancellation, reclaim
and sender-proof capture reuse SQLite's existing 4 MiB bounded reader. Discovery
after a lost preparation preview now shares that bound through native
`IncompleteSagaReader::next_with`. Pagination, identity validation and retry
position stay in the shared iterator; no database trait method, schema, dependency
or protocol message is added. Native recovery's default reader remains unchanged.

The file-backed public cancellation regression covers oversized, malformed and
missing originals with and without a saved preview. The request journal, reserved
coins and remaining native evidence stay unchanged on rejection. Restoring the
original allows cancellation and a safe repeated call. Before the discovery fix,
the oversized original was loaded and the request journal changed before the
later exact-read bound rejected it. Shared iterator tests also retain the cursor
after a loader error or an identity mismatch, then resume the same original.

The matching graph passes 412 native shared/storage tests,
28 focused send tests, the full 418-test SDK workspace suite (one opt-in soak
excluded), strict native/SDK lint, 301 relay unit tests, fee-bearing paid
settlement and interrupted funding recovery after route expiry. Formatting and
source-size checks pass. All use the matched local source graph and test money.
The r20 ARM64 package includes both the exact-read bounds and the discovery
extension, and passes twelve isolated Linux process cases. Current-device
acceptance remains pending.

The service now also configures SQLite's individual-operation read policy at
4 MiB whenever it opens the wallet. Native paged recovery, pending-melt scans and
exact send-confirmation recovery therefore use the same bounded SQL reader after
SDK reconciliation. Explicit record budgets cannot raise the configured limit.
CDK's unconfigured default remains unchanged; this adds no database trait method,
schema, protocol message or dependency. The existing file-backed cancellation
regression now exercises native recovery too: oversized or malformed originals
fail before processing, retain the journal and reserved coins, and recover after
the original is restored. Repeated cancellation remains safe. SQLite boundary
coverage includes exact-sized reads, a one-byte overrun, stricter explicit
budgets and independently configured handles.

The same configured policy checks new operation writes and projected completion
before financial submission. It shares native storage-capacity projections for
receive, send (including its final token), reclaim, standalone swap and both
withdrawal stages. Longest state/scalar encodings and worst-case payment-proof
escaping are included; issuance retains its exact original request. Native size
regressions reproduce the case where preparation fits but completion exceeds the
read limit. A real wallet receive rejects such a plan before mint submission,
keeps its original coins and counter, and completes a smaller retry.

The matching graph passes 184 shared SQL/SQLite tests, three native receive
storage tests including rejection/retry, the full 418-test SDK workspace suite
(one opt-in soak excluded), 301 relay unit tests, fee-bearing paid settlement
and interrupted-funding recovery after route expiry. Strict native, SDK and relay
lint and source-size checks pass. Native workspace and changed SDK source
formatting pass; the SDK-wide format check retains pre-existing differences in
nine unchanged files. PostgreSQL has compile/lint coverage only; runtime
acceptance uses SQLite and local test money.

Internal completion and output-key storage admission now apply the configured
limit when loading their saved parent. Exact transactional comparisons also clamp
their caller-sized budget to that ceiling. All use the existing bounded SQL
projection; the duplicate default operation reader has been removed. Three
file-backed regressions reproduce the earlier bypasses, reject oversized valid
and malformed records before decoding, preserve parent/proof/reservation/counter
state, and complete after restoring the original.

The matching graph passes all 187 shared SQL/SQLite tests, the full 418-test
SDK workspace suite (one opt-in soak excluded), fee-bearing paid settlement and
interrupted-funding recovery after route expiry. Strict native lint, including
PostgreSQL compilation, and native workspace formatting pass. Runtime acceptance
uses SQLite and local test money; SDK and relay executable sources are unchanged.

Legacy bulk enumeration retains its existing behavior. Record admission does not
reserve physical storage or grant spending authority. The r21 package includes
both configured-read extensions and passes the isolated Linux process cases.

These bounds cover individual records crossing the storage interface, not SQL
engine memory, total wallet/custody capacity, uncapped SDK stores or other native
recovery payloads and results. Current-device and physical power-loss acceptance
remain open; no hardware services changed.

Prepared-send recovery now bounds every coin reserved by the saved operation
before confirmation. The original plan sets the row count; the same 4 MiB ceiling
as its complete native preparation bounds stored payloads. The SQL query shares
the existing inventory reader, probes one extra owner to reject overflow, and
includes every mint, unit and state. It does not silently select only expected
identities or truncate results. No database trait, schema, dependency or peer
message changes.

The real-mint regression fails on the old code, rejects oversized, malformed,
missing or changed coins and an extra foreign/spent owned coin without spending
or changing original evidence, then completes the same send once after restoration.

Native withdrawal recovery now shares configured 4-MiB aggregate reserved and
selected-proof reads. Admission measures original and future replacement rows
through the production encoders before spending, including later ownership
metadata and distinct change outputs. Oversized inventories produce one error
row instead of projecting every rejected payload. The real-mint regression
rejects corrupted originals before and after a preparatory swap, preserves the
saved operation and ownership without new spending, and completes the same
cancellation after restoration without reviving spent coins.

History collection uses an explicit 8 MiB + 16 KiB stored-byte allowance for the
admitted proof, its parsed spending conditions and mint/provenance framing.
This does not change ordinary withdrawal read limits. Existing near-limit
collection regressions cover large derived conditions and later metadata;
oversized or malformed witness growth retains the original and release journal,
and collection resumes after restoring the original. No database trait, Wallet
API, schema, dependency or peer message changes.

All 190 shared SQL/SQLite tests, 420 SDK tests (one opt-in soak excluded), 301 relay
unit tests, fee-bearing paid settlement, interrupted-funding recovery after route
expiry and seeded WebSocket restart/recovery pass. Strict native, SDK and relay
lint, native workspace formatting and changed SDK formatting pass. PostgreSQL
has compilation coverage only. These checks use local test money. The r21 package
includes these read-bound extensions and passes the isolated Linux process cases.
Other wallet stores and queries, combined interrupted transitions, physical storage
capacity and current-device acceptance remain open.


## Native mint response bounds

Wallet funding and recovery use a 4 MiB response-body limit in both native HTTP
backends. Raw, JSON and HTTP error replies share the same read path; oversized
length headers fail before waiting for a body, and chunked responses are counted
incrementally. Size failures are excluded from automatic payment-request replay.

The test-mint regression rejects an oversized committed swap reply and a later
oversized restore reply after reopening. It preserves the original financial
intent and coins, then restores the full balance with one swap submission total.
Recovery's normal version fence may advance while its financial intent remains
unchanged. Both backend suites cover headers, chunked overflow, the exact limit,
error statuses and a successful request after rejection.

CDK `255c9cba` with bitreq `f22cf3e` passes 63 bitreq and 62 reqwest tests,
including documentation tests, plus strict lint. SDK `3acb5e8` passes its full
374-test workspace suite, all 18 feature profiles, strict lint and formatting.
The matching FIPS graph passes 295 relay tests, five opening-recovery process
cases, the payout/refund crash case and automatic adjacent-router payments,
plus strict lint. All 2,674 recorded source/dependency inputs match those runs.

These bounds cover native HTTP body bytes. Decoded heap use, total request time,
other transports, aggregate wallet storage and current-device acceptance remain
separate. No router or production wallet is involved in these checks.

## Atomic issue ownership

CDK `150a422b` saves the initial issue journal, every exact mint-quote reservation
and canonical pending receipts in one transaction. Single and batch preparation
share this boundary after output planning and signing. Conflicts cannot leave a
partially owned batch; an uncertain commit reply retains any committed evidence.

The checkpoint holds the original unreserved quotes, every original secret and
its individual derivation index, payment method, signed request and precomputed
compatibility signatures. Normal submission and recovery use this one copy.
Advancing the shared counter, using conditioned secrets or losing external
signing keys after preparation cannot change the original request or coins.
Restore responses must cover every original output and are reordered before
unblinding. Missing or invalid checkpoints, stale journals and conflicting quote
ownership stop recovery before mint contact. Debug output redacts bearer secrets
and quote signing keys.

Completion checks the unchanged journal, all owned quote snapshots, original
proof records and canonical receipts in one transaction. It publishes verified
outputs, completes receipts, sets the original issued-amount targets, releases
quotes and deletes the journal together. Existing output records retain later
spent/reserved states, owners and evidence; a concurrent change rejects the whole
completion. A status refresh that already observed issuance cannot cause another
credit. Newer deposits and other quote metadata survive. Delayed normal replies
and recovery attempts cannot overwrite coins after another recovery completes.
Prepared cancellation marks existing pending receipts failed without publishing
coins; a stale prepared snapshot cannot cancel submitted work. Startup and
quote-status refresh retain mint reservations whose journal is missing.

Batch-size rejections and transport failures retain the original batch for
replay or restore, without fresh individual requests. A rejection cannot rule
out an earlier or concurrent successful submission. A mint that permanently
rejects the original batch still needs reconciliation or safe original-output
repartitioning; this change does not provide that mechanism.

Forty-four focused checks cover acquisition/completion conflicts, write rollback,
receipt identity, original output ownership and concurrent recovery. Native race
cases pause both at the mint response and immediately before the database
transaction, covering normal/recovered single/batch issues with later spent or
reserved coins. All 658 native wallet/SQLite checks, 91 SDK wallet checks and the
single/batch optional signing-key refresh test pass. Five FIPS interrupted-funding
process cases and the payout/refund crash case pass on the same graph; all 2,656
recorded inputs match. Formatting, source-size checks, native and relay strict
all-target lint, and PostgreSQL compilation pass. PostgreSQL runtime is not
accepted here. Custom backends, including Supabase, must implement the complete
atomic acquisition and publication contracts before issuing; there is no
sequential fallback.

This accepts original checkpoint recovery and atomic issue publication on the
tested source graph. The format targets fresh profiles; records without original
evidence fail closed rather than inventing replacement secrets. Melt orphan
cleanup, total storage bounds, current hardware acceptance and production
readiness remain open.

## Authenticated adjacent neighbors

The opt-in service setting `"neighbor_admission": "authenticated_adjacent"`
admits bounded payment control from currently connected, authenticated FIPS
neighbors without a payment-control roster. The default is `"configured_only"`.
Native Ethernet beacons and automatic connection are configured separately in
`transports.ethernet`, with explicit `discovery`, `announce`, `auto_connect` and
`accept_connections` flags on each intended interface. Control admission does
not enable transport discovery. Account initialization still uses loopback.
Other discovery mechanisms remain disabled.

Quote, acceptance and payment ports share one admission object. Unconfigured
peers have eight ordinary active exchanges and eight reserved for locally verified
financial counterparties. Each pool has its own burst of 80 requests and refills
at 320 requests/second. The per-identity limit remains four exchanges across both
pools, all ports and both directions; directional request buckets and existing
quote-service limits remain 16 requests with 10/second refill. Each pool has
64 identity-budget slots, for a combined bound of 128. Only idle, fully refilled
records may be reclaimed. Reconnection, financial eligibility changes and
controller reload cannot reset a retained bucket. Core peer, link, handshake,
session and TCP connection limits also apply.

Reserved capacity follows funded outgoing intents, verified incoming agreements
(including prepared/stopped routes), and retained seller channel terms. The
controller publishes this bounded membership view after a successful journal
write and reconstructs it on validated reload. It remains available for payment
and settlement retries until existing financial-history retirement removes the
records. Unfunded requests, watches, free grants, advertisements and request
contents cannot grant it. Automatic binding covers all three control ports and
rejects a service belonging to another endpoint. No wire messages, configuration
switches or spending permissions are added.

An advertised identity or a routed session does not establish adjacency.
Membership is checked again before an unsent request connects and before an
incoming record reaches its handler. Disconnection does not cancel dispatched
financial work, release channel capital or reset lifetime spending. Explicit
source purchases and verified onward funding keep their existing authority.
UDP customers in the configured customer network remain inbound-only unless
explicitly listed as neighbors.

Admission and revalidation now use futures owned by the bounded pending request
or TCP exchange. The shared transport loop polls each check without waiting for
its native adjacency lookup; dropping its owner immediately cancels the check.
The original permit remains held during revalidation. Waiting for connection
capacity requires another check before connecting, and completed records are
rechecked before dispatch. Existing queue, connection, identity and rate limits
are unchanged; no worker, protocol operation, configuration field or dependency
is added.

A real loopback TCP/FIPS regression pauses the native node's status loop while
configured control still works. Before this change, starting an unrelated
adjacency lookup prevents that configured exchange from completing until the
lookup is released. With the change, it completes while the lookup remains held;
releasing the lookup still rejects the unknown identity. All 16 admission tests
and 12 control-transport cases pass in both feature profiles, as do both existing
paid-route saturation cases under incomplete requests and half-open handshakes.
The mixed UDP/TLS process case conserves all 384 test sats; strict all-target
lint, formatting and source-size checks pass. This identifies an independent
control-loop blocking defect, not the cause of the older intermittent stalls.
The r27 package includes this change and passes the thirteen isolated Linux
process cases above. Current hardware acceptance and attribution of the older
stalls remain open. Reproduce the focused case with the library filter
`control_transport::admission_delay_tests::` and the matching dependency overrides
in [FUNDING-COSTS.md](FUNDING-COSTS.md).

The aggregate rate accommodates the request count of 16 neighbors paying in
both directions at 250-ms intervals, with bounded additional control traffic.
This is a capacity calculation, not a latency or hardware throughput guarantee.
Multiple hostile identities can still compete within each pool; funded or
recently retired counterparties can occupy reserved resources. These limits do
not promise Sybil-resistant fairness, newcomer progress, or protection from
exhaustion by eligible TCP peers, native session overload, radio contention or CPU load.
Mobile Wi-Fi merge/split and router/Pixel acceptance remain separate checks from
authenticated-link control admission and the Ethernet fixture below.

The `priced_paths::control_saturation` regression uses three automatically
discovered SimNetwork routers and two additional authenticated neighbors with no
wallets or controllers. Each attacker holds four incomplete TCP/FIPS records.
Before the reservation fix, all 12 fresh data payloads arrived but the automatic
payment stalled for the five-second observation window; it recovered after the
streams were aborted. With the fix, three batches deliver all 36 fresh payloads
and advance cumulative credit while all eight attack permits remain held. The
original channel also settles under that load. Every wallet receives its exact
purchase/earnings balance and all 768 test sats are collected. Fresh stream checks,
active permit counts and a hold age below 25 seconds prevent the 30-second
exchange timeout from satisfying the test. Explicit aborts release every permit
before attacker shutdown. All 232 relay library tests, 12 control-transport tests
and 17 priced-path scenarios pass with both reservation boundaries. Strict
all-target relay lint, formatting and the 769-file size check also pass. This is a bounded
incomplete-record attack in software,
not a hardware flooding or fairness result. Reproduce with `cargo test -p
fips-relay --all-features --test priced_paths control_saturation:: --
--test-threads=1 --nocapture` using the dependencies in
[FUNDING-COSTS.md](FUNDING-COSTS.md).

The TCP/FIPS connection table also reserves eight of its existing 32 slots per
control port for configured neighbors or counterparties in that same current
financial projection. Ordinary new tuples require fewer than 24 retained
connections; eligible peers may use the full 32, and every identity still has a
four-connection cap. The generic stack applies this rule before allocating an
incoming half-open handshake or an outgoing connection. Existing tuples continue
normally after eligibility changes. It adds no messages, priority claims on the
wire, eviction policy or connection-state migration. The reservation is installed
before driving traffic; application adjacency and request checks still follow.

The companion SYN-only regression offers 32 handshakes from eight newly
authenticated neighbors without wallets or payment records. Before this fix,
all 32 receive SYN-ACKs and retain their tuples, all 12 fresh data payloads arrive,
and automatic payment stalls for five seconds. Resetting the tuples restores
payment and permits exact settlement and collection of all 768 test sats. With
the fix, only 24 tuples remain held, all three fresh 12-packet batches deliver
and advance credit, and settlement completes while that load remains active.
The existing incomplete-record case passes as well. This checks retained
connection capacity, not handshake processing throughput or fairness among
eligible peers. Native peer/session admission and radio contention remain
separate boundaries.

Both cases use the same funding, credit and settlement assertions. The SYN-only
driver never sends an ACK, repeatedly observes unchanged server sequence numbers,
and requires fresh SYN-ACKs from every previously confirmed tuple. Cleanup sends
exact resets and requires a distinct absent-tuple response for all 32 offers
before shutting down their transports. Failed financial progress is checked
after cleanup and test-fund recovery. These software results do not establish
hardware availability under hostile load. Reproduce both with the command above;
the TCP reservation currently requires the local dependency changes described in
[FUNDING-COSTS.md](FUNDING-COSTS.md). That matching dependency passes 43 Rust
workspace tests and 48 TypeScript tests, including shared admission vectors and
live interoperability in both directions. Typechecking, the generated TypeScript
build and strict dependency lint also pass. These gates preserve the source and
dependency fingerprints used for each run.

Transport receive priority now has an independent 64-packet reserve. This early
classification uses unauthenticated packet shape, so its queue must remain
bounded even before identity validation. Both priority and ordinary receive
limits include partially drained batch tails; owned credits release on consume,
drop and concurrent receiver shutdown. Pressure drops do not close the transport,
and `transport_priority_dropped` records priority overflow when measurements are
enabled. Five regressions fail before the fix; 42 focused queue tests, eight
counter tests, 362 transport tests, 116 dataplane tests and strict core all-target
linting pass, with simulation transport enabled for the broader checks. Packet
counts do not bound allocator overhead. An attacker can still compete with
legitimate control within the reserve; this is neither per-source fairness nor
paid/free scheduling. Radio and CPU effects of this change remain unmeasured.

Focused checks cover rate/capacity limits, cancellation, disconnect/reconnect,
customer restrictions and rejection of routed non-neighbors. A five-node paid
controller scenario uses empty control rosters, verifies quotes do not authorize
wallet spending, then funds, forwards and settles in both directions. Its
underlying links are configured UDP peers; it does not test beacon discovery.

The final affected suite passes 136 tests: all 127 relay library tests, two
customer scenarios and seven service scenarios. Core configuration checks,
repeated native-control shutdown/rebind and the multi-hop renewal scenario also
pass. The earlier complete relay run passed 214 checks and exposed two regressions:
a detached control listener and overlapping channel renewals. Both now have tests
that fail before the fix and pass afterward; their affected integration checks
also pass. Strict all-target linting, formatting and the source-size check pass
with the corrected local dependencies. These are software checks, not router
performance measurements.

The exact r32 packaged executable passes all 16 phases of the existing isolated
three-router ARM64 Linux fixture using only native Ethernet beacons and empty
neighbor rosters. Its matching test-mint executable is built offline from the
same immutable source bundle. Discovery leaves wallets and
spending authority unchanged; four unpaid packets deliver none. Funded probes
deliver eight of eight packets in both directions before and after a link
outage, actual dead-peer eviction and beacon rejoin. Funding operation and
channel identities, capital and wallet aggregates remain unchanged; automatic
payments advance without resetting lifetime budgets.

Both directions also pass observed 80-ms delay, a short 100% loss interval,
reordering and healthy recovery. Loss has eight source submissions and zero
received packets, with matching-route accounting advancing while the fault is
active; the same stream remains undelivered after restoration and payment
reconciliation. Aggregate carrier counters do not identify individual encrypted
probe packets. Payments reach fixed supported claims while background traffic
continues; seller exposure stays within the original grace and capacity, and
recorded credit is bounded by later durable buyer authorization.

The original two channels settle, all 384 test sats are redeemed into the test
collector, and all three node wallets have zero spendable balance. Exact owned
containers, links and network are cleaned up. The r32 run takes 105.2 seconds;
all six directional fault effects, settlements and resource removal are also
checked against its saved evidence. Source and executable hashes remain unchanged.
The existing fixture's assertions and runtime code are unchanged. Evidence is
retained in `work/paid-relay-verification/2026-09-29-ethernet-r32`, bound to the same
FIPS/SDK/CDK source graph as the package acceptance above.
This checks bounded Ethernet faults and one partition/rejoin, not radio mobility,
physical power loss or an intentionally interrupted payment reply. The additional
payment checks below cover two distinct interruption boundaries.
See the [reproducible harness](../../testing/chaos/README.md#paid-ethernet-acceptance)
for its configuration and runtime requirements.

With `measurements` enabled, the five-node controller test loses payments on both
sides of the real handler. First it discards a successful Update reply after the
handler has persisted the payment and seller credit. Another neighbor keeps paying
while that reply is held. Recovery starts with Usage and acknowledges the retained
credit without repeating that cumulative Update. The same scenario's next traffic
then loses a durably authorized Update before the handler applies it. Seller credit
must remain unchanged while it is held; automatic recovery must reconcile Usage
and send an actual Update. Unchanged buyer evidence requires exactly the retained
balance, while additional evidence may support a higher cumulative payment.
Neither interruption changes funding identities, purchase records or funding
budgets. The ordinary feature mode instead pauses a request before handling.

Repurchase checks preserve the original 64-sat lifetime limit, retired obligations
and every closed channel's authorization. They allow only evidence-backed payments
on new channels: session reports can use a replacement route before its next
application packet. A former equality check failed when the remaining budget
legitimately decreased; later runs observed these additional one-sat authorizations
with all old obligations intact. Final focused checks pass in both feature modes,
including held settlement and collection of all 640 test sats, as does strict
all-target lint. Recovery itself uses no manual payment flush or settlement.
These are test-only changes with no new wire messages or dependency versions;
the broader intermittent failures below remain open.

The optional `--payment-faults` Ethernet run passes all 20 phases in about
176 seconds with `testbench,measurements` binaries. Reverse carrier loss lasts
8.8 and 8.7 seconds, below production request and dead-link timeouts. Each
direction delivers eight fresh paid data packets while payment acknowledgment
stays unresolved across repeated observations; the owned queues drop 43 and 33
opaque carrier packets. Both original channels automatically reconcile fixed
supported balances after restoration and pay for a further healthy stream.
Neither fault observation records a completed Update handler, so this native
result does not identify an accepted Update's lost reply. All 384 test sats are
collected, every node has zero spendable balance, and all owned resources are
removed. The 76 Python checks, both controller feature modes, strict all-target
linting, formatting and source-size checks pass. Production code and payment
wire messages are unchanged.

The forwarding audit found shared transit admission before outgoing transport
selection, including batched sends. Service configuration now uses the core
`transports` schema and accepts UDP, native TCP, Ethernet and WebSocket. Other
core adapters are rejected until their paid-service acceptance is supplied. The
service checks the exact configured type/name set against operational adapters
before starting payment workers. A failed TCP or WebSocket listener beside a
healthy UDP socket stops startup, releases the sibling socket and preserves
financial state.
Initialization still uses only loopback, without runtime discovery or listeners.
The node owns and joins its operator listener during shutdown before the same
account path can be reopened, including when the endpoint cancels its receive loop.

Channel renewal also serializes unfinished replacements for each provider. A
replacement accepted before its predecessor's completion checkpoint cannot reserve
another renewal that would block both. Existing retries and unrelated providers
continue normally; rejection leaves funding, capital and saved journals unchanged.

A three-process UDP-to-TCP route passes two-way unpaid denial and paid delivery,
full use of each initial 8-sat channel, denial with connected links, explicitly
resumed renewal, middle-relay crash/restart and settlement. Both sources retain
their lifetime budgets and exact wallet debit history; the relay earns payment
and all 384 test sats are conserved. One endpoint has only native TCP, so no UDP
fallback can satisfy the scenario. Payment control remains TCP-over-FIPS over
the selected physical carriers; no new payment wire messages are introduced.

TCP/Tor connection close and transport shutdown invalidate retained writers,
release idle write halves and cancel active or queued writes. The shared
one-byte-stream regression wakes the receiver and both writers and confirms that
only the byte sent before close arrives. Peer removal now closes the current
carrier and cancels pending dials synchronously, preserving other active or
pending owners. Shared connection maps use short synchronous locks; socket I/O
and task joins remain outside them. Shutdown invalidates all pooled generations
before joining their receivers, and rotation reuses the ordinary peer cleanup.

A real TCP disconnect regression fails before this fix with a removed peer and
one retained carrier; it now releases both inbound and outbound carriers. Another
case retains a shared carrier until its pending preparation retires. Existing TCP
and local SOCKS5 tests cover asynchronous close, synchronous close, shutdown and
cancellation of completed but unpromoted dials. Obsolete pool-wait cancellation
coverage is removed; post-promotion cancellation still exercises a blocked writer.
The final checks pass two shared, 28 TCP, 33 Tor, ten TCP-node, 80 rotation and one
ready-preparation ACL test, strict core/relay lint, formatting and source-size checks.
The paid UDP-to-TCP process case above passes with all features and with optional
relay features disabled. Core test filters `tcp_peer_disconnect` and
`tcp_peer_removal_preserves` reproduce the node regressions. This does not enable
Tor in the paid service or accept new hardware. The ARM64 package at `7ca69d1c3`
includes these connection-lifecycle fixes and passes the paid TCP/WebSocket
process checks above.

Failed connection preparations now use the same owned-carrier retirement as
rejected ready connections. Previously the node removed its logical link but left
WebSocket's failed-attempt state behind. The real HTTP-rejection regression
`failed_websocket_preparations_release_transport_state_and_keep_retry` fails
before the fix and passes afterward across three distinct endpoints. Cleanup
releases transport, preparation, link and Noise-allocation state while retaining
the configured retry. Shared carriers remain protected by the existing owner
check; completed DNS errors are cleared before cleanup can await.
All six preparation, ten TCP-node, six WebSocket-node and one pending-connection
expiry checks pass, with strict core/relay lint. The paid seed-bootstrap process
case also passes in both feature modes, including restart and settlement of all
384 test sats. The ARM64 package at `7ca69d1c3` includes this preparation change;
current-device acceptance remains outstanding.

A matching three-process UDP-to-WebSocket test passes the same payment,
exhaustion, renewal, middle restart and 384-test-sat conservation checks. Its
final endpoint has only WebSocket, and runtime adapter/peer checks establish
the intended route. Six fixed round-trip probes before exhaustion and after
restart each verify complete delivery, matching paid byte progress and no
extra channel funding. Startup checks cover named WebSocket instances beside
UDP and TCP, including outbound-only TCP and cleanup of failed listeners.
These checks use real native adapters on macOS loopback, with no new payment
wire messages or dependencies.

A second WebSocket case uses only the middle relay's bootstrap URL, with no
configured WebSocket peer identities. Its final endpoint is client-only, and
both WebSocket participants explicitly permit authenticated adjacent peers.
The same paid delivery, exhaustion, renewal, restart and conservation assertions
pass; restarting the middle relay requires the seed connection to recover.
This proves URL-bootstrapped adjacency, not arbitrary endpoint discovery. Both
WebSocket cases also pass with test instrumentation disabled. All five mixed-link
tests, four startup tests, 292 relay library tests and strict all-target linting
pass; formatting and source-size checks pass without new size exceptions.
Run `cargo test -p fips-relay --all-features --test service websocket` for the
WebSocket process cases, or use `--no-default-features` for their production mode.

A third WebSocket case adds a loopback TLS reverse proxy to the URL-only fixture.
The real client rejects an untrusted issuer and a server-name mismatch without
connecting to the WS backend, admitting peers, funding channels or debiting its
wallet. A generated CA is passed only through the child client's `SSL_CERT_FILE`
and an empty `SSL_CERT_DIR`; that earlier dependency graph's native-root loader
used these alongside bundled web PKI roots. No system trust store or certificate
verifier is changed. With a valid certificate, the existing FIPS authentication,
unpaid denial, paid forwarding, exhaustion, renewal and settlement assertions
pass. Crashing the middle relay requires a fresh TLS connection; paid traffic
resumes and all 384 test sats are conserved. This passes with all relay features
and with optional relay features disabled; the plaintext seed regression and
strict all-target lint also pass. Test-only dependencies reuse already locked
`rcgen` and `tokio-rustls` versions. Production code and wire messages are unchanged.
Current builds require `--features test-native-roots` with the service test filter
`mixed_udp_websocket_tls`; see [the explicit fixture command](SERVICE.md#initialization-and-configuration). Local TLS
acceptance does not cover remote proxy deployment or resolve the intermittent
paid-delivery timeout below.

Native outbound WebSocket instances can explicitly select
`tls_verification: "fips"` for untrusted/self-signed certificates. The default
`web_pki` path retains ordinary chain, name and date validation. FIPS mode parses
the certificate and uses Rustls' real TLS 1.2/1.3 handshake-signature verification,
but leaves peer identity to FIPS Noise instead of the certificate's issuer, name
or dates. Browser trust policy is unchanged. See [configuration](SERVICE.md).

The shared three-process fixture now also uses an untrusted self-signed leaf
whose name does not match the URL. It first confirms that default TLS still
rejects that issuer and that FIPS mode rejects a handshake signed by the wrong
key, with no admitted peer, backend connection or wallet debit. The actual
self-signed connection then passes authenticated adjacency, unpaid denial,
paid forwarding, exhaustion, renewal, middle-relay restart and settlement with
all 384 test sats conserved. The test failed before the connector was wired in.
It passes with all relay features and with optional features disabled. Default
TLS, all 21 transport and six authenticated-node checks, strict core/relay lint,
formatting and file-size checks also pass on the matching source graph.
Run the service filter `mixed_udp_websocket_self_signed` to reproduce it.
No wire messages or dependency versions change; core uses the already locked
Rustls directly. This acceptance remains local and does not resolve the earlier
intermittent timeout or accept the current build on routers.

Native WebSocket lifecycle checks additionally reproduce and fix stalled HTTP
upgrades retaining both connection slots indefinitely and completing after a
transport restart. Incoming upgrades now use the existing connection deadline.
The transport owns and joins accepted workers on shutdown, retaining their
handles if shutdown itself is cancelled. Regression tests observe actual socket
closure and release of both inbound and total connection permits, then complete
a fresh WebSocket/key-hint exchange. The hint is discovery metadata; the separate
node and paid-service tests exercise FIPS authentication and forwarding.
Closed-connection statistics now include cancellation exactly once; incomplete
HTTP upgrades count as neither opened nor closed. The three lifecycle regressions
failed before the fix and pass afterward. All 14 transport checks (including those
regressions), six authenticated-node checks and seven public-API reconnect/churn
checks pass. Paid-service
checks in both feature modes and strict core/relay linting also pass.

Three additional regressions reproduce failed initial key-hint writes retaining
their connection address, old connection completion clearing a replacement's
status, and a late HTTP upgrade rejection overwriting an established replacement's
status. The hint write and frame loop now share one cleanup path. Pool and status
removal use the same lock and require the exiting connection's generation; dial
status updates leave an established owner unchanged. The tests use the production
WebSocket encoder with a deterministically closed duplex underlay, overlapping
connection workers, and real loopback HTTP upgrades. They verify fresh physical
record delivery and balanced connection counters; this is separate from FIPS
identity authentication. All three fail before the fix and pass afterward, along
with all 17 transport, six authenticated-node and seven public reconnect/churn
checks. All four paid-service checks pass in each feature mode, as do strict
core/relay lint, formatting and source-size checks. These concrete cleanup
failures have not been linked to the intermittent paid-delivery timeout below.

Stalled-write regressions additionally reproduce an initial key-hint write
outliving its exchange deadline, a data write suspending the idle timer, and
local close leaving the writer blocked. They use the real WebSocket encoder
over a one-byte duplex underlay whose peer stays alive without reading. The
existing hint/idle deadlines now cover all frame writes, and removing a pool
entry signals cancellation independently of the data queue. Explicit close and
network rebind release stalled streams even with the idle timeout disabled;
generation checks still protect replacement connections. Partial writes do not
increment completed-frame counters or resume on a replacement stream. No new
wire messages, configuration fields or dependency versions are required.
All three regressions fail before the fix and pass afterward. The matching graph
passes all 20 transport, six authenticated-node and seven public-API WebSocket
checks, five paid-service/startup checks in each relay feature mode, strict
core/relay lint, formatting and source-size checks. These are local native
checks; the current ARM64 package includes this fix, while current-device
acceptance remains outstanding.
The stalled-write failures have not been linked to the earlier intermittent
paid-delivery timeout.

WebSocket reads and writes now progress concurrently under the same connection
lifetime. Previously, simultaneous writes could leave two healthy peers waiting
for each other to read. The reader now continues receiving while a write is
blocked. An eight-message control-reply reserve stays separate from the bounded
data queue; overflowing it closes the stream. Incoming activity can extend the
idle deadline, while hint expiry, explicit close and network rebind still drop
both halves and any partial write. This adds no detached workers, wire messages,
configuration fields or dependencies.

The bidirectional regression uses the real encoder over a one-byte duplex
underlay, with and without an initial hint request. It fails before the fix and
passes afterward, preserving record order and balanced frame/connection counters.
Expanded lifetime checks cover incoming activity during a blocked write, later
idle expiry and bounded control-flood closure with idle expiry disabled.
The matching source graph passes all 27 transport, six authenticated-node and
seven public-transit checks, plus six service/startup checks in each relay feature
mode. All eight paid process scenarios conserve 384 test sats each. Strict
core/relay lint, formatting and source-size checks pass. The r20 ARM64 package
includes this change and passes the isolated Linux process cases above.
These results do not identify the cause of the historical intermittent delivery
timeout or establish current-device acceptance.

A deterministic regression also reproduces a deferred node-lifecycle close
removing a replacement WebSocket registered at the same seed URL. The close now
removes the current pool entry synchronously, using a short lock that never spans
I/O or an await. No deferred close task can act on a later connection; the existing
generation check still protects replacement state from an old worker's exit.
The regression controls execution order, covers both an existing and absent
original connection, delivers a physical record over the replacement and checks
balanced connection counters. It fails on the old code and passes after the fix.
The final checks pass 22 transport, six node and seven public-transit tests,
plus six process tests in each of the all-feature and no-default-feature modes.
Strict core/relay lint, formatting and the source-size gate also pass.
The ARM64 package checks above include this cleanup fix. Its connection to the
earlier intermittent paid-delivery timeout remains unproven.

Pending WebSocket discovery hints now belong to their live physical connection.
The previous separate queue retained hints after a stream closed, allowing stale
discovery and accumulation when the node did not drain it. Each connection now
holds at most one unconsumed hint; close, replacement, network change and shutdown
retire it with the pool entry. A late hint can update only its original connection
generation. This removes the queue and its lock without changing wire messages,
configuration, FIPS authentication or payment policy.
The real framing regression `unconsumed_seed_hints_retire` fails before the fix
on remote close and passes afterward across all four retirement paths. A fresh
connection at the same URL announces its own key once, and the existing delayed
completion case preserves the replacement's hint and writer. All 23 transport,
six node and seven public-transit checks pass, along with strict core/relay lint.
The paid seed-bootstrap process case passes with all features and with optional
relay features disabled, including recovery and settlement of all 384 test sats.
The packaged ARM64 build at `7ca69d1c3` includes this discovery-hint change; the
original intermittent timeout and current-device acceptance remain open.

Retiring an outbound WebSocket attempt now cancels its pending HTTP/TLS upgrade.
Previously, explicit close removed the status but left the dial running; a late
upgrade could register an abandoned connection and hold the only available slot.
Each attempt now owns its slot and cancellation before network work is queued.
Its generation guards both connection registration and failure publication, so
an old worker cannot replace a newer pending or established connection. Seed and
one-shot dials share this path in the outbound-dial module; reconnect backoff,
wire messages, TLS policy and payment rules are unchanged.

The real HTTP-upgrade regression fails before the fix and passes afterward for
both close APIs and both dial types. It releases the sole slot promptly, rejects
stale discovery and sends a physical record over a fresh connection at the same
URL without restarting the transport. Admission coverage also reserves the
configured connection limit before workers run, while the delayed-completion
case preserves a pending replacement through establishment and record delivery.
All 25 transport, six node, seven public-transit and six preparation checks pass,
along with strict core/relay lint, formatting and source-size checks. Paid seed
bootstrap passes in both relay feature modes; ordinary TLS and FIPS-authenticated
self-signed TLS pass with all features. Each of these four process cases includes
recovery and settlement with all 384 test sats conserved. The ARM64 package at
`7ca69d1c3` includes the discovery-hint, failed-preparation and outbound-dial
fixes and passes the process checks above. These results do not establish
current-device acceptance or explain the original intermittent delivery timeout.

Paid seed-bootstrap acceptance now also interrupts the physical stream while all
three relay processes keep running. A bounded loopback proxy closes and joins its
owned stream workers before acknowledging the interruption, while retaining the
listener. The fixture requires a fresh physical connection and authenticated
adjacency, then delivers and acknowledges payment in both directions through the
original purchases. New traffic must exceed the previously paid amount,
including whole-sat rounding, and receive a new cumulative payment. An earlier
acknowledgment cannot satisfy this check. Channel history and funding totals
remain unchanged, and remaining spending budgets cannot increase. The same run
also keeps the proxy unavailable across the middle-process crash/restart. It
requires at least two rejected reconnection attempts, absent authenticated
adjacency and unchanged funding identities, history, wallet debits and pending
reservations while partitioned. After restoring the carrier, fresh authentication,
paid traffic, bounded crash-exposure renewal and final settlement must succeed.
The proxy shares plaintext and TLS forwarding. All five carrier cases pass with
all features, and three instrumented seed runs pass without default features.
Each conserves all 384 test sats. Strict all-target relay lint passes in both
modes after correcting an unrelated mobile-mesh diagnostic's optional measurement
access; unavailable buyer payment counters serialize as null. All five changed
test files pass formatting and the 1000-line limit. These checks cover finite
loopback interruptions and a partitioned process restart, not sustained loss,
remote proxy deployment or current-device acceptance; they do not establish the
cause of the original intermittent timeout.

The five later core size-limit failures are cleared by moving existing identity,
peer-refresh and gateway tests into focused modules. Gateway runtime code is
byte-identical, and the extracted test bodies are preserved. The full source-size
gate passes; 61 configuration and 23 peer-update tests pass on macOS, and 91 gateway
tests pass in isolated, offline ARM64 Linux with Rust 1.96.0. Two privileged kernel
checks remain ignored. Strict core lint passes on both platforms. This cleanup
changes no protocol, payment or routing behavior.

One no-default-feature seed-only service run timed out in paid delivery. Its
original failure lacked a phase snapshot. Bounded failure-only diagnostics now
retain the purchase/renewal/restart phase, safe payment state, native
routes/sessions and daemon-log tails without changing retries or deadlines.
Subsequent passing runs do not establish the cause of that timeout. Intermittent
paid delivery remains an open readiness item.

A later no-default-feature seed run delivered the recovery packets after silent
loss but timed out waiting for payment progress within the existing 20-second
bound, before the new partitioned restart. Payment-wait failures now reuse the
bounded, read-only delivery snapshot and record the channel's submitted, paid and
previously paid amounts. The payment timeout's cause remains unproven; subsequent
passes do not close it or establish that it shares the earlier delivery timeout's
cause.

Recovery failure snapshots retain bounded buyer authorizations, route accounting
and attempt outcomes from the last durable journal, including when optional
measurements are disabled. These records can lag live submission state. Only
selected non-secret fields and known controller-error labels are emitted; arbitrary
error strings are excluded.

A directed repeated-traffic workload exposed a false payment wait after legitimate
renewal: the old channel had 5,764 msat submitted and 6,000 paid, while its replacement
had 4,096 submitted and 5,000 paid. The fixture kept waiting for new usage on the
retired channel. Recovery now follows payment across retained and replacement
channels, waits for in-progress renewal to finish, and uses the same sampled
purchases for its final accounting checks. Replacement must be justified by buyer
evidence reaching the configured threshold; original funding records, destination,
price, lifetime budget and capital limits remain checked.

The seed case now requires one extra replacement per payer across its two carrier
recoveries. Its minimum application workload exceeds the unchanged renewal
threshold, with a spare delivery attempt during silent-loss recovery. The existing
three-attempt limit and ten-second delivery waits remain; both payment directions
and renewal must reconcile within one twenty-second window. A smaller preload did
not reliably reach the threshold, and a separate sample caught replacement still
committing after payment; both failed experiments are retained. Final acceptance
passes all five carrier cases with all features and the seed case without optional
features, conserving 384 test sats per case. Strict all-target relay lint passes in
both modes. These are test-harness changes; the r21 runtime is unchanged.

Separate failures remain open: an earlier TLS run timed out before carrier fault
injection with an active channel, 432 msat submitted, zero paid and one sat locally
authorized. A comparison using the old payment wait instead observed an unfinished
renewal with 8,000 msat submitted and 6,000 paid. Later passes do not explain either
failure, or attribute the original intermittent delivery/payment timeouts to the
retired-channel fixture defect. No production-readiness claim follows from these
bounded local checks.

The existing five-node payment-loss fixture now holds an unapplied signed update
through the production request deadline. The transport releases it after 30.007
seconds in the measured run; automatic recovery queries usage and resends credit
on the original channel. The other neighbor makes three new payments while the
update is held. Original purchases, funding identities, lifetime budgets and
settlement checks remain intact, using the same traffic budget as before. Loss
of an already applied reply still exercises prompt cancellation and reconciliation.
The focused scenario and strict controller-test lint pass. A separate TLS run
with temporary failure-stage tracing also passes; tracing was removed. Runtime,
wire messages and production deadlines are unchanged. These checks cover silent request
expiry, without identifying the historical intermittent failure causes.

Optional payment progress reports the current automatic-payment stage and its
monotonic age, alongside the latest failed exchange's retained stage. The existing
bounded registry distinguishes queued work, channel-lock wait, preparation,
requests, response validation, signing, reconciliation and completed exchanges
awaiting scheduler harvest. The pending stage also determines `in_flight`; no
duplicate internal flag, timer, task or persistent record is added. One observation
owner covers completion and cancellation. Late teardown cannot restore a pending
stage after the scheduler clears it. Labels and elapsed time contain no raw error,
payment material, financial authority or peer traffic.

The existing held-update fixture observes an aging `update_request` while a healthy
neighbor keeps paying, then verifies recovery after the unchanged 30-second request
deadline. Pending state clears in the acknowledged snapshot and the failed stage
survives recovery. The assertion fails before the addition; disabling only the
update-request observation also fails at the held request. Lifecycle unit coverage
distinguishes unharvested completion and verifies cleanup despite late observations.
All 304 relay unit tests, 290 without optional features, the held-update case,
TLS process/status and repeated bidirectional UDP/TLS renewal pass. Strict all-target
lint passes in both modes, along with workspace formatting and source-size checks.
Sources remain unchanged during each gate, and the exact verified implementation
is restored after the controlled reversion. Evidence is retained in
`work/paid-relay-verification/2026-09-29-payment-progress` with its tested dependency
lock and the immutable metadata-bounds dependency bundle reference.
These native checks postdate r32; packaged default builds omit measurements.
Historical timeout causes and current-device acceptance remain open.
See the [observation semantics](../../testing/relay-cadence/README.md).

The existing TCP/FIPS carrier regression now drops the initial SYN, SYN/ACK and
completed control reply on the encrypted simulated link. No application record
can be submitted before connection recovery, and the completed exchange contains
exactly one application request. The separate port's accounting counters remain
unchanged. Both relay feature profiles pass in 4.19 and 4.15 seconds within the
existing twenty-second deadline, along with strict target lint, formatting and
the source-size gate. This extends one existing case without changing runtime
behavior, protocol or dependencies. It does not reproduce or attribute the
historical stalls. Exact sources, the tested lock and all six unchanged-source
gates are retained in `work/paid-relay-verification/2026-09-30-control-handshake-loss`.

With these diagnostics enabled, one bounded run each of seeded WebSocket
recovery, ordinary TLS and repeated bidirectional UDP/TLS renewal passes against
unchanged native executables. None reproduces the historical stalls. The renewal
fixture now also captures the existing bounded failure snapshot when its mint
commit or overlapping-settlement wait fails. Its shared controller projection
includes at most sixteen seller settlements, exposing only identifiers and
payment/report presence flags. The existing held-close round verifies those
flags against its real journal while retaining all accounting checks. The
30-second, 10-second and overall 240-second deadlines are unchanged. Focused
renewal acceptance, strict service-test lint in both feature profiles, formatting
and source-size checks pass. This changes only test diagnostics; r32 runtime and
hardware acceptance are unchanged. Evidence, including the passing three-case
sequence, is retained in `work/paid-relay-verification/2026-09-29-stall-diagnostics`.

An optimized ARM64 diagnostic comparison exposed a receiver-setup race in the
repeated-renewal fixture. One direction could start sending before the opposite
direction armed its receiver, which the service correctly rejects while a probe
sender is active. The failure occurred with no CPU throttling or memory-limit
event. Paired probes now prepare both receivers before sending concurrently.
Shared submission and delivery checks retain the original packet counts, rates,
three attempts per direction, ten-second delivery waits and financial limits;
directions that have already delivered are not retried. No runtime behavior,
protocol or dependency changes, and no additional test case, are introduced.

The repaired fixture passes renewal at two CPUs and half a CPU, plus TLS and
seeded recovery, against the byte-identical daemon from the failed run. Each case
retains its 384-test-sat conservation checks. Half-CPU renewal takes 44.045 seconds
and records 19 throttled periods, 1.205 seconds throttled and a 66.43 MiB peak;
these cover the entire container, including the harness, mint, relays and cache,
not per-byte or physical-router performance. Strict all-feature service-test
lint, changed-file formatting and workspace source-size checks also pass.
The original failed comparison and exact repair evidence are preserved in
`work/paid-relay-verification/2026-09-29-arm64-payment-pressure` and
`work/paid-relay-verification/2026-09-29-probe-pair`. The previous package evidence
is unchanged. This fixes the reproduced fixture race without attributing the
historical delivery, payment or renewal stalls.

A diagnostic build from the r46 source bundle passes the three existing
TLS recovery, seeded reconnect and repeated bidirectional renewal cases at
two CPUs and a quarter CPU, with payment-stage measurements enabled. The same
optimized static ARM64 executable and matching harness run in six fresh,
unprivileged, network-isolated Linux containers with local test money. Workloads,
deadlines, funding and settlement assertions are unchanged. Elapsed times are:

| Case | Two CPUs | Quarter CPU |
| --- | --- | --- |
| TLS interruption and recovery | 65.122 s | 68.651 s |
| Seeded connection break, silent loss and restart | 116.996 s | 121.879 s |
| Repeated bidirectional channel renewal | 42.489 s | 48.567 s |

The quarter-CPU cases record 62, 152, 137 throttled periods respectively;
none records a memory-limit event. These counters cover the whole test
network, including mint and harness; they are not per-byte router costs.
All source and executable hashes remain unchanged, and all owned containers
are absent. Exact inputs, results and cgroup observations are retained in
`work/paid-relay-verification/2026-10-01-payment-pressure-r46`.
The earlier r35 comparison remains preserved in its original evidence directory.
No historical stall reproduces in this finite comparison, so its cause remains
unattributed. Current-device, physical power-loss and sustained performance
acceptance remain outstanding. Runtime code and payment policies are unchanged.

The shared slow-renewal mesh fixture now also holds the renewing buyer's wallet-send
reply before channel funding exists. The fixture rotates zero-fee mint keys and
refreshes receiver key metadata to require a real wallet swap; existing bearer
coins could otherwise bypass that network wait. The fault matches the buyer's
existing or refunded inputs and its admitted replacement, excluding other nodes'
concurrent settlement requests. Healthy-neighbor credit advances from 2,000 to
6,000 msat while the reply remains held. Funding terms, capital reservation and
the original wallet operation stay unchanged; releasing the reply completes that
replacement, and all 1,536 test sats reconcile through final collection.

All three slow-renewal scenarios pass with all features, and the new wallet-send
case also passes without optional features. Strict priced-path test lint,
formatting and the source-size gate pass. The additional case shares the existing
traffic and settlement helpers and their deadlines. Exact sources and results are
retained in `work/paid-relay-verification/2026-09-30-renewal-preparation`.
This changes only tests. Its manual receiver refresh isolates the wallet-send
wait; automatic receiver refresh is covered separately by the UDP/TLS process
case in the scope section above. Physical-device acceptance and attribution of
historical stalls remain open.

The same mesh fixture now holds mint keyset replies during the renewing buyer's
unstarted admission. The existing mint proxy gains a simulation-only matching
reply gate: earlier refund lookups pass, while every matching metadata reply stays
held until release. A single paused reply was insufficient on the shared mint;
the initial fault experiments are retained without attributing a runtime defect.

Healthy-neighbor payments advance both before and after the ordinary 30-second
metadata request timeout. The SDK releases its unstarted admission without a wallet
send; the controller retains its original request, policy and 64-sat reservation.
Restoring replies resumes automatic renewal without a new funding counter or
changed authority. Final settlement and collection reconcile all 1,536 test sats.
The elapsed-time check starts at the held reply, independently of healthy-link
traffic duration; production timeouts and the existing fixture deadlines stay
unchanged.

All four slow-renewal cases pass with all features, and the metadata-outage case
also passes without optional features. The full SDK workspace suite passes 430
tests with one existing opt-in soak ignored. Its new proxy check verifies both
concurrent replies stay held, nonmatching replies pass, and release restores
access. Strict SDK and relay-test lint, changed-file formatting and the relay
source-size gate pass. Evidence is retained in
`work/paid-relay-verification/2026-09-30-renewal-keysets`.
Only simulation support, tests and this readiness record change. This closes the
full-mesh metadata-outage check, not historical-stall attribution, automatic mint
key-rotation acceptance or physical-device acceptance.

A separate SDK regression reproduced cross-channel signing contention during
refund recovery: a held mint-state request prevented the real nonblocking signer
from loading another funded channel in the same wallet. The original 30-second
request deadline and retry of the original unspent funding still passed.
SDK `1d520f1a1d60` now retains the existing exclusive wallet owner throughout
settled and expired refund recovery, but releases the shared signing store before
network and database awaits. Short store operations reload concurrent payments
and revalidate the original funding. Competing wallet recovery and retirement
remain serialized, and an expiry intent still fences its own channel's signing.
No journal format, message type or dependency changes are introduced.

The three existing HTTP refund cases now check unrelated signing during held
query, restore, import and committed-swap replies, preservation of concurrent
signed balances, duplicate-recovery rejection and final refund accounting. The
full SDK suite passes 429 tests with one existing opt-in soak excluded. After a
test-helper-only lint cleanup, the affected three-test target and strict
all-target lint pass again; the recorded whole-tree comparison verifies that no
production source changed after the full suite. Changed-file formatting and
whitespace checks also pass.

Native FIPS fee-bearing settlement/restart recovery passes in 125.87 seconds, and
bidirectional UDP/TLS renewal passes in 49.60 seconds with four replacements per
direction and all 384 test sats reconciled. Original deadlines and workloads are
unchanged. Exact sources, tested locks, the failing regression and final gates are
retained in `work/paid-relay-verification/2026-09-29-refund-signing`.
This fixes the reproduced contention without attributing the historical stalls.
The r34 package includes this fix and passes the isolated Linux acceptance above.
Current-device acceptance and other long-held signing-store workflows remain open.

Provider rejections now emit fixed debug labels for record parsing, agreement,
buyer identity, verification, credit application and checkpoint failures. Enable
them with `RUST_LOG=warn,fips_relay::payment_control=debug`; raw errors, requests,
signatures and identities are not logged. Wire replies and financial operations
are unchanged. The existing payment-control regressions pass with and without
measurements, and the TLS process scenario passes with these diagnostics enabled,
reconciling all 384 test sats. This does not attribute the historical stalls.
The r26 package includes this logging change; the dependency graph adds only a
direct reference to the already resolved logging library, with no version change.

The funded buyer/receiver regression first blocks the real signer's client-file
replacement after the buyer durably authorizes 3 sats of observed forwarding.
Signing reports the write failure while the original client file remains intact,
the seller has zero credit, and the buyer's lifetime budget stays fully reserved.
Repairing the file and reloading the authorizer and signer preserves that budget;
a retry with a zero new claim signs the original 3-sat obligation.

The same fixture then forces forwarding-journal replacement to fail after the
receiver accepts that signed payment. The response fails at credit publication:
the in-memory balance has advanced, but the original journal retains zero credit
and the accounting writer stays suspended. Repairing the filesystem and replaying
the payment cannot acknowledge that uncommitted balance. Reloading the receiver
and ledger, then replaying the same payment, restores exactly 3 sats of credit;
settlement conserves all 64 test sats within the original wallet limit.
Both payment-control cases pass with optional features enabled and disabled,
strict all-target lint, formatting and source-size checks. This extends the existing
fixture without changing runtime behavior; r30 is the accepted executable.
The checks cover forced writes and component reload, not automatic daemon retry,
a process kill, physical power loss or attribution of the historical stalls.

Automatic signer recovery has native macOS ARM64 and exact-packaged ARM64 Linux
process acceptance. The existing three-node UDP/TCP lifecycle removes write permission from
one disposable wallet directory. Existing signer files remain readable and
lockable, but atomic replacement fails after the buyer durably authorizes new
usage. The original signer file and seller credit remain unchanged. While that
fault persists, the other buyer advances its payment through the shared provider.
Restoring the directory permissions lets the scheduler pay the original channel
without restarting a process, flushing manually or making another purchase.
Original purchases, funding identities and lifetime budgets survive. The same
fixture then exercises exhaustion, renewal, relay restart and settlement,
conserving all 384 test sats.

Both relay feature profiles, strict all-target lint, formatting and source-size
checks pass. This is an opt-in extension of
`mixed_transport::mixed_udp_tcp_daemons_preserve_paid_limits_through_exhaustion_and_restart`
in the `service` integration target: set `FIPS_TEST_SIGNER_WRITE_FAILURE=1` and
run as an unprivileged user with the matching dependency graph. The test checks
that file creation is actually denied and restores permissions on scope exit.
The check needs no runtime fault-injection hook or protocol change. The r37
packaged TCP case requires both automatic-recovery markers. This covers one transient signer-write failure, not physical power
loss, current-device acceptance or attribution of the historical stalls.

A separate six-node regression reproduces interference between neighbor renewals.
It holds the real mint's successful close response for one provider, then drives
the source's other channel to its renewal threshold. The previous serial recovery
pass leaves that second channel without a renewal intent for the full 20-second
observation window. Releasing the held response restores service; all 1,536 test
sats reconcile before the regression reports failure.

Renewals now have an independent two-second scan and up to sixteen owned workers,
with one claim per channel. Newly due channels can advance while an earlier close
waits. Each waiting worker retains its selected renewal, releasing the full
journal snapshot before network work. The existing per-channel payment/settlement
lock and serialized wallet writes
remain; this does not make funding independent of another operation holding the
same wallet. Orderly pause waits for active renewals, graceful shutdown drains
owned work and forced cancellation aborts it. No peer request, journal field,
funding authority or dependency changes.

The final six-node runs complete the healthy renewal and credit new traffic after
11.776 seconds with optional features and 11.932 seconds without them, while the
other close remains held. Each checks pause/drain and reconciles all 1,536 test
sats. The existing delayed-funding scenario also passes in both profiles. All 303
relay unit tests, 289 without optional features, both complete seven-test controller
suites, strict all-target lint in both modes and the TLS process case pass on the
same frozen source graph. The source-size gate and changed-file formatting pass.
Reproduce the two neighbor-isolation cases with the `merge_split::slow_renewal::`
filter in the `priced_paths` test target and the development dependency overrides
in [funding and recovery](FUNDING-COSTS.md).

This is a demonstrated scheduling fault and controlled recovery evidence, not an
attribution of the earlier intermittent TLS, payment or delivery failures. Current
ARM64 package acceptance now covers this scheduler revision through the twelve
isolated process cases. The two six-node renewal scenarios also pass in a separate
no-default-feature ARM64 Linux harness built from the same bundle, with test-money
conservation and unchanged source hashes. Those simulated-link cases exercise
linked controllers; the twelve process cases exercise the packaged daemon. Physical
device and sustained-performance acceptance remain outstanding.

A native macOS replay at this scheduler revision also passes all five mixed-carrier
cases in the order of the earlier failed sequence, with optional features enabled
and unchanged deadlines. Each case conserves 384 test sats; source, dependency and
executable hashes remain unchanged. An initial run was interrupted by the disk
reserve guard; the completed replay uses its exact binaries after reclaiming
superseded build outputs. This does not reproduce or explain the historical stalls.

An opt-in three-daemon UDP/TLS regression now checks four renewal cycles in both
directions, with fresh delivery and automatic payment on every channel generation.
One cycle holds a committed mint close reply while the same provider accepts new
credit from its other buyer. Both original signed settlements must then be
durably pending before the reply is released. The shared wallet serializes closes
without blocking that other payment. All eight replacements preserve original
funding operations and spending limits; final collection reconciles 384 test sats.
The case passes with and without measurements. It uses the existing bounded
delivery retries and 20/40-second payment/renewal waits, plus an explicit request
budget for its isolated mint. It is ignored during routine tests; run it with
the [matching dependency overrides](FUNDING-COSTS.md):

```sh
cargo test --config /path/to/local-dependencies.toml -p fips-relay --all-features --test service mixed_transport::renewal_load:: -- --ignored --test-threads=1 --nocapture
```

Use `--no-default-features` instead of `--all-features` for the second profile.
This finite turnover check neither identifies the historical stall causes nor
establishes sustained physical-router performance. It changes only test code.

Broader five-node controller runs also retained two failures before the new
payment-loss or repurchase checks: a no-default-feature run timed out during
automatic renewal, and an all-feature route-change run failed ordinary delivery
before changing topology. Each suite had six passes and one failure. A focused
renewal pass and two subsequent route-change passes do not establish their causes.
Failure-only diagnostics now query every generated node's routing, sessions and
tree within a four-second budget, retain bounded unfinished funding/offer and
active-purchase projections, and report the received batch's lengths and test tags.
The earlier ordinary-delivery errors did not distinguish a receive timeout from
a nonmatching batch. Delivery deadlines and retry limits remain unchanged; no
wallet secrets are included in the diagnostics. These failures prevent broad
controller-readiness acceptance despite the focused payment checks above.

The current runtime and controller fixtures also pass four isolated ARM64 Linux
checks: automatic renewal with all features and without optional features,
route replacement/repricing, and delayed-neighbor payment/settlement isolation.
The five-node renewal cases retain all 18 bidirectional rounds, native rekey-loss
checks, interrupted-renewal recovery and capital/lifetime assertions. The delayed
neighbor includes an unapplied update past its request deadline and a lost applied
reply while healthy neighbors continue paying. Existing workloads and deadlines
are unchanged. Source verification matches all 816 current core, relay and
controller-fixture Rust files against the frozen dependency bundle; executable
and log hashes are retained in
`work/paid-relay-verification/2026-09-29-controller-recovery`.
These are four finite linked-controller runs with a test mint, not packaged-daemon
or hardware acceptance. They do not reproduce or attribute the older failures.

A controlled comparison changes only management-socket placement: five runs with
all five sockets and five with the original three middle-node sockets pass with
unchanged delivery limits. Neither configuration reproduces the failure. The
controller fixture now retains the latest 128 forwarding records per node for
payloads of at least 1,000 bytes and structurally valid native session handshakes,
including encrypted-envelope hashes, admission decisions and local send outcomes.
Failure output can correlate envelopes between hops;
timestamps are relative to each node's trace creation, and older records may be
evicted. No payload contents are retained, and local submission does not prove
delivery. At the revision with large-envelope diagnostics alone, both complete
seven-test controller suites passed, with and without optional features.
This adds test evidence only: the earlier
timeouts remain unexplained, and runtime and current-device acceptance are
unchanged.

The automatic-renewal case explicitly selects `forwarding_attempt`, the fresh
service tariff, and lowers the native key-rotation threshold to eight messages.
After the routed session is established, the middle relay drops the first native
Setup, Ack and Finish envelope once each. Later packets for all three phases must
pass the ordinary paid forwarding gate. Native session snapshots during the same
18 bidirectional traffic rounds must observe a later epoch and a changed key bit
in all eight adjacent payment-session directions and both routed data directions.
Arming the fault discards earlier routed rotations, and a subsequent traffic round
must complete after both endpoints rotate. The expected pairs are fixed before
traffic, so a missing routed session cannot reduce the required set.

Both relay feature profiles pass with the same source: all three loss phases,
paid delivery, automatic renewal, capital and lifetime limits, and collection of
all 1,280 test sats. The final runs take 83.745 and 82.604 seconds including their
compilation and final source checks. Strict all-target relay lint, formatting and source-size
checks pass. The workload, 16-sat channel capacity, per-payload 30-second delivery
limit and overall 240-second deadline remain unchanged. This is real loopback UDP
with production controllers and a local test mint, not hardware acceptance.
Run the `controller` integration target with the exact test filter
`exhausted_channels_renew_automatically_without_resetting_capital_or_spending`,
using the matching dependency overrides and either relay feature profile.

The initial loss fixture inherited the original `unique_session_envelope` tariff.
A failed diagnostic run records 25 duplicate-handshake buyer decisions under the
accounting lock and three seller credit-exhaustion decisions. Native retries reuse
the encrypted envelope, so the legacy duplicate rule rejects them after an earlier
onward submission even when the next relay dropped that submission. Switching the
fresh fixture to its intended per-attempt tariff recovers without changing runtime
accounting, native retry timers or payment limits. Temporary runtime tracing was
removed. This attributes the loss fixture's duplicate rejections; it does not
attribute the older intermittent delivery, renewal or payment stalls.

The existing slow-neighbor scenario retains the 16-message threshold. With
measurements enabled, it loses an applied payment reply and holds another update
without applying it until the production 30-second request deadline. Both
directions of that payment session must change their authenticated key epoch and
key bit during loss and automatic recovery. Setup first waits for any previous-key
drain to finish and discards setup rotations; the first attempted observation
recovered payments but saw no key change within the shorter fault window.
Healthy-channel payment and settlement checks retain their original deadlines,
spending limits and traffic. The measured loss case and the companion delayed-request
case without optional features pass, each collecting all 640 test sats. The
original all-feature renewal case still observes eight payment and two routed-data
directions and collects 1,280 test sats. Strict all-target relay lint, formatting
and source-size checks pass. This changes shared test coverage only. That payment
request/reply-loss case alone does not cover dropped native rekey handshakes or
identify the historical stalls.

A post-timeout credit snapshot cannot establish that credit was available when
the packet arrived. Two controlled five-second payment holds reproduce an
ordinary-delivery timeout with a first-hop denial of a 1,138-byte envelope. After
payments resume, the snapshot has 7,868–7,964 msat of channel headroom for that
3,414-msat packet, with no native route, send-error or TTL drops. The existing hop
trace identifies the denied envelope; the older failure logs lack that evidence.
Twelve unmodified executions across five controller cases pass, including the
original three-test prefix and six bounded repeats. The temporary fault injection
was removed. This comparison establishes a diagnostic limitation, not the cause
of the historical delivery, renewal or payment failures.

Rejection-time inspection must also distinguish the financial allowance from the
durable checkpoint ceiling. With temporary tracing under the existing ledger
lock, the original three-test prefix and renewal in both feature profiles pass.
The renewal runs record 44 full-channel denials and one new-channel denial with
credit available but its first durable window not yet published. All recover
within the unchanged retry and delivery limits. Tracing was removed afterward;
no historical timeout was reproduced or attributed, and no runtime fix is claimed.

A later configured-WebSocket run exposed a separate fixture race: delivery and
payment passed, but automatic renewal changed channel history before the fixed
round-trip check finished. The small post-restart warm-up could remain covered
by the previous rounded payment, leaving the round trip to trigger a fresh usage
claim and crash-exposure renewal. Every carrier now uses the seed fixture's
recovery sequence: exceed the previous whole-sat payment, observe automatic
replacement, and verify that retained crash exposure remains unbilled before
starting the unchanged fixed cohort. Each paying endpoint must add exactly one
replacement while preserving original purchases, funding intents and spending
limits. Renewals remain enabled; no additional purchase command, payment flush,
retry or longer deadline is introduced.

All five carrier cases pass with no default features and with all features,
plus two further configured-WebSocket runs without default features. Each of the
12 process cases settles all 384 test sats; strict all-target relay lint,
workspace formatting and source-size checks pass. This changes only the shared
fixture and does not attribute the older delivery timeout or accept new hardware.

The earlier r16 source graph also passes four serial configured-WebSocket/seed
pairs on macOS loopback, preserving the original test order and using no optional
relay features. Both executables are built offline from the same immutable source
bundle as the ARM64 package. All eight process cases reach automatic replacement
and settlement, conserving 384 test sats per case; source and executable hashes
match before and after every pair.

The r32 packaged executable additionally passes repeated bidirectional UDP/TLS
renewal and seeded WebSocket recovery in isolated ARM64 Linux with a shared
half-CPU limit. The renewal case completes eight replacements while another
neighbor keeps paying during a held settlement reply. The seed case covers broken
and silently dropping connections plus a middle-relay restart during partition.
Both retain ordinary deadlines and reconcile all 384 test sats per case. Linux
confirms the unchanged 50,000/100,000-microsecond CPU quota and records 29 and 26
throttled periods respectively. The complete test containers consume 7.62 and
13.84 CPU seconds, with memory peaks of 93.2 and 108.5 MiB and no memory-limit or
out-of-memory events. These measurements include the harness, local mint, three
relays and filesystem cache. Source and executable hashes match before and after
each case. See the [CPU-pressure reproduction](openwrt/README.md#cpu-pressure-check)
and `work/paid-relay-verification/2026-09-29-arm64-pressure` for the records.
These finite checks do not reproduce the original delivery timeout or establish
sustained capacity, per-byte payment overhead or current-device acceptance.

The seed fixture also tests silent loss: the proxy retains existing sockets and
discards their traffic while new connections remain usable. Production keepalive
and idle timers are unchanged. After authenticated reconnection, both directions
must advance paid usage on the original channels before the middle-relay crash.
This exposed a separate recovery gap: retained crash exposure can exhaust a
seller's funded capacity before the buyer's local usage reaches its renewal
threshold. The existing authenticated usage response now triggers ordinary
renewal when reported crash exposure takes reservations past that threshold.
The controller rechecks the active purchase, renewal policy, pause switch and
trial exclusion in its durable store. Duplicate hints do not rewrite the journal.

This adds no messages or delivery receipts. Payment signatures still cover only
the locally supported portion of submitted usage; lost exposure stays unbilled
and consumes the relationship's grace after replacement. Settlement and verified
refund precede new funding, under the existing price, capital, fee and lifetime
spending limits. A dishonest provider can accelerate renewal and consume allowed
funding overhead, but cannot make its reported loss billable. Repeated crashes
can still exhaust the finite grace budget. Renewal may interrupt datagrams: the
post-crash fixture observes automatic replacement before its unchanged fixed
round-trip cohort, then checks retained unbilled loss and total fund conservation.
This does not attribute the older timeout or prove whole-device power-loss
recovery. The current ARM64 package above includes this fix and passes the same
recovery sequence in isolated Linux.

That production change passes 298 relay unit tests, 12 durable-accounting tests and
strict all-target lint. Seed WebSocket passes without default features and with
all features; ordinary TLS passes without default features and self-signed
FIPS-authenticated TLS passes with all features. Each process case conserves
384 test sats. The two silent-loss runs resume paid traffic in 34.8 and 35.2
seconds with production timers; these loopback observations are not a radio
failover benchmark. Formatting and the 600-line relay source limit also pass.

These results establish bounded link behavior. They do not establish radio
mobility, congestion fairness, throughput, remote TLS proxy deployment or
support for every core adapter.

### Packet demand before the checkpoint threshold

An existing durable-window test exposed a local scheduling gap. Session setup
reserved 1,536 msat of a 4,000-msat window; the next data packet cost 3,180 msat
and could not fit. Because less than half the window had been consumed, the
checkpoint worker had no reason to advance it. The old test manually checkpointed
without checking that scheduling decision, masking dependence on other activity.

Admission now reports a window-only refusal to the durable wrapper, which requests
a local checkpoint when the packet fits a fresh window. The worker still requires
new reservations, and financial or oversized-packet refusals cannot request the
earlier write. The hint clears before sampling reservations so demand during disk
I/O is retained. Forwarding still uses only persisted allowance; credit, crash
exposure, wire messages and saved journal formats are unchanged.

The existing tests now require the scheduling hint, retry the rejected packet,
and retain idle, financial-limit and crash-exposure checks. The scheduling
assertion fails on the previous runtime. This identifies a checkpoint defect;
it does not establish the cause of the historical delivery/payment timeouts.
The r26 package includes this change and passes the isolated Linux process cases;
current-device acceptance remains open.

The first controller acceptance run also exposed an offline wallet inspection
racing live controller work. The fixture now drains those workers before checking
the original balances and resumes the same controllers and request streams.
Wallet ownership rules and financial assertions are unchanged.

The matching graph passes 302 relay unit tests, 10 ledger tests, all 12 durable
tests with optional features enabled and disabled, and all seven controller
scenarios. Strict all-target relay lint passes. These native checks are separate
from the package checks above and physical-device acceptance.

### Operator-selected free forwarding

An operator may donate CPU, airtime, power or metered capacity. Fresh
`forwarding_data` accounts can set their default local fee to zero for every
destination; exact destination overrides remain available. A zero aggregate
price ceiling refuses positive downstream prices. Entirely free routes use the
existing authenticated, bounded permissions without funding payment channels.
Zero local markup over a paid continuation still requires ordinary paid resale.
See [default and destination pricing](DESTINATION-PRICING.md) for configuration,
resource bounds and the real-process acceptance scope.

Superseded free offers now retain bounded rejection records until expiry, so
old cached offers cannot reset their byte quotas. The existing 128-record and
16-per-neighbor bounds include those records. Optional source price selection
preserves a paused zero-ceiling authorization across restart; it grants no
automatic purchase authority. An explicit free-only watch can instead authorize
bounded automatic upkeep, without mint access or payment debt. Its normal grants
renew through fresh recursive quotes, retaining replay history and capacity
bounds; source quality trials keep their separate allowance rules. See the
pricing document for the current acceptance evidence. Optional local free-data
rate limits now share global and authenticated-neighbor budgets across grants
and destinations. Four regressions failed before enforcement and the slow-refill
retention fix; all 196 relay library tests and strict all-target linting pass.
A five-process UDP check also verifies bidirectional free delivery, per-neighbor
denial and the shared node cap with two neighbors. It observes admission counters
within elapsed refill bounds; all financial journals remain unchanged and the
mint is never contacted. Strict all-target relay linting passes on the combined
free-bandwidth and receive-queue changes. This does not establish radio congestion
fairness or paid/free scheduling.
Outgoing-link price selectors and choosing between free and paid tiers for the
same destination remain unfinished.

Local admission now binds accounting and scheduling together. Negotiated free
and earned-return traffic uses a bounded background lane; locally authorized
paid data uses the normal lane, with strict handshakes retaining protocol
priority. Both scalar and batched forwarding preserve that local decision over
peer-supplied header shapes. Background queue overflow yields to new receive
work, and foreground receipt drains preserve intentionally waiting background
packets instead of recording false route failures. Shutdown still drains or
cancels all lanes. See [local scheduling](DESTINATION-PRICING.md#local-traffic-scheduling)
for bounds and ordering limits.

Eight focused scheduler checks and all 124 dataplane tests pass. The overflow
and control-drain regressions each fail before their fixes; all 17 forwarding
tests, three policy tests and 197 relay library tests pass afterward. Existing
five-process free-bandwidth acceptance and mixed UDP/TCP paid exhaustion,
renewal, restart and settlement acceptance also pass with classification enabled.
The automatic paid watch recovers through native loss and delay simulations while
retaining channel evidence. Strict core and relay linting, project formatting and
the 738-file source-length check pass.

The subsequent five-process mixed free/paid acceptance passes with an explicit
requirement to observe background queue overflow during paid delivery. In the
accepted run, 4,591 background packets overflow that window while all 24 paid
packets arrive without duplicates or invalid payloads. The paid balance is
acknowledged before the free stream ends. Free admissions remain bounded and a
fresh free stream succeeds after refill; settlement conserves all 256 test sats,
and the unfunded source's financial journals remain unchanged. A native counter
regression verifies that window overflow is observable separately within send
errors; all 17 forwarding and 22 operator-query checks pass. Earlier lower-rate
runs proved concurrency but did not establish queue pressure during paid delivery.
This covers loopback UDP and local scheduling. It does not establish radio airtime
fairness, a throughput/latency guarantee, or the same-destination service tier
feature. The [strict reproduction command](DESTINATION-PRICING.md#local-traffic-scheduling)
fails if the host never develops the required pressure.

### Physical Wi-Fi discovery and free recovery

The [physical Wi-Fi harness](../../testing/chaos/README.md#physical-wi-fi-discovery-acceptance)
passes all 14 phases on three ARM64 OpenWrt routers. Fresh, unfunded profiles use
native Ethernet beacons over an existing 802.11s mesh, with no FIPS peer roster.
Temporary filters exclude the direct leaf-to-leaf shortcut. Both directions
deliver through the middle router before and after one leaf leaves the radio
mesh, its peers are evicted, and it rejoins. The same free-only source watches
recover delivery without another purchase command. All 40 fresh packets arrive;
middle-router admission and both shortcut-drop counters corroborate the route.

Rejoin uses the retained supplicant network and interface, with saved and live
kernel mesh forwarding disabled. Cleanup verifies original configuration/account
hashes, identities, budgets, peer connections and AP availability, plus Internet
and DNS reachability. All 228 management checks pass; their largest sampling gap
is 2.21 seconds. No financial journals change. Candidate processes and temporary
filters are removed without a forced stop. The 26 Wi-Fi harness checks and 17
affected fault/probe checks also pass, including failed restoration and cleanup
races. The installed router services remain on their original build.

This first run establishes one controlled free radio leave/rejoin using the
existing shared SAE key. The separate open-radio acceptance below removes that
shared-key requirement; mixed/mobile neighborhoods and the updated Pixel
regression remain separate checks.

The opt-in open-radio run passes all 20 phases on the same three ARM64 OpenWrt
routers. Two nodes discover and authenticate each other before the third radio
joins the temporary public mesh, without a shared mesh key or a configured FIPS
peer roster. All 40 fresh packets arrive, including both directions through the
middle router before and after a leaf leaves, its peers are evicted, and it
rejoins. The existing free-only watches recover automatically. Middle-router
admission and observed shortcut drops corroborate the two-hop path.

The harness verifies open radio admission, an eight-peer limit, 60-second
inactivity limits and disabled kernel mesh forwarding after convergence and
rejoin. Original-service EtherTypes are isolated in both directions while the
temporary radio profile is active. No funds are issued and financial journals
remain unchanged. All 285 management checks pass, with a maximum sampling gap
of 2.30 seconds. Cleanup restores the exact original radio profile, limits and
router baselines, and removes candidate processes and owned filters without
errors. The 56 Linux guard checks pass without skips. This establishes controlled
open joining and free recovery on one common radio channel. Hostile-load
tolerance, automatic channel selection and arbitrary physical mobility remain
unverified; combined paid/open acceptance is recorded below.

The [paid Wi-Fi harness](../../testing/chaos/README.md#paid-wi-fi-recovery) also
passes all 22 phases on three ARM64 OpenWrt routers. Dedicated SSH connections
make the same controller test mint available through each router's loopback;
only the management connection carries mint HTTP, while FIPS payloads use the
radio mesh. All three listeners and HTTP endpoints are verified before issuance.
No firewall setting change is needed. The 109 Linux harness checks cover forwarding ownership,
partial startup, uncertain collection, cleanup and the existing radio guards.

The enforced two-hop path delivers all 32 paid packets in both directions before
and after one radio departure/rejoin. Four submitted unpaid transit packets
deliver none. Automatic payments resume with the original funding/channel
identities and lifetime budgets. The middle router earns 14 test sats; final
wallets contain 121, 142 and 121 sats before all 384 test sats are collected and
every test wallet is empty. Both shortcut-drop counters corroborate the path.
All 321 management checks pass, with a maximum sampling gap of 2.24 seconds.
Original router baselines are restored, and candidate processes, temporary
filters, mint forwards and the fully collected mint stop without cleanup errors.

The combined paid/open run also passes all 28 phases. Two nodes authenticate on
the temporary open mesh before the third radio joins; all three use fresh funded
accounts and discover neighbors without a preset FIPS roster. The enforced
two-hop path delivers all 32 paid packets in both directions before and after
one radio departure, peer eviction and rejoin. All four unpaid transit probes
are denied. Automatic payments resume on the original channels; the middle
router earns 14 test sats. All 384 issued sats are collected and every wallet is
empty. All 372 management checks pass, with a maximum sampling gap of 2.63
seconds. Original radio profiles, limits and router baselines are restored;
candidate processes, owned filters, mint forwards and the fully collected mint
stop without cleanup errors. The combined lifecycle has 89 passing Linux checks,
including funding order and preservation after radio or financial uncertainty.

These runs cover controlled departure/rejoin with reconciled, already funded
routes on both SAE-protected and open radio meshes.

The [interrupted trial-promotion fixture](../../testing/chaos/README.md#interrupted-trial-promotion)
also passes on the three-router SAE-protected mesh (2026-09-20). The provider
commits a full agreement after the source consumes 3,752 of its 32,768 trial
units; the successful response is held while the source retires that trial.
Removing the middle radio causes complete native peer eviction and withdrawal
by the original Watch. After rejoin, the same three processes recover a working
full route and automatic payments without a replacement Watch or rescue purchase.
The recovery trial retains exactly 29,016 units. All 32 round trips across four
fresh bursts complete, including the final eight under the recovered full
agreement. No traffic is offered during the outage.

The pinned runtime validator checks that the original source channel's 27-sat
refund precedes its sole 32-sat replacement and that lifetime budgets remain
intact; the reverse channel remains original. These exact journal transitions
are runtime assertions, not replayable from the retained summary evidence alone.
The provider earns 18 test sats, all 384 issued sats are collected, and every
test wallet ends empty. All 423 management checks pass. Independent restoration
checks confirm unchanged original router baselines, Internet access and removal
of the owned test processes and filters.

Releasing the held response closes two abandoned responders without delivering
a late reply to the buyer; this run does not test buyer rejection of a late
response.

The full source-process restart variant also passes on these routers
(2026-09-20). The harness sends one SIGKILL at that held commitment and verifies
the original pending acceptance in the stopped profile. It then restarts the
same profile while the middle radio is absent. The original Watch withdraws the
pending offer and recovers after rejoin; the other two process epochs remain
unchanged. All 40 round trips across five fresh bursts complete, including the
final eight under a stable full agreement with qualifying native feedback and
an advancing acknowledged payment. No traffic is offered during the outage.
Original trial consumption remains 3,652 units; the recovery trial receives
exactly 29,116 remaining units. One 32-sat replacement follows the original
28-sat refund, as checked by the same runtime financial validator. The provider
earns 21 test sats; all 384 issued sats are collected and every wallet ends
empty. All 402 management checks pass. Independent checks confirm restoration
of original router settings and Internet access, with owned test processes and
filters absent. Both held stale replies encounter closed responders.

These checks cover a process crash, not whole-router power loss. Other funding
interruption boundaries, arbitrary physical mobility/mesh merge-split, phone
outage recovery and sustained hardware capacity still require verification.
Neither controlled recovery establishes seamless roaming or a performance bound.

The [paid/free priority and round-trip fixture](../../testing/chaos/README.md#paidfree-wi-fi-priority)
also passes on these routers. With a 500-ms maximum payment age, all 72 paid
round trips complete across three 24-packet phases. Mean application RTT is
5.13 ms before free load, 24.30 ms during it and 4.60 ms afterward. Middle-router
background drops increase during partial paid progress; payments advance in both
directions while the free sender remains active. Fresh free traffic recovers,
all 384 test sats are collected, and 279 management checks and restoration pass.
This is one short stationary workload, not a latency guarantee, radio airtime
fairness or evidence of mobile route selection.

The [active radio-outage fixture](../../testing/chaos/README.md#paid-wi-fi-recovery)
also passes on the temporary open mesh. The cut precedes the final scheduled
send, interrupts 21 of 24 round trips, and is followed by observed peer eviction.
After rejoin, all eight fresh round trips and subsequent bidirectional payments
succeed on the same processes and channels. All 384 test sats are collected,
original radio settings are restored, and 312 management checks pass. The
9.75-second request-to-complete-recovery upper bound includes polling and probe
time; the test deliberately waits for eviction before requesting rejoin. It
does not establish arbitrary mobility or interrupt a specific payment message.

The same fixture also passes a middle-router departure during live paid traffic
(2026-09-19). All three full FIPS peer lists become empty; rejoin restores the
exact two-hop line with the original processes, identities, funding and channels.
The interrupted stream loses 22 of 24 replies. All eight fresh round trips and
subsequent bidirectional payments succeed; all 384 test sats are collected,
original router baselines restore, and 417 management checks pass. Full peer
eviction is observed 57.47 seconds after the completed cut, before rejoin is
requested. The separate 26.70-second rejoin-to-complete-recovery upper bound
includes polling and the fresh probe. This is a real radio departure with an
emulated endpoint range limit; it does not prove physical movement, merging two
multi-router meshes or seamless roaming. The extended harness passes all 451
Linux checks across the main suite and an isolated native firewall check.

Native route selection also retains a single unanswered Full-MMP request as
failure evidence after its existing feedback deadline (10.5 seconds by default).
Heartbeat maintenance can select a known alternate even after the sender goes
quiet, while retaining the authenticated direct peer and end-to-end session.
Deterministic regressions cover fresh control traffic, the deadline boundary,
Minimal-mode inactivity, changed carriers and the absence of an alternate.
This prepares fallback for subsequent traffic; retransmitting the lost request
remains the caller's responsibility.

An instrumented middle-router trial on the updated software (2026-09-20) passes
with the same processes, original funding and channels, and advancing payments
in both directions. The interrupted stream loses 21 of 24 replies; all eight
fresh recovery round trips arrive. All 384 test sats are collected, 387 management
checks pass, and independent live reads confirm every original baseline field,
including radio limits and Internet access. The recorded mint and three forwarding
processes are absent after cleanup.

The 27.01-second rejoin-to-probe upper bound separates into 1.56 seconds for the
radio command, 18.83 seconds until the successful FIPS peer-roster read completes,
0.33 seconds of subsequent diagnostics, and about 6.29 seconds for profile/process
checks, probe setup, paced sending and observation. The first post-command station
read, bracketed 0.73–0.90 seconds after the command returns, shows established Wi-Fi
peers; the preceding FIPS peer reads were empty. These serial observations do not
establish simultaneous topology. Native logs confirm 30-second beacon intervals;
parsed beacons and discovery connection attempts appear about 13 and 18 seconds
after the radio command returns. Consistent clock anchors bound log alignment to
roughly 1.16 seconds, assuming no unobserved clock step. This supports testing a
shorter discovery interval. Full peer eviction is separately observed 62.44 seconds
after the cut; this run did not capture rekey retransmissions. Scoped trace logging
and serial diagnostics make this a recovery investigation, not a matched speed
comparison.

A follow-up with the existing 10-second beacon option on temporary profiles passes
the same middle-radio outage, channel continuity and settlement checks. Native logs
confirm the effective interval on every router, with consecutive beacon gaps of
9.998–10.002 seconds. The successful peer-roster read completes 1.91 seconds after
the radio command returns; the full rejoin-to-probe upper bound is 10.24 seconds.
All eight fresh replies arrive, both directions advance signed payments and seller
credit, and all 384 test sats are collected. All 384 management checks pass;
independent live reads confirm the original radio limits, accounts and Internet
access after cleanup. The default interval remains unchanged. Beacon phase and
serial diagnostics prevent treating these two runs as a latency guarantee or a
matched performance comparison.

The follow-up also records the cause of the extended peer-removal grace. Full
eviction is observed 63.17 seconds after the cut. For the two lingering direct
peers, same-router logs show all five FMP rekey retries, followed by stale removal
one maintenance tick later: about 33 seconds after rekey initiation. Active rekey
temporarily defers link-dead removal until its retry budget is exhausted. Reducing
the discovery interval does not shorten that separate grace period.

A separate local-send failure found during this investigation is fixed: FMP rekey
retries previously advanced their budget only after a successful send, allowing
persistent local errors to defer dead-peer removal indefinitely. Each due attempt
now advances the existing budget and backoff before awaiting transport submission,
so cancellation cannot erase the attempt either. Eleven focused core tests pass,
including real UDP initiation followed by a stopped transport, unanswered-packet
grace, success-only byte accounting, and peer/session-index cleanup. Strict core
Clippy passes. A rebuilt ARM64 artifact including the fix also passes the guarded
three-router outage: all eight fresh recovery replies arrive, original funding
and channels persist, and both directions advance signed payments and seller
credit. With the temporary 10-second interval, full peer rediscovery is observed
2.00 seconds after the radio command returns and the rejoin-to-probe upper bound
is 10.58 seconds. The interrupted stream loses 22 of 24 replies. All 384 test sats
are collected, all 351 management checks pass, and independent live reads match
every saved router baseline after cleanup. No local retry-send errors occur in
this radio run; the stopped-transport regression supplies that failure-path
evidence. The run preserves ordinary retry grace and does not establish a general
handover latency or change the production discovery default.

A shorter middle-radio interruption now passes before FIPS peer eviction
(2026-09-20), using the same rebuilt artifact and temporary 10-second beacon
interval. Rejoin is requested 16.35 seconds after the cut completes. During the
cut the departing radio has no stations, while all original FIPS neighbors retain
their authentication timestamps. Processes, identities, funding and channels
remain unchanged. The interrupted stream loses 21 of 24 replies; all eight fresh
recovery replies arrive and subsequent payments advance in both directions.
The 9.18-second rejoin-to-complete-probe bound includes commands, diagnostics and
paced sending, rather than measuring the first usable route. All 384 test sats
are collected, all 315 management checks pass, and independent live reads match
every original router baseline, including Internet access. The mint and three
forwarding processes are absent after cleanup.

Two earlier pilots remain failed harness runs: one incorrectly required peers
to stay connected while their radio was absent; the other rejected normal key
renewal and link rebinding despite retained authentication timestamps and eight
fresh replies. Both collected all test funds and restored every original
baseline. The corrected check accepts rekey/rebinding, rejects recreated peers,
and passes 66 focused Linux tests alongside unchanged prior guard coverage
(230 passes and one unrelated customer-firewall skip). This is evidence of
observed peer retention within a controlled interruption, not physical mobility,
seamless handover or a unique peer-incarnation proof under clock rollback.

The [competing-provider topology fixture](../../testing/chaos/README.md#competing-wireless-provider-topology)
also passes on the three routers without funding. A separate source identity on
the destination's physical router reaches two providers over management-LAN UDP;
each provider's only destination link uses native Wi-Fi. Exact adapters/peer sets
and 24/23 observed shortcut drops exclude direct source-to-destination and
provider-to-provider edges. All 32 direct-link diagnostic packets arrive. Eight
unfunded source-to-destination data attempts advance native application counters;
one provider records 11 policy denials, and the same receive stream remains empty
after those observations. These counters are phase aggregates, not matched
packet receipts. Four wallets remain empty, journals and source authority remain
unchanged, all 234 management checks pass, and original router baselines restore.
The initial run exposed a harness comparison that included mutable memory/I/O
counters in process identity; the corrected check compares identity, host, PID
and process start time and rejects late reception. Shared Linux guard checks and
focused regressions pass. This proves the controlled two-provider topology, not
automatic paid selection on physical alternatives or mobile mesh behavior.

The [funded extension](../../testing/chaos/README.md#automatic-paid-selection-between-wireless-providers)
now also passes one controlled cheaper-provider → wireless alternative → recovered
cheaper-provider cycle. One watch uses the normal selector defaults; each stage
has a fresh trial, full-agreement payload delivery, native feedback on the selected
carrier and an advancing acknowledged payment. The two original 64-sat channels
remain intact. Of 144 packets submitted across the trials, 96 arrive; all 48
missing packets occur during failover, and every accepted stage ends with a fresh
16/16 burst. Settlement pays the providers 3/2 test sats and refunds 123 to the
source. All 128 test sats are collected, all four wallets end empty, all 486
management checks pass and original router baselines restore. The focused Linux
suite passes 107 checks. A source-tariff configuration error in the earlier
attempt stopped initialization before any funds were issued; the corrected four
configs also pass initialization with the actual ARM64 artifact offline.

This adds physical working-route selection and recovery evidence, not isolated
quality-ranking causality: the radio cut also invalidates onward reachability and
quotes. The source/destination share one router and first hops use management-LAN
UDP. Explicit eviction waits and paced probes preclude a failover-latency claim.
Arbitrary moving mesh merge/split, fast roaming and sustained capacity remain open.

The first [active-cut run](../../testing/chaos/README.md#failover-with-traffic-during-the-radio-cut)
failed the complete cycle. It delivered and paid through the alternative after a
cut during traffic, but recovery to the cheaper provider stalled. That returning
trial delivered 100 packets while its loss estimate remained
unknown, then could not fit another payload into its remaining 16-byte allowance;
selection did not fall back. This exposed loss-evidence continuity and exhausted
trial liveness failures. All 128 test sats were recovered,
all 600 management checks passed and original radio settings restored. The
50.05-second cut-request-to-alternative-confirmation upper bound includes polling
and confirmation traffic; it does not establish fast or seamless roaming.

The follow-up software investigation reproduced key-rotation measurement bugs
in both session and link traffic: authenticated packets and reports from draining
keys could enter the new key's measurements, and the first pending session-key
measurements could be discarded during promotion. The core now isolates these
counter spaces while preserving delivery of valid late application data. Encrypted
ingress regressions, 99 handler tests and strict core lint pass; the preceding
session fixes also pass 87 key-rotation tests. Together with the source trial
quota-refusal fallback, the combined code passes all eight paid-path scenarios,
including loss with neighbor departure, four leave/rejoin cycles and interrupted
acceptance; the preceding combined run failed the first two of those scenarios.
The same source passes 212 relay library tests and strict relay lint. These are
simulated-carrier results with native routing and payment code.

A matching router build now passes the complete active-cut cycle, including
return to the cheaper provider. Across trials and accepted streams, 122 of 160
submitted packets arrive; all 38 missing packets occur during failover. The
return phase delivers 32/32 packets, ending with a fresh 16/16 full-agreement
burst, native quality feedback and an advancing acknowledged payment. The two
original 64-sat channels remain intact. Settlement pays providers 5/4 test sats
and refunds 119 to the source; all 128 sats are collected and all four wallets
end empty. All 402 sampled management checks pass. Independent post-run reads
match all original router baselines, including account/configuration hashes,
mesh settings, access points and Internet/DNS checks; owned processes and filters
are absent. The 49.84-second cut-request-to-alternative-confirmation bound is
controller-observed confirmation time, not packet outage duration. This single
guarded cycle already observes a full alternative agreement, fresh native
feedback and credited payment at 33.06 seconds after the cut request. The next
16.78 seconds include a fresh 32-packet confirmation burst at two packets per
second; they do not establish another 16.78 seconds of network outage. Exact
first-delivery and carrier-transition timestamps were not captured. The cycle
does not establish seamless roaming, arbitrary mobile merge/split,
isolated quality-ranking causality or sustained capacity.

A default-policy simulated diamond now separates delivery from controller
confirmation. One uninterrupted 128-packet numbered stream runs at two packets
per second; the cheaper provider's onward edge is cut after an actual delivery,
while both source adjacencies remain connected. Independent 250-ms observations
record native quality, trial/full agreement identity and acknowledged provider
credit. A matched baseline delivers the first new payload 18.504 seconds after
the cut and observes a full paid replacement with fresh quality at 24.248 seconds.
The refresh worker now wakes at the existing five-second per-watch deadline,
instead of rounding that deadline up to its independent two-second scan. Time
spent refreshing counts toward the next scan; expired retained checks alone do
not cause busy retries. The 15-second native feedback window, quote guard,
authorization and spending bounds are unchanged.

The corrected run delivers the first new payload at 15.501 seconds and observes
the full working replacement at 19.994 seconds; the full-suite repeat records
15.504 and 19.995 seconds. All 98 received packets match their original
submissions, compared with 92 in the baseline; 30 of 128 are still lost during
the cut. Both versions start three new source quotes. A complete 32-packet batch
confirms the replacement at about 47.75 seconds, which includes the confirmation
workload and is not the outage duration. Both original channels remain intact
and final settlement conserves all 259 test sats. The slow-scan regression,
218 relay library tests, all 14 priced-path scenarios, strict relay lint,
workspace formatting and source-length checks pass. This is one matched seeded
simulation, not a hardware recovery bound or evidence of seamless roaming.
Reproduce with the `recovery_timing::` filter of the `priced_paths` integration
target.

Source selection now excludes currently ineligible providers before requesting
quotes, using the same predicate as final offer selection. A failed provider
cannot consume one of the four candidate slots or delay a round while its quote
is awaited. Cursor rotation, fixed cooldown expiry, exhausted-trial latching and
fresh bounded retry rules are preserved. Three candidate regressions and the
actual TCP/FIPS quote-request regression fail on the preceding code and pass with
the fix; all 20 selector tests pass. The combined source also passes all 14
priced-path tests, 216 relay library tests, 128 dataplane tests, the ten optional
carrier diagnostic tests, endpoint compilation and strict core/endpoint/relay
lint.

Optional carrier diagnostics now reach the payment service's private status
and the cadence analyzer. A real TCP/FIPS test over SimTransport loses an
encrypted segment, triggers TCP's retransmission timer and verifies both
submissions, receiver ACKs and exclusion of unrelated service traffic. It caught
and now covers a diagnostic bug that counted successfully queued outputs as
discarded. The mixed UDP/TCP daemon test verifies each funded endpoint's carrier
activity through the status interface; ordinary builds report unavailable
instrumentation as null. Both integration cases pass with measurements enabled
and disabled, together with 11 core carrier cases, 129 dataplane cases, strict
core/endpoint/relay lint and the source-length check. The analyzer has 95 passing
tests and retains guard-gap traffic separately. Instrumented hardware reports
must include positive cumulative Ethernet submissions for each node with recorded
payment-service sends; an idle window need not add any new submissions. These counters measure local
transport submissions, excluding opaque transit and physical radio overhead.
The router capture below exercises these counters and retains its clean-link
delivery rejection alongside the diagnostic costs.

Diagnostic builds also expose `data_carrier` for the local data service
(port 44740), using the same optional carrier registry. It counts actual local
transport submissions for all traffic on that port, including probes and replies;
snapshots are cumulative and not atomic. This is neither a per-stream counter nor
a delivery receipt. It distinguishes transport submission from the probe sender's
successful endpoint API calls.
Normal builds return null, and opaque middle-router transit is excluded. The
mixed UDP/TCP daemon test verifies these boundaries in both feature modes while
preserving payment, exhaustion and restart checks.

Ethernet adapter statistics now separately expose Linux AF_PACKET `kernel_drops`
and the effective `recv_buffer_bytes`. One socket-owned accumulator serializes
the resetting kernel reads; unsupported or failed reads return null. These
diagnostics do not change congestion feedback or routing decisions. Zero drops
cannot exclude earlier radio/driver loss or later endpoint loss. The
[current-build hardware pilot](CADENCE-RESULTS.md#socket-and-data-service-observation--20-september-2026)
delivers all 11,712 packets with matching source submissions and destination
application counts, available socket measurements and zero socket drops. This
single clean run leaves the earlier intermittent loss unexplained. The capture
now retains full adapter replies inside existing process-bound samples, with
65 Linux harness and 101 analyzer tests passing.

The subsequent [eight-trial socket-observed comparison](CADENCE-RESULTS.md#full-socket-observed-comparison)
reproduces intermittent loss: 93,332 of 93,696 packets arrive, with all 364 missing
packets in one steady stream. Source transport submissions are complete; middle
output and destination ingress observations differ by the same 364 packets,
while recorded receive-socket drops remain zero. The repeated policy is clean.
This narrows the affected leg without identifying the queue, driver or radio
cause. Strict delivery acceptance remains failed; all 3,072 test sats are
collected, 2,091 management checks pass, and independent restoration succeeds.
Diagnostic costs are retained without changing the 500-ms default.

The subsequent [250-ms link-counter pilot](CADENCE-RESULTS.md#link-counter-pilot)
delivers all 11,712 packets with the same matched binaries. Optional station and
interface observations retain comparable epochs. Station retry/failure counters
increase together despite complete delivery; they must not be treated as missing
application-packet counts. Recorded interface/socket drops remain zero; queue
statistics are unavailable because `tc` is absent. All 384 test sats are collected,
261 management checks pass and independent restoration succeeds. The added capture
passes 82 Linux harness and 101 analyzer checks. The longer comparison's loss
remains unexplained, so this clean pilot does not close delivery readiness.

The next [software-queue observation pilot](CADENCE-RESULTS.md#software-queue-observation-pilot)
also delivers all packets and completes fund collection and restoration. Four
bounded middle-router queue snapshots are usable, with no observed backlog or
increasing software-queue drop/limit counters. This validates the added capture;
the earlier intermittent radio-path loss remains unexplained.

The subsequent [eight-trial queue-observed comparison](CADENCE-RESULTS.md#full-software-queue-observed-comparison)
delivers all 93,696 packets and completes collection and independent restoration.
Its 32 usable queue snapshots show no recorded software-queue drops, marks or
overlimit events, and no snapshot backlog or STOP. All 3,072 test sats are
collected and 2,091 management checks pass. The earlier intermittent loss remains
unresolved; this clean comparison does not establish its cause or close delivery
readiness. The 500-ms default remains unchanged.

The focused Ethernet suite passes 47 tests on macOS and 35 on Linux. An isolated
Linux veth test also forces two separate AF_PACKET queue overflows, verifies
increasing cumulative drops across resetting/concurrent reads, and confirms
continued reception after draining the queue. It exercises the production socket
implementation without changing the host's network interfaces.

The current isolated Android package passes a fresh arm64 native build, Android
lint and strict Android-target relay/app linting. Native-library provenance is
verified through packaging, including the build tool's stripping step. Installation
and native startup on the phone first verified an unconfigured, stopped test
account with the existing app's private files unchanged. The subsequent physical
customer-network acceptance is described below.

Customer profiles now select an explicit immutable per-attempt billing mode.
The former hardcoded mode rejected quotes from a forwarding-data mesh; a real
customer deployment reproduced that rejection before the fix. Both the original
mode and forwarding-data mode now pass the same purchase, delivery, reopen,
settlement and 384-test-sat collection checks. Missing billing in a saved profile
retains its exact original forwarding-attempt meaning. Unsupported tariffs and
later tariff replacement are rejected. Three profile checks, all three customer
integration tests and strict all-target linting pass. The physical phone run
below uses the explicit forwarding-data tariff.

The phone-test infrastructure now has a shared, capped mint endpoint and three
temporary customer firewall exceptions. The existing router lease owns the UDP
entry rule; mint access remains until a fresh, fully collected report is followed
by verified clean process exit. Fixed process identity, persistent money-operation
intents and a closing fence prevent automatic resubmission or unsafe cleanup after
lost replies. An interrupted completion checkpoint can recover from the exact
supervisor exit record. Missing supervisor evidence retains the run for deliberate
reconciliation; it is not proof of safe shutdown.

An ARM64 host passes a zero-funded start/report/stop check and a separate capped
128-test-sat issue/collection check. Cleanup preserves the live mint while those
funds are outstanding, then verifies 128 issued equals 128 collected before stop.
The host's existing mint processes and web service remain healthy. These initial
checks cover mint ownership and cleanup; they do not measure router throughput.

### Earlier physical phone customer across the wireless mesh

An earlier isolated Pixel app completes a paid session through all three
ARM64 OpenWrt routers. The phone joins the existing customer AP and authenticates
at its UDP entry. Native Ethernet discovery forms the temporary open 802.11s mesh
without a router peer roster; owned shortcut filters force the remaining two
wireless hops. Exact connected peer sets and observed shortcut drops corroborate
this mixed UDP/wireless path. Return allowance is disabled, and both endpoints
explicitly authorize their own sending direction.

All eight fresh 1,000-byte application payloads arrive: four from the phone to the
far router and four in reverse. Forward delivery checks exact packet/byte growth
and fresh payload hashes; reverse delivery additionally matches known sent hashes.
All four original 32-sat channels advance automatically and reconcile with the
providers' credited balances. Before funding, source-bound phone TCP probes reach
the shared mint, reject three explicit LAN/Internet targets, and reach the mint
again. This establishes those scoped isolation checks, not unrestricted firewall
coverage or paid Internet browsing.

Cooperative settlement leaves the entry and middle routers with 146 test sats
each and the phone and far router with 110 each, from initial grants of 128 each.
Both relays therefore earn 18 test sats net. An initial checker incorrectly
expected textual node addresses instead of the stored 16-byte arrays and stopped
collection after settlement. The corrected checker passes the exact retained
buyer/seller journals, immutable funding, terminal reports, signed balances,
refunds and all four wallet equations. Deliberate collection then redeems the
same settled wallets, without repeating funding, payments or settlement.

All 512 issued test sats are collected and all four wallets are empty. The mint
has a verified clean stop, and its temporary customer UDP/TCP/SNAT rules are gone.
All 633 management samples pass, with a maximum sampling gap of 2.34 seconds.
Original router baselines and the original phone app's files are unchanged; the
phone returns to its previously selected saved Wi-Fi. This completes the bounded
phone session with recorded checker recovery. It does not establish phone
mobility, arbitrary mesh merge/split, throughput or production readiness.

## Guarded cadence measurement

The earlier r12 source bundle also passes the existing eight-trial cadence
matrix on isolated ARM64 Linux with the OpenWrt optimization profile and
measurement instrumentation. All 285,696 packets arrive and all 40,960 test sats
are recovered after 48 channel settlements. The unchanged analyzer passes all
120 regression tests and its strict delivery, credit and interval reconciliation
checks. At 500 ms, the high-rate workload averages 8.01 ms of payment CPU per MiB
and locally attributed payment carriers equal 0.325% of application bytes; idle
payment and journal work remain zero. The source bundle and accepted r12 package
are unchanged. These are instrumented software measurements with wallets and
journals on tmpfs, not current router, physical disk or radio acceptance. The
500-ms default is retained; see the [27 September comparison](CADENCE-RESULTS.md#accepted-arm64-linux-comparison--27-september-2026)
for policy results, environment and limits.

The accepted 23 September optimized loopback comparison covers
250/500/1000/2000-ms policies with two opposite-order repetitions. All 285,696
original packets arrived, all six channels settled in each trial, and all 40,960
test sats were collected. Source, dependency, lock, analyzer and executable guards
remain unchanged throughout measurement. All eight idle windows show no payment
polling, signing, updates, payment records, attributed carriers or journal writes.

The explicit schema-2 contract `boundary_accounting: "prepaid-usage-v1"` retains
15 disjoint intervals per trial, including guards and gaps; integer costs
reconcile exactly from first to last observation. Only monotonic usage covered
by prior unchanged acknowledged credit may advance between windows. Payment,
open/stop operations, journal activity, changed authorization or acknowledgments,
and pending payments still reject the comparison. Delivery, credit limits and
the common three-second tail are unchanged. Reports without this declaration
retain strict usage equality; hardware reports keep their existing validation.
All 120 analyzer tests and an independent static review pass.

A native idle diagnostic confirms that path-MTU confirmations and session reports
consume 216 billable bytes per endpoint without new payment or journal work.
That explains a legitimate class of prepaid usage growth; it does not identify
the exact frames in the untraced 22 September report, which remains rejected.
The fresh accepted matrix has no guard/gap usage increments, but includes all
188.895 ms of guard/gap process CPU and 668 aggregate link bytes.

At high rate, 500 ms averages 44 updates, 359.62 ms of payment CPU and 101.63 KiB
of locally attributed payment carrier submissions; 1 s averages 40 updates,
327.42 ms and 92.39 KiB, about 9% less in this workload. The 500-ms default remains
unchanged. Two repetitions on a shared host do not establish an optimal policy.
CPU attribution covers synchronous payment spans, storage covers logical relay
journals, and carrier counters cover local submissions rather than full physical
wire cost. Sustained capacity and impaired hardware measurements remain open;
this software comparison does not revalidate the routers. See
[the results and boundaries](CADENCE-RESULTS.md).

The guarded hardware runner now has an accepted 250-ms pilot on three ARM64
OpenWrt routers. All 11,712 workload payloads crossed the forced two-hop wireless
path, both original paying channels reconciled at every measurement boundary,
and all 384 issued test sats were collected. The test mint stopped, original
router baselines were restored, and 258 management observations had no errors.
The idle window recorded no payment messages, synchronous payment CPU or payment
journal writes. The subsequent eight-trial matrix collected all 32 workload
windows and delivered 93,693 of 93,696 submitted packets. Two packets were missing
in the second 2-second high-rate window and one in the second 1-second steady
window. The strict clean-link validator rejected the matrix; its failed result
is retained, with no cadence default or performance optimization selected from it.
All 3,072 test sats were collected, every mint stopped, and original router
baselines were restored with 2,175 management observations and no management or
cleanup errors. Saved counters do not establish a precise loss cause. Separate
router clocks leave
one-way latency unmeasured. These kernels lack process I/O counters, which stay
explicitly null; process CPU, memory, logical relay journal and payment-record
measurements remain available. See the [hardware experiment contract](../../testing/relay-cadence/README.md#hardware-report-contract-schema-3).

A separate 2-second pilot with guarded native status/routing observations passed
all 11,712 packets and recovered all 384 test sats. All 264 management observations
passed and router baselines were restored. It did not reproduce the earlier loss.
It exposed incomplete native telemetry: the middle-router counters cover transit,
but optimized endpoint traffic bypasses the legacy received/delivered counters.
Ethernet also does not supply the kernel-drop signal used by the congestion API.
Zero counters therefore cannot establish a clean endpoint/kernel path.

The subsequent full eight-trial matrix pinned existing dataplane drop logging
and native counters to guarded process snapshots. Strict validation passed all
93,696 packets, with 53 out of order and no duplicates, invalid packets or
controller errors. All 3,072 test sats were recovered, all mints stopped, and
router baselines were restored with 2,157 successful management observations.
No native failure counters or log bytes advanced within measurement spans.
Later drop events demonstrate active logging but do not explain the earlier
loss. At high rate, 1 s/2 s used two updates versus four at 250 ms; total CPU
ranges overlapped. The default remains 500 ms. See the results for exact costs
and attribution limits. The earlier rejected matrix remains failed, and broader
hardware acceptance and the intermittent loss cause remain open.

The current priority-enabled build also passes a matched eight-trial matrix with
the controller mint reached through dedicated SSH forwards: all 93,696 payloads
arrive and all 3,072 test sats are collected. All 2,055 management checks and
restoration pass. At high rate, the 1-second policy uses about 38% less measured
payment CPU and 33% fewer payment-record bytes than 500 ms; idle windows perform
no payment polling or writes. These partial costs and two stable-topology repeats
do not establish an optimal cadence. The default remains 500 ms, and the earlier
loss remains unexplained. See the [matched results and measurement limits](../../testing/relay-cadence/README.md#hardware-report-contract-schema-3).

A separate ARM64 Linux syscall comparison now covers all four ages in both
orders with the same finite workload sizes on virtual Ethernet. All 93,696
packets arrive and all 3,072 test sats are collected. Independent raw-trace replay
and terminal wallet checks pass, and all owned resources are absent. Idle and
bursty windows perform no payment/storage work; prepaid bursty usage remains
metered. At high rate, the 1-second pair records two updates and about 95 KB of
file writes, versus three updates and 142–149 KB at 500 ms. SDK snapshots,
receiver SQLite, relay journals and directory syncs are reported separately;
funding-wallet writes are zero within the windows. This measures successful
syscall bytes, not physical media wear, and traced CPU is not a timing benchmark.
The default remains unchanged. See the [storage results and boundaries](CADENCE-RESULTS.md#matched-storage-syscall-comparison--19-september-2026).

The subsequent router capture adds local payment-service TCP/FIPS submissions,
including acknowledgments and retransmissions. Independent replay verifies all
32 workload windows and their separate guard gaps. It delivers 93,694 of 93,696
packets: two are missing from one burst that has no payment activity or recorded
native drop/error increment. Strict clean-link acceptance therefore fails, and
the rejection is retained. All 3,072 test sats are collected, 2,064 management
checks pass, original profiles are identical across trials and restored, and all
32 owned local mint/forwarding processes are absent. At high rate, local payment
connection bytes are 7,317 per 8,000,000 delivered bytes at 500 ms and 4,878 at
1 second; these exclude physical radio overhead. The 500-ms default is unchanged.
See [the costs, loss evidence and attribution limits](CADENCE-RESULTS.md#payment-connection-costs-on-wi-fi--19-september-2026).

A same-build 1-second diagnostic pilot reproduces one missing packet in the sixth
burst; a supplemental same-stream snapshot after the quiet gap still lacks it.
Strict acceptance remains rejected, with all funds collected and original router
state restored. This narrows the timing evidence without locating the loss or
validating newer native code. See the [supplemental observation and limits](CADENCE-RESULTS.md#supplemental-burst-observation--20-september-2026).

## Sequence and acceptance

1. **Adaptive payment cadence.** Share one schedule per neighbor channel and
   paying direction. Trigger on priced usage and maximum outstanding age; recover
   unacknowledged balances and suppress confirmed-idle polling. Separate local
   durable allowance checkpoints from payment exchanges and channel renewal.
   Preserve existing agreements, signed balances and lifetime budgets. Measure
   250/500/1000/2000-ms maximum ages under idle, burst and sustained workloads.
2. **Transport and admission coverage.** Audit every production FIPS transit
   entry/exit, batching and failure path. Exercise mixed supported transports
   through the real forwarding gate. Existing results cover UDP, TCP and native
   Ethernet interfaces; generic core support alone is not a tested service claim.
3. **Permissionless neighbors.** Use authenticated FIPS identities discovered
   locally or through an explicitly enabled transport. Remove dependence on a
   private roster without letting discovery authorize arbitrary spending. Bound
   active/candidate peers, handshakes, queues, retries, bootstrap bytes, credit and
   capital. Keep routing local to actual FIPS neighbors; avoid a flat bridged LAN.
4. **Durability and long operation.** Exercise changing routes during payment,
   renewal and settlement; interrupted funding, expired offers, partitions and
   repeated crashes. Retire completed route/channel history while keeping durable
   lifetime spending and replay evidence. Any unresolved financial operation must
   keep its identity and capital reservation; never reset an account to proceed.
5. **Readiness evidence.** Reproducible seeded topology/fault sweeps, full relevant
   integration checks, measured CPU/storage/wire overhead, initialization/recovery
   procedures, supported-link/architecture matrix, and controlled router/Pixel
   regression with test funds conserved. Update the local TollGate proposal.

## Wallet costs, capital and refunds

The controller now saves a full wallet-debit reservation before funding, records
the original wallet operation and actual cost, and retains net wallet spending
across verified refunds. Every financial mutation and restart validates the same
capital/lifetime limits. Recovery includes the original cost even after quote
expiry or pause, and restores committed mint outputs for an exact persisted
opening without another spend. Replayed refunds require the SDK's durable total;
importing zero new coins is no longer treated as evidence of a zero original refund.

The nonzero-fee service fixture also exposed unused fee reserves returning above
nominal capacity. Settlement now validates the value after the funding swap;
actual debit minus the wallet-verified refund determines lifetime spending.
See [funding costs](FUNDING-COSTS.md) for limits, status fields, verification and
the required unreleased dependencies. Fresh-profile route and channel retirement
is implemented. Both the persisted-opening crash boundary and the committed
pre-opening send now recover automatically after route expiry; the latter reclaims
the original send without creating a channel. The focused process test conserves
all 384 test sats, and all 265 relay library checks passed at that checkpoint.
Subsequent cases cover safe cancellation before native funding and recovery
alongside another intent for the same provider whose original channel settlement
and wallet refund are verified terminal. Started sends without an exact saved plan, missing
evidence and still-live shared authority remain retained; [funding costs](FUNDING-COSTS.md)
describes these boundaries. Physical power-loss recovery, whole-wallet storage
bounds and dependency distribution remain open. Legacy profile migration is
outside this greenfield milestone.

The focused gates pass 89 relay tests: library, controllers, destination pricing,
fee-bearing funding/replayed refunds, standalone services, and ordinary/native
settlement. Strict all-feature/all-target linting, formatting and source-size
checks pass with the corrected local dependencies.

### Controller route-history cleanup

The recovery worker now coordinates closed-route compaction across the controller,
buyer and seller journals. It saves exact before/after accounting evidence before
changing any store, blocks competing controller mutations during the transaction,
replays an interrupted prefix before startup reconciliation, and only then removes
completed replacement/renewal references. Idle maintenance does not rewrite files.

Monotonic expiry floors prevent stale agreements from reopening after clock
rollback. Accepted channel identities and seller terms remain available to settle
funds even after their last route is removed; settle-all and stop-selling include
these retained channels. Failed writers cannot certify unpersisted memory totals.

Verification passes 136 relevant tests across the focused gates: 83 all-feature
library tests (including nine controller-retirement cases), 43 buyer/seller/ledger
and lower-level retirement checks, seven live controller scenarios, and three
fee-bearing funding/ordinary/native test-mint settlement scenarios. Strict
all-feature/all-target linting, formatting and source-size checks pass. The final
library and mint-settlement gates include the settlement-history fallback and
failed-controller-write guard. Expiry in the retirement fixtures is simulated;
these tests do not claim physical power-loss or hardware acceptance.

Controller journal version 3 loads version 2 without inventing financial evidence;
version-1 cost reconciliation remains unfinished. The later outgoing-channel
workflow below extends this route-only milestone; the seller workflow also
preserves unpaid exposure.
Active, pending, legacy and otherwise unresolved records are kept. No live device
changes or production-readiness claim accompanies this local work. See [history
and recovery](HISTORY.md).

### Completed outgoing channel retirement

New funding uses stable numbered SDK request IDs. After verified settlement and
wallet expiry, the recovery worker saves a recoverable plan across buyer,
wallet/Spilman and controller records. Cumulative signed spending and gross wallet
cost/refund totals survive deletion, restart and repeated acknowledgments. New
funding cannot reuse retired numbers; unknown old channel identities are rejected
even under renamed IDs or clock rollback. No network message was added.

The controller's 16-slot funding bound and buyer channel bounds now count retained
records. The later seller and receiver workflows below extend this milestone.
CDK activity histories still need retirement; full legacy profiles need an
explicit migration. This does not yet establish indefinitely reusable two-way
routers or production readiness.
See [the full eligibility, schema and test contract](HISTORY.md).

The focused acceptance gates pass 144 distinct tests: 90 library tests, 43
buyer/seller/ledger/route-history tests, seven live multi-node controller scenarios,
and four real test-mint financial scenarios. The new service test waits for actual
channel expiry and checks automatic cleanup, restart and retained lifetime budget
refusal. It exposed and now covers accepted settled routes being stranded until
replacement. Strict linting, formatting and file-size checks pass. These results
cover local processes and test money, not hardware power loss or public operation.


### Seller channel retirement and report release

The buyer now acknowledges report release after durable refund recovery. Completed
seller records can then retire after route compaction and expiry. One persistent
controller/ledger plan preserves exact settlement totals and each buyer/mint's
unpaid allowance across cleanup, restart and failed writes. Unacknowledged reports
remain recoverable; an absent release retry is a read-only no-op and cannot
preauthorize removal of a future channel. Existing neighbor control carries this
one-time exchange; payment and packet-delivery cadence are unchanged.

Fully paid channels recycle slots without retaining one record per former peer.
Unpaid relationships remain bounded and never get silently evicted; reaching that
bound retains further channel evidence. CDK database cleanup and legacy receiver reconciliation,
legacy/full-profile migration and hostile-identity admission remain incomplete.
See [history and compatibility](HISTORY.md) for these explicit limits.

Verification passes 154 distinct focused tests: 100 library tests, 43 accounting
and route-retirement tests, seven live multi-node controller scenarios, and four
test-mint financial scenarios. The service test keeps the buyer offline after a
lost release reply until seller cleanup, then recovers unchanged balances and
lifetime spending. The crash fixture now rolls back a report and its later release
flag together; contradictory saved state remains rejected. Strict linting, default
build, formatting and the 694-file source-size gate pass. These results cover local
processes and test money; router and Pixel acceptance remains separate.

### Coordinated receiver retirement

Seller cleanup now verifies original payout custody with the SDK before saving
an intent. One durable plan binds released reports, ledger evidence and exact SDK
before/after history. Recovery commits the ledger and receiver before removing
controller identities, under the existing wallet owner guard. A lost reply or
interruption retries that same plan without another payment or payout import.
Paid amounts remain distinct from receiver redemption reserves.

Controller version 6 requires explicit receiver history and pending SDK evidence.
Older pending seller plans can upgrade while their original IDs and reports still
exist, even after ledger removal. Already-orphaned legacy receiver records need
explicit reconciliation; out-of-band history is never silently adopted. CDK
proof history now has an explicit bounded release queue, and coordinated receiver
retirement transfers its exact original payout custody through a saved plan before
removing controller records. Unspent coins and other owners remain protected;
this does not bound total wallet storage or enumeration. Hostile-load and device
acceptance remain limited to the cases documented here, and dependency distribution
is unfinished. See [eligibility and recovery](HISTORY.md).

Ten focused seller-coordinator tests pass, covering 64 reuse cycles, changed
evidence, legacy pending upgrades and failures across all three stores. All three
financial service scenarios pass against a local test mint, including actual
expiry, lost report release, paid reserves, receiver removal and unchanged wallet
balances/lifetime spending. Fixture failure injection and local process restarts
do not establish physical power-loss or live-router acceptance.

The complete focused gate passes 163 distinct tests: 108 library, 43 accounting
and route-history, seven multi-node controller and five test-mint financial
scenarios. Strict all-feature/all-target linting, default compilation, formatting
and the 600-line relay source / 1000-line integration-test limits pass.

### Bounded incoming receipt enumeration

The SDK's receipt reader now selects at most 128 incoming sat transactions for
one mint before decoding them. An indexed timestamp/ID cursor continues through
empty eligible-result pages and survives deletion of its own row. Each call is
a separate read; a new pass sees earlier insertions or newly eligible receipts.
Selected corrupt evidence and pages exceeding 4 MiB of projected payload fail
explicitly. Unsupported backends fail without a whole-history fallback.

This bounds receipt enumeration, not total wallet storage or every maintenance
operation. Proof-owner checks still inspect complete history before permitting
deletion; normal interrupted-history recovery can run those checks before the
page read. The per-page limits do not bound that recovery. The payload limit
protects the database-driver boundary; it does not bound all database-engine
memory or proof-eligibility work. These changes add no network message or
automatic retirement authority.

The regression first fails against the old reader because malformed history for
an unrelated mint poisons receipt enumeration. The new reader passes five
SQLite-backed SDK scenarios covering that case, empty pages, tied timestamps,
deleted cursors, reopening, changing history, invalid cursors and oversized or
malformed selected rows. Exact records, balances and accounting totals remain
unchanged in those reads. All 341 SDK workspace tests, strict linting and 18
feature configurations pass. Native storage checks pass 358 common/SQL/SQLite
unit tests, including five page tests. PostgreSQL compiles but has no runtime
acceptance here; the query-plan assertion covers index use by the header seek,
not the complete generated payload query. No hardware or throughput result is
claimed for this storage change.

With the same dependency sources, all 292 relay unit tests and nine test-mint
funding/recovery scenarios pass, including expiry, restart, refunds and channel
retirement without resetting lifetime spending. Strict all-target relay lint,
formatting and the 867-file source-size gate also pass.

### Route-evidence retirement foundation

Buyer and seller accounting now share fixed-size per-channel rollups for closed,
expired per-attempt route records. Original per-route rounding, submitted and
uncertain usage, paid/reserved totals, signed amounts and lifetime budgets remain
unchanged. A durable expiry cutoff rejects stale agreements after removal and
restart. Active or pending work and legacy fingerprints block the whole batch.

The regression runs 64 replacements on each side with a one-route limit and a
restart after every retirement, keeping journals below 4 KiB. It also covers
unpaid grace, duplicate callbacks, failed writes, malformed summaries and loading
older accounting schemas. Verification passes 120 relevant relay tests, including
fee-bearing funding and ordinary/native mint settlement; strict linting, formatting
and source-size checks pass. See [history boundaries](HISTORY.md) for evidence and
compatibility. Controller coordination is described above. Completed outgoing
channels now have the additional workflow described in [history](HISTORY.md);
the receiver workflow above extends it. CDK history cleanup remains unfinished.

### Receiving during tree convergence

The intermittent healthy-trial failure was traced to session ingress depending
on an outgoing route. A responder could complete the Noise handshake before the
current tree supplied a return route; its empty route table then discarded
incoming encrypted traffic. Existing reply-path learning could not run until
recovery rebuilt the owner, by which point route selection had abandoned the
initial paid trial. This reproduced on the unchanged funding predecessor too.

Established sessions now retain their encrypted receive route while an outgoing
route is unavailable. Only authenticated incoming data can warm the existing
reply path; outgoing authorization and quotas still apply. A focused regression
fails before the change and passes afterward in tree mode, with the shared
reply-learned fixture also passing. A corrupted packet cannot deliver or create a
reply route, and does not prevent the valid packet with the same counter from
being accepted. There is no new protocol message or receipt; existing timeouts
and assertions were not weakened.

Focused verification passes 46 core tests covering routed handshakes, route
metrics, source bindings and queued outgoing traffic without a route. Strict
all-feature/all-target core and relay linting, formatting and source-size gates
pass. The full serial priced-path suite also passes its three tests across 13
scenarios: three quota/restart repetitions, loss/delay/one-way failure under two
seeds, and blackhole recovery at all four tree-root placements. The suite retains
its original timing and financial-conservation assertions. This repair is not a
production-readiness claim. Devices are unchanged.

## Earlier funding recovery after quote expiry

Recovery checks original wallet funding before applying route expiry and pause
checks. Opening and recovery share the same immutable wallet request. Completed
funding is recovered locally. An incomplete persisted opening uses the Cashu SDK's
restore-only operation to retrieve its committed mint outputs, with shared output
and signature validation. It cannot create an opening, send wallet funds or fall
back to a swap. Recording the original funding identity does not accept a quote,
activate forwarding or release reserved capital. Missing and conflicting records
retain their reservations. No new FIPS message, journal field or dependency is added.

Two journal tests exercise durable, repeatable recording and rejection of changed
funding intent or conflicting channel/payment records. The live five-node
baseline removes the controller's funded result after the wallet has committed
it, then exercises missing wallet identity, changed receiver, expired offer,
paused offer and absent offer cases. Each case repeats after controller reload,
checking unchanged wallet balance, capital reservation and acceptance counters.
The recovered wallet opening is then used for ordinary acceptance, paid quote
traffic, application traffic and final settlement in the enclosing scenario.
The quote phase also waits for the controllers' scheduled payments to cover its
submitted traffic before the separate datagram phase. An immediate burst can
otherwise exhaust the shared unpaid allowance before replenishment. It neither
forces a payment nor changes production credit limits.

That baseline covers the wallet-committed/controller-unrecorded boundary. A new
three-process case also kills the buyer after the mint commits the exact saved
funding swap, before its response reaches the wallet. It lets the quote expire
naturally and withdraws the watched route through ordinary provider absence.
The previous read-only lookup left funding unresolved; the restore-only path
recovers the original operation and channel automatically, with unchanged wallet
balance, swap count and spending authority. No purchase is installed. The test
observes retained funding before the original wallet expiry, then verifies its
unused refund and coordinated SDK/controller retirement after expiry. Spendable
balances plus mint fees conserve all 384 issued test sats; lifetime accounting
retains the original debit and verified refund.

The earlier r16 packaged ARM64 daemon also passes this exact interrupted-funding
case in an isolated Linux container, using the existing funding harness and no
fixture changes. It completes in 126 seconds, including the natural expiry wait.
Original funding, debit, refund and the 384-test-sat conservation assertions pass;
the source bundle and both executable hashes remain unchanged. This extends the
nine r16 transport, customer-restart and storage checks with unused-funding expiry
acceptance. It does not accept used/shared-channel unilateral recovery, current
routers or physical power loss.

The shared SDK cases cover idempotent completion, empty and partial restore,
invalid signatures, changed terms, missing custody evidence and a missing opening
signature. A nonzero-fee proxy regression also verifies that a disconnected response
cannot erase a mint charge from the test evidence. These checks do not establish
recovery before a channel opening is persisted, physical power-loss durability or
renewed routing permission. An empty restore is uncertainty, not permission to
spend or retire the record. The ordinary opening API retains its swap fallback
for separately authorized purchases; expired-route recovery never calls it.

The matching source passes all 232 relay library tests, all four fee-bearing
funding process cases and the five-node controller baseline described above.
Strict all-feature/all-target relay lint, workspace formatting and the 771-file
size gate pass with the local development dependencies. No device deployment is
implied by these software checks.

Expired withdrawn requests which never reached funding now release their
reservation slots through ordinary upkeep. Removal requires no funding intent
or retained shared work for that provider, and occurs under the same lock as
funding. The existing offer-expiry fence advances only to an actually removed
offer's expiry; this keeps already-expired authorization invalid after clock
rollback without implying any financial completion. Newer watches, funding
sequences and financial totals remain unchanged. Regression checks cover delayed
workers, reload, pending retirement, older uncertain funding, and reclaiming a
full 32-slot book. All 179 library tests and strict all-target linting pass.

Fully identified, never-used withdrawn channels now recover their verified refund
after immutable wallet expiry. The controller saves a distinct expiry intent;
it does not invent provider usage, payment, settlement reports or acknowledgments.
The SDK's actual recovered amount remains authoritative. Recovery fences delayed
channel installation and uses the existing coordinated retirement path, including
an explicit never-installed buyer entry and a durable expiry floor. Initial
eligibility rejects shared or previously used channels; later unrelated provider
selection cannot strand completion of an already saved exact refund intent.

Three real-mint checks cover expiry enforcement, a locally installed but unused
channel, and SDK completion lost before controller recording. In the last case,
all recovered funds are spent into another wallet before reload; replay preserves
the exact refund without importing it twice. This exercises the SDK-to-controller
boundary, not an additional HTTP response-loss injection. All 186 library tests,
strict all-target linting, formatting and the 730-file size gate pass. Hardware
power loss and used/shared-channel unilateral refunds were not covered by that
earlier check; the current used/shared-channel acceptance is recorded above.

An intent with no recovered channel must retain its full reservation:
the SDK's empty lookup result also covers incomplete wallet operations, so it
does not prove that no money was spent. Missing or conflicting original financial
evidence remains outside the verified recovery paths.
These retained records can exhaust bounded slots, and an early unresolved funding
sequence can block retirement of later completed channels. Safe retention alone
does not establish indefinitely reusable accounts.

Run `cargo test -p fips-relay --lib controller::funding::tests`,
`cargo test -p fips-relay --test controller`, and the focused interrupted-funding
command in [funding costs](FUNDING-COSTS.md).

Verification passes 70 library tests and all seven controller-target tests across
runs. The full controller run passed six tests; the affected baseline passed
after correcting fixture serialization and observing automatic quote payments
before the separate data phase. All live scenarios conserve their test funds.
Strict all-feature/all-target relay Clippy, formatting and the 669-file size gate
also pass. No hardware or performance acceptance is claimed for this change.

## Concurrent transition reservations

Route-change and renewal workers now reserve shared channels in the durable
journal mutation, checking the current predecessor, acceptance, settlement and
renewal state there. Either worker can win; the other must retry after completion.
Both predecessor channels and a replacement provider's shared channel are
reserved. Paused route changes retain their reservation. Accepted replacement
history does not prevent later renewal, and a reservation conflict does not skip work
on other channels. Startup rejects overlapping unfinished intents without
discarding financial records; see [service recovery](SERVICE.md).

Ten deterministic journal tests cover both reservation orderings, restart
between steps, stale acceptance/predecessor/settlement/trial snapshots, the
replacement-acceptance boundary, a new provider's shared channel, unrelated
channels and conflicting legacy state. They exercise the actual reservation
and storage code, using fixture
payment records rather than mint signatures. This is not an exhaustive
route/payment/renewal/settlement fault matrix. In particular, interruption after
each network/mint boundary, automatic free-route transitions and history
retirement remain part of the broader acceptance work.

Run these with `cargo test -p fips-relay --lib controller::transition_tests`;
`cargo test -p fips-relay --test controller` exercises live native routing,
actual test-mint payments, renewal, route replacement, reload and final
conservation of funds.

The final reservation implementation passes all 61 relay library tests and
all seven controller-target tests (six live five-node scenarios plus the
identity-matching gate test). Strict all-feature/all-target relay Clippy,
formatting and the source-size gate also pass. This is isolated software
evidence; no new router, phone or radio acceptance is claimed.

## Purchases during closure and interrupted acceptance

Purchase checks now share one implementation at request reservation, funding
selection and purchase recording. They reject expired/paused/retired offers,
closing channels and competing renewal authorizations. Renewal cannot seal a
shared channel with an unacknowledged purchase. Acceptance completion checks
closure state in its journal mutation. Explicit settlement can proceed while
acceptance is in flight, and late replies cannot reactivate closed purchases.
No financial lock spans multi-hop acceptance, and no protocol message or journal
field is added.

A confirmed refund retires interrupted, unacknowledged purchases on that channel
without dropping financial records. It clears their pending offers, including
source-watch references, and releases their route-change reservation. Replaying
an earlier recovery snapshot cannot recreate the same authorization. This is
closure of interrupted work, not bounded retirement of old financial history.

Seven new journal tests cover closing/renewing channels, state changes between
funding selection and recording, unacknowledged shared-channel purchases,
refund-confirmed retirement, restart, late acceptance, stale replay and expired
authorization. The live five-node baseline holds a real acceptance request and
allows settlement to queue its Seal RPC while that acceptance remains in flight.
It cancels the purchaser and drops the held acceptance before the provider handler.
With Seal still held, it verifies that a new destination is rejected promptly without
another request, purchase or funding record, and that the cancelled purchase
is retired only after confirmed settlement. Existing repurchase, reload and
full test-fund conservation checks run afterward.

These checks do not cover every mint-response loss or power-loss boundary, nor
do they establish fair latency for simultaneous purchases on one channel.
Automatic free-route transitions, history compaction, permissionless mobility
and controlled hardware/performance acceptance remain work.

Run `cargo test -p fips-relay --lib controller::purchase_state_tests` and
`cargo test -p fips-relay --test controller` for this boundary and its live
controller regressions.

The final implementation passes all 68 relay library tests and all seven
controller-target tests, including the six live five-node scenarios and final
test-fund conservation. Strict all-feature/all-target relay Clippy, formatting
and the 667-file size gate pass. These are isolated software results; hardware
and updated performance acceptance remain outstanding.

## Simulation reuse

The existing `fips-sim` crate starts real endpoints over `SimNetwork` and runs
under Tokio's paused clock. It already models seeded regional/random topologies,
loss, bandwidth, latency, partitions, blackholes and churn. Its `production_mesh`
example supports large graph sweeps; `wot_admission` covers open discovery,
newcomer probe slots and rejection of untrusted rating spam. Those are routing/
admission foundations, not proof of paid forwarding. Extend these facilities
instead of introducing a second router. Keep virtual routing time distinct from
wall-clock mint/crypto integration until their financial expiry clocks are aligned.

The Docker `testing/chaos` harness also has mixed-technology, TCP, Ethernet and
churn scenarios, with real interfaces and netem. Use the in-process harness for
bounded repeatable sweeps and the existing container harness for carrier/bypass
acceptance; preserve its network isolation and do not duplicate topology logic.

The current hashtree `hashtree-sim` contains a local relay fixture; its old mesh
simulator was retired. Its `hashtree-network` topology/recovery tests provide the
useful pattern: production routers and wire codecs over a minimal instrumented
carrier. They cover chains, cycles, churn, corruption and cancellation. Do not
revive the removed quote/chunk payment protocol or copy simulation-only business
logic. Measurements must state which framing/transport layers they count.

## Initial transport/admission audit

The optional native forwarding policy is consulted in the shared SessionDatagram
transit preparation path, before transport submission. Locally originated evidence
is attached for both scalar and batched data-plane sends; transit packets cannot
manufacture that local provenance. This is a useful common enforcement point,
not yet a full mixed-transport acceptance result. Local destination delivery and
routing/discovery control have distinct paths that need explicit bootstrap bounds.

Ethernet already has versioned public-key discovery beacons and a bounded pending
peer buffer. Discovery scope is explicitly a noise filter, not access control.
At the initial audit, the relay service disabled native discovery/auto-connect
and authorized outgoing purchases through configured neighbors. Its customer control
exception is direct authenticated UDP within a configured subnet. Permissionless
router admission therefore needs a coherent discovery/admission/purchase policy;
simply enabling Ethernet beacons or removing the Wi-Fi password is insufficient.

The cadence fixture exposed an end-to-end bootstrap constraint in the original
tariffs: a forward purchase does not admit the reverse FSP handshake reply.
The explicitly negotiated [forwarding-data tariff](BOOTSTRAP.md) now provides
strictly shaped, per-neighbor and aggregate-limited free session establishment.
A five-process test crosses three relays to an unfunded recipient, retains
agreements across full restart, rejects unpaid reverse data and conserves all
1,024 test sats after three settlements. Existing tariffs retain their semantics.
The cadence measurements funded both directions and predate this change; they
are not performance evidence for it. Broader bootstrap/adversarial acceptance
and saved-account migration remain work.

## Destination-specific prices and free local destinations

The service now supports explicit [destination fees](DESTINATION-PRICING.md),
keyed by canonical FIPS identities, with the existing default fee elsewhere.
Each router adds its local fee to the onward quote. Zero local markup over a
paid continuation still requires paid agreements; an entirely free route uses
bounded, expiring in-memory permissions without a channel or wallet debit.
Zero prices require the explicitly selected forwarding-data tariff. Saved
financial terms and accepted prices remain unchanged by future fee edits.

A five-process UDP test crosses three free relays, restarts and resumes with
zero mint requests and no funding. Another mixes different destination prices,
zero markup over a paid continuation, and a paid prefix with a free tail. Its
two neighbor channels settle and conserve all 512 isolated test sats. Unit
checks cover identity matching, quotas, expiry, state limits and paid/free
transition exclusions. Free permissions do not infer ownership from a source,
IP range or interface.

This is explicit route opening, not automatic free-route refresh. Permissions must be reopened after restart, expiry or path
change. Active paid agreements must close before the same relationship becomes
free. Radio/mixed-transport acceptance and broader concurrent transition/failure
coverage remain work. The earlier no-mint startup evidence exercised the service directly. The r57
wrapper removes its separate mint probe and passes focused shell checks with
platform doubles; actual OpenWrt startup during a mint outage remains pending.

## Cheapest routes that work

Core now exposes native `source_route_quality` and explicit `set_source_route`
first-hop bindings for an embedding controller. A four-endpoint SimNetwork
diamond tests actual forwarding and MMP feedback in both Tree and ReplyLearned
modes: a transit blackhole with healthy neighbor links times out, and an
explicit carrier switch restores delivery and reports. Binding tests cover
64-entry capacity, authenticated-neighbor admission, unchanged transit routing,
cached-output replacement, failure without fallback, and same-hop feedback
invalidation. See [source route API](../fips-core/SOURCE-ROUTES.md) for limits.
The core simulation itself involves no prices, channels, payments or radio links.
The opt-in relay [price and quality selector](PRICE-SELECTION.md) now builds on
this API: it ranks actual adjacent quotes by estimated delivered-byte cost with
loss/RTT ceilings, limited unknown-path trials, recent-cost retention, hysteresis
and provider cooldown. The real paid SimNetwork diamond passes all four root
positions, preserves channels/history through trial upgrade and path replacement,
restores a controller/selector reload, and settles all isolated test money. A
separate exhausted-trial case proves that automatic renewal and reload do not
reset the quota. Early source admission now rejects known quote exhaustion before
native sequence/send counters, so local refusal cannot masquerade as wire loss;
paid and free reservations reuse their existing counters. Local control refusal
does not penalize native routing, and coordinate/packet-size updates retain the
authenticated reply carrier rather than displacing earned return allowance.
Cold-cache setup also
retains the real destination identity for strict bounded bootstrap. This is local
candidate selection, not global optimality or broad production acceptance.
Eight deterministic core recovery cases now preserve initial/rekey state after
local send cancellation and preserve the correct key-epoch flag on coordinate
warmups. They verify actual payload delivery after recovery. Six paid deployments
now exercise forward loss, excess latency and a failed return direction over two
seeds. The same harness verifies replacement delivery, feedback, reload and funds.
Observed carrier changes reset native smoothing and reject old-path timestamp
echoes; no new measurement messages or financial receipts are introduced.
The reproduced large-mesh failure came from tree mode using an asymmetric
handshake return neighbor for outbound traffic and retaining broken reply affinity
after `PathBroken`. Initial tree sessions now use the native forward route;
established reply paths survive refresh/rekey and explicit failure releases them
in both routing modes. A separate delayed-report regression keeps a newer
unanswered request eligible for recovery using the existing timestamp echo.
This aggregate feedback remains limited by timestamp resolution and is not a
per-packet delivery acknowledgment.

Current local acceptance passes all 152 session tests, including 200/200 payloads
in the 100-node mesh, 112 dataplane tests, the source-quality integration in both
routing modes, and all three paid-path tests (13 deployments with test funds
conserved). Strict core/relay/simulator linting also passes. Test teardown now
drains forwarding completions before closing carriers, matching production stop.
These results cover the reproduced failures, without attributing every historical
intermittent stall to the same causes. Longer stress runs, remote credit/payment
effects, full restarts and the remaining impairment/mobility matrix remain open.

The paid diamond also passes two departure/rejoin cycles in each of two root
placements and seeds. Its source starts with one adjacent provider, then admits
the second through shared authenticated-adjacent control with empty control
rosters. SimNetwork removes the original carrier until both native endpoints
report it disconnected. Automatic selection uses the available provider and
returns to the cheaper original provider after reconnection; no further Buy,
Watch or payment-flush command is issued. Every handover delivers fresh payloads,
obtains native feedback on the selected carrier and advances automatic seller
credit. Both original 64-sat channels and their funding operation identities are
retained through repeated use. Locked capital and historical wallet debits stay
at 128 sats after the second channel opens, refunds remain zero, and the lifetime
buyer allowance never increases. Controller/selector reload still delivers, and
each deployment conserves all 259 test sats after final settlement.

These are real controllers over explicitly configured simulated carriers, with
a two-second feedback/cooldown policy. They do not establish radio discovery,
physical movement, open-radio admission, or interruption before a replacement
purchase is accepted. Run the focused case with `cargo test -p fips-relay
--all-features --test priced_paths
mobile_neighbors_reuse_channels_and_preserve_spending_authority`.

A continuously active source watch now also passes separate real carrier-loss
and delay cases. It leaves the impaired cheaper provider, promotes a working
alternative, then retries and promotes the recovered cheaper path. No additional
Buy, Watch, payment flush, forced source binding or injected quality observation
drives these transitions. Fresh application payloads and native feedback verify
each selected path. Both deployments reuse the original two channels, keep
historical debit and locked capital at 128 sats with no early refund, preserve
the lifetime spending bound through reload, and finally conserve all 259 test
sats. This fixture uses ten-second feedback/cooldown and a 55-second deadline
per transition; it does not establish production failover latency.

The delay case first reproduced a stale cached full offer pinning the watch
after a healthy recovery trial. Paid and free trial promotion now negotiate a
fresh full offer; a still-active full agreement remains reusable. The selector
regression failed before that change, and the unchanged automatic integration
then passed both scenarios. This prevents the obsolete pending intent on the new
path; it does not migrate a watch already stuck by older code. Broader physical
mobility and hostile-load acceptance remain separate work. Run the focused case
with `cargo test -p fips-relay --all-features --test priced_paths
automatic_quality::automatic_watch_leaves_impaired_routes_and_reuses_recovered_channel`.

A combined case now keeps the same active watch while 35% forward loss first
selects the better alternative, that neighbor departs, and the impaired original
route regains delivery, fresh native feedback and automatic payment. The
alternative then rejoins and is selected; repairing the cheap route returns to
its original channel. Every later handover reuses the two original channels,
without increasing lifetime allowance or releasing their capital. Reload and
settlement conserve all 259 test sats. The existing automatic loss/delay cases
and strict relay lint also pass with the shared helper changes.

The combined case uses the production 32 KiB trial allowance. Its fallback
consumes 21,358 billed trial bytes before promotion. An earlier 8 KiB fixture
stopped at 8,178 bytes without fresh feedback; that failed evidence is retained.
Trial capacity therefore constrains whether a working impaired path can be
verified. This is one simulated topology/seed with sparse application traffic,
not a general mobility or traffic-rate guarantee. Run it with `cargo test -p
fips-relay --all-features --test priced_paths
quality_failover_survives_alternative_departure_without_refunding_or_rebuying`.

A watched paid offer now becomes pending in the same journal transaction that
reserves its purchase or route change, after native neighbor admission. A peer
that disconnects before this boundary cannot pin the watch to an unreserved
quote. The transaction rechecks the captured watch's price ceiling, billing,
pause state and pending intent; stale authority leaves no partial reservation.
The regression first reproduced the old failure through a real endpoint and
controller. Four focused tests, all 156 relay library tests and the existing
automatic paid-watch integration pass, including reload and retained-intent
checks. The combined four-test priced-path suite also passes all 15 deployments
with this change: quota exhaustion, loss, delay, asymmetric feedback, blackholes
and mobile neighbor changes.

For an already-reserved watched purchase, observed neighbor loss now withdraws
routing authority while retaining the original financial intent. The withdrawal
is durable before local quotes close, and quote installation uses the same lock.
Failed accounting writes still stop the affected local packet authority; startup
reconciles a crash between the journals. Late success cannot reactivate the old
route. A returning neighbor's detached channel uses ordinary automatic settlement,
with an atomic check that no other eligible route or reservation still needs it.
No new payment messages are introduced. See [retained recovery authority](HISTORY.md#withdrawn-routing-and-retained-recovery).

The real-mint diamond holds a successful provider acceptance after the provider
commits it, then removes that neighbor before the source receives the reply. The
original provider resumes with its existing channel and automatic payments while
the interrupted channel remains fully reserved. On the final run, its automatic
refund appears 2.44 seconds after authenticated rejoin, before any manual settlement
call; reload and final collection conserve all 259 test sats. The held response is
canceled by disconnection, so a consumed late success is covered separately by
deterministic journal tests, not claimed for this network run.

The lost-settlement-reply variant extends that same abandoned-account scenario.
It holds every successful `Settled` reply after the real provider has closed at
the test mint, imported its proceeds and saved its report. The buyer still has
no report or refund. Both carrier edges to that provider are then cut and the
held responses discarded. All four directed native memberships must become
disconnected. The original provider continues delivering fresh traffic and its
automatic payment is acknowledged while the unresolved channel remains locked.

After native rejoin, the existing workers must recover the identical report,
refund once and persist release on both sides within 30 seconds, before any
explicit settlement replay or cleanup. Final signed payments, funding/channel
and wallet-operation identities, policy and lifetime spending bounds remain
unchanged. The explicit replay then returns the same report and financial totals.
Controller/selector reload preserves the remaining route. Final settlement
checks each wallet's expected proceeds and collects all 259 test sats, leaving
every node wallet empty. Independent wallet inspection waits until controller
workers stop, avoiding contention with background history retirement; automatic
recovery acceptance happens before that shutdown.

The new case, the original lost-acceptance case and both interrupted-promotion
cases pass, alongside strict relay lint, formatting and the source-size gate.
The response gate and wallet collector are shared with the existing fixtures.
No production behavior or wire messages change. This is software evidence for
two specific lost-reply boundaries with isolated test money, not physical-radio
or power-loss acceptance. Reproduce with `cargo test -p fips-relay --features
measurements --test priced_paths mobility::pending::settlement::`, using the
development dependencies in [FUNDING-COSTS.md](FUNDING-COSTS.md).

Review also reproduced two branches where equivalent concurrent source/transit
offers could bind a watch to an unsaved offer ID. Both now bind the retained
purchase; successful completion rechecks that exact purchase and the captured
source authorization before clearing it. All three production-path regressions,
171 library tests, strict all-target linting, formatting and source-size checks
pass. The complete five-case priced-path suite passed 16 deployments before this
last narrow binding correction; the affected interrupted-mobility scenario passes
again on the final source. The later expiry cleanup above reclaims never-funded,
unreferenced reservations and verified expired, never-used funding. Uncertain
funding and used/shared-channel recovery still retain bounded slots and capital.
This does not establish arbitrary physical movement or power-loss recovery.

Price-aware route selection is an explicit requirement, not proven by simply
accumulating prices along the native planner's chosen next hops. Reuse FIPS's
existing MMP link/session receiver reports, RTT/loss/goodput/ETX estimates,
freshness checks, fallback routing and route-quality tests. Do not build a
parallel measurement stack or inspect encrypted application traffic at relays.
Higher-layer success, timeout or acknowledged-byte observations may supplement
native measurements at the local endpoint if they can be attributed to the
actual route and sampling interval. Missing feedback means unknown quality.

Compare eligible loop-free paths using agreed monetary costs and observed
quality under explicit spending/capital limits. Define the service's minimum
quality and how to treat unknown/new paths; bound exploratory spending and
avoid route oscillation. A quote is not proof of a working path, and local
link acknowledgments are not end-to-end delivery evidence. Measurement reports
need not be per-packet payment receipts and must not authorize wallet spending.
Recent successful delivery is an estimate, not a guarantee of future service.

Use existing SimNetwork/fips-sim and production route selection. Required cases:
a cheapest healthy path, a cheaper blackhole, loss/delay/asymmetry/congestion,
stale/replayed or misleading reports, unknown paths, disappearing feedback,
changing prices, mobile merge/split and recovery, alternate paths, zero-price
destinations, limited capital and insufficient reverse/control reachability.
Measure delivered-byte cost, goodput, latency, convergence, exploration cost,
control overhead and state bounds; use an independent small-graph reference
where an exact optimum exists. Bind the actual forwarded path to the quote.

Native quality monitoring already exists in `proto/mmp/metrics.rs`,
`node/handlers/session/node_reports_errors.rs`, `node/tests/session/route_metrics*`
and `node/tests/routing/stale_metrics.rs` under fips-core. The relay's new free
handshake allowance excludes established encrypted session reports. The opt-in
[bounded return allowance](RETURN-ALLOWANCE.md) now earns opaque reply credit
from admitted forward traffic. A five-process paid path obtains session RTT and
positive goodput from an unfunded recipient before and after restart; the free
destination case also obtains native quality with zero mint requests. Credit,
rate, expiry and exact reverse-path bounds apply; this is not report-only traffic
or guaranteed feedback. Impaired/asymmetric/mobile paths, hostile contention,
transition races and performance still need acceptance. Dedicated monetary
delivery receipts remain an optional experiment.

The ETX literature is a reference for loss-aware link metrics, not proof of
optimal monetary routes or malicious-relay resistance:
[De Couto et al., MobiCom 2003](https://pdos.csail.mit.edu/~decouto/my-papers/mobicom03.pdf).

## Boundaries and threats

- Quote discovery uses existing authenticated TCP/FIPS. A bounded complete-offer
  cache and shared in-flight requests avoid repeated downstream negotiations;
  the quote server adds an aggregate rate limit across identities. Forwarded
  quotes use ordinary negotiated byte accounting, with no quote-specific fee or
  free transit exception. See [cache and admission limits](README.md#price-cache-and-request-bounds).
- A minted token and signed balance authorize payment, not delivery. The mint
  remains a trust dependency; neighboring relays can drop traffic. Exposure must
  remain bounded even with false usage reports, stale replies or crash gaps.
- Anyone may seek a connection; admission is not unlimited capacity or free
  forwarding. Identity churn must not reset shared limits or reserved liabilities.
- Discovery, route establishment and payment need a bounded unpaid bootstrap.
  A payment requirement for the messages needed to pay would deadlock joining.
  Audit that exceptions cannot carry arbitrary unpaid application traffic.
- Source policy controls aggregate price, budget and permitted onward purchases.
  A discovered peer, inbound quote, received packet or new route never grants a
  blanket authorization to spend the router's wallet.
- L2 neighbor links are sufficient for native wireless participation. Standard
  802.11s can provide one-hop radio adjacency while FIPS owns multi-hop forwarding;
  ordinary phones use AP/UDP access. Each local radio neighborhood can use its
  own channel; the global FIPS network need not share one SSID or broadcast domain.
  An open radio link removes the shared-secret
  invitation but does not provide RF anti-jamming or universal driver support.
- Keep normal management/Internet access separate from customer/relay discovery.
  Test new admission on isolated interfaces before changing the physical bench.

### Denied discovery advertisements

Transport discovery now checks outbound permission before reserving its bounded
dial budget, matching LAN discovery. Previously, a denied new peer or denied
alternate advertisement for an existing peer could consume the only poll slot;
the later connection check rejected it, leaving an allowed neighbor undialed
despite free capacity. The final connection path still rechecks permission.

Three native Sim regressions reproduce that failure on the previous code and
pass with the common prefilter. They cover an empty roster, an active refresh
with spare peer capacity, and full-roster rotation with a separate idle victim.
Each authenticates the allowed neighbor and delivers a fresh application payload;
the active owner is retained and the denied advertiser's undrained receive queue
stays empty. Repeated adverts retain the same pending attempt and resource caps.
All 34 simulated discovery tests, the LAN regression, nine Bluetooth tests and
strict core lint pass. Reproduce with core test filter
`node::tests::sim_discovery::discovery_acl::` and the existing development dependency
configuration. No timers, admission allowances or wire messages change. This
fix does not explain the default-allow crowded timeout or establish radio mobility.

## Mobile routers are a first-class case

A neighborhood means the currently reachable peers, not a fixed region or a
permanent membership. Router identity, wallet, spending history and neighbor
channel identity survive physical movement. Discovery and route selection follow
changing adjacency. Returning to an earlier peer should reuse an eligible saved
channel; a new peer needs its own independently bounded agreement. Disconnection
must not manufacture a refund or release unresolved capital prematurely.

Test moving relays and endpoints through overlapping coverage, short outages,
asymmetric links, repeated old/new neighbor transitions and topology changes
while a payment, renewal or settlement is pending. Measure reconvergence time,
loss, unpaid exposure, locked capital and recovery after a return, in addition to
stationary throughput. Mobility must not require a central enrollment service.

One common mesh channel is the simple initial radio rendezvous mechanism.
Multiple channels are optional; discovery/scanning and handover need explicit
capability and interruption tests, especially on a single radio. Keep financial
identity independent of channel, MAC address, interface, IP address and position.
A mobile topology can change faster than settlement; admission/capital policy
must fail within its bounds without freezing unrelated healthy neighbors.
Payment exchanges now run independently per channel, with same-channel payment/
settlement exclusion and bounded worker ownership. The delayed-control regression
is a step toward this acceptance, not evidence of radio handover or fair progress
through every renewal/recovery operation.

### Ad hoc formation acceptance

Start independently operated routers with compatible mesh radio settings and no
preconfigured peer identities or addresses. Nearby routers must discover and
authenticate each other, exchange bounded control traffic and form paid routes
within each operator's price, credit and capital policy. No shared private mesh
password or central enrollment may be required by the permissionless profile.
Radio compatibility still needs a common mesh ID and an overlapping channel;
FIPS identity authentication happens above that link and is not a promise of
unlimited admission or trust in a newly seen public key.

Test two independently formed meshes approaching, joining through moving bridge
routers, separating and meeting again. Preserve identity, eligible channels,
unsettled obligations and lifetime budgets throughout. Include a previously
unknown neighbor, short overlap, repeated link flaps and more candidates than
available admission slots. Demonstrate useful progress for healthy peers while
other peers are absent or slow, and measure join/rejoin time and bounded state.

The six-node `priced_paths::merge_split` simulation now exercises two independently
formed three-node components, each carrying paid traffic before contact. A new
bridge link joins them; both directions then pay all four forwarding hops. The
bridge disappears, both components regain their own tree roots and continue local
paid delivery, and fresh cross-component probes cannot cross the partition. On
meeting again, every paying neighbor pair retains its original channel and funding
operation. No new Watch, Buy, explicit payment flush, peer roster update or session
reset drives that recovery. Stable checkpoints reject pending funding and retain
all capital limits and lifetime spending. Both placements of the combined tree
root pass, with eight original directional channels per case and all 1,536 test
sats settled and collected into the isolated collector wallet. Each settlement
redeems at least the acknowledged payment; each wallet must equal its initial
balance minus purchases plus that router's relay earnings before collection.

The `merge_split::crowded` variant also passes (2026-09-20). After the first paid
merge/split, eight unfunded, roster-free endpoints compete for the two spare
bridge slots. Both local paid routes deliver fresh payloads and advance credited
payments while native observations show the bridge slots full. When all competing
neighbors depart, the original cross-component Watches recover automatically:
the same eight directional channels advance without new funding, changed Watch
authority or reset lifetime budgets. All 72 unique payloads arrive in 72 attempts
across six finite bursts, and all 1,536 test sats reconcile and are collected.

The six paying nodes have 340 observation rounds, with maxima of two peers, two
pending connections, four links and three sessions per node. A simultaneous
authenticated dial may temporarily retain an outbound link beside its inbound
counterpart; the fixture bounds links by the configured link limit plus pending
connections. After convergence it requires zero pending connections and exactly
one link per peer. These are sampled resource/fullness checks, not continuous
occupancy, newcomer fairness at capacity, radio airtime or physical mobility
evidence. Candidate departure is explicit; healthy admitted peers keep their slots.

The optional full-roster variant passes without candidate departure (2026-09-21).
It enables [`node.neighbor_rotation`](../../docs/design/fips-configuration.md#optional-neighbor-rotation-nodeneighbor_rotation)
with a ten-second idle threshold and two-second attempt interval on the six
paying nodes. Eight unfunded adjacent candidates remain physically available.
Only the bridge carrier changes during acceptance: native discovery and fresh
authentication must replace idle learned neighbors within the existing limits.
Configured peers and recent application demand, whether free or paid, remain
protected. Msg1 replay, failed proof and demand appearing before confirmation
cannot displace the incumbent. No new protocol messages are used.

The accepted run observes the authenticated bridge and common tree at 33.374 s,
then fresh two-way delivery and credit on all eight original directional channels
at 35.137 s. These times include discovery, polling and payment catch-up, not just
packet latency. An independent one-packet-per-second local workload delivers
36/36 packets in each direction with no duplicates and a largest delivery gap of
1.015 s. The original local link IDs and authentication epochs remain unchanged.
Across 189 native observations, maxima are two peers, two pending connections,
four links and three sessions per node. The same channel/funding identities and
spending bounds remain, and all 1,536 test sats reconcile and are collected.

Continuous traffic initially exhausted the fixture's 128-KiB local route allowance
(131,032 bytes used, 40 left). This variant authorizes 384 KiB per offer, costing
at most 48 sats at its 128-msat/KiB rate, within the unchanged 64-sat channels.
It does not remove byte accounting or increase wallet, channel or funding limits.
The finite workload and five-second maximum local delivery gap remain enforced.

Run this case with `cargo test -p fips-relay --features measurements --test
priced_paths merge_split::crowded::automatic::full_rosters_form_a_paid_bridge_without_forced_departure
-- --exact --test-threads=1 --nocapture`. Focused native tests also exercise real
TCP pool release and remote EOF before shutdown, fresh traffic on the replacement,
and an exact prepared replacement surviving elapsed time during carrier cleanup.
This simulation does not establish physical roaming, channel coordination,
subsecond handover, Sybil fairness or general topology preservation. Idle-neighbor
selection scans existing bounded session and demand state. Admission-query CPU
measurements follow below; current hardware evidence predates this policy.

An explicit release-build microbenchmark measures the production admission query
over populated native peer and FSP-owner metadata (2026-09-21). It covers 23
combinations of 2/8/32/128 neighbors, 0/64/256/1,024 session owners, idle demand,
recent received data, recent admitted transit, cooldown, another pending candidate,
and disabled rotation. Each sample queries 64 distinct candidates at a fixed policy
time; seven samples follow repetition calibration. Every sample checks the same
expected admission decisions and unchanged peer count. Thread CPU and wall time
are separate; the values below are median CPU per query on aarch64 macOS with
Rust 1.96.0. Repetition counts and maximum sample costs are emitted with each row.

| State | Neighbors / sessions | Before | After |
|---|---:|---:|---:|
| Idle learned peers | 8 / 64 | 16.455 µs | 2.253 µs |
| Idle learned peers | 128 / 1,024 | 4,365.054 µs | 36.698 µs |
| Cooldown rejection | 128 / 1,024 | 4,328.953 µs | < 1 µs |
| Unrelated pending candidate | 128 / 1,024 | 4,314.257 µs | < 1 µs |
| All protected by recent transit | 128 / 1,024 | 1.734 µs | 0.169 µs |
| All protected by recent received data | 128 / 1,024 | 187.684 µs | 190.565 µs |

Cheap cooldown/candidate checks now precede session scans. Victim metadata is
ordered by the existing age/identity key, then demand is checked only until the
first eligible victim is found. Recent transit excludes peers before sorting.
This keeps the exact victim choice and fresh promotion validation without caching
demand across calls. The large idle case uses about 99% less query CPU. The
RX-only protected cases are slightly slower: 0.721 to 0.833 µs at 8/64 and 9.534
to 10.673 µs at 32/256. This is not a claim of improvement for every workload.

These measurements exclude state construction, cryptographic authentication,
discovery enumeration, real slot reservation, packet forwarding and payments.
They do not predict OpenWrt throughput, whole-node CPU or physical mobility.
The session metadata is populated through native APIs; no live traffic is driven
during a timed sample. Very cheap cases can reach the repetition cap before the
ten-millisecond calibration target. Run explicitly with `cargo test
-p nvpn-fips-core --features sim-transport --release --lib
node::neighbor_rotation::benchmark::admission_cpu_by_roster_and_session_count
-- --ignored --exact --test-threads=1 --nocapture`, using the workspace's
development dependency overrides where required.

After the optimization, all 54 native handshake, two discovery and five local/
transit-demand tests pass. The paid full-roster case again preserves the original
local link epochs and eight channels: 32/32 independent local packets arrive in
each direction, fresh cross-component delivery and credit complete at 31.245 s,
and all 1,536 test sats are collected. This is a functional regression result;
the difference from the previous encounter time is not an established latency
improvement.

The admission audit reproduced a fresh inbound identity bypassing connection/link
limits when peer slots remained. The gate now applies before index/link allocation,
preserving the authenticated simultaneous-dial exception. The crowded fixture then
exposed rejected outbound promotions retaining orphan links and pending dial entries
after the connection itself was consumed. Those entries now retire before physical
carrier closure, preserving any healthy owner sharing that carrier. Focused real
UDP regressions fail before these fixes; all 43 handshake tests, native discovery,
strict core/relay lint and the source-size gate pass. The crowded regression checks
final cleanup as well as delivery and financial conservation.

The full-roster admission audit also reproduced an unconfirmed inbound renewing
its slot (2026-09-21). A fresh Noise Msg1 from the same identity and carrier could
replace its pending inbound after the attempt cooldown but before the handshake
timeout. The replacement now retains the first connection's activity timestamp
when that identity is not active and the roster is full. Timeout cleanup and
encrypted confirmation therefore enforce the original connection deadline.
Admission, attempt pacing and promotion checks remain unchanged. Exact duplicates
still resend the current stored Msg2; authenticated peers and simultaneous dials
retain their existing paths. No wire message, state table or additional admission
slot is introduced.

The native regressions check two fresh replacements and 32 additional identities
on shared and separate source addresses, including another path for the same
identity. They check identical responses to exact retries, rejection of superseded
encrypted proofs, resource/index bounds, and an incumbent's continuing heartbeats
and unchanged link generation. Every replacement retains the first activity
timestamp; the real three-second timeout frees its slot for another neighbor to
confirm and exchange encrypted traffic. Another case checks fresh confirmation
after the normal retry interval but before the original connection deadline. The
simulated-carrier case dispatches
actual Noise packets through native ingress, then runs timeout cleanup followed
by discovery in the production maintenance order. Discovery selects and
authenticates another advertised neighbor after the original timeout without
removing any carrier, fabricating connection state, or configuring a peer roster.
All 56 handshake and three discovery tests, strict core/relay lint and source-size
checks pass. The paid full-roster regression preserves the original local link
epochs and eight channels: 51/51 independent local packets arrive in each direction,
with no duplicates and a maximum observed delivery gap of 2.293 s. The bridge and
all-hop credit complete at 50.648 s, within the existing 60-second gate; all 1,536
test sats are collected. This is slower than the 25.554-second unchanged control
run and does not establish a fixed latency bound. The 267 native samples stay
within the existing limits (two peers, two pending connections, four links and
three sessions at most).

These checks bound one continuously retained inbound connection and establish
recovery for this sequence. They do not establish fairness among newly admitted
identities or later attempts after cleanup, radio contention tolerance, or useful
progress under every possible packet schedule.

Incoming attempts also no longer reset local discovery's exploration cursor
(2026-09-21). A first inbound attempt can seed the cursor, but only subsequent
outbound attempts advance it. The native regression establishes ordered peers
B < C < D, authenticates incoming C, discovers and authenticates D, then accepts
a fresh incoming C. The next discovery now selects B; before the fix it selected
D again. It uses real Noise messages, encrypted confirmation, transport discovery
and normal idle/cooldown waits, without fabricated timestamps or peer state.
This adds no wire messages or stored state and does not reserve an exploration
turn while other handshakes occupy the available slots.

All four discovery tests, 56 handshake tests and strict core/relay lint pass.
The existing paid full-roster regression completes all-hop credit at 34.939 s,
preserves the original eight channels and boundary-to-internal link epochs, and
delivers 35/35 independent local packets in each direction (largest gap 1.016 s).
All 1,536 test sats are collected. These observations are not a latency guarantee.
Those initial repeated-encounter experiments failed: one exceeded the five-second
local delivery-gap limit after splitting; another missed the first 60-second
join deadline and subsequently timed out during settlement. Their retained
evidence does not establish complete fund collection for those failed runs.

The unchanged repeated full-roster acceptance now passes (2026-09-21). Both
boundaries keep four responsive candidates available throughout two encounters
and the intervening partition. Independent local traffic and the original
boundary-to-internal link identities remain protected. Elective neighbor removal
preserves end-to-end sessions and queued traffic; fresh remote startup epochs
still use the restart recovery path. Pending neighbors can prepare before an
incumbent is old enough to replace, but activation requires fresh encrypted
confirmation and current eligibility at both ends. That revision gave an interrupted
local discovery attempt one fresh retry within its original deadline. The existing
heartbeat carries readiness; no new wire message or larger admission allowance is needed.
See the [rotation policy](../../docs/design/fips-configuration.md#optional-neighbor-rotation-nodeneighbor_rotation)
for exact pacing, demand protection and discovery-source limits.

In the final run, the two encounters resume fresh bidirectional delivery and
credit on all eight original directional channels at 40.327 s and 52.612 s,
within each original 60-second deadline. The intervening split evicts the bridge,
refills both rosters and restores separate component roots in 33.306 s. No
competing candidate is forced to leave. Original funding/channel identities,
capital and lifetime budgets remain intact; the independent local workload stays
within its five-second maximum delivery-gap bound. Native resource observations
retain their existing caps. Settlement and collection recover all 1,536 test sats;
the complete test takes 211.38 s. An earlier accepted run also completes both
encounters and collection. These timings are observations, not a latency bound.

Focused checks cover retained proof and unique-frame accounting, crossed dials,
reply reception on another local listener, original retry deadlines, restart
recovery, routed sessions and Bluetooth reconnection. A real TCP regression also
checks preparation ownership across cancelled rejection cleanup and confirms
that a newly denied peer receives no Noise handshake. Strict core and relay
linting and the source-size gate pass. The latest code has no matched physical
router measurements; arbitrary encounter schedules, hostile-identity fairness,
radio contention and channel handover remain separate acceptance work.

An unchanged-policy diagnostic run (2026-09-21) records bridge admission at
31.011 and 39.917 seconds, tree convergence at 32.027 and 40.933 seconds, and
all-hop credit at 33.775 and 51.032 seconds. Targeted native rotation/discovery
logs show successive incumbent replacements approximately ten seconds apart:
each newly admitted idle peer receives the configured minimum-age protection.
The 32.417-second intervening split/eviction is outside both encounter timers.
All 1,536 test sats are collected and the existing native resource caps hold.
These observations identify serial candidate turnover as a substantial cost;
they do not prove that every wait is necessary or establish a join-time bound.

The post-tree application measurement includes the fixture's seven-second retry
spacing and sequential bidirectional bursts. In the second encounter, the first
direction delivered its second batch at 7.429 seconds, followed by a 1.953-second
reverse burst. Their combined time is not an isolated routing-outage measurement.
Admission timing must be separated from application retry gaps before retaining
an optimization; no protection interval or acceptance deadline was shortened.

The existing native responsive-candidate fixtures now emit a bounded timing
ledger at their normal maintenance and packet-processing boundaries. It records
incumbent maturity, exact candidate ownership and original deadline, retained
authentication evidence, resend state and promotion observations. At most 256
changed states per boundary are emitted; the summary reports any omissions.
Monotonic observation brackets and native wall-clock deadlines remain distinct.
Victim-selection eligibility alone does not establish final ACL/carrier/proof
validity, so the ledger does not invent a new promotion deadline.

Both original native fixtures pass: two competing candidates form the bridge in
20.515 seconds and four in 40.509 seconds, within their unchanged 35/60-second
windows. The ledger emits 37 and 59 total transitions respectively, with no
omissions; this covers observed state changes, not every wire event. Strict core
lint, formatting and the 868-file source-size gate pass. These diagnostic changes
do not alter production neighbor selection or prove faster recovery. Reproduce
with `cargo test -p nvpn-fips-core --all-features --lib
node::tests::handshake::candidates::rotation::rendezvous::responsive::
-- --test-threads=1 --nocapture`, using the same development dependencies.

The native fixture also covers a successful encounter, an actual simulated
partition, and a second automatic encounter while all four local competitors per
boundary stay available (2026-09-22). Re-exposure waits for both rosters to refill
and the component trees to separate. The same identities, sessions, discovery
cursors and retry state survive; both bridge owners must authenticate again and
both payload directions must complete within the original 60-second window.
Local traffic, peer/link/index caps and ordinary maintenance continue throughout.
Shared payload checks use a longer sequence tag for this scenario without
wrapping or weakening duplicate detection or receive-credit handling.

With synchronized maintenance, the two native deliveries complete in 40.719 and
40.203 seconds, separated by an 11.861-second split. A second case starts one
component's maintenance half a second later, preserving one-second ticks and
half-second local traffic rounds: delivery completes in 41.213 and 38.126 seconds
with a 13.382-second split. Both timing ledgers report no omitted transitions.
The original two responsive controls, four same-path rejoin controls and strict
core lint pass. These fixed-identity native cases add repeated-contact coverage;
they do not reproduce or resolve the larger paid scenario's second-encounter
failure, nor establish a general rendezvous bound or physical mobility support.

A separate two-boundary UDP regression reproduces a transferred retry expiring
before the remote incumbent becomes eligible (2026-09-22). The retry exchanges
real Noise messages, but the original policy releases one candidate before the
other side can promote it. The control with earlier remote maturity passes. The current
policy lets the exact successful incoming replacement earn one bounded successor
window, anchored at its promotion; see the
[rotation policy](../../docs/design/fips-configuration.md#optional-neighbor-rotation-nodeneighbor_rotation)
for its ownership, expiry and fairness limits. Both maturity cases now establish
reciprocal keys and deliver payloads in both directions without another repair
dial. Seven retry controls cover frozen expiry across configuration changes,
replayed proof, unrelated promotion, missing targets, local infeasibility,
second-transfer consumption and preservation of the owed exploration turn.
The 99-test handshake compatibility group, strict core lint, default-feature
compilation and source-size checks pass. The repeated native contact with
half-second-offset maintenance restores delivery in 40.888 and 39.164 seconds,
with a 12.400-second split, within the same 60-second encounter windows.

This addresses one readiness race, not general crowded rendezvous. An unchanged
policy trace separately forms its second bridge at 50.783 seconds and joins the
tree at 51.814 seconds, but misses the original 60-second delivery/credit target;
all 1,536 test sats are collected. That encounter uses fresh ordinary attempts,
so additional interrupted-retry time does not address its late bridge selection.
With the earned-window change, one full paid compatibility run completes delivery
in 32.736/39.153 seconds and all-hop credit in 33.547/40.067 seconds, then collects
all 1,536 test sats. This passing run does not resolve the earlier schedule-dependent
failures. Reproduce the focused maturity cases with `cargo test -p nvpn-fips-core
--all-features --lib rotation_readiness::transferred:: -- --test-threads=1` and the
same development dependencies.

#### Crowded-neighbor recovery

Recently used discovery-only neighbors receive one bounded, one-use discovery
preference after physical link-dead removal or committed idle replacement
(2026-09-22). The history retains only
identity and remembrance time, stays within the current peer cap,
and spends the existing alternating demand turn. New advertisements, link
maintenance and failed attempts cannot renew it. Unused history survives waiting
behind other admissions until consumed or displaced by newer entries;
the actual connection attempt keeps its normal frozen deadline. Admission still
uses current addresses, ACLs, capacity and fresh Noise proof; no route or paid authority is
retained by this history. Recent admitted transit and local application RX/TX
qualify through their actual carrier. Local activity must be strictly newer than
the current adjacency's admission, including at millisecond boundaries. This
reuses existing activity timestamps; it does not add generation tracking or
per-packet work. Outbound activity records an admitted attempt, not delivery.
See the configuration policy for qualification and retirement rules.

Two native five-node cases distinguish a former transit relay from a heartbeat-only
neighbor after simulated link loss, heartbeat cleanup and a refilled roster.
The transit case fails on the prior policy's candidate selection. With the preference,
it exposed a separate stalled-queue bug: an earlier PathBroken recovery probe with
no queued data treated missing Bloom information as an offline result for an
existing FSP session. The next original payload was suppressed before gaining
lookup ownership, then remained queued after topology convergence. Missing Bloom
information now follows the existing known-session exhaustion rule and does not
record offline failure. Unknown destinations still back off, idle known sessions
create no requests or pending lookups, and exhausted recovery does not restart
through maintenance. Both unchanged native traffic/deadline cases then authenticate
and deliver their original routed payload, without an extra submission.

The local-use extension adds native sender-only and receiver-only cases to the
same five-node fixture. Both select an ordinary stranger on baseline and select
the recently used neighbor with the extension. All four cases pass with real
authentication, native heartbeat removal, ordinary refill, fresh re-admission and
original routed payload delivery. Component controls cover direct and routed
carriers, the exact activity cutoff, old/equal-admission observations, new-owner
activity, the original frozen expiry, queue/report exclusions and unchanged
active-peer protection. These controls do not claim wire replay rejection or exact
connection-generation binding.

Validation of the initial link-dead-only history passes all 23 native discovery
cases, seven reconnection-policy controls, six peer-activity controls,
107 handshake compatibility cases and four
original responsive-neighbor cases. The repeated paid encounter resumes delivery
at 22.135/30.351 seconds and credits every hop at 22.848/30.962 seconds. Both
independent local streams deliver all 87 original payloads exactly once; maximum
delivery gaps are 1.043/2.285 seconds within the unchanged five-second limit.
Existing channels, resource caps and budgets are retained, and all 1,536 test sats
are collected. Strict core lint, default-feature compilation and the source-size
check pass. Source, dependency and lock fingerprints stay unchanged during the
gates, and the portable lock is restored. This is simulation and loopback payment
evidence; physical mobile-radio acceptance remains open.

Reproduce the native cases with `cargo test -p nvpn-fips-core --all-features
--lib node::tests::sim_discovery::rotation::reconnection:: -- --test-threads=1`;
use `node::peer_activity::tests::` for the local-activity controls, with the same
development dependencies in [FUNDING-COSTS.md](FUNDING-COSTS.md).

The original history expiry could spend a preference before discovery used it.
A paid seed-139 trace misses the unchanged second-encounter 60-second deadline:
one boundary's unused preference expires at 27.812 seconds, before its preferred
outgoing turn at 29.814 seconds. It chooses a local foreign-root hint instead.
A focused native regression independently reproduces the premature loss: genuine
transit earns history, heartbeat cleanup removes both old owners, and the peer
stays absent for 6.1 seconds, beyond the configured six-second history window,
while maintenance and local traffic continue. No queued returning-peer demand
forces the choice. The original policy selects an ordinary stranger; bounded
one-use retention selects the returning peer, authenticates it and delivers the
original routed payload. The new attempt still has its six-second deadline.

With this change, all seven policy controls and 35 native discovery cases pass,
including the nine reconnection cases. The policy controls retain oldest-entry
eviction, single-use consumption, ordinary exploration and frozen attempt deadlines.
Both the original staggered four-candidate fixture and a variant with the paid
fixture's connection/link caps pass both encounters; peer caps and receive-index
ownership checks remain unchanged. Strict core lint, formatting and source limits
pass. The paid finite-contact compatibility run delivers at 15.823/21.298 seconds,
credits every hop at 16.635/22.007 seconds and collects all 1,536 test sats. Its
returning bridge is selected before the former expiry, so it is compatibility
evidence, not a reproduction of the late-selection schedule. The earlier crowded
timeout and cold short-contact failures remain open; this does not establish
physical mobile-radio readiness.

An additional paid case holds the bridge absent for 31 seconds after both old
owners disappear, beyond the default 30-second handshake deadline. One initial
instrumented run passes, but two subsequent runs fail after the new bridge and
common tree are already established. The traced failure shows repeated coordinate
lookup attempts with no forwarding peer, followed by exhaustion and suppressed
fresh demand. Existing channels still have credit; both bridge owners remain
connected. This trace does not establish that every earlier attempt was unsent.

A smaller three-node native UDP regression exposes an unsent-lookup recovery
defect with real Noise
handshakes, the default `[1, 2, 4, 8]` lookup ladder and an unchanged source parent.
Both the eventual destination and an unrelated absent identity first exhaust
their actual lookup attempts. The destination then joins downstream and a genuine
filter update reaches the source. Before the fix, fresh demand is still suppressed;
after it, the original fresh payload arrives exactly once while the unrelated
destination remains suppressed.

Backoff now retains whether the exhausted lookup ever selected a peer. For an
unsent failure, fresh local demand can spend one early retry when normal peer
selection finds a route. Admission capacity and deduplication still apply first;
the failure count and suppression deadline are preserved. Request ownership is
recorded before the send await, so an unanswered or cancelled send cannot regain
the exception merely because its route disappears. Reachability announcements
alone do not initiate traffic or clear other destinations' backoff. No wire type,
retry deadline, forwarding interval or payment bound changes.

All 89 enabled discovery-handler tests, 26 backoff/rate-limit controls and the
native tree-reachability wake-up regression pass. One existing large-network
discovery case remains ignored. The new component controls cover ineligible
hints, full/deduplicated admission and an unanswered lookup whose route disappears;
the separate UDP case establishes encrypted delivery. Strict core and relay lint
and the 906-file source-size gate pass. These are local software results; the
independent cold short-contact failure and physical mobile-radio acceptance remain
open.

Before the shared-ingress correction below, the paid long-absence scenario still
failed after this narrower fix. Its second
bridge connects at 28.890 seconds and shares a tree at 29.506 seconds, but none of
the 12 fresh source-to-destination payloads arrives during the existing traffic
window. All 1,536 test sats are collected. Both local streams remain complete
without duplicates, and all source/dependency/lock guards pass. The passing native
case therefore does not establish recovery of the crowded paid mesh; that
regression was still an unintegrated diagnostic. Reproduce the integrated native
case with `cargo test -p nvpn-fips-core --all-features --lib
node::tests::discovery::forwarding_contention::reachable_after_backoff::
-- --test-threads=1`, using the development overrides in
[FUNDING-COSTS.md](FUNDING-COSTS.md).

A detailed paid trace then shows the missing response despite genuine positive
reachability. Two origins' requests reach a transit through the same authenticated
neighbor, 33 ms apart. The first takes the target's forwarding slot; the second
cannot join the deferred queue because it shares that ingress. Its final attempt
expires before another request is permitted. The new four-node native UDP case
reproduces this failure with a 17 ms collision and the original lookup deadline.

The bounded deferred queue now accepts an ingress that aggregates multiple
origins, preserving the two-second target interval, ingress tokens, one waiter
per target, original request/carrier ownership and expiry. Dispatch still consumes
the normal slot and token before awaiting transport. The unused previous-ingress
field is removed. Repeated IDs cannot replace a waiter or extend its slot;
cancellation cannot replay the charged send. First-waiter scheduling does not
guarantee fairness against a continuously competing ingress.

All ten native contention cases, 27 rate/backoff controls, three queue-bound
controls and the strengthened real-send cancellation case pass, as do strict core
lint and the 909-file source-size gate. The final-attempt native case delivers
with 1.902 seconds remaining. The integrated paid long-absence case also passes:
delivery resumes at 17.168/33.919 seconds and every-hop credit at 17.980/34.733
seconds for the two encounters. Both local streams deliver all 143 originals
without duplicates, with maximum gaps of 1.969/1.309 seconds. Channel identities,
caps and budgets remain intact; all 1,536 test sats are collected. The existing
60-second encounter limit and all source/dependency/lock guards are preserved.
These are controlled software observations, not mobile-radio latency guarantees.
Run the relay `priced_paths` filter
`merge_split::crowded::automatic::repeated::long_absence_reuses_paid_routes_with_full_rosters`
with the same development overrides to reproduce the paid scenario.

The separate 400 ms cold-contact regression now passes. With an authenticated
but unmeasured bridge, the first RTT report could re-arm an obsolete tree
declaration just before the new parent's declaration arrived. That spent the
unchanged 500 ms announcement interval; the corrected declaration arrived after
the radio contact had closed. A smaller authenticated peer identity necessarily
advertises a root below the local root. Only on that peer's first RTT, with its
declaration still missing, the handler now defers this re-arm. It preserves
already pending work; later reports and all root disagreements retain repair.
There is no new timer, state or wire message, and both endpoints cannot defer.

Both native UDP contact phases learn the current signed declarations in
176.738 and 181.296 ms, within their original 400 ms openings. The three existing
first-RTT cases also pass. Nine loss/bootstrap controls, the unchanged-refresh
case and six deadline controls pass; a new control proves later reports create
fresh repair after previous pending work clears, with periodic refresh disabled.
Strict core lint, formatting and the 907-file source-size gate pass, with the
source/dependency/lock guards intact. These checks establish declaration recovery
for the tested schedules, not end-to-end delivery during arbitrary short contacts
or physical mobile-radio acceptance. Reproduce with the core library filters
`node::tests::spanning_tree::first_rtt::` and
`node::tests::spanning_tree::bootstrap_loss::` using the same development overrides.

A separate native UDP case exposes lost reachability on a stable tree. It drops
only the first genuine positive FilterAnnounce after a downstream join. Without
refresh, 31 subsequent link-metric reports arrive but reachability and delivery
remain absent through the unchanged 15-second lookup ladder. The undropped
control delivers normally. This is independent of the shared-ingress paid failure,
whose trace already contained positive reachability.

Bloom maintenance now refreshes unchanged filters every five seconds by default,
using existing successful-send history, pending updates and debounce. No new
message, acknowledgement or per-peer timer is added. A fresh sequence permits
acceptance; unchanged content does not cascade updates. Failed or cancelled sends
remain pending, removed peers lose their history, and setting
`node.bloom.announce_refresh_interval_secs` to `0` disables periodic refresh.
The native dropped-advertisement case then delivers after 6.049 seconds without
extending the lookup deadline. All 44 focused Bloom checks pass, including actual
encrypted refresh/cancellation, stricter debounce, disable and failure controls.
The [configuration reference](../../docs/design/fips-configuration.md#bloom-filters-nodebloom)
documents the calculated 1,071 FMP bytes per announcement: 214.2 bytes/second per
outgoing peer at the default interval, excluding transport overhead. CPU and
radio costs remain unmeasured.

The combined tree, shared-ingress and Bloom fixes pass all 12 discovery-contention
cases and four first-RTT cases. Both short-contact phases learn declarations in
180.089/159.402 ms. The combined paid long-absence run delivers at 16.904/38.207
seconds and credits every hop at 17.817/39.122 seconds across its two encounters.
Both independent local streams deliver all 148 originals without duplicates;
maximum gaps are 2.622/1.018 seconds within the original five-second limit.
All 1,536 test sats are collected. Strict core/relay lint, formatting and the
912-file source-size gate pass, with source/dependency/lock guards intact.
These fixes are integrated locally; they have not been deployed to the routers.
The observed timing varies between runs and does not establish arbitrary mobility,
loss-free short contacts, adversarial fairness or physical-router performance.

A fresh combined-source check also passes both paid short-contact root placements:
all 24 direction/contact checks deliver fresh traffic before their respective
cuts, including each first 400-ms contact after bidirectional authentication.
Each scenario collects all 1,536 test sats. Two crowded-recovery seeds retain
1 Mbit/s, 10-ms one-way delay and 5% independent packet loss throughout delivery
and payment acceptance. All four encounters recover within the original
60-second bound; their latest delivery and every-hop credit observations are
34.596 and 35.208 seconds. Both local streams in each run deliver every original
without duplicates or breaching the five-second maximum gap. Each seed collects
all 1,536 test sats. The source, dependency and lock guards remain intact. These
software checks do not extend the physical-router acceptance scope.

The initial link-dead-only policy misses the dense eight-candidate repeat
encounter. Cold delivery takes 51.004 seconds, but neither boundary attempts the
bridge during the next 60-second window. During the split, ordinary promotion
replaces both bridge owners before link-dead detection; neither removal records
their earlier application use. A longer history timeout cannot help when no
history is created. Ordinary candidates receive their ten-second minimum age,
without cursor rewind or different-identity takeover.

The corresponding dense-client regression submits one original endpoint payload
after physical split and refill, before warm re-exposure. On that baseline its
first demanded bridge attempt starts at 8.543 seconds. All 13 received requests
meet a different completed candidate at the destination, and the original remains
queued at the 60-second deadline. This exposes receiver-admission contention even
when the sender has real demand.

Committed replacement now preserves the same bounded recent-use preference for
the exact validated victim. Qualification happens before cleanup, and history
is recorded afterward without an intervening await. Generic administrative and
failed-promotion cleanup remain excluded. This shares the existing qualification,
expiry, cap and ordinary-turn alternation; no new state, message or timer
configuration is introduced. Re-admission without new application use cannot
renew old history.

Four added native cases exercise real replacement before heartbeat expiry,
distinguishing transit, local sender and local receiver traffic from heartbeat-only
activity. The three application cases fail baseline candidate selection; all eight
physical-loss/replacement cases pass with the change. A fixture guard checks the
original owner before and after timeout/heartbeat maintenance, proving that
replacement, rather than earlier local expiry, removed it. Original useful links,
fresh proof, resource caps and payload delivery remain required.

The unchanged dense case now delivers at 50.805 seconds cold and 19.160 seconds
after re-exposure. The queued variant delivers at 50.803 seconds cold; its single
waiting original arrives exactly once at 19.114 seconds after re-exposure, leaving
no queued copy. Both retain eight local candidates, ten-second minimum age,
500-ms maintenance offset, two-peer boundaries and the original 60-second limits.
These finite runs establish recovery for these returning-neighbor scenarios,
not a general cold-start convergence bound or physical mobile-radio acceptance.

Compatibility passes all 27 native discovery cases, seven reconnection-policy
controls, six activity controls, 107 handshake cases, four original responsive
cases and all seven fixed population variants. The paid repeated encounter
resumes delivery at 21.636/27.687 seconds and credits every hop at
22.447/28.396 seconds. Both local streams deliver all 84 originals without
duplicates; their maximum delivery gaps are 1.009/1.017 seconds. Existing
channels and budgets survive, and all 1,536 test sats are collected.
Strict core lint, default-feature compilation, formatting and the source-size
check pass. Sources, dependencies and tested locks remain unchanged during each
gate, and the portable lock is restored. No physical router is changed or tested
by this validation.

Subsequent dense first-contact coverage adds two fixed identity assignments chosen
before testing, retaining eight candidates, ten-second minimum age, two-peer
boundaries, the same maintenance phase and 60-second encounter limits. Reversing
the boundary roles delivers at 10.895 seconds cold and 20.128 seconds after
re-exposure. Shifting the identity population misses its first encounter: four
bridge requests in one direction and nine in the other all meet occupied remote
admission slots. The repeat encounter cannot run because cold acceptance fails.
The endpoints take turns among local candidates, but their bridge service windows
do not overlap. Recent-use history cannot prioritize an edge that has never
carried application traffic.

An observation-only continuation preserves that failure and follows the same
shifted population for another 120 seconds, without resetting state, submitting
new demand, dialing explicitly or changing traffic cadence. It still observes no
reciprocal bridge or delivery at 180.017 seconds from initial exposure. This is
finite evidence of sustained missed opportunities, not proof of permanent
starvation. The original 60-second assertion remains failed. Resource caps and
the useful local traffic checks continue to hold. The isolated diagnostic source
passes strict core lint and the 889-file size check; sources, dependencies and
tested locks remain unchanged during the gates, and the portable lock is restored.
These tests remain separate from the integrated runtime fix.

Cold endpoint-demand controls retain that shifted population and all original
limits. One original from boundary 0 starts a bridge attempt at 0.875 seconds,
after boundary 1 selected a local candidate at 0.446 seconds. Lookup exhaustion
removes the original at 15.932 seconds without an FSP session. The peers later
complete matching Noise handshakes, but the remote incumbent does not mature until
60.615 seconds; no reciprocal adjacency or delivery exists at the 60-second
deadline. This is late admission, not an observed cryptographic failure.

One original each way succeeds: both arrive exactly once at 10.816 seconds, with
established FSP sessions and empty queues. The reverse one-way control also
succeeds at 10.822 seconds. Boundary 1 starts first in both passing cases and
reaches boundary 0 before it chooses another candidate. Mutual demand is therefore
not required by these runs; the available receiver slot explains the directional
difference. Queue, carrier, lookup and session transitions are observed without
extending lookup lifetime, resubmitting originals or claiming that a post-start
observation proves the selection reason. The original warm queued control still
passes after the shared fixture refactor, delivering its one original at 20.093
seconds after re-exposure. Strict core lint and file-size checks pass, and all gate
fingerprints remain stable. No runtime policy or physical router changes.

A subsequent unmerged listening experiment delays ordinary automatic discovery
for the existing attempt interval after initial learned fill or committed ordinary
outgoing replacement. Current demand/history, earned retries and reserved outgoing
starts remain exempt. One frozen-expiry deferred hint preserves an advertisement
while active-path refreshes continue; consumption rechecks policy and capacity.
Two native UDP controls fail the old immediate-dial behavior and pass with the
experiment, establishing one-time LAN advertisement survival through an actual
Noise request, including concurrent active-path refresh. They do not establish
full newcomer promotion or the complete expiry/replay contract. Strict core lint
and the 891-file size check also pass.

The experiment does not fix cold convergence. Source-0-only still fails at
60 seconds and loses its original at 16.048 seconds. During listening, a local
peer's unsolicited Msg1 occupies the remote slot at 0.660 seconds and supplies
fresh encrypted proof; the desired bridge request arrives 378 ms later. Reciprocal
originals pass at 10.838 seconds, while the reverse one-way original takes 15.474
seconds. Background discovery again misses 60 seconds and remains disconnected
at 180.023 seconds during observation-only continuation. Original caps, ages,
lookup retirement and acceptance deadlines remain unchanged; all gate fingerprints
remain stable and portable locks are restored. The listening code and its isolated
tests remain unmerged: an open receiver slot can be taken by local incoming
competition, so a listening delay alone does not coordinate service of an edge.

A separate signed-callback experiment also remains unmerged (2026-09-22). It
adds one 104-byte advisory response bound to the exact outstanding Msg1 and the
expected responder identity. A busy receiver retains one permitted UDP/Sim
return path under its completed candidate's original lease, then dials it after
that candidate commits. The requester protects its existing attempt without
changing Noise state, indices, resend credit or expiry. Invitations cannot chain,
displace an earned retry, or obtain a renewed window through incoming transfer.
This is an experimental datagram mechanism, not a released wire extension or a
general policy for stream addresses.

The native UDP control fails on baseline's absent reply and passes with the
experiment. It captures the receiver's actual callback Msg1 before polling the
requester's resend timer, checks exact resource ownership and inherited deadlines,
rejects a forged signature and a signed response for a different request before
accepting the genuine reply, and completes normal reciprocal authentication.
It does not establish payload delivery, hostile-load behavior, complete expiry
coverage or compatibility of a new wire phase across all transports.

The unchanged cold-demand population still passes two cases and fails one.
Reciprocal originals arrive once at 10.783 seconds; the reverse unilateral
original arrives once at 10.754 seconds. For the failing unilateral direction,
reciprocal admission now appears at 20.597 seconds (the bridge observation is
20.997 seconds), but lookup exhaustion already removed the original at 16.026
seconds. Serving the completed local candidate and then the callback incurs two
ten-second minimum-age periods. The original remains undelivered at 60 seconds;
neither its lifetime nor the admission ages were changed.

Background discovery still has no bridge or endpoint delivery at 60.007 seconds
or after the unchanged continuation through 180.017 seconds. Its first accepted
cross-component invitation also demonstrates incompatible remaining lifetimes:
the requester expires before the receiver's newly promoted incumbent becomes
eligible for replacement. Merely acknowledging a future callback does not align
those windows. Strict core lint, formatting and the 892-file size check pass;
source/dependency fingerprints remain stable during each gate and portable locks
are restored. The implementation and diagnostics are preserved in an isolated
checkout, with no runtime integration or hardware changes. This rejects callback
signalling alone as the crowded-admission solution; a useful next candidate must
address both neighbor selection and compatible admission windows.

A subsequent topology-discovery candidate was initially held for paid continuity
(2026-09-22); the verified follow-up below is now integrated locally. A node
with an active neighbor publishes its current connected-tree root; an isolated
node publishes no hint. Ethernet appends an optional 18-byte trailer after scope
(19 bytes when an empty scope prefix is needed). Sim discovery carries the same
Node-published value without inferring components from its network map. A foreign
root ranks below earned retries and local demand/history, and alternates with
ordinary exploration. The actual attempt consumes its preferred turn before I/O.
Hints do not authorize admission, routes or payments, and do not change caps,
minimum ages, lookup retirement or frozen attempt deadlines. Missing, malformed
and same-root hints retain ordinary service. LAN/mDNS has no new hint support.

The focused native case fails baseline selection and passes with the candidate:
real authentication and TreeAnnounce form a separate tree, discovery chooses its
bridge ahead of an isolated candidate, and normal Noise precedes payload delivery.
A visible but silent advertiser cannot extend its original deadline or take the
next ordinary turn. Both native cases, five demand/priority controls, 52 Ethernet
tests, 29 discovery tests and 107 handshake compatibility tests pass. Strict lint,
the default-feature build and the 890-file size check also pass. The unchanged
three cold-demand controls deliver each original once in 10.885–10.927 seconds.
Shifted crowded background discovery delivers at 10.986 seconds, then at
21.225 seconds after a split and re-exposure; its earlier 60-second failure and
180-second diagnostic disconnection are not reproduced in this candidate run.

The initial paid-continuity failure blocked integration. The repeated paid fixture forms a
bridge at 19.839 seconds and a common tree at 21.482 seconds, but its existing
local stream exceeds the five-second inactivity limit. At failure, 25 originals
were submitted to the endpoint and only 20 reached the carrier and destination.
All five queued originals subsequently arrive once, with a 5.453-second delivery
gap. The same internal links, session indices and established end-to-end session
survive; the local purchase remains eligible with ample credit. Source coordinates
are absent while a lookup is pending, then appear as the queue drains. These
snapshots localize the pause to route readiness but do not prove why coordinate
recovery took about 4.46 seconds or that the new preference caused it. The next
check needs correlated tree, lookup and queue transitions before changing policy.
All 1536 test sats are collected. Source/dependency fingerprints stay stable and
portable locks are restored. The population and warm-rejoin gates queued after
the paid test did not run. No runtime merge or physical-router changes occurred;
hostile-identity fairness, arbitrary mobility and hardware acceptance remain open.

The follow-up traces retain that failure as evidence. A controlled first-root
encounter observes a correctly rejected foreign-root reply, a one-second retry
rejected by the existing two-second forwarding interval, and a later successful
reply. Separately, an actual three-node UDP/Noise RX-loop regression proves a
retry can wait 954 ms beyond its recorded deadline because lookup maintenance
previously ran only on the one-second tick. The first response is actually lost;
normal recovery, request correlation and unchanged authenticated link owners are
checked before the timing assertion. This isolates a scheduling defect without
claiming to reproduce every cause of the original 5.453-second gap.

Lookup retries now use a cached earliest deadline, with constant-time selection
and bounded scans only during lookup maintenance. The reserved turn precedes
management requests and drains bounded data and status work afterward. A timed-out
turn retains untouched due targets and waits one existing tick before another
dedicated turn. Successful response removal can leave one harmless stale wake;
an empty queue disables it. The existing retry ladder, forwarding limiter,
request IDs, FSP timeout ownership and all financial/admission limits remain.
The native timing cases observe retries within 4 and 6 ms of their deadlines;
this is a loopback result, not a loaded-radio latency guarantee. A separate real
Sim send-completion cancellation test proves the untouched second destination
retains its due retry, resumes once and completes with the same link owners.

Both repeated paid cases pass twice with the scheduler change. On the final
source, the original case delivers all 84 local packets per component without
duplicates (maximum gaps 1.005/1.015 seconds), and the controlled root-change case
delivers all 106 per component (3.752/3.491 seconds). Both retain the original
five-second continuity bound and collect all 1536 test sats. Cross-component
paid delivery takes 22.021/27.540 seconds in the original case and
34.241/37.663 seconds in the root-change case. All nine fixed population variants
pass both encounters within their unchanged 60-second bound (18 deliveries,
2.128–30.044 seconds). The warm-rejoin case delivers its one queued original
once at 29.175 seconds; this run does not show improvement over the earlier
20.093-second warm result. Joining crowded meshes still takes tens of seconds.

The 77 discovery checks (one large case ignored), seven pending-lookup checks,
18 RX-loop scheduling checks, strict core lint, default-feature build and final
892-file size check also pass. Gate source/dependency fingerprints and tested
locks remain stable; portable locks are restored. Local integration preserves
all 935 checked source-file hashes. Reproduce the focused native checks with
`cargo test -p nvpn-fips-core --all-features lookup_deadline -- --test-threads=1`,
the population cases with the `responsive::population::` filter, and paid cases
with the `priced_paths` test target's `repeated::` filter, using the dependencies
in [FUNDING-COSTS.md](FUNDING-COSTS.md). No router services were changed. Hardware,
arbitrary mobility, channel selection, hostile-identity fairness and broader
performance acceptance remain open.

#### Crowded loss and finite-contact characterization

The repeated paid fixture now also passes seeds 137 and 138 with a bridge limited
to 1 Mbit/s, 10 ms one-way latency and 5% independent packet loss. Faults remain
active through delivery and payment acceptance in both encounters; only financial
collection restores a reliable carrier. Observed bridge losses are 18/37 and
20/18 packets, respectively. Fresh cross-component delivery takes
29.453/36.135 seconds and 35.150/37.140 seconds. Each run collects all 1536 test
sats. Independent local streams deliver 100/100 and 106/106 packets per direction,
without duplicates; their maximum gaps remain below the existing five-second
bound. These tests add no runtime policy changes. The focused loss cases, strict
relay lint and source-size gate pass; integration matches all 936 checked source
files. Reproduce with the `priced_paths` filter
`merge_split::crowded::automatic::repeated::loss::`, using the development
dependencies in [FUNDING-COSTS.md](FUNDING-COSTS.md).

The combined seed-139 case adds brief contacts and a 31-second absence after the
bridge's authenticated owners are removed. Its original run failed the second
encounter: the native tree recovered, but none of 12 fresh cross-component
payloads arrived in the existing 20-second traffic window. A traced reproduction
showed the first actual lookup request leaving with about 1.97 seconds left in
the final attempt. The destination answered, but no verified response reached
the source before expiry; fresh demand then met the normal 30-second backoff.
The trace does not identify the exact lost reply hop. The source purchase stayed
eligible and unrelated local payments advanced. A separate diagnostic run passed;
that intermittent pass did not erase either failure.

A three-node native UDP regression drops exactly that first genuine signed reply.
Before the correction, fresh demand remains suppressed after the original lookup
and packet expire. Discovery now records the first peer-selection phase before
awaiting transport. If reachability delayed that selection beyond the initial
phase, expiry grants the existing one-shot retry on usable reachability. An
entirely unsent lookup retains the same exception. Normal admission still applies;
the failure count and suppression deadline remain until verified success. The
new lookup selects in its first phase, so its own timeout cannot rearm the
exception. A request selected in the original first phase keeps ordinary backoff
even if its route later disappears. Configured connection and session-recovery
demand retain their existing behavior; routing announcements alone do not create
fresh work. No message type, lookup deadline, transit interval or payment limit
changes.

The native case now delivers only the distinct fresh payload, with both original
carrier owners retained. Offline and fully unanswered controls stay suppressed;
the original packet remains discarded. Two combined paid runs after the
correction recover delivery at 15.848/21.363 and 23.142/43.969 seconds from the
two sustained openings. Every-hop credit follows at 17.266/22.279 and
24.666/44.683 seconds. Loss stays active through acceptance, with 11/15 and 21/53
actual dropped packets. Each local stream delivers all 131 or 160 originals
without duplicates; the largest observed gap is 2.999 seconds. Both runs collect
all 1,536 test sats after reliable-carrier cleanup. Initial crowded brief contacts
still deliver none of 18 or 17 offered packets; warm contacts deliver 25/30 and
29/32. These finite observations do not establish seamless short contacts, a
general recovery bound or physical-radio acceptance.

All 15 native contention cases, ten pending-lookup controls, 27 rate/backoff
controls, two request-history tests and the lookup-cancellation regression pass.
Strict core/relay lint, formatting and the 916-file source-size gate pass, with
the four existing oversized-file exceptions unchanged. The shared encrypted-frame
test helper removes duplicate interception plumbing. Each gate verifies frozen
source/dependency/lock fingerprints and restores the portable workspace lock.
Reproduce the native case with the `nvpn-fips-core` library filter
`node::tests::discovery::forwarding_contention::late_reply_loss::`, and the combined
paid case with the `priced_paths` filter
`merge_split::crowded::automatic::repeated::loss::lossy_brief_contacts_and_long_absence_reuse_original_paid_routes`.
Use the development dependencies in [FUNDING-COSTS.md](FUNDING-COSTS.md).

The current-build finite-contact trace also records complete boundary rosters
from the existing peer queries. Both idle incumbents remain young during the
initial brief openings, and observed bridge requests meet an already-owned
preparation attempt. Later paid delivery succeeds at 16.505/47.844 seconds and
all 1,536 test sats are collected. This trace does not establish a missed
admissible opportunity; its host-clock correlation is diagnostic evidence.

A native-clock admission control now checks the corresponding exclusion without
changing policy. Real local traffic first matures each useful owner; a younger
idle owner then fills its boundary's second slot. During an independently cut
1.502-second contact, both complete rosters stay retained, actual application or
transit demand protects each useful owner at all 239 observations, and both idle
owners remain below the ten-second minimum age through the cut. Four local
payload rounds complete. No cross-boundary payload is offered during this
admission-only phase. After the sustained opening, a reciprocal bridge appears
at 8.807 seconds and both payload directions complete at 8.849 seconds, within
the unchanged 60-second bound. Preparation from the short contact may finish
without another handshake request.

The new normal test and the original repeated paid-capacity native control pass,
as do strict core/relay lint, formatting and the 917-file size gate. Reproduce
with the core library filter `responsive::brief::`. Existing useful-owner,
connection, link and timing limits remain enforced. This identifies one expected
short-contact exclusion, not a universal minimum contact duration or convergence
guarantee for already-admissible neighbors. No runtime policy or hardware changes
are included; physical mobile-radio acceptance remains open.

An already-admissible companion now tests actual end-to-end service during the
same independently cut 1.5-second encounter. Both full rosters retain a useful
neighbor carrying real local traffic and an idle neighbor matured on the native
clock. Read-only checks establish initial admission eligibility, including ACLs,
handshake capacity and rate limits. Four competing candidates remain available.
Each useful leaf submits one original payload to the other leaf with no existing
end-to-end session; neither original is resubmitted. Receive observations must
precede the actual cut, and later recovery cannot change that acceptance result.

Two runs form the reciprocal bridge in 76 and 79 ms and deliver both originals
in 1.159–1.210 seconds, before actual cuts at 1.501–1.503 seconds. Each original
arrives exactly once, the useful neighbors remain retained, and resource limits
hold. The protected-owner exclusion and the existing repeated paid-capacity
native control also pass, alongside strict core lint, formatting and the
919-file source-size gate with four unchanged exceptions.

Earlier attempts exposed omissions in this manual fixture: Bloom maintenance,
between-tick lookup/tree/report deadlines, asynchronous completion draining and
continuous endpoint receipt observation. It now invokes the existing production
handlers for that work; no runtime policy, timers or messages change. A separate
setup assertion was corrected to tolerate initial same-identity carrier handover
while still requiring unchanged owners throughout the maturation interval.

This is reliable-carrier SimNetwork evidence using manual native dispatch, not
full RX-loop scheduling or radio performance evidence. It does not establish
first-time paid funding within the contact, arbitrary admission at capacity,
lossy mobile encounters or a universal 1.5-second service guarantee. Reproduce
with the core library filter
`responsive::brief::mature_full_rosters_deliver_originals_during_brief_contact`
and the development dependencies in [FUNDING-COSTS.md](FUNDING-COSTS.md).

The production RX-loop companion now exercises that same twelve-node population
without manual protocol dispatch. Each node runs its ordinary event loop from
startup, with the existing half-second cohort offset. The shared population
factory preserves identities, timers and allocation limits. Initial local links
use ephemeral connect commands; cross-component neighbors and competitors use
automatic discovery. Real local payloads and increasing application-data counters
establish useful-carrier traffic while the original full rosters remain stable
and mature. Existing queries verify cold opposite-endpoint sessions and sample
peer, connection and link bounds; they do not expose every private admission
predicate or provide atomic multi-node snapshots.

One original is submitted through each source's normal application queue. An
independent receiver records arrivals continuously, and the carrier cuts without
waiting for a handshake, query or payload. Across three runs, reciprocal bridge
observation completes at 303–388 ms and both originals arrive exactly once at
1.297–1.395 seconds, before actual cuts at 1.501–1.502 seconds. All 236 local
payloads per run arrive within their unchanged two-second individual bound.
Reopening can observe late originals but cannot change short-contact acceptance.
Startup and encounter failures stop and join owned tasks and unregister the
simulation network.

The live case, original manual mature-contact case, protected-owner control,
strict core lint, formatting and the 922-file size gate pass. Final native/lint
source and dependency fingerprints match; the only earlier compatibility-source
difference is an equivalent iteration-style lint fix in the live observer.
No production routing or payment behavior changes. This verifies a fixed
reliable-carrier encounter through the actual RX loop; first-time paid funding,
lossy radio mobility, channel coordination and general timing guarantees remain
separate. Reproduce on Unix with the core library filter `responsive::live::`
and the same development dependencies.

The funded companion remains an unmerged failing experiment at `821502e87`.
It retains the six-node paid line, eight competing neighbors and eight existing
directional channels. Only one idle competitor per boundary is initially visible;
both full rosters then remain unchanged for twelve seconds with real local paid
traffic. All competitors and the bridge become available at contact opening.
One fresh 256-byte datagram is offered in each direction, with an independently
scheduled 1.5-second cut. Existing end-to-end sessions are retained, unlike the
cold-session core companion. No additional cross-component application probe is
sent during recovery, and later payment progress cannot change the cutoff result.

Four runs miss both original deliveries before cuts at 1.501–1.502 seconds.
The forward original uses a stale route and is dropped at the boundary with a
no-route indication, without a payment-policy denial. This is permitted by the
existing best-effort datagram semantics; submission is not a delivery promise.
The reverse original stays queued. Its sole local peer is connected, healthy
and eligible for tree forwarding, but its Bloom filter does not advertise the
destination. The final trace first selects that peer about 7.10 seconds after
opening, before the next scheduled retry; a verified reply then flushes the
original. This supports the existing wakeup on newly usable reachability, not
a missed eligible-peer retry. Why that reachability information arrives late
still needs isolation; these runs do not establish useful paid service during
the short encounter or a general mobile convergence bound.

The final two runs separately verify fresh cross-contract usage and supported
cumulative credit plus payer acknowledgements on all eight original channels
4.10–4.18 seconds after reopening, within one shared twenty-second passive bound.
Some usage consumes prior credit; native session upkeep can also advance contract
counters. These observations do not attribute every payment to a delivered
original or place acknowledgement before the cut. Local streams remain complete,
authority and resource limits hold, and all 1,536 test sats are collected in each
run. Strict relay lint, formatting and the 925-file size check pass on the isolated
experiment; the delivery assertion remains failing and is not integrated into
the canonical test suite. No production behavior or hardware changed. Reproduce
the experiment with the `finite::mature::` priced-path filter and the same
development dependencies.

The pending-Bloom deadline regression isolates one avoidable propagation delay.
Three real UDP/Noise nodes establish a stable tree and a successful announcement
that does not yet advertise the target. A genuine incoming filter makes the
target reachable, then all three nodes use their normal receive loops. Before
the fix, the changed announcement arrives after 1,015 ms because it waits for
the one-second maintenance tick, missing the unchanged 850-ms acceptance bound.
With cached pending deadlines, it arrives after 503 ms while respecting the
existing 500-ms debounce. Unchanged-filter refresh remains on ordinary ticks at
the existing five-second interval; no new wire message or timing limit is added.

Pending tree and Bloom updates share the existing bounded routing turn. Failed
sends retain their work and successful-send history; fresh retry floors prevent
failed or canceled writes from immediately rearming fast dispatch. A timed-out
tree batch leaves unvisited Bloom work eligible for the next turn. Real encrypted
Sim sends exercise both cancellation boundaries, retained updates and the
512-packet receive-drain cap. Ordinary periodic retry remains independently
eligible. This does not establish progress past a persistently stalled peer
within one serial batch.

All 75 focused checks pass, including the live twelve-node encounter: both
originals arrive once at 858–864 ms, before the independent 1,501-ms cut, and all
236 local payloads arrive within their existing bounds. Strict core lint,
formatting and the 925-file size check pass on the frozen source/dependency
graph. This isolates and removes a scheduler delay; the matched paid short-contact
comparison below still fails, and the change has not been tested
on physical routers. Reproduce with the core filters
`forwarding_contention::bloom_deadline::`, `node::bloom::deadlines::`,
`sim_discovery::bloom_refresh::` and `responsive::live::`.

Three paid comparisons on that runtime still miss both originals before the
independent 1.5-second cut. The first preserves the original experiment unchanged;
the second adds a wall-clock opening bracket and routing traces. Their native
admission order differs: the traced run admits competitors first and does not
establish the bridge before the cut. Its first bridge filter arrives after
20.56 seconds, so it cannot explain the first run's post-join delay.

A separate diagnostic leaves the additional competitors hidden while retaining
both mature full rosters. The bridge filter arrives at 559 ms, the receiving
boundary adopts the joined root at 768 ms, and reachability reaches the reverse
source at 1.059 seconds. That source's lookup reaches the last intermediate at
1.075 seconds but encounters the existing two-second incoming-peer/target
forwarding limit: an earlier boundary lookup used the same slot at 557 ms.
The original lookup reaches its target at 2.563 seconds, after separation;
a retry's verified reply reaches the source at 5.099 seconds, after reopening.
This isolates a post-join discovery delay without weakening spam protection.
Signed replies bind the request ID, target and coordinates, so reusing another
request's reply unchanged is not a valid cache shortcut.

All eight original channels separately pass fresh usage, supported cumulative
credit and payer acknowledgement checks 4.03, 18.61 and 4.18 seconds after
reopening. These counters can include native upkeep and prior credit; they do
not establish delivery of the originals. Local streams remain complete and all
1,536 test sats are collected in each run. Source/dependency/lock guards pass.
Both paid experiments remain unmerged and failing; no physical device changed.

A separate native TCP regression exposes lost initial Bloom work when bootstrap
is canceled after successful peer promotion. The connection is already consumed,
but the old code has not yet marked the filter for dispatch. Periodic refresh
cannot repair a peer with neither pending work nor a previous successful send.
Promotion now retains the initial update synchronously after validating the
installed owner, before cleanup or bootstrap can suspend. Duplicate-request
bootstrap also marks before its first send. No new message, owner, retry interval
or resource allowance is added.

The regression fails on the old runtime and passes with the fix: after releasing
the blocked carrier, ordinary dispatch sends one real encrypted initial filter,
which the counterpart decrypts and validates. First-packet delivery, replay
rejection and exact connection ownership remain checked. All 108 handshake
compatibility cases, four pending-deadline cases, four refresh simulations, the
native propagation-deadline case and the live twelve-node encounter pass, as do
strict core lint, formatting and the 925-file size gate. Their final source and
dependency fingerprints match. One earlier handshake run failed a fixture setup
window; the unchanged baseline passed on another schedule. The fixture now opens
relative to the receiver's actual maturity deadline, preserving all acceptance
assertions. This promotion fix does not establish general short-contact or radio
readiness.

The parent-change audit also reproduces lost routing work. A three-node fixture
holds a genuine encrypted root declaration while accepting its filter and link
measurement, then invokes the production signed-tree handler with the captured
input. Cancellation occurs after a real parent switch and one encrypted tree
packet reaches its carrier, while that send's completion remains suspended.
The baseline loses pending Bloom work; the uninterrupted control passes.

Bulk topology announcements now retain both Tree and Bloom work for every peer
before the first send. Seven post-send marking blocks are removed. Successful
sends still clear their own pending flags, while interrupted and unvisited peers
remain eligible for ordinary dispatch. Changed ancestry under the same parent
also retains Bloom work; ordinary periodic refresh does not rearm it. Existing
debounce, retry floors, wire messages and resource bounds are unchanged.

Both native cases pass with the fix: ordinary dispatch delivers a valid encrypted
target-positive filter and the changed tree to the observer, with exact original
peer/link/index/generation ownership retained. This isolates handler ownership,
not receive-loop scheduling. All 55 focused behavioral checks pass, including
the 100-node convergence fixture, lost-announcement repair, first link measurement,
deadline/refresh controls and the live twelve-node encounter. The live originals
arrive at 924–933 ms before the independent 1,501-ms cut; all 236 local payloads
arrive. Strict core lint, formatting and the 926-file size gate pass. Runtime and
dependency fingerprints match across the gates; the final native/lint rerun only
changes equivalent test syntax and a type alias. Devices remain unchanged.

The preserved paid encounter and its bridge-only diagnostic still miss both
originals on this integrated runtime, before independent 1,501-ms cuts. The
crowded run first observes the bridge around 20.8 seconds after opening. With
additional competitors hidden, the reverse source already reports the joined
root before 0.8 seconds, but its first lookup for that root begins at 1.657
seconds. These observations separate admission delay from post-join route
availability; they do not prove a single cause or establish mobile delivery.
All eight original channels recover their accounting and acknowledgements
17.38 and 4.19 seconds after reopening, respectively. Local streams deliver
35/35 and 22/22 per direction, and all 1,536 test sats are collected in each run.
The unchanged failing experiments remain unmerged. The current-root routing experiment below evaluates that post-join delay
with an original queued before the tree merge.

Pending-session traffic retains a single owner across retries and cancellation.
Only one TUN packet or one endpoint batch of at most 16 payloads leaves the
node-owned queue across an await. Native regressions cancel a real encrypted send
after its selected packet reaches the next hop; unvisited originals remain queued
for ordinary retry. Preparing TUN traffic stamps initially unaged packets before
sending, so cancellation cannot renew the two-second ready-send budget.

Endpoint errors return only actual deferred payloads matched by the existing
send token. They retain their original age and the existing destination/packet
caps. TUN route and MTU preflight likewise runs before removing the selected
queued packet. After handoff, the cached TUN sender checks its own local transport
receipt and never authorizes replay from an unrelated failure or an uncertain
result. It moves the original payload and reuses native IPv6 compression and
source admission. Terminal turns retain unrelated control ingress; cached sends
leave deferred TUN packets for their normal dispatcher. The superseded aggregate
send-result helper and unused bookkeeping are removed.

Two additional UDP/Noise regressions reproduce the distinct TUN failures. One
rejects an older endpoint record through ordinary source admission, then proves
that the admitted TUN original arrives while the old runtime wrongly retains a
queued copy. The other stages genuine SessionAck and TUN reports in the native
completion-before-control order: the older endpoint arrives, but its cached flush
previously discarded the waiting TUN original. The fixed runtime delivers both
originals once. These deliberately staged handler boundaries do not establish
complete RX scheduling or radio behavior.

All 30 focused behavioral checks pass on the final source, covering these cases,
TUN delivery, cancellation and original queue ages, endpoint partial failures,
discovery, current-root recovery and source admission. Strict core lint across
all features/targets, workspace formatting and the 933-file size check pass.
Source and dependency fingerprints remain unchanged through the gates. No wire
messages, allowance limits, payment policy or hardware settings change. Selected
TUN sends remain best effort; local send receipts are not end-to-end delivery
proofs. Physical mobile-radio acceptance remains separate.

Tree-mode routing now uses the current root's existing ancestry entry when no
cached destination coordinate is present. Cached records still take precedence,
including a record from another root; the hint does not create cache entries,
verified discovery results or delivery evidence. Explicit source bindings,
strictly progressing transit routes and previous-hop exclusion remain enforced.

Root adoption also retains a bounded wake for already queued established traffic
before announcement sends can suspend. The ordinary control dispatcher sends one
TUN packet or at most 16 endpoint payloads under the existing two-second budget.
The same source admission and queue helpers are used by ordinary retry. Rejection
ends the prompt wake; cancellation retains the wake and untouched queue without
replaying an uncertain selected send or spinning on an unconditional notification.
No wire message, dependency, retry interval or allowance was added.

A three-node native fixture establishes real encrypted sessions, splits the tree,
queues an original and releases a genuine new-root declaration. The old runtime
lacks the routing hint; a hint-only implementation still leaves the original
queued. With the wake, the original arrives within 750 ms without another lookup
or an application retry. Denied source allowance prevents sealing and delivery
without repeated immediate admission attempts. A cancellation control holds a
real send completion beyond the production two-second limit: its 15 untouched
payloads retain their age and ownership, and ordinary completion processing
ultimately delivers all 16 originals once. That control invokes the signed-tree
handler with captured genuine input; it isolates handler/dispatcher ownership,
not the full receive-loop timing or paid accounting.

All 113 distinct focused behavioral checks pass, including routing boundary
controls, queue cancellation/error regressions, source admission, coordinate
recovery, tree changes and receive-loop scheduling. The 100-node routing test
reaches all 9,900 ordered pairs without loops. The separate live twelve-node test
delivers both originals at 860/869 ms before its independent 1,502-ms cut, with all
236 local payloads received. Strict core lint, workspace formatting and the
930-file size check pass; the four existing line-count exceptions are unchanged.
Each gate preserves its source/dependency graph. Across final gates, changes are
limited to test code and routing comments; the native cancellation and lint gates
run on the final exact sources.

An initial broader coordinate-recovery run failed three of six cases; the
unchanged baseline passed on another schedule. Inspection found that the manual
fixture omitted production's deferred-discovery deadline service. It now runs
that service, retaining the original one-second filter-release acceptance window
and additionally checking that source lookup clocks and request counts do not
advance to rescue delivery. All six cases pass. This corrects fixture fidelity;
the observations do not isolate the cause of every initial failure. Physical
routers are unchanged, and the paid short-contact comparison remains necessary.

On the integrated current-root and queue-ownership runtime, the unchanged paid
bridge-only encounter delivers the reverse original at 764 ms, before its
independent 1,501-ms cut. The forward original remains absent through the
five-second observation, so the overall test still fails. The previous comparison
missed both originals; this single observation does not establish a general
latency improvement or crowded/mobile readiness. The fully crowded variant was
not rerun for this change.

A subsequent passive fingerprint trace identifies the original precisely. Its
encrypted session envelope is sealed at 0.897 ms, forwarded by the first transit
at 3.898 ms, and reaches a no-route decision at the disconnected boundary at
7.575 ms. The matching drop occurs at 7.657 ms and the source handles PathBroken
at 14.049 ms, before the bridge forms. This is an already submitted best-effort
datagram, not lost node-owned queued work. The reverse queued original arrives
at 808 ms before the unchanged 1,501-ms cut. Both local streams deliver 18/18;
all eight channels recover accounting after reopening and all 1,536 test sats
are collected. Source/dependency guards and strict core lint pass. The passive
trace code remains in the isolated experiment; no routing or wire behavior changed.

FSP deliberately provides no retransmission or ordering. The strict raw-datagram
experiment remains failing and unchanged; it cannot by itself establish a defect
in retaining queued work. A later lookup also crosses the root change, but the
boundary reports current-root target coordinates before its verified reply, so
that reply's latency does not identify how long the application route was unusable.
That distinction motivates a separate test of one accepted TCP write across a
paid bridge outage, without reconnecting or resubmitting the application write.
Prior paid mobility datagram retries and direct unpaid TCP loss tests did not
jointly prove that behavior.

The new `merge_split::reliable::accepted_tcp_write_recovers_after_bridge_rejoin`
case uses the existing six-node paid bench and FipsTcpEndpoint adapter. It first
establishes one TCP connection across the funded route, cuts the bridge and waits
for ordinary peer eviction and separate component roots. This takes 30.203 seconds
in the observed run. The same TCP connection then accepts one 4,096-byte write
while the bridge remains down. An independent task reopens the bridge two seconds
later. TCP receive/poll uses actual elapsed time; no clock jump, reconnect,
application retransmission or new delivery-receipt protocol rescues the write.

The original byte range arrives once in order and its TCP marker is acknowledged
within the unchanged 20-second deadline anchored at the write. First receipt is
6.244 seconds, complete receipt 6.317 seconds and acknowledgment 6.334 seconds;
the bridge reopens at 2.002 seconds. All eight original paid channels and funding
identities remain intact, their observed usage advances and ordinary cumulative
payments cover the supported usage. Aggregate channel counters can include
handshake/upkeep traffic: TCP's exact read and acknowledgment separately prove
application delivery. The measured verdict is retained before carrier restoration
and collection, including task panic/timeout; all 1,536 test sats are collected.

The integration test, strict all-target relay lint, workspace formatting and
931-file size gate pass. Source/dependency/lock guards pass; the only source
change after the behavioral run sorts the test module declaration for formatting,
and the final lint gate covers that exact source. This proves one retained
reliable stream across a simulated paid tree split; it does not establish fast
physical eviction, general mobile-radio latency, restart recovery or sustained
throughput. The strict short-contact datagram experiment remains unchanged and
failing. No physical device changed.

The focused carrier-loss follow-up at `e433cd31d` reuses that fixture and stream
driver. `accepted_tcp_write_recovers_after_directed_carrier_loss` keeps the carrier
up while dropping all encrypted traffic from node 0 to node 1 for two seconds.
The application submits one 4,096-byte write. Before restoration, the source
records five submissions on application service port 44753 (5,770 FIPS payload
bytes); the network records 16 loss drops and zero link-down drops. Those network
totals also include control traffic. The original TCP connection delivers the
exact byte range once and acknowledges it without application replay: first
receipt at 3.020 seconds, complete receipt at 3.081 seconds, acknowledgment at
3.096 seconds, and independent carrier restoration at 2.001 seconds. The original
20-second deadline and payment/capital limits are unchanged.

The original split/rejoin case also passes on this source: ordinary split takes
30.201 seconds, followed by acknowledgment 6.311 seconds after its single write.
Both cases retain their eight original channels/funding identities, advance
supported all-hop usage and catch up automatic payments; each collects all 1,536
test sats. The separate service-carrier retransmission test passes too. These
three focused checks, strict lint for both affected integration targets,
workspace formatting and the 1,026-file size gate pass. Frozen source and
dependency-manifest checks pass; acceptance evidence digest is
`af5d296e775f8e4eb7ac43e61ea1bfafee1f5611388e7c30ec8ab2b85bd9e75f`.
This verifies reliable application bytes over a simulated paid lossy carrier,
independently of payment control. It adds no delivery-receipt protocol. The
physical phone raw-datagram loss result remains failed; sustained reliable
application-byte acceptance on the phone/router route is still required.

The private stream diagnostic at `c02ead9e1` now supports that next experiment.
It arms one authenticated peer on ordinary paid port 44744, bounds duration,
buffers and offered bytes, and verifies exact duplex delivery plus TCP
acknowledgements without replaying accepted application prefixes. In the real
three-daemon UDP/TCP fixture, unfunded streams deliver no application data;
paid streams accept, receive and acknowledge all 131,072 bytes each way in
2.846 seconds, within their original six-second windows. Original channels and
funding budgets remain unchanged, cumulative payments advance, and settlement
reconciles all 384 test sats with no locked or pending funds.

Three lower-level carrier tests also pass, including a directed two-second loss
window with backpressure, exact 512 KiB duplex recovery, odd-parity peer keys,
cancellation/rebind and unrelated-peer rejection. Strict lint for both affected
integration targets and compilation without `measurements` pass. The immutable
test executables and actual spawned daemon are bound to the same source archive;
source and frozen dependency manifests remain unchanged. Evidence is in
`work/reliable-stream-probe-r3`; result digest is
`1ffd59dd59fd4b30a6e39ca916780073faad420602961197750004828c238fe9`.
The first two failed attempts remain recorded. These are host-side checks, with
no physical device changes or new delivery-receipt protocol.

All eight original channels separately recover the required usage, cumulative
credit and acknowledgements 661 ms after reopening. Those checks include native
upkeep and prior credit and do not establish delivery of the missing original.
Both local streams deliver 18/18 without duplicates, and all 1,536 test sats are
collected before reporting the failure. Fixture, source, dependency and lock
guards pass. The failing experiment remains isolated and unmerged, and no
physical router changed.

The finite-contact fixture, initially isolated as `1725169c`, reuses the
independently timed contact driver with full neighbor tables and no reciprocal
bridge at the first opening. Financial agreements and earlier session history are retained: this is
cold adjacency, not first-time funding. Complete application submission spans
and receive observations must both precede the cut to count as finite-contact
delivery; later receives and packets unobserved by the cohort deadline remain
separate. The final sustained opening retains the original 60-second deadline,
including time spent draining the cohort.

Before the child-update repair below, seed 139 delivers **0/20** fresh in-window
packets during cold openings lasting 0.3–1.5 seconds. Sustained contact then
restores delivery at 16.518 seconds and all-hop credit at 17.232 seconds.
Subsequent warm windows deliver **31/33** fresh
offers before their cuts, with progress in every direction/window and original
authenticated owners retained. After a full split and native roster refill, the
second encounter first observes a bridge at 49.765 seconds and a common tree at
51.209 seconds, but **fails the unchanged 60-second paid-recovery bound**.
Local streams still deliver all 138 packets per direction without duplicates
(maximum gaps 1.562/3.995 seconds), and all 1536 test sats are collected after the
failure. The late admission and subsequent route-lookup delay need separate
diagnosis; the owner history alone does not establish their causes.

The original brief suite also misses the first cold contact with the original
root, both after the fixture extraction and on unchanged `6b9d3fb8`. A native
UDP regression isolates one cause: a lost child root-change declaration leaves
its parent with the child's former root. Authenticated link feedback previously
retried only missing declarations, and a child ignored its parent's unchanged
same-root announcement. The repair retries missing or conflicting root state
through the existing announcement exchange. A stale same-root announcement from
the current parent elicits the child's current declaration only when the existing
send rate permits an immediate reply. It neither accepts stale state nor queues
an extra reply when rate-blocked. No message types, timers or limits are added.

The regression drops one genuine encrypted child update while preserving the
live session and replay state. Before the repair, the parent remains obsolete
after the two-second bound; with it, the latest run repairs in 513 ms, before the
five-second periodic refresh. It retains the authenticated owners, signed
sequence, 500-ms send spacing and settled quiet-tree bound. Bad signatures and
valid nonparent duplicates cannot trigger the new reply. All 20 focused tree
checks and strict core lint pass. Both paid brief scenarios now deliver fresh
traffic in every contact window, including both directions of the previously
missed first 400-ms window. Each scenario collects all 1536 test sats.

With this repair, the crowded seed-139 characterization also passes its unchanged
60-second sustained-recovery bound. Bridges appear at 15.366/29.756 seconds,
delivery at 16.546/37.448 seconds, and all-hop credit at 17.257/38.263 seconds.
Cold short contacts still deliver **0/20** in-window offers; warm contacts deliver
**31/31**. Independent local streams deliver 115/115 packets per direction without
duplicates, with maximum gaps of 1.019/1.015 seconds, and all 1536 test sats are
collected. Formatting and the source-size gate pass. The fixture is integrated
as characterization, not as proof that cold mobile encounters work. Reproduce
with the `priced_paths` filter `merge_split::crowded::automatic::repeated::finite::`.

An earlier run with diagnostic logging alone also passed after the original
timeout. Scheduling varies, so neither passing run establishes that the
child-update repair fixes the separate late-admission failure. The earlier
timeout remains evidence of an open crowded-recovery gap. No deadlines or safety
limits were relaxed. Sim discovery does not model radio beacon airtime or RF
loss, and these runs do not establish physical mobile-mesh readiness.

#### Queued discovery after reordered reachability

A filter can arrive while its authenticated sender is still a non-tree peer.
Accepting a later child declaration previously made that filter usable without
releasing a queued lookup that had never sent a request. The tree handler now
reuses the filter handler's bounded wake-up helper after accepting the transition
and recomputing coordinates. Already-sent requests retain their normal retry
cadence. No queue, timer, message type or rate-limit exception is added.

The native regression offers one original endpoint payload, delivers the filter
and child declaration over existing encrypted carriers, and observes the first
lookup on that carrier before the unchanged one-second retry deadline. It fails
with zero requests before the fix and passes with exactly one afterward. Two
stale signed declarations in fresh encrypted frames cannot send another lookup;
owners, indexes, session generations, pending traffic and retry clocks remain
unchanged. The triangle setup, advertised target and local parent choice are
controlled: this proves the eligibility wake-up, not destination delivery or
organic parent selection. Cancellation before the callback still falls back to
the existing lookup deadline.

All 23 focused routing checks, strict core lint, formatting and the 896-file size
gate pass. Both paid brief-contact scenarios and the crowded seed-139 scenario
also pass, collecting all 4608 issued test sats. The crowded run delivers at
15.711/20.511 seconds and credits every hop at 16.423/21.223 seconds. Cold short
contacts remain **0/18**, while warm contacts deliver **31/31**. Local streams
deliver 98/98 per direction without duplicates; maximum gaps are 1.004/1.016
seconds. These timings do not establish a general speedup or resolve the earlier
crowded timeout. A preceding instrumented run showed several coordinate lookups
rejected by the existing forwarding limits during recovery, without establishing
that those rejections alone caused the paid-delivery delay. Reproduce the native
regression with the `spanning_tree::reachability_wakeup::` core test filter.

#### Competing discovery requests

A native four-node regression reproduces starvation under the existing global
per-target forwarding limit: an authenticated neighbor requests the same target
every 2.1 seconds, while another origin submits one application payload. All four
normal lookup attempts are rejected, and the payload remains undelivered after
its 15-second discovery ladder. The same target answers all eight competing
requests; the quiet control delivers. Neither the retry ladder nor the two-second
forwarding interval is changed.

The relay now retains one waiting request per target from a different authenticated
ingress than the last served peer. Retention is capped at 256 requests and 64 KiB
of encoded payload, plus bounded metadata, with at most 64 requests and 16 KiB per
ingress. A retained request gets first consideration at the next existing target
slot, including when new traffic triggers dispatch. Fresh IDs cannot replace it
or extend its captured expiry. Dispatch rechecks the route, original reverse-path
admission generation, response ownership, connection admission and ingress budget.
Eviction and same-millisecond ID reuse cannot revive an old payload. TTL is spent
once, and the ordinary target slot and ingress token are charged before I/O.

The existing lookup deadline turn also wakes transit-only work; an empty queue
adds no polling. Local-origin retries run before deferred transport awaits. Each
turn selects at most 16 deferred requests, and cancellation consumes only selected
work while keeping untouched requests due. Capacity exhaustion falls back to the
existing origin retries. Limits apply to authenticated ingress peers, which may
aggregate many clients; this is not general multi-ingress or Sybil fairness.
No wire messages, application spending permissions or bootstrap exemptions change.

With the repair, an autonomous production relay RX loop delivers the original
payload 2.058 seconds after the first competing request, at the next forwarding
slot. Endpoints use real encrypted UDP with manually driven wall-clock maintenance.
The 47 focused checks, 31 native simulation checks, 85 discovery-handler checks,
normal build, strict core lint, formatting and source-size gate pass. The existing
long-running 100-node discovery test remains ignored in the handler suite.

Both paid short-contact scenarios and the crowded scenario pass and collect all
4608 issued test sats. Crowded sustained delivery takes 26.452/31.354 seconds and
all-hop credit 27.163/32.268 seconds; warm contacts deliver 32/32 offers, while cold
short contacts remain 0/17. Independent local streams deliver 119/119 per direction
without duplicates. These timings do not establish a general speedup, resolve the
earlier crowded timeout, or prove radio mobility. The changes are local only.
Reproduce with core filters `discovery::forwarding_contention::` and
`sim_discovery::deferred_lookup_cancellation::`, and the paid filters above.

#### Observing recovery after the tree connects

The crowded fixture can reuse the bounded brief-contact observer with
`FIPS_CROWDED_TIMING=1`. It preserves unfamiliar candidate identities and records
pending lookup changes alongside coordinates, session epochs, watches and
purchases. Packet submission spans distinguish a blocked application call from
subsequent delivery delay. Query spans are conservative observation brackets,
not exact protocol event times. The existing 4096-change/2048-round bounds remain;
trace destruction also emits retained observations on Rust unwinding or task
cancellation. `recovery_wait_ok` describes the deadline result, not whole-test
success. Cancellation output can arrive during cleanup. Submission spans print
only when the inner traffic operation returns; their absence after cancellation
does not prove that no packets were offered.

A seed-139 observation recovered its second tree at 40.249 seconds, but the first
batch completed at 43.153 seconds. All twelve originals were submitted in
0.344 seconds, with no call taking more than 44 microseconds. The source's missing
destination coordinates appeared within the observed 43.020–43.217 second bracket;
session epoch, watch and purchased allowance remained unchanged. Its original
attempt-four lookup remained pending. This favors recovery through incoming
coordinate-bearing traffic rather than that source accepting a lookup response,
but does not identify the insertion event or prove a lost wake-up.

Final validation keeps failures visible. Strict relay lint passes. With the
optional crowded observer disabled, both crowded encounters complete and all
1536 test sats are collected; the second takes 47.730 seconds, including three
payload retries in the existing seven-second retry round. An instrumented run
instead misses the unchanged 60-second second-encounter limit and still collects
all 1536 test sats. Its boundary candidates had completed handshakes before the
deadline, but no bridge was observed during acceptance. Bridge admission seen
after the local traffic pump stopped is cleanup evidence only. The final brief
suite passes the opposite-root case but fails the other case's first 400 ms cold
window, after collecting all 3072 test sats. An earlier instrumented build passed
both brief cases; these variable outcomes do not establish an improvement or a
regression caused by observation. No routing, payment or admission policy changes
in this diagnostic work, and none of these results proves mobile readiness.

Reproduce observations with the existing `priced_paths` test and the
`merge_split::crowded::automatic::repeated::finite::` filter, adding
`FIPS_CROWDED_TIMING=1` and `--nocapture`; use the same dependency configuration as
the preceding acceptance runs. Coordinate insertion and autonomous discovery
selection still need controlled evidence before changing scheduling policy.

A six-node localhost-UDP readiness regression now keeps four local streams (two bidirectional
pairs) running across staggered full rosters. Each boundary retains a useful
neighbor and an idle elective neighbor. Real delivered data, useful-peer age and
the actual victim selector establish that application demand protects the useful
neighbor. Both boundaries retain one complete incoming and one complete outgoing
bridge handshake, with unchanged original attempt deadlines. The fixture retains
the crowded profile's ten-second minimum age, two-second rotation spacing and
thirty-second handshake timeout, with one-second maintenance ticks offset by
500 ms. No timestamp, peer, proof or coordinate is injected.

The final run admits the original candidates 539 ms after the younger incumbent
becomes eligible. All 676 local originals and both fresh bridge payloads arrive
exactly once; the largest local inter-delivery gap is 121 ms. A final bounded drain
starts only after admission and another second of uninterrupted local offers.
Strict core lint, formatting and source limits pass, alongside the five existing
readiness cases. This isolates retained-proof service under continuing application
load; it does not reproduce autonomous discovery ordering or the full RX loop.
Initial dials are explicit and rekey is disabled. The crowded timeout and cold
contact failures above remain open. Reproduce with core test filter
`rotation_readiness::loaded::` and the same development dependency configuration.

#### Earlier crowded-admission experiments

Earlier native population diagnostics exposed the admission-latency gap.
They preserve the two-peer boundary cap, one pending candidate, original local
links, 500-ms maintenance phase and 60-second encounter deadline. Two alternative
four-candidate identity layouts pass both encounters, with delivery at
25.257/50.987 and 35.483/38.074 seconds. Increasing to eight local candidates per
boundary misses the first encounter deadline with the ten-second minimum age.
Reducing that age to five seconds also misses the deadline. A two-second age
passes one identity layout at 12.405/10.789 seconds but fails independent layouts:
one joins at 6.772 seconds and misses rejoin; the reversed layout misses the first
join. Bridge requests reach the remote boundary while other candidates own its
admission slot. Local traffic, owner retention and resource-cap checks continue
to pass, and the bounded transition records omit no changes. At that stage these
seven cases remained isolated failing diagnostics. The later ordering and
replacement-history changes above make all seven pass under their original
limits; earlier checkouts remain as historical evidence. The failures do not
support a timer-only recommendation or a general mobile-readiness claim.

A separate bounded-displacement experiment kept the last elective victim from
immediately taking an outgoing discovery slot back. Its three native controls
pass, but only two of the seven population cases complete: three miss an
encounter deadline, one finds an orphaned receive index, and one violates the
original-owner retention assertion. This policy remains unmerged. The index
failure led to the independently reproduced overlapping-rekey cleanup fix below;
that correction does not establish convergence or validate the rejected policy.

The native encounter fixture now tracks retained admissions independently of
normal key renewal (2026-09-22). Its old snapshot included the current receive
index and crypto generation, which legitimately change during periodic rekey.
Long encounters could therefore fail even while the original neighbor stayed
connected and delivered traffic. Retention now compares link, authentication
time and remote startup epoch. Exact receive-index ownership, resource caps,
continuous local delivery and encounter deadlines remain separate assertions.
A native control reproduces the old false failure using real rekey and
bidirectional endpoint data, then passes with the corrected snapshot. Its negative
control sends encrypted Disconnects and performs a fresh Noise handshake with
the same identity and process, proving that removal and re-admission still fail
retention. Strict all-feature/all-target core lint also passes. Earlier retention
failures require reevaluation; deadline failures remain routing evidence.

An earned outgoing retry now keeps its one frozen window against a second
different-identity incoming requester (2026-09-22). Ordinary attempts may still
yield; a retry has already spent that yield. No state, wire message, timeout or
resource allowance is added. A silent retry can delay unrelated incoming requests
until expiry, so this is a local service-order rule, not a rendezvous guarantee.
Seven native controls cover real retry completion, expiry despite a configuration
increase, cleanup, missing or ineligible targets, and the next actual discovery
choice when ordinary exploration is owed. Three of those controls fail on the
previous transfer behavior and all seven pass with the guard.

All 100 handshake compatibility tests pass. The unchanged paid repeated-encounter
fixture delivers at 29.354/20.387 seconds and credits every hop at 30.167/21.200
seconds. Its 170 independent local originals arrive exactly once, with maximum
gaps of 1.003/1.017 seconds below the five-second bound. Existing channels and
budgets survive both encounters, and all 1,536 test sats are collected. These are
compatibility results, not a matched performance comparison. Strict all-feature,
all-target core lint, the default core build, formatting and source-size checks
also pass with unchanged source/dependency fingerprints during the runtime gates.

Five of the seven extended population diagnostics pass with this rule. The
eight-candidate, ten-second minimum-age case still misses its first 60-second
encounter. With a five-second minimum age, first delivery takes 46.068 seconds,
but rejoin misses the same unchanged limit after the retention correction above.
The two-second shifted and reversed identity layouts that previously failed now
complete both encounters. These results do not establish general mobile mesh
convergence: a remote boundary can still keep completed local candidates in its
only admission slot while rejecting the connecting neighbor's requests.

The corrected five-second-age rejoin trace also reveals a crossed-handshake
backoff gap. Both boundaries eventually own outgoing attempts to one another.
The deterministic outbound winner has spent four of five resends, but its next
scheduled send falls after its frozen deadline. Capacity correctly prevents it
from accepting a second handshake; repeated incoming requests receive no reply.
An authenticated, permitted crossed request can now spend one remaining resend
early on the exact existing outbound carrier, without a new index, handshake or
deadline. Replays cannot obtain another early send, and an earlier scheduled
future retry is preserved within the same shared budget.

Six native controls exercise actual UDP/Noise handshakes, reciprocal readiness
and bidirectional endpoint delivery. They cover the backoff gap, loss of the early
packet followed by the original scheduled retry, duplicate requests, exhausted
credit, invalid or denied requests, and frozen expiry after a configuration
increase. The original code fails the two prompt-response controls; a draft that
postpones the scheduled retry fails the lost-early-packet control. All six pass
with the bounded resend and preserved earlier schedule; strict core lint passes.

All 106 handshake compatibility tests and the default core build pass with the
same frozen source and development dependencies. The paid repeated encounter
delivers at 22.278/27.630 seconds and credits every hop at 22.787/28.240 seconds.
All 168 independent local originals arrive once, maximum local gaps remain
1.003/2.311 seconds, and all 1,536 test sats are collected. The extended
eight-candidate, five-second-age diagnostic still misses its first 60-second
encounter, so it does not reach the former rejoin stall. Its trace instead shows
a boundary waiting on a previously displaced local neighbor while rejecting the
connecting router. The repair closes the demonstrated crossed-handshake gap;
it does not establish crowded admission convergence or physical mobile readiness.

A focused regression reproduces a second capacity conflict after elective UDP
neighbor replacement. The displaced endpoint retains its old active peer and
starts a full refresh. If the returning peer's simultaneous request wins the
identity tie-break, the losing refresh still occupies the only candidate slot.
The original code refuses that request until old state expires. Admission now
reuses the existing candidate cleanup to retire that unanswered outgoing refresh
only when identity, active carrier and pending carrier match the incoming request.
Completed candidates and active keys remain protected; fresh encrypted proof is
still required before replacement. No messages, timers or resource limits change.

The native UDP/Noise regression fails before this fix and passes afterward. It
checks corrupt requests, genuine requests replayed from another source address,
exact request replay, old-frame replay rejection,
continued decryption with the retained old keys, reciprocal fresh indices,
unchanged attempt deadlines, bounded resources and bidirectional endpoint data.
All 107 handshake compatibility tests pass. The repeated paid encounter delivers
at 29.024/20.469 seconds and credits every hop at 29.835/21.078 seconds. All 168
independent local originals arrive once, maximum local gaps are 1.133/4.001
seconds, and all 1,536 test sats are collected. Strict core lint, the default core
build, formatting and source-size checks pass. The additional source-address
control and strict lint pass after that test-only extension. Tested source and
dependency fingerprints remain stable throughout each gate.
Six of seven fixed population cases pass on this runtime. The eight-candidate,
five-second-age case delivers at 47.495/39.807 seconds. All three two-second-age
identity populations pass both encounters, with delivery ranging from 6.758 to
46.225 seconds; both four-candidate identity variants also pass. The eight-candidate,
ten-second-age case still misses its first 60-second deadline. Its trace shows
each boundary preparing completed local candidates while the other offers the
cross-component bridge.

A separate diagnostic preserves that failed acceptance and continues the exact
scenario for another 120 seconds, without resetting native state, traffic,
maintenance cadence or limits. Neither a reciprocal bridge nor endpoint delivery
appears by 180.016 seconds from the original exposure. Both boundaries attempt
the bridge during this observation; every received request meets a completed
local candidate. The trace has no omitted transitions, and the test still fails
its original 60-second requirement. This is evidence of sustained admission
starvation within the observed window, not proof of permanent failure. The
reproduced stale-refresh collision is fixed; crowded admission fairness and
physical-router validation remain open.

A separate incoming-service experiment retains one authenticated requester with
a frozen expiry and a cursor independent of ordinary exploration. Two native
arrival-order regressions fail on the current runtime and pass with that policy.
Five native cases then pass, including real endpoint delivery, preservation
through unrelated demand and an owed ordinary turn, consumption by matching
demand, and replay/replacement expiry with no pending connection. Corrupt or
inbound-denied requests leave the completed candidate and active owner intact.

That policy is not integrated: the unchanged eight-candidate, ten-second-age
case still misses its first 60-second encounter. Continuing it without resetting
state produces no bridge or endpoint delivery by 180.012 seconds. The complete
trace shows bridge requests receiving a preference, then being superseded by
other requesters in the cyclic order while the boundaries' admission windows
remain out of phase. This falsifies the candidate as a sufficient fix for this
crowded scenario; the focused fairness checks do not establish convergence.
The isolated implementation and diagnostic fixtures are retained for further
work. Source, dependency and lock fingerprints remain stable throughout these
checks. That incoming-service experiment is not integrated.

A later first-arrival variant removes the separate service cursor and preserves
one frozen requester across unrelated demand and an owed ordinary turn. Four
native selection regressions fail on baseline; all five controls, including
expiry/replay/configuration and corrupt/denied-request checks, pass with the
variant. It is also rejected for integration: the dense queued-client fixture
now misses its cold 60-second encounter, before reaching the queued warm phase.
Preferred local requesters add service turns, delaying one boundary's first bridge
request from 15.926 to 35.198 seconds. All eight bridge requests still meet a
different completed candidate at the receiver. Retaining local requests does not
ensure timely reciprocal discovery, and the original deadlines remain unchanged.
The isolated branch also retains a reviewed spare-capacity consumption gap; it
has not received the compatibility checks required for production integration.

A separate experiment defers ordinary outbound preparation until an idle
incumbent reaches its existing minimum age, preserving incoming preparation,
already-owned attempts, effective demand preference and earned retry deadlines.
It also fails the unchanged dense fixture's cold encounter: neither boundary
attempts the bridge within 60 seconds, so the queued warm phase never runs.
The trace contains both incoming and outgoing local candidates, with six and
five incumbent changes at the two boundaries. Delaying outbound preparation
alone does not ensure reciprocal bridge discovery. Source, dependency and lock
fingerprints stay stable, and the portable lock is restored.

This experiment is not integrated. Its shared admission gate also changes the
existing explicit-connect contract, which allows preparation before incumbent
maturity. Moving that gate into the shared path-candidate budget would still
affect manual and configured connections through Nostr address resolution.
Any future discovery-only experiment must preserve those call paths and account
for incoming candidates competing for the same slot; no broader compatibility
claim follows from this failed run.

Ordinary exploration now uses a smaller change with a symmetric edge score:
the XOR of the local and remote node identifiers. The stored cursor remains an
identity, compared in the same edge order. Demand and earned retry precedence,
first-inbound cursor seeding and subsequent incoming-cursor protection retain
their existing rules. This adds no state, wire message, timeout or resource limit.

In the original ordering and the separate incoming-service experiment, the
observed bridge-candidate ownership windows never overlap during the three-minute
diagnostic. With symmetric ordering they overlap for about ten seconds, followed
by reciprocal bridge authentication at 61.117 seconds and endpoint delivery at
61.160 seconds from exposure. The original 60-second assertion remains failing.
All six other fixed population variants pass both encounters with their original
limits, useful-owner retention and payload requirements. These finite runs show
an improved rendezvous outcome, not a universal convergence bound or an overall
performance comparison; some passing encounters take longer than before.

Compatibility checks pass: 19 native discovery controls, 107 handshake controls,
the four original responsive-neighbor cases, strict core lint and the default
core build. One handshake fixture initially assigned roles by raw identity; its
setup now uses the actual discovery order, preserving its acceptance assertions.
The repeated paid encounter delivers in 21.953 and 31.950 seconds and credits
every hop in 22.765 and 32.662 seconds. Both independent local streams deliver all
88 original payloads without duplicates; their maximum delivery gaps are 4.001
and 1.015 seconds. All 1,536 test sats are collected. Source, dependency and lock
fingerprints remain stable during these checks, and the portable lock is
restored. This is native simulation and loopback payment evidence; physical
Wi-Fi discovery, roaming and radio performance remain unverified for this change.

The accepted learned admission that first fills a roster now initializes the
ordinary cursor. A native four-candidate control previously selected that initial
neighbor again after authenticating only two alternatives; it now authenticates
all three alternatives before selecting it again. The first incoming rotation can
still replace this initial position, preserving escape from an unconfirmed
request. Its existing pacing timestamp distinguishes the first attempt from later
attempts, including after
expiry. Later incoming attempts and promotions cannot rewind ordinary progress.
This uses existing state and changes no messages, limits or deadlines. Initial
spare-capacity inbound admission is not proof of fresh reciprocal ownership.

With this initialization, the eight-candidate, ten-second-minimum-age cold
encounter delivers at 51.127 seconds within its original 60-second window. The
repeat encounter still fails that window: neither boundary attempts the bridge
before the deadline while other candidates consume their ordinary turns. A
diagnostic continuation observes the bridge at 79.011 seconds and original
endpoint delivery at 79.046 seconds from the repeat exposure; it preserves the
failed original assertion. All six other fixed population variants pass both
encounters. The initialization improves first-sweep service, but does not supply
a universal encounter bound; some other identity populations take longer.

All 21 native discovery controls, 107 handshake controls and four original
responsive-neighbor cases pass. The added expiry
control sends two distinct unconfirmed incoming attempts with no outgoing turn
between them. Both expire and release their indexes while preserving the initial
neighbor's exact link, index and authentication time. The next ordinary attempt
authenticates the healthy candidate that a repeated cursor reset would skip.

The paid repeated-encounter regression also passes: delivery resumes at 21.899
and 23.828 seconds, with credit on every hop at 22.818 and 24.438 seconds. Both
independent local streams deliver all 80 original payloads without duplicates;
their maximum delivery gaps are 2.870 and 3.738 seconds. All 1,536 test sats are
collected. Strict core lint, the default core build, formatting and the source
size check pass. Source/dependency fingerprints are unchanged throughout the
gates and the portable lock is restored. Those initialization controls alone left
the dense repeat-encounter target unresolved; the later replacement-history
acceptance above addresses that case. Physical mobile-radio acceptance remains open.

Reproduce with `cargo test -p fips-relay --features measurements --test
priced_paths merge_split::crowded::automatic::repeated::repeated_full_rosters_recover_paid_routes_without_candidate_departures
-- --exact --test-threads=1 --nocapture`, using the development dependencies in
[FUNDING-COSTS.md](FUNDING-COSTS.md).

Full-roster transport and LAN discovery now alternate queued-destination
preference with ordinary exploration (2026-09-21). The policy adds one boolean
and reads the existing bounded local endpoint/TUN queue; it adds no wire message
or spending authority. It prioritizes the destination itself, not an inferred
transit neighbor. See the [rotation policy](../../docs/design/fips-configuration.md#optional-neighbor-rotation-nodeneighbor_rotation)
for cursor, retry, admission and discovery-source limits.

A matched native fixture keeps all candidates advertised and queues one original
payload before exposing them. Baseline discovery admits B, C, then destination D;
the preference admits D first. Observed delivery changes from 3,027 to 1,021 ms
and from three admissions to one. Only the production neighbor-selection source
differs in that comparison. These are one-second idle/polling/maintenance fixture
observations, not general latency bounds; observed refresh attempts are counted
separately from admissions. Endpoint and TUN delivery both pass. An unresponsive
D receives alternating D, B, D, C attempts while its original payload remains
queued, and that revision's transferred demand retry preserved the original
deadline and owed ordinary turn. Native caps and incumbent protection remain unchanged.

All ten discovery tests, 89 handshake tests and strict core/relay lint pass.
Broader verification exposed an existing crossed-handshake fixture's packet-order
race: confirmation arriving before Disconnect required maintenance that its
packet-only wait omitted. Those tests now delay genuine incoming confirmation
until authenticated Disconnect, retaining their live stale-reply, epoch, FSP key,
payload and cleanup assertions. This is a fixture correction, not a protocol fix.

The repeated paid full-roster test also passes: both encounters resume delivery
and all-hop credit at 40.749 and 46.421 seconds, within the original 60-second
windows, and all 1,536 test sats are collected. This establishes compatibility,
not faster transit-bridge discovery or physical-router acceptance of this policy.
Run the focused cases with `cargo test -p nvpn-fips-core --all-features --lib
node::tests::sim_discovery::rotation::demand:: -- --test-threads=1 --nocapture`.

LAN discovery checks the current outbound ACL for each advertised carrier before
spending its connection-attempt budget (2026-09-22). Previously, a denied first
candidate could consume the only available attempt on every poll, leaving an
allowed candidate untried. A native loopback UDP regression reproduces that
failure with a full roster and one spare candidate slot. After the fix, the
allowed peer receives exactly one valid Noise request; a repeated event batch
preserves its original pending owner and the established incumbent still delivers
heartbeats. The test feeds the production LAN event-batch handler without starting
mDNS; it does not establish multicast discovery or radio behavior. The default
core test build, strict all-feature/all-target core lint, and all four existing
queued-demand ordering controls pass. Reproduce with `cargo test -p nvpn-fips-core
--all-features --lib denied_lan_candidate_cannot_consume_the_only_discovery_slot
-- --test-threads=1 --nocapture`.

Authenticated direct destinations now wake original queued first contact from
the shared inbound/outbound handshake bootstrap (2026-09-21). The existing route
selector must choose that destination itself; explicit other-carrier bindings
and existing sessions are preserved. The existing session admission, send,
retransmission and timeout paths remain authoritative. No new message type,
queue, timer or spending authority is added. A returned send error can still
leave an installed initiating session owning the queue; its redundant lookup is
then removed. Cancellation before cleanup may retain the bounded lookup, whose
existing final-timeout rule preserves session-owned traffic.

The instrumented baseline observes a direct peer at about 26 ms but does not
start its lookup until about 971 ms. Waking the existing session at authentication
reduces original endpoint delivery from 1,021 to 48 ms, TUN delivery from 1,008
to 51 ms, and the matched measurement case from 1,007 to 50 ms. The original
offers, maintenance/discovery schedules, limits and dependencies are unchanged.
Separate outbound endpoint/TUN regressions authenticate real reciprocal peers
but fail the original 15-second delivery deadline on baseline when further
maintenance is withheld. They pass at about 50 ms after this change, with zero
lookup requests. Incoming-destination variants also deliver once using real
packet/completion processing alone. These are controlled simulation observations,
not general latency bounds or current-router acceptance.

All 14 discovery cases, five focused queue/route/session ownership controls,
89 handshake cases, 10 source-route cases, five session-admission cases, eight
interrupted-handshake cases and 75 active lookup cases pass; the existing ignored
100-node lookup test remains ignored. Strict core/relay linting, formatting and
the source-size check pass. The repeated paid full-roster test preserves all
original channels, resource caps and 60-second encounter deadlines: delivery is
observed at 33.413/33.443 seconds and all-hop credit at 34.330/34.256 seconds.
All 1,536 test sats are collected. Bridge authentication still takes
30.765/29.760 seconds in that run; broad mobile-mesh convergence remains open.

Queued carrier recovery now shares the existing incumbent-demand attribution
with optional discovery preference (2026-09-22): explicit source binding, otherwise
current session carrier, otherwise the destination itself. Shared carriers remain
demanded until their last local queue drains. Historical paths, payment authority,
ordinary exploration turns and interrupted-attempt deadlines are unchanged.

Two recovery prerequisites accompany this preference. Missing reverse application
traffic no longer marks a responsive adjacent FMP link for key replacement:
one-way end-to-end traffic is valid, and direct-session degradation retains its
own recovery rules. Queued established sessions also retain bounded lookup retries
while Bloom reachability converges. An accepted healthy tree-peer filter can wake
an unexpired lookup that has never selected an eligible peer, even with an existing
session. It does not reset retry clocks or repeatedly send on later filters.

The real six-node retained-carrier fixture starts with successful routed delivery,
then authenticates the carrier again after an actual reciprocal departure. The
original baseline misses its 15-second delivery deadline. With the fixes, both
measurement and strict-selection cases deliver the one original in 931 ms, through
one relay admission, with 30 native packets/5,509 bytes after the offer. Original
FSP identities and binding survive. These are controlled observations, not radio
latency guarantees. The separate five-node root-change regressions retain signed
discovery, real retry time, transit anti-spam limits and the two-second TUN queue
lifetime. After reachability arrives, the original endpoint/TUN packet delivers
in 138/132 ms without maintenance or resubmission. Reintroducing the session
exclusion fails both cases. Expired attempts, replayed filters and drained queues
cannot wake requests; later accepted filters cannot reset or duplicate a request.
The direct/reply-learned controls explicitly remove destination cache entries
after genuine convergence because background traffic can legitimately refill them.

The shared demand query keeps a bounded scan instead of a new route cache. A native
release benchmark of 64 ordering keys reports median CPU costs of 0.17 microseconds
with no queues, 43.23 microseconds with 64 carrier misses, 1,011.19 microseconds
with 512 carrier misses, and 0.83 microseconds for 64 direct hits. The previous
direct-destination query measured 0.09/0.61/0.62/0.60 microseconds. These measure
ordering-key evaluation, not a full discovery pass, forwarding cost or router CPU.

Focused validation passes all six coordinate-recovery cases, 75 active lookup
cases (one existing ignored), 17 native discovery cases, and strict core/relay
linting. Run the carrier cases with `cargo test -p nvpn-fips-core --all-features
--lib node::tests::sim_discovery::rotation::carrier_demand:: -- --test-threads=1
--nocapture`; use the same invocation with
`node::tests::session::source_coords_recovery::` for coordinate recovery. The
ignored release benchmark is
`node::neighbor_rotation::benchmark::discovery_key_cpu_by_queued_destination_count`.

An earlier candidate exceeded the paid full-roster local delivery-gap limit
(5,001 ms versus 5,000 ms). Four delayed originals arrived in the normal drain;
credit remained available and all 1,536 test sats were collected. The matched
unchanged baseline passed, as did an instrumented candidate run. The deterministic
filter regression establishes an unnecessary recovery wait but does not reconstruct
the exact cause of that earlier failure. After the wakeup fix, two planned runs
with normal logging pass both crowded reconnects under the original limits.
Their 112/110 offered local packets per direction all arrive once; maximum local
gaps are 2,249/4,315 ms. Paid cross-component delivery resumes in
33.879–43.591 seconds and all-hop credit in 34.594–44.406 seconds, within each
60-second encounter window. Both runs collect all 1,536 test sats.

Asymmetric quiet-FMP refresh now binds an incoming candidate to the current
link, receive index and session generation. Fresh encrypted proof may replace
only that exact owner, in either original connection direction. An existing
outbound owner must already have authenticated its current epoch when the new
request arrives, preserving simultaneous-dial arbitration. A delayed proof
cannot roll back a completed rekey. Disabling periodic rekeys still permits
normal pending-session maintenance and ten-second retirement of old indices.
Real UDP regressions cover quiet and healthy controls in both directions,
obsolete proof after an actual overlapping rekey, and index retirement.

An overlapping rekey could overwrite an already-draining receive epoch without
releasing its index. The existing real-UDP stale-proof regression reproduces
this on the unchanged runtime: the current and newest draining epochs own two
indices while the allocator retains three. Rekey cutover now shares the same
old-versus-retained index reconciliation as full-session replacement, on both
initiator and authenticated responder paths. The regression checks dispatch and
allocation retirement, preserves both retained indices, performs another real
rekey while both peers drain, and delivers payload in both directions afterward.
The final source passes 18 registry tests, 16 rekey-policy tests, 99 handshake
tests (including all five same-path refresh controls), six direct/routed rekey
tests and strict core lint. This fixes a resource leak under connection churn;
it does not prove the larger crowding failure had this cause.

Readiness proves possession of candidate keys, not continued remote admission.
A four-node UDP regression delays a real request until the initiator's original
attempt is nearly expired. The responder can subsequently admit its retained
readiness frame after the initiator has freed that receive index. A fresh dial
must restore reciprocal authenticated keys within two seconds and deliver one
payload in each direction. This passes with periodic rekeys enabled and disabled;
the unchanged baseline fails the disabled-rekey recovery case. Reproduce with
`cargo test -p nvpn-fips-core --all-features --lib
node::tests::handshake::candidates::rotation::rotation_readiness:: --
--test-threads=1 --nocapture`; the asymmetric cases are under
`node::tests::handshake::same_path_refresh::`.

Crowded reconnection timing remains open. Both this candidate and unchanged
master have exceeded the second 60-second paid encounter window. The baseline
snapshots are consistent with the expiry/admission overlap above, but do not
prove the exact cause. Two later diagnostic runs pass both encounters, with
all-hop credit restored in 33.658–39.988 seconds and all 1,536 test sats collected
per run. Those passing controls do not waive the earlier failures. The fixture
now keeps bounded neighbor-transition history from its existing queries and
prints it on failure. Latest code has not received physical-router or mobile-radio
acceptance.

After every settlement and budget assertion, the fixture now drains controller
workers before checking and collecting wallet balances. Periodic proof-history
upkeep can otherwise own the same exclusive wallet while collection reopens it.
The validation run retains its second-encounter 60-second failure, completes all
six settlements, and collects all 1,536 test sats. Strict relay lint, formatting
and source-size checks pass. Crowded recovery timing remains unresolved.

Interrupted outgoing discovery retries now skip a candidate when the current
full roster cannot satisfy minimum age or replacement spacing before its frozen
deadline. The check preserves that deadline, peer limits and discovery fairness;
it does not predict later disconnects or remote progress. Two production-path
regressions independently cover age and spacing, confirm another discovered peer
is selected, and observe no handshake sent to the ineligible retry target. All
98 handshake tests, eight demand-discovery tests and strict core/relay lint pass.
One unchanged paid full-roster compatibility run restores delivery in
34.191/34.787 seconds and all-hop credit in 34.904/35.602 seconds, then collects
all 1,536 test sats. This verifies avoiding a futile local attempt, not faster
bridge recovery or resolution of the earlier 60-second failures.

The `merge_split::brief` variant covers repeated short contacts (2026-09-20).
Independent tasks change the bridge carrier and send single-attempt packets in
both directions; actual contact intervals must remain within half to one-and-a-half
times their scheduled lengths. Short outages preserve the existing authenticated
bridge peers. After full separation and eviction, the fixture cuts a newly observed
bidirectional adjacency immediately, then tries 300-ms, 400-ms and 1.5-s contacts
before leaving the carrier up. No convergence or payment wait extends those contacts.

Before periodic announcement refresh, separate runs deliver either zero or 13 of
32 cold-cohort packets per direction. One takes 52.516 seconds from the recorded
sustained-link observation to fresh payloads and credited payments, including the
remaining cohort, receive window and polling. This exposes variable recovery;
the later isolated bug below is not proven to explain that particular long run.

Follow-up real-UDP regressions isolate a routing repair gap: losing the initial
announcements in both directions, or losing a child's announcement after it adopts
the root, leaves a one-peer node without its neighbor's tree state. Both fail before
the fix despite measured bidirectional RTT and intact authentication. No tree state
is deleted or injected; the tests discard actual bootstrap datagrams, including the
queued duplicate handshake response that could otherwise hide the failure.

Current announcements now refresh every five seconds by default, independently of
the 60-second cost-based parent reevaluation and its two-peer requirement. Refresh
uses the existing per-peer timestamp and rate limit, with no new wire message or
acknowledgment exchange; the redundant no-change rebroadcast is removed. Operators
can tune or disable refresh using
[`node.tree.announce_refresh_interval_secs`](../../docs/design/fips-configuration.md#spanning-tree-nodetree).
The two loss cases synchronize in 5.031 s and 6.029 s in the accepted native run,
retaining their original authenticated links. A healthy control synchronizes in
1.025 s. Disabling refresh produces zero announcements during six stable seconds;
enabling a one-second refresh under a two-second peer rate limit produces three
frames per direction over six seconds, with every recorded send respecting the
two-second minimum. All 14 spanning-tree tests, 128 configuration-related tests,
strict core/relay lint and the source-size gate pass. Run the focused regressions
with `cargo test -p nvpn-fips-core --all-features --lib
node::tests::spanning_tree::bootstrap_loss:: -- --test-threads=1 --nocapture`.
These cases do not establish useful payload service during subsecond encounters.

With refresh enabled, the paid encounter regression delivers 40/64 warm and 13/32
cold packets per direction without duplicates. These counts include sustained
contact and a five-second receive window after the scheduled final submission;
unobserved packets are not proof of permanent loss. Separate fresh probes deliver
all 72 payloads in 72 attempts. Recorded-link-up-to-fresh-delivery-and-all-hop-credit
elapsed times are 12.238 s warm and 8.942 s cold, including remaining cohort traffic,
receive-window time and polling. The timestamp follows the carrier mutation at
millisecond resolution; this is not an isolated routing latency measurement or a
controlled before/after performance comparison.

All four original Watch authorities and eight directional funding/channel/wallet
operation identities survive, with unchanged capital limits and no new funding.
Native state stays within its bounds over 371 observation rounds; final pending
connections and excess links drain. Exact wallet equations hold and all 1,536 test
sats are collected. This historical run established eventual recovery. The later
contact-specific gate below verifies useful delivery within each tested encounter;
physical mobility and radio handover still need acceptance of those newer fixes.

The brief-contact fixture now records bounded passive state observations every
200 ms alongside structured carrier events and per-packet send/receive observations.
Cold-contact queries and traffic share a clock; the warm cohort has its own clock.
Each changed state carries the previous query's start and current query's end as
a conservative transition bracket. These are application observations, not exact
protocol or wire event times; sampling can miss intermediate changes and may itself
affect timing. The contact schedule and its actual-duration guards are unchanged.

In the final measured run, the returning bridge node learns the smaller root
within 0.608–0.807 s of the cold observer's start. Its first measured RTT appears
within 4.605–4.807 s, alongside root adoption; the first cold-cohort payload is
observed at 4.941 s in both directions. Endpoint sessions remain established in
the samples, with unchanged session epochs, Watches and eligible paid agreements.
Eligible agreements do not identify the route actually used. An earlier instrumented
run places first RTT and adoption in the same 4.605–4.807 s interval. This points to
initial link measurement and parent eligibility as the next focused reproduction;
it does not explain every missing packet or establish a controlled performance gain.

The final run retains 40/64 warm and 13/32 cold packets per direction with no
duplicates, passes the existing recovery/authority/accounting assertions and
collects all 1,536 test sats. Its 80 observation rounds have a maximum query-round
duration of 11.443 ms and maximum gap of 201.230 ms. Strict relay lint across all
features/targets and the source-size gate pass. No production timing or payment
policy changes accompanied this instrumentation. The later contact-specific
regressions below address subsecond delivery; hardware acceptance remains open.

A subsequent three-node real-UDP regression isolates one delay in the live RX
loop. With an already measured parent, a newly encountered smaller root is
advertised promptly but becomes measured and adopted only after 1.976 s in the
pre-fix run. Link reports were collected only by the default one-second maintenance
tick, despite their 200-ms cold-start cadence. The regression uses real handshakes
and reports, without seeding RTT or driving synthetic maintenance. Encounters use
two nominal startup-relative offsets; bounded driver wake lateness does not prove
the phase of a maintenance tick, which can be reset after an overrun.

Link reports now wake the RX loop at their existing report deadlines. Successful
send, authenticated receive and receiver-feedback processing update one cached
earliest deadline using only the touched link; the existing collection pass
recomputes that hint. Idle and Minimal-mode links arm no extra timer. Removed or
rekeyed links can leave one early wake, which collection clears. Cadence, backoff,
report formats and the rule excluding unmeasured alternatives remain unchanged.
No payment or session-report scheduling policy changes accompany this fix.

Each report turn retains the two-second send budget and then performs the existing
bounded data-queue drain, including successful batches whose next report is already
overdue. Actual data progress updates maintenance activity; timeout retries retain
their maintenance-period floor. An expired absolute deadline is ready on its first
poll. The queue regression processes 512 queued packets and leaves one for another
turn after ordinary report dispatch; it does not establish slow-carrier throughput
or a payload latency bound.

The final live-UDP run observes adoption after 223/233 ms for sustained contacts
at the two nominal offsets and 221/34 ms for half-second contacts. The independent
cuts occur after 501.987/501.687 ms and discard 18/14 real datagrams. Both cases
retain the original measured neighbor and require a positive RTT before accepting
the new root. All 16 spanning-tree regressions pass, including the existing
unmeasured-neighbor safety check. This establishes local route setup during these
brief contacts, not physical mobility or end-to-end service latency.

The unchanged paid brief-contact scenario passes its authority, recovery and
financial checks, including collection of all 1,536 test sats, but delivery is
mixed. Warm delivery remains 40/64 per direction; cold delivery is 4/32 and 20/32
without duplicates, versus 13/32 each in the earlier baseline. First cold payloads
are observed at 7.883 s and 1.886 s on the common observer clock. The child adopts
the shared root within 0.408–0.608 s, but its neighbor first observes that child's
declaration within 7.604–7.804 s. Sampled endpoint sessions and eligible agreements
remain unchanged. This demonstrates another route-information gap, not its exact
send/loss cause; the existing five-second announcement repair and pending-send
scheduling need a focused bidirectional-readiness regression. No overall paid
recovery speedup is claimed. All 43 handshake, 77 shared-MMP, four link-deadline
and 16 RX-loop tests pass, as do strict core/relay lint and source-size checks.
These changes remain local software work and have not been deployed to routers.

A separate live-UDP regression now reproduces deferred declaration delivery during
a 750-ms contact. The child adopts the new root with a measured link, but its
rate-limited updated declaration remains pending and the parent retains its old
root, parent, sequence and coordinates when the contact ends. The test observes
that deferred state before accepting the reproduction; it does not inject loss
before the independent carrier cut.

Pending tree announcements now wake the receive loop at their existing per-peer
deadline. One cached earliest epoch timestamp is armed when an update is deferred
or a peer removal/restart changes the tree. Dispatch rechecks the rate limit and
recomputes the hint, so a cleared or removed owner cannot keep an idle timer alive.
Periodic five-second repair and 60-second parent reevaluation retain their existing
maintenance schedule. There are no new wire messages or configuration settings.
The added turn keeps the existing two-second send budget and bounded packet drain;
failed or cancelled batches delay fast-path retries by the existing maintenance
interval. Ordinary maintenance retries remain independent of that floor.

The first corrected run observes matching declarations in both directions after
519/520 ms, before actual cuts at 753.867/752.021 ms. It preserves authenticated
link identities and positively observes the deferred update. Its sampled send
timestamps respect the 500-ms interval; exact deadline boundary tests separately
exercise the unchanged rate-limit predicate. This proves bidirectional route
information for these contacts, not payload delivery or physical mobile recovery.

The unchanged paid brief-contact scenario passes its financial, resource and
recovery assertions. Cold delivery is 19/32 in each direction, compared with
4/32 and 20/32 in the preceding run; warm delivery remains 40/64 each way, with
no duplicates. First cold payloads arrive in the 2.339-second observer bracket.
The parent first observes the child's updated root within 2.008–2.207 seconds,
and sampled endpoint sessions, source watches and eligible purchases remain
unchanged. All 1,536 test sats are collected. This single run does not establish
a general delivery-rate improvement, seamless recovery or arbitrary mobility.
All six node-deadline, two peer-deadline, 18 receive-loop, 17 spanning-tree and
43 handshake tests pass, along with strict core/relay lint, formatting and the
source-size gate. The matching routing fix still requires hardware acceptance.

The paid brief-contact gate now distinguishes useful service during contact from
eventual recovery. It records microsecond spans around application submission and
the first observation of each unique received packet. Each finite contact must
carry at least one fresh packet in each direction: the complete submission span
and receive observation must fall after the up mutation completes and before the
cut starts. Pre-contact queued packets and delivery after a later rejoin cannot
satisfy this check. Financial settlement and collection finish before a missing
contact-progress assertion is reported. The same finite workload runs with the
combined tree root in either component; no retries, new purchases or manual
recovery actions are added to obtain contact delivery.

This gate exposed two recovery gaps. A local tree change cleared destination
coordinates while established application routes could still dispatch through
the chosen first hop. A native UDP regression reproduced loss of the original
packet before coordinate repair. Application maps and slow endpoint/TUN sends
now wait for usable current-tree coordinates, retaining session keys, ingress,
control transport and the selected paid carrier. Demand uses existing bounded
queues and signed discovery; no application replay or delivery receipt is added.
Direct carriers and ReplyLearned routing keep their existing behavior. A signed
parent refresh with the same address path preserves cached routes and backoff.

A separate loss regression showed authenticated, measured neighbors missing each
other's initial tree declarations until the five-second periodic refresh. Valid
link feedback now re-arms the existing pending announcement when the remote
declaration is absent. A repeated signed larger-root declaration also receives
the existing rate-limited disagreement response even when its sequence is stale;
the stale routing state remains rejected. Two real-UDP loss cases recover in
900 and 522 ms while preserving authenticated edges and the 500-ms send interval.
The periodic interval and wire messages are unchanged. Synchronized peers do not
trigger this repair; an authenticated peer withholding its declaration can
sustain announcements at the configured bounded rate.

Both paid scenarios still pass after the current-root, pending-send and TUN
ownership fixes: all 24 direction/contact checks deliver fresh traffic before
their respective cuts, including the scheduled 300- and 400-ms returning contacts.
Warm cohorts deliver 40/64 packets each way; returning cohorts deliver 19/32 and
24/32 with root 0, and 24/32 and 19/32 with root 3. No duplicate is observed,
the original eight channels in each scenario retain their funding and authority,
and all 3,072 test sats are collected. The two runs use identical fingerprinted
source/dependency graphs and leave the portable workspace lock unchanged.

One packet offered within root 3's first returning contact remains unobserved;
packets offered while disconnected also remain part of these denominators.
This establishes useful service during each tested contact, not lossless handover.
The returning phase follows a genuine split but observes a newly authenticated
bidirectional adjacency before immediately cutting it and starting the schedule.
The short contacts therefore do not bound first-ever admission. Arbitrary mobility,
saturated neighbor rosters and physical radio handover remain separate acceptance
cases. The original routing correction passed all 160 session and 20 spanning-tree
tests, both paid scenarios, strict core/relay lint, formatting and the source-size
gate; the later ownership checks are recorded in the pending-traffic section.

A held-funding variant now covers a new encounter interrupted after the mint
commits but before its response reaches the opening caller. The original run
delivered 36 fresh payloads on an existing healthy route while its credited
payment remained at 2,000 msat instead of advancing to 6,000 msat. Payment signing
waited behind both the controller wallet mutex and the SDK's complete channel
store snapshot. Signing now keeps its channel/authorization/store locks without
taking the wallet mutex. Wallet-backed final funding and restore waits retain
the wallet owner, release the JSON snapshot, and reload/recheck the exact opening
and closed/refund/retirement fences before completion.

The same encounter exposed a second failure: after disconnect withdrawal, an
unpaused Watch could repeatedly receive the provider's reusable, locally fenced
offer. Full native-route refresh now requests a fresh quote at the next ordinary
five-second deadline, after rechecking current authority. It never removes the
old fence, widens the Watch or creates a new funding intent. The focused real
control-path test checks the request cadence, reload re-detection and unchanged
capital; guard tests exclude paused/retired authority and selector/trial offers.

With both corrections, the six-node regression advances healthy credit from
2,000 to 6,000 msat while the original response is still held and its funding
unresolved. The final credit observation takes 0.358 seconds after the finite
traffic batches. Following the normal mint timeout and bridge rejoin, the
original Watch recovers using the same restored wallet operation and channel.
All three final 12-payload streams complete; the four original authorized
channels settle, and all 1,536 test sats are collected. This is one controlled
simulation, not a hardware handover or latency guarantee. This run covers the
final funding wait. The later renewal-preparation regressions above also cover
the wallet-send wait after a forced keyset change and a metadata outage through
request timeout. Interrupted selector trials still require separate regressions.

That checkpoint passed all 234 relay library tests and all 18 priced-path
scenarios, including a repeat of this held-funding encounter. The payment SDK
passes all 240 workspace tests with every feature enabled. Strict relay and SDK
lint checks pass; these changes have not yet been tested on the physical routers.

Wallet-backed opening now also reserves bounded channel history before keyset
lookup and wallet sends, then releases channel storage during those waits. Final
admission is rechecked under the wallet's existing send lock, so a queued retry
cannot use a slot that failed-send cleanup has released to another caller.
Cancellation retains the exact request and uncertain funding evidence; unrelated
payments keep signing. The SDK passes all 249 workspace tests, strict lint and
formatting. Its nine admission integration tests cover held metadata/send waits,
concurrent retries, token-only capacity competition and retirement fences. The
18 production feature profiles also pass. These SDK checks do not replace the
held-funding FIPS regression or establish hardware acceptance of the earlier waits.
The later companion [pre-opening process regression](FUNDING-COSTS.md) now covers
FIPS recovery of expired requests with either committed wallet preparation sends
or exact unsubmitted plans. Missing or changed wallet evidence remains a separate
boundary.

An additional same-provider promotion regression holds the successful full-offer
acceptance after the provider commits it. The source has already retired its
partly used trial. After an idle application window and peer departure, ordinary
withdrawal and verified refund complete, but the original Watch previously kept
selecting that retired trial: none of 120 fresh packets arrived within 60 seconds
of the recovery observation window, despite restored carrier connectivity.

Selection now reads the exact trial's retained buyer accounting and requests only
its unspent allowance when the old grant is closed or expired and path quality
is unknown. This grants no authority to the old offer; the new agreement still
passes the original Watch, funding and acceptance checks. A watched route saves
only its selected trial's existing contract ID after successful acceptance.
Withdrawal, refund and pause preserve that reference; accepted replacement updates
it, and full or free acceptance clears it. A format flag prevents older readers
from dropping this accounting reference; pre-feature journals without a pointer
do not reconstruct their prior selected trial. The restored selector ignores native
quality until an accepted route binds the carrier. Exhausted or missing trial
accounting excludes that provider before alternative selection, without refilling
the allowance after cooldown.

Retirement preserves the referenced trial. One pointer per bounded Watch can
also defer later expiry-prefix records on the same channel and related reference
groups; existing history limits still apply. Component tests exercise repeated
same-channel replacement and reload, exhausted quota, stale/paused completion,
exact retained-offer identity, native binding and eventual retirement after a
full agreement replaces the trial.

Both promotion variants pass in the complete 20-test priced-path suite. The live
run recovers after 12.61 seconds of observation with 29 of 31 packets delivered;
the controller-and-selector reload run takes 17.13 seconds with 29 of 40 delivered.
Each retains 3,334 consumed trial
units, advances automatic credit to 2,000 msat, and settles exactly two channels
for 3 sats paid and 125 refunded. All 259 test sats per run are collected. The
reload variant keeps the native sessions, wallet and buyer instance alive; it
checks that the retired agreement remains unusable before reconnecting. These
are bounded simulations, not full-process restart, radio handover or latency
guarantees. Verification also includes 247 relay library tests, a repeat of all
28 selector tests after test-only cleanup, strict all-feature/all-target lint,
formatting and source-size checks. Source and dependency fingerprints remain
unchanged during the final complete suite; physical-router acceptance remains
separate.
Run both variants with
`cargo test -p fips-relay --features measurements --test priced_paths
mobility::pending::promotion:: -- --test-threads=1 --nocapture`, using the development overrides in
[FUNDING-COSTS.md](FUNDING-COSTS.md).

This uses the existing SimNetwork, real Noise authentication, native tree/session
routing and production relay controllers. Sim discovery supplies at most 64
rotating direct-neighbor identity hints per poll; the existing node admission
limits still govern connections. It models eventual incoming-link visibility,
including asymmetric reachability, rather than radio beacons or airtime. The
fixture uses a two-peer cap per node and no configured native or control peers.
The focused discovery tests cover cut/rejoin, absent/down endpoints, directed
visibility, bounded rotation, actual authentication and admission at capacity.
All 15 priced-path tests pass after sharing the existing fixture setup. The
stronger per-router settlement assertions also pass in both focused mesh cases;
strict core/relay linting, formatting and the source-size check pass.

The traffic check allows three finite attempts per payload at 0, 7 and 14 seconds
inside a 20-second window. In the focused run, one rejoin needed the second round:
all 12 fresh payloads were observed after 7.45 seconds, with 24 attempts. This is
an observation bound from the start of probing, not exact network convergence or
lossless handover. The earlier test exhausted its three attempts within about
1.4 seconds and then only waited; its failed observation is retained and does not
establish a 20-second production recovery failure. Physical moving meshes,
broader interrupted funding/settlement during encounters and hostile discovery load remain
separate acceptance cases. Run the scenario with `cargo test -p fips-relay
--all-features --test priced_paths merge_split:: -- --test-threads=1 --nocapture`,
using the development dependencies described in [FUNDING-COSTS.md](FUNDING-COSTS.md).

The initial radio profile uses direct 802.11s links with kernel mesh forwarding
disabled; FIPS owns the routed hops and their accounting. Isolate this interface
from the management LAN. Neither a wired uplink nor an Internet gateway is needed
to form the radio mesh. Paid service availability additionally depends on valid
funding and mint reachability where required: test existing funded agreements
separately from first-time funding and settlement during an uplink outage. Do
not claim arbitrary offline channel creation or guaranteed service across a
partition.

## Engineering constraints

One implementation of forwarding/accounting/Cashu logic; thin transport bindings.
Keep relay and Android source modules under the enforced 600-line ceiling and
integration files under 1000 lines. Keep code and tests simple and well organized.
Reuse shared logic, consolidate overlapping coverage, and remove obsolete code
and tests when doing so preserves quality and reliability. Keep verification
focused and reasonably fast; each retained regression should cover a distinct
failure or requirement through production paths. Record failed runs, preserve
private operational evidence, and keep only changes with a measured benefit or
a demonstrated correctness/maintainability purpose.
