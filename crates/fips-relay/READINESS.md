# Paid-relay v1 readiness work

This extends the completed bounded prototype. Production readiness is not yet
claimed. The target is sender-funded FIPS forwarding across supported transports,
with permissionless discovery and bounded financial/resource risk. Publication,
real-money operation and public deployment are separate authorization decisions.

Acceptance targets fresh wallet/controller profiles. Migrating legacy profiles
is outside this greenfield scope; historical migration notes below do not add a
requirement to the current milestone. Existing accounts remain untouched.

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
peers share eight active exchanges, with at most four per identity across ports
and directions. The node-wide bucket allows a burst of 80 requests and refills
at 320 requests/second; existing per-peer directional and quote-service limits
remain 16 requests with 10/second refill. The identity table holds at most 64
entries and reclaims only idle, fully refilled entries. Reconnection cannot
reset a retained bucket. Core peer, link, handshake and session limits also apply.

An advertised identity or a routed session does not establish adjacency.
Membership is checked again before an unsent request connects and before an
incoming record reaches its handler. Disconnection does not cancel dispatched
financial work, release channel capital or reset lifetime spending. Explicit
source purchases and verified onward funding keep their existing authority.
UDP customers in the configured customer network remain inbound-only unless
explicitly listed as neighbors.

The aggregate rate accommodates the request count of 16 neighbors paying in
both directions at 250-ms intervals, with bounded additional control traffic.
This is a capacity calculation, not a latency or hardware throughput guarantee.
Multiple hostile identities can still compete for the shared slots and budget;
the limits bound their resource use without promising Sybil-resistant fairness.
Mobile Wi-Fi merge/split and router/Pixel acceptance remain separate checks from
authenticated-link control admission and the Ethernet fixture below.

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

An isolated three-router ARM64 Linux fixture passes all 16 phases using only
native Ethernet beacons and empty neighbor rosters. Discovery leaves wallets and
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
containers, links and network are cleaned up. The corrected fixture takes about
140 seconds; 59 Python checks cover ownership, fault evidence, active credit and
settlement validation. No payment wire messages or relay implementation changed.
This checks bounded Ethernet faults and one partition/rejoin, not radio mobility,
physical power loss or an intentionally interrupted payment reply. The additional
payment checks below cover two distinct interruption boundaries.
See the [reproducible harness](../../testing/chaos/README.md#paid-ethernet-acceptance)
for its configuration and runtime requirements.

With `measurements` enabled, the five-node controller test discards a successful
Update reply only after the real payment handler has persisted the received
balance and seller credit. Another neighbor keeps paying while the reply is held.
After it is discarded, the first recovery request must be Usage; the automatic
scheduler acknowledges the saved balance without repeating that cumulative
Update, then pays for further traffic. Funding identities and the original
64-sat lifetime limits remain unchanged. The ordinary feature mode instead pauses
a request before handling. Both scenarios pass their held-settlement phase and
complete test-fund collection. Recovery itself uses no manual payment flush or
settlement; this is a lost-response test, not a process-crash test.

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
`transports` schema and accepts UDP, native TCP and Ethernet. Other core adapters
are explicitly rejected until their paid-service acceptance is supplied. The
service checks the exact configured type/name set against operational adapters
before starting payment workers. A failed TCP listener beside a healthy UDP
socket stops startup, releases the sibling socket and preserves financial state.
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

These results establish bounded configured-link behavior. They do not establish
radio mobility, congestion fairness, throughput or support for every core adapter.

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
pricing document for the current acceptance evidence. Outgoing-link price
selectors, a rate-limited free tier and paid traffic priority remain unfinished.
Paid priority must derive from a valid local agreement.

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
routes on both SAE-protected and open radio meshes. Interrupted purchase
acceptance on hardware, arbitrary physical mobility/mesh merge-split, phone
outage recovery and current hardware performance measurements still require
verification.

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

### Physical phone customer across the wireless mesh

The current isolated Pixel app also completes a paid session through all three
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

The current optimized comparison covers 250/500/1000/2000-ms policies with two
opposite-order repetitions. All 285,696 packets arrived and all 40,960 test sats
were conserved. Both sampling passes at every boundary show all six paying
channels reconciled, with no pending payment or unmeasured payment/journal activity
between windows. The validator rejects missing evidence, delivery loss, controller
errors and unexpected idle work. Optional diagnostics add no financial authority.

At high rate, 1 s/2 s produced 40 updates versus 59 at 250 ms, but CPU varied
substantially across repeats; the 500-ms default remains unchanged. These are
loopback observations with partial synchronous CPU, logical relay journal and
application-record attribution. SDK/receiver storage writes, full carrier cost,
impaired links and current hardware measurements remain open. See
[the results and boundaries](CADENCE-RESULTS.md).

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
capital/lifetime limits. Read-only recovery includes the original cost even after
quote expiry or pause. Replayed refunds require the SDK's durable total; importing
zero new coins is no longer treated as evidence of a zero original refund.

The nonzero-fee service fixture also exposed unused fee reserves returning above
nominal capacity. Settlement now validates the value after the funding swap;
actual debit minus the wallet-verified refund determines lifetime spending.
See [funding costs](FUNDING-COSTS.md) for limits, status fields, verification and
the required unreleased dependencies. Controller version-1 reconciliation and
remaining CDK history retirement and legacy receiver reconciliation remain release blockers. Devices
are unchanged.

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
activity/proof history remains retained, and complete legacy migration, hostile
admission, device acceptance and dependency distribution remain unfinished.
See [eligibility and recovery](HISTORY.md).

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

Recovery now looks up wallet-committed channels before applying route expiry and
pause checks. Opening and recovery share the same immutable wallet request. The
existing Cashu SDK recovery operation performs no mint requests and cannot open
another channel. A successful lookup saves the original funding identity without
accepting a quote, activating forwarding or releasing reserved capital. Missing
and conflicting records retain their reservations. No new message, journal field
or dependency is added.

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

This covers the wallet-committed/controller-unrecorded boundary. It does not
establish recovery after every mint-response or power-loss boundary, refund an
orphan channel, or renew expired route authorization. The later bounded expiry
recovery below covers fully identified, never-used withdrawn funding. Funding lost
before the wallet committed its channel remains unresolved. Completed channel
retirement cannot remove unresolved work.

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
power-loss and used/shared-channel unilateral refunds remain unverified.

An intent with no recovered channel must retain its full reservation:
the SDK's empty lookup result also covers incomplete wallet operations, so it
does not prove that no money was spent. Used/shared-channel unilateral recovery
also remains outside the verified zero-use path.
These retained records can exhaust bounded slots, and an early unresolved funding
sequence can block retirement of later completed channels. Safe retention alone
does not establish indefinitely reusable accounts.

Run `cargo test -p fips-relay --lib controller::funding::tests` and
`cargo test -p fips-relay --test controller`.

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
coverage remain work. The existing OpenWrt readiness wrapper still requires a
reachable mint; the no-mint startup evidence is for the service directly.

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
integration files under 1000 lines. Use focused production-path tests. Record
failed runs, preserve private operational evidence, and keep only changes with a
measured benefit or a demonstrated correctness/maintainability purpose.
