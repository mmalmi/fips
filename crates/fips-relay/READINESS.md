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
response. Full-process restart during promotion, other funding interruption
boundaries, arbitrary physical mobility/mesh merge-split, phone outage recovery
and sustained hardware capacity still require verification. This controlled,
same-process recovery does not establish seamless roaming or a performance bound.

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

The optimized loopback comparison covers 250/500/1000/2000-ms policies with two
opposite-order repetitions. All 285,696 packets arrived and all 40,960 test sats
were conserved. Both sampling passes at every boundary show all six paying
channels reconciled, with no pending payment or unmeasured payment/journal activity
between windows. The validator rejects missing evidence, delivery loss, controller
errors and unexpected idle work. Optional diagnostics add no financial authority.

At high rate, 1 s/2 s produced 40 updates versus 59 at 250 ms, but CPU varied
substantially across repeats; the 500-ms default remains unchanged. These are
loopback observations with partial synchronous CPU, logical relay journal and
application-record attribution. Full carrier cost,
sustained capacity and impaired hardware measurements remain open. See
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
all 384 test sats, and all 265 relay library checks pass. Unsubmitted sends,
shared-owner cleanup, physical power-loss recovery and bounded CDK database growth
remain open; [funding costs](FUNDING-COSTS.md) describes the exact retained cases. Legacy
profile migration is outside this milestone; dependency distribution remains a
separate requirement.

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
power-loss and used/shared-channel unilateral refunds remain unverified.

An intent with no recovered channel must retain its full reservation:
the SDK's empty lookup result also covers incomplete wallet operations, so it
does not prove that no money was spent. Used/shared-channel unilateral recovery
also remains outside the verified zero-use path.
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
final funding wait; earlier wallet-send/keyset waits and interrupted selector
trials require separate regressions.

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
FIPS recovery of an expired request with a committed wallet preparation send;
missing or unsubmitted wallet evidence remains a separate boundary.

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
integration files under 1000 lines. Use focused production-path tests. Record
failed runs, preserve private operational evidence, and keep only changes with a
measured benefit or a demonstrated correctness/maintainability purpose.
