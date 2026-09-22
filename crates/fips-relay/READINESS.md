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

One no-default-feature seed-only service run nevertheless timed out in paid
delivery. Its original failure lacked a phase snapshot. Bounded failure-only
diagnostics now retain the purchase/renewal/restart phase, safe payment state,
native routes/sessions and daemon-log tails without changing the original retries
or deadlines. Four isolated diagnostic runs and a full sequence on the fixed code,
plus two full sequences before the lifecycle fix, passed. These passing reruns do
not resolve the earlier timeout or establish whether it relates to this change.
Intermittent paid delivery therefore remains an open readiness item.

These results establish bounded link behavior. They do not establish radio
mobility, congestion fairness, throughput, remote TLS proxy deployment or
support for every core adapter.

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

The combined paid run passes all 24 direction/contact checks across both root
placements, including each first 400-ms cold contact. Warm cohorts deliver 40/64
packets each way; cold cohorts deliver 19/32 and 24/32 with root 0, and 24/32 and
19/32 with root 3. No duplicate is observed, original funding/channel identities
and spending authority remain intact, and all 3,072 test sats are collected.
Packets offered while disconnected remain part of these denominators. These
bounded software cases establish useful service during the tested contacts, not
arbitrary mobility, a general latency bound, or hardware acceptance of this fix.
The final source passes all 160 session and 20 spanning-tree tests, both paid
brief-contact scenarios, strict core/relay lint, formatting and the source-size
gate. The dependency overrides and tested lock are fingerprinted for each gate;
the portable workspace lock remains unchanged.

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
