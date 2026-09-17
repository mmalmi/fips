# Paid-relay v1 readiness work

This extends the completed bounded prototype. Production readiness is not yet
claimed. The target is sender-funded FIPS forwarding across supported transports,
with permissionless discovery and bounded financial/resource risk. Publication,
real-money operation and public deployment are separate authorization decisions.

## Sequence and acceptance

1. **Adaptive payment cadence.** Share one schedule per neighbor channel and
   paying direction. Trigger on priced usage and maximum outstanding age; recover
   unacknowledged balances and suppress confirmed-idle polling. Separate local
   durable allowance checkpoints from payment exchanges and channel renewal.
   Preserve existing agreements, signed balances and lifetime budgets. Measure
   250/500/1000/2000-ms maximum ages under idle, burst and sustained workloads.
2. **Transport and admission coverage.** Audit every production FIPS transit
   entry/exit, batching and failure path. Exercise mixed supported transports
   through the real forwarding gate. The present service enables UDP and native
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
   integration checks, measured CPU/storage/wire overhead, migration/recovery
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
remaining receiver/CDK history retirement remain release blockers. Devices
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
records. The later seller workflow below extends this milestone. Receiver SDK and
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
bound retains further channel evidence. Receiver SDK/CDK database cleanup,
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
receiver/CDK cleanup remains unfinished.

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
orphan channel, or renew expired route authorization. Funding lost before the
wallet committed its channel, automatic expiry refunds, and bounded financial
history retirement remain work.

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
The current relay service disables native discovery/auto-connect and authorizes
outgoing purchases through configured neighbors. Its public customer control
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
