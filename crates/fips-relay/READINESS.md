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

This is explicit route opening, not automatic free-route refresh or cheapest
path selection. Permissions must be reopened after restart, expiry or path
change. Active paid agreements must close before the same relationship becomes
free. Radio/mixed-transport acceptance and broader concurrent transition/failure
coverage remain work. The existing OpenWrt readiness wrapper still requires a
reachable mint; the no-mint startup evidence is for the service directly.

## Cheapest routes that work

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
handshake allowance excludes established encrypted session reports. Verify and
resolve their return path for an unfunded recipient before relying on them for
paid-route quality selection. Do not mistake handshake success for full feedback
availability. Dedicated monetary delivery receipts remain an optional experiment.

The ETX literature is a reference for loss-aware link metrics, not proof of
optimal monetary routes or malicious-relay resistance:
[De Couto et al., MobiCom 2003](https://pdos.csail.mit.edu/~decouto/my-papers/mobicom03.pdf).

## Boundaries and threats

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
