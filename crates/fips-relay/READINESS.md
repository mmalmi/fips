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

The desired policy is an explicit fee per destination identity, with a default
fee for other destinations. Configured own FIPS addresses can have zero local
relay fee, and other destinations can have different positive fees. Local
delivery within one FIPS instance is already outside transit charging; relaying
to another local instance must also support an intentionally free path without
a funded channel, wallet payment or mint dependency.

Current contracts already bind destination-specific immutable prices, but the
service adds one positive local fee to every quote and requires a funded paid
agreement. The destination policy and channel-free path are not implemented.
Do not model zero as a tiny positive charge or open a pointless zero-payment
channel. Match configured destination identities, never a claimed source,
private IP range, interface name or an assertion of common ownership.

Each router controls only its local fee. A zero local fee cannot waive a paid
downstream hop or silently authorize the router to subsidize it. Preserve the
existing onward-purchase price, capital and lifetime-spend limits, and reject
an unfunded paid continuation. Accepted paid quotes and unresolved liabilities
remain unchanged when future destination rules change.

Acceptance must cover free forwarding between own instances with no mint or
funding, simultaneous paid/free destinations, different positive destination
fees, exact identity matching, route changes to a paid next hop, restart and
policy changes without erasing prior obligations. Free destinations still need
bounded queues/admission; they must not turn into a blanket transit bypass.

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
