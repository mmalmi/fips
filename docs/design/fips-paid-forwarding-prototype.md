# Sender-funded forwarding prototype

Status: local native forwarding/control/mint integration, autonomous route buying
and same-service renewal demonstrated; wireless router demonstration remains in progress.

## Payer rule

Sending and receiving are separate decisions. A recipient never incurs debt by
receiving unsolicited traffic. The endpoint originating a direction buys its
delivery. A download provider or Internet exit can recover that expense through
an application agreement with its customer. That agreement is outside routing.

For the prototype, the authenticated neighbor submitting a transit packet buys
onward forwarding from this router. A relay is both seller to its previous hop
and buyer from its next hop. It quotes its own forwarding charge plus the cost
of onward service. These are separate gross payments, not automatically netted
mutual debts. This is a choice for the experiment, not a protocol requirement.

## Model comparison

| Model | Advantage | Cost / limitation |
| --- | --- | --- |
| Adjacent buyer/seller accounts with onward resale | Fits authenticated FMP neighbors and route changes; reuses existing single-seller Cashu channels | Relays need working capital; quotes must include downstream cost; upstream default can leave a bounded downstream expense |
| Original sender pays every relay directly | No relay working capital or downstream price resale | Sender must discover/authenticate every paid participant and refresh funding when the route changes; channel count grows with route diversity |
| Destination receipt releases all payments | Aligns payment with destination delivery | Receipt alone proves neither which relays participated nor that each can redeem; requires additional settlement machinery and deals poorly with a withholding receiver |
| Adjacent resale with end-to-end delivery feedback | Local automatic payments and bounded risk, plus a way to stop buying a bad path | Delivery feedback detects poor service; it is not cryptographic fair exchange |

Choose adjacent resale with optional endpoint delivery feedback for the first
native-routing prototype. It matches the authenticated forwarding boundary and avoids
inventing a multi-party conditional Cashu protocol. Keep the admission interface
payment-neutral so direct sender funding remains possible later.

Delivery receipts are not a protocol prerequisite. FIPS cannot assume the opaque
payload is TCP or inspect its acknowledgments. Endpoints may use TCP, application
receipts, probes or another mechanism to assess service; the routing payment
contract buys forwarding attempts. Payment/accounting acknowledgments are a
separate concern. A dishonest forwarder can lie about submission: small windows
bound exposure but do not prove forwarding or provide cryptographic fair exchange.

## Accounting contract

Neighbors maintain persistent one-way Spilman channels, normally one active
channel for each buyer/seller direction and accepted mint. They reuse a channel
across many destination quotes and traffic flows. Reverse traffic can open the
opposite-direction channel when needed. Persist funding and cumulative signed
balances; settle/renew near capacity or expiry. Persistent does not mean an
unbounded lifetime or an unlimited balance.

Open channels on demand for an authorized purchase. Discovering a neighbour
alone is not permission to lock funds. Brief disconnects retain the account;
expiry and settlement deadlines still apply. Keep individual channel limits and
a total working-capital limit. A relay must redeem incoming signed balances at
the mint before spending those funds on onward service, so capacity exhaustion,
approaching expiry and liquidity needs motivate settlement and replacement.
Opposite-direction channels remain separate funded obligations; do not silently
net their balances. Payment signatures authorize value and do not prove delivery.

Quotes authorize forwarding and set prices; channels hold aggregate payment and
exposure. A quote change cannot reset channel usage or grant another grace
window. Retain duplicate-packet evidence across quote changes and channel
rollover. Route prices accumulate in millisats, then round cumulative channel
payments to the mint's unit; do not round each payment update to an additional
whole sat. Closed unpaid exposure carries forward for the same neighbor and mint.
The new channel can reserve at most its verified payment plus grace minus the
sum of older channels' positive unpaid reservations, capped by its funded value.
This permits renewal with a partly consumed allowance while refusing a fresh
free allowance. If no allowance remains, opening stops for reconciliation.

* Each direction requires an explicit, capped buyer agreement. The claimed FSP
  source is not evidence of who owes money; only the authenticated submitting
  neighbor and its accepted agreement authorize a debit.
* A quote names the destination, next provider, price, expiry, byte allowance and
  route epoch. A new provider or price needs a new accepted quote. No silent
  repricing. Quote propagation has a hop limit and rejects repeated routers.
* Meter unique session-envelope bytes submitted to the selected outgoing local
  transport. Exclude mutable FMP TTL/MTU, link headers and Wi-Fi retries. A local
  successful send is **not** confirmed neighbor or destination delivery. Present
  submitted, destination-received, claimed, signed and redeemed amounts as
  distinct evidence. Do not advertise delivery-contingent payment.
* Fingerprint immutable source, destination and encrypted session envelope.
  Within the retained buyer history, a retry or replay must not create a second
  upstream charge. Bound retained history and fail closed at its limit. A newly
  encrypted application retransmission is a new network packet; logical TCP
  retransmission accounting belongs to the application selling that service.
* Admission reserves allowance before asynchronous send; successful local
  completion reports submission. Errors and cancellation are unconfirmed,
  not proof of non-delivery. Recovery must retain uncertain reservations or
  close their epoch, never silently replenish them.
* Reuse Cashu Spilman funding and cumulative signed updates in small windows.
  Verify and durably store payment updates outside the forwarding loop. A
  local counter, receipt or signature that the mint cannot redeem is not
  payment. Demonstrations must close channels and check redeemed test proofs.
* Use capped unpaid grace and capped buyer advances. Stop at either spending or
  exposure limit. A buyer refusing the next update cannot create unlimited
  provider loss; a lying provider cannot claim more than the buyer signed.
  A relay's downstream commitments require a separate local liquidity budget.
* Channels are relationship-local. Incoming unpaid claims cannot be spent as
  Cashu. Incoming and outgoing redeemable claims cannot simply be netted away.
* Restart invalidates active forwarding epochs until durable payment/usage state
  is reconciled. Replayed opens and balance updates are idempotent. A changed
  route must not reuse a spent allowance. Expiry and failed redemption suspend
  service rather than manufacture a new balance.

The implemented durable wrapper persists a per-channel absolute allowance
ceiling before exposing a window to the node. Payment claims come only from a
completed durable checkpoint. After a crash, the difference between that ceiling
and the last recorded reservations becomes unbilled, reserved `lost_msat`.
Recorded packet fingerprints remain authoritative for replay protection. A
packet lost from memory before a checkpoint was never included in a claim; its
unknown attempt cannot justify a new debit to the buyer. Loss consumes the same
bounded channel allowance, so repeated restarts eventually stop service.
Orderly suspension records a zero-sized next window and can resume the same
channels/quotes without consuming unused exposure. Controllers must not erase
missing/corrupt accounting state and silently open a fresh account.

The seller wrapper keeps the previously durable allowance usable while saving a
checkpoint. A separate writer lock serializes disk work; node callbacks briefly
lock memory and never wait for disk I/O. A new journal covers at least the old
ceiling, including submissions racing its snapshot, before a larger allowance is
published. Persistence failure suspends admission. Window size, checkpoint
scheduling and retained history still need deployment measurements.

The buyer separately records unique local transport submissions to the accepted
provider. `BuyerAuthorizer` prices that evidence using immutable accepted quotes;
an untrusted provider report cannot authorize more than the evidence plus an
explicitly bounded advance. Neither locally submitted bytes nor a valid channel
signature proves that the provider forwarded them. Cumulative payments round up
by less than one sat per channel; capacity and lifetime spending caps include it.

Before calling the signer, the buyer persists the evidence and maximum possible
signed obligation. Signing failure cannot release that reservation: a signature
may already exist. The lifetime cap spans all retained channels and cannot reset
on rollover. A stale claim only reproduces an existing balance. After restart,
recorded pending sends remain unconfirmed; lost uncheckpointed evidence cannot
support a signature and may conservatively interrupt service. Missing/corrupt
files never mean fresh authorization. Accepted channels must start at zero and
all signatures must go through this authorizer; existing externally signed
channels require separate reconciliation before adoption.

## Placement

Add an optional admission interface at native FMP SessionDatagram forwarding.
It sees authenticated ingress, selected next hop, claimed addresses and opaque
session bytes; it reserves before enqueue and reports local transport outcomes.
Scalar, batched and deferred sends must use the same hook. No Cashu dependency
or wire-format change belongs in the core. Source-side buying, quote exchange,
payment verification, durable usage and automatic downstream buying belong in
an optional service using authenticated FSP control messages between neighbors.

The optional `OriginatedSessionObserver` supplies the local sender's evidence
after FSP sealing and before FMP link encryption. Internal packet-creation
provenance excludes transit even when a packet claims the router's own source
address. It reports local submission or uncertainty and does not gate sending.
`PaidForwarder` combines upstream admission with onward buyer observation;
unapproved inbound data cannot create a downstream purchase obligation. Only a
direct final endpoint needs no onward forwarding agreement.

Direct local control services remain accessible without transit credit. Rate
limit discovery, onboarding and payment traffic. This is not permission for
ordinary IP forwarding, free arbitrary FMP transit, or unbounded free probes.
Internet-exit authorization is a separate application contract.

The current control prototype uses the existing TCP/FIPS adapter for bounded
request/reply records. The server accepts only configured neighbors and
immutable channel/quote bindings approved by the local controller. It validates
Cashu and persists accounting outside the native packet loop. Record size, connection count, queue
depth and request admission are capped. These control-stream acknowledgments
are not receipts for paid data. The automatic controller now funds and accepts
channels, schedules payment updates and completes requested mint settlements.
An optional policy also schedules same-service channel renewal.

`RouteQuotes` now follows `FipsEndpoint::resolve_next_hop`: the source uses the
native origin planner, and each provider uses the same planner as native transit
for that destination and ingress neighbor. An unresolved route starts bounded
FIPS discovery using the destination's public identity, with no queued paid
application packet. Explicit route queries retain the normal startup retry
ladder while bloom reachability converges; they do not turn that interval into
an immediate offline-destination backoff.

Providers recursively request a next-hop offer and add their own positive fee.
The prototype uses one accepted mint and a common 1,024-byte price quantum,
checked addition, local price ceilings, and downstream expiry/byte minima.
Requests retain their original deadline and reject repeated routers or more than
eight paid hops. Offered paths describe the proposed route, not proof of transit.
The receiver key comes from the authenticated neighbor's offer.

Pending offers are bounded to 128 total and 16 per buyer, with eight concurrent
handler jobs and a maximum 30-second request deadline. Pending offers may expire
or disappear on restart; they have created no financial obligation. Accepted
bindings must be persisted separately in the existing durable journals. Binding
an offer to a channel is idempotent, preserves channel terms and grants no
credit. The acceptance controller must recheck the retained offer's native next
hop, verify funding, arrange onward service and persist the accepted bindings
before enabling forwarding. If the route changes later, the existing forwarding
policy rejects the unapproved next hop until a new agreement is accepted.

A local integration test now sends application data through three paid native
relays in both directions, exchanges six channels' signed updates over FIPS,
blocks delivery after forwarding closes, excludes direct peer shortcuts, and
redeems/spends every final wallet balance at a real local test mint. It uses
local source/relay evidence to authorize every signature and rejects inflated
provider claims despite spare capacity. The paths, prices and contracts now come
from recursive quote exchange; the fixture still orchestrates channel funding,
acceptance and buyer scheduling. It is not the wireless or phone
acceptance test. Service payloads must fit the discovered path after headers;
queued sends can later fail MTU checks while session-control packets still travel.

The automatic `Controller` adds a private durable journal for authorized offers,
funding identities, outgoing contracts and incoming acceptance phases. Funding
intent is saved before wallet work and keeps a stable Cashu request ID across
retries. Every unresolved operation consumes its full intended capital budget.
One provider channel is reused across destinations, while the buyer's separate
lifetime signing limit continues to bound actual obligations. An upstream
opening must verify before the relay commits its own capital downstream, and
onward acceptance precedes activation of upstream data admission.

Usage and signed updates run periodically over the authenticated neighbor control
service. Signatures, including funding-proof reproduction, pass through the
buyer's durable evidence/authorization gate. A failed channel update does not
skip attempts to pay independent channels. Incomplete requests resume from the
journal; conflicting or expired routes remain stopped for explicit replacement.
Graceful controller reload drains in-flight work. Abrupt cancellation retains
wallet ownership until any already-running blocking wallet operation finishes.

The `controller` integration test gives each of five native endpoints its own
controller and test wallet. Concurrent purchases automatically create six
neighbor channels, then scheduled updates sustain both traffic directions past
the initial unpaid allowance. Controller reload models a lost acceptance reply
and an interruption after funding but before storing the outgoing contract. Both
resume with identical channels and no extra locked funds. This exercises
controller recovery while the network, seller and buyer services remain alive;
it is not yet a whole-process crash/restart test. Each relay has a positive net
margin and all final balances are redeemed and spent again at the local mint.

Settlement now has durable buyer and seller stages. An authenticated buyer first
requests sealing: stop that channel, classify any still-pending local sends as
unconfirmed, retain their reservations and freeze the final claim. The buyer
stops recording new purchase evidence and signs only within its established
evidence and budget bounds. If evidence, budget or service expiry prevents an
increase, it may resend its already-authorized balance. A failed journal or
signer never bypasses the authorization gate. Any unpaid remainder stays in the
relationship's carried exposure; closure does not erase it.

The seller fixes the final signed balance before closing at the mint and imports
its payout idempotently. Control replies contain paid/refunded/fee totals, never
bearer proofs. The buyer restores and verifies its refund through the mint before
releasing locked capital. Both sides retain their intents and completed reports;
background recovery resumes incomplete work. The native controller test now
uses these APIs for all six closures and refunds. It then spends all payouts and
retries seller recovery with lost completion reports, verifying that no spent
proof is restored as spendable balance. Rejected state transitions preserve the
last committed controller journal rather than retaining a partial mutation.

Optional renewal policy now triggers from the buyer's local submitted value,
observed byte allowance or approaching channel/contract expiry. Untrusted seller
usage cannot itself trigger a new funded channel. Renewal saves its intent,
settles and confirms the old refund, obtains fresh offers for every destination
sharing that channel, retires those old outgoing agreements and purchases their
replacements. Historical funding, replay evidence and signed obligations remain
retained. Released capital can be reused; the lifetime spending cap cannot reset.

Automatic replacements must retain the provider, next hop, price and mint, with
at least the old byte allowance. Changed service stops for a new agreement so
onward costs cannot silently exceed an upstream accepted price. The replacement
intent and funded channel survive a lost acceptance reply. Pausing renewal is
durable and also pauses saved replacement requests; `settle_all` pauses it before
closing channels. Explicit resumption permits those retained requests again.

The native exhaustion test replaces all six original channels, checks the same
capital cap and retained lifetime budget throughout, preserves positive relay
margins and redeems/spends all 1,280 test sats. Controller reload also recovers an
interrupted replacement without another funding identity. Traffic retries during
renewal are endpoint test behavior, not new protocol delivery receipts. A relay
checks onward availability before reserving upstream allowance, so a packet
rejected before enqueue remains eligible after renewal. Actual uncertain sends
still consume exposure.

The Unix service now runs each node as an independent process. Its integration
test retains the same accounts across an orderly restart of all five nodes and
an abrupt middle-router restart, resumes bidirectional paid traffic, checks a
positive net margin at all three routers and redeems/spends all 1,280 test sats.
Local administrative controls are private Unix-socket requests; they are not a
public customer onboarding API. Initialization is explicit, saved financial terms
cannot change on ordinary startup, and data admission waits for all components
to validate. No TUN, DHCP, DNS or ordinary Internet gateway is installed.

Restart recovery primes native destination discovery from retained agreements.
A completed native handshake proving a changed neighbor startup epoch also
resets that neighbor's old tree/filter announcement state; otherwise new low
sequence numbers can be rejected indefinitely. Unaccepted restart hints cannot
reset routing state. A connected link alone does not prove end-to-end readiness,
so the process test uses bounded endpoint retries and checks actual delivery.

Route-change propagation, recovery from expired in-flight replacement offers,
interruptions at every funding/acceptance stage and retirement of bounded history
remain to be implemented.
Settled records cannot silently reactivate an old channel; recovery of an orphaned
funding operation still precedes closure. Renewal intentionally permits a service
gap while settlement and new funding complete; uninterrupted service is not yet
demonstrated.

## Hardware proof still required

Use Linux AF_PACKET on ordinary OpenWrt Wi-Fi interfaces. Capability-check mesh
support; keep lower-layer mesh forwarding disabled so native FIPS accounts for
each wireless hop. AP/STA links are another portable topology where mesh mode
is unavailable. No monitor injection or chipset-specific frame handling.

Management Ethernet stays available, but bind test links exclusively to the
wireless interfaces and verify actual peer MACs, packet captures and counters.
Demonstrate three independently paid transit routers between test endpoints,
both directions, exhaustion/renewal, replay and unsolicited traffic, route
changes, restart recovery and actual local-mint redemption. Then demonstrate an
unrooted phone joining customer Wi-Fi and buying FIPS forwarding independently
of ordinary Internet access. Measure throughput, latency, CPU, memory and
installed size; publish no performance claim before measurement.

Keep test balances, mint keys, device addresses and private deployment state out
of this repository. Preserve management access and recoverable device configs.
Use isolated user-owned test services on the endpoint host; existing services
must not depend on this prototype.

## TollGate boundary

After the prototype works, evaluate a reusable adjacent-provider quote/usage/
settlement adapter and accounting semantics. Existing hotspot Internet quotas
are not automatically native multi-hop FIPS admission. Prepare a local proposal
with demonstrated behavior and limitations; upstream contact or publication is
a separate decision.
