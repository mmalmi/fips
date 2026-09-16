# FIPS paid forwarding prototype

Experimental service components for **sender-funded, best-effort forwarding**.
Delivery receipts are an optional future experiment. The relay does not inspect
TCP, UDP or application delivery acknowledgments inside encrypted FIPS traffic.

See [the acceptance report and runbook](PROTOTYPE-RESULTS.md) for the completed
three-router/Pixel demonstration and its limits, [SERVICE.md](SERVICE.md) for
operation, and [TESTBENCH.md](TESTBENCH.md) for isolated funding and collection.
Physical route changes, restart, exhaustion/renewal and customer Wi-Fi have been
exercised. All 12,800 historical test sats were collected. The latest
[performance comparison](PERFORMANCE.md) retained the baseline after rejecting
two tuning experiments without reliable CPU savings.

See [openwrt/README.md](openwrt/README.md) for the persistent APK package,
size-oriented ARM64 build, startup readiness checks and backup procedure.

The broader [v1 readiness work](READINESS.md) is active. [Adaptive cadence](CADENCE.md)
is the first software milestone; permissionless admission, wider transport
acceptance, long-operation recovery and matched performance evidence remain work.
The physical prototype reports below describe the earlier r6 hardware build.

Fresh accounts can explicitly select the [bounded handshake tariff](BOOTSTRAP.md)
to deliver through paid relays to an unfunded recipient without buying a reverse
route. Existing account terms and the physical bench remain unchanged.
Explicit [destination fees](DESTINATION-PRICING.md) can make selected destinations
free without opening payment channels, or charge different local fees. These
software checks cover per-destination agreement and accounting semantics.
An opt-in [bounded return allowance](RETURN-ALLOWANCE.md) lets an unfunded
recipient return encrypted native quality reports and other small replies.
Opt-in [price and quality selection](PRICE-SELECTION.md) now compares adjacent
providers' real quotes by estimated delivered cost, with latency/loss limits,
bounded path trials and cooldown. Real paid diamond simulations exercise
failover, loss, latency, asymmetric feedback, quota exhaustion and controller reload; global optimality, mobility
and broad production readiness remain unclaimed.

## Peer protocol

The automatic path is **quote, accept, then batched cumulative payments**.
For A → B → C → destination, B quotes its fee plus C's onward cost. A pays B;
B pays C using a separate persistent neighbor channel. Quotes specify destination,
price, expiry and usage limits. Many destination agreements can share one channel;
neither packets nor each individual onward hop require a new channel from A.

The current peer API has nine request operations across three services:

| Service | Requests | Purpose |
| --- | --- | --- |
| Quotes | Quote request | Offer or reject bounded destination service |
| Controller | Accept, StopRoute, Seal, Settle | Bind an offer, retire one route, freeze a channel's usage, settle its final balance |
| Payment | Open, Usage, Update, StopForwarding | Manually preapproved setup, cumulative usage/payment and channel-wide admission stop |

Automatic purchases use Accept rather than Payment Open. An active payment cycle
asks for cumulative usage, signs only the claim supported by local evidence and
spending limits, then sends Update and receives durable status. Updates cover many
packets. Confirmed idle channels suppress unnecessary polling. Seal and Settle are
separate so final usage stops changing before the final balance is signed.
StopRoute affects one agreement; channel operations affect all its agreements.

These are bounded application records over existing authenticated TCP/FIPS, not
nine new native FIPS packet types. Existing native MMP supplies quality evidence;
there is no per-packet quote, payment message or new financial delivery receipt.
The manual setup/stop surface overlaps the automatic lifecycle and should be
reviewed before a stable v1 protocol is promised. Consolidation must retain
immutable agreement authority, channel-wide limits and crash-safe finalization.
Private operator commands are separate from this peer API.

### Price cache and request bounds

Complete validated offers are cached locally for at most 30 seconds and never
past their original expiry. The key includes provider, destination, loop ancestry
and requested trial cap. Concurrent reusable requests share one exchange; explicit
fresh purchases/renewals bypass a cached answer. Rejections are retained for only
500 ms. Cached answers never renew expiry, reset quota or create another agreement.
There are at most 128 entries and 16 per provider; idle entries can be evicted,
while a full set of active requests refuses additional work. Each caller's deadline
includes waiting for a shared exchange. Cancellation cannot leave a stuck owner.

Quality monitoring still runs on its existing cadence. Failed active quality or
failed watched acceptance discards the corresponding price cache; financial
recovery intents remain durable. A changed downstream price/path can remain unseen
until refresh; nested caches can delay propagation beyond one local cache window.
The original downstream-bounded offer expiry still limits reuse. Acceptance
validates the offer and actual route. The cache is volatile and adds no wire messages.

Quote handling has an aggregate burst of 16 requests and refill of 10 per second,
shared across callers, plus eight concurrent handlers. Existing TCP/FIPS limits
also bound records to 64 KiB, total connections to 32, connections per peer to four,
queues and per-peer/customer admission. Caller identity churn cannot multiply the
quote service's shared budget. These are workload bounds, not a delivery promise.

Forwarded quote requests and replies use the ordinary negotiated byte accounting,
including ordinary explicit free-route/earned-return rules where configured. There
is no quote-port exception or separate quote fee. Adjacent local service requests
do not cross a forwarding gate. Strictly shaped FIPS handshakes retain bounded
bootstrap admission; that allowance cannot carry encrypted quote application data.

The native quote integration checks 32 cached refreshes with no additional network
requests and eight concurrent misses with one exchange per paid hop. Sequential
requests from 64 identities remain within the quote server's aggregate rate.
Cache tests cover unchanged terms, expiry, rejection backoff, cancellation,
independent deadlines and memory bounds. The controller fixture sends a real remote
TCP/FIPS quote through three paid relays and accounts for request/reply bytes in
all six directional agreements before normal settlement. Its test channel was
sized for the additional traffic; production limits and the exhaustion case retain
their prior settings. Across focused runs, 69 library/quote/transport/controller/
paid-path tests passed, including the 13 impairment/exhaustion deployments.
Strict relay and Android ARM64 linting, default builds, formatting and the
663-file size gate passed. These are software results; devices remain unchanged.

## Implemented and checked

* The core's optional `ForwardingPolicy` gates native FMP transit, including
  batched/deferred sends. A five-node integration test crosses three gated
  routers in both directions, exhausts the middle allowance, accesses its local
  service while blocked, and resumes transit after replenishment.
* The core's optional `OriginatedSessionObserver` records opaque session
  envelopes created locally and their actual local transport outcome, including
  native batches. A claimed source address in transit cannot create this
  evidence. MTU rejection/cancellation remains unconfirmed. Its optional pre-seal
  admission also bounds established source records against known attempt/data
  quotes before native sequence/send metrics. The passive default and legacy
  ciphertext accounting remain available. See [source admission](PRICE-SELECTION.md#bounds-and-recovery).
* `RelayLedger` keeps persistent neighbor channels separate from destination
  quotes. Many quotes share one channel's credit and unpaid exposure. It
  reserves before enqueue and retains uncertain usage. Repeated opens, new
  destinations and route changes cannot reset grace or create credit. Replay
  protection spans retained quotes/channels for the same authenticated buyer
  under the original tariff. The explicit `forwarding_attempt` tariff keeps
  cumulative totals plus bounded unfinished sends; FIPS rejects link replays
  before admission. A fresh authenticated retransmission is another attempt.
  See [ACCOUNTING.md](ACCOUNTING.md) for the precise duplicate and recovery rules.
* `DurableRelay` records bounded allowance windows before admission and records
  submitted totals before exposing a payment claim. Crash recovery consumes the
  whole unrecorded window as unbilled exposure; repeated restarts cannot reset
  credit. Orderly suspension preserves channels and quotes without consuming an
  unused window. Known pending sends remain reserved and unconfirmed.
* Accounting journals use private files, atomic replacement, file/directory
  synchronization and an exclusive owner lock. Corrupt state, failed persistence
  and exhausted windows stop admission. During a checkpoint, forwarding can use
  its previously persisted ceiling; publishing a larger ceiling waits for disk
  synchronization. Node callbacks hold only brief memory locks. Checkpoint
  frequency, window size and packet loss still need live measurement.
* The payment adapter reuses `cashu-service` and checks the authenticated buyer,
  channel, capacity, denomination, expiry and signed balance before credit can
  be published. The trusted controller owns immutable agreement bindings.
* `ControlTransport` reuses TCP/FIPS for bounded authenticated request/reply
  records between configured neighbors. It supports 64 KiB records, bounded
  queues/connections, per-neighbor request admission and cancellation. TCP
  reliability here concerns control records, not paid data delivery.
* `PaymentControl` opens, updates, reports and stops forwarding for explicitly
  preapproved agreements. Wire requests cannot choose their payer, price, grace
  or route. A blocking worker validates signatures and saves accounting while
  the transport continues processing messages. Startup checks retained bindings.
* `BuyerAuthorizer` accepts immutable provider/channel/quote bindings and caps
  cumulative signatures at priced local submissions plus an explicitly approved
  advance (zero in the native test). It persists evidence and the full possible
  obligation before invoking the signer. A lifetime spending cap covers every
  retained channel, including replaced channels and interrupted signing. A stale
  claim can reproduce a prior balance but cannot lower it or reset the budget.
* `PaidForwarder` admits the upstream purchase before recording local evidence
  for an onward purchase. Unapproved transit cannot create a buyer obligation;
  the final direct endpoint needs no onward forwarding channel. Together with
  the source observer, it records both source and relay purchases. It checks that
  the onward purchase is usable before reserving upstream allowance. A packet
  rejected during renewal, before any send was queued, consumes no allowance
  and can be retried after the replacement is accepted.
* `RouteQuotes` asks the native FIPS planner for the next hop, recursively asks
  that neighbor for an offer and adds the local fee. Requests carry the
  destination's public identity so lookup responses can be verified before any
  application traffic starts. Prices share a 1,024-byte quantum, with checked
  addition, local rate ceilings and expiry/byte limits inherited downstream.
  Paths reject repeated routers and stop at eight paid hops. One deadline covers
  the whole request. Pending offers and concurrent work are bounded.
* Retained offers belong to their authenticated buyer and produce deterministic
  contract IDs when bound to a channel. The controller can recheck the actual
  native next hop. Offers alone grant no credit or forwarding. A fixed channel
  grace limit is independent of destination quotes, so quoting another route
  cannot increase a relationship's unpaid allowance.
* `Controller` persists an authorized route request and an idempotent funding
  intent before opening a Cashu channel. It reuses the channel across routes,
  verifies upstream funding before committing onward capital, and obtains
  downstream acceptance before enabling upstream forwarding. Incomplete funding
  locks its full intended capacity against a separate working-capital limit.
* Each controller periodically requests usage and sends cumulative payments
  through `BuyerAuthorizer`. Funding-proof retries use the same durable signing
  gate. Background recovery resumes retained requests without allocating fresh
  funding identities. Graceful controller reload drains outstanding work and
  keeps the existing control transport available for its replacement.
* A separate integration test runs a real local CDK mint and Cashu Spilman
  channels. Each channel pays for two destinations with cumulative updates.
  Three relay ledgers receive gross payments of 3, 2 and 1 test sats.
  After downstream expenses, each relay earns 1 test sat. Channel receiver
  state and durable forwarding accounting are reloaded before closing.
  Buyer refunds are restored and signed using
  the existing recovery API; every final wallet balance is spent and redeemed
  again, and replayed receiver payouts are rejected by the mint.
* `native_settlement` joins those components: actual endpoint datagrams cross
  three native transit routers in both directions. Six one-way neighbor channels
  exchange signed updates over TCP/FIPS. Closing forwarding blocks delivery;
  peer checks reject shortcuts. Each relay retains a positive margin after
  downstream purchases, and all final balances are redeemed and spent again.
  Paths, prices and contract terms come from recursive native quote exchange.
  The test still orchestrates channel funding, acceptance and buyer scheduling.
  Its buyers reject inflated claims even when unused channel capacity exists,
  and every actual payment is authorized against local submission evidence.
* `controller` runs the five-node path with independent per-node controllers.
  Sources purchase both directions concurrently; routers fund and accept all six
  neighbor channels themselves and periodically pay beyond the initial grace.
  Controller reload exercises a lost acceptance reply and a lost outgoing record
  after funding: retained requests recover the exact same channels and balances.
  Seller, buyer and network services remain running during this reload. Each
  router earns a positive margin, and all 640 test sats are redeemed and spent.
* `settle_channel`/`settle_all` automate sealing, final authorized payment, mint
  closure, payout import and refund recovery. Durable pending steps resume after
  interruption. No bearer proofs are sent in settlement responses. Capital is
  released only after local refund recovery confirms completion at the mint.
  The integration test retries payout recovery after spending those payouts;
  spent proofs do not become spendable balance again.
* A fresh purchase after an explicit close can reuse the saved account once its
  refund is confirmed. It atomically records the new offer and retires the old
  route while retaining its channel evidence. It preserves service terms and
  lifetime limits, rejects stale offers and unfinished refunds/renewals, and
  never reopens a closed route solely because background recovery runs. The
  native controller test closes and repurchases all six channels, forwards both
  directions again, and settles both generations without resetting any wallet.
* An explicitly requested fresh route can replace the provider, native path or
  price while retaining unchanged neighbour channels. The controller saves a
  replacement intent, stops old quote admission, verifies upstream funding and
  accepts onward service before activating the new quote. Other upstream quotes
  dependent on the old onward purchase stop and require fresh agreements.
  Old accounting and duplicate evidence remain; a disconnected former provider
  cannot prevent buying the new path, but its funding stays locked. Authenticated
  stop notices retry when it reconnects. Settlement pauses pending replacements.
* The route-change controller test disconnects the middle node through the native
  management API and connects the outer relays directly. Both directions resume
  at a lower price, keep the source channels, and open only two new one-way
  channels. Controller reload recovers a lost reply and outgoing record with the
  same replacement agreements. Reconnecting old neighbours permits all eight
  channels to settle and all 640 test sats to be redeemed and spent again.
* Sources can opt into automatic route refresh for a specific destination with
  an explicit maximum aggregate byte rate. The saved authorization permits
  background path/price replacement under the existing spending and capital
  limits. No source watch arises from transit or unsolicited traffic. Quotes
  reuse unchanged offers, so polling does not exhaust pending-offer history;
  stopped or sealed agreements are excluded from reuse. Pending watched offers
  recover their exact funding intent. Settlement durably pauses source watches.
* The automatic route-change scenario rejects an unaffordable initial rate
  without locking funds, then accepts explicit watch ceilings in both directions.
  Removing the middle router leads to lower-priced replacement agreements without
  another source purchase command. The original source channels remain, only the
  two new neighbour directions need funding, and all 640 test sats are conserved.
  Physical route changes subsequently passed; combined route-change/unfinished-
  renewal recovery remains outside the demonstrated cases.
* If a crash leaves the provider's usage ahead of the buyer's saved submission
  evidence, the controller pays the supported portion of the cumulative claim.
  Later known submissions can continue earning payments; the unsupported
  remainder is never invented as evidence. Closure also signs only supported
  usage, and any unpaid remainder continues consuming the neighbour's retained
  exposure allowance. A native integration test injects this evidence gap,
  forwards both ways, settles and repurchases without resetting accounts.
* Sealing retains pending attempts as unconfirmed and freezes the final claim.
  Older closed channels' unpaid reservations reduce the next channel's available
  allowance. Unknown crash exposure stays unbilled across renewal; it never
  creates another grace period. Expired buyers may reproduce their previously
  authorized balance for closure, but cannot authorize a larger amount.
* Optional `RenewalPolicy` schedules channel replacement from local submission
  evidence, byte limits or approaching expiry. It settles the old channel and
  confirms its refund before funding a replacement. Fresh offers must retain the
  provider, next hop, price, mint and byte allowance; changed service stops for a
  new agreement. Historical channels and authorizations remain retained.
* A second native controller test exhausts and replaces all six original channels
  while sending both ways across the three routers. It keeps the capital cap and
  lifetime spending limit, verifies positive relay margins and redeems/spends all
  1,280 test sats. Controller reload recovers a replacement whose acceptance reply
  was lost without funding another channel. A saved renewal pause also survives
  reload; `resume_renewals` explicitly permits replacement recovery again.
* The Unix `fips-relay` executable assembles those components with explicit
  initialization, saved financial terms, native interface/UDP configuration and
  private local controls. A five-process test recovers the same accounts after
  all nodes stop/restart and after the middle router is killed. Both traffic
  directions continue, all three relays retain positive margins, and all 1,280
  test sats are redeemed/spent. Recovery rebuilds native destination knowledge;
  authenticated peer restarts also reset stale tree/filter announcement state.

Only the local mint's Lightning backend is simulated. These test tokens have no
external backing. `settlement` supplies submission outcomes to test exact
multi-destination prices; `native_settlement` and `controller` use real local
FIPS transport. These are loopback tests, not wireless hardware demonstrations.

## Run local checks

```sh
cargo test -p nvpn-fips-core --lib forwarding
cargo test -p fips-relay --features testbench
./scripts/check-rust-file-lines.sh
```

The settlement test owns temporary wallets/mint state and binds the mint to a
random loopback port. It does not use a user's wallet or contact a public mint.

### Code organization

The existing CI file-length check caps relay source modules at 600 lines and
integration-test files at the workspace's 1,000-line limit. No relay exception
raises either ceiling. Split by responsibility instead of compressing code to
satisfy the check. Public entry points remain in the top-level modules:

- `controller/` separates purchases/payments, upstream acceptance, journal
  validation, runtime supervision, settlement, renewal and route changes.
- `buyer/forwarding.rs` owns local evidence hooks and upstream/onward admission.
- `ledger/` separates admission/completion from snapshot recovery.
- `route_quotes/validation.rs` owns offer validation and contract binding.
- `service/` separates saved configuration, service assembly and private control.

Buyer evidence and seller claims remain independent trust boundaries. Shared
types and pricing helpers do not let a provider manufacture buyer authorization.

## Prototype limits and follow-on work

The [acceptance report](PROTOTYPE-RESULTS.md) records the completed bounded
prototype, including the actual Pixel flow and hardware measurements. Earlier
run reports retain their original scope; use the current report to distinguish
completed checks from follow-on work. Combined route-change/unfinished-renewal
recovery, expired pending offers, broader interrupted-funding exercises and safe
route/channel history retirement remain limitations. Renewal can interrupt
delivery, and maximum throughput and indefinite hotspot service are not claimed.

The controller retains up to 16 funded or unresolved channel intents and 32
requested, outgoing and incoming routes in each category. Retained funding still
counts against capital after service stops until settlement and refund recovery
complete. Settlement and renewal history are capped at 16 channels each.
Same-service channel replacement requires an explicit renewal policy and
remaining lifetime budget; changed routes require a source watch ceiling or a
fresh explicit purchase. `settle_all` pauses watches and renewal before closure;
saved replacement requests stay paused until explicitly resumed. Changed service
during an unfinished renewal and expired pending offers still stop recovery.
No controller loop erases history or resets the
buyer's lifetime spending limit to make another purchase possible.

Retained history is bounded to 16 channels and 32 destination contracts. The
legacy tariff also retains 4,096 distinct packets per contract; the r4 hardware
run reached that cutoff while credit remained available. The explicit
`forwarding_attempt` tariff retires completed packet records into cumulative
totals, keeping at most 1,024 unfinished sends. The journal is capped at 32 MiB.
Safe route/channel retirement and longer continuous physical runs remain needed.
The r5 results establish bounded streams separately from historical r4 evidence.

Datagrams must fit the discovered path after FIPS headers are added. The native
test uses 1,000-byte service payloads on the default 1,280-byte path. A
1,200-byte application datagram exceeded that path once headers were included;
the source dropped it while session control still incurred forwarding usage.
Endpoint `send_datagram` queue acceptance alone is not proof of transmission or
delivery. The gateway/client must enforce path limits or use a segmenting layer.

The disk window limits unknown crash exposure, separately from the channel's
unpaid grace. `lost_msat` never contributes to a claim, but remains reserved
against the same neighbor relationship. A new channel's reservation limit is its
verified payment plus grace, minus outstanding reservations on older channels,
capped by its funded capacity. If repeated failures consume the available allowance,
automatic forwarding stops; a restart is not permission to write off that loss.
This implementation assumes the accounting files survive the process restart.
Never automatically replace missing/corrupt state with a newly initialized ledger.

Buyer journals retain the same bounded evidence history. Pending observations
become unconfirmed on restart; they cannot support a signature. Evidence lost
before a checkpoint was never usable for a signature, and losing it may cause
conservative underpayment/service interruption. A signer error retains the full
reserved authorization because a signature may already have escaped. A journal
write error suspends further signing. Packet observation does not wait for the
disk/signing worker. Established records under the attempt/data tariffs now
reserve existing quote allowance before encryption; a known exhausted, expired
or inactive purchase rejects the local send without inventing wire loss. Legacy
passive observation, manual handshakes and direct transport semantics are retained.
Remote provider admission and signing limits still enforce their separate credit,
capital and spending bounds; the local quote gate does not replace them.

Sat-denominated payments round the cumulative channel amount up by less than one
sat, including approved advances. Capacity and lifetime spending limits include
that rounding. The authorizer assumes a newly accepted funded channel starts at
zero and that its controller uses this authorizer for every signature; importing
a channel previously signed elsewhere needs explicit reconciliation first.

See [the design decision](../../docs/design/fips-paid-forwarding-prototype.md)
for the adjacent-resale model, working-capital requirement and trust assumptions.

The [Android bench customer](../fips-relay-app/README.md) reuses this service
through `CustomerClient`; its platform shell only selects Wi-Fi and presents the
customer actions. It is a foreground test tool with bounded, immutable profiles.
