# FIPS paid forwarding prototype

Experimental service components for **sender-funded, best-effort forwarding**.
Delivery receipts are an optional future experiment. The relay does not inspect
TCP, UDP or application delivery acknowledgments inside encrypted FIPS traffic.

## Implemented and checked

* The core's optional `ForwardingPolicy` gates native FMP transit, including
  batched/deferred sends. A five-node integration test crosses three gated
  routers in both directions, exhausts the middle allowance, accesses its local
  service while blocked, and resumes transit after replenishment.
* The core's optional `OriginatedSessionObserver` records opaque session
  envelopes created locally and their actual local transport outcome, including
  native batches. A claimed source address in transit cannot create this
  evidence. MTU rejection/cancellation remains unconfirmed. This read-only hook
  lets a buyer bound payment authorization without introducing delivery receipts.
* `RelayLedger` keeps persistent neighbor channels separate from destination
  quotes. Many quotes share one channel's credit and unpaid exposure. It
  reserves before enqueue and retains uncertain usage. Repeated opens, new
  destinations and route changes cannot reset grace or create credit. Replay
  protection spans retained quotes/channels for the same authenticated buyer.
* `DurableRelay` records bounded allowance windows before admission and records
  submitted totals before exposing a payment claim. Crash recovery consumes the
  whole unrecorded window as unbilled exposure; repeated restarts cannot reset
  credit. Orderly suspension preserves channels and quotes without consuming an
  unused window. Known pending sends remain reserved and unconfirmed.
* Accounting journals use private files, atomic replacement, file/directory
  synchronization and an exclusive owner lock. Corrupt state, failed persistence
  and exhausted windows stop admission. This first implementation briefly drops
  new transit packets during checkpoints instead of waiting for disk on the node
  loop. Checkpoint frequency, window size and packet loss need live measurement.
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
  the source observer, it records both source and relay purchases.
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

Only the local mint's Lightning backend is simulated. These test tokens have no
external backing. `settlement` supplies submission outcomes to test exact
multi-destination prices; `native_settlement` uses real local FIPS transport.
Neither test constitutes a wireless hardware or autonomous route-buying demo.

## Run local checks

```sh
cargo test -p nvpn-fips-core --lib forwarding
cargo test -p fips-relay
```

The settlement test owns temporary wallets/mint state and binds the mint to a
random loopback port. It does not use a user's wallet or contact a public mint.

## Runtime work remaining

Automatic onward channel funding/acceptance, checkpoint scheduling, and channel
renewal/settlement
policy, OpenWrt packaging, Wi-Fi path verification and a phone
customer demo remain to be implemented. The current library is not a deployed
hotspot or a complete daemon.

Default retained history is bounded to 16 channels, 32 destination contracts
and 4,096 distinct packets per contract. Reaching a limit stops admission;
evidence is not evicted to make room. The journal is capped at 32 MiB. A deployment
needs explicit contract retirement and a memory/throughput
measurement before increasing these limits.

Datagrams must fit the discovered path after FIPS headers are added. The native
test uses 1,000-byte service payloads on the default 1,280-byte path. A
1,200-byte application datagram exceeded that path once headers were included;
the source dropped it while session control still incurred forwarding usage.
Endpoint `send_datagram` queue acceptance alone is not proof of transmission or
delivery. The gateway/client must enforce path limits or use a segmenting layer.

The disk window limits unknown crash exposure, separately from the channel's
unpaid grace. `lost_msat` never contributes to a claim, but remains reserved
against credit/capacity. If repeated failures consume the available allowance,
automatic forwarding stops; a restart is not permission to write off that loss.
This implementation assumes the accounting files survive the process restart.
Never automatically replace missing/corrupt state with a newly initialized ledger.

Buyer journals retain the same bounded evidence history. Pending observations
become unconfirmed on restart; they cannot support a signature. Evidence lost
before a checkpoint was never usable for a signature, and losing it may cause
conservative underpayment/service interruption. A signer error retains the full
reserved authorization because a signature may already have escaped. A journal
write error suspends further signing. Packet observation does not wait for the
disk/signing worker. The observer itself does not block source transmission;
provider admission and the controller enforce service exhaustion.

Sat-denominated payments round the cumulative channel amount up by less than one
sat, including approved advances. Capacity and lifetime spending limits include
that rounding. The authorizer assumes a newly accepted funded channel starts at
zero and that its controller uses this authorizer for every signature; importing
a channel previously signed elsewhere needs explicit reconciliation first.

See [the design decision](../../docs/design/fips-paid-forwarding-prototype.md)
for the adjacent-resale model, working-capital requirement and trust assumptions.
