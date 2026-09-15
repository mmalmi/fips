# FIPS paid forwarding prototype

Experimental service components for **sender-funded, best-effort forwarding**.
Delivery receipts are an optional future experiment. The relay does not inspect
TCP, UDP or application delivery acknowledgments inside encrypted FIPS traffic.

## Implemented and checked

* The core's optional `ForwardingPolicy` gates native FMP transit, including
  batched/deferred sends. A five-node integration test crosses three gated
  routers in both directions, exhausts the middle allowance, accesses its local
  service while blocked, and resumes transit after replenishment.
* `RelayLedger` keeps persistent neighbor channels separate from destination
  quotes. Many quotes share one channel's credit and unpaid exposure. It
  reserves before enqueue and retains uncertain usage. Repeated opens, new
  destinations and route changes cannot reset grace or create credit. Replay
  protection spans retained quotes/channels for the same authenticated buyer.
* Snapshot restoration retains usage and invalidates active permissions. This
  is a recovery primitive, **not a complete durable runtime**: the future
  controller must persist its exposure window before allowing packet sends and
  reconcile the last window after a crash. A saved snapshot alone is insufficient.
* The payment adapter reuses `cashu-service` and checks the authenticated buyer,
  channel, capacity, denomination, expiry and signed balance before credit can
  be published. The trusted controller owns immutable agreement bindings.
* A separate integration test runs a real local CDK mint and Cashu Spilman
  channels. Each channel pays for two destinations with cumulative updates.
  Three relay ledgers receive gross payments of 3, 2 and 1 test sats.
  After downstream expenses, each relay earns 1 test sat. Channel receiver
  state is reloaded before closing. Buyer refunds are restored and signed using
  the existing recovery API; every final wallet balance is spent and redeemed
  again, and replayed receiver payouts are rejected by the mint.

Only the local mint's Lightning backend is simulated. These test tokens have no
external backing. The settlement test supplies submission outcomes directly to
the ledger; it does not yet join automatic settlement to the native FIPS test.

## Run local checks

```sh
cargo test -p nvpn-fips-core --lib forwarding
cargo test -p fips-relay
```

The settlement test owns temporary wallets/mint state and binds the mint to a
random loopback port. It does not use a user's wallet or contact a public mint.

## Runtime work remaining

Authenticated quote/payment exchange, automatic onward buying, source-side
spending controls, durable window reservation/reconciliation, live native FIPS
and Cashu integration, OpenWrt packaging, Wi-Fi path verification and a phone
customer demo remain to be implemented. The current library is not a deployed
hotspot or a complete daemon.

Default retained history is bounded to 16 channels, 32 destination contracts
and 4,096 distinct packets per contract. Reaching a limit stops admission; evidence is not evicted to make
room. A deployment needs explicit contract retirement and a memory/throughput
measurement before increasing these limits.

See [the design decision](../../docs/design/fips-paid-forwarding-prototype.md)
for the adjacent-resale model, working-capital requirement and trust assumptions.
