# Funding costs and lifetime wallet limits

Each new channel reserves `channel capacity + max_funding_overhead_sat` in the
controller journal before calling the wallet. The wallet receives that exact
maximum debit with the stable funding request ID. After completion the controller
saves the original operation ID, token value, wallet swap fee and total debit.
Retrying the request cannot authorize another spend or a larger limit.

Two wallet limits apply to every funding mutation and restart:

- `max_locked_sat` bounds unresolved reservations and funded channels whose
  refunds are not yet confirmed by the local wallet.
- `max_wallet_spend_sat` bounds lifetime wallet debits minus verified refunds,
  including the full worst-case cost of unresolved requests. Fees and payments
  remain spent after settlement. Refunds cannot reset them.

For example, a 32-sat channel with an 8-sat overhead allowance initially reserves
40 sats. An actual debit of 37 reduces exposure to 37. A verified 25-sat refund
releases locked capital but retains 12 sats of lifetime spend. With a 40-sat
lifetime limit, another 40-sat reservation must be rejected before wallet access.

The existing `buyer_budget_sat` separately bounds cumulative relay payment
signatures. It does not include wallet/mint fees. Set all limits explicitly.
Zero funding overhead allows only funding that needs no value above capacity.

Recovery reads the original wallet cost even if its quote has expired or the route
is paused. For a persisted channel opening, the SDK restores its exact mint outputs
without creating another opening, sending wallet funds or falling back to a mint
swap. This grants no routing permission. Missing or conflicting evidence, empty
restore replies and invalid or partial signatures retain uncertainty.

Before a channel opening exists, an exclusively withdrawn funding intent can
instead reclaim its original wallet send. The controller and SDK persist separate
abandonment fences before recovery. The SDK verifies the original request and saved
plan, restores only that send's confirmation, and durably revokes its token. An
empty restore may retry the identical saved confirmation; it never prepares a new
send or processes unrelated wallet operations. Only the verified original debit
and net refund release reserved capital. Until that result is saved, new purchases
from the same provider remain blocked; unrelated providers retain their normal
limits. Route changes check the same fence atomically with reservation; if the
route change owns the provider first, reclaim must wait for its withdrawal.
An existing channel opening still uses its original restore/refund path.

Completed abandoned sends share numbered-prefix retirement with channels after
their original wallet expiry. They retain gross costs, refunds and lifetime
exposure, and count as `abandoned_requests`, with zero channel capacity or signed
payments. The controller retains the `0x800` format bit and the SDK uses version 8
so older readers cannot silently ignore the abandonment fences.

This recovery remains conservative. Missing admissions, missing plans and
unsubmitted `ProofsReserved` sends do not prove a terminal financial outcome.
They keep their reservation. A stopped, expired upstream agreement can now retire
without an installed seller contract if its verified seller channel already
exists. The ordinary retirement transaction records zero usage, preserves channel
terms and paid credit for settlement, and prevents delayed activation even after
a clock rollback. Its `0x1000` journal flag prevents older readers from ignoring
the saved retirement evidence. Four focused regressions, 269 relay library tests
and nine retirement integration tests pass with this change.

Ordinary upkeep now stops expired incoming agreements and withdraws expired
purchases that have no live owner, including middle relays with no local Watch.
Withdrawal and local forwarding closure hold the controller mutex; failure keeps
the durable fence and suspends the store until reload reconciles it. Live incoming
agreements, pending Watches and unfinished renewals or route changes retain their
exact offer IDs. A fresh offer with a different ID does not pin the expired one.
The existing recovery-only state preserves original funding and capital; this
adds no wire messages or financial record format. Six focused regressions and all
275 relay library tests pass, including reload after local closure failure.

Earlier interruptions before a verified seller channel exists still retain their
records. A pending source Watch can still retain an expired purchase while its
provider stays connected. Do not remove unresolved records or reset budgets to
force progress.

A retained trial or route-change record on a different funding intent no longer
blocks recovery once its exact original channel has a validated terminal
settlement and verified wallet refund. Both abandoned-send reclaim and unused
persisted-opening expiry recovery use the same ownership check. Missing or
inconsistent evidence, live requests, pending Watches, incoming dependencies and
unfinished renewals continue to block recovery. Route-change targets must be
withdrawn or exactly bound to terminal history; predecessors must resolve to that
history. A completed renewal still needs matching terminal predecessor evidence.
This changes recovery eligibility only: the old trial pointer, consumed quota,
signed charges, financial records and lifetime costs remain intact.

Refund recovery requires the wallet's durable original recovered amount, including
on calls that import zero new coins. Peer settlement reports alone cannot release
budget. A settlement report also names the value after the funding swap; returned
unused fee reserves can exceed nominal channel capacity. The wallet debit and
verified refund determine the lifetime cost.

## Signed charges and payout reserves

`SettlementReport.paid_sat` is the final signed traffic charge. The separate
`receiver_fee_reserve_sat` retains extra receiver proof value reserved for later
redemption. Their sum is the original receiver payout proof value. For example,
a three-sat signed payment can close with four sats of receiver proofs: three
charged sats plus one reserve sat. Importing those proofs increases the wallet's
stored proof value by four; it does not authorize billing four sats for traffic.

`refunded_sat` remains the original sender refund proof value, before later
redemption fees. `fee_sat` retains the difference between the reported
post-stage-one value and both parties' proof values. It excludes fee reserves and
earlier wallet funding fees. A reserve is not evidence that a later fee was paid.
Actual wallet debits/refunds continue to control lifetime exposure independently.

Settlement validates these values before importing the receiver payout. Seller
cleanup preserves signed payments, receiver reserves, refunds and reported fees
separately; a reserve never consumes the traffic-signing budget or becomes another
usage claim. Checked arithmetic rejects overflow and inconsistent reports.

Older reports and seller rollups load with zero receiver reserve. Their original
accounting must still conserve value; removing a nonzero reserve from a new record
fails validation. Older executables reject nonzero-reserve reports and histories
under their original value-sum checks. Use matching settlement implementations;
this adds one report field over existing control, not another request operation.

`status.funding_budget` exposes pending reservations, total recorded debits,
confirmed refunds, locked capital and worst-case lifetime exposure. The historical
`locked_sat` status field has the same meaning as `funding_budget.locked_sat`.
The 16-record funding bound applies to retained funding intents. The recovery
worker recycles eligible completed channels or reclaimed sends after verified
financial completion, route cleanup and immutable wallet expiry. Persistent gross debit/refund rollups keep
lifetime exposure unchanged. Legacy, unfinished and still-referenced channels
remain retained. Seller cleanup now requires the buyer's durable refund and report
release; unpaid exposure remains attached to buyer and mint. It now coordinates
SDK receiver removal using original wallet payout custody and a durable exact
plan. CDK operation/activity/proof histories still need separate bounded-retention
work. Cleanup of already-orphaned legacy receiver records is outside this
fresh-profile milestone.
[History and recovery](HISTORY.md) specifies the transaction and remaining bounds.

## Development and migration

Controller journal versions 2 through 6 require the saved debit approvals, wallet cost
evidence and refund totals. Version-1 controller journals cannot be automatically
upgraded because their fee approval and exact wallet costs may be unavailable.
Keep old state intact and use its matching executable for recovery; do not delete
the journal or supply invented zero fees. Legacy reconciliation and migration are
outside this greenfield milestone. Fresh test profiles must explicitly configure
the two new policy fields. Settlement peers need the same updated report format.

This source requires the unreleased local cashu-service, CDK, Spilman and TCP/FIPS changes;
the published dependency pins cannot build the funding adapter yet. Use the
cashu-service development override example, adding the local `cashu-service`
crate path to `[patch.crates-io]`. Keep machine-specific overrides outside the
repository and record exact revisions. Dependency release/version updates remain
necessary before distribution. No device deployment is implied by these tests.

The TCP stack and endpoint override must include `set_connection_reservation`.
Override both `nvpn-fips-tcp` and `nvpn-fips-tcp-endpoint`; this workspace still
pins stack 0.2.2 and endpoint 0.2.16, whose FIPS core requirement is 0.4.81. Use
the matching development checkout with the reservation change (verified TCP/FIPS
revision `491b11209aba`). Endpoint 0.2.17
requires core 0.4.82 and cannot silently replace this graph. Shared Rust/TypeScript
admission vectors and live interoperability checks cover the new local policy;
the wire encoding is unchanged. Dependency version alignment remains a distribution
requirement, separate from these matching-graph development tests.

Run with those overrides:

```sh
cargo test --config /path/to/local-dependencies.toml -p fips-relay --all-features --lib --test controller --test funding_costs --test service --test priced_paths --test destination_service
cargo clippy --config /path/to/local-dependencies.toml -p fips-relay --all-features --all-targets -- -D warnings
scripts/check-rust-file-lines.sh
```

The focused process tests use three or four real services and a local test mint charging
fees. They check wallet balance deltas, restart, actual refund recovery, replay
after lost controller completion, and lifetime-budget rejection before another
wallet spend. Unit tests exercise journal reservations, cost reconciliation,
duplicate operation IDs, corruption and retention of spent costs after refunds.
The paid-traffic case additionally delivers datagrams, closes a nonzero signed
balance with a receiver redemption reserve, and checks both parties' original
values, wallet conservation, report replay and restart. After actual expiry, it
checks receiver removal and identical SDK/controller histories for both paid and
zero-usage channels, preserving the original payout values and lifetime budget.
Zero-usage funding tests alone do not exercise the redemption-reserve distinction.

The interrupted-funding process case kills the buyer after the mint commits the
exact saved funding swap, while its response is held. The original quote expires
naturally and the departed provider causes ordinary route withdrawal. Restart
restores the same operation and channel without another send or swap; the route
remains disabled. At the original wallet expiry, the unused funding is refunded
and its SDK/controller records retire. Spendable balances plus mint fees conserve
all 384 issued test sats, and gross debits/refunds remain in lifetime accounting.
This covers a persisted opening with restorable committed outputs. Physical
power-loss durability remains a separate boundary. Run the focused case with:

```sh
cargo test --config /path/to/local-dependencies.toml -p fips-relay --all-features --test funding_costs restore::interrupted_funding_restores_after_route_expiry_without_new_spending
```

The companion pre-opening case interrupts the original wallet preparation send
before a channel opening exists. After the quote expires and the provider stops,
ordinary restart upkeep reclaims that exact operation without another send,
channel or route. The verified run recorded 43 sats debited and 35 refunded, with
zero pending or locked capital and eight sats of lifetime mint fees. All 384 test
sats are accounted for as 376 spendable plus eight in mint fees. This reclaim can
finish before the original wallet expiry; retirement still waits for that expiry.
The test checks unchanged request/plan identity, funding sequence and buyer budget.
It does not cover the retained unsubmitted or shared-owner cases above. Reproduce:

```sh
cargo test --config /path/to/local-dependencies.toml -p fips-relay --test funding_costs preopening::interrupted_wallet_send_recovers_after_offer_expiry_without_replacement_funding -- --exact --test-threads=1 --nocapture
```

The four-service transit case extends this boundary to source → middle payer →
provider → destination. It kills the middle payer after its preparation swap
commits, with a verified upstream seller channel but no installed seller contract
or local Watch. Native disconnection withdraws the source's original pending
purchase. Restart after quote expiry leaves the downstream provider absent; the
middle receives only status requests during the acceptance window.

Ordinary upkeep withdraws the expired transit purchase, retires its stopped
incoming dependency and reclaims the same wallet operation without opening a
channel. The run records 43 sats debited, 35 refunded, no locked capital and eight
sats of retained lifetime cost. A direct database balance query proves the middle's
120 sats are already spendable before any cleanup can rescue a send. The original
upstream channel settles automatically; channel terms and verified credit survive
retirement. Aggregate wallet balances plus mint fees conserve all 512 test sats
(494 spendable and 18 fees), without replacement funding or changed limits.
All six funding/refund process scenarios pass together with strict all-feature,
all-target lint, formatting and the source-size gate.
This interruption has zero paid upstream usage; nonzero-credit retirement is
covered by the focused journal tests, not this process case. Physical power loss,
radio mobility and the unresolved ownership cases above remain separate checks.

```sh
cargo test --config /path/to/local-dependencies.toml -p fips-relay --all-features --test funding_costs transit_preopening::interrupted_transit_wallet_send_recovers_without_a_middle_watch -- --exact --test-threads=1 --nocapture
```

Retained-history regressions exercise actual buyer admission, cumulative signature
authorization and journal mutations with explicitly modeled settlement evidence.
After 1,234 trial bytes and a two-sat authorization, reclaiming another withdrawn
intent preserves the closed trial's 28,766 remaining bytes and the 1,022-sat buyer
budget across replay and reload. The same holds for an unused persisted opening
after its original expiry. Fourteen rejection cases keep live or unproven owners
blocked without changing the journal. These unit cases establish the accounting
and ownership transition; they are not a mint-process or hardware demonstration
of this retained-history sequence.

```sh
cargo test --config /path/to/local-dependencies.toml -p fips-relay --all-features --lib controller::source_selection::recovery::tests::reclaim -- --test-threads=1
```
