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
is paused. It grants no routing permission. Missing or conflicting evidence keeps
the full reservation. Refund recovery requires the wallet's durable original
recovered amount, including on calls that import zero new coins. Peer settlement
reports alone cannot release budget. A settlement report also names the value
after the funding swap; returned unused fee reserves can exceed nominal channel
capacity. The wallet debit and verified refund determine the lifetime cost.

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
The 16-record funding bound now applies to retained channels. The recovery worker
recycles eligible completed numbered channels after verified settlement, route
cleanup and immutable wallet expiry. Persistent gross debit/refund rollups keep
lifetime exposure unchanged. Legacy, unfinished and still-referenced channels
remain retained. Seller cleanup now requires the buyer's durable refund and report
release; unpaid exposure remains attached to buyer and mint. Receiver/CDK history
cleanup is still unfinished.
[History and recovery](HISTORY.md) specifies the transaction and remaining bounds.

## Development and migration

Controller journal versions 2 through 5 require the saved debit approvals, wallet cost
evidence and refund totals. Version-1 controller journals cannot be automatically
upgraded because their fee approval and exact wallet costs may be unavailable.
Keep old state intact and use its matching executable for recovery; do not delete
the journal or supply invented zero fees. Automated reconciliation/migration is
still a release blocker. Fresh test profiles must explicitly configure the two
new policy fields. Settlement peers need the same updated report format.

This source requires the unreleased local cashu-service, CDK and Spilman changes;
the published dependency pins cannot build the funding adapter yet. Use the
cashu-service development override example, adding the local `cashu-service`
crate path to `[patch.crates-io]`. Keep machine-specific overrides outside the
repository and record exact revisions. Dependency release/version updates remain
necessary before distribution. No device deployment is implied by these tests.

Run with those overrides:

```sh
cargo test --config /path/to/local-dependencies.toml -p fips-relay --all-features --lib --test controller --test funding_costs --test service --test priced_paths --test destination_service
cargo clippy --config /path/to/local-dependencies.toml -p fips-relay --all-features --all-targets -- -D warnings
scripts/check-rust-file-lines.sh
```

The focused process tests use three real services and a local test mint charging
fees. They check wallet balance deltas, restart, actual refund recovery, replay
after lost controller completion, and lifetime-budget rejection before another
wallet spend. Unit tests exercise journal reservations, cost reconciliation,
duplicate operation IDs, corruption and retention of spent costs after refunds.
The paid-traffic case additionally delivers datagrams, closes a nonzero signed
balance with a receiver redemption reserve, and checks both parties' original
values, wallet conservation, report replay and restart. Zero-usage funding tests
alone do not exercise this distinction.
