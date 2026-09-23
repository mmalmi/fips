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
abandonment fences before recovery. If mint submission began, the SDK verifies the
original request and saved plan, restores only that send's confirmation, and
durably revokes its token. An
empty restore may retry the identical saved confirmation; it never prepares a new
send or processes unrelated wallet operations. For a mint-submitted send, only the
verified original debit and net refund release reserved capital. Until that result
is saved, new purchases from the same provider remain blocked; unrelated providers
retain their normal limits. Route changes check the same fence atomically with reservation; if the
route change owns the provider first, reclaim must wait for its withdrawal.
An existing channel opening still uses its original restore/refund path.

Completed abandoned sends share numbered-prefix retirement with channels after
their original wallet expiry. They retain gross costs, refunds and lifetime
exposure, and count as `abandoned_requests`, with zero channel capacity or signed
payments. The controller retains the `0x800` format bit. The current SDK
preparation authority and result format requires client-store version 12;
older readers reject this evidence.

An exact admission which never started a wallet send has a separate terminal
`Cancelled` outcome. The SDK fences that admission and verifies both wallet
request namespaces are absent while holding the money lock. Only that evidence
releases its original reservation; FIPS records no operation ID, debit, refund or
channel. The controller retains the `0x2000` format bit in addition to `0x800`,
and the SDK uses version 9. Cancellation survives reload, rejects delayed funding
and preserves the original sequence, withdrawal fences and lifetime limits.
After the original wallet expiry, ordered retirement counts `cancelled_requests`
separately from wallet sends and `abandoned_requests`, with zero monetary totals.

The three-daemon cancellation regression kills the source during the exact
admitted metadata wait, before any wallet send. A one-time purchase permits no
automatic replacement. Ordinary startup/upkeep cancels the original intent and
retires it after its original expiry; another restart preserves both cutoffs.
All 384 test sats remain spendable before cleanup, with no swaps, fees, channels,
debits or refunds. The original FIPS implementation keeps its 48-sat reservation
under the same scenario. This proves the local SDK/controller handoff, not
physical power-loss or Wi-Fi acceptance.

A started wallet preparation has its own terminal `PreparedCancelled` outcome.
The SDK binds the original request to CDK's exact preparation, releases only its
original reservation, saves the wallet cancellation outcome and then acknowledges
CDK's retained result. FIPS records that original operation and releases its
capital reservation without adding a debit, refund, fee or channel. The operation
cannot belong to another live funding intent. The `0x8000` format bit prevents an
older controller from overlooking this distinction. Both cancellation outcomes
share the existing cancelled-request count and original-expiry retirement path.

A lost SDK fee preview can recover exact native preparation evidence through the
original request commitment; it cannot invent a preview or confirm a different
send. Local cancellation does not depend on the mint's current keyset. Missing or
changed original evidence still retains the financial reservation. A send whose
mint submission began must recover and revoke its original token, preserving its
real debit, refund and fees. This is a fresh-profile format, not a migration of
existing accounts. See the SDK's wallet request and channel history documentation.

A stopped, expired upstream agreement can now retire
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
agreements and unfinished renewals or route changes retain their exact offer IDs.
A fresh offer with a different ID does not pin the expired one.
The existing recovery-only state preserves original funding and capital; this
adds no wire messages or financial record format. Six focused regressions and all
275 relay library tests pass, including reload after local closure failure.

A pending source Watch no longer pins an exactly matching expired requested
offer solely because the provider remains connected. The same expiry transaction
clears that pending pointer and records withdrawal, preserving the Watch's pause,
price ceiling and selected-trial accounting. Same-ID Watches with different terms
and other live owners still block withdrawal. Four new journal regressions and all
282 relay library tests pass, including rejection of delayed activation and
durability after local closure failure.

A real-mint, three-daemon regression holds a successful wallet-preparation reply
through quote expiry, then loses the reply. Both adjacent daemons keep their
original processes and native link IDs, with fresh bidirectional application data
throughout. The original implementation retains the expired reservation; the fix
automatically recovers the exact original send without replacement funding or
administrative settlement. Before cleanup, spendable wallets contain 376 test
sats and measured fees account for the remaining eight of 384 issued. This is
local process evidence, not physical Wi-Fi or arbitrary mobility acceptance.

Earlier interruptions before a verified seller channel exists still retain their
records. Unfinished route changes and renewals also require their own completion
or withdrawal. Do not remove unresolved records or reset budgets to force progress.

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
plan. Unreleased wallet receipts, spent proofs and other CDK histories still need
separate bounded-retention work. Cleanup of already-orphaned legacy receiver
records is outside this fresh-profile milestone.
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

The wallet's incoming-receipt reader now requires CDK's indexed
`get_transactions_page` API and the matching SQL scope/cursor index. Its SDK API
returns a page and continuation cursor; a page with no eligible receipts can
still have more history. This bounds receipt enumeration without truncating the
independent checks that protect coin and receipt ownership. Use matched SDK/CDK
sources; the published versions do not provide this storage contract.

The TCP stack and endpoint override must include `set_connection_reservation`.
Override both `nvpn-fips-tcp` and `nvpn-fips-tcp-endpoint`; this workspace still
pins stack 0.2.2 and endpoint 0.2.16, whose FIPS core requirement is 0.4.81. Use
the matching development checkout with the reservation change (verified TCP/FIPS
revision `491b11209aba`). Endpoint 0.2.17
requires core 0.4.82 and cannot silently replace this graph. Shared Rust/TypeScript
admission vectors and live interoperability checks cover the new local policy;
the wire encoding is unchanged. Dependency version alignment remains a distribution
requirement, separate from these matching-graph development tests.

### Portable development source bundle

[`scripts/source_bundle.py`](../../scripts/source_bundle.py) exports the exact
committed workspace and local dependency trees, replaces the workspace lockfile
with an explicitly hashed tested lock, and vendors its crates.io dependencies.
It then resolves all workspace features offline with an empty Cargo home and
rejects package sources outside the bundle. This makes the local development
graph movable without publishing or relying on the original checkouts. It does
not repair the published package graph or constitute a release.

The private input specification uses schema 1. Each source must be a clean Git
workspace at the full revision specified, and the output must be outside those
workspaces. This abbreviated example shows the format; include **every** local
patch needed by the tested lock:

```json
{
  "schema": 1,
  "workspace": {"path": "/path/to/fips", "revision": "<full-commit>"},
  "dependencies": [
    {
      "name": "cashu-service",
      "path": "/path/to/cashu-service",
      "revision": "<full-commit>",
      "packages": {
        "cashu-service": "crates/cashu-service",
        "cashu-credit": "crates/cashu-credit"
      }
    }
  ],
  "lockfile": "/path/to/tested.Cargo.lock",
  "lockfile_sha256": "<64-character-sha256>"
}
```

The current development graph also patches the eight CDK packages `cashu`, `cdk`,
`cdk-axum`, `cdk-common`, `cdk-http-client`, `cdk-signatory`, `cdk-sql-common` and
`cdk-sqlite` from their corresponding `crates/<package>` directories; Spilman's
`cdk-spilman` from `crates/cdk-spilman`; `bitreq` from `bitreq`; and
`nvpn-fips-tcp`/`nvpn-fips-tcp-endpoint` from `rust/fips-tcp`/`rust/fips-tcp-endpoint`.
Each repository gets one dependency entry with its exact audited revision. The
generated manifest records those revisions and the tested lock digest without
copying the private input paths or specification.

```sh
python3 scripts/source_bundle.py create /path/to/spec.json /path/to/bundle --toolchain 1.96.0 --offline
python3 /path/to/bundle/checkout/scripts/source_bundle.py verify /path/to/bundle --resolve
```

Creation requires the pinned registry sources to be cached when `--offline` is
used; omit that flag to allow Cargo to fetch missing pinned registry sources.
The exported `checkout/.cargo/config.toml` contains relative patches and a
relative vendor directory. Run Cargo from `checkout/`, including after relocation,
with `--offline --locked`. Rust 1.96.0, Python 3.9 or newer, Git and the target's
native compiler/build tools remain external requirements. Selected dependency
features can require additional tools, such as protobuf compilation for CDK
signatory's gRPC feature; vendoring sources does not supply those tools.

The verifier checks hashes, executable flags, symlink targets and unexpected
files, excluding only the manifest itself and Cargo's `checkout/target/` output.
Tracked files excluded by `git archive` attributes are still exported. Ignored
files, Git history, escaping symlinks and submodules are excluded or rejected.
The manifest is an integrity/provenance record, **not a signature**; trust in its
contents still depends on how the bundle and manifest are obtained. This is
source reproducibility, not a claim of bit-identical binaries.

Offline verification also disables compiler wrappers inherited from enclosing
Cargo configuration files. Manual Cargo builds retain the caller's other build
configuration and native toolchain; a fresh Cargo home alone does not isolate
ancestor configuration files.

Cargo builds in the bundle use a Git discovery ceiling to avoid reporting the
revision of an unrelated enclosing repository. Verification clears inherited
`GIT_*` overrides; use a similarly clean shell for manual builds. Version output
has no Git revision in the archive; use the manifest's workspace revision.
Reproduce the export, relocation, tamper and clean-environment build checks with:

```sh
python3 -m unittest discover -s testing/source_bundle -v
```

### Development acceptance

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

The companion pre-opening cases interrupt the original wallet preparation before
a channel opening exists. The committed-send case kills the source after its mint
swap commits. After the quote expires and the provider stops, ordinary restart
upkeep reclaims the original operation without replacement funding, channel or
route. The verified run records 43 sats debited and 35 refunded:
376 spendable test sats plus eight in mint fees account for all 384 issued sats.
This reclaim can finish before the original wallet expiry; retirement still waits
for that expiry.

The unsubmitted case holds a read-only keyset reply after the exact
`ProofsReserved` plan is durable. It checks the original saga and reserved coins,
kills the source, rotates the mint's actual keyset and restarts after quote expiry.
With `testbench`, the same case kills the source again after the SDK has durably
cancelled but before FIPS saves the result. The shared private wallet-completion
barrier matches the process and original funding identity; it changes no financial
journal and is absent from production builds. Ordinary restart consumes the
saved outcome and retires the original request after its original expiry.

The run passes with no replacement funding, swaps, fees, debits or refunds; all
384 test sats remain spendable. Cancellation and retirement preserve the exact
original spendable coin rows, funding sequence and buyer budget. These
process kills do not simulate physical loss of writes acknowledged by storage.
Run the pre-opening regressions with:

```sh
cargo test --config /path/to/local-dependencies.toml -p fips-relay --all-features --test funding_costs preopening:: -- --test-threads=1 --nocapture
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

The retained-history process case also exercises the full mint sequence. A paid
trial delivers two fresh payloads, signs and credits two sats, and settles while
its paused Watch retains the selected trial and 1,962 consumed units. A second
destination uses the same provider and a separately authorized original wallet
send. The buyer stops after that preparation swap commits, before any new channel
opens. After the provider stops and the quote expires, ordinary restart upkeep
reclaims the exact second operation without replacement funding.

Before fixture cleanup, the refund is already spendable and the old trial's
remaining quota, signature and lifetime budget are unchanged. The observed total
is 80 sats debited, 65 refunded and no pending or locked capital; all 512 test sats
are conserved as 500 spendable plus 12 in mint fees. This covers a naturally
retained selected trial with real settlement.
Retained route-change/renewal variants and physical interruptions remain separate
checks. Reproduce:

```sh
cargo test --config /path/to/local-dependencies.toml -p fips-relay --all-features --test funding_costs terminal_history::refunded_selected_trial_does_not_pin_another_original_send_to_same_provider -- --exact --test-threads=1 --nocapture
```
