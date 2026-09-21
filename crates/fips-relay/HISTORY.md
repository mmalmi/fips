# Bounded route and channel evidence

Buyer and seller accounting can fold closed, expired routes into one fixed-size
`RetiredRouteEvidence` record per retained channel. It preserves route count,
observed/reserved, submitted and unconfirmed units, and the original rounded
reserved/submitted costs. Each route is priced before adding its totals; combining
bytes first would change charges when tariffs or rounding differ.

The channel's identity, signed authorization, paid balance, reserved exposure,
lost crash allowance and lifetime buyer budget remain intact. Retiring evidence
neither settles a channel nor releases its unpaid allowance. Late completion
callbacks cannot change retired totals, and the lifetime completion-token counter
continues increasing.

An expiry cutoff retained with the totals rejects old agreements after their
individual records are removed, including after restart or clock rollback. The
cutoff advances only with removed routes. Every route on that channel through the
requested cutoff must be closed, use per-attempt billing, and have no pending
completion. One active, pending or legacy record rejects the whole operation.
Legacy ciphertext fingerprints remain retained because deleting them would change
the original duplicate tariff.

## Controller coordination

The controller's existing recovery worker now compacts eligible closed route
history. It first saves one bounded intent containing the exact accounting
prefixes and their before/after totals. It then commits buyer and seller rollups,
and finally removes the matching controller route, request and completed
replacement/renewal records. An idle pass writes no journals.

An interrupted intent resumes before normal startup reconciliation. During an
unfinished intent, other controller mutations stop; an already completed
accounting prefix is recognized by its exact durable totals and absence of the
removed contracts. A suspended accounting writer cannot certify an in-memory
result after a failed disk write. Recovery either retains the old records or
finishes the same intent; it never invents a new payment or resets evidence.

A verified completed refund also makes an accepted route eligible: a settled
route does not have to be replaced before its history can be removed. The same
accounting-closure and expiry checks still apply, including for existing journals.

Only complete reference groups can retire. Active agreements, unfinished route
changes or renewals, prepared replacements, pending submissions and legacy
fingerprints block their affected prefixes. Independent channels can still make
progress. Contract and offer expiry must both have passed on the local clock.
A monotonic controller expiry floor also prevents a removed offer from funding a
fresh channel if the clock moves backward. Existing per-channel accounting floors
continue preventing direct agreement replay.

Accepted buyer channel identities and seller channel terms remain available for
settlement after their last route disappears. An active incoming replacement
keeps the original predecessor ID for repeated Accept requests, with a durable
marker recording that its validated stopped predecessor was compacted. Funding,
settlement reports, paid balances, signatures and lifetime budgets are retained.

The lower-level `retire_closed_routes` APIs are trusted local operations, not
network requests or operator cleanup commands. Use the controller workflow for a
controller-owned profile; calling only an accounting API leaves stale references.

## Withdrawn routing and retained recovery

When a watched purchase loses its native neighbor, the controller may mark its
exact offer as `recovery_only` and let source selection consider another provider.
This withdraws routing permission, not financial liability: original funding IDs,
pending wallet operations, channel terms, debits and lifetime limits remain.
An eventual successful acceptance is retained without restoring that permission.

The controller persists this disposition before closing local quote authority.
Quote installation shares the same lock, and startup repairs an interrupted
cross-journal close. A failed close still removes the affected in-memory packet
permission and reports the persistence error; it does not certify durable cleanup.

If the provider returns, automatic settlement uses the existing Seal/Settle
exchange. Its journal reservation rechecks that no eligible route, new request or
renewal shares the channel. The ordinary verified refund and expiry-retirement
workflow removes the exact offer marker. Permanently absent uncertain financial
work remains retained; absence or expiry alone is not a refund.

Ordinary upkeep may remove an expired withdrawn reservation which never reached
a funding intent, provided no retained funding, outgoing channel, incoming route,
change, renewal, active request or pending watch shares that provider. Selection
and removal use the same store lock as funding. The existing offer-expiry floor
advances to the removed expiry, rejecting stale workers even after clock rollback.
This releases metadata slots only: it creates no accepted-channel history, refund
or retired financial totals. It preserves newer watches and funding sequence
numbers, skips pending cross-journal retirement, and writes nothing when no
reservation qualifies. Financial requests need their own verified terminal result.

For a fully identified, never-used withdrawn channel, upkeep saves a typed expiry
settlement intent and asks the SDK to verify the refund after immutable wallet
expiry. Initial admission excludes shared routes, renewals, changed or retired
usage, and any signed authorization. Once saved, the exact funding and expiry
intent govern recovery; unrelated new provider selection cannot prevent recording
an already verified refund. Its actual amount is immutable across retries.
No provider usage, payment, report or release acknowledgment is manufactured.

Funding installation checks the original offer and funding under the controller
lock. When a channel never reached the local buyer, coordinated retirement uses
an explicit never-installed entry instead of pretending it was accepted. The
buyer rechecks absence and saves an expiry floor to reject delayed installation.
Its rollup includes the known funded capacity and channel count, with zero signed
authorization, advance and route use. Controller and SDK totals must still match
exactly. Uncertain funding and used/shared-channel unilateral recovery remain
retained; absence of an outgoing route alone never establishes zero use.

The journal keeps the `0x100` authorization-format bit after all markers retire,
so older binaries reject the state instead of ignoring a withdrawal. Each base
history version still requires its accounting evidence. Do not
remove the bit or recovery records to reopen an account with an older executable.
Expiry intents also persist the `0x200` format bit before recording their new
semantics, so older readers reject them instead of attempting provider settlement.

## Completed outgoing channels

New controller funding uses the SDK's numbered request IDs in one stable scope
per controller journal. Existing issued IDs are never renamed: interrupted legacy
funding must recover its original wallet operation, not send again under a new ID.

The same prefix can include a verified reclaimed send that never became a channel.
Its `abandoned_requests` count retains the original costs, refund and expiry with
zero capacity or signed payments. See [funding recovery](FUNDING-COSTS.md) for the
fences and states that still block retirement.

After route compaction, the recovery worker retires a completed numbered funding
prefix when every cooperative member has a final payment, verified refund and
acknowledged report release. A zero-use expiry member instead needs its verified
SDK refund and exact retained expiry intent. Every member must have no remaining
route or renewal references and must have passed the immutable
wallet expiry (service expiry plus 60 seconds). An unfinished earlier numbered
request stops the prefix. Funding and buyer limits apply to retained records; eligible completed records recycle
slots. Opaque legacy channels and legacy duplicate-evidence routes remain retained.

The controller saves one exact plan, then commits the buyer's channel rollup,
invokes the SDK's coordinated wallet/channel retirement, checks returned gross
costs, refunds, signed amounts, capacity, count and expiry, and finally removes its
funding and settlement records. The wallet's requested token amount remains
SDK-owned; the controller checks the actual debit, including mint fees. A saved
intent resumes before ordinary funding recovery. Wallet ownership spans the
blocking operation even if the async caller is cancelled. This performs local
journal cleanup only and introduces no network message.

For an abandoned wallet send, the SDK also acknowledges its exact original refund
receipt before discarding the operation identity. Its saved channel intent retains
the verified net refund and original token cost through the wallet's durable
incoming-history handoff. Recovery completes those refund/fee totals exactly once
even if receipt deletion preceded an interrupted totals write. The later proof
handoff releases only the retired send's original native inputs and outputs;
unspent coins and unrelated receipt owners remain protected. This does not change
the controller's gross debit, refund or lifetime spending calculations.

Buyer rollups retain signed obligations, capacity, advances and rounded route
accounting. The lifetime signing limit counts both retained and retired channels.
The controller's capital calculation similarly includes cumulative retired gross
debits and refunds: spent fees never become a new spending allowance. A buyer
expiry floor rejects unknown old channels under renamed identities or after clock
rollback; already retained channels remain available. SDK numbered cutoffs also
reject replayed funding, including skipped request numbers. Idle passes and repeated
completed handoffs write neither buyer nor controller journals.

## Completed seller channels and report release

After the buyer has durably recovered its refund, it sends one
`ReleaseSettlement { channel_id }` request over the existing authenticated
neighbor control connection. `SettlementReleased { channel_id }` acknowledges
release of the saved report. This happens once per settled channel; payment and
packet-delivery cadence are unchanged. The buyer saves the acknowledgment before
its own outgoing-channel records can retire. A lost reply remains retryable.

The seller requires the original FIPS buyer identity and a completed settlement
report, which already follows its verified payout import. Unfinished or
unacknowledged reports stay retained. After removal, another release of an absent
ID is a no-op acknowledgment: it certifies neither channel existence nor a payment, creates no
future release permission or tombstone, and writes no journal. Known unfinished
channels and wrong buyers cannot use that acknowledgment path to remove evidence.

Following release, route compaction and immutable wallet expiry, the controller
asks the receiver SDK to verify custody of the original payout in the wallet.
It binds the SDK's exact channel identities, expiry, mint, currency, capacity,
signed amount and both original payout values to the released settlement reports.
The SDK retains ownership of its nominal funding and usage accounting. An
ineligible payout retains its records without saving a new cleanup intent.

The controller then saves one exact plan, including the SDK's original receiver
payout identities and wallet/receiver binding. It commits the seller ledger, retires
receiver records through the SDK, and hands those exact payout identities to the
wallet's proof-release queue. Only after that handoff and the returned history
have been checked does it remove its channel terms and settlement records.
It retains cumulative settlement value, signed payments, receiver redemption-fee
reserves, returned funds and reported fees. Reserves remain distinct from both
signed spending and fees already paid;
see [settlement values and compatibility](FUNDING-COSTS.md#signed-charges-and-payout-reserves).
The wallet owner guard spans this local operation even if its async caller is
cancelled. It performs no payout import, payment or network exchange. Startup
resumes an interrupted plan before ordinary funding recovery. Failed writers
suspend admission; retry checks exact before/after evidence and does not count a
completed handoff twice. Durable credit windows remove only the retired channel
entries; other channels keep the same allowance.

The saved plan survives receiver deletion, a full proof-release queue and a lost
handoff reply. Startup retries that same plan; it neither reconstructs payout
ownership from wallet balances nor changes signed amounts or fees. The durable
`0x4000` format bit rejects older controller readers that could discard the new
handoff. The bit remains after completion. Original sender refunds have their own
ownership lifecycle; the receiver handoff does not release them.
The local SDK plan contains bearer proofs and must remain in protected storage;
it is never sent to peers. One plan is limited to 1024 original coins and 4 MiB.

The SDK requires original unspent payouts to retain their spending signatures;
already-spent payouts are eligible without restoring their value. Empty zero
payouts are valid. An exact committed plan can be retried without advancing
history twice. SDK rollups preserve their own expiry floor and original values;
the controller must match its previous saved SDK history before adding a batch.
It does not silently adopt an independently advanced receiver history.

Old pending seller intents still retain the channel IDs, released reports and
original accounting needed to acquire a verified SDK plan. Recovery saves that
plan before further deletion, including when the ledger step already committed.
Previously completed application-only cleanup may have lost those identities;
its SDK records require separate reconciliation. New SDK rollups can therefore
cover a subset of cumulative application totals, without replacing older totals
or inventing payout evidence.

Seller history keeps each channel's positive unpaid exposure:
`max(reserved_msat - paid_msat, 0)`. These amounts accumulate by buyer identity and
mint, including lost crash windows and unconfirmed submissions. They keep consuming
the relationship's shared allowance on later channels, without being billed again.
An overpayment on another channel does not erase that debt. Fully paid channels
need no relationship record. Unknown old channel terms are rejected using a saved
expiry floor, including renamed IDs and clock rollback.

Debt relationships are bounded by the ledger's channel limit. If a new unpaid
relationship would exceed it, cleanup retains the channel and all evidence; it
never drops another identity to create room. This conservative bound can require
operator intervention after enough distinct unpaid peers. Active, unexpired,
unacknowledged, pending, legacy or otherwise unresolved records also retain slots.
The controller and ledger's channel bounds now count retained records on both sides.

**Remaining history work:** unreleased spent proof records, unreleased or unrelated
transactions, mint/melt records and orphaned legacy receiver records remain.
Completed CDK recovery operations already remove their saga records; unfinished
creating and spending operations must retain their original coins. Spent proof
evidence also supports the SDK's receiver-custody checks. Proof cleanup must
coordinate all of those owners, not merely observe a spent state or completed
spending operation. This is not yet a bound on total router database size or proof
of indefinite operation under hostile identity churn.

The SDK provides an explicit local proof-release queue for that handoff.
Its caller must durably release every external owner before adding
the original coins; spent state alone grants no cleanup authority. The queue
retains at most 1024 candidates and deletes at most 128 eligible spent records per
pass, preserving unspent value, local recovery/send/receipt owners and an exact
crash-recovery intent. FIPS seller-channel retirement supplies its saved original
receiver payout batches only after custody checks and receiver retirement finish.

Outgoing channel retirement now hands off exact completed sender refunds and
wallet-created funding records through the same queue. The SDK saves a bounded,
wallet-authenticated snapshot before removing send records, checks its original
channel and accounting evidence on retry, and removes the channel records only
after queue admission succeeds. Unspent coins remain spendable. Spending an
imported receiver payout does not release its receiver owner; receiver retirement
must still finish separately. Sender records use SDK format version 10 and require
the original refund proofs, including an explicit empty list for a zero refund.
No additional FIPS journal or wire message is introduced.

One sender intent holds at most 2048 distinct coins and 8 MiB of proof JSON, with
queue admission in groups of 128. Native funding capture separately permits at
most 1024 coins and 4 MiB. An already saved FIPS retirement prefix can exceed
these snapshot limits and cannot currently be reduced automatically; resumable
paging of that unchanged target remains unfinished. A full queue can also delay
retirement. These limits do not bound unrelated wallet history, total database
size or the aggregate SDK client file. Local proof and transaction enumeration still loads existing records.
Production bounds require recovery headroom reserved before funding and sustained
storage acceptance across supported histories; cleanup must not discard live
value or evidence to make space.

The supported v1 scope uses fresh profiles. Automated migration of legacy/full
profiles and version-1 funding-cost records is unsupported; missing original
evidence must never be replaced with zero costs.
Expiry alone does not settle or refund an unfinished channel.

The release exchange requires matching controller versions to complete cleanup.
Old journals load with `released: false`, preserving retrieval rights until the
buyer acknowledges them. An older peer that does not support release may already
have completed the financial settlement; the new buyer then reports that its
refund is recovered and report release remains pending. Existing records remain
available. Profiles whose old buyer already removed its records without a release
need separate reconciliation; do not fabricate an acknowledgment.

## Journal compatibility and checks

Buyer journals start at version 3 and advance to version 4 on channel retirement;
seller snapshots start at version 5 and advance to version 6 on channel retirement.
Existing buyer versions 1/2 and seller versions 3/4 load with zero retired totals
and retain their original evidence and billing mode. New versions require an explicit, internally
consistent rollup field; missing fields are rejected. Older executables reject
the new versions, so do not downgrade a profile after it has been opened by this
code. New controller journals start at version 3. Version 2 loads with no retired history
and upgrades on its first retirement. Missing
version-3 history is rejected, and older executables reject version 3.
The first numbered funding or outgoing-channel retirement upgrades the controller
to version 4, which requires explicit buyer channel history. Version 5 additionally
requires explicit seller totals. Coordinated receiver retirement
upgrades the controller to version 6, requiring explicit receiver history and an
exact SDK plan in every pending seller intent. Versions 2 through 5 still load;
the original rights and evidence determine which records can migrate. Later
funding and route cleanup preserve the higher version. SDK outgoing channel
retirement upgrades its client journal to version 6.
Older binaries cannot read these newer journals; keep their matching code and
dependencies together and do not downgrade a used profile.
Version-1 funding-cost reconciliation remains separate and incomplete.

The isolated retirement suite runs 64 successive route replacements on each side
with a one-route storage limit and restart after every retirement. It checks exact
cost/signature/budget conservation, a journal below 4 KiB, stale replay rejection,
unpaid-grace preservation, atomic refusal of unresolved batches, legacy retention,
old-schema loading, malformed state and failed writes. It uses real accounting,
admission and storage paths with a trusted simulated expiry clock; it does not
claim wall-clock channel expiry or mint settlement coverage from these tests.

Run with the unreleased dependency overrides described in [funding costs](FUNDING-COSTS.md):

```sh
cargo test --config /path/to/local-dependencies.toml -p fips-relay --all-features --test retirement --test buyer --test ledger --test durable
```

The controller tests exercise 64 successive replacements, restart, exact
cross-journal interruption boundaries, failed accounting and final controller
writes, pending submissions, unfinished/prepared replacements, stale offers,
malformed intents, idle write suppression and settlement identity after provider
changes. These are real journal/accounting paths with simulated expiry and
fixture funding identities; real mint/controller settlement is covered separately.

```sh
cargo test --config /path/to/local-dependencies.toml -p fips-relay --lib controller::retirement_tests
```

The channel coordinator tests cycle 64 completed channels with a one-channel buyer
limit, restart after each handoff, preserve nonzero fees and signed spending, reject
old/renamed channels and changed wallet evidence, and cover intent/accounting/final
write failures. Wallet results in those deterministic tests are fixtures; the
`funding_costs` service test separately exercises real numbered wallet funding,
fee-bearing settlement, wall-clock expiry, automatic cleanup, restart and lifetime
budget refusal through running FIPS processes and a local test mint. Simulated
Lightning supplies test money; no live-router or physical power-loss claim follows.

```sh
cargo test --config /path/to/local-dependencies.toml -p fips-relay --all-features --lib channel_history
cargo test --config /path/to/local-dependencies.toml -p fips-relay --all-features --test funding_costs
```

Seller tests cycle 64 completed channels through a single retained slot and
restart after each cleanup. They verify exact debt, crash-window retention,
non-netting of unrelated overpayments, buyer/mint isolation, bounds under distinct
unpaid identities, missing/corrupt history, release authorization and all local
write boundaries. The real `funding_costs` service scenario loses a release reply,
keeps the buyer offline while the seller removes its acknowledged report, and
then recovers both sides without changing wallet balance or lifetime spending.
It also verifies SDK receiver removal and exact matching controller/SDK history.
The paid-fee service case retires both paid and zero-usage channels after actual
expiry, retaining the original signed amounts, redemption reserves and payouts.

Coordinator fixtures additionally cover receiver failure before commit, a lost
commit reply, final controller write failure and a mismatched returned history.
Each resumes the original plan once. Legacy pending intents recover both before
and after ledger removal; changed payout/history evidence and incomplete modern
schemas are rejected. These use fixture SDK callbacks through the production
coordinator; actual custody and removal are exercised by the service tests above.
These coordinator tests do not establish whole-wallet storage bounds or physical
power-loss recovery. Exact proof-history collection has the separate ownership
and recovery requirements described above.
