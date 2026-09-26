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
incoming-history handoff. Exact receipt deletion, unused native completion-space
release and cumulative totals commit together in one SQLite transaction, including
at full configured payload capacity. Failure rolls everything back; retrying a
committed batch does not count it twice. Fresh incoming-history format 2 needs no
separate redo log. Exact receipt batches and selected input pages cap stored
payloads at 128 records and 4 MiB before SQL driver projection. Oversized input
groups retry smaller pages; individual oversized or malformed records retain the
original evidence. All original input checks still complete inside the retirement
transaction before deletion. The later proof handoff releases only the retired
send's original native inputs and outputs;
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

The payment controller pairs its receiver with the original wallet directory.
Automatic acceptance and preapproved `Open` requests reuse the same agreement
checks and SDK wallet admission. When native capacity accounting is enabled, the
SDK reserves the complete payout and shared bookkeeping before retaining funding.
Updates and final settlement require the original complete funding record; they
cannot reconstruct it from a later signed payment. Ordinary updates do not open
the wallet. Admission, payout import and retirement share the controller's wallet
owner; automatic acceptance acquires it before the journal lock and releases it
before onward purchase or peer-control waits.

Settlement imports the SDK's original closed payout through its original wallet
allowance, including a zero payout, before saving the controller report. Retrying
an interrupted import does not credit coins twice. Authenticated receiver retirement
removes the corresponding wallet admission only after the original payout handoff.
These are logical storage reservations; service capacity accounting remains
disabled pending the other wallet paths/stores and physical recovery acceptance.

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
Completed CDK recovery operations remove their saga records after any required
owner acknowledgment; unfinished creating and spending operations must retain
their original coins. Spent proof
evidence also supports the SDK's receiver-custody checks. Proof cleanup must
coordinate all of those owners, not merely observe a spent state or completed
spending operation. This is not yet a bound on total router database size or proof
of indefinite operation under hostile identity churn.

The SDK provides an explicit local proof-release queue for that handoff.
Its caller must durably release every external owner before adding the original
coins; spent state alone grants no cleanup authority. The queue retains at most
1024 candidates and deletes at most 128 eligible spent records per pass, preserving
unspent value, local recovery/send/receipt owners and the lifetime retired count.
FIPS seller-channel retirement supplies its saved original receiver payouts only
after custody checks and receiver retirement finish.

The version-3 queue stores compact authenticated references. Original coins remain
in the wallet until native full-record comparison and deletion, committed in the
same SQLite transaction as the authenticated queue and count update. A failure
rolls back both records and storage charges; there is no separate deletion redo
log. An admitted eligible queue batch can reclaim full native payload capacity
without growing a recovery intent first. Ordinary wallet reads remain available
after refusal, and retry advances the count once. Archive collection shares this
proof/count transaction and the same per-call budget. Physical disk recovery and
sustained aggregate storage pressure remain separate requirements.

Collection reads originals incrementally, with a soft 4 MiB batch budget and one
oversized original allowed to progress alone. Neither queue references nor its
checkpoint duplicate complete proof payloads. Older queue formats require fresh
profiles.

## Proof custody storage

Outgoing channel retirement hands off exact completed sender refunds and
wallet-created funding records through paged wallet custody. The SDK saves a
wallet-authenticated plan binding the original native send records, channel
identity and accounting before capture starts. Pages contain at most 128 coins
and 4 MiB of proof JSON. Native exact-Y reads for original inputs and indexed reads
by creating operation both cap aggregate stored payload at 4 MiB before it crosses
the database driver boundary. Capture halves the requested identity count on a
size error, down to one, while keeping the same cursor and money lock. Original
cursors advance only past checked inputs, including filtered imported coins;
missing originals fail. Created-coin traversal uses the actual requested count
to detect its final page. Large valid groups therefore progress without skipping
coins. An individually oversized record remains intact and blocks that capture.
Proof-collection reads, total storage and traversal time remain separate. All pages must
be sealed before send owners are removed. The client financial commit acknowledges
custody; retry completes that acknowledgment after interruption. Unspent coins
remain spendable without occupying the deletion queue. Spending an
imported receiver payout does not release its receiver owner; receiver retirement
must still finish separately. Sender retirement plans use SDK format version 11;
completed refunds still require
the original refund proofs, including an explicit empty list for a zero refund.
No additional FIPS journal or wire message is introduced.

A cancelled preparation retains its exact operation identity until ordinary
numbered-prefix retirement, using SDK client-store version 12 for the original
preparation identity. The SDK records cancellation before acknowledging
the native result. Its released input coins can be reused immediately and do not
belong to that cancelled request's custody archive. Cancellation contributes no
wallet sends, debits or refunds; the channel history records a cancelled request
after its original expiry. Missing or changed evidence retains the reservation.

The wallet retains one custody stream per existing numbered-send scope, within
the same 32-scope lifetime bound. It reuses the descriptor across retirements.
FIPS upkeep visits one acknowledged page even when no new channel retires, after
releasing the controller journal lock. Residual coins rotate to the tail so an
unspent head cannot starve later pages. One conditional SQLite transaction deletes
eligible spent originals, removes matching queue references, updates the lifetime
count and commits custody pages and their cursor. No intermediate queue admission
is required. A pending capture pauses only its own scope's collection.

Native atomic proof comparison reads pages of at most 128 identities within
4 MiB of stored payload. One larger expected record can progress alone, with its
ceiling derived from the caller-owned original through the production row encoder.
Stored growth cannot raise that ceiling. Each read is bounded before driver
projection and decoding; full typed equality and atomic proof/checkpoint rollback
are retained. Initial collection reads remain
separate limits. This does not impose a smaller admission limit on original coins
whose stored mint, witness or ownership metadata makes them larger than proof JSON.

Exact recovery-record comparisons in atomic proof changes, output preparation,
receipt publication, issuance retirement and withdrawal completion share the same
caller-sized bound. Their bounded operation query retains row locking and typed
equality; a required absence check reads only existence. Larger expected originals
still compare, while unexpected stored growth cannot raise the ceiling. Internal
storage-reservation reads without an exact original snapshot and ordinary recovery
reads remain separate bounds.

The version-4 custody registry caps retained pages plus unfinished capture
reservations at 64 MiB by default. Before copying a new capture, the SDK pages the
original owners to reserve its full serialized proof size plus 16 KiB per nonempty
page. Appending transfers that allowance to retained pages; retries use the same
reservation, and acknowledgment releases unused allowance only after the client
financial commit. Older archives and unfinished redo logs require a fresh profile.
`CashuWalletService::configure_proof_archive_capacity` persists a different limit
but rejects shrinking below retained and reserved usage. It never evicts evidence.

On pressure, retirement visits at most one previously acknowledged page before
rejecting a new capture. Repeated retries can therefore free eligible spent
history even when retirement precedes ordinary upkeep collection. Unspent or
otherwise owned coins remain charged. The original plan and native owners remain
until the complete capture fits and is sealed. The same transaction commits page
changes and byte counters, checking every original record before replacement.

This is a logical page limit. Registry metadata has its separate 1 MiB bound and
each page is limited to 4 MiB plus 16 KiB. Encoding reserves bounded whitespace
for each rotating counter's full decimal width and the longest scope cursor. Page
keys already have fixed-width indexes. An all-unspent rotation therefore keeps
its native storage charge unchanged, including digit and scope-length boundaries.
An update has at most four record changes and 128 exact proof deletions; proof
and old-page deletions run first inside the transaction to release space. Failed writes, capacity
checks and changed originals roll back the whole update and its native storage
charges. No SDK archive redo log remains; SQLite keeps its own journal. The receiver
release queue retains its existing limit, and capture still runs to exhaustion
within one retirement call. These mechanisms do
not bound unrelated wallet history, total database size or physical disk use.
The SDK client file separately reserves completion space within its 32 MiB limit
before funding. Outgoing receipt recovery and retirement use indexed pages scoped
to the exact mint, unit and direction.
The native read limits each page to 128 rows and 4 MiB of stored payload before
decoding; retirement retains candidates from at most one page. Outgoing recovery
shares the native incoming/outgoing eligibility check: exact original proofs use
bounded pages, oversized groups retry smaller pages, and active-operation checks
read only existence. The atomic retirement repeats all checks before deletion.
Oversized or
corrupt evidence stops the operation without skipping records, releasing custody
or falling back to a full-table read. The money lock spans traversal. These bounds
cover receipt enumeration and retirement eligibility reads; full traversal time
remains separate. New-operation proof selection has its separate
inventory limit; it does not cap total historical wallet records.

Proof-history collection uses the same transaction pages across every mint, unit
and direction, including unregistered scopes. It retains ownership only for its
bounded candidate set. Archive transfer and queue collection use this check too;
an owner after earlier pages still prevents deletion. Oversized or corrupt pages
retain the original coins and release queue. An index on timestamp
and ID supports the whole-wallet cursor. This bounds transaction reads and the
retained ownership set; full-scan time remains separate.

Unfinished wallet operations use a shared identity reader: at most 128 creation-time/
UUID headers, then one original recovery record at a time. SQL uses a matching
index and never projects recovery payloads into the header page. Coin collection
inspects each operation with a separate 4 MiB stored-column read bound. It retains
coins named by checkpoints, tokens, receipts and output secrets, and any candidate
row naming an unfinished creator or spender. An unrelated open payment no longer
holds the entire release queue. Missing, changed, corrupt or oversized operation
evidence stops collection; its original recovery record remains untouched.
Cancellation discovery scans all mint/unit
scopes so a later duplicate or foreign preparation still prevents a replacement
send. Native recovery and pending-send/melt enumeration share the same reader.
Deleted cursor rows remain valid, but pages are not a snapshot; the SDK keeps its
existing writer and money locks. Corrupt reads stop the scan, potentially after
previous native operations have completed. Already-admitted records keep their
original size for recovery. The collection-only inspection budget does not bound
recovery payloads, accumulated result lists, traversal time or total wallet storage.

SDK journal and archive reads enforce their existing byte limits before payloads
cross the SQL driver boundary. One statement checks size and conditionally selects
the value; malformed records cannot look absent. Redb checks the borrowed value
before copying it, and unsupported backends fail without an unbounded fallback.
Oversized records remain intact. Restoring current-format evidence permits retry;
older custody redo logs are rejected without decoding their payload. These
individual read limits do not reserve total storage or bound other wallet queries; see the
[accepted scope and checks](READINESS.md#recovery-record-read-bounds).

Before submitting new swap, mint or melt-change outputs, the native wallet requires
durable issuing keys and keyset metadata. A failed optional cache write cannot
substitute for that requirement. Send confirmation, receive, reclaim and preparatory
withdrawal swaps derive private proposals from read-only counter snapshots. A
shared helper validates the exact derived range and issuing keyset; one transaction compares the exact parent
and counter and saves the keys, counter allocation and recovery plan. Rollback
leaves no proposal-owned records or counter increments. Conflicting or uncertain
writes prevent submission, and any committed plan remains available for recovery.
Withdrawal change uses the same transaction to commit its issuing keys, range,
exact request and pending wallet receipt. Receipt conflicts roll back the complete
proposal, and matching terminal receipts keep their status. Standalone swaps and
mint issuance also commit their initial output plans with completion reservations;
see the [accepted wallet scope](READINESS.md#scope-and-outstanding-acceptance).
SQLite single-value writes finish their statement before returning, so a
`RETURNING` value cannot hide a late commit failure.
The SDK reserves logical completion space for channel refunds and abandoned
funding, but service capacity accounting remains disabled until the other wallet
paths and stores are covered. Logical allowances do not reserve physical disk.

For incoming tokens, locally unfamiliar coins require one NUT-07 state query
before native acquisition. Spent, pending, malformed or unavailable results leave
no new acquired coins, recovery operation or allocated output secrets. This
prevents a collected spent token from creating another unresolved receive on
replay. Known local inputs keep their existing ownership checks. The mint must
retain authoritative spent-state history; an unspent answer does not prevent a
later competing spend. After submission begins, errors remain ambiguous and the
original recovery evidence stays protected. This adds a standard mint lookup per
unfamiliar batch, not a FIPS message or a per-packet payment.

Initial mint-quote acquisition saves the original issue journal, every exact
quote reservation and canonical pending receipts together. Output planning and
signing precede acquisition; conflicting snapshots or write failures cannot leave
a partially owned batch. A lost commit reply keeps any committed evidence.
The checkpoint includes original unreserved quotes, secrets, individual derivation
indices, payment method, signed request and compatibility signatures. Submission
and recovery share that checkpoint; restore validates and orders every original
output. Missing or invalid checkpoints, stale journals and conflicting quote
ownership stop recovery before mint submission. The format targets fresh profiles;
submitted records without original evidence cannot be replayed.

Completion atomically publishes verified original outputs and completed receipts,
sets original issued-amount targets, releases quotes and deletes the journal. It
compares the exact journal, owned quote snapshots and complete original proof
records before writing. Later coin states, owners and evidence survive; a stale
attempt cannot revive spent coins or overwrite a newer reservation after another
recovery completes. Already-observed issuance is not credited again, and newer
quote deposits and metadata remain. Prepared cancellation changes existing pending
receipts to failed without publishing coins. A conflict or write failure preserves
the original evidence. Startup and quote-status refresh retain mint reservations
whose journal is missing. Batch rejections keep their original outputs for
recovery; permanently rejected batches still need reconciliation or safe
original-output repartitioning.

Melt orphan cleanup is unchanged. See [issue ownership](READINESS.md#atomic-issue-ownership)
for the accepted revision and regression evidence.

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
After another restart, it requires custody-page progress without new funding or
another financial retirement, while retaining the original sender refund coins.
The paid-fee service case retires both paid and zero-usage channels after actual
expiry, retaining the original signed amounts, redemption reserves and payouts.
It snapshots payout records before retirement, then checks that authenticated
queue references identify the same complete original wallet records afterward.

Coordinator fixtures additionally cover receiver failure before commit, a lost
commit reply, final controller write failure and a mismatched returned history.
Each resumes the original plan once. Legacy pending intents recover both before
and after ledger removal; changed payout/history evidence and incomplete modern
schemas are rejected. These use fixture SDK callbacks through the production
coordinator; actual custody and removal are exercised by the service tests above.
These coordinator tests do not establish whole-wallet storage bounds or physical
power-loss recovery. Exact proof-history collection has the separate ownership
and recovery requirements described above.

The current paged-custody revision passes the complete 336-test SDK workspace
suite, 290 relay library tests and all nine funding process scenarios. Feature
matrix, strict lint, formatting and source-size checks pass with matching source
and dependency fingerprints. This verifies the tested custody and recovery paths;
it does not establish total wallet storage bounds or current-build hardware
acceptance.
