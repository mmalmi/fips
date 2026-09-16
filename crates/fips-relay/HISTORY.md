# Bounded route evidence

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

## Controller integration boundary

`BuyerAuthorizer::retire_closed_routes` and `DurableRelay::retire_closed_routes`
are trusted local maintenance APIs, not network requests. The timestamp comes from
the local controller's clock. The seller wrapper persists the rollup before
returning; retirement validates the entire batch before changing live state. A failed
write suspends subsequent durable mutations; seller admission also suspends until
recovery. Recovery can safely retain the old detailed records if the replacement
journal never became durable.

**Automatic retirement is not enabled yet.** The controller must first retain a
recoverable retirement intent spanning its requested/outgoing/incoming routes,
renewals, replacements and settlements. Only then may it fold the accounting
records and remove the corresponding controller references. Calling the accounting
APIs alone against a running controller can prevent startup reconciliation from
reinstalling an old agreement. Do not use them as an operator cleanup command.

Whole-channel retirement also remains unfinished: it must retain wallet debit and
verified refund evidence, cumulative signed spending, remaining unpaid exposure,
and protection against replayed funding. The current 16-channel funding limit
still applies. These route rollups are the shared accounting foundation for that
work, not completion of long-running history management.

## Journal compatibility and checks

Buyer journals use version 3 and seller snapshots use version 5. Existing buyer
versions 1/2 and seller versions 3/4 load with zero retired totals and retain their
original evidence and billing mode. New versions require an explicit, internally
consistent rollup field; missing fields are rejected. Older executables reject
the new versions, so do not downgrade a profile after it has been opened by this
code. Controller funding-journal migration is separate and remains incomplete.

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
