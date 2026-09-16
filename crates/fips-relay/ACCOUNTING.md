# Forwarding attempts and bounded packet evidence

`terms.billing: "forwarding_attempt"` explicitly selects the new tariff for a
fresh service account. It buys local forwarding attempts, measured in bytes of
the opaque session envelope. Each router still charges its authenticated
previous neighbor and purchases onward service from the next one. Source
authorization, aggregate prices, channel capacity, lifetime spending and unpaid
exposure limits remain independent bounds.

## What counts as another attempt

FIPS authenticates a link frame and checks its replay counter before exposing a
transit request to the policy. Replaying that encrypted link frame cannot create
another admission. Changing a captured frame's counter without a valid tag also
fails authentication and cannot advance the receive window. The policy receives
an authenticated neighbor identity, not an authenticated end-to-end sender claim.

A neighbor can deliberately transmit the same inner session envelope again in a
fresh authenticated link frame. That is another requested forwarding attempt
under this tariff. Native retransmission can therefore incur another charge;
ordinary radio retries that duplicate the same FIPS frame do not. A successful
local transport submission does not prove radio acknowledgment, next-hop receipt
or final delivery. Receipt-based delivery guarantees are not part of this tariff.

The buyer authorizes cumulative payment only up to its own submitted attempts
and any explicit advance, subject to capacity and lifetime budget. A provider's
usage report alone cannot create buyer evidence. A relay obtains upstream
admission before creating an onward obligation. Unsolicited traffic cannot open
channels, create source authorization or authorize reverse traffic. An operator
must fund and authorize each sending direction independently.

## Records that remain

The seller retains cumulative reserved, submitted and unconfirmed bytes for each
contract, plus the associated channel totals and crash exposure. The buyer
retains cumulative observed and submitted bytes and the signed obligation for
each channel. Both retain individual records only for unfinished local sends.

Admission assigns a process-owned token. Completion removes that pending record
and adds its bytes to the appropriate completed total. Repeated completion of a
token does nothing. Once a seller seals its claim or a process restarts, a late
outcome cannot turn previously unconfirmed usage into that bill. Tokens are not
wire receipts and no peer can submit completion callbacks.

The number of unfinished records is capped by `max_pending` (1,024 by default).
Completed traffic does not consume `max_packets_per_contract`. Local submission
still respects the contract byte allowance, channel credit, persisted allowance
window and arithmetic bounds. Quotes and channels still have separate count
limits; their safe retirement remains work before indefinite service across
unbounded route changes and renewals can be claimed.

Durable ordering is unchanged: reserve the allowance window before exposing it,
checkpoint submitted totals before reporting a claim, and persist buyer liability
before signing. Recovery moves saved pending attempts into unconfirmed totals.
The unrecorded portion of the seller's persisted window remains lost, unbilled
exposure; it is not refunded as fresh credit. Compact totals do not reconstruct
missing buyer evidence from a seller's report.

The storage bound for this tariff depends on retained channels/contracts and
unfinished sends, not the number of completed packets. These totals are trusted
local accounting state, not cryptographic proof of fair delivery. Protect the
private state directory just as the wallet and signed-balance journals.

## Size the window for packets and session setup

The durable window is shared by session setup and application envelopes. A
funded channel can still refuse a datagram when its remaining checkpoint window
is smaller than that envelope's price. The router drops that attempt without
reserving or billing it; it does not queue the packet for the next checkpoint.
Earlier hops can still charge for their own successful forwarding attempts.

For example, at 3,072 msat/KiB, 512 bytes of session setup cost 1,536 msat.
A subsequent 1,060-byte opaque envelope costs another 3,180 msat and cannot fit
the rest of a 4,000-msat window. A checkpoint restores enough room for a new
attempt; an 8,000-msat window can fit both in the same interval. Actual setup and
envelope sizes depend on the session and payload. Neither choice guarantees
delivery, and application retries are independently billable attempts.

Choose the window from the aggregate route price, largest envelope and expected
burst between checkpoints. A window smaller than one full-priced envelope can
prevent that packet size from ever passing. The adaptive runtime now checkpoints
consumed windows locally, separately from payment timing; see [CADENCE.md](CADENCE.md).
Credit and saved allowance still bound throughput when control or disk work is
slow. Increasing the window also increases possible unrecorded crash exposure
and must stay within the relationship's grace and capacity. Set these terms before
initializing the account; do not edit saved financial state to tune a live account.

Native `show_routing` reports `drop_policy_denied_packets` and
`drop_policy_denied_bytes` separately from missing routes, MTU errors and failed
transport sends. These count any forwarding-policy refusal, not just window
exhaustion. Like the other native forwarding counters, bytes include the FMP
datagram rather than only the billable session envelope. Use the seller's
durable usage and ceiling alongside these counters to diagnose allowance loss.

## Explicit agreement and compatibility

The billing basis travels in route offers and accepted contracts. A service
rejects a downstream offer using a different basis. Renewal must preserve it,
and saved source watches retain it alongside their price ceiling. Receiving a
new offer or reconnecting a radio cannot silently change it.

Omitting `billing` means `unique_session_envelope`, the original prototype
tariff. Its ciphertext fingerprints and 4,096-record limit remain enforced.
Earlier accounts keep that meaning when loaded. The service manifest includes
the billing basis in its immutable terms; editing an existing configuration to
select a different tariff is rejected. Initialize an explicitly funded new test
account when comparing tariffs. Do not reset an existing account or its spending
history to bypass a limit.

The new reader accepts legacy buyer journal version 1 and seller snapshot version
3. Subsequent writes use versions 2 and 4 respectively. Old executables cannot
read those newer accounting formats. Keep a full stopped-account backup before
an upgrade; replacing only the executable is not a financial-state rollback.
Newer formats validate completed totals, unfinished records, channel sums and
obligation limits on load. Legacy files cannot opt into the new tariff merely
by adding a field to an old-format packet table.

## Verification scope

Focused checks exercise 10,000 repeated-content attempts beyond a deliberately
tiny legacy record limit, duplicate callbacks, bounded pending work, cumulative
budget rejection, compact journals, crash windows, final sealing and legacy
account interpretation. A native receive-path check replays captured encrypted
link frames, injects an unauthenticated high counter and sends a fresh frame
containing the same inner envelope.

The five-process service scenario selects the new billing basis on all nodes,
negotiates real paid routes through three relays and sends 6,000 application
packets in each direction. It checks compact stopped-account journals, restarts
all processes, kills/restarts the middle relay, continues traffic and settles
through the isolated Cashu mint. The subsequent r5 wireless run delivered streams
of 6,000 and 12,000 packets per direction, retained compact journals and renewed
source channels automatically. Renewal interrupted delivery; it is not seamless.
See [WIRELESS-ACCOUNTING.md](WIRELESS-ACCOUNTING.md) for the separate physical
evidence, resource costs, settlement and limitations. The r4 cutoff remains
historical evidence for the legacy tariff.
