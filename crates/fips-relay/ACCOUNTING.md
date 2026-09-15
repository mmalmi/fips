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
through the isolated Cashu mint. Keep its actual test result separate from a
physical deployment claim: r4's documented hardware cutoff is historical
evidence, and the new tariff needs its own wireless installation and measurement.
