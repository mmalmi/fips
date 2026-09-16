# Destination prices and free routes

`ServiceConfig.destination_fees` is an optional map from a canonical destination
`npub` to this router's fee in millisatoshis per KiB. Omit it or use `{}` to retain
the existing default `terms.fee_msat_per_kib`. Set an exact destination's value to
zero for free local forwarding, or a positive value for a different price.
At most 64 entries are accepted; each price must fit the configured price cap.
Addresses must be canonical public identities, not IPs, interface names or aliases.

Zero fees require fresh accounts explicitly using `terms.billing:
"forwarding_data"`. Do not change the immutable terms of a saved account to
enable this feature. Destination rules are outside those terms and may change
for future offers on restart. Existing agreements, evidence, signed balances,
capital reservations and lifetime spending limits remain intact.

## Price composition

The quoted price is the local fee plus the onward quote. A zero local fee cannot
waive somebody else's charge or authorize a subsidy. For example, local fees
of 0, 1024 and 2048 msat/KiB yield a source quote of 3072 msat/KiB. Each paid
relationship still needs its normal funding and spending authorization.

When every remaining hop quotes zero, forwarding uses free permissions rather
than a zero-value payment channel. A paid prefix can use a free continuation
without funding that continuation. One channel can still carry paid quotes for
several destinations, including a destination where this router adds no markup.

## Opening and bounds

The service's existing admin `buy` operation calls `Controller::open_route`.
Paid replies contain `purchase`; free replies contain `free_route`. The older
library `buy_route` and automatic paid watch API retain their paid semantics;
they do not automatically refresh free routes.

Each free permission binds the authenticated neighbor, destination, actual next
hop, offer ID, expiry and byte quota. Incoming and outgoing maps each hold at
most 128 entries and 16 per neighbor. Re-reading the same offer does not reset
its usage. Expired entries retire during installation; status counts may include
expired entries until then. New offers may explicitly grant a fresh allowance.
There is no lifetime free-byte cap; discovery/control rate limits remain separate.

Transit admission reserves both free sides together. For a paid prefix with a
free continuation, rejected upstream traffic consumes no onward free allowance.
Admitted bytes consume quota even if transport submission later fails. No free
admission creates buyer payment evidence or financial credit.

Free permissions are volatile. Reopen after restart, expiry, quota exhaustion or
a route change. A newly paid continuation does not trigger automatic funding
from a free permission. Close an active paid agreement before offering the same
neighbor/destination relationship for free; concurrent paid activation and free
incoming permission are mutually excluded. Financial history is retained.

## Mint availability

Direct service initialization and startup load local receiver state without an
HTTP request. Free route opening and traffic also require no mint requests.
New paid funding refreshes the receiver's mint keys before verifying its proof;
success is cached for 60 seconds, failure for one second, with a ten-second
request deadline. Missing receiver state is an error and is not recreated by
refresh. A newly rotated keyset may be rejected until the success cache expires.
Existing payment verification continues to read the receiver's stored keysets.

This does not make funding or settlement offline operations. The existing
OpenWrt readiness wrapper also still waits for the configured mint; no-mint
startup evidence below concerns running the service directly.

## Evidence and remaining work

`tests/destination_service.rs` runs five real service processes over loopback UDP.
One test delivers through three free relays to an unfunded destination, restarts
and resumes, rejects an unpurchased different destination and observes zero mint
requests. Another mixes free destinations, different paid prices, zero local
markup over a paid continuation and a paid prefix with a free tail. It retains
financial state across a policy change and settles two channels, conserving all
512 test sats. Unit tests cover exact identities, bounds, quotas, expiry,
atomic admission and active paid/free exclusions.

This milestone passed 77 distinct focused tests: 33 relay unit, ten buyer, seven
controller/helper, two customer, 12 durable, three existing service, one bootstrap
service, two destination service, one quote integration and six native quality
checks. Strict relay all-target/all-feature Clippy, default library/binary checks,
Android ARM64 app Clippy with measurements, formatting and the 643-file size gate
passed. Two pre-existing test assumptions were corrected: the stalled-neighbor
helper now matches FIPS identity independently of public-key parity representation,
and the idle customer check observes bounded payment quiescence before measuring.

These tests do not establish permissionless admission, automatic free refresh,
mixed radio acceptance or price-optimal routing. Quotes still follow the native
FIPS-selected path. [Readiness work](READINESS.md) requires combining existing
MMP quality observations with price selection. The optional
[bounded return allowance](RETURN-ALLOWANCE.md) now covers native quality reports
from an unfunded recipient on a tested reverse path. Reports remain outside the
free handshake classifier; enabling destination pricing alone does not enable
that return allowance or prove feedback availability on an arbitrary route.
