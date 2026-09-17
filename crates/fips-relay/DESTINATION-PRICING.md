# Default and destination prices

`terms.fee_msat_per_kib` is this router's default local forwarding fee. Set it to
zero to offer free local forwarding to any destination, with no destination
roster. `terms.max_rate_msat_per_kib: 0` additionally refuses every positive
aggregate route price. This is a free-only ceiling, including downstream costs;
it does not authorize the router to subsidize a paid continuation.

`ServiceConfig.destination_fees` is an optional map from a canonical destination
`npub` to this router's fee in millisatoshis per KiB. Omit it or use `{}` to retain
the existing default `terms.fee_msat_per_kib`. Set an exact destination's value to
zero for free local forwarding, or a positive value for a different price.
Overrides work with either a paid or free default.
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
hop, offer ID, expiry and byte quota. Incoming and outgoing books each hold at
most 128 offer records and 16 per neighbor, including superseded offers retained
until expiry. Re-reading the current offer does not reset its usage; a superseded
offer cannot become active again. Rejected replacements leave the current grant
intact. Expired entries retire during installation; status counts may include
expired entries until then. New offers may explicitly grant a fresh allowance
within those limits; cycling offer IDs cannot bypass the retained-record caps.
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
Optional source price selection can save a paused zero-ceiling authorization for
an explicitly opened free route. This preserves the free-only limit on restart
without authorizing automatic purchases. Automatic free-route refresh, an
aggregate free-bandwidth allowance and paid traffic priority remain separate work.

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

`tests/destination_service.rs` runs six scenarios, each using five real service
processes over loopback UDP:

- Two default-free scenarios deliver to multiple destinations without destination
  rules or a return allowance, before and after restart. They use distinct,
  unavailable mint URLs and observe no mint requests, funding or monetary journal
  changes. The optional source-selection scenario waits for observed native tree
  convergence and verifies that its paused free-only authorization survives
  restart. Routes are explicitly reopened.
- A zero-ceiling source rejects a paid prefix without funding or data delivery.
- A default paid prefix followed by free relays opens exactly one payment channel,
  leaves the free suffix unfunded, and settles with all 256 test sats conserved.
- The original destination-specific scenarios cover free destination isolation,
  restart, differing paid prices, zero local markup over a paid continuation and
  policy changes. The mixed-price case settles two channels and conserves all
  512 test sats.

`tests/route_quotes.rs` exercises paid and default-free quotes over TCP-FIPS. It
covers cache reuse, concurrent misses, bounded request handling and provider-side
reuse of the current free grant. Unit tests cover configuration, exact identities,
expiry, quotas, atomic admission, paid/free exclusions and saved authorization.
Regression tests reject superseded offer reuse, including after a paid switch;
cycling new offer IDs cannot evade the per-neighbor or global retained-record
bounds, and a rejected replacement preserves the current allowance.

Verification passed all 142 relay library tests, both quote scenarios and all
six service scenarios. The optional-selection restart scenario also passed two
additional runs with fresh identities. Strict all-feature/all-target relay
Clippy, default library/binary checks, formatting and the source-size gate pass.

This acceptance scope uses configured peers and explicit free-route opens. It
does not establish automatic free renewal, a rate-limited free tier, traffic
priority, mobile radio behavior or globally optimal routing. Optional
[source price and quality selection](PRICE-SELECTION.md) has its own acceptance
scope; without it, quotes follow the native FIPS-selected path. See
[readiness](READINESS.md) for the wider deployment limits. The optional
[bounded return allowance](RETURN-ALLOWANCE.md) now covers native quality reports
from an unfunded recipient on a tested reverse path. Reports remain outside the
free handshake classifier; enabling destination pricing alone does not enable
that return allowance or prove feedback availability on an arbitrary route.
