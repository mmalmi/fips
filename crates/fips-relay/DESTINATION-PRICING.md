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
Paid replies contain `purchase`; free replies contain `free_route`. The `watch`
operation uses the same reply shape and accepts a zero price ceiling on a
`forwarding_data` account. The older library `buy_route` remains paid-only.

Each free permission binds the authenticated neighbor, destination, actual next
hop, offer ID, expiry and byte quota. Incoming and outgoing books each hold at
most 128 offer records and 16 per neighbor, including superseded offers retained
until expiry. Re-reading the current offer does not reset its usage; a superseded
offer cannot become active again. Rejected replacements leave the current grant
intact. Expired entries retire during installation; status counts may include
expired entries until then. New offers may explicitly grant a fresh allowance
within those limits; cycling offer IDs cannot bypass the retained-record caps.
There is no lifetime free-byte cap; discovery/control rate limits remain separate.

Optional `free_bandwidth` service configuration limits negotiated free-data
admission across all destinations and grant renewals:

```json
"free_bandwidth": {
  "global_bytes_per_second": 16384,
  "global_burst_bytes": 32768,
  "peer_bytes_per_second": 4096,
  "peer_burst_bytes": 8192
}
```

Omitting this setting preserves the existing grant quotas without adding a rate
limit. Rates must be positive; peer rates and bursts cannot exceed their global
limits, and the peer burst must be at least 256 bytes. Every admitted packet
consumes its session-envelope length or 256 units, whichever is larger, to bound
small-packet processing. Oversized packets and exhausted budgets are dropped;
the limiter does not queue them. Choose bursts large enough for the intended
packet size. These are admission units, not measured radio airtime or wire bytes.

The global bucket covers all neighbors; a neighbor bucket binds its authenticated
identity, not claimed source/destination addresses. At most 64 neighbor buckets
are retained, and an idle bucket cannot retire before its full refill time.
Rejected permissions consume neither bandwidth nor onward grant quota. Local
paid admission with a free continuation does not use this free-data rate budget.
Bootstrap and optional earned return allowances have separate existing limits.
Budgets are volatile and restart with a full burst; they are not durable spending
caps. Status exposes admissions, charged units, denials and tracked neighbors in
`free_routes.bandwidth`. This setting does not offer a second service tier for
the same destination. Local scheduling is described below.

Transit admission reserves both free sides together. For a paid prefix with a
free continuation, rejected upstream traffic consumes no onward free allowance.
Admitted bytes consume quota even if transport submission later fails. No free
admission creates buyer payment evidence or financial credit.

Free permissions are volatile. One-shot routes need reopening after restart,
expiry, quota exhaustion or a route change. A newly paid continuation cannot
exceed the saved watch ceiling. Close an active paid agreement before offering the same
neighbor/destination relationship for free; concurrent paid activation and free
incoming permission are mutually excluded. Financial history is retained.
Optional source price selection can save a paused zero-ceiling authorization for
an explicitly opened free route. This preserves the free-only limit on restart
without authorizing automatic purchases.

## Local traffic scheduling

The relay assigns a scheduling class in the same admission decision that reserves
accounting. Locally authorized paid data uses the ordinary data lane; negotiated
free traffic and optional earned return traffic use a background lane. Strictly
validated session handshakes retain protocol priority under their applicable
admission limits. A peer cannot promote data by setting a packet header flag.
No new wire message or payment receipt is required. Embeddings using the older
admission hook retain the core's existing protocol classification.

Background transit has separate waiting limits: 32 packets per node and 16 per
outgoing neighbor or claimed source. Overflow returns immediately to the receive
loop. Crypto work admits at most four background packets across its worker pool
and one per owner, subject to the smaller configured capacity. Control and
ordinary data run first; ordered work already in progress for that owner still
finishes before later packets. Waiting free traffic does not make local/control
ingress wait or count as a failed route. Shutdown still completes or cancels its
pending accounting obligations.

These are local queue and crypto bounds. They do not reserve Wi-Fi airtime,
preempt bytes already sent to a socket/radio, or guarantee minimum free throughput
under continuous paid load. Native `show_status`/`show_routing` now expose
`forwarding.drop_background_full_packets` and `drop_background_full_bytes` for
this waiting-window overflow. These are subsets of the existing send-error totals;
bytes count the received session datagram, not radio airtime.

A five-process loopback test sends 64,000 free packets at 16,000 packets/s alongside
24 paid packets through the same outgoing neighbor. The strict acceptance run
observes background queue overflow during paid delivery, delivers every paid
packet without corruption or duplication, and reconciles automatic payments
before the free stream ends. Free admission stays within the configured bucket,
a fresh free stream succeeds after refill, and settlement conserves all 256 test
sats without changing the free source's financial journals. This is bounded local
congestion evidence; physical-radio and wider load measurements remain outstanding.

With the development dependencies from [funding costs](FUNDING-COSTS.md), run:

```sh
FIPS_RELAY_REQUIRE_BACKGROUND_PRESSURE=1 cargo test -p fips-relay \
  --all-features --test destination_service \
  concurrency::paid_delivery_progresses_during_free_traffic_and_free_resumes_idle \
  -- --exact --test-threads=1 --nocapture
```

Without the environment flag, the test verifies concurrency and reports whether
queue pressure occurred. The strict mode rejects a run with no observed overflow
during paid delivery; offered rate alone is insufficient evidence of congestion.

## Automatic source watches

An explicit `watch` with `max_rate_msat_per_kib: 0` persists permission to obtain
new free grants for that destination. It never authorizes a paid purchase, even
when the service-wide ceiling allows positive prices. A positive watch ceiling
allows paid offers only under the existing spending and capital limits. Free
grants require neither monetary budget nor a common mint.

Healthy free grants are retained without quote requests or journal writes when
source price selection is disabled. The source checks its remaining allowance,
expiry and native next hop at most once per five seconds. A normal grant nearing
expiry or quota exhaustion is replaced through a fresh recursive quote request,
so its downstream grants are refreshed too. Existing quotes, quotas and retained
history bounds remain unchanged; this is not an extension of an old allowance.
With price selection enabled, native quality checks retain their separate trial
and retry rules. Source authorization survives restart; grants and measurements
remain volatile. `pause_route_refresh` stops new grants after its current work
finishes, and a paused watch does not reopen after restart.

The operator must size `quote_max_units` and `quote_lifetime_secs` together.
For example, a 1 GiB grant over 300 seconds covers about 28.6 Mbit/s of admitted
session bytes before exhaustion; this is a byte budget, not a measured throughput
guarantee. Small grants can exhaust the 16-per-neighbor or 128-total retained-offer
limits before their history expires. Upkeep then fails closed and backs off;
it does not erase history or reset quotas. Several destinations and overlapping
replacements share those bounds. Shared downstream traffic can exhaust a grant
before an individual source does, so arbitrary fan-in has no uninterrupted-service
guarantee. Choosing between free and paid tiers for the same destination remains
separate work.

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

`tests/destination_service.rs` and its modules define eleven scenarios, each
using five real service processes over loopback UDP:

- Two default-free scenarios deliver to multiple destinations without destination
  rules or a return allowance, before and after restart. They use distinct,
  unavailable mint URLs and observe no mint requests, funding or monetary journal
  changes. The optional source-selection scenario waits for observed native tree
  convergence and verifies that its paused free-only authorization survives
  restart. Routes are explicitly reopened.
- A zero-ceiling source rejects a paid prefix without funding or data delivery.
- A default paid prefix followed by free relays opens exactly one payment channel,
  leaves the free suffix unfunded, and settles with all 256 test sats conserved.
- Configured free limits bound two authenticated neighbors and their shared node
  budget without contacting a mint. The separate concurrency case above checks
  paid and free delivery, local queue pressure and automatic payment progress.
- The original destination-specific scenarios cover free destination isolation,
  restart, differing paid prices, zero local markup over a paid continuation and
  policy changes. The mixed-price case settles two channels and conserves all
  512 test sats.
- A single free-only watch delivers beyond its initial quota and expiry, then
  resumes after all five processes restart. A paused watch stays paused through
  another restart. Distinct unavailable mints receive no requests; financial
  journals remain unchanged. Healthy idle grants make no control requests or
  journal writes across multiple refresh checks.
- A free-only watch refuses paid repricing despite a positive service-wide
  ceiling, without funding or delivery, then recovers when free service returns.
- A paid watch refreshes an expired free suffix while retaining its original
  payment channel and funding record. The free suffix remains unfunded; final
  settlement conserves all 256 test sats.

`tests/route_quotes.rs` exercises paid and default-free quotes over TCP-FIPS. It
covers cache reuse, concurrent misses, bounded request handling and provider-side
reuse of the current free grant. Unit tests cover configuration, exact identities,
expiry, quotas, atomic admission, paid/free exclusions and saved authorization.
Regression tests reject superseded offer reuse, including after a paid switch;
cycling new offer IDs cannot evade the per-neighbor or global retained-record
bounds, and a rejected replacement preserves the current allowance.

The free selector regressions also exercise authenticated TCP-FIPS negotiation
and actual source/provider grant admission. Promotion obtains a fresh full grant
after a trial supersedes the cached offer. An expired unproven trial can carry
only its exact unused allowance; missing or exhausted quota fails closed. These
focused tests inject quality observations; the separate paid-path simulations
exercise native feedback under loss, delay and asymmetric connectivity.

The upkeep verification passes all 152 relay library tests, all nine service
scenarios, the existing automatic paid-watch scenario and all three paid-path
scenarios. Strict all-feature/all-target relay Clippy, default library/binary
checks, formatting and the 719-file source-size gate pass. The new free lifecycle
test fails against the previous watch implementation at its initial zero-ceiling
request. The preceding default-free milestone also passed both quote scenarios.

This earlier acceptance scope uses configured peers and explicit source authority.
It does not establish mobile radio behavior or globally optimal routing. The
subsequent rate-limit and local scheduling checks have the narrower scope
described above and in readiness. Optional
[source price and quality selection](PRICE-SELECTION.md) has its own acceptance
scope; without it, quotes follow the native FIPS-selected path. See
[readiness](READINESS.md) for the wider deployment limits. The optional
[bounded return allowance](RETURN-ALLOWANCE.md) now covers native quality reports
from an unfunded recipient on a tested reverse path. Reports remain outside the
free handshake classifier; enabling destination pricing alone does not enable
that return allowance or prove feedback availability on an arbitrary route.
