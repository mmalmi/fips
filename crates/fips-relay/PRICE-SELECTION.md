# Source route price and quality selection

This opt-in policy compares real adjacent providers' downstream quotes and binds
the accepted source route to the selected provider. Transit still uses the native
FIPS planner. It is a bounded local search, not a globally cheapest-path algorithm
or a delivery guarantee. The broader [readiness work](READINESS.md) remains active.

## Decision rule

1. Read the existing native end-to-end MMP observations for the actual source
   carrier. No encrypted application acknowledgments are inspected.
2. Exclude a provider while it is in cooldown after missing delivery feedback or
   exceeding the configured loss/round-trip-time ceilings.
3. Rank remaining offers by estimated delivered cost:
   `quoted millisats per 1024 bytes / (1 - measured loss fraction)`.
   Thus a price of 1000 at 50% loss has estimated cost 2000; an unmeasured price
   of 1500 merits a limited trial when the quality ceiling permits that loss.
4. Keep the active eligible route unless the alternative improves this score by
   more than the configured margin. Equal costs retain the current carrier.
5. A new or retried path gets a quota-limited agreement. Fresh native feedback
   with valid finite RTT and loss can qualify the path for the provider's normal
   quota on the next authorized selection. The normal spending/capital ceilings
   still apply; qualification is not unlimited credit.

The score is an estimate from packet-loss statistics, not an exact invoice per
application byte. Framing, packet sizes, correlated loss and retransmissions can
change the actual delivered cost. RTT is an eligibility limit, not an arbitrary
weight added to money. Raw observed goodput is not treated as link capacity:
an idle or lightly loaded client has low throughput even on an excellent link.

Unknown alternatives use their advertised cost as an optimistic lower bound for
a limited trial. Idle missing feedback is unknown, not automatically a failure.
Only the active path can qualify for a larger allowance. Recently used paths
retain a bounded cost sample for one feedback window after their last eligible
observation, so switching does not instantly forget measured loss. Expired or
evicted samples become unknown and can merit another limited trial. Native
estimates restart after an observed carrier change; reports whose timestamp echo
predates that carrier's first data cannot qualify or penalize it. Unannounced
onward changes and overlapping in-flight traffic remain attribution limits.
These are aggregate quality observations, not per-packet receipts or proof
against a dishonest participant.

## Configuration and authority

`ServiceConfig.price_selection` is absent by default. To opt in on a
`forwarding_data` account, its default settings are:

```json
{
  "price_selection": {
    "feedback_timeout_ms": 15000,
    "retry_after_ms": 60000,
    "trial_max_units": 32768,
    "min_improvement_percent": 10,
    "max_loss_percent": 25,
    "max_rtt_ms": 5000
  }
}
```

These are local selection settings outside saved financial terms. They do not
change a legacy account's billing basis. Existing accepted agreements, channels,
accounting and lifetime budgets remain intact. Upgrading an account's immutable
tariff still requires the documented explicit migration/reconciliation process.

`watch` authorizes periodic selection for a destination under its saved aggregate
price ceiling. One-shot `buy` or `open` records a paused source marker for recovery;
it does not authorize ongoing alternative purchases. Transit resale cannot
activate a local source binding merely because this router bought onward service.
Free `open` can select a free path; watches remain paid-only and do not yet support
automatic paid/free/direct transitions.

For an unfunded receiver, enable [return allowance](RETURN-ALLOWANCE.md) on the
corresponding forwarding-data relays if native reports need earned reverse credit.
The selector itself does not grant reverse service. Its 15-second default window
allows for native session-report intervals up to 10 seconds. The integration test
uses a shorter 2-second window to exercise failover; it is not a deployment default.

Wire peers on the quote path must support `requested_max_units` and the `trial`
offer marker. A capped request propagates downstream; oversized caps or an
incorrect trial marker are rejected. Old strict decoders reject this optional
request rather than silently returning an uncapped trial. Omitted optional fields
preserve the default wire form, but saved trial offers require the newer reader.
Do not downgrade an account containing them without reconciliation.

## Bounds and recovery

- [Quote caching](README.md#price-cache-and-request-bounds) reuses full validated
  offers for up to 30 seconds without extending their expiry or financial limits.
  Quality is still observed on each selection; a cached price does not qualify a
  failed path. Explicit fresh/trial requests retain their existing semantics.
  Changes behind an unchanged neighbor may remain unseen until cache refresh;
  nested caches do not provide a network-wide 30-second convergence guarantee.
- At most 32 source destinations, four concurrent candidate quotes per round,
  16 failed providers and 16 recent quality samples per destination. The current
  provider stays in the candidate set; other connected neighbors rotate through it. Quote rounds and
  accepted-path activation are serialized. Each round shares a five-second
  deadline; capped negotiation has its own five-second deadline.
- Cooldown keys the authenticated provider, so a new quote ID or advertised path
  cannot evade it. Repeated observations do not extend its retry time forever.
  An expired entry may be evicted at capacity; otherwise admission fails closed.
- Polling an unchanged unqualified trial reuses its existing cumulative quota.
  Automatic channel renewal cannot reset an active trial. A fresh authorized
  trial/upgrade retains prior accounting and shares the existing neighbor channel
  where usable. A failed-path retry is a new capped agreement, not renewed grace.
  Explicit fresh requests obtain fresh offer IDs. Ordinary renewal requests a
  fresh quote from the same provider and validates the complete previous service;
  it does not run source discovery for a transit purchase.
- Discovery alone does not change forwarding. Binding follows free-route
  authorization or durable paid acceptance. Recovery checks current accepted,
  non-retired state under the route-change lock before restoring a source binding.
- Source ownership persists; measurements/cooldowns are volatile. Controller
  reload restores the accepted binding without granting another quota or channel.
  Old path obligations remain locked until settlement and confirmed refund.
- Trial caps bound each agreement, not the total number of future authorized
  trials. Lifetime spending, capital and bounded retained-history limits remain
  the aggregate bounds. State exhaustion is an error, never an account reset.

Established source records under forwarding-attempt/data tariffs now reserve
their exact sealed session bytes against the existing buyer allowance before
FIPS reserves packet sequence numbers or sent-data metrics. Known exhausted,
expired or inactive purchases reject the local attempt. Free source records use
the same lease counter as onward forwarding. This prevents local quota refusal
from creating artificial wire loss, without adding a second financial ledger.
Local control refusal also leaves native carrier health unchanged. Coordinate and
packet-size refreshes retain a usable authenticated reply carrier, preserving the
branch on which an unfunded receiver has earned bounded return allowance.
Completion still follows local transport submission; canceled work retains its
conservative quota reservation. The legacy unique-envelope tariff keeps its
post-seal ciphertext/deduplication observer and is not changed into a source gate.

Unknown/unpurchased routes and direct endpoints retain their original admission
paths, so bounded bootstrap and earned return traffic can still reach the relay's
gate. This is not a universal source authorization gate. Seller credit/grace,
payment failures, channel capital/lifetime budgets and network loss remain
distinct constraints; early quote admission alone cannot explain every missing
report. Financial signing/forwarding limits continue to apply separately.

## Reproducible acceptance

```sh
cargo test -p fips-relay --features measurements --lib \
  --test bootstrap_service --test buyer --test controller --test customer \
  --test destination_service --test durable --test priced_paths \
  --test route_quotes --test service
```

The real four-endpoint `SimNetwork` diamond uses production quotes, controllers,
native forwarding/receiver reports and isolated Cashu test-money channels. All
four spanning-tree root positions select the cheaper healthy relay, upgrade its
trial in the same channel, then replace it when it drops transit while continuing
to answer adjacent control traffic. The more expensive path carries payload and
native feedback; cooldown prevents immediately buying the failed cheap path.
Controller/selector reload retains the working route, purchase history and capital.
Both old and current channels settle, conserving all 259 isolated test sats per run.

The same harness also runs two seeds for each of three carrier impairments:

- 35% loss on the cheap relay's forward link. The loss ceiling allows the path,
  but measured delivered-cost ranking selects the slightly dearer alternative.
- 250-ms latency in each direction on that link. Native RTT exceeds the configured
  150-ms ceiling and the replacement must meet it with fresh native feedback.
- Complete loss of the reverse link only. Forward payload still arrives, but
  missing end-to-end reports makes the source select the working alternative.

These six deployments pause automatic quote refresh only while collecting
attributable evidence; payment tasks continue. They then invoke the production
selector and verify actual replacement payload, earned return allowance, reload,
history/capital limits and complete test-money settlement. They reuse SimNetwork's
packet delivery and a removable directional override, not injected quality values
or an alternate routing model. They do not prove unattended convergence during
arbitrary concurrent churn. A native regression reproduces inherited RTT and late
old-path reports; filtering existing timestamp echoes fixes both without adding
financial receipts or resetting traffic/accounting counters.

A separate exhaustion case repeats three fresh deployments and leaves automatic
renewal enabled beyond its configured threshold. An exhausted trial stays capped before and after controller/selector
reload, preserves history/capital and settles without resetting the lifetime
budget. It first proves actual application delivery, then confirms that locally
refused excess traffic does not increase native sent counters or quarantine the
healthy provider. It checks that every admitted application packet arrives. These reloads retain the live FIPS endpoints and control servers; they are
not full network/process restart tests. Unit checks cover hostile cap metadata,
quality ceilings, cooldown, hysteresis, remembered alternative costs, bounded
state and a 125-case independent
cross-product reference for the delivered-cost choice.

The final acceptance run passed 92 focused tests with measurements enabled across
the relay library, priced paths, buyer, durable accounting, controller, quotes,
customer, service, bootstrap and destination suites. Core checks also passed:
66 targeted route/discovery/session regressions, the two pre-seal admission tests,
and the earlier dataplane/observer/profile checks. Strict all-target/all-feature
core and relay Clippy, the default relay library/binary check, Android ARM64 app
Clippy with measurements, formatting and the 658-file source-size gate passed
(five unchanged legacy core exceptions).

A subsequent handshake-recovery check passed all 150 core session tests,
including the eight cancellation/epoch regressions and bidirectional delivery
across 100 nodes. The simulator's 10 tests and both paid-path tests (four root
positions and three exhaustion runs) also passed. Strict core/relay/simulator
linting, Android ARM64 linting, the default relay check, formatting and the
659-file size gate passed. These are software checks, not updated device results.

The latest impairment run passed all three paid-path tests (13 deployments in
total), 111 dataplane tests, 32 route-metric tests, 12 metric tests, two transport
tests and 10 simulator tests. Strict core/relay/simulator and Android ARM64 linting,
the default relay check, formatting and the 660-file size gate also passed.
The latest broad session check was **not green**: 148/149 tests passed with the
100-node case run separately. Sparse-session recovery failed once in the combined
run, then both sparse cases passed alone. The 100-node case failed its first
forward payload despite established sessions on both endpoints; a freshly rebuilt,
unchanged baseline also failed. These remain readiness issues, not waived gates.

## Remaining limitations

Initial handshake failure before data is transmitted can remain unknown rather
than trigger end-to-end timeout. Deterministic core tests now reproduce and fix
lost initial/rekey state when a send completes remotely but is canceled locally,
including duplicate-ACK replay. They also fix coordinate warmups clearing the
key-epoch bit after rotation. All eight [recovery cases](../fips-core/SOURCE-ROUTES.md#handshake-recovery)
pass with actual payload delivery. The earlier intermittent setup stalls are not
all proven to share these causes. Quote exhaustion is now locally gated, but
remote credit/grace exhaustion, interrupted payments and missing return allowance
still need explicit attribution before penalizing a provider. No eligible alternative leaves the
existing agreement/binding in place; applications can still emit billable traffic
within its bounds. This is not an automatic stop-on-poor-quality source gate.

Further acceptance must extend the bounded loss/delay/asymmetry cases to misleading
reports, multiple simultaneously changing paths/prices, renewal races,
full restarts, longer operation, free-route transitions, mobile merge/split,
permissionless admission, mixed links and physical devices. No throughput or
selection-overhead benchmark is claimed. The physical routers remain unchanged.
