# Source path choice and native quality

FIPS already measures link and end-to-end session quality with MMP. Embedding
applications can read that native state and explicitly choose the first hop
for session payload and reports. The API adds no wire messages, measurement
protocol, financial receipt or payment authority.

## API

`FipsEndpoint::source_route_quality(destination, feedback_window)` returns:

- The actual most recent outbound next hop, separately from a planned route.
- Whether session receiver reports are enabled, recent native delivery
  evidence, and whether an unanswered burst exceeded the feedback window.
- Session-smoothed RTT, most recent forward-loss sample when available, and
  useful bytes per second. Numerical estimates are absent when delivery
  feedback is stale or missing; absence does not mean zero loss.
- Cumulative session application-data packet and byte counters. These survive
  rebinding, but are not durable financial counters or transport wire totals.

The window is clamped to 50 ms through 60 s. Choose it with regard to path
latency and report cadence; session report intervals can reach 10 s. A short
window can label a slow working path as unresponsive. Minimal MMP mode uses
native data-return evidence and cannot verify one-way delivery. RTT and goodput
are smoothed session estimates whose history may include previous paths. A
quiet, previously answered session loses fresh quality evidence without being
declared failed merely because it is idle.

`FipsEndpoint::set_source_route(destination, Some(neighbor))` binds the first
hop to a currently sendable authenticated neighbor. It replaces the cached
session output carrier and invalidates delivery attribution, even when the
same neighbor is supplied again (for example, after its onward path changes).
Avoid redundant rebinding if the path did not change: it discards useful
feedback. Passing `None` removes the binding and restores native selection.

Bindings are volatile, capped at 64 destinations and persist until changed or
cleared. An unavailable chosen neighbor fails closed; there is no automatic
switch to a potentially unpriced provider. Existing in-flight packets may still
use the previous carrier. Transit routing and native Noise setup/reply rules
remain independent. No binding is installed by default.

## Controller responsibilities

The caller must validate the downstream route and authorize its spending before
binding it. This API chooses only the adjacent carrier; it neither fixes every
onward hop nor proves that relays follow an advertised path. MMP is aggregate
quality evidence, not proof of individual packet delivery, an exact per-path
counter across overlapping in-flight traffic, or evidence of honest forwarding
by each relay. Attribute observations carefully across route changes; delayed
reports and asymmetric return paths require additional controller acceptance
tests before using the result to compare monetary offers.

A price chooser must still bound unknown-path trials, honor destination fees,
budgets and capital limits, avoid oscillation, and recover accepted bindings
after restart. Native forwarding admission must keep traffic aligned with
accepted financial agreements. None of these responsibilities can be inferred
from a positive quality sample.

## Verification

`cargo test -p nvpn-fips-core --lib source_routes` covers binding capacity,
non-neighbor/local rejection, independent transit routing, cached carrier
replacement, failure without fallback and rebind invalidation without resetting
traffic totals.

`cargo test -p nvpn-fips-core --features sim-transport --test source_routes`
uses four real endpoints on the existing SimNetwork carrier. In both native
routing modes it obtains receiver-report RTT and goodput on one branch, drops
transit while keeping neighbor links alive, checks that a lone unanswered burst
remains timed out after the sender goes quiet, then explicitly selects the
other branch and verifies payload delivery and renewed native quality. It does
not use higher-layer acknowledgments or financial delivery receipts. It does
not yet test an automatic monetary chooser, adversarial report forgery, payment
switching, wireless links, or production readiness.
