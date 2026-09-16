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
native data-return evidence and cannot verify one-way delivery. An observed
outbound carrier change resets derived quality estimates on its first attributable
report. An existing timestamp echo must identify traffic no earlier than the first
data sent on that carrier; late reports about the former carrier cannot qualify
or penalize its replacement. Session traffic counters are retained. Unannounced
onward-path changes and overlapping traffic still limit attribution. A quiet,
previously answered session loses fresh quality evidence without being
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

## Local allowance admission

An embedding application's optional `OriginatedSessionObserver::prepare` receives
the current routed carrier and exact sealed session-envelope length before an
established FSP record reserves a sequence number, coordinate warmup or sent-data
metrics. It can reject the local attempt, reserve a tracked accounting token,
allow untracked traffic, or defer to the original post-seal ciphertext observer.
The default is defer, preserving existing passive observers. Direct session
transports and manual Noise handshake envelopes retain their existing paths.

A rejected local attempt cannot create a sequence gap or pretend to be wire loss.
A locally refused control record does not quarantine its healthy carrier. Coordinate
and packet-size updates preserve the authenticated reply carrier while it remains
usable; the updates do not silently move reports to an unrelated forwarding path.
A tracked token follows both encryption stages and completes once as locally
submitted or unconfirmed, including cancellation. Reservations are conservative:
an uncertain outcome does not refund quota automatically. This is memory-only
local admission, not a durable receipt or an end-to-end delivery guarantee.

Unknown destination ancestry uses a one-entry destination coordinate rather than
the sender's coordinates, so a cold-cache setup still names its real destination
and can qualify for the strict bounded handshake allowance. It does not invent a
tree route or bypass native routing/handshake authentication.

## Handshake recovery

Initial setup, rekey and final-message replay retain their Noise state, exact
retry payload and established/pending keys before awaiting a transport send.
A canceled local completion cannot withdraw a packet already delivered to the
peer. Existing retry, timeout and admission limits still apply; this adds no
delivery receipts. Initial setup with a definitive missing route remains refused
before a new session is inserted. Coordinate warmups preserve the key-epoch bit
when adding their coordinate flag, so a rekey cannot label new-key ciphertext as
belonging to the old epoch.

## Controller responsibilities

The caller must validate the downstream route and authorize its spending before
binding it. This API chooses only the adjacent carrier; it neither fixes every
onward hop nor proves that relays follow an advertised path. MMP is aggregate
quality evidence, not proof of individual packet delivery, an exact per-path
counter across overlapping in-flight traffic, or evidence of honest forwarding
by each relay. The paid controller's [impairment acceptance](../fips-relay/PRICE-SELECTION.md#reproducible-acceptance)
covers bounded loss, delay and asymmetric return loss. It does not prove correct
attribution under arbitrary malicious reports or simultaneous onward-path changes.

A price chooser must still bound unknown-path trials, honor destination fees,
budgets and capital limits, avoid oscillation, and recover accepted bindings
after restart. Native forwarding admission must keep traffic aligned with
accepted financial agreements. None of these responsibilities can be inferred
from a positive quality sample.

## Verification

`cargo test -p nvpn-fips-core --lib new_carrier_does_not_inherit`
reproduces a 700-ms carrier poisoning a 20-ms replacement's smoothed RTT and a
late old-carrier report qualifying the replacement. Both are rejected/reset
without resetting traffic counters or introducing a new wire record.

`cargo test -p nvpn-fips-core --features sim-transport --lib handshake_retention`
uses the existing SimNetwork with local completion delayed after wire delivery.
It cancels each initial and rekey handshake send, plus duplicate-ACK replay, and
checks retained state followed by actual endpoint delivery. An ordinary rekey on
the same carrier also exercises coordinate warmups through authenticated epoch
cutover. These eight cases reproduced failures before the fixes and now pass.
They do not establish that every earlier intermittent setup stall had this cause.

`cargo test -p nvpn-fips-core --lib source_routes` covers binding capacity,
non-neighbor/local rejection, independent transit routing, cached carrier
replacement, failure without fallback and rebind invalidation without resetting
traffic totals. It also reproduces local control-budget refusal and coordinate/
packet-size refresh without false route failure or loss of reply affinity, with
fallback still available when the retained carrier disconnects.

`cargo test -p nvpn-fips-core --lib source_admission` covers scalar/batched denial,
unchanged sequence/coordinate/send counters, exact encrypted-envelope size and
single completion across the FSP/FMP stages. It also checks cancellation,
untracked admission and compatibility with the passive observer.

`cargo test -p nvpn-fips-core --features sim-transport --test source_routes`
uses four real endpoints on the existing SimNetwork carrier. In both native
routing modes it obtains receiver-report RTT and goodput on one branch, drops
transit while keeping neighbor links alive, checks that a lone unanswered burst
remains timed out after the sender goes quiet, then explicitly selects the
other branch and verifies payload delivery and renewed native quality. It does
not use higher-layer acknowledgments or financial delivery receipts. It does
not yet test an automatic monetary chooser, adversarial report forgery, payment
switching, wireless links, or production readiness.
