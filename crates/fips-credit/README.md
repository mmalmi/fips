# FIPS service credit

`CreditForwarder` implements the existing native forwarding admission hook.
Controllers install an `Allowance` returned by the shared `peer-payments`
durable store; packet admission performs no database, network or signature work.
No FIPS wire format or routing semantics change.

Each window binds the local provider, authenticated ingress neighbor, next hop
and final destination. Claimed packet source cannot select a different payer.
The service is explicitly `fips.forwarding.attempt_bytes`: admitted encrypted
session bytes, not evidence of delivery. Neither failed nor successful local
submission refunds a window or produces a financial receipt. Settlement requires
the separate, signed service protocol and the application's verified meter.

Install the policy with `FipsEndpoint::builder().forwarding_policy(...)` only for
the service it controls. For a Cashu relay, use
`PaidForwarder::with_peer_credit` in `fips-relay`: existing active Cashu routes keep
priority, and incoming credit cannot bypass the buyer's approved onward purchase
or negotiated free route. Separate completion-token namespaces prevent counting
one packet against another payment method. Exhausted Cashu routes retain their
normal renewal behavior without silently consuming credit. The bounded bootstrap
tier remains available when data-completion slots are full.

Application discovery and automatic activation are still separate integrations;
do not replace a running Cashu relay's policy with the standalone adapter.
`remove` disables a route without refunding its reservations.
Dropping the owning payment store or closing an agreement revokes its windows.

Tests exercise route/source substitution, quota exhaustion and uncertain sends,
then route real FSP traffic through three native endpoints on `SimNetwork`, with
no mint, before revoking forwarding. Relay composition tests also negotiate real
signed credit through the shared controller, check onward spending authorization,
interleave Cashu/credit completions and disable credit while Cashu continues.
These are functional checks, not throughput
benchmarks. Native FIPS control traffic retains the core's existing treatment.

The two vendored credit libraries are development snapshots from `cashu-service`;
their `SOURCE.json` files bind each source file by hash. They are not claimed as
published releases. That repository owns the accounting implementation and tests.
The workspace patches `peer-payments` to this snapshot. When testing with a local
`cashu-service` override, also override `peer-payments` to the same checkout's
`crates/peer-payments`; both services must resolve one copy of `cashu-credit`.
