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

Install the policy with `FipsEndpoint::builder().forwarding_policy(...)` for
the service it controls. Call `remove` to disable a route. Closing the agreement
or dropping the owning payment store revokes its windows. Reserved units remain
charged to their original window.

Run `cargo test --locked -p fips-credit` from the repository root. The tests
cover authenticated ingress, quota exhaustion and uncertain sends. A three-node
test sends native FIPS traffic across a relay and verifies that revoking the
agreement stops forwarding.

The two vendored credit libraries are development snapshots from `cashu-service`.
Each `SOURCE.json` records the hashes of the upstream source files. The adapter
uses these snapshots through local Cargo dependencies.
