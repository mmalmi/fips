# Optional TollGate adapter proposal

This is a local design proposal, not implemented or accepted interoperability.
The first integration would expose FIPS customer entry alongside an ordinary
TollGate Internet service. FIPS forwarding must remain purchasable when the
customer has no ordinary Internet entitlement.

## Existing contracts

TollGate already defines time- and byte-based allotments. Its HTTP interface
accepts a bearer payment, derives a device identifier from the network context
and returns a session event. The Go implementation uses NoDogSplash to gate
ordinary access and tracks per-customer usage; it also buys upstream access.
These are useful existing components, but a TollGate session is not a FIPS
neighbor channel or destination agreement. Reviewed upstream references:

- [TIP-01 allotments and sessions](https://github.com/OpenTollGate/tollgate/blob/0c242a1f8fc6d224493a8fcde33707f748d27bad/TIP-01.md).
- [HTTP-01 payment and discovery](https://github.com/OpenTollGate/tollgate/blob/0c242a1f8fc6d224493a8fcde33707f748d27bad/HTTP-01.md).
- [Go module responsibilities](https://github.com/OpenTollGate/tollgate-module-basic-go/blob/74cd6f994864d685016b5eb97617c86fd2dbc967/README.md)
  and [data-session metering](https://github.com/OpenTollGate/tollgate-module-basic-go/blob/74cd6f994864d685016b5eb97617c86fd2dbc967/docs/data-session-management.md).

FIPS already has an opt-in [local UDP customer entry](CUSTOMER-ENTRY.md),
authenticated TCP/FIPS quote and payment services, and a shared native customer
library used by the [Android bench app](../fips-relay-app/README.md). Reuse these
interfaces and the existing Cashu service. The adapter adds no peer operation,
per-packet payment, delivery receipt or alternative accounting implementation.
The [eight peer operations and compatibility limits](README.md#peer-protocol)
remain the wire contract.

## First integration

| Component | Responsibility |
| --- | --- |
| TollGate portal and ordinary access gate | Keep the existing Internet purchase and entitlement flow; offer a separate FIPS setup link. |
| Optional local adapter | Publish only operator-approved public setup information. It holds no wallet and cannot initiate spending. |
| Native FIPS customer | Preview the provider identity, endpoint, destination, mint, tariff and budget; require explicit setup/purchase consent; retain its own keys and recovery state. |
| FIPS relay | Authenticate customers, enforce admission and forwarding policy, quote onward cost, update persistent neighbor channels and settle through the existing service. |

Use an explicit setup link and the existing test-profile format for the first
isolated demonstration. Do not invent TollGate event tags or a public discovery
endpoint and present them as agreed upstream standards. Automatic discovery or
a production profile format would require a separately reviewed contract.

Publish the entry's FIPS public identity and customer-facing UDP address, intended
test destination, accepted test mint and billing basis. Budget and price limits
are proposed customer choices, not remote permission to spend. The native client
must preview them and preserve its immutable account policy. Treat the setup
link as untrusted input: authenticating the advertised FIPS key establishes
possession of that key, not that the advertised operator or mint is trustworthy.

Serve this information from explicit public configuration. Do not proxy the
private operator socket or its full status response to a guest web client.
Keys, tokens, wallet paths, topology and financial history stay private. MAC/IP
identifiers used by the ordinary access gate cannot authorize a FIPS debit or
replace its authenticated payer identity.

## Reachability and charging

The guest subnet needs DHCP/local bootstrap, the selected local FIPS UDP listener
and a bounded path to the accepted test mint before any Internet purchase.
The three peer control services are inside FIPS; do not expose host TCP ports
for them. Keep management services isolated. Exhausting an ordinary TollGate
session must leave this FIPS entry reachable without granting unrestricted WAN
forwarding. Conversely, paying a FIPS relay must not open the ordinary access gate.

FIPS retains its existing sender-pays model. Each relay buys onward service under
its own configured price, capital and lifetime limits. Accepting customer funds
does not authorize buying from arbitrary customers. The adapter must not fund
these channels from TollGate's wallet, duplicate its proofs, translate each FIPS
payment into a TollGate session, or reset FIPS history when an Internet session
expires. Ordinary access and FIPS forwarding have separate prices and counters;
the acceptance run must prove which service accounts for each traffic path.

Use `forwarding_data` consistently for a fresh test path when bounded unpaid
session establishment is desired. Sustained return payload needs its sender's
paid route or an explicitly configured free policy. The optional
[earned return allowance](RETURN-ALLOWANCE.md) is bounded and cannot promise a
general download service. An eventual Internet exit would need an explicit
return-payer and reimbursement arrangement; the adapter does not implement one.

Forwarded quote traffic keeps the ordinary priced accounting and existing
request/cache limits. Local bootstrap reachability is not a free remote quote
tunnel. Free or discounted destinations remain ordinary
[FIPS operator policies](DESTINATION-PRICING.md), independent of portal sessions.

## Current limits

The native customer and profile are test-only: local numeric endpoints, an
explicit local HTTP test mint, finite test-fund limits and explicit account
setup. The Android app sends test payloads; it is not an Internet VPN or
production wallet. An ordinary browser cannot use this UDP customer interface
by opening the portal alone. Matching-build FIPS tests do not establish an
independent TollGate client or mixed-version peer implementation.

## Acceptance before an upstream contribution

Extend the existing isolated customer/service harness, using disposable test
funds, with the adapter and real TollGate gate. Keep the same FIPS accounting
implementation and reuse its recovery assertions. Required observations:

1. A customer without a TollGate purchase can discover the advertised FIPS entry,
   reach the test mint, buy a three-relay route and deliver accounted traffic.
   Ordinary WAN forwarding and management access remain blocked.
2. Starting, exhausting or restarting an ordinary Internet session neither
   removes FIPS bootstrap access nor changes FIPS agreements, balances or limits.
   Captures and both services' counters identify any overlap in metering.
3. Each direction has explicit authority; unpaid reverse application traffic
   stays bounded or blocked. Each paid relay earns its expected amount and final
   settlement conserves test funds, including after a relay/adapter restart.
4. A forged setup profile, MAC change, repeated portal request or lost reply
   cannot spend the operator's wallet, replace a customer account, create a
   second debit or expose private status. Unavailable mint/relay failures leave
   the original recoverable intent intact and ordinary access policy unchanged.
5. The current Pixel client and selected OpenWrt target pass the same isolation
   and lifecycle checks when hardware testing is available. Record exact builds,
   tariff, limits, both payer policies and evidence; do not infer radio or device
   acceptance from the process harness.

The first upstream proposal should be the optional public setup link and bounded
local entry configuration, accompanied by this demonstrated separation of
entitlements. Further TollGate wire extensions or Internet-exit billing need
their own interoperability evidence. No implementation or contribution is
claimed by this document; [production readiness](READINESS.md) remains separate.
