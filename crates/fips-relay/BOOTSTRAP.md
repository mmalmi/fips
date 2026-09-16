# Bounded unpaid session establishment

The explicitly selected `forwarding_data` tariff lets a sender purchase a path
through relays to a recipient with no funded wallet or reverse route purchase.
It uses the same cumulative per-attempt accounting as `forwarding_attempt`,
excluding strictly shaped FSP session-establishment messages from paid evidence.
Application traffic in either direction still needs that direction's purchase.

## Compatibility and operation

For a **fresh isolated account**, select `terms.billing = "forwarding_data"`
before explicit initialization. All paid relays on that route must offer the
same billing basis. Quotes and accepted contracts carry it explicitly. Old
binaries reject the unknown tariff; they do not silently reinterpret it.

Existing `unique_session_envelope` and `forwarding_attempt` accounts retain
their semantics. The saved manifest rejects changed financial terms. Do not
edit manifests, delete journals or reinitialize a funded account to enable this
feature. An in-place migration with outstanding obligations is not implemented.
This milestone does not change the physical test bench or Android profile.

`PaidForwarder::for_billing` installs the allowance for the new tariff.
`PaidForwarder::new` retains the old behavior. Both the buyer observer and the
seller ledger exclude eligible messages under the new tariff, so a free
handshake cannot create a claim, payment evidence or perpetual idle usage polls.
The low-level ledger alone rejects these free messages; it cannot supply the
separate allowance. The service's existing startup gate still applies.

## Eligibility and bounds

The core classifier uses the existing codecs. Eligible messages must have the
current exact prefix/version, canonical encoding, known flags and fixed Noise
payload sizes: Setup 33 bytes, Ack 57 bytes, Finish 73 bytes. Clear Setup/Ack
coordinates must match the envelope's claimed end-to-end addresses. Trailing
bytes, altered lengths, unknown phases and envelopes over 2,048 bytes are not
eligible. Established encrypted traffic and plaintext session errors are not
free under this rule. The size ceiling is an allowance limit, not an FSP limit.

Every admitted handshake consumes `max(session_envelope_bytes, 256)` units:

| Scope | Burst | Refill per second |
| --- | ---: | ---: |
| One authenticated ingress identity | 16,384 | 4,096 |
| Entire relay | 65,536 | 16,384 |

These are session-byte units with a minimum packet charge, not physical link
bytes or airtime. At most 64 neighbor entries are retained. An entry retires
after 60 seconds without an admission, longer than its four-second full refill.
Changing claimed source/destination, reconnecting or churning identities does
not reset the relay-wide bucket. Local and aggregate debits commit together;
rejection for an exhausted peer cannot drain other peers' aggregate allowance.
Rejection at the aggregate limit allocates no peer state. Capacity exhaustion
fails closed. The budget is consumed even if transport submission later fails.

Status exposes admissions, session bytes, charged units, rate/capacity denials
and tracked peers under `bootstrap`; old tariffs return null. Counters and rate
limits are volatile and reset on process restart. They are not financial state.
Financial agreements, liabilities, limits and recovery remain durable.

## Threat and evidence boundaries

Structural recognition is **not** end-to-end authentication or proof of delivery.
Noise verification remains at the endpoints. A malicious peer can place chosen
bytes inside a syntactically valid handshake. Thus this is a bounded free
forwarding allowance, not a proof that every admitted byte is useful control.
The ingress bucket uses the authenticated adjacent peer, never the claimed
end-to-end source. An identity flood can consume shared capacity and deny
bootstrap availability; the limits bound forwarded work, not fairness or all
CPU spent rejecting traffic. Native link/endpoint admission limits still apply.

Local five-process integration verifies: unpaid handshakes cross three relays
without delivering unpaid application data; one forward purchase delivers to
an unfunded recipient; all identities and agreements survive a full restart;
unpaid reverse application traffic remains blocked; idle payment counters stop;
only three channels settle; all 1,024 issued test sats remain conserved and
each relay earns a fee. This is a loopback UDP test, not radio-mobility evidence.
Ledger tests cover old tariff compatibility, both sides excluding free evidence,
malformed envelopes, duplicate completion, compact histories and durable reload.
Limiter tests cover shared capacity, identity churn, entry retirement and refill.

Verification for this milestone: 58 distinct focused tests passed (26 relay
library, 10 buyer, 12 durable, two customer, one native settlement, three existing
service, two bootstrap ledger, one one-way service and one core classifier).
The strengthened startup/free-completion test also passed after its final edit.
Strict relay all-target/all-feature Clippy, default library/binary checks,
Android ARM64 app Clippy with profiling, formatting and the source-size gate
passed. These checks do not replace the broader acceptance below.

Remaining work includes independent bounds for other discovery/control paths,
impaired-link/rekey/hostile-input combinations, mixed transports, payment-specific
overhead and physical-device regression. This allowance does not implement
permissionless discovery or destination-specific free application forwarding.
