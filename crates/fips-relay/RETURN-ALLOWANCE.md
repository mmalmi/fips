# Bounded return traffic for native quality monitoring

FIPS already measures link and end-to-end quality with MMP receiver reports.
The handshake-only free tier cannot carry established encrypted reports from
an unfunded recipient. A real five-process test reproduced this: forward data
arrived through three paid relays, but the source obtained no session RTT sample.

An optional local `return_allowance: true` service setting now gives an admitted
forward path a small, bounded return allowance. It requires `forwarding_data`
billing, defaults to false and does not rewrite saved financial terms. Existing
paid reverse agreements retain normal admission and accounting; their quota or
credit limits cannot fall back to this allowance. This is a complimentary local
policy, not a negotiated guarantee that every relay supports a return route.

## What it permits

Relays cannot inspect the encrypted message type. The allowance therefore admits
opaque small replies, including native reports and potentially application data.
It is not a report-only exemption and cannot provide cryptographic proof of
delivery. Endpoints retain normal FIPS authentication and replay validation.

Each allowance binds all four local facts: authenticated returning neighbor,
reverse next hop, original destination and claimed original source. A changed
neighbor, next hop or address does not match. Only paid or explicitly free
forward admission earns credit. Rejected traffic, free handshakes and replies
admitted by this allowance earn none. No return admission creates payment
evidence, a channel, a wallet debit or authority to purchase an onward path.

Admission earns credit before the local transport outcome is known. It does not
prove that a forward packet arrived. The bound includes packets whose outgoing
submission later fails. Return credit is volatile and independent of financial
journals; a restart loses it, and fresh admitted traffic can earn it again.

## Fixed limits

| Limit | Value |
|---|---|
| Largest return session envelope | 2,048 bytes |
| Credit earned per admitted forward envelope | Its length, clamped to 512–2,048 bytes |
| Stored credit per exact path | 4,096 bytes |
| Minimum credit/rate charge per return packet | 256 units |
| Expiry | 30 seconds after last admitted forward packet |
| Tracked paths | 128 total; 16 per returning neighbor |
| Neighbor rate budget | 2,048-unit burst; 1,024 units/second |
| Aggregate rate budget | 8,192-unit burst; 4,096 units/second |
| Rate-budget identities | 64, with 60-second idle retirement |

Replies consume credit and both rate budgets together. A denial cannot consume
another flow's credit or the aggregate allowance. Replies cannot extend expiry.
Expired paths retire on forward admission; status counts can include expired
entries until then. Churning source addresses or identities cannot exceed these
state and aggregate limits. There is no fairness or report-delivery guarantee
under hostile contention. Restart resets these non-financial rate limits.

The rate limiter is shared code with the handshake allowance, with independent
budgets and unchanged handshake limits. The prices and charged units of existing
paid agreements remain intact. A live paid incoming or outgoing relationship
for the reverse destination suppresses the complimentary path; its reports use
that paid relationship instead. Asymmetric paths and movement need new forward
admission on the corresponding edges before a free reply can pass.

## Evidence and limits

The five-process paid test now observes native session RTT and positive delivered
throughput across multiple report intervals, repeats after full restart, and
keeps the recipient unfunded. Bulk unpaid reverse traffic is limited, idle
payment control becomes quiet, three paid channels settle and all 1,024 test
sats are conserved. The handshake-only case retains its previous behavior.

The separate free-destination test enables the same allowance with no funded
channels, observes native quality before and after restart and requires zero
mint requests. Unit checks cover exact reverse binding, expiry, credit/rate/
state limits, rejected-forward exclusion and precedence of existing paid quotes.

Verification: 66 distinct focused tests passed (38 relay unit, ten buyer,
12 durable, two customer, two bootstrap/quality process and two destination
process tests). Strict all-target/all-feature relay Clippy, default library/binary
checks, Android ARM64 app Clippy with measurements, formatting and the source-size
gate passed. The process checks use production native MMP metrics, not a synthetic
acknowledgment or a separate delivery monitor.

This is loopback UDP evidence. Impaired and asymmetric links, mobility, hostile
contention, paid/free transition races, mixed transports, overhead and controlled
hardware acceptance remain part of [readiness work](READINESS.md). Oversized
reports and depleted budgets may be dropped. Silence means unknown quality,
not a free or working path. Monetary cost-aware routing and its simulations are
still required; these changes reuse the native measurements rather than adding
another reporting or receipt protocol.
