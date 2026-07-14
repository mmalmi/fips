# FIPS Nostr-Mediated Discovery and NAT Traversal

Nostr-mediated discovery lets FIPS nodes find each other and, if
necessary, punch through UDP NAT. A node publishes its reachable transport
endpoints as a signed Nostr event under its own Nostr identity (which is also
its FIPS identity), and peers resolve those endpoints at dial time by npub.
Peer adverts can travel through FIPS's built-in advert-relay path or through
an external provider such as `nostr-pubsub`, whose configured relay and
decentralized pubsub sources remain outside FIPS. For peers behind UDP NAT,
a separate encrypted offer/answer signaling path coordinates hole-punching;
STUN supplies the reflexive address.

Nostr discovery is unconditionally compiled into the `fips` binary on
every supported platform and ships in every stock packaging artifact
(`.deb`, AUR, systemd tarball, OpenWrt `.ipk`, macOS `.pkg`, Windows
`.zip`). It is runtime-opt-in: the YAML configuration defaults to
disabled (`node.discovery.nostr.enabled: false`), so the discovery
runtime stays dormant -- and opens no relay connections -- until an
operator flips the flag. Default relay and STUN-server lists ship in
the config; both are optional overrides. When disabled, nodes behave
exactly as before: only the static `peers[]` addresses are used.

## Role

The feature adds three capabilities on top of FIPS's static peer model:

- **Advertising.** A node publishes the transport endpoints it wants
  peers to use (direct UDP, direct TCP, a Tor onion, or the special
  `udp:nat` rendezvous token) as a signed Nostr event. The advert is
  anchored to the node's FIPS identity key — a peer that knows the npub
  knows the advert is authentic.
- **Lookup.** When dialing a configured peer, or any peer in `policy:
  open` mode, the node resolves that peer's advert from the selected
  peerfinding source and appends the advertised endpoints to its dial list.
  Static addresses are always tried first.
- **UDP NAT hole-punch.** When both sides of a connection have UDP NAT
  endpoints, the advert carries enough information to run a STUN-based
  offer/answer exchange over encrypted ([NIP-59](https://github.com/nostr-protocol/nips/blob/master/59.md))
  Nostr events. Each side observes its reflexive address via STUN,
  exchanges candidate pairs through the relay, and both sides send UDP
  probes at a shared punch time. On the first successful probe, the
  punch socket is handed to FMP and becomes a normal UDP transport.

## When to use it

- **You run a public node** and want peers who know your npub to reach
  you without you distributing an address list out-of-band.
- **You want to reach a peer behind UDP NAT** without deploying a relay
  or running Tor on both sides. The peer advertises `udp:nat` and you
  dial by npub.
- **You want zero-touch peer discovery** within a known application
  namespace (`policy: open`), subject to an admission budget.
- **You want to advertise a Tor onion** so peers don't need to know the
  `.onion` address out-of-band.

Skip the feature when every peer is already reachable through a stable
static address (a LAN mesh, a pre-configured test bed, or a deployment
where operators distribute `peers[]` blocks directly). The feature adds
relay dependencies, STUN round-trips for NAT cases, and a small ambient
background of relay traffic; none of that is useful when you already
know where peers are.

## Build configuration

Nostr discovery is part of the normal build. Plain `cargo build
--release` produces a binary with the discovery runtime available, and
every stock packaging artifact under `packaging/` ships it.

Shipping the feature is runtime-safe: Nostr discovery is **off by
default in the YAML configuration**
(`node.discovery.nostr.enabled: false` in every stock config). An
operator opts in per-node by flipping the flag; until then the feature
is dormant and does not open connections to any relay.

## Scenarios and configuration

Each scenario below gives the minimal YAML fragment that enables it.
Only keys relevant to Nostr discovery are shown; surrounding node,
transport, TUN, DNS, and peer configuration follows the usual shape
described in [fips-configuration.md](fips-configuration.md).

All scenarios assume `node.identity` is set to a persistent key — an
ephemeral identity would invalidate any advert the moment the node
restarts.

### Scenario 1: Advertise a directly-reachable UDP node

The node has a public IP (or a stable port-forward) and binds UDP on a
known port. It publishes `udp:host:port` to the advert relays. Any peer
that knows this node's npub and has Nostr discovery enabled can dial it
without knowing the address out-of-band.

```yaml
node:
  identity:
    persistent: true
  discovery:
    nostr:
      enabled: true
      advertise: true

transports:
  udp:
    bind_addr: "0.0.0.0:2121"
    advertise_on_nostr: true
    public: true
```

What this achieves: the node publishes a single `udp:<public-ip>:2121`
endpoint to the three default advert relays
(`wss://relay.damus.io`, `wss://nos.lol`, `wss://offchain.pub`,
`wss://temp.iris.to`).

What the other side needs: with `node.discovery.nostr.enabled`, a
configured peer can have either static `addresses` or an empty
`addresses` list. Static and Nostr-resolved addresses can also be
combined: when both are present, static addresses are tried first and
Nostr-resolved endpoints are appended as fallback.

### Scenario 2: Advertise a Tor onion node

The node runs a Tor onion service in directory mode (Tor-managed
`HiddenServiceDir`) and advertises the `.onion` address. Peers dial via
their local Tor SOCKS5 proxy without ever knowing the onion string
out-of-band.

```yaml
node:
  identity:
    persistent: true
  discovery:
    nostr:
      enabled: true
      advertise: true

transports:
  tor:
    mode: directory
    socks5_addr: "127.0.0.1:9050"
    directory_service:
      hostname_file: "/var/lib/tor/fips/hostname"
      bind_addr: "127.0.0.1:8444"
    advertise_on_nostr: true
```

What this achieves: the node publishes a `tor:<hash>.onion:8443`
endpoint alongside any other advertised transports. The advert itself
is still published over clearnet WebSocket relays — Tor protects the
data plane, not the discovery plane. See
[Security and threat model](#security-and-threat-model) for the trade-off.

### Scenario 3: Lookup a configured peer by npub (no advertising)

The node does not publish any advert of its own. It only consumes
adverts for configured peers. This is the right shape for a client that
wants Nostr-mediated resolution without becoming a rendezvous target
itself.

```yaml
node:
  identity:
    persistent: true
  discovery:
    nostr:
      enabled: true
      advertise: false
      policy: configured_only

transports:
  udp:
    bind_addr: "0.0.0.0:2121"

peers:
  - npub: "npub1peer..."
    alias: "remote-node"
    addresses:
      - transport: udp
        addr: "203.0.113.45:2121"
        priority: 10
    connect_policy: auto_connect
```

What this achieves: on dial, the static address is tried first; if the
peer has published a newer advert (for example, its public IP has
changed), those addresses are appended as additional candidates.
`configured_only` is the default — it is shown here for clarity.

If you have no static address for the peer at all, omit `addresses`
entirely or leave it empty. Dial endpoints are taken from the advert.

### Scenario 4: UDP NAT hole-punch with a configured peer

Neither side has a stable public UDP endpoint. Both sides advertise
`udp:nat`, run the STUN + offer/answer exchange, and punch through
their NATs to establish a direct UDP link. This is the full
NAT-traversal path.

```yaml
node:
  identity:
    persistent: true
  discovery:
    nostr:
      enabled: true
      advertise: true
      dm_relays:
        - "wss://relay.damus.io"
        - "wss://nos.lol"
      stun_servers:
        - "stun:stun.l.google.com:19302"
        - "stun:stun.cloudflare.com:3478"

transports:
  udp:
    bind_addr: "0.0.0.0:2121"
    advertise_on_nostr: true
    public: false

peers:
  - npub: "npub1peer..."
    alias: "nat-peer"
    addresses:
      - transport: udp
        addr: "nat"
        priority: 1
    connect_policy: auto_connect
    auto_reconnect: true
```

What this achieves: the node publishes a `udp:nat` endpoint plus its
signaling relays and STUN server list in the advert. The peer side runs
the same configuration. When either side initiates, an encrypted offer
is sealed to the peer's npub, a matching answer comes back, and both
sides punch at the negotiated time. On success, the punch socket is
adopted as an FMP UDP transport and Noise IK proceeds normally.

> **Validation:** `advertise_on_nostr: true` with `public: false` on UDP
> requires both `dm_relays` and `stun_servers` to be non-empty. The
> node fails startup with a config validation error if either list is
> empty. This is enforced because a `udp:nat` advert without signaling
> relays or STUN servers is unreachable by construction.

Works best with full-cone NAT on at least one side. Symmetric NAT on
both sides is not reliably traversable with this protocol and will time
out after `punch_duration_ms`; fall back to a Tor or TCP transport in
that case.

### Scenario 5: Open discovery — no pre-configured peers

Under `policy: open`, any node that publishes an advert under the same
`app` namespace becomes a candidate. Discovered peers are queued for
connection attempts subject to `open_discovery_max_pending`.

```yaml
node:
  identity:
    persistent: true
  discovery:
    nostr:
      enabled: true
      advertise: true
      policy: open
      open_discovery_max_pending: 32
      app: "my-experiment.v1"

transports:
  udp:
    bind_addr: "0.0.0.0:2121"
    advertise_on_nostr: true
    public: true

peers: []
```

What this achieves: peers are discovered entirely through ambient advert
traffic on the configured relays. Setting a non-default `app` value
(replacing `fips-overlay-v1`) scopes the discovery set to participants
who opt into the same experiment and avoids being joined to unrelated
overlays that happen to share the default namespace.

> **Scope warning:** Open discovery is an admission-free mode. Any node
> that publishes on the same `app` name and passes the peer-ACL check
> becomes a connection candidate. If you rely on peer ACLs for admission
> control, verify that list is set correctly before enabling this mode.

## Operational knobs

All fields below live under `node.discovery.nostr.*`. Defaults are
defined in `src/config/node.rs`.

| Field | Type | Default | Purpose |
| --- | --- | --- | --- |
| `enabled` | bool | `false` | Master switch. When false, the discovery runtime is not started. |
| `advertise` | bool | `true` | If true, publish this node's own overlay advert. |
| `peerfinding_source` | enum | `relays` | `relays` uses FIPS's built-in kind 37195 relay path. `external` delegates publication, subscription, and queries to the embedding application, normally through a `nostr-pubsub` event bus. |
| `advert_relays` | list | `["wss://relay.damus.io", "wss://nos.lol", "wss://offchain.pub", "wss://temp.iris.to"]` | Relays used to publish and fetch overlay adverts (kind 37195) in `relays` mode. Ignored in `external` mode. |
| `dm_relays` | list | same defaults as `advert_relays` | Relays used only for encrypted offer/answer signaling (kind 21059). They are not a peerfinding source. |
| `stun_servers` | list | `["stun:stun.l.google.com:19302", "stun:stun.cloudflare.com:3478", "stun:global.stun.twilio.com:3478"]` | STUN servers used to observe the local reflexive address before a punch. Peer-advertised STUN values are not used. |
| `share_local_candidates` | bool | `false` | If true, include this node's RFC 1918 / ULA interface addresses as host candidates in the traversal offer. Off by default — sharing private host candidates is only useful when peers are on the same physical LAN, and tends to cause misleading punch successes when an asymmetric L3 path (corporate VPN, Tailscale subnet route, overlapping address space) makes a peer's private IP one-way reachable. Enable per-node only when same-LAN punching is wanted. |
| `app` | string | `"fips-overlay-v1"` | Application namespace. Included in the advert identifier; only peers with the same value cross-resolve. |
| `policy` | enum | `configured_only` | Advert consumption policy: `disabled`, `configured_only`, or `open`. |
| `signal_ttl_secs` | u64 | `120` | TTL on the encrypted offer/answer events. Also caps the wait for an answer. |
| `advert_ttl_secs` | u64 | `3600` | NIP-40 expiration set on this node's published advert. |
| `advert_refresh_secs` | u64 | `1800` | Interval between re-publishes. Must be less than `advert_ttl_secs`. |
| `attempt_timeout_secs` | u64 | `10` | Overall timeout for a single punch attempt (STUN + signal + punch). |
| `punch_start_delay_ms` | u64 | `2000` | Delay between receiving the answer and sending the first punch packet. Gives the remote side time to arrive at the same point. |
| `punch_interval_ms` | u64 | `200` | Gap between successive punch probes. |
| `punch_duration_ms` | u64 | `10000` | How long to keep probing before declaring the attempt failed. |
| `replay_window_secs` | u64 | `300` | How long a session id stays in the replay-detection cache. |
| `max_concurrent_incoming_offers` | usize | `16` | Semaphore cap on inbound offers being processed simultaneously. Excess offers are dropped with a warn log. |
| `advert_cache_max_entries` | usize | `2048` | Max cached peer adverts (LRU by expiry). |
| `seen_sessions_max_entries` | usize | `2048` | Max tracked session ids for replay detection. |
| `open_discovery_max_pending` | usize | `64` | Max peers queued for connection attempts under `policy: open`. |

The per-transport keys are:

| Key | Type | Where | Default | Purpose |
| --- | --- | --- | --- | --- |
| `advertise_on_nostr` | bool | `transports.{udp,tcp,tor}` | `false` | Include this transport's endpoint in the overlay advert. |
| `public` | bool | `transports.udp` | `false` | When `advertise_on_nostr` is true: `true` publishes `udp:host:port`, `false` publishes `udp:nat`. |

## Validation rules at startup

The following combinations are rejected with `ConfigError::Validation`:

- Any transport sets `advertise_on_nostr: true` while
  `node.discovery.nostr.enabled` is `false` or absent.
- A peer has no static addresses while `node.discovery.nostr.enabled` is
  `false` or absent.
- A UDP transport sets `advertise_on_nostr: true` with `public: false`
  (a `udp:nat` advert) but `dm_relays` is empty.
- A UDP transport sets `advertise_on_nostr: true` with `public: false`
  but `stun_servers` is empty.

## Under the covers

The rest of this document describes how the feature works inside the
node. For the on-the-wire event format and NIP references, see the
protocol reference at
[../proposals/nostr-udp-hole-punch-protocol.md](../proposals/nostr-udp-hole-punch-protocol.md).

### Overview

The discovery runtime is a background task group started during node
initialization when `nostr.enabled` is true. In `peerfinding_source: relays`
mode it maintains a `nostr-sdk` client connected to the union of
`advert_relays` and `dm_relays`, and runs advert publication/subscription,
DM subscription, and advert-cache pruning. In `external` mode the advert
publication and subscription loops are absent, direct advert queries are
disabled, and `advert_relays` are not connected. The embedding application
publishes `FipsEndpoint::local_nostr_discovery_advert_event()` and feeds
received adverts to `FipsEndpoint::ingest_nostr_discovery_event()`; the
`nostr-pubsub-fips` adapter provides this bridge for any selected EventBus.
`dm_relays` remain available solely for offer/answer traversal signaling.

```text
                    +-----------------------+
                    |   Discovery runtime   |
                    +-----------------------+
                       |       |       |
        advert publish |       | DM sub (offers, answers)
                       |       |
                       v       v
              +-------------------------+
              |   Nostr relay pool      |  (advert_relays ∪ dm_relays)
              +-------------------------+
                       ^       ^
    advert fetch/cache |       | encrypted signaling
                       |       |
   +----------------+  |       |  +--------------------+
   | connect_peer   |--+       +->|  offer / answer    |
   |  (node side)   |             |  handler           |
   +----------------+             +--------------------+
           |                                |
           v                                v
      +---------+                    +--------------+
      |  STUN   |<-- same socket --->|  UDP punch   |
      +---------+                    +--------------+
                                            |
                                            v
                                   adopt_established_traversal()
                                            |
                                            v
                                      FMP IK handshake
                                      on adopted socket
```

### Phase 1 — Advertisement

Adverts are published as Nostr kind `37195` parameterized replaceable
events (FIPS-specific, in the application-defined replaceable range
`30000–39999`; the digits visually spell `FIPS` — 7=F, 1=I, 9=P, 5=S).
The `d` tag is set to the `app` value (default `fips-overlay-v1`), so
each node has a single, in-place-updatable advert under its identity.
The event is signed with the node's FIPS identity key; there is no
separate Nostr key. A NIP-40 `expiration` tag is set to now +
`advert_ttl_secs`.

The advert content is a JSON document shaped as `OverlayAdvert`:

```json
{
  "identifier": "fips-overlay-v1",
  "version": 1,
  "endpoints": [
    {"transport": "udp", "addr": "203.0.113.45:2121"},
    {"transport": "tor", "addr": "xxxxx.onion:8443"},
    {"transport": "udp", "addr": "nat"}
  ],
  "signalRelays": ["wss://relay.damus.io", "wss://nos.lol"],
  "stunServers": ["stun:stun.l.google.com:19302"]
}
```

`signalRelays` and `stunServers` are only present when at least one
endpoint is `udp:nat`; for advert shapes that cannot involve punching
they are omitted to reduce advert size and keep the relay and STUN
lists private to the nodes that need them.

In built-in `relays` mode, publication happens on startup, again whenever the
set of advertised endpoints changes (for example, when a Tor onion hostname
first becomes available), and on a refresh timer every
`advert_refresh_secs`. The kind 37195 event is parameterized replaceable, so a
newer event supersedes the previous advert. Publication fans the same event to
every `advert_relays` entry. In `external` mode, the pubsub provider owns the
publication cadence and source selection.

### Phase 2 — Lookup

When the node decides to dial a peer that is eligible for Nostr resolution, it
first checks the validated advert cache. In built-in `relays` mode, a cache
miss issues a time-bounded Nostr REQ filtered by `author = peer_pubkey`,
`kind = 37195`, and `#d = <app>` against `advert_relays`. In `external` mode,
a cache miss never starts a direct relay query; the external pubsub provider
fills the same cache via normal FIPS advert ingestion.

Results are kept in an in-memory cache keyed by author npub. Cache
entries carry the advert's expiration time; a periodic prune drops expired
entries, and an LRU-by-expiry eviction enforces `advert_cache_max_entries`.
The built-in long-lived relay subscription or an external pubsub subscription
populates the cache passively, so open-discovery candidates do not require
per-dial fetches.

On cache hit, advert endpoints are appended to the peer's static
address list with lower priority; the static list is tried first.

### Phase 3 — Offer/Answer signaling

For any endpoint shaped as `udp:nat`, dialing triggers an
offer/answer exchange before the first packet is sent. Signaling events
are Nostr kind `21059` (ephemeral, not stored by conforming relays),
gift-wrapped per [NIP-59](https://github.com/nostr-protocol/nips/blob/master/59.md)
and encrypted with [NIP-44](https://github.com/nostr-protocol/nips/blob/master/44.md),
so only the intended recipient can decrypt the payload.

The initiator performs STUN first (see Phase 4), then builds a
`TraversalOffer` containing:

- A unique `sessionId` and a random `nonce` (used to correlate the
  answer).
- Its reflexive address (if STUN succeeded).
- Its list of local (private) addresses for same-LAN paths.
- The STUN server it used, for informational reporting only.
- An `expiresAt` equal to now + `signal_ttl_secs`.

The offer is sealed to the recipient's npub and published to the peer's
preferred signaling relays — the node first tries to resolve the peer's
NIP-65 inbox relay list (kind 10002), and falls back to `dm_relays` if
the inbox-relays fetch fails. Each side also publishes its own inbox
relay list on startup so dialers can discover it.

On the receiving side, an inbound semaphore bounds concurrent offer
processing at `max_concurrent_incoming_offers`. When the semaphore is
full, the offer is dropped with a warn log; this is the primary guard
against offer-spam from a misbehaving or compromised relay. A
`sessionId` replay cache (bounded by `seen_sessions_max_entries`, with
entries valid for `replay_window_secs`) rejects duplicates.

The responder runs its own STUN query and replies with a
`TraversalAnswer` carrying its reflexive and local addresses plus a
`PunchHint { startAtMs, intervalMs, durationMs }` that tells both sides
when to begin probing and how aggressively. If the responder has no
usable addresses at all, it replies with `accepted: false` and a
`reason` string.

### Phase 4 — UDP hole-punch

Each side runs STUN (parsing XOR-MAPPED-ADDRESS from the response, all
other attributes ignored) on the *same* UDP socket it will later use
for punching and for the adopted FMP transport. This is critical: NAT
state is per-socket, so the punch has to reuse the socket that taught
the NAT about this binding.

Given its own reflexive + local addresses and the peer's, each side
builds a candidate-pair plan that tries, in priority order:

1. **Reflexive ↔ reflexive.** The classic STUN path. Tried first because
   it is the only candidate that's reliable across arbitrary network
   topologies — host candidates from one peer that happen to be
   reachable from the other (via a corporate VPN, a Tailscale subnet
   route, or overlapping private address space) will succeed at the
   socket layer in the punch but fail in the FMP handshake when the
   return path doesn't match.
2. **LAN ↔ LAN.** If both sides share a /24 prefix, same-subnet private
   addresses are likely reachable directly. Only fires when both peers
   shared local host candidates (which requires `share_local_candidates`
   to be enabled — off by default).
3. **Mixed.** Reflexive on one side, local on the other — catches
   hairpin and one-side-public scenarios.

At `startAtMs` both sides begin sending 24-byte probe packets on the
candidate pair(s) at `intervalMs` cadence for up to `durationMs`. A
probe carries a 4-byte magic (`NPTC`), a 4-byte sequence, and the
first 16 bytes of `SHA256(sessionId)`; both sides can compute the same
session hash independently from the public `sessionId`, so no shared
secret is needed on the punch path itself. On receiving a valid probe,
a side replies with an `NPTA` ack. The first valid probe or ack seen
from the far side records the working remote address and completes the
attempt.

On timeout (`attempt_timeout_secs` as overall bound,
`punch_duration_ms` as probe window), both sides issue NIP-9 deletes
for their offer and answer events and report failure up to the
discovery runtime's `BootstrapEvent::Failed` channel.

### Phase 5 — Adoption

On success, the discovery runtime emits `BootstrapEvent::Established`
carrying the session id, the punch socket, and the learned remote
address. `adopt_established_traversal()` in the node lifecycle takes
the socket, registers it with the UDP transport layer as a new
transport instance, and calls `initiate_connection()` with the peer's
FIPS identity as the expected remote. FMP's Noise IK handshake runs on
the same socket — there is no "promote link" step between punch and
handshake; the punch socket *is* the FMP socket.

From that moment on, the connection is a normal FMP link and is
subject to the usual liveness (MMP heartbeats), rekey, and removal
behavior. A link-dead event does not re-enter the discovery runtime
automatically; reconnection relies on `auto_reconnect` and the same
dial path that triggered the original punch.

### Auto-connect semantics

Discovery does not itself initiate connections. It only supplies
addresses. Dial attempts originate from the existing peer-connection
machinery:

- **Configured peers** (`peers[]` with `connect_policy: auto_connect`)
  are dialed on startup and on retry. When Nostr discovery is enabled,
  advert endpoints are appended to the dial list with lower priority
  than static entries.
- **Open discovery peers** are assembled from the advert cache, fenced
  by the peer ACL, and enqueued into a bounded retry queue sized by
  `open_discovery_max_pending`. There is no event-driven
  "connect on every advert" — a peer re-enters the queue only when its
  prior attempt has drained.
- **Manual dials** (`fipsctl connect`) can target any configured peer
  and use the same dial path, including Nostr resolution if configured.

### Rate limits and safeguards

| Mechanism | Default | What it prevents | Behavior at limit |
| --- | --- | --- | --- |
| Offer semaphore (`max_concurrent_incoming_offers`) | 16 | CPU and memory exhaustion from offer spam on DM relays. | Warn log, offer dropped. |
| Advert cache (`advert_cache_max_entries`) | 2048 | Memory growth from ambient advert traffic under `policy: open`. | LRU-by-expiry eviction. |
| Seen-sessions (`seen_sessions_max_entries`) | 2048 | Replay of stale `sessionId` values. | Oldest entry evicted. |
| Signal TTL (`signal_ttl_secs`) | 120 s | Indefinite in-flight offers on relays. | Expired offers rejected at validation. |
| Open discovery queue (`open_discovery_max_pending`) | 64 | Unbounded retry queue under ambient advert load. | New candidates skipped until the queue drains. |
| Punch window (`punch_duration_ms`) | 10 s | Endless probe traffic after one side has given up. | Attempt declared failed; sockets discarded. |

Only one of these (`max_concurrent_incoming_offers`) is a load-shedding
mechanism — the rest are capacity bounds. The load-shedding threshold
is deliberately conservative so that a misbehaving relay cannot flood
the node with offers fast enough to starve legitimate traffic.

### Relay model

In built-in `relays` mode, configured advert and DM relays are opened on one
`nostr-sdk::Client`. Publication is fan-out to the target list. In `external`
mode, FIPS does not open or select advert relays; `nostr-pubsub` or another
embedding provider owns the configured relay and decentralized peerfinding
sources. The FIPS client may still open `dm_relays`, but only for traversal
signaling.

For signaling specifically, the node prefers the recipient's NIP-65
inbox relays when available (the recipient publishes its inbox list as
a kind 10002 event to its own DM relays on startup) and falls back to
the local `dm_relays` list otherwise. This keeps the common case
off the sender's DM relays when those are different from the
recipient's, at the cost of one extra NIP-65 fetch per offer.

There is no per-relay rate limiting or health check. The relay model
assumes that an operator chooses relays they trust to be best-effort
available and that outright misbehavior is handled at the offer
semaphore and replay-cache layers downstream.

## Security and threat model

- **Relay operators can observe metadata.** They see which npubs
  publish adverts, to whom offers are sent, and the timing of that
  traffic. The *contents* of offer and answer events are
  NIP-59/NIP-44 sealed — only the intended recipient decrypts them.
  Adverts are public by design.
- **STUN servers see the node's public IP and port.** Only the STUN
  servers listed in the node's own `stun_servers` are ever contacted
  for reflexive discovery. Peer-advertised STUN values are
  informational; a malicious peer cannot steer this node to a
  chosen STUN target. See the doc comment on
  `node.discovery.nostr.stun_servers`.
- **The FIPS identity key signs adverts.** Compromise of
  `fips.key` is compromise of the node's Nostr identity — an attacker
  can publish adverts on behalf of the node. The recovery path is
  the same as for any identity compromise: rotate the key and
  re-advertise. There is no separate Nostr keypair to rotate
  independently.
- **Tor advertising leaks timing via clearnet relays.** When a
  Tor-only node advertises its onion address, the advert itself is
  published on clearnet WebSocket relays. Operators who want full
  unlinkability between the advertising identity and the node's
  IP must route relay traffic through Tor as well — for example by
  running `fips` inside a network namespace with a Tor SOCKS
  proxy as its only egress, or by pointing `advert_relays` and
  `dm_relays` at onion relay endpoints.
- **Open discovery accepts anyone publishing on the same `app`.**
  Admission control is the peer ACL, not the discovery layer. Verify
  the ACL before enabling `policy: open`, and consider using a
  non-default `app` value to scope visibility.
- **Nothing about discovery bypasses FMP.** A successful punch yields
  a UDP socket with a claimed remote identity. That identity is not
  trusted until FMP's Noise IK handshake completes. A peer whose
  advert says "I am npub X at 1.2.3.4:5678" but whose FMP handshake
  presents a different static key is rejected at the mesh layer.

## See also

- [fips-configuration.md](fips-configuration.md) — full configuration
  reference, including all surrounding keys elided from the scenarios
  above.
- [fips-transport-layer.md](fips-transport-layer.md) — UDP, TCP, and
  Tor transport mechanics; the punch socket is adopted as a normal
  UDP transport after handoff.
- [fips-mesh-layer.md](fips-mesh-layer.md) — FMP Noise IK handshake
  that runs on the adopted socket.
- [../proposals/nostr-udp-hole-punch-protocol.md](../proposals/nostr-udp-hole-punch-protocol.md)
  — protocol-level reference for event tags, NIP usage, and the
  on-the-wire offer/answer schema.
