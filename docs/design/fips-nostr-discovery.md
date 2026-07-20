# Nostr peer and service discovery

> **Status:** Implemented.

FIPS uses Nostr only as a bounded discovery and signaling plane. Public kind
`37195` adverts identify peers and describe reachable physical transports and
services. Encrypted NIP-59 kind `21059` events carry UDP traversal offers and
answers. Applications may distribute both through configured Nostr relays,
decentralized `nostr-pubsub`, or a composition of the two.

Nostr events are not a FIPS physical transport. In particular, FIPS wire
records are never wrapped in ephemeral relay events. A node needs a physical
adjacency such as WebSocket, WebRTC, Ethernet, UDP, TCP, or Tor before it can
exchange authenticated FIPS traffic.

## First adjacency and upgrades

A browser or native client that starts with no peer addresses can dial one or
more explicit `wss://` seed URLs. The WebSocket connection carries ordinary
FIPS records and the normal Noise handshake authenticates the peer. Because a
URL does not identify the seed's FIPS key, a client first sends a 13-byte
nonce-bound key-hint request and receives the seed's 45-byte key-hint response.
The hint is untrusted routing metadata; Noise IK remains the authentication
boundary. All later binary WebSocket messages are exactly one complete FIPS
record. A native seed may expose a plain-WS listener on a loopback or private
address behind a TLS reverse proxy.

Once an authenticated adjacency exists, FIPS link negotiation can establish a
better direct WebRTC, UDP, TCP, or other configured path. Link selection is
transport-neutral: a healthy direct path may preempt the WebSocket bootstrap
path, while the WebSocket connection can remain available for control traffic.

## Ownership boundary

FIPS owns advert construction, validation, expiry, and the authenticated link
negotiation that follows discovery. The embedding application owns relay and
pubsub provider selection.

```text
 configured relays and/or decentralized nostr-pubsub
                  |
  signed adverts + encrypted traversal signals
                  |
        validated peer/service cache
                  |
      direct physical adjacency
       /       |        |        \
     WSS     WebRTC     UDP      TCP
```

The external peerfinding provider may be `nostr-pubsub-fips`. Relay-backed
`nostr-pubsub` also carries encrypted UDP bootstrap signaling; it does not turn
a Nostr relay into a FIPS packet carrier.

## Configuration

Peerfinding lives under `node.discovery.nostr`:

```yaml
node:
  discovery:
    nostr:
      enabled: true
      peerfinding_source: external
      policy: configured_only
      advertise: true
      stun_servers:
        - "stun:stun.cloudflare.com:3478"

transports:
  websocket:
    seed_urls:
      - "wss://seed-a.example/fips"
      - "wss://seed-b.example/fips"
```

`peerfinding_source` has two modes:

- `relays`: fips-core opens `advert_relays` and directly publishes,
  subscribes to, and queries signed adverts.
- `external`: fips-core opens no advert relay connections. The application
  publishes `FipsEndpoint::local_nostr_discovery_advert_event()` and feeds
  received events to `FipsEndpoint::ingest_nostr_discovery_event()`. It also
  drains encrypted offers/answers with
  `FipsEndpoint::drain_nostr_traversal_signal_events()` and publishes them
  through the same provider composition.

Applications integrating `nostr-pubsub` should normally use `external`, so a
single provider graph owns relay and in-FIPS pubsub distribution.

## Public peer adverts

An advert is a signed kind `37195` parameterized replaceable event. Its `d`
tag is the application namespace, which defaults to `fips-overlay-v1`. A
NIP-40 expiration tag and created-at bound reject stale advertisements.

The content is an `OverlayAdvert` document:

```json
{
  "identifier": "fips-overlay-v1",
  "version": 1,
  "endpoints": [
    {"transport": "websocket", "addr": "wss://seed.example/fips"},
    {"transport": "udp", "addr": "nat"},
    {"transport": "tcp", "addr": "203.0.113.8:2121"},
    {"transport": "webrtc", "addr": "<author-xonly-pubkey>"}
  ],
  "stunServers": ["stun:stun.cloudflare.com:3478"]
}
```

Adverts contain capabilities and transport addresses, not relay sets. Static
peer addresses are tried before advert-derived addresses. With
`policy: configured_only`, only configured identities may be learned from
adverts. With `policy: open`, ambient valid adverts may enter the bounded
open-discovery retry queue, subject to the peer ACL and trust ordering.

## Link negotiation

UDP traversal can bootstrap without an existing FIPS route by using encrypted
kind `21059` events. WebRTC negotiation between already-routable peers uses the
generic link-negotiation service on standard FSP service port 257.

- `udp:nat` triggers provider-routed, STUN-assisted hole punching.
- WebRTC SDP/ICE is carried by authenticated link-negotiation messages.
- Reachable TCP and WebSocket addresses can be dialed directly.

## Security properties

- Kind `37195` adverts are signed and public. They prove authorship, not
  reachability or authorization.
- Noise authenticates every FIPS physical link independently of the advert or
  TLS reverse proxy.
- Advert caches, event age, peer counts, reconnects, frames, and queues are
  bounded.
- Relay operators may observe advert metadata, but they never carry FIPS
  ciphertext packets as Nostr events.
