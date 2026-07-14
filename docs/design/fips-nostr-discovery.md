# Nostr peerfinding and relay fallback

> **Status:** Implemented behind the `nostr-discovery` cargo feature.

FIPS uses Nostr for two deliberately separate jobs:

1. Public kind `37195` adverts find peers and describe candidate transports.
2. Optional ephemeral kind `21060` events carry encrypted FIPS wire datagrams
   when no direct transport is available yet.

There is no DM-relay configuration or Nostr-specific offer/answer plane.
UDP traversal and WebRTC negotiation are ordinary encrypted FIPS session
messages. Once a relay-carried session exists, FIPS can negotiate a better
UDP, WebRTC, or TCP path over that authenticated session.

## Ownership boundary

FIPS owns event construction and validation. The embedding application owns
relay selection and network delivery.

```text
                       public kind 37195 adverts
             configured relays + decentralized pubsub mesh
                                    |
                                    v
                         +---------------------+
                         | validated advert    |
                         | cache / peerfinding |
                         +---------------------+
                                    |
                         low-priority bootstrap
                                    |
                                    v
        app-configured relays <-> kind 21060 <-> FIPS session
                                    |
                        authenticated negotiation
                         /          |          \
                       UDP       WebRTC        TCP
```

The external peerfinding provider may be `nostr-pubsub-fips`, which forwards
kind `37195` events through both configured Nostr relays and decentralized
pubsub. The raw relay fallback must not be sent through that whole EventBus:
decentralized pubsub may already use FIPS and would recurse. Instead, the
embedding application sends kind `21060` directly over its configured relay
connections.

Relay URLs therefore do not appear in `NostrRelayConfig`. The same application
configuration that owns the relay bridge is the source of truth.

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
  nostr_relay:
    mtu: 1280
    auto_connect: true
    accept_connections: true
    max_pending_events: 1024
```

`peerfinding_source` has two modes:

- `relays`: fips-core opens `advert_relays` and directly publishes,
  subscribes to, and queries kind `37195` adverts.
- `external`: fips-core opens no advert relay connections. The application
  publishes `FipsEndpoint::local_nostr_discovery_advert_event()` and feeds
  received events to `FipsEndpoint::ingest_nostr_event()`.

Applications integrating `nostr-pubsub` should use `external`, so public
peerfinding follows nostr-pubsub's configured relays and decentralized
distribution rather than a duplicate relay pool inside fips-core.

`transports.nostr_relay` enables only the FIPS transport endpoint and its
bounded event queues. It does not open sockets or choose relays. The
application drains signed outbound events with
`FipsEndpoint::drain_nostr_relay_events()` and feeds received events back via
`FipsEndpoint::ingest_nostr_event()`.

Direct `Node` embedders can attach the equivalent `NostrRelayIo` handle before
starting the node. The standalone `fips` daemon enables the default transport
and attaches the adapter whenever `node.discovery.nostr.enabled` is true. It
uses its application-configured `advert_relays` for the direct relay bridge.
An explicit `transports.nostr_relay` section overrides the transport defaults.

| Nostr relay transport field | Default | Meaning |
| --- | --- | --- |
| `mtu` | `1280` | Maximum FIPS wire datagram size before text encoding. |
| `auto_connect` | `true` | Permit advert-derived relay fallback dials. |
| `accept_connections` | `true` | Accept inbound FIPS handshakes from relay events. |
| `max_pending_events` | `1024` | Bound on signed outbound events awaiting the adapter. |

Deprecated `dm_relays` and WebRTC `signal_relays` fields are rejected as
unknown configuration. This catches stale deployments instead of silently
creating an unintended relay plane.

## Public peer adverts

An advert is a signed kind `37195` parameterized replaceable event. Its `d`
tag is the application namespace, which defaults to `fips-overlay-v1`. A
NIP-40 expiration tag limits stale advertisements.

The content is an `OverlayAdvert` document:

```json
{
  "identifier": "fips-overlay-v1",
  "version": 1,
  "endpoints": [
    {"transport": "nostr_relay", "addr": "<author-npub>"},
    {"transport": "udp", "addr": "nat"},
    {"transport": "tcp", "addr": "203.0.113.8:2121"},
    {"transport": "webrtc", "addr": "<author-xonly-pubkey>"}
  ],
  "stunServers": ["stun:stun.cloudflare.com:3478"]
}
```

Adverts contain capabilities and addresses, not relay sets. The relay that
delivered an advert is useful reachability provenance, so an adapter may keep
a short-lived author-to-relay mapping and prefer one or two of the newest
observed routes for kind `21060`. This is a delivery hint, not an identity or
trust signal. If no fresh route is known, the adapter should fan out to its
configured relay list.

Validated adverts populate an in-memory cache keyed by author. Expiration and
a created-at staleness bound reject stale events, while
`advert_cache_max_entries` bounds memory. Static peer addresses are tried
before advert-derived addresses.

With `policy: configured_only`, only configured identities may be learned from
adverts. With `policy: open`, ambient valid adverts may enter the bounded
open-discovery retry queue, subject to the peer ACL and trust ordering.

## Ephemeral relay transport

Kind `21060` is in Nostr's ephemeral range. Each event has:

- the FIPS node identity as author;
- exactly one `p` tag naming the recipient;
- base64url-without-padding content containing one complete FIPS wire
  datagram; and
- a normal Nostr signature.

The wire datagram is already encrypted and authenticated by FIPS. Adding
NIP-44 or NIP-59 would duplicate encryption, introduce another key/envelope
path, and increase message size. Base64url is used because Nostr event content
is JSON text and interoperable binary event content is not available. Its
rough 4/3 expansion is accepted for a fallback transport whose default MTU is
1280 bytes.

Inbound validation checks the Nostr signature, recipient, freshness, decoded
size, and author/address binding before the packet enters the normal FIPS
transport receive path. A relay can observe sender, recipient, timing, and
size, but cannot decrypt the FIPS payload.

The relay transport is connectionless and unreliable. Relays may reject,
delay, duplicate, reorder, or drop ephemeral events. FIPS reliability and
session behavior remain responsible for tolerating those properties. The
transport advert priority is intentionally low (`250`) so directly reachable
transports win.

## Establishment and automatic upgrade

The relay transport does not bypass FIPS authentication. Two peers bootstrap
exactly as on UDP or another datagram carrier:

1. A kind `37195` advert supplies the peer identity and relay capability.
2. FIPS handshake datagrams are signed as kind `21060` events and delivered
   by the application's relay bridge.
3. The receiver validates the event, decodes the datagram, and completes the
   normal Noise-authenticated FIPS handshake.
4. After the session is established, candidate transport negotiation travels
   inside encrypted `SessionMessage` frames.
5. A successful UDP traversal or WebRTC/TCP connection becomes an ordinary
   FIPS link and is preferred over the relay fallback.

FIPS automates selection among configured and discovered transport candidates;
it is not an unrestricted path oracle. A transport must be configured and its
required runtime support must be present. UDP NAT traversal also requires a
local STUN server list. When no better candidate succeeds, the relay-carried
session remains usable, including in constrained environments where direct
UDP, TCP, or WebRTC is unavailable.

### UDP traversal

A `udp:nat` advert says that the peer supports STUN-assisted hole punching.
The initiating side gathers candidates on a per-peer punch socket, then sends
`TraversalOffer` over the authenticated FIPS session. The responder validates
the session peer identity, gathers its candidates, and returns
`TraversalAnswer` on the same session. Both sides punch using the socket on
which their reflexive address was observed. A successful socket is adopted by
the UDP transport and runs the ordinary FIPS link handshake.

Offers and answers are no longer Nostr events. Their TTL, replay cache, and
bounded inbound-offer semaphore remain defense-in-depth for malformed or
duplicated session messages.

### WebRTC

WebRTC SDP/ICE negotiation is also carried as authenticated FIPS session
messages. The WebRTC transport has an internal signal outbox/inbox but no
Nostr client and no relay URL configuration. Once negotiated, its SCTP data
channel carries FIPS traffic directly.

### TCP

Advertised reachable TCP addresses can be dialed directly. Applications may
also negotiate or distribute TCP candidates above the authenticated session;
the relay fallback does not require a special TCP signaling protocol in
fips-core.

## Adapter guidance

An external application bridge should:

1. Publish and receive kind `37195` through its configured relay bridge and
   decentralized pubsub EventBus.
2. Record relay provenance only for valid received adverts.
3. Subscribe on configured relays to kind `21060` filtered by the local `p`
   tag.
4. Pass relay datagrams directly between Nostr and `FipsEndpoint`, bypassing
   the decentralized EventBus.
5. Prefer up to two fresh advert-delivery relays for the recipient, then fall
   back to all configured relays.
6. Keep queues, event age, and event size bounded.

The adapter may share relay connections with nostr-pubsub. It should not call
the whole nostr-pubsub forwarding path for relay datagrams, since that path can
include already-established FIPS connections.

## Security properties

- Kind `37195` adverts are public and signed. They prove authorship, not that
  advertised endpoints are reachable or safe.
- Kind `21060` metadata is visible to relays. Its content is an encrypted FIPS
  datagram, and the eventual peer identity is accepted only after the normal
  FIPS handshake.
- Relay provenance is untrusted reachability information. A malicious relay
  can suppress or replay adverts but cannot impersonate an author with a valid
  signature.
- Only locally configured STUN servers are queried. Advertised STUN metadata
  is informational and cannot steer arbitrary egress.
- Open peerfinding is not admission control. Peer ACLs and authenticated FIPS
  identities remain authoritative.
- The fallback's bounded queue and MTU limit memory amplification before
  normal protocol admission takes effect.

## See also

- [fips-configuration.md](fips-configuration.md)
- [fips-transport-layer.md](fips-transport-layer.md)
- [nostr-udp-hole-punch-protocol.md](../proposals/nostr-udp-hole-punch-protocol.md)
