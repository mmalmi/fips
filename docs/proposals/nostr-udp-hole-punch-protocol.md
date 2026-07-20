# FIPS-session UDP hole punching

> **Status:** Implemented behind the `nostr-discovery` cargo feature. The
> historical direct Nostr signaling protocol was removed: Nostr is used for
> public peer adverts while traversal negotiation runs inside an authenticated
> FIPS session.

## Abstract

Two FIPS peers behind NAT can negotiate a direct UDP path with STUN-assisted
hole punching. A public Nostr kind `37195` advert announces the `udp:nat`
capability. The peers first establish any FIPS session, possibly over the
WebSocket bootstrap transport, and exchange traversal offers and answers as
encrypted FIPS session messages. The successfully punched socket is adopted as
a normal UDP transport.

This removes the former kind `21059` gift-wrap protocol, DM relay sets, and
NIP-65 inbox relay lookup. No relay receives a plaintext traversal payload or
needs to support a special signaling convention.

## Roles and socket lifecycle

- The **initiator** has an authenticated session to a peer whose advert
  includes `udp:nat` and begins an upgrade attempt.
- The **responder** receives the offer from that authenticated session and may
  accept it for the same peer identity.
- Each attempt owns a fresh UDP **punch socket**, bound to an ephemeral local
  port. STUN, probes, acknowledgements, and the adopted UDP transport all use
  that socket. A retry creates a new socket and a new session id.

The long-lived UDP listener is not substituted for an attempt's punch socket;
changing sockets after STUN would invalidate the observed NAT mapping.

## Advertisement

The responder's signed kind `37195` event includes a public endpoint:

```json
{
  "identifier": "fips-overlay-v1",
  "version": 1,
  "endpoints": [
    {"transport": "websocket", "addr": "wss://seed.example/fips"},
    {"transport": "udp", "addr": "nat"}
  ],
  "stunServers": ["stun:stun.cloudflare.com:3478"]
}
```

The advert has no signaling relay list. Delivery of kind `37195` is owned by
the selected peerfinding provider. In external mode this is normally a
nostr-pubsub bridge using both configured relays and decentralized pubsub.
Advertised STUN values are informational; each node contacts only its locally
configured STUN servers.

## Prerequisite session

Traversal negotiation requires an authenticated FIPS session. That session
may already run over UDP, TCP, WebRTC, Tor, or another transport. Where no
direct path exists, an explicit WSS seed supplies the first physical
adjacency. Relay-backed `nostr-pubsub` can distribute the signed advert, but it
does not carry the FIPS session packets.

## Offer

The initiator:

1. Creates the attempt's punch socket.
2. Sends STUN Binding Requests on that socket and records the returned
   XOR-MAPPED-ADDRESS.
3. Optionally collects same-port local interface candidates when
   `share_local_candidates` is enabled.
4. Sends a `TraversalOffer` as a FIPS traversal session message to the
   authenticated peer.

The offer identifies the attempt with a random session id and nonce, binds
sender and recipient identities, carries the reflexive and optional local
candidates, records the local STUN server for diagnostics, and has a bounded
expiry.

Although the data structure retains Nostr-shaped npub identities for stable
wire compatibility, the receiving node binds them to the authenticated FIPS
session source. A payload cannot select a different sender.

## Answer

The responder accepts an offer only from a configured peer or an active
authenticated peer. It checks expiry and replay state, then:

1. Creates its own attempt-specific punch socket.
2. Runs STUN using its local allowlist.
3. Returns `TraversalAnswer` over the same authenticated FIPS session.
4. Includes its candidates and a bounded punch timing hint.

An inbound semaphore limits simultaneous offer processing. Recently seen
session ids are stored in a bounded replay cache. These limits protect the
runtime even though the source has already passed FIPS authentication.

## Hole punching

Both peers build candidate pairs from their own and the remote addresses:

1. reflexive to reflexive;
2. compatible LAN candidates when explicitly shared; and
3. mixed local/reflexive candidates for hairpin or one-side-public cases.

At the negotiated start time, each side sends probes at the configured
interval for the bounded punch duration:

```text
Bytes 0..4    NPTC probe or NPTA acknowledgement magic
Bytes 4..8    big-endian sequence number
Bytes 8..24   first 16 bytes of SHA-256(session id)
```

The first valid probe or acknowledgement records the usable remote address.
The probe only proves coordination for this attempt; it does not authenticate
the final link.

## Adoption and authentication

On success, the discovery runtime hands the punch socket and learned address
to the UDP transport. The normal FIPS link handshake then authenticates the
expected peer on that socket. Only after that handshake is the UDP link an
accepted path.

The WebSocket or other bootstrap session can remain available while the
direct path is tested. Transport selection prefers the direct link once it is
usable. If punching fails, the existing session remains valid and another
transport upgrade may be attempted.

## Failure behavior

| Failure | Result |
| --- | --- |
| STUN unavailable | No UDP candidate; retain the existing FIPS path. |
| Symmetric NAT or firewall | Punch timeout; retain the existing path and try another configured transport. |
| Stale advert | Advert expiry/cache rules reject it or the attempt times out. |
| Duplicated session message | Replay cache rejects the traversal session id. |
| Identity mismatch | Authenticated session binding or final FIPS handshake rejects it. |
| WebSocket seed unavailable | Bounded reconnect tries another configured seed or physical transport. |

## Security and privacy

- Traversal offers and answers are encrypted by the established FIPS session;
  they are never published as standalone Nostr events.
- Relays distributing public adverts see advert authors and transport
  metadata, but never carry encrypted FIPS packet traffic.
- STUN providers see the node's public address. A peer cannot choose the STUN
  server because only local configuration is used for egress.
- Public adverts intentionally expose identity and transport capabilities.
- Successful probe traffic is not sufficient authentication. The adopted UDP
  socket still runs the ordinary FIPS handshake.

## References

- RFC 8489 — Session Traversal Utilities for NAT (STUN)
- NIP-01 — Nostr event and ephemeral-kind semantics
- NIP-40 — Expiration timestamps
- [Nostr peer and service discovery](../design/fips-nostr-discovery.md)
