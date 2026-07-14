# FIPS Connectivity and Private-Network Roadmap

This document describes the implementation path from the current FIPS
prototype to a Nostr-native connectivity system that can serve both as:

- a native secure mesh addressed by `npub`
- a private-network / VPN substrate for existing IP applications

The target is not "WireGuard but renamed". The target is a transport-agnostic
secure mesh with strong private-network support, optional public services, and
minimal dependence on any single bootstrap provider.

## End State

At completion, FIPS should support the following model:

- Users and applications identify endpoints by `npub`.
- Native FIPS applications can send datagrams, open streams, or create
  sessions directly to `npub`.
- Existing IP applications can use a FIPS TUN adapter and derived overlay
  addresses for compatibility.
- Nodes can connect over heterogeneous transports including internet UDP/TCP,
  Tor, Ethernet, Bluetooth, serial, and radio.
- Discovery can be disabled, private, or public depending on transport and
  discovery-domain policy.
- Brand-new nodes can bootstrap through Nostr relays, local discovery,
  invitations, or static peers.
- Once on the mesh, most introduction, signaling, peer lookup, and service
  discovery happens over FIPS itself rather than over Nostr relays.
- Direct paths are preferred when possible.
- Relay fallback is available when direct connectivity fails.
- Public relays and NAT-assist nodes can be open, rate-limited, or paid.
- Relay payment uses Cashu, but routing correctness does not depend on a mint.

## Principles

### Bootstrap and steady-state are different

A node that is not yet on the mesh cannot use the mesh to find the mesh.
Cold start therefore needs at least one out-of-band path:

- Nostr relay bootstrap
- local-medium discovery
- static peers
- invitation links / QR codes

After a node has one or more FIPS peers, discovery and signaling should move
in-band onto FIPS wherever possible.

### Public capability hello is not public endpoint disclosure

Ordinary nodes should not publish home IP:port information publicly by
default. Public discovery and private endpoint exchange are separate:

- public service advertisement is opt-in
- direct endpoint exchange is private by default

### NAT traversal is a transport feature, not a universal assumption

UDP internet overlays need NAT assist and hole punching. Tor, Ethernet,
serial, and radio do not. The routing core must stay transport-agnostic while
letting specific transports use richer reachability logic.

### Relay is a fallback path, not the identity or control plane

Relays provide reachability when direct paths fail. They should not become
the permanent control plane for an already-connected mesh.

### Cashu is for economic policy, not routing truth

Cashu can price relay access and service leases. It should not be the
foundation of route selection or packet validity.

## Publication and Reachability Policy

The labels in this section are policy bundles, not universal node identities.
They primarily describe internet-facing publication and reachability behavior.
They do not replace transport-specific policy for local media such as
Ethernet, Bluetooth, serial, or radio.

Examples:

- a node may be `private` on UDP, publicly reachable on Tor, and locally
  discoverable on radio
- a radio transport may support local announcements without any notion of
  `public_peer`
- a service node may publish a public UDP entry address while keeping its
  other transports private

### Internet-facing postures

- `private`
  Does not publicly advertise direct internet endpoints by default.
- `public_peer`
  Publicly reachable on a given internet-facing transport and accepts direct
  peering from strangers on that transport.
- `public_service`
  Publicly reachable on a given transport and offers one or more service
  capabilities such as `entry`, `relay`, `nat_assist`, `directory`, or
  `bridge`.

These postures should be applied per transport or per publication domain, not
as a single global truth for the node.

### Discovery modes

- `disabled`
  No public discovery. Static peers, invites, or local manual configuration
  only.
- `private`
  Public capability presence is optional, but endpoint exchange happens only
  through private introductions.
- `public_service`
  Publish public service capabilities and reachable addresses.
- `public_peer`
  Publish a direct reachable address and accept direct peering from strangers.

Recommended defaults:

- internet UDP/TCP ordinary nodes: `private`
- public relays / community entry nodes / NAT-assist nodes:
  `public_service`
- public internet peers: explicit `public_peer`
- local media such as Ethernet or radio: use transport-local discovery policy
  rather than internet publication posture

### Transport-local policy

Shared and special media should keep their own knobs:

- whether the transport announces locally
- whether it listens for local discovery
- whether it accepts inbound connections
- whether it allows auto-connect from discovered peers

These transport-local decisions are orthogonal to internet publication
posture.

## Addressing and APIs

FIPS should expose two complementary models:

- native FIPS addressing by `npub`
- compatibility addressing by derived overlay IP

### Native FIPS API

Native applications should be able to:

- send a datagram to `npub`
- open a reliable stream or session to `npub`
- query peer reachability and path quality
- optionally request policy such as `prefer_direct`, `allow_relay`, or
  `paid_only`

### Private-network / VPN API

The TUN adapter remains important for:

- unmodified IP applications
- subnet-style private networks
- migration from `nostr-vpn`

This means FIPS should become the connectivity substrate while still offering
an overlay IP mode for legacy applications.

## Discovery Architecture

### Phase 1: bootstrap discovery

Bootstrap discovery is how a node finds its first usable FIPS peers.

Supported bootstrap sources:

- Nostr relays
- local-medium announcements
- static peers
- invite payloads containing known entry peers or service nodes

Nostr bootstrap should carry:

- service capabilities
- contact policy
- optionally a public reachable address for opt-in public peers/services
- enough metadata to open a private introduction flow

Ordinary private nodes should not publish direct addresses publicly by
default.

### Phase 2: in-mesh discovery

Once connected to the mesh, most discovery should be routed over FIPS:

- peer introduction
- service lookup
- relay lookup
- NAT-assist lookup
- directory lookups
- session rendezvous

This should build on the existing routed lookup and coordinate cache model
rather than introducing an unrelated side protocol. Discovery messages should
be routable to service nodes and peers by `node_addr`.

### Directory and introduction messages

FIPS should add routed control messages for:

- `IntroduceRequest(npub or node_addr, constraints)`
- `IntroduceResponse(candidates, capabilities, expiry)`
- `ServiceLookup(service_type, filters)`
- `ServiceLookupResponse(services, hints, expiry)`
- `PeerHello` and `PeerHelloAck` for private endpoint exchange

These messages should be end-to-end encrypted at the session layer when they
reveal peer endpoint information.

## Connectivity Strategy

### Candidate classes

Connectivity should use ranked endpoint candidates rather than a single
"address":

- local shared-medium candidates
- configured static candidates
- public UDP candidates discovered via NAT assist
- publicly advertised service addresses
- relay candidates
- transport-specific special candidates such as Tor onion or serial peer IDs

### Path manager

Add a per-peer path manager that tracks:

- candidate endpoints
- last known working direct path
- relay path if active
- observed RTT, loss, and success/failure counts
- when to reprobe direct paths
- policy such as `prefer_direct`, `allow_relay`, `allow_paid_relay`

Direct paths should always be preferred when they work. Relay paths should be
used only when no direct path succeeds or when policy explicitly requires a
relay.

## NAT Assist and Hole Punching

### NAT-assist providers

Any node may opt into offering `nat_assist`, but clients should treat assist
providers as disposable hints rather than trusted authorities.

The protocol should allow:

- querying several assist nodes in parallel
- comparing observed public endpoints
- using the answers only as connection hints

### Initial implementation

The first implementation should be UDP-focused:

- public or opt-in service nodes expose NAT-assist capability
- clients ask several assist nodes for observed public UDP address
- clients exchange UDP candidates privately with intended peers
- clients race real FIPS handshake packets to those candidates

FIPS should not start with a separate custom punch packet type. Authenticated
FIPS handshake traffic should act as the punch traffic.

### Transport boundaries

NAT assist applies to internet UDP. Other transports should simply ignore
this machinery.

## Relay Architecture

### Relay model

Relay fallback should be implemented as a capability of FIPS service nodes.
There should not be a separate relay universe with separate identity rules.

Possible service capabilities:

- `entry`
- `relay`
- `nat_assist`
- `directory`
- `bridge`

### Relay behavior

The initial relay goal is simple:

- if direct connectivity fails, traffic can flow through one relay service
- clients continue probing for a direct path in the background
- if a direct path succeeds, traffic migrates off the relay

Longer-term extensions can include:

- multiple relay candidates
- policy-based relay selection
- transport bridging
- partial-path relay assistance

### Trust model

Relays are untrusted intermediaries. They may carry hop-to-hop encrypted
traffic and route encrypted session traffic without learning plaintext
application content.

## Cashu Payment Model

### Who pays for what

Payment authorization belongs to an optional service adapter above FSP, not to
FMP forwarding or route validity. The payer is the peer that requests or
sponsors a named service; it is not universally the packet sender or recipient.
For example:

- an interactive sender can sponsor a session to a destination;
- a recipient pulling a requested pubsub event or Hashtree block can pay the
  immediate provider after verifying it;
- an application can offer to pay for a bounded link or bandwidth budget to a
  destination `npub`.

The authorization must name the application-defined resource, meter, limit,
expiry, and payer. Raw FMP bytes, retransmissions, duplicates, unsolicited
traffic, and spam do not create debt merely because a router forwarded them.
Application adapters decide what useful service means. An nVPN adapter can use
acknowledged TCP progress and buyer-originated UDP flow costs; pubsub can use
requested verified events; Hashtree can use first-accepted hash-valid blocks.

### V1 economics by service shape

Use one accounting model with a small set of settlement strategies:

- weak-trust streaming: allow a free probe, then use a small, short-lived
  incremental Cashu Spilman channel. Sign updates after useful service so the
  provider's unpaid risk is bounded by one update and the buyer does not hand
  the full stream budget to an unknown provider;
- verifiable one-shot service: deliver and verify first, then settle directly
  or in a Cashu batch;
- trusted or intermittently connected peers: permit bounded bilateral peer
  credit and settle later through an accepted mint;
- fixed prepayment: use only when the buyer explicitly accepts the full lease
  exposure or already trusts the provider.

"Pay only if a transit hop definitely forwarded this packet" remains a hard
protocol problem because a payment does not prove end-to-end delivery. Do not
put per-packet payment or inspection in FMP. A particular FSP service may use a
receiver-verifiable meter, but routing must continue to work when payment is
disabled.

Peer credit is an unbacked, non-cashout relationship limit. Closed-loop Cashu
is a backed issuer liability that can buy issuer service or circulate among
peers accepting that mint. Only separately reserve-backed withdrawable value
may authorize an external Cashu or Lightning payout; peer or closed-loop credit
must never borrow that reserve transitively.

Accepted mint IDs and local limits should normally be exchanged privately with
connected peers. A public service may optionally advertise exact accepted mints
and limits so clients can estimate usefulness, but nodes must not advertise a
generic "supernode" or high-capacity role. Capacity and reliability are learned
from observed service.

### Integration boundary

Cashu and peer credit should live at the service-access layer:

- negotiate a named resource, meter, budget, expiry, and accepted settlement
  methods;
- obtain a quote, establish bounded credit, or open a small channel;
- present the resulting authorization when opening the relay or public entry
  service;
- record only verified useful-service progress;
- settle, close, or suspend service when the negotiated limit is reached.

The reusable accounting and Cashu wallet/mint integration belong in a separate
adapter crate. `fips-core` should expose transport/session observations needed
by that adapter but must not depend on Cashu, pubsub, or a payment database.
Routing and forwarding logic remain valid when payment is disabled.

## Transport-Agnostic Design

FIPS must keep the routing core independent from transport-specific details.

This means:

- path selection can compare candidates from different transports
- service discovery can advertise heterogeneous transport support
- weird radios, Ethernet, Tor, and UDP all feed the same routing core

This does not mean every transport supports the same features. For example:

- UDP may support NAT assist and hole punching
- Ethernet may support local discovery but no NAT traversal
- Tor may support onion reachability and relay-like access semantics
- serial/radio links may support explicit configured peers only

## Borrowed Ideas

### From `nostr-vpn`

- private endpoint exchange via targeted Nostr messages
- public endpoint discovery for direct internet paths
- simple path memory / endpoint preference heuristics

### From `iroh`

- treat address discovery and relay as service-node capabilities
- race direct connectivity aggressively
- upgrade from relay to direct when possible

### From `boringtun`

- keep the packet/session engine separate from OS/network glue
- maintain small per-peer endpoint state with timers and stats
- provide a clear API boundary between encrypted packet engine and device /
  transport integration

### What not to copy

- do not force FIPS into a WireGuard-shaped protocol model
- do not make every transport look like UDP
- do not make Nostr a permanent dependency for already-connected meshes

## Implementation Phases

### Phase 0: lock the architecture

Document and codify:

- node roles
- discovery modes
- capability advertisement rules
- privacy rules for endpoint disclosure
- native-vs-TUN API model

Deliverables:

- updated design docs
- config schema for per-transport publication posture, discovery modes, and
  service capabilities

Exit criteria:

- design documents reflect the intended privacy and bootstrap model
- config can represent the planned node/service modes

### Phase 1: privacy-aware Nostr bootstrap

Extend the current Nostr discovery work to distinguish:

- public service announcements
- private introductions
- public peer opt-in

Deliverables:

- public service announcement events
- private endpoint exchange messages
- config-driven publish policy

Exit criteria:

- ordinary nodes can bootstrap without public endpoint leakage
- public service nodes can advertise entry/relay/NAT-assist capability

### Phase 2: in-mesh introduction and service discovery

Implement routed discovery and introduction over FIPS itself.

Deliverables:

- routed service lookup messages
- routed introduction messages
- private `PeerHello` endpoint exchange over FIPS sessions

Exit criteria:

- once connected to any entry peer, a node can discover additional peers and
  services without using Nostr relays for every step

### Phase 3: UDP NAT assist

Add UDP address-discovery support to public or opt-in service nodes.

Deliverables:

- `nat_assist` capability advertisement
- client logic to query multiple assist nodes
- public UDP candidate gathering

Exit criteria:

- two NATed nodes can learn useful public UDP candidates without manual port
  forwarding

### Phase 4: FIPS-native hole punching

Use real FIPS handshakes to race direct candidates.

Deliverables:

- direct candidate ranking
- simultaneous outbound direct-connect attempts
- authenticated address roaming and direct-path promotion

Exit criteria:

- NATed UDP peers can establish direct sessions in common home-router cases
- relay is not required for the common case

### Phase 5: path manager and failover

Introduce explicit per-peer path management.

Deliverables:

- path book storing candidate state and working path
- direct-to-relay failover
- relay-to-direct migration when direct connectivity appears

Exit criteria:

- sessions survive path change
- relay fallback is automatic and reversible

### Phase 6: relay service nodes

Add public relay service support without payment dependencies.

Deliverables:

- relay service capability
- relay session setup and teardown
- rate limiting and abuse controls

Exit criteria:

- a node with no direct path can still communicate through one relay

### Phase 7: native application API

Expose FIPS as more than a TUN overlay.

Deliverables:

- datagram API addressed by `npub`
- stream/session API addressed by `npub`
- policy knobs for direct vs relay preference

Exit criteria:

- native apps can use FIPS without going through overlay IP

### Phase 8: private-network / VPN migration path

Make FIPS usable as the connectivity substrate for `nostr-vpn`-style private
networks.

Deliverables:

- clear TUN adapter integration
- subnet and peer policy support
- compatibility layer for private-network deployments

Exit criteria:

- existing private-network use cases can be moved from WireGuard to FIPS with
  acceptable ergonomics and performance

### Phase 9: Cashu-priced public services

Add economic policy to relay and entry services.

Deliverables:

- optional FSP service-authorization adapter, without a `fips-core` Cashu
  dependency
- free probe and bounded incremental Spilman flow for weak-trust streams
- verified post-delivery Cashu batching and bounded offline peer credit
- accepted-mint/limit exchange and reserve-separated withdrawal authorization
- adversarial accounting tests for replay, default, provider failure, and
  forged service claims

Exit criteria:

- public service operators can require payment without modifying routing core
  or turning raw FMP traffic into billable service

### Phase 10: hardening and release readiness

Close the gap from prototype to dependable deployment.

Deliverables:

- churn, partition, and recovery testing
- mixed-transport integration coverage
- resource controls and abuse protections
- operator documentation
- security review of discovery, relay, and payment layers

Exit criteria:

- FIPS can operate as a practical private-network substrate and as a native
  secure mesh in real-world small-to-medium deployments

## Testing Strategy

Each phase should land with focused tests and at least one realistic
end-to-end scenario.

### Unit and component tests

- config parsing and policy selection
- message codecs
- candidate ranking
- NAT-assist client/server logic
- path manager state transitions

### Integration tests

- private bootstrap through Nostr into FIPS-only steady state
- public service discovery without public private-node leakage
- UDP direct connection through common NAT patterns
- direct failure followed by relay fallback
- relay recovery back to direct
- mixed transport topologies, including at least one non-UDP transport

### System tests

- Docker-based sparse meshes
- churn and chaos tests
- long-running soak tests for roaming, relay migration, and reconnect storms

## Non-goals for the first useful version

- perfect trustless per-packet relay payment proofs
- universal NAT traversal across all transports
- eliminating all bootstrap dependence on out-of-band channels
- replacing the TUN adapter with native APIs only

## Completion Criteria

This roadmap is complete when all of the following are true:

- a new user can join using Nostr bootstrap, local discovery, or an invite
- a connected user can discover additional peers and services mostly over FIPS
- two common NATed internet peers usually connect directly without manual port
  forwarding
- relay fallback works automatically when direct connectivity fails
- public service operators can publish and optionally monetize relay access
- private nodes can remain private by default
- native applications can address `npub` directly
- existing IP applications can use FIPS through the TUN adapter
- mixed-transport networks remain first-class rather than a special case
