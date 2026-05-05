# Nostr-VPN In-App Data Plane Integration

> **Status**: In progress.
> This plan describes the FIPS library and broker work needed for
> `nostr-vpn` to move its private mesh data plane from WireGuard to FIPS
> without exposing a FIPS-owned network adapter to the host system.

## Summary

`nostr-vpn` should keep owning membership, policy, user experience, private
routes, and any OS-visible VPN adapter. FIPS should become an embedded
connectivity substrate that can carry named application protocols between
Nostr identities.

The first application protocol is:

```text
nostr-vpn/ip/1
```

That protocol carries private VPN IP packets only between `nostr-vpn` roster
members. Other FIPS peers may still be used for reachability, bridge, relay,
or transit paths, but they do not automatically become members of the private
network and cannot inject packets into the local host or app.

## Goals

- Let `nostr-vpn` use FIPS as the private mesh data plane.
- Do not create or expose a separate FIPS `fips0` or `utun` adapter.
- Do not accept arbitrary FIPS peer traffic into the host or private VPN.
- Keep `nostr-vpn` rosters as the source of membership truth.
- Allow FIPS to connect broadly for reachability without granting private
  network access.
- Preserve the option to use WireGuard as an internet exit path, for example
  with Mullvad, while FIPS handles private-network packets.
- Allow reuse of a trusted local FIPS broker when available.

## Non-Goals

- Do not replace `nostr-vpn` invites, rosters, admin flows, GUI, or services.
- Do not make FIPS discovery membership-authoritative.
- Do not expose host services to FIPS peers by default.
- Do not require a separately installed daemon on mobile.
- Do not remove FIPS TUN support for normal FIPS node use.

## Iroh Lessons

The useful Iroh pattern is endpoint-oriented application integration:

- one local endpoint owns identity, sockets, discovery, relays, and connection
  reuse
- applications register explicit protocol handlers
- accepted connections are delivered to handlers, not to the host network
- unsupported protocols are rejected or ignored
- identity and reachability are separate concepts
- relays and bridges improve reachability but are not membership grants

FIPS should expose the same kind of application boundary:

```rust
let endpoint = FipsEndpoint::builder()
    .identity_nsec(nostr_identity)
    .discovery_scope(format!("nostr-vpn:{network_id}"))
    .without_system_tun()
    .connectivity_policy(FipsConnectivityPolicy::OpenTransit)
    .bind()
    .await?;

endpoint.accept_protocol(
    b"nostr-vpn/ip/1",
    NostrVpnIpHandler {
        roster,
        route_policy,
        packet_sink,
    },
);
```

The application handler decides whether a peer is allowed into the private
network.

## Target Architecture

### Embedded Endpoint

The default integration is library-first:

```text
nostr-vpn runtime
  -> route classifier
  -> embedded FIPS endpoint
  -> FIPS peer links, bridges, NAT traversal, TCP/Tor fallback
```

In this mode, FIPS does not create a TUN interface, configure routes, install
DNS state, or expose host services. It receives packets and sessions through
app-owned channels.

When system-wide VPN behavior is needed, the visible adapter remains the
`nostr-vpn` adapter:

- Android: `VpnService`
- iOS: packet tunnel
- desktop: existing `nostr-vpn` tunnel interface

FIPS only carries the selected private mesh traffic behind that adapter.

### Optional Local Broker

A local FIPS broker can improve reuse between apps:

```text
nostr-vpn runtime
  -> authenticated local IPC
  -> local FIPS broker
  -> remote FIPS peers and bridges
```

The broker owns reusable connectivity resources:

- UDP, TCP, and Tor sockets
- peer links
- Nostr advert cache
- STUN and NAT traversal state
- bridge and relay paths
- metrics and path selection

The broker must not be an ambient network adapter for this use case. It must
only deliver app-registered protocols over authenticated local IPC:

```rust
broker.register_protocol(
    b"nostr-vpn/ip/1",
    allowed_remote_npubs,
    app_packet_channel,
);
```

If no compatible local broker is available, `nostr-vpn` starts its own
embedded endpoint.

## Peer Policy Model

FIPS and `nostr-vpn` need separate policy concepts:

| Role | Meaning | Policy owner |
| --- | --- | --- |
| Connectivity peer | A node we may connect to or use as a path | FIPS plus app config |
| Transit peer | A node whose traffic may be forwarded through us | App policy |
| Private member | A roster npub allowed into this VPN network | `nostr-vpn` roster |
| Host service peer | A peer allowed to reach local host services | Explicit app policy |

Default policy for `nostr-vpn`:

```text
connect to FIPS peers: allowed when useful
use public bridge peers: allowed when useful
forward transit traffic: configurable
deliver private packets locally: roster npubs only
deliver packets to host services: deny by default
```

This allows "connect to many FIPS peers" without "route anyone's traffic into
this system".

## FIPS Work

### 1. Embedded Runtime Without TUN

Status: implemented for the library endpoint API.

Add a runtime mode that disables all system network integration:

```rust
pub struct FipsEndpointBuilder {
    // identity, transports, discovery, policy
}

impl FipsEndpointBuilder {
    pub fn identity_nsec(self, nsec: String) -> Self;
    pub fn discovery_scope(self, scope: String) -> Self;
    pub fn without_system_tun(self) -> Self;
    pub async fn bind(self) -> Result<FipsEndpoint>;
}
```

`without_system_tun()` must prevent:

- FIPS TUN creation
- route changes
- DNS configuration
- local host service exposure
- automatic delivery into host networking

### 2. External Packet I/O

Status: implemented for app-owned packet send/receive with source attribution.

Expose app-owned packet I/O:

```rust
impl FipsEndpoint {
    pub async fn send_ip_packet(&self, packet: &[u8]) -> Result<()>;
    pub async fn recv_ip_packet(&self) -> Option<FipsDeliveredPacket>;
}

pub struct FipsDeliveredPacket {
    pub source_npub: String,
    pub destination: FipsAddress,
    pub packet: Vec<u8>,
}
```

`source_npub` is required so `nostr-vpn` can enforce roster membership before
writing a packet to its VPN file descriptor or app packet sink.

### 3. Application Protocol Handlers

Status: implemented for loopback sessions and remote FSP session data frames.

Add explicit protocol routing:

```rust
pub trait FipsProtocolHandler: Send + Sync + 'static {
    async fn accept(&self, session: FipsSession) -> Result<()>;
}

impl FipsEndpoint {
    pub fn accept_protocol(
        &self,
        protocol: &'static [u8],
        handler: impl FipsProtocolHandler,
    );

    pub async fn connect_protocol(
        &self,
        remote: Npub,
        protocol: &'static [u8],
    ) -> Result<FipsSession>;
}
```

Unknown protocols must be rejected or ignored. They must not fall through to
host networking.

The current remote wire path uses an app-owned FSP service port and frames:

- open protocol session
- data frame
- close frame

Open and data frames are queued while the underlying end-to-end FSP session is
establishing, then flushed once the Noise XK session reaches Established.

### 4. Local Delivery vs Transit

Expose hooks that let an application distinguish private local delivery from
transit forwarding:

- app can disable all automatic local packet delivery
- app receives only registered application protocols
- app can inspect source npub before accepting payload
- app can choose whether to forward transit traffic

Optional later API:

```rust
pub enum LocalDeliveryDecision {
    Accept,
    Drop,
}

pub trait LocalDeliveryPolicy {
    fn decide(&self, packet: &FipsDeliveredPacket) -> LocalDeliveryDecision;
}
```

### 5. Discovery Scope

Discovery needs app-level scope fields so `nostr-vpn` can advertise private
network reachability without joining the global FIPS mesh as a private member.

Minimum fields:

- application protocol name
- network id or invite id hash
- supported protocol versions
- optional bridge capability
- optional public bridge endpoint metadata

FIPS may discover broad connectivity peers. Only the app protocol handler may
grant private membership.

### 6. Broker IPC

Add a local broker protocol after embedded mode works.

Minimum operations:

- version and capability check
- authenticate local app
- open or reuse endpoint identity
- register application protocol
- connect protocol to remote npub
- accept protocol sessions
- send and receive packet frames
- report peer/path status

The broker should support at least two identity modes:

- app-owned identity: app supplies signing/encryption material or delegates
  narrowly scoped signing
- broker identity: useful for local tooling but weaker isolation

The `nostr-vpn` default should be app-owned identity.

## Nostr-VPN Work

`nostr-vpn` should add a data-plane abstraction:

```rust
trait PrivateMeshBackend {
    async fn start(&mut self, roster: Roster, routes: RoutePolicy) -> Result<()>;
    async fn send_private_packet(&self, packet: &[u8]) -> Result<()>;
    async fn recv_private_packet(&self) -> Result<PrivatePacket>;
    async fn peer_status(&self) -> Vec<PeerStatus>;
}
```

The initial backends are:

- `WireGuardMeshBackend`
- `FipsMeshBackend`

Configuration should separate private mesh and internet exit:

```toml
private_data_plane = "wireguard" # wireguard | fips
exit_data_plane = "wireguard"    # none | wireguard
```

With that split:

- private roster subnets go to FIPS
- default route and non-private internet traffic may keep using WireGuard
- mobile packet tunnels classify packets internally because only one OS VPN
  profile can usually be active at a time

The Nostr control plane should publish data-plane capabilities in node records:

```json
{
  "data_plane": "fips",
  "fips": {
    "protocol": "nostr-vpn/ip/1",
    "endpoint_npub": "<npub>",
    "network_scope": "<network-id>",
    "bridge_ok": false
  }
}
```

During migration, peers should advertise both WireGuard and FIPS capability
when possible.

## Phased Implementation

### Phase 0: API Spike

- Add `fips` as a local path dependency in a `nostr-vpn` integration branch or
  worktree.
- Build a tiny executable that starts a FIPS endpoint without TUN.
- Connect two endpoints by npub using `nostr-vpn/ip/1`.
- Send framed bytes and verify source npub attribution.

Exit criteria:

- no FIPS-owned adapter appears on the system
- unknown protocol names are rejected
- source npub is visible to the application

### Phase 1: FIPS Library Boundary

- Split node runtime from TUN/DNS/system setup.
- Introduce `FipsEndpointBuilder`.
- Introduce protocol handler registration.
- Add source-attributed delivered packets.
- Add tests for no-TUN mode.

Exit criteria:

- existing FIPS TUN mode still works
- embedded mode runs without system network changes
- protocol dispatch has deny-by-default behavior

### Phase 2: Nostr-VPN Backend Abstraction

- Extract current WireGuard private mesh operations behind
  `PrivateMeshBackend`.
- Keep existing behavior through `WireGuardMeshBackend`.
- Add config parsing for `private_data_plane` and `exit_data_plane`.

Exit criteria:

- current WireGuard-only flows still pass
- route and peer state are backend-neutral above the abstraction

### Phase 3: FIPS Private Mesh Backend

- Implement `FipsMeshBackend`.
- Map roster npubs to FIPS remote identities.
- Register `nostr-vpn/ip/1`.
- Drop incoming private packets from non-roster npubs.
- Send private route traffic over FIPS.

Exit criteria:

- two roster peers exchange private IP packets over FIPS
- non-roster FIPS peer traffic is dropped
- broad FIPS connectivity does not imply private VPN membership

### Phase 4: Hybrid Exit

- Keep WireGuard exit support for providers such as Mullvad.
- Classify private routes to FIPS.
- Classify default route to WireGuard when configured.
- Ensure route precedence is deterministic.

Exit criteria:

- private peer traffic uses FIPS
- internet exit traffic uses WireGuard
- disabling WireGuard exit does not break FIPS private mesh

### Phase 5: Bridge and Transit Policy

- Add explicit `bridge_ok` and `forward_transit` settings.
- Permit public FIPS bridge nodes for NAT-hostile peers.
- Keep local delivery denied unless source npub is in the roster.

Exit criteria:

- a public bridge helps two NATed private members connect
- bridge nodes cannot inject private packets unless they are also roster
  members
- local transit behavior is visible and configurable

### Phase 6: Local Broker

- Add local FIPS broker IPC.
- Add discovery and compatibility probing from `nostr-vpn`.
- Fall back to embedded mode when no broker is available.
- Keep policy enforcement inside `nostr-vpn`.

Exit criteria:

- multiple local apps can reuse broker connectivity
- `nostr-vpn` still controls its private packet admission policy
- broker absence does not change user-visible behavior

### Phase 7: Mobile Integration

- Embed FIPS in Android `VpnService`.
- Embed FIPS in the iOS packet tunnel.
- Use internal route classification for FIPS private mesh and optional
  WireGuard exit.
- Add mobile status reporting for FIPS peer paths.

Exit criteria:

- no external FIPS daemon requirement on mobile
- one mobile VPN profile can carry both FIPS private mesh and optional
  WireGuard exit
- app UI distinguishes private mesh path from exit path

## Tests

Prefer end-to-end tests over mocks:

- two embedded FIPS endpoints exchange `nostr-vpn/ip/1` frames
- no TUN interface is created in embedded mode
- unknown protocol is rejected
- non-roster peer cannot deliver private packets
- bridge peer can assist connectivity without private membership
- private route goes to FIPS while default route goes to WireGuard
- mobile packet classifier sends the same synthetic packets to the same
  backend choices as desktop

Unit tests are useful only for route classification and policy edge cases.

## Open Questions

- Should `nostr-vpn/ip/1` carry raw IP packets, length-prefixed packet frames,
  or a small envelope with network id and route metadata?
- Does FIPS need per-application sub-identities, or is an app-owned Nostr
  identity enough for the first version?
- Which FIPS bridge policy is safe as a default for personal devices?
- Should broker IPC use Unix sockets/named pipes first, or reuse a FIPS local
  protocol over loopback?
- How much of WireGuard peer config should remain in node records during the
  migration window?

## First Patch Set

1. Add a no-TUN `FipsEndpointBuilder` API behind an experimental cargo feature.
2. Add protocol registration and source-attributed session delivery.
3. Add an embedded two-node example for `nostr-vpn/ip/1` framed bytes.
4. Add tests proving no system adapter is created in embedded mode.
5. Add a `nostr-vpn` `PrivateMeshBackend` abstraction while preserving the
   current WireGuard backend.
