# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## Unreleased

### Fixed

- Raised the default inbound `FilterAnnounce` false-positive-rate cap so
  legitimate near-capacity roster filters are not rejected during open Nostr
  discovery, while saturated poison filters remain rejected.
- Skipped Nostr advert signature verification for events whose cheap tags do
  not target the configured app, reducing open-discovery CPU on low-power
  nodes.
- Stopped `configured_only` Nostr discovery from subscribing to ambient advert
  traffic; it now keeps configured-peer advert fetches and encrypted signaling
  without processing the public advert stream.
- Demoted routine Bloom and traversal backpressure logs from warning level so
  low-power nodes do not spend excessive CPU on repeated expected drops.

## [0.3.60] - 2026-06-15

### Fixed

- Tightened idle connected-UDP activation and slow-maintenance receive-loop
  slices together so packets arriving during idle maintenance stay inside the
  app release-gate priority wait budget.
- Bumped `fips-endpoint` to 0.3.35 so app-facing consumers pick up the
  `fips-core` 0.3.60 idle maintenance latency fix.

## [0.3.59] - 2026-06-15

### Fixed

- Reduced idle receive-loop slow-maintenance slices so a newly arriving
  priority transport packet is not held behind discovery/status work past the
  app release-gate latency budget.
- Bumped `fips-endpoint` to 0.3.34 so app-facing consumers pick up the
  `fips-core` 0.3.59 receive-loop latency fix.

## [0.3.58] - 2026-06-15

### Fixed

- Fixed Windows builds by keeping pipelined plaintext endpoint state available
  on non-Unix targets while preserving Unix-only raw-socket send paths.

## [0.3.57] - 2026-06-14

### Fixed

- The receive loop now shortens side-queue interleaves while endpoint send
  commands are waiting, gives selected endpoint commands a larger bounded drain
  turn, and keeps priority decrypt fallback work at non-packet cadence so bulk
  packet receive pressure does not delay endpoint command progress.
- Bumped `fips-endpoint` to 0.3.33 so app-facing consumers pick up the
  `fips-core` 0.3.57 rx-loop scheduling fix.

## [0.3.56] - 2026-06-12

### Fixed

- Fixed Windows builds after the dataplane worker split by making shared send
  target identity and FSP receive snapshot state available on non-Unix targets
  while keeping Unix raw-socket batching platform-gated.
- Bumped `fips-endpoint` to 0.3.32 so app-facing consumers pick up the
  Windows-buildable `fips-core` 0.3.56 patch.

## [0.3.55] - 2026-06-12

### Changed

- Split oversized dataplane, node, transport, and test modules into focused
  submodules and added a CI-enforced Rust source file line guard capped at
  1000 lines.
- Bumped `fips-endpoint` to 0.3.31 so the app-facing endpoint crate follows
  the `fips-core` 0.3.55 release.

### Added

- Added fast dataplane ownership checks and a Linux Docker dataplane safety
  harness covering queue pressure, priority traffic, and long-run routing
  reliability scenarios.

## [0.3.54] - 2026-06-07

### Fixed

- The FIPS receive loop now keeps control, heartbeat, and ACK-like endpoint
  work responsive while bulk tunnel egress is saturated by splitting endpoint
  commands into priority and bulk lanes and treating a full bulk worker queue
  as network backpressure instead of blocking the rx loop.

## [0.3.53] - 2026-06-07

### Fixed

- FMP rekey promotion now authenticates packets against the pending session
  before accepting a K-bit flip, preventing unauthenticated header flips from
  advancing the receive epoch.
- FMP msg1 rekey retransmits now respect the handshake resend budget with
  exponential backoff, while link-dead handling gives active rekeys time to
  finish before degrading the peer.
- Nostr traversal now suppresses duplicate responder-side sockets during dual
  auto-connect election, TCP/Tor inbound limits count accepted inbound sockets
  only, mesh-size estimates union overlapping Bloom filters, and selected
  poisoned mutex/logging unwraps no longer panic.

## [0.3.52] - 2026-06-07

### Fixed

- TCP bulk endpoint-data traffic now yields encrypt-worker capacity to
  control/session traffic, preventing queued session handshakes and mesh
  control packets from starving under sustained throughput.

## [0.3.51] - 2026-06-06

### Fixed

- Direct-path payload routing now keeps a healthy low-cost direct peer selected
  instead of falling through to fallback selection, improving stable LAN path
  throughput.
- macOS direct UDP sends are paced by default to avoid bursty utun/Wi-Fi queue
  stalls during high-throughput idle-daemon traffic.
- Bloom filter membership checks now reuse the SHA-256 hash pair across all
  filter probes, reducing per-packet routing overhead.

## [0.3.50] - 2026-06-06

### Fixed

- CI synthetic UDP topology tests now wait for multiple idle packet polls and
  serialize the burst-heavy medium tests with the large topology tests,
  preventing dropped one-shot handshakes under GitHub runner load.
- Endpoint-data fallback tests now keep draining node packets while waiting for
  endpoint events, and Windows ignores manually configured Unix encrypt workers
  so outbound FMP sends keep using the supported tokio UDP path.
- The macOS-only encrypt-worker bulk-lane marker is now allowed as dead code on
  non-macOS targets, fixing Linux Clippy with `-D warnings`.

## [0.3.49] - 2026-06-06

### Fixed

- TCP endpoint-data packets now backpressure instead of being dropped by the
  encrypt worker under bulk-send pressure, preventing stalled session
  initiation and direct endpoint-data delivery regressions in CI.
- Local route failures now shorten link-dead detection only for the affected
  peer, so one broken outbound path no longer demotes unrelated direct peers.
- Configured static UDP paths remain preferred while direct probing continues,
  and active refresh can reclaim lower-priority in-flight slots for those
  configured direct paths.

## [0.3.48] - 2026-06-06

### Fixed

- Authenticated packets from lower-priority alternate paths no longer rewrite a
  healthy preferred path's selected send tuple or liveness state, preventing
  public/reflexive traffic from demoting configured LAN gateway paths while
  still allowing degraded paths to roam to an authenticated alternate.

## [0.3.47] - 2026-06-06

### Fixed

- Peer-list refreshes now update existing retry state even when the peer entry
  itself is unchanged, preventing stale retry candidates from surviving after
  static/direct address hints have been refreshed.
- Nostr traversal initiators now bound the wait for an answer by the traversal
  attempt timeout instead of the full signal TTL, so stale offers fail and
  retry in seconds rather than waiting up to the event freshness window.

## [0.3.46] - 2026-06-06

### Fixed

- Active outbound path refreshes no longer demote a healthy preferred/static
  path to a lower-priority alternate that completed a later handshake, keeping
  configured LAN gateway paths sticky while still allowing upgrades from
  lower-priority or unusable paths.

## [0.3.45] - 2026-06-06

### Fixed

- Active direct-refresh retries are now processed by oldest due time before
  applying the per-tick cap, preventing one peer from being repeatedly deferred
  behind other active peers that keep requeueing probes.

## [0.3.44] - 2026-06-06

### Fixed

- Outbound refresh handshakes now match msg2 replies by their globally
  allocated sender index when the reply arrives through an equivalent UDP
  transport id, allowing NAT-rewritten gateway paths to promote instead of
  repeatedly timing out.

## [0.3.42] - 2026-06-06

### Fixed

- Authenticated outbound alternate-path refreshes now replace an existing
  healthy path even when the generic cross-connection tie-breaker would keep
  the old link, allowing configured LAN/static paths to promote after probing.

## [0.3.41] - 2026-06-06

### Fixed

- Direct candidate selection now honors explicit peer-address priority before
  freshness, so configured/static LAN hints can outrank fresh overlay adverts
  while still racing overlay candidates when capacity allows.

## [0.3.38] - 2026-06-05

### Fixed

- Stale direct UDP paths no longer get reinstalled into the connected-UDP
  fast path after link-dead, so fallback can carry traffic while direct
  probing keeps trying to recover the path.

## [0.3.37] - 2026-06-05

### Fixed

- Stale direct/FIPS links now remain probe targets but are no longer selected
  for payload or lookup routing, so fallback discovery can carry traffic after
  link-dead instead of blackholing packets on the dead UDP path.

## [0.3.36] - 2026-06-05

### Fixed

- Lookup responses now flush queued traffic over an already-established
  session after a direct path fails, so fallback routing starts carrying
  packets immediately when discovery finds a transit path.

## [0.3.35] - 2026-06-05

### Fixed

- Session-degraded direct paths no longer hide a usable tree/mesh fallback
  route; stale direct peers stay probeable while payload traffic uses the
  fallback.

## [0.3.34] - 2026-06-05

### Fixed

- Traversal/recent UDP paths now use a short liveness window even after they
  previously carried authenticated traffic, so NAT or hotspot path stalls fall
  back quickly while direct re-probing continues.
- Link-dead direct paths now mark payload routing degraded, keeping the stale
  direct path probeable without hiding an available mesh fallback route.

## [0.3.33] - 2026-06-05

### Fixed

- Link-dead direct UDP paths now become stale/probeable instead of
  reconnecting, so nvpn roster sessions can keep sending over mesh fallback
  while direct probes and late authenticated packets revive the path.

## [0.3.32] - 2026-06-05

### Fixed

- Healthy-but-slow direct UDP paths no longer hide clearly better learned or
  tree fallback routes; fallback can carry traffic while direct probing
  continues.
- Session traffic now demotes direct UDP after moderate recent loss instead
  of waiting for severe loss or link-dead timeout.
- Legacy macOS `FIPS_MACOS_CONNECTED_UDP=0` environment overrides no longer
  disable the default connected-UDP fast path from stale launchd plists.

## [0.3.31] - 2026-06-05

### Fixed

- Link-dead static UDP paths no longer count as fresh direct candidates while
  reconnecting, so fallback traffic cannot suppress the background direct
  re-probe loop after repeated mobile-hotspot-style drops.

## [0.3.30] - 2026-06-05

### Fixed

- Active direct-path retries now re-probe the last observed UDP endpoint while
  fallback mesh/relay traffic stays active, so link-dead liveness timeouts do
  not strand Nostr-discovered peers on fallback transport.
- Nostr-only configured peers without static addresses now keep probing their
  observed UDP path and still send reciprocal direct-refresh requests after a
  transient liveness failure.

## [0.3.29] - 2026-06-04

### Fixed

- Stale active UDP peers that rely on Nostr/NAT discovery now keep a direct
  refresh probe pending before link-dead removal, so NAT-rebound mobile
  hotspot paths can refresh instead of briefly falling back to mesh.
- Link-dead direct peers now immediately refresh fallback discovery through
  live transit peers while direct UDP probing continues in the background.
- Embedded endpoint peer snapshots now distinguish retry-only direct probes
  from authenticated link-layer connectivity.

## [0.3.28] - 2026-06-03

### Changed

- Embedded endpoint peer snapshots now report pending direct UDP probes so
  applications can show fallback transport and background direct probing as
  separate states.

### Fixed

- Link-dead direct paths now schedule quick direct reprobes while keeping
  fallback mesh/relay traffic active, instead of preserving long peer retry
  backoff.
- Link-dead direct liveness failures no longer create long Nostr traversal
  cooldowns for configured peers, and configured mesh-signal refreshes can
  still request immediate reciprocal probing during stale endpoint churn.
- Fresh overlay-discovered UDP candidates now outrank stale unstamped static
  hints when the retry budget is constrained.

## [0.3.27] - 2026-06-02

### Fixed

- Local route outages during network changes now retry quickly without
  increasing peer/NAT failure backoff, so transient `Network is unreachable`
  or `No route to host` sends do not strand peers on stale relay paths.
- Stale local route errors now stop shortening link-dead detection after a
  brief recovery window, and rx-loop maintenance stalls no longer count as
  repeated bad NAT traversal paths.
- Link heartbeats now run before slower retry/discovery maintenance so the
  watchdog cannot skip liveness traffic during bulk tunnel pressure.
- Proven direct endpoint paths now use the normal link-dead timeout instead
  of staying on the short "recent endpoint" timer forever, and FMP worker
  queueing now classifies established session datagrams as bulk correctly.

## [0.3.26] - 2026-06-02

### Fixed

- Saturated encrypt-worker queues now drop bulk endpoint data instead of
  blocking the node receive loop, preventing active tunnels from being
  removed by false link-dead timeouts while control traffic is still queued.
- macOS encrypt workers now reserve and prioritize capacity for FIPS control
  frames so heartbeats, traversal signals, and routing control can pass ahead
  of bulk tunnel traffic under Screen Sharing or other high-rate streams.

## [0.3.25] - 2026-06-02

### Fixed

- Direct-path traversal failures now cool down stale recent endpoint paths
  after link-dead timeouts instead of repeatedly promoting a silent path.
- Recently advertised endpoint paths now use a bounded liveness timeout so a
  stale direct path fails over sooner without shortening normal relayed links.

## [0.3.24] - 2026-06-01

### Fixed

- FMP rekey responders now wait for an authenticated peer K-bit flip instead
  of time-cutting over on their own maintenance tick, avoiding split-session
  direct links after rekey churn.
- Connected UDP peer drains now detach their worker thread on drop, avoiding a
  runtime-driver deadlock during direct-path teardown.

## [0.3.23] - 2026-06-01

### Fixed

- Connected UDP drains drop stray NAT punch probes after adoption so stale
  punch traffic cannot poison direct peer receive paths.
- Direct-path refresh now keeps existing mesh reachability while retrying stale
  endpoint hints, including active-peer traversal retries with backoff.
- Nostr mesh signaling can warm configured roster peer sessions over an
  existing mesh route before direct NAT traversal is established.
- Open-discovery enqueue limits now count already-active non-roster peers so
  cached transit peers cannot bypass the pending-peer cap.

## [0.3.22] - 2026-05-27

### Fixed

- Connected UDP peer drains now consume `SO_ERROR` after `POLLERR`, preventing
  unreachable peers from waking the drain loop continuously.
- Linux encrypted sends now use bounded fair admission per peer, so saturated
  bootstrap/server nodes share sender capacity across peers while preserving a
  small priority boost for explicitly configured peers.

## [0.3.21] - 2026-05-27

### Fixed

- Ported upstream admission gates so saturated nodes stop starting outbound
  retries, Nostr NAT traversal handshakes, or Msg2 replies for net-new peers
  once `node.limits.max_peers` is reached.
- TreeAnnounce now re-broadcasts periodically even when parent selection is
  unchanged, letting stable meshes heal missed announce delivery.
- Mesh-size estimation no longer double-counts the current parent while cached
  peer declarations are stale after a parent switch.

## [0.3.20] - 2026-05-27

### Added

- `fips-core` now exposes `node.connected_udp.*` settings for the connected UDP
  fast path, including configurable file-descriptor reserve headroom.

### Fixed

- Connected UDP activation now respects the process `RLIMIT_NOFILE` budget so
  high-peer nodes do not exhaust descriptors while installing per-peer sockets.
- Peer receive-drain shutdown now closes its wake pipe promptly and avoids
  blocking when an idle connected UDP drain is dropped.
- Multi-file YAML config loading now deep-merges partial sections so overlays
  can set `node.connected_udp` without replacing unrelated `node` defaults.

### Changed

- Debian service packaging now raises `LimitNOFILE` for higher-capacity FIPS
  nodes.

## [0.3.19] - 2026-05-27

### Fixed

- FSP rekey handling now preserves epoch state more defensively.
- Configured-only discovery now rejects unknown peers instead of accepting
  ambient overlay discoveries.
- Peer update priority is preserved when refreshing peer configuration.
- Static peer dialing avoids an overlay race after startup.
- Build metadata no longer forces Cargo rebuilds after unrelated git fetches.

## [0.3.18] - 2026-05-22

### Fixed

- `fips-core` host firewall support now compiles on unsupported targets such as
  iOS and Android, while still reporting host firewall support as unavailable.

## [0.3.17] - 2026-05-22

### Added

- `fips-core` now exposes a reusable host firewall helper for FIPS TUN
  interfaces, with Linux nftables and macOS PF backends.

## [0.3.16] - 2026-05-21

### Fixed

- Musl Linux builds no longer pull in the nftables gateway dependency, avoiding
  host-side `libclang` dynamic-loading failures when embedding FIPS in static
  release binaries.

## [0.3.15] - 2026-05-20

### Added

- Embedded endpoints can now opt into host-local raw Ethernet discovery with
  `FipsEndpointBuilder::local_ethernet(interface)`. Ethernet beacons may carry
  an optional discovery scope label, and endpoint configs inherit the builder's
  discovery scope for local Ethernet beacons.

### Fixed

- Outbound-only stale FSP sessions now expire and re-handshake when peers stop
  returning authenticated frames, preventing a direct path from staying wedged
  until process restart.

## [0.3.14] - 2026-05-18

### Added

- `wss://temp.iris.to` is now part of the built-in Nostr discovery relay
  defaults for adverts and encrypted signaling.

## [0.3.13] - 2026-05-18

### Added

- Embedded endpoints now expose live Nostr relay status snapshots and can
  update discovery relay sets at runtime without rebuilding the endpoint.

## [0.3.12] - 2026-05-18

### Fixed

- Reply-learned routing now prefers a live learned mesh route over a stale
  direct peer link, so failed NAT paths no longer hide an available routed path.

## [0.3.11] - 2026-05-17

### Fixed

- Reply-learned lookup fanout is limited to configured/bootstrap transit peers
  so open-discovery peers do not become ambient transit for unrelated
  destinations.
- Open-discovery lookup fallback now respects the configured transit gate while
  still allowing direct lookups to the discovered peer itself.

## [0.3.10] - 2026-05-16

### Fixed

- Active peers now race refreshed alternate paths without tearing down the
  current working session first. This lets peers move from relayed or stale
  paths to fresh direct candidates when discovery data changes.
- Discovery retry work is bounded per tick so stale or unreachable peers cannot
  overwhelm a node while reconnecting.
- Recovery rekeys and peer restarts now refresh or reset stale FSP sessions,
  preventing old session state from blackholing newly discovered paths.
- Nostr discovery startup no longer blocks node startup while initial relay
  work is in progress.
- Stale same-path discovery updates now refresh active peer state instead of
  being ignored as no-ops.

### Added

- Embedded startup tracing for FIPS users that need to diagnose slow startup.
- Runtime control for disabling FIPS worker pools in constrained embeddings.

## [0.3.9] - 2026-05-16

### Fixed

- `Node::run_open_discovery_sweep` now expedites the retry queue entry of
  a CONFIGURED peer when a fresh overlay advert lands. Previously the
  sweep skipped configured peers entirely (they're driven by the normal
  retry path), so on cold-start every initial `initiate_peer_connection`
  failed before any overlay data was available, each pushed the peer
  into `retry_pending` with exponential backoff (5/10/20/40/80s), and by
  the time the next backoff slot fired the Nostr advert had already
  been cached — we just sat on it for ~80s. The sweep now pulls
  `retry_after_ms` forward to "now" so the next `process_pending_retries`
  tick fires immediately with the freshly available addresses. Cuts
  cold-start time for NAT'd peers from ~1 min to a few seconds.

## [0.3.7] - 2026-05-15

### Fixed

- Session retries after discovery now restart stale non-established FSP
  sessions so a fresh LookupResponse rebuilds `SessionSetup` with the current
  route/coordinates instead of keeping an old pending handshake that can
  blackhole routed or relayed peers.
- FSP packets from the previous key epoch that arrive during the post-rekey
  drain window no longer count toward session AEAD recovery if they are too old
  or replayed to authenticate with the retained previous session. Current-epoch
  failures still trigger recovery, but stale old-epoch drain traffic no longer
  causes unnecessary rekey churn.
- FSP rekey initiators now retain and resend the final XK `SessionMsg3`
  while the responder has not proven the pending session. Old-session traffic
  during the drain window no longer clears that retained rekey payload, which
  prevents a single lost final rekey packet from splitting peers across old/new
  session keys and triggering AEAD recovery churn.
- Worker-reported FMP AEAD failures are now suppressed during the bounded
  fresh-session drain window until the new worker replay window authenticates
  traffic. This prevents stale ciphertext left over from peer restart, roaming,
  or rekey from immediately triggering another recovery rekey on a healthy new
  link session.
- Stale Nostr UDP traversal completions/failures are now ignored once the peer
  is already connected or already handshaking. This prevents speculative direct
  path retries from creating duplicate link attempts and recovery-rekey noise
  for peers that are already reachable through the mesh.
- Reply-learned discovery now fans lookup requests out to live peers even when
  a tree/bloom candidate exists. This prevents stale tree state or
  NAT-asymmetric VM/host topologies from leaving peers permanently pending when
  another neighbor has a working route.

### Added

#### Security

- Mesh-interface nftables baseline (Linux). Ships `/etc/fips/fips.nft`
  as a documented operator conffile and `fips-firewall.service`
  (disabled by default) for default-deny inbound on the `fips0` mesh
  interface. Operators enable explicitly with
  `systemctl enable --now fips-firewall.service`. Drop-ins in
  `/etc/fips/fips.d/*.nft`. See `docs/fips-security.md`.

#### Platform Support

- Windows platform support: wintun TUN device, TCP control socket on
  `localhost:21210` (in place of the Unix domain socket), Windows
  Service lifecycle (`--install-service`, `--uninstall-service`,
  `--service`), ZIP packaging with PowerShell install/uninstall scripts,
  and CI build/test matrix entry
  ([#45](https://github.com/jmcorgan/fips/pull/45))
- macOS platform support: native `utun` TUN interface management, raw
  Ethernet transport via BPF, `.pkg` packaging with launchd plist and
  uninstall script, x86_64 cross-compile from arm64, and CI build/unit
  test jobs
- `gateway` Cargo feature flag gates the optional Linux-only
  `rustables` dependency so macOS and Windows builds never pull in
  nftables bindings

#### Outbound LAN Gateway

- New `fips-gateway` binary that lets unmodified LAN hosts reach FIPS
  mesh destinations via DNS-allocated virtual IPs and kernel nftables
  NAT. Virtual-IP pool (`fd01::/112` by default) with state-machine
  lifecycle and TTL-based reclamation; conntrack-backed session
  tracking; proxy NDP on the LAN interface; control socket at
  `/run/fips/gateway.sock` with `show_gateway` and `show_mappings`;
  fipstop Gateway tab with pool gauge and mappings table; design doc
  at `docs/design/fips-gateway.md`; integration test harness
- Gateway packaging: systemd service unit with `After=fips.service`,
  Debian and AUR package entries, OpenWrt procd init with dnsmasq
  forwarding, proxy NDP, RA route advertisements, and IPv6 forwarding
  sysctls. Gateway enabled by default on OpenWrt

#### Nostr-Mediated Discovery and NAT Traversal

- Optional overlay-discovery and NAT-hole-punching path behind the
  `nostr-discovery` cargo feature. Nodes publish signed overlay adverts
  as Nostr kind `37195` parameterized replaceable events listing
  reachable transport endpoints to a configurable set of public relays,
  and consume peer adverts to populate fallback addresses for
  configured peers or, under `policy: open`, for non-configured peers
  within a budget cap. The kind value is FIPS-specific: `37195` sits in
  the application-defined replaceable range `30000–39999`, and the
  digits visually spell `FIPS` (7=F, 1=I, 9=P, 5=S)
- STUN-assisted UDP hole punching for `addr: "nat"` UDP endpoints. STUN
  reflexive observation, gift-wrap (NIP-59) offer/answer signaling, and
  candidate-pair punch planner (LAN-private + reflexive paths attempted in
  parallel). Successful punches hand the live socket into the standard
  FIPS UDP transport via a bootstrap-handoff API
- New `node.discovery.nostr.*` configuration tree with operator-tunable
  resource caps, replay tracking, and punch timing; new per-transport
  `advertise_on_nostr` / `public` flags. Cross-field validation at
  startup catches mis-configured combinations
- Docker NAT lab covering cone, symmetric (TCP-fallback), and LAN
  scenarios, wired into the integration CI matrix

#### Examples

- macOS WireGuard sidecar: run FIPS in a local Docker container and
  route `.fips` traffic from the macOS host through a WireGuard tunnel
  to the container's `fips0` interface. Only traffic destined for
  `fd00::/8` transits the sidecar; regular internet traffic continues
  to use the host network
  ([#51](https://github.com/jmcorgan/fips/pull/51))

#### Bluetooth Transport

- Bluetooth Low Energy (BLE) L2CAP Connection-Oriented Channel transport
  with per-link MTU negotiation, behind the `ble` Cargo feature flag
  (default-on, Linux only, requires BlueZ)
- BLE peer discovery via continuous scan/probe with cooldown-based
  deduplication (`probe_cooldown_secs`, default 30s)
- Continuous BLE advertising for reliable L2CAP connectivity
- Cross-probe tie-breaker using deterministic NodeAddr comparison
- Connection pool with configurable capacity and eviction

#### DNS

- Multi-backend `.fips` DNS configuration: a detection script
  configures whichever resolver is available, in priority order:
  systemd dns-delegate (systemd >= 258), systemd-resolved via
  `resolvectl`, standalone dnsmasq, NetworkManager with the dnsmasq
  plugin. Teardown reads the recorded backend from
  `/run/fips/dns-backend` and reverses only what was applied
  ([#58](https://github.com/jmcorgan/fips/pull/58),
  fixes [#52](https://github.com/jmcorgan/fips/issues/52))

#### Operator Configuration

- `node.log_level` config field (case-insensitive, default `info`)
  replaces the hardcoded `RUST_LOG=info` previously baked into
  systemd units and the OpenWrt procd init script. The daemon now
  loads config before initializing tracing so the configured level
  takes effect; `RUST_LOG` still overrides when set

#### Operator Tooling

- `fipsctl show identity-cache` lists every cached node identity
  (npub, IPv6 address, display name, LRU age) alongside the
  configured cache capacity
- `fipsctl show peers` extended with per-peer security signals
  (replay suppression count, consecutive decrypt failures), Noise
  session counters, session indices, and rekey lifecycle state
- `fipsctl show sessions` extended with handshake resend count
  during establishment and rekey/session health fields when
  established (session start, K-bit epoch, coords warmup remaining,
  drain state)
- `fipsctl show cache` now includes individual coordinate cache
  entries (tree coordinates, depth, path MTU, age). The top-level
  count field was renamed from `entries` to `count` for clarity
- `fipsctl show routing` expands `pending_lookups` from a count to
  per-target detail (attempt, age, last sent), adds pending TUN
  packet queue depth, and adds per-peer connection retry state
  ([#42](https://github.com/jmcorgan/fips/pull/42),
  [@osh](https://github.com/osh))

#### Documentation

- Pre-implementation proposal for NAT traversal using Nostr relays
  as the signaling channel and STUN for reflexive address discovery
  (`docs/proposals/`)

#### Packaging and Deployment

- Linux release artifact workflow: builds x86_64 and aarch64 tarballs
  and `.deb` packages on `v*` tag push, with SHA-256 checksums
- AUR publish workflow for tagged stable releases
- Arch Linux AUR packaging for `fips` (release) and `fips-git`
  (development) packages with sysusers.d/tmpfiles.d integration
  ([#21](https://github.com/jmcorgan/fips/pull/21),
  [@dskvr](https://github.com/dskvr))
- `transports.udp.outbound_only` (default `false`). When true, the UDP
  transport binds a kernel-assigned ephemeral port (`0.0.0.0:0`) instead
  of the configured `bind_addr`, refuses inbound handshakes, and is
  never advertised on Nostr regardless of `advertise_on_nostr`. Use
  this to participate in the mesh as a pure client — initiate outbound
  links without exposing an inbound listener on a known port.
  Implements the long-form fix for `udp.bind_addr: "127.0.0.1:..."`
  not actually working as a workaround (Linux pins the loopback source
  IP, dropping outbound flows to external peers at the routing layer)
- `transports.udp.accept_connections` (default `true`). Mirrors the
  Ethernet/BLE knob; setting to `false` produces a "client" posture
  (initiate outbound, refuse inbound msg1 from new addresses). The
  Node-level handshake gate carves out msg1 from peers already
  established on this transport so rekey continues to work
  (ISSUE-2026-0004). Affects every transport via the `Transport` trait
- Startup validation now rejects `transports.udp[*].bind_addr` set to a
  loopback address when at least one peer has a non-loopback UDP
  address. Replaces the silent "peer link won't establish" failure
  mode where Linux's source-address routing check dropped outbound
  flows from the loopback-bound socket. `outbound_only: true` is
  exempt from the check (it overrides `bind_addr` to `0.0.0.0:0`)
- `fips-gateway` DNS upstream probe now retries up to 5 times with a
  1-second per-attempt timeout and a 1-second delay between attempts
  (~10 second worst-case wait), instead of a single 3-second hard-fail.
  Covers the cold-boot race where the daemon's TUN is up (the systemd
  ExecStartPre wait gates on that) but the DNS responder is still
  binding `[::1]:5354`. Without retry the gateway exited and relied on
  `Restart=on-failure` for recovery (5-second blip + spurious error
  log line per cycle); with retry the gateway recovers gracefully
  without a unit restart
- `packaging/debian/fips-gateway.service` now waits up to 30 seconds
  for the daemon's `fips0` TUN to appear before exec'ing the gateway
  binary (`ExecStartPre` poll loop). Eliminates the cold-boot race
  where `fips-gateway` exits with `fips0 interface not found` and
  recovers via `Restart=on-failure`, producing a 5-second blip and a
  spurious error log line per restart cycle. If `fips0` never appears
  within 30 seconds, the existing error path runs as before
- `packaging/debian/build-deb.sh` now auto-derives a per-commit Debian
  Version field for dev builds (Cargo.toml version ending in `-dev`)
  using the form `<base>~dev+git<YYYYMMDD>.<sha>[.dirty]-1`, e.g.
  `0.3.0~dev+git20260429.6def31b-1`. Each commit produces a uniquely-
  comparable Version string so `apt install ./*.deb` and
  `ansible.builtin.apt: deb:` no longer silently no-op when one dev
  build is installed on top of another. The `~dev` marker sorts
  pre-`0.3.0` so a tagged release supersedes any prior dev .deb.
  Tagged release builds (no `-dev` in Cargo.toml) keep the clean
  `<version>-1` form. Operator override via `--version` still wins
- One-shot startup advert sweep for Nostr open-discovery. On daemon
  startup under `node.discovery.nostr.policy: open`, after a short
  settle delay (`startup_sweep_delay_secs`, default 5s) the cached
  overlay-advert table is iterated once and recent adverts (newer
  than `startup_sweep_max_age_secs`, default 3600s) are queued for
  outbound retry, modulo the same skip-filters as the per-tick sweep
  (configured peer, already connected, retry-pending, connecting).
  Closes the gap where peers learned only through relay backlog at
  startup were not dialed until they republished.
- Diagnostic logging on the open-discovery sweep. Each `queued retry`
  now logs at info-level with the peer short-npub and advert age,
  and a one-line summary (cached count, queued count, per-reason
  skip counts) is emitted on every startup sweep and on any per-tick
  sweep that queues at least one retry. Operator-facing visibility
  into what the auto-dial path is doing.

### Changed

- `node.rekey.after_messages` default raised from `65536` to
  `281474976710656` (`2^48`). The old packet-count default forced
  high-throughput packet tunnels to run full FMP/FSP rekeys every few
  seconds, so rekey cutover churn could dominate throughput even though
  the time-based `node.rekey.after_secs` cadence already provides
  periodic forward-secrecy rotation. Operators can still lower
  `node.rekey.after_messages` explicitly for CI stress tests or more
  aggressive packet-count rekey policy.
- Per-peer connected UDP sockets and recv drains are now enabled on
  macOS as well as Linux. Darwin routes matching peer 5-tuples to the
  connected socket under `SO_REUSEPORT`, so the encrypt worker can use
  `send(2)` on a connected fd instead of repeating `sendto(2)` sockaddr
  work for every tunneled packet while the paired drain preserves
  inbound delivery.
- macOS encrypt-worker drain batches now default to 8 packets instead
  of 32. Darwin has no userspace UDP GSO/sendmmsg path, and MacBook
  Wi-Fi sender tests showed large worker bursts could collapse TCP
  throughput even without kernel `ENOBUFS`; the smaller default trims
  burst size without forcing one worker wake per datagram, while
  `FIPS_MACOS_WORKER_BATCH` remains available for machine-specific
  benchmarks.
- The connected-UDP worker path now reuses the connected socket's
  kernel peer address for dispatch instead of re-resolving the
  configured transport address per packet. This removes an avoidable
  cached-DNS/string-parse await from the macOS sender hot path.
- Noise session ChaCha20-Poly1305 backend switched from RustCrypto's
  `chacha20poly1305` to `ring 0.17`. ring wraps BoringSSL's
  hand-tuned ChaCha20-Poly1305 implementation, dispatching to NEON
  on aarch64 and AVX2 / AVX-512 on x86_64 — typically 3-5 GB/s/core
  vs the ~600-800 MB/s/core RustCrypto soft path on the same
  hardware. Wire format unchanged: ChaCha20-Poly1305 is
  byte-deterministic for a given `(key, nonce, plaintext, aad)`,
  so any correct AEAD produces identical ciphertext and a mixed
  pre-swap / post-swap mesh interoperates without protocol
  awareness. The keyed AEAD is now cached on `CipherState` instead
  of being re-derived per packet (the cached Poly1305 key state is
  the actual perf win); `EndToEndState` grew from ~600 B to
  ~1.5 KB as a consequence and is annotated
  `#[allow(clippy::large_enum_variant)]` since boxing would re-add
  a per-packet indirection on every encrypt/decrypt. aarch64
  measurements (Apple Silicon docker, two nodes): TCP 1-stream
  437 → 1097 Mbps (~2.5×); UDP at 1000 Mbit goes from
  599 Mbps / 40 % loss to lossless line-rate; 3-node ping under
  load 7.68 ms avg / 215 ms max → 0.72 ms / 3.6 ms max as the
  relay path stops being crypto-bound
  ([#80](https://github.com/jmcorgan/fips/pull/80),
  [@mmalmi](https://github.com/mmalmi))
- Nostr-mediated overlay discovery is now always-on. The
  `nostr-discovery` cargo feature flag has been dropped along with the
  `optional = true` markers on `nostr` / `nostr-sdk` dependencies and
  every `#[cfg(feature = "nostr-discovery")]` source-level gate. Plain
  `cargo build` produces a binary with overlay discovery available
  whether or not the operator enables it via
  `node.discovery.nostr.enabled`. Mirrors PR #79's collapse of the
  `tui` / `ble` / `gateway` features in favor of platform cfg gates.
  No runtime behavior change — the feature was in `default` already
- MMP link-layer report intervals retuned for constrained transports:
  steady-state floor raised from 100ms to 1000ms, ceiling from 2000ms
  to 5000ms. Cold-start uses a 200ms floor for the first 5 SRTT samples
  before switching to steady-state. Reduces BLE overhead ~10× while
  keeping reports well above the EWMA convergence threshold.
  Session-layer intervals unchanged
- 35 info-level log messages demoted to debug (handshake
  cross-connection mechanics, periodic MMP telemetry, TUN/transport
  shutdown, retry scheduling). Info output now focuses on
  operator-relevant state changes: lifecycle events, peer promotions,
  session establishment, parent switches, transport start/stop
- **Breaking (control socket JSON):** `show_cache` response field
  `entries` has changed type from a `u64` count to an array of entry
  objects; a new `count` field carries the previous scalar value.
  `show_routing` response field `pending_lookups` has changed type
  from a `u64` count to an array of per-target lookup objects.
  External consumers parsing these fields as numbers must be
  updated. In-tree `fipstop` is adjusted to the new schema. The
  control socket interface is still pre-1.0 and not covered by
  stability guarantees
- Discovery rate limiting retuned to be less aggressive at cold start.
  The previous defaults (30s base post-failure suppression, doubling
  to a 300s cap, with reset only on parent change / new peer / first
  RTT / reconnection) reliably outlasted initial mesh convergence: a
  single timed-out lookup during bloom-filter propagation suppressed
  any retry for 30s while none of the reset triggers fired on a
  stable post-handshake topology. The suppression window dictated
  effective time-to-converge instead of bounding repeat traffic.
  Replaces the single-lookup-with-internal-retry model
  (`timeout_secs`/`retry_interval_secs`/`max_attempts`) with a
  per-attempt timeout sequence in
  `node.discovery.attempt_timeouts_secs` (default `[1, 2, 4, 8]`).
  Each attempt sends a fresh `LookupRequest` with a new `request_id`,
  which lets successive attempts take different forwarding paths as
  the bloom and tree state evolve. The destination is declared
  unreachable only after the full sequence is exhausted (15s total
  at the default). Disables post-failure suppression by default
  (`backoff_base_secs`/`backoff_max_secs` now both `0`); operators
  with chatty apps generating repeat lookups against unreachable
  destinations can opt back in
- Validate bloom filter fill ratio on FilterAnnounce ingress.
  Inbound FilterAnnounce messages whose derived false-positive
  rate exceeds `node.bloom.max_inbound_fpr` (new config field,
  default 0.05) are rejected silently on the wire, logged at WARN,
  and counted in a new `bloom.fill_exceeded` counter. A
  rate-limited WARN also fires if our own outgoing filter's FPR
  exceeds the cap. `BloomFilter::estimated_count` now takes
  `max_fpr` and returns `Option<f64>`, returning `None` for
  saturated filters; this propagates through `compute_mesh_size`
  into `estimated_mesh_size` (already `Option<u64>`)
- Generic systemd install tarball brought to feature parity with
  the `.deb` and AUR packages. The tarball now ships the
  `fips-gateway` binary with its (operator-opt-in)
  `fips-gateway.service`, a `fips-firewall.service` unit with the
  `/etc/fips/fips.nft` mesh-interface nftables baseline (also
  opt-in), an `/etc/fips/fips.d/` operator drop-in directory for
  per-service nft rules, and the multi-backend `fips-dns-setup` /
  `fips-dns-teardown` helpers. `install.sh` and `uninstall.sh`
  handle the new units and conffile (preserve-on-upgrade for
  `fips.nft`, like `fips.yaml`). `README.install.md` documents
  the gateway, firewall, and DNS-routing services. Closes the
  longest-standing parity gap for non-Debian / non-Arch systemd
  Linux distros (Fedora, RHEL/CentOS, openSUSE, etc.) installing
  from the release-distribution tarball.

### Fixed

- End-to-end XK session setup now keeps and resends the final
  `SessionMsg3` for a short retry window after the initiator enters
  `Established`. This prevents one-way half-established sessions when
  the final handshake packet is lost: the initiator no longer sends
  encrypted data forever to a responder still waiting in `AwaitingMsg3`,
  and the responder can also resend its `SessionAck` when early encrypted
  data arrives.
- Rekey cutover now repairs a missing or stale FMP receive-index cache
  entry before registering the promoted session with the decrypt-worker
  pool. Previously this path relied on a debug assert that the pending
  index had already been pre-registered; if that assumption failed
  under high-throughput rekey churn, debug builds could panic and
  release builds could miss the fast decrypt-worker path or produce
  post-cutover decrypt failures until the link recovered.
- Simultaneous rekeys now use the same deterministic NodeAddr
  tie-breaker after msg2 as initial session setup. If both peers have a
  pending rekey and one side starts over, the losing side abandons the
  stale pending state and responds instead of leaving the pair stuck
  with incompatible pending sessions until a later recovery path fires.
- Encrypt-worker dispatch now applies backpressure instead of dropping
  tunneled IP packets when a bounded worker queue fills. The old
  behavior was appropriate for application UDP but harmful for
  TCP-over-TUN, where internal queue loss caused avoidable
  retransmits and large directional throughput drops under load.
- UDP send workers now also treat `ENOBUFS`/`ENOMEM` from the kernel
  transmit path as backpressure instead of a fatal batch error. This is
  especially important on macOS Wi-Fi, where the NIC/socket queue can
  fill before `send(2)` reports `WouldBlock`; dropping that batch made
  MacBook outbound tunnels lose packets at rates Tailscale handled. The
  retry path yields instead of sleeping, avoiding the old whole-batch
  loss mode without imposing the artificial per-packet sleep cap that
  limited MacBook Wi-Fi throughput. The remaining MacBook-to-Ethernet
  ceiling is the single per-peer encrypt/send lane, which needs the
  wireguard-go-style split between parallel encryption and sequential
  transmission.
- Generic systemd install tarball: `install.sh` now correctly
  resolves the `fips-dns-setup` and `fips-dns-teardown` helpers
  from the tarball staging directory. Previously the script
  referenced them at `${SCRIPT_DIR}/../common/`, a path that
  exists only in the source-repo layout, not in the extracted
  tarball. Bug latent since the multi-backend DNS helpers
  landed in `7260ad2`; only manifested when operators ran
  `install.sh` from an extracted tarball rather than from a
  source checkout.
- UDP transport with `advertise_on_nostr: true` + `public: true` +
  a wildcard `bind_addr` (e.g. `0.0.0.0:2121`) is now advertised
  with its STUN-discovered public IPv4 instead of being silently
  dropped from the published Kind 37195 advert. Previously the
  advert builder filtered the wildcard out (since `0.0.0.0` is
  not a valid endpoint), but emitted no log explaining what
  happened — operators saw the daemon up, both flags set, and
  no UDP endpoint in the advert. The fix runs a one-shot STUN
  observation against an ephemeral socket on the daemon's
  configured `stun_servers` and combines the reflexive IPv4 with
  the configured listener port for the advert (`udp:<eip>:<port>`).
  Successful STUN observations are cached per-transport for one
  `advert_refresh_secs` cycle (default 30 min) so we don't re-STUN
  every refresh. Failed observations are cached for only 60s, so
  a transient STUN flake at startup retries within ~a minute and
  grows the advert with UDP as soon as STUN starts working —
  rather than waiting the full 30-min cycle. Per-server STUN
  response timeout is 5s for the advert-publish path (vs. 2s for
  the latency-sensitive per-traversal path), giving slow
  first-call STUN time to complete without giving up. On STUN
  failure, the wildcard-bind path still skips, but now logs a
  loud `warn!` pointing at the operator-side fixes (set
  `external_addr`, bind to a specific IP, or ensure `stun_servers`
  reachable). Restores zero-config public-IP autodiscovery on
  AWS EIP / GCP / Azure setups where binding to the public IP
  directly is impossible (1:1 NAT)
- New `external_addr` field on `transports.udp.*` and
  `transports.tcp.*` for explicit advertise-as override. Accepts
  either a bare IP (`"198.51.100.1"` — the configured `bind_addr`
  port is appended) or a full `host:port`
  (`"198.51.100.1:8443"`). Takes precedence over both the bound
  address and any STUN-derived autodiscovery. Required for TCP
  on cloud-NAT setups (AWS EIP, GCP/Azure external IPs) where
  binding to the public IP directly fails with `EADDRNOTAVAIL`
  (the EIP isn't on a host interface). Optional but useful for
  UDP as a deterministic alternative to STUN — operators who
  want to skip STUN egress (or whose STUN is blocked) can
  specify it explicitly. Without `external_addr`, TCP with a
  wildcard `bind_addr` + `advertise_on_nostr: true` now logs a
  loud `warn!` pointing at the two fixes instead of silently
  skipping
- Nostr-discovery now tolerates ±60s of clock skew on offer/answer
  freshness checks so a responder whose wall clock leads the
  initiator's by less than that no longer silently rejects every
  offer. Previously, a public-test daemon with un-NTP'd peers (or
  long uptime — `now_ms()` anchors to `SystemTime` once at startup,
  then advances monotonically; post-startup NTP step adjustments
  don't propagate) would see ~100% signal-timeout rate against
  skewed peers, indistinguishable from "peer is offline." New
  optional `offerReceivedAt` field on the answer payload lets the
  initiator log per-peer NTP-style skew estimates (DEBUG when ≥30s)
  for operator visibility. Backward-compatible — older responders
  that don't fill the field still produce valid answers
- Nostr-discovery NAT-traversal failure suppression: per-npub
  consecutive-failure counter triggers a 30-min extended cooldown
  after 5 failures, preventing the daemon from hammering Nostr
  relays with offers to peers that have gone away. WARN log lines
  rate-limited to one per peer per 5 min (subsequent failures
  emit DEBUG with `consecutive_failures` + remaining `cooldown_secs`).
  Threshold-crossing also fires a one-shot active re-check of the
  peer's Kind 37195 advert against `advert_relays`; absent →
  evict cache; newer → refresh + reset streak; same → cooldown
  stands. New `failure_streak_threshold`, `extended_cooldown_secs`,
  `warn_log_interval_secs`, `failure_state_max_entries` config
  fields under `node.discovery.nostr`. Per-peer state visible in
  `fipsctl show peers` JSON under `nostr_traversal`
- Tor onion adverts published over Nostr overlay discovery now
  include the public-facing port (`<onion>.onion:<port>`) instead of
  just the bare onion hostname. The publisher previously emitted a
  bare onion that the parser refused (`expected host:port`),
  producing a persistent retry-fail loop on any peer whose Tor
  advert was the only entry in the discovery cache. New
  `transports.tor.advertised_port` config field (default `443`,
  matching the Tor `HiddenServicePort` convention) controls the
  advertised port; operators with non-default virtual ports can
  override.
- Control socket path detection in fipsctl and fipstop now checks for
  the `/run/fips/` directory instead of the socket file inside it, so
  users not yet in the `fips` group get a clear "Permission denied"
  error instead of a misleading "No such file" fallback to
  `$XDG_RUNTIME_DIR` ([#30](https://github.com/jmcorgan/fips/issues/30),
  reported by [@Sebastix](https://github.com/Sebastix))
- OpenWrt ipk build excluded BLE feature that requires D-Bus, which is
  unavailable on OpenWrt targets
- IPv6 routing policy rule added at TUN setup to protect `fd00::/8`
  from interception by Tailscale's table 52 default route
- Bloom filter routing no longer swallows traffic when no bloom
  candidate is strictly closer than the current node. `find_next_hop`
  now falls through to greedy tree routing in that case instead of
  returning `NoRoute`, which previously caused dropped packets in
  topologies where the tree parent was closer but not a bloom
  candidate
- Nostr-discovered peers running an FMP-protocol version we cannot
  speak no longer trigger an indefinite retraversal storm. Open-
  discovery NAT-traversal succeeds at the UDP layer regardless of
  protocol version, so the daemon would adopt the punched socket,
  drop every incoming packet at `Unknown FMP version`, idle out
  after 31s, and re-fire the full STUN-offer-answer-punch sequence
  ~30s later — every minute, forever, against peers the handshake
  literally cannot complete with. The rx loop now detects mismatched-
  version packets arriving on adopted bootstrap transports, reverse-
  maps to the originating npub, and applies a long structural
  cooldown to the discovery layer's `failure_state` so the next
  open-discovery sweep skips the peer until either side upgrades.
  One-shot WARN per fresh observation; subsequent mismatches inside
  the cooldown window are silent. New `protocol_mismatch_cooldown_secs`
  config field under `node.discovery.nostr` (default 86400 = 24h),
  separate from the transient-failure `extended_cooldown_secs`.
- Proactive end-to-end `PathMtuNotification` now mirrors into the
  TUN-side `path_mtu_lookup` (TCP MSS clamp store), parallel to the
  reactive `MtuExceeded` mirror that already existed. Previously the
  proactive handler only updated the session-canonical
  `MmpSessionState.path_mtu`; on stable long-lived paths where the
  destination's echo had tightened the session MTU but no transit
  router had emitted a fresh `MtuExceeded` (because all current
  traffic was already sized by the tighter session value), new TCP
  flows opened in that window kept getting clamped by the staler
  discovery-time value. The proactive mirror closes that gap with
  the same tighter-only semantics — never loosens the clamp.
- Nostr-discovered peers running an FMP-protocol version we cannot
  speak no longer trigger an indefinite retraversal storm. Open-
  discovery NAT-traversal succeeds at the UDP layer regardless of
  protocol version, so the daemon would adopt the punched socket,
  drop every incoming packet at `Unknown FMP version`, idle out
  after 31s, and re-fire the full STUN-offer-answer-punch sequence
  ~30s later — every minute, forever, against peers the handshake
  literally cannot complete with. The rx loop now detects mismatched-
  version packets arriving on adopted bootstrap transports, reverse-
  maps to the originating npub, and applies a long structural
  cooldown to the discovery layer's `failure_state` so the next
  open-discovery sweep skips the peer until either side upgrades.
  One-shot WARN per fresh observation; subsequent mismatches inside
  the cooldown window are silent. New `protocol_mismatch_cooldown_secs`
  config field under `node.discovery.nostr` (default 86400 = 24h),
  separate from the transient-failure `extended_cooldown_secs`.
- Auto-connect peers now reconnect after a graceful `Disconnect`
  notification from the remote side. `handle_disconnect` previously
  removed the peer without scheduling a reconnect, orphaning the
  entry on a clean upstream shutdown; the other removal paths
  (link-dead, decrypt failure, peer restart) already scheduled
  reconnect ([#60](https://github.com/jmcorgan/fips/issues/60),
  reported by [@SwapMarket](https://github.com/SwapMarket))
- `fipsctl connect` now rejects FIPS mesh (`fd00::/8`) addresses for
  `udp`, `tcp`, and `ethernet` transports with a clear error message
  instead of echoing success while the daemon silently failed the
  bind with `EAFNOSUPPORT`
  ([#61](https://github.com/jmcorgan/fips/issues/61),
  reported by [@SwapMarket](https://github.com/SwapMarket))
- Rekey msg1 on non-accepting transports (e.g. UDP holepunch) was
  rejected at the top of `handle_msg1()`, which broke rekey handshakes
  on established links and produced repeated "dual rekey initiation"
  log floods. The gate now only blocks truly new inbound handshakes
  from unknown addresses; rekey and restart msg1s for established
  peers are processed normally
  ([#47](https://github.com/jmcorgan/fips/issues/47),
  [#49](https://github.com/jmcorgan/fips/pull/49))
- `fipstop` now uses `ratatui::try_init()` instead of `ratatui::init()`,
  so terminal initialization failures (e.g. Docker on macOS Sequoia,
  or environments without a usable tty) produce a clean error message
  instead of a hard crash
- Tighten TreeAnnounce ancestry validation to match the spanning
  tree specification. The receive path now verifies that the
  ancestry is structurally consistent with the signed parent
  declaration before mutating tree state.
- Fix DNS resolution on Ubuntu 22 with systemd-resolved. The DNS
  responder now binds `::` (dual-stack) instead of `127.0.0.1` so
  systemd-resolved's interface-scoped routing via fips0 reaches
  it. DNS queries are accepted only from the localhost.
- Make the tree ancestry acceptance unit test deterministic.
  `test_tree_announce_validate_semantics_accepts_valid_non_root`
  generated a random signing identity while pinning the fixed root
  to `node_addr[0] = 0x01`; about 2 in 256 random identities were
  numerically smaller than the claimed root, triggering
  `AncestryRootNotMinimum`. The test now regenerates the identity
  until its `node_addr` is strictly larger than both the fixed
  parent and root.

## [0.2.0] - 2026-03-22

### Added

#### Operator Tooling

- `fipsctl connect` and `disconnect` commands for runtime peer
  management via control socket, with hostname resolution from
  `/etc/fips/hosts`

#### IPv6 Adapter

- Pre-seed identity cache from configured peer npubs at startup, so TUN packets can be dispatched immediately without waiting for handshake completion ([@v0l](https://github.com/v0l))

#### Mesh Peer Transports

- New Tor transport with SOCKS5 and directory-mode onion service for anonymous inbound and outbound peering
- DNS hostname support in peer addresses for UDP and TCP transports
- Non-blocking transport connect for connection-oriented transports (TCP, Tor)

#### Packaging and Deployment

- Reproducible build infrastructure: Rust toolchain pinning via
  `rust-toolchain.toml`, `SOURCE_DATE_EPOCH` in CI and packaging
  scripts, deterministic archive timestamps
- Top-level packaging Makefile for unified build across formats
- Kubernetes sidecar deployment example with Nostr relay demo
- Nostr release publishing in OpenWrt package workflow
- SHA-256 hash output in CI build and OpenWrt workflows

#### Testing and CI

- Maelstrom chaos scenario with dynamic topology mutation and
  ephemeral node identities via connect/disconnect commands
- Consolidated Docker test harness infrastructure

### Changed

- Discovery protocol: replace flooding with bloom-filter-guided tree
  routing. Includes originator retry (T=0/T=5s/T=10s), exponential
  backoff after timeouts and bloom misses, and transit-side per-target
  rate limiting. Removed 257-byte visited bloom filter from LookupRequest wire format. *This is a breaking change; nodes running versions prior to this release will not be compatible.*

### Fixed

- DNS responder returned NXDOMAIN for A queries on valid `.fips` names,
  causing resolvers to give up without trying AAAA. Now returns NOERROR
  with empty answers for non-AAAA queries on resolvable names.
  (#9, reported by [@alopatindev](https://github.com/alopatindev))
- Stale end-to-end session left in session table after peer removal blocked session re-establishment on reconnect — `remove_active_peer` now cleans up `self.sessions` and `self.pending_tun_packets`. (#5, [@v0l](https://github.com/v0l))
- `schedule_reconnect` reset exponential backoff to zero on each link-dead
  cycle instead of preserving accumulated retry count.
  (#5, [@v0l](https://github.com/v0l))
- FMP/FSP rekey dual-initiation race on high-latency links (Tor): both
  sides' timers fired simultaneously, both msg1s crossed in flight, each
  side's responder path destroyed the initiator state. Fixed with
  deterministic tie-breaker (smaller NodeAddr wins as initiator).
- Parent selection SRTT gate bypass: `evaluate_parent` used default cost
  1.0 for peers filtered out by `has_srtt()`, defeating the MMP eligibility
  gate. Now skips unmeasured candidates when any peer has cost data.
- FSP rekey cutover race: initiator cut over before responder received msg3,
  causing AEAD failures. Fixed by deferring initiator cutover by 2 seconds.
- MMP metric discontinuity after rekey: receiver state carried stale
  counters across rekey, inflating reorder counts and jitter. Fixed via
  `reset_for_rekey()`.
- Auto-connect peers exhausted `max_retries` on initial connection failures
  and were permanently abandoned. Now retry indefinitely with exponential
  backoff capped at 300 seconds.
- Control socket permissions: non-root users couldn't connect. Daemon now
  chowns socket and directory to `root:fips` group at bind time.
- Post-rekey jitter spikes: old-session frames arriving via the drain window
  produced 2,000–7,000ms jitter spikes that corrupted the EWMA estimator.
  Added a 15-second grace period after rekey cutover that suppresses jitter
  updates until drain-window frames have flushed. (#10)
- ICMPv6 Packet Too Big source was set to the local FIPS address, which
  Linux ignores (loopback PTB check). Now uses the original packet's
  destination so the kernel honors the PMTU update.
  (#16, [@v0l](https://github.com/v0l))
- Reverse delivery ratio used lifetime cumulative counters instead of
  per-interval deltas, making ETX unresponsive to recent loss. (#14)
- MMP delta guards used `prev_rr > 0` to detect first report, conflating
  it with a legitimate zero counter. Replaced with `has_prev_rr`. (#14)

## [0.1.0] - 2026-03-12

### Added (Initial Release)

#### Session Layer (FSP)

- End-to-end encrypted datagram service between mesh nodes addressed by Nostr npub
- Noise XK sessions with mutual authentication, replay protection, and forward secrecy
- Automatic session rekeying with configurable time/message thresholds and drain window for in-flight packets
- Port multiplexing for multiple services over a single session
- Session-layer metrics: sender/receiver reports with RTT, jitter, delivery ratio, and burst loss tracking
- Passive RTT measurement via spin bit

#### IPv6 Adapter

- IPv6 adapter interface allowing tunneling TCP/IPv6 through FIPS mesh
  for traditional IP applications (TUN interface)
- DNS resolver allowing IP applications to reach nodes by npub.fips name
- Host-to-npub static mappings: resolve `hostname.fips` via host map
  populated from peer config aliases and `/etc/fips/hosts` file

#### Mesh Layer (FMP)

- Self-organized core mesh routing protocol with adaptive least cost forwarding
- Noise IK hop-by-hop link encryption with mutual authentication and replay protection between peer nodes
- Distributed spanning tree construction with cost-based parent selection and adaptive reconfiguration
- Destination route discovery via bloom filter-based directed search protocol
- Path MTU discovery with per-link MTU tracking and MtuExceeded error signaling
- Link-layer MMP: SRTT, jitter, one-way delay trends, packet loss, and ETX metrics
- Link-layer heartbeat with configurable liveness timeout for dead peer detection
- Epoch-based peer restart detection
- Automatic link rekeying with K-bit epoch coordination and drain window
- Static peer auto-reconnect with exponential backoff
- Multi-address peers with transport priority-based failover
- Msg1 rate limiting for handshake DoS protection

#### Mesh Peer Transports

- UDP overlay transport with inbound and static outbound peer configuration
- TCP overlay transport with listening port and static outbound peer support
- Ethernet/WiFi transport (MAC address based, no IP stack) with optional automatic peer discovery and auto-connect

#### Operator Tooling

- Ephemeral or persistent node identity with key file management
- Unix domain control socket for runtime observability
- `fipsctl` CLI tool for control socket interaction and node management
- Comprehensive node and transport statistics via control socket
- `fipstop` TUI monitoring tool with real-time session, peer, and transport configuration and metrics display

#### Packaging and Deployment

- Debian/Ubuntu `.deb` packaging via cargo-deb
- Systemd service packaging with tarball installer
- OpenWRT package with opkg feed and init script
- Docker sidecar deployment for containerized services
- Build version metadata: git commit hash, dirty flag, and target triple
  embedded in all binaries via `--version`

#### Testing and CI

- Comprehensive unit and integration tests covering all protocol layers and transports
- Docker test harness with static and stochastic topologies
- Chaos testing with simulated severe network conditions: latency, packet loss, reordering, and peer churn
- CI with GitHub Actions: x86_64 and aarch64, integration test matrix, nextest JUnit reporting
- Local CI runner script (`testing/ci-local.sh`)

#### Project

- Design documentation suite covering all protocol layers
- CHANGELOG.md following Keep a Changelog format
- Repository mirrored to [ngit](https://gitworkshop.dev/npub1y0gja7r4re0wyelmvdqa03qmjs62rwvcd8szzt4nf4t2hd43969qj000ly/relay.ngit.dev/fips)
