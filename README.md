# FIPS: Free Internetworking Peering System

![banner](docs/logos/fips_banner.png)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-1.94.1%2B-orange.svg)](https://www.rust-lang.org/)
[![Status](https://img.shields.io/badge/status-v0.2.0-green.svg)](#status--roadmap)

A distributed, decentralized network routing protocol for mesh nodes
connecting over arbitrary transports.

> FIPS is under active development. The protocol and APIs are not yet stable.
> See [Status & Roadmap](#status--roadmap) below.

## Overview

FIPS is a self-organizing mesh network that operates natively over a variety
of physical and logical media — local area networks, Bluetooth, serial links,
radio, or the existing internet as an overlay. Nodes generate their own
identities, discover each other, and route traffic without any central
authority or global topology knowledge.

FIPS uses Nostr keypairs (secp256k1/schnorr) as native node identities,
allowing users to generate their own persistent or ephemeral node addresses.
Nodes address each other by npub, and the same cryptographic identity serves
as both the routing address and the basis for end-to-end encrypted sessions
across the mesh.

FIPS allows existing TCP/IP based network software to use the FIPS mesh
network by generating a local IP address from the node npub and tunnelling
IP packets to other endpoints transparently knowing only their npub. Native
FIPS-aware applications do not need this IP tunneling or emulation capability.

All traffic over the FIPS mesh is encrypted and authenticated both
hop-to-hop between peers and independently end-to-end between FIPS
endpoints.

## Features

- **Self-organizing mesh routing.** Spanning-tree coordinates with
  bloom-filter-guided discovery; no global routing tables, no
  flooding.
- **Multi-transport.** UDP, TCP, Ethernet, Tor, and Bluetooth (BLE
  L2CAP) ship today; transports compose on a single mesh and a
  node may run several at once.
- **Two-layer encryption.** Noise IK between peers (hop-by-hop) and
  Noise XK between mesh endpoints (independent end-to-end), with
  periodic rekey for forward secrecy.
- **Nostr-native identity.** secp256k1 / schnorr keypairs as node
  addresses; self-generated, no registration, no central authority.
- **IPv6 adapter.** A TUN interface maps each remote npub to an
  `fd00::/8` address, so unmodified IPv6 software reaches mesh
  peers as `<npub>.fips`. Built-in `.fips` DNS resolver, with
  optional static name mapping via `/etc/fips/hosts`.
- **Nostr-mediated discovery and fallback.** Public endpoint adverts find
  peers. Applications may carry already-encrypted FIPS datagrams through
  configured Nostr relays as a low-priority bootstrap path; authenticated FIPS
  sessions then negotiate direct UDP, WebRTC, or TCP paths when possible.
- **LAN gateway.** Optional `fips-gateway` service folds an entire
  unmodified LAN into the mesh: outbound (LAN clients reach mesh
  destinations through a DNS-allocated virtual IPv6 pool and
  nftables NAT) and inbound (LAN-side services exposed to the mesh
  through 1:1 port forwards).
- **Per-link metrics.** RTT, loss, jitter, and goodput on every
  hop, plus mesh-size estimation, via the Metrics Measurement
  Protocol.
- **ECN congestion signaling.** Hop-by-hop CE-flag relay with RFC
  3168 IPv6 marking and transport kernel-drop detection.
- **Mesh-interface security baseline.** Optional default-deny
  nftables policy for `fips0` shipped as a packaged conffile
  (`/etc/fips/fips.nft`) with an operator drop-in directory
  (`/etc/fips/fips.d/`) and a disabled-by-default
  `fips-firewall.service`. The baseline polices only the mesh
  interface, leaving Docker, Tor, and the host firewall untouched.
- **Operator visibility.** `fipsctl` CLI for control and inspection
  with time-series stats history queryable for any metric,
  `fipstop` TUI for live status with inline sparkline dashboards,
  and a JSON-line control socket on each binary for direct
  programmatic access.
- **Reproducible builds** with toolchain pinning and
  `SOURCE_DATE_EPOCH`.
- **Zero configuration.** Sensible defaults let a node start with no
  config file, though peer addresses are needed to join an existing
  network.

## Building

```bash
git clone https://github.com/jmcorgan/fips.git
cd fips
cargo build --release
```

Requires Rust 1.94.1+ (edition 2024). Linux, macOS, and Windows are
supported; transport availability varies by platform.

### Transport support by platform

| Transport | Linux | macOS | Windows | OpenWrt |
|-----------|:-----:|:-----:|:-------:|:-------:|
| UDP       |  ✅   |  ✅   |   ✅    |   ✅    |
| TCP       |  ✅   |  ✅   |   ✅    |   ✅    |
| Ethernet  |  ✅   |  ✅   |   ❌    |   ✅    |
| Tor       |  ✅   |  ✅   |   ✅    |   ✅    |
| BLE       |  ✅   |  ❌   |   ❌    |   ❌    |

On **Linux**, the BLE transport requires BlueZ and libdbus. On
Debian/Ubuntu: `sudo apt install bluez libdbus-1-dev`. BLE support is
enabled automatically when the build script detects those dependencies.

On **OpenWrt**, BLE is disabled because libdbus is not available on
the target. All other transports work and ship in the default ipk.

## Installation

After building, choose one of the following methods to install.

### Debian / Ubuntu (.deb)

Requires [cargo-deb](https://crates.io/crates/cargo-deb):

```bash
cargo install cargo-deb
cargo deb
sudo dpkg -i target/debian/fips_*.deb
```

This installs the daemon, CLI tools, systemd units, and a default
configuration. Edit `/etc/fips/fips.yaml` before starting:

```bash
sudo nano /etc/fips/fips.yaml
sudo systemctl start fips
```

The service is enabled at boot automatically. To use `fipsctl` and
`fipstop` without sudo, add your user to the `fips` group:

```bash
sudo usermod -aG fips $USER    # log out and back in to take effect
```

Remove with `sudo dpkg -r fips` (preserves config) or
`sudo dpkg -P fips` (removes everything including identity keys).

### Generic Linux (systemd tarball)

```bash
./packaging/systemd/build-tarball.sh
tar xzf deploy/fips-*-linux-*.tar.gz
cd fips-*-linux-*/
sudo ./install.sh
```

See [packaging/systemd/README.install.md](packaging/systemd/README.install.md)
for the full installation and configuration guide.

### macOS (.pkg)

```bash
./packaging/macos/build-pkg.sh
sudo installer -pkg deploy/fips-*-macos-*.pkg -target /
```

This installs binaries to `/usr/local/bin/`, config to
`/usr/local/etc/fips/`, sets up `.fips` DNS resolution via
`/etc/resolver/fips`, and registers a launchd daemon. Edit
`/usr/local/etc/fips/fips.yaml` before starting:

```bash
sudo nano /usr/local/etc/fips/fips.yaml
sudo launchctl load -w /Library/LaunchDaemons/com.fips.daemon.plist
```

Remove with `sudo packaging/macos/uninstall.sh` (preserves config).

To restart the node after making configuration changes:

```bash
sudo launchctl unload -w /Library/LaunchDaemons/com.fips.daemon.plist
sudo launchctl load -w /Library/LaunchDaemons/com.fips.daemon.plist
```

Check logs for troubleshooting:

```bash
sudo tail -f /usr/local/var/log/fips/fips.log
```

> **Note:** On macOS, the TUN device is named `utun<N>` (kernel-assigned)
> rather than `fips0`.

### Windows

Build without BLE (requires Linux-only libdbus):

```powershell
cargo build --release
```

The [wintun](https://www.wintun.net/) driver is required for TUN support.
Download `wintun.dll` and place it in the same directory as `fips.exe`.
Running the daemon requires Administrator privileges for TUN creation.

**Foreground mode:**

```powershell
.\fips.exe -c fips.yaml
```

**Windows Service:**

```powershell
# Install (requires Administrator)
.\fips.exe --install-service

# Manage via standard service tools
sc start fips
sc stop fips

# Uninstall
.\fips.exe --uninstall-service
```

Place `fips.yaml` in the current directory or `%APPDATA%\fips\`, or set
the `FIPS_CONFIG` environment variable.

The control socket uses TCP on `localhost:21210` instead of a Unix domain
socket. `fipsctl` and `fipstop` connect to this port automatically.

## Configuration

The default configuration file is installed at `/etc/fips/fips.yaml`:

```yaml
# FIPS Node Configuration

node:
  identity:
    # By default, a new ephemeral keypair is generated on each start.
    # Uncomment persistent to keep the same identity across restarts;
    # on first start a keypair is saved to fips.key/fips.pub next to
    # this config file (mode 0600/0644).
    # persistent: true
    #
    # Or set an explicit key (overrides persistent):
    # nsec: "nsec1..."

tun:
  enabled: true
  name: fips0
  mtu: 1280

dns:
  enabled: true
  bind_addr: "127.0.0.1"
  port: 5354

transports:
  udp:
    bind_addr: "0.0.0.0:2121"

  tcp:
    # Accepts inbound connections. No static outbound peers.
    bind_addr: "0.0.0.0:8443"

  # Ethernet transport — uncomment and set your interface name.
  # ethernet:
  #   interface: "eth0"
  #   discovery: true
  #   announce: true
  #   auto_connect: true
  #   accept_connections: true
  #   discovery_scope: "my-private-host-mesh"

peers:
  # Static peers for bootstrapping (UDP or TCP):
  - npub: "npub1qmc3cvfz0yu2hx96nq3gp55zdan2qclealn7xshgr448d3nh6lks7zel98"
    alias: "fips-test-node"
    addresses:
      - transport: udp
        addr: "test-us01.fips.network:2121"
    connect_policy: auto_connect
```

See [docs/design/fips-configuration.md](docs/design/fips-configuration.md)
for the full reference.

## Usage

### DNS Resolution

FIPS includes a DNS resolver (enabled by default, port 5354) that maps
`.fips` names to fd00::/8 IPv6 addresses.

**Linux**: The `.deb` package auto-detects and configures whichever
resolver is present (systemd dns-delegate, systemd-resolved, dnsmasq,
or NetworkManager with dnsmasq); no manual setup is needed. For
manual or tarball installs, point your resolver at `127.0.0.1:5354`
for the `fips` domain — e.g., with systemd-resolved:

```bash
sudo resolvectl dns fips0 127.0.0.1:5354
sudo resolvectl domain fips0 ~fips
```

**macOS**: DNS is configured automatically by the `.pkg` installer via
`/etc/resolver/fips`. No manual setup is needed.

Then reach any FIPS node by npub with standard IPv6 tools:

```bash
ping6 npub1bbb....fips
ssh -6 npub1bbb....fips
```

> **macOS note:** Use `ping6` instead of `ping`. macOS ships separate
> `ping` (IPv4-only) and `ping6` (IPv6) binaries; `ping` will not
> resolve AAAA records. Similarly, use `curl -6`, `ssh -6`, etc. when
> connecting by `.fips` hostname.

### Monitoring

Use `fipsctl` to query a running node:

```bash
fipsctl show status         # Node status overview
fipsctl show peers          # Authenticated peers and security state
fipsctl show links          # Active links
fipsctl show tree           # Spanning tree state
fipsctl show sessions       # End-to-end sessions and rekey health
fipsctl show bloom          # Bloom filter state
fipsctl show mmp            # MMP metrics summary
fipsctl show cache          # Coordinate cache entries and routes
fipsctl show connections    # Pending handshake connections
fipsctl show transports     # Transport instances
fipsctl show routing        # Routing, discovery, and retry state
fipsctl show identity-cache # Known node identities (npubs)
```

`fipstop` provides an interactive TUI dashboard with live-updating
views of node status, peers, links, sessions, tree state, transports,
and routing:

```bash
fipstop                   # connect to local daemon
fipstop -r 1              # 1-second refresh interval
```

### Service Management

```bash
sudo systemctl start fips
sudo systemctl stop fips
sudo systemctl restart fips
sudo journalctl -u fips -f
```

### Testing

See [testing/](testing/) for Docker-based integration test harnesses
including static topology tests and stochastic chaos simulation.

## Examples

- [examples/sidecar-nostr-relay/](examples/sidecar-nostr-relay/) —
  Run a [strfry](https://github.com/hoytech/strfry) Nostr relay
  reachable exclusively over the FIPS mesh. The relay container shares
  the FIPS sidecar's network namespace and is isolated from the host
  network.
- [examples/k8s-sidecar/](examples/k8s-sidecar/) — Run FIPS as a
  Kubernetes Pod sidecar. The sidecar creates `fips0` in the Pod's
  shared network namespace so every other container in the Pod gets
  mesh access without modification.
- [examples/wireguard-sidecar-macos/](examples/wireguard-sidecar-macos/) —
  Reach the FIPS mesh from a macOS host through a local Docker
  container over a WireGuard tunnel. Only traffic destined for
  `fd00::/8` transits the sidecar; regular internet traffic continues
  to use the host network.

## Documentation

Protocol design documentation is in [docs/design/](docs/design/), organized as
a layered protocol specification. Start with
[fips-intro.md](docs/design/fips-intro.md) for the full protocol overview.

If you want to contribute, start with:

- [CONTRIBUTING.md](CONTRIBUTING.md)
- [docs/design/README.md](docs/design/README.md)
- [testing/README.md](testing/README.md)

## Project Structure

```text
src/          Rust source (library + fips/fipsctl/fipstop/fips-gateway binaries)
packaging/    Debian, macOS .pkg, Windows ZIP, OpenWrt ipk, AUR, systemd tarball
examples/     Deployment examples (Nostr relay, K8s sidecar, macOS WireGuard)
docs/design/  Protocol design specifications
testing/      Docker-based integration test harnesses
```

## Status & Roadmap

FIPS is at **v0.2.0**. The core protocol works end-to-end over UDP, TCP,
Ethernet, Tor, and Bluetooth (BLE) with a small live mesh of deployed nodes.

### What works today

- Spanning tree construction with greedy coordinate routing
- Bloom filter guided discovery (no flooding, single-path with retry)
- Noise IK (link layer) and Noise XK (session layer) encryption
- Periodic Noise rekey with hitless cutover for forward secrecy (FMP + FSP)
- Persistent node identity with key file management
- IPv6 TUN adapter with built-in `.fips` DNS resolver and multi-backend
  auto-configuration (systemd dns-delegate, systemd-resolved, dnsmasq,
  NetworkManager)
- Static hostname mapping (`/etc/fips/hosts`) with auto-reload
- Per-link metrics (RTT, loss, jitter, goodput) and mesh size estimation
- ECN congestion signaling (hop-by-hop CE relay, IPv6 CE marking, kernel drop detection)
- UDP, TCP, Ethernet, Tor, and BLE transports (BLE via L2CAP CoC with per-link MTU negotiation)
- Outbound LAN gateway for unmodified hosts via DNS-allocated virtual IPs and nftables NAT
- Runtime inspection and peer management via `fipsctl` and `fipstop`
- Reproducible builds with toolchain pinning and SOURCE_DATE_EPOCH
- Linux (Debian, systemd tarball, OpenWrt, AUR), macOS (`.pkg`), and Windows (ZIP, service) packaging
- Docker-based integration and chaos testing
- Nostr-mediated overlay endpoint discovery, optional encrypted-datagram relay
  fallback, and authenticated in-session negotiation of direct UDP, WebRTC,
  or TCP paths

### Near-term priorities

- Native API for FIPS-aware applications (npub:port addressing)
- Security audit of cryptographic protocols

### Longer-term

- Mobile platform support
- Bandwidth-aware routing and QoS
- Protocol stability and versioned wire format
- Published crate

## License

MIT — see [LICENSE](LICENSE).
