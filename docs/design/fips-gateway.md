# FIPS Outbound LAN Gateway

`fips-gateway` is a sidecar binary that runs alongside the FIPS daemon, enabling
unmodified LAN hosts to reach mesh destinations. It provides DNS resolution of
`.fips` names to virtual IPv6 addresses from a managed pool and configures
kernel nftables NAT rules for traffic forwarding through the fips0 TUN
interface. LAN clients need no FIPS software — any device that can resolve DNS
and send IPv6 packets can use the gateway.

## Architecture

The gateway is a separate binary (`fips-gateway`), not part of the FIPS daemon.
It connects to the daemon indirectly: `.fips` DNS queries are forwarded to the
daemon's built-in resolver (`[::1]:5354` by default), which resolves names to mesh
addresses and primes its identity cache as a side effect. The gateway then
allocates a virtual IP, installs NAT rules, and returns the virtual IP to the
LAN client.

```text
                    LAN Client
                        |
                   DNS query (.fips)
                        |
                        v
             +---------------------+
             |   DNS Proxy         |  Listens on [::1]:5353
             |   (dns.rs)          |
             +---------------------+
                   |          |
          .fips query    non-.fips → REFUSED
                   |
                   v
          FIPS Daemon Resolver
          ([::1]:5354)
                   |
             mesh address (fd00::/8)
                   |
                   v
             +---------------------+
             |   Virtual IP Pool   |  Allocates from pool CIDR
             |   (pool.rs)         |
             +---------------------+
                   |
             pool event (new/removed mapping)
                   |
                   v
        +----------+----------+
        |                     |
        v                     v
+---------------+    +-----------------+
| NAT Manager   |    | Network Setup   |
| (nat.rs)      |    | (net.rs)        |
| DNAT/SNAT/    |    | Proxy NDP,      |
| masquerade    |    | pool route      |
+---------------+    +-----------------+
        |                     |
        v                     v
   nftables rules       ip -6 neigh proxy
   (inet fips_gateway)   ip -6 route local
```

### Data Flow

1. LAN client queries `hostname.fips` via DNS
2. Gateway forwards to daemon resolver (`[::1]:5354` by default)
3. Daemon resolves name to mesh address (fd00::/8), primes identity cache
4. Gateway allocates virtual IP from pool, creates DNAT/SNAT rules and proxy NDP
   entry
5. Gateway returns AAAA record with virtual IP to client
6. Client sends traffic to virtual IP
7. Kernel DNAT rewrites destination to mesh address, masquerade rewrites source
   to gateway's fips0 address
8. Traffic flows through fips0 into the mesh
9. Return traffic follows the reverse path via conntrack

## NAT Pipeline

The gateway manages a dedicated nftables table (`inet fips_gateway`) containing
two chains with rules that translate between virtual IPs and mesh addresses.

### Prerouting DNAT

A per-mapping rule in the `prerouting` chain (priority dstnat / -100) rewrites
the destination address from the virtual IP to the corresponding fd00::/8 mesh
address:

```text
match: ip6 daddr == <virtual_ip>
action: dnat to <mesh_addr>
```

After DNAT, the kernel routes the packet through fips0 via the standard routing
table.

### Postrouting Masquerade

A single masquerade rule in the `postrouting` chain (priority srcnat / 100)
rewrites the source address of all traffic exiting via fips0 to the gateway's
own fips0 address:

```text
match: oifname == "fips0"
action: masquerade
```

This is critical. Without masquerade, LAN client source addresses (e.g.,
`fd01::5` from the virtual pool) would appear as the source on the mesh. These
addresses are meaningless to mesh peers, so return traffic would be black-holed.
Masquerade ensures all mesh traffic appears to originate from the gateway's own
FIPS identity.

### Postrouting SNAT

A per-mapping rule in the `postrouting` chain rewrites the source address of
return traffic from the mesh address back to the virtual IP:

```text
match: ip6 saddr == <mesh_addr>
action: snat to <virtual_ip>
```

This ensures LAN hosts see responses from the virtual IP they connected to,
not from the raw fd00::/8 mesh address.

### Atomic Table Rebuild

The entire nftables table is rebuilt atomically on every mapping change. The
rebuild sequence is: delete the existing table (ignore ENOENT on first call),
then create a new table with all chains, the masquerade rule, and all
per-mapping DNAT/SNAT rules in a single netlink batch.

This approach avoids relying on kernel rule handle tracking, which the rustables
crate does not expose. The table is small — one masquerade rule plus two rules
per active mapping — so rebuilding is cheap.

## Virtual IP Pool Lifecycle

The pool allocates IPv6 addresses from a configured CIDR range (e.g.,
`fd01::/112`). Each address maps to one FIPS mesh destination (keyed by
NodeAddr, not hostname). Address 0 (network equivalent) is reserved; the
remaining addresses are available for allocation.

### State Machine

```text
ALLOCATED ──→ ACTIVE ──→ DRAINING ──→ FREE
    │                                   ↑
    └───────────────────────────────────┘
         (TTL expired, no sessions)
```

| State | Description |
| ----- | ----------- |
| Allocated | DNS query created the mapping. No NAT sessions yet. |
| Active | Conntrack reports at least one active session. |
| Draining | TTL expired but sessions remain, or sessions ended and grace period is running. |
| Free | Reclaimed. Virtual IP returned to the available pool. |

### Transitions

- **Allocated to Active**: Conntrack reports sessions > 0.
- **Allocated to Free**: TTL expired with no sessions ever created.
- **Active to Draining**: TTL expired (sessions may or may not remain).
- **Draining to Free**: Sessions drop to zero and the grace period elapses.

### Timing

- **TTL**: Default 60 seconds (matches DNS TTL). Repeated DNS queries for the
  same destination reset the `last_referenced` timestamp.
- **Grace period**: Default 60 seconds after draining begins with zero sessions.
  Prevents immediate reuse that could confuse hosts with cached DNS responses.
- **Tick interval**: The pool evaluates state transitions every 10 seconds.

### Conntrack Integration

The pool queries `/proc/net/nf_conntrack` to count active sessions per virtual
IP. A session is counted if any conntrack entry's original destination matches
the virtual IP address.

### Pool Exhaustion

If no addresses are available, new DNS queries return SERVFAIL. Existing
mappings are never evicted prematurely — correctness of active sessions takes
priority over new allocations. The pool is capped at 2^16 addresses regardless
of CIDR prefix length to prevent excessive memory allocation.

## DNS Resolution Flow

1. Gateway listens on configured address (default `[::1]:5353`). The default
   assumes a LAN resolver already owns port 53 and forwards `.fips` queries to
   the gateway over loopback; set `listen: "[::]:53"` explicitly on hosts where
   the gateway should answer LAN clients directly.
2. Client sends DNS query.
3. If the query is not for a `.fips` domain, return `REFUSED`.
4. Forward the query to the daemon resolver at `[::1]:5354` (configurable).
5. If the daemon is unreachable or times out (5 seconds), return `SERVFAIL`.
6. If the daemon returns NXDOMAIN or an error, forward the response as-is.
7. Extract the AAAA record (fd00::/8 mesh address) from the daemon's response.
8. Allocate a virtual IP from the pool for this destination (idempotent — if a
   mapping already exists, reuse it and refresh the TTL).
9. If a new mapping was created, emit a `MappingCreated` event to install NAT
   rules and proxy NDP entry.
10. Build and return an AAAA response containing the virtual IP with the
    configured TTL.

The daemon's resolver populates its identity cache as a side effect of
resolution. This is required for fips0 routing to work — without the cache
entry, the daemon cannot map the fd00::/8 address back to a NodeAddr for mesh
routing.

## Network Requirements

### Gateway Host

The following must be true on the machine running `fips-gateway`:

- **FIPS daemon running** with TUN enabled (fips0 interface must exist) and DNS
  resolver on port 5354
- **IPv6 forwarding enabled**: `sysctl -w net.ipv6.conf.all.forwarding=1`
- **Proxy NDP enabled**: `sysctl -w net.ipv6.conf.all.proxy_ndp=1`
- **CAP_NET_ADMIN**: Required for nftables table management and proxy NDP
  manipulation (run as root or set the capability)
- **Pool route**: The gateway adds `local <pool-cidr> dev lo` at startup, which
  tells the kernel to accept packets destined for pool addresses as
  locally-owned, enabling NAT processing. This route is cleaned up on shutdown.

### LAN Clients

LAN clients need no FIPS software. They require:

- **Route to virtual IP pool**: `ip -6 route add <pool-cidr> via
  <gateway-lan-addr>`. This can be pushed via DHCP, configured on the LAN
  router, or set per-host.
- **DNS resolution**: Either configure the LAN's main DNS server to forward
  `.fips` queries to the gateway, or point individual hosts at the gateway for
  DNS (noting that non-`.fips` queries will get `REFUSED`).

## Configuration Reference

All configuration lives under the `gateway` key in `fips.yaml`:

```yaml
gateway:
  enabled: true
  pool: "fd01::/112"
  lan_interface: "enp3s0"
  dns:
    listen: "[::1]:5353"
    upstream: "[::1]:5354"
    ttl: 60
  pool_grace_period: 60
  conntrack:
    tcp_established: 432000
    udp_timeout: 30
    udp_assured: 180
    icmp_timeout: 30
```

| Field | Type | Default | Description |
| ----- | ---- | ------- | ----------- |
| `enabled` | bool | `false` | Enable the gateway. Must be `true` for `fips-gateway` to start. |
| `pool` | string (CIDR) | required | Virtual IP pool range (e.g., `fd01::/112`). |
| `lan_interface` | string | required | LAN-facing interface for proxy NDP entries. |
| `dns.listen` | string | `[::1]:5353` | Address and port for the gateway DNS listener. The default avoids port 53 conflicts with an existing LAN resolver; set `[::]:53` explicitly when the gateway should answer clients directly. |
| `dns.upstream` | string | `[::1]:5354` | FIPS daemon DNS resolver address. |
| `dns.ttl` | u32 | `60` | DNS response TTL in seconds. Also governs mapping TTL. |
| `pool_grace_period` | u64 | `60` | Seconds after last session before a mapping is reclaimed. |
| `conntrack.tcp_established` | u64 | `432000` | TCP established timeout (seconds). 5 days. |
| `conntrack.udp_timeout` | u64 | `30` | UDP unreplied timeout (seconds). |
| `conntrack.udp_assured` | u64 | `180` | UDP bidirectional (assured) timeout (seconds). |
| `conntrack.icmp_timeout` | u64 | `30` | ICMP timeout (seconds). |

## Troubleshooting

### "No gateway section in configuration"

The `fips-gateway` binary loads the same config file as the daemon. If it
cannot find a `gateway:` section, use the `--config` flag to point at the
correct file:

```bash
fips-gateway --config /etc/fips/fips.yaml
```

### DNS Queries Fail

Verify the daemon resolver is running and reachable:

```bash
dig @127.0.0.1 -p 5354 hostname.fips AAAA
```

If this fails, the daemon is not running or its DNS resolver is not enabled.
Check that the daemon config has `dns.enabled: true` (enabled by default).

### Ping Works But TCP Does Not

This usually means the masquerade rule is missing or misconfigured. Inspect the
nftables table:

```bash
nft list table inet fips_gateway
```

Verify the postrouting chain contains a masquerade rule matching `oifname
"fips0"`. Without masquerade, the mesh peer sees a source address it cannot
route replies to.

### Connection Timeout

Check that IPv6 forwarding is enabled:

```bash
sysctl net.ipv6.conf.all.forwarding
```

Verify the pool route exists:

```bash
ip -6 route show table local | grep <pool-cidr>
```

If the route is missing, the kernel does not recognize pool addresses as local
and drops the packets before NAT can process them.

### Virtual IP Unreachable From Client

Verify the client has a route to the pool via the gateway:

```bash
ip -6 route get <virtual-ip>
```

On the gateway, verify proxy NDP entries exist for allocated virtual IPs:

```bash
ip -6 neigh show proxy
```

If proxy NDP entries are missing, the gateway cannot answer Neighbor Solicitation
requests for virtual IPs on the LAN, so clients cannot resolve the link-layer
address.

### Port 53 Conflict

The default `[::1]:5353` should not collide with a normal resolver. If you
override the gateway onto port 53 and another DNS server is already there,
identify the owner:

```bash
# Check what is using port 53
ss -tulnp | grep :53

# Return to the loopback default or choose another explicit listen address
dns:
  listen: "[::1]:5353"
```

Then configure the existing resolver to forward `.fips` queries to the gateway.

## Security Considerations

- **LAN trust boundary**: The gateway DNS listener is accessible to any host on
  the LAN. Any host that can reach the DNS port and route to the virtual IP pool
  can access mesh destinations through the gateway. Access restriction must be
  enforced at the network level (firewall rules on the LAN interface).

- **Identity masking**: All LAN traffic appears on the mesh under the gateway's
  own FIPS identity. Mesh peers cannot determine which LAN host originated a
  connection. This provides privacy for LAN hosts but means the gateway's
  reputation covers all its clients.

- **Plaintext at the gateway**: Traffic between LAN hosts and the gateway is
  unencrypted at the IP layer. FIPS encryption (FSP) protects traffic between
  the gateway and the destination mesh peer. Application-layer encryption (TLS,
  SSH) provides end-to-end protection through the gateway.

- **Pool addresses are ephemeral**: Virtual IPs are allocated dynamically and
  recycled. They are not authenticated or bound to client identity. A LAN host
  connecting to a virtual IP is trusting the gateway's DNS response.

- **No client identity verification**: The gateway does not authenticate LAN
  clients. Any host that can send packets is served.

## Future Work

- **IPv4 pool support**: NAT46 translation via TAYGA or Jool, allowing LAN
  hosts to use IPv4 virtual addresses while the mesh remains IPv6.
- **Inbound gateway**: Exposing LAN services to mesh peers (mesh to LAN
  direction), requiring port-forwarding or reverse-proxy configuration.
- **fipstop Gateway tab**: Monitoring integration showing pool utilization,
  active mappings, and NAT session counts.
- **Gateway control socket**: Status queries via `fipsctl gateway status` and
  `fipsctl gateway mappings` for operational visibility.

## References

- [fips-ipv6-adapter.md](fips-ipv6-adapter.md) — IPv6 adapter and TUN interface
  design
- [fips-configuration.md](fips-configuration.md) — Configuration reference
- [fips-intro.md](fips-intro.md) — Protocol overview and architecture
