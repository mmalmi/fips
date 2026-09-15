# OpenWrt package

The APKv3 package targets OpenWrt 25.12 and newer. It uses standard Linux network
interfaces and OpenWrt services; it contains no device-specific driver changes.
The binary must be cross-compiled for the selected CPU architecture. The package
builder checks its ELF machine against the APK architecture. Hardware validation
currently uses ARM64; other architectures need their own build and runtime check.

## Build

From the repository root, with Rust's target, Zig and cargo-zigbuild installed:

```sh
cargo zigbuild -p fips-relay --bin fips-relay --locked \
  --target aarch64-unknown-linux-musl --profile openwrt -j 4
```

The size-oriented profile keeps normal panic semantics and builds a static musl
executable. Inspect the result with `file` before packaging. The ARM64 executable
is approximately 19 MiB; the previous speed-oriented build was about 36 MiB.
This size comparison is not a forwarding-performance benchmark.

Use an APKv3 tool with the `mkpkg` applet. OpenWrt's installed package manager
may omit that build applet; the SDK host tool or Alpine's full build tool can
provide it. Run packaging as root in an isolated build environment to give the
archive root ownership. The script writes only its temporary staging directory
and the requested new output file; it does not install anything:

```sh
crates/fips-relay/openwrt/build-apk.sh /path/to/apk \
  target/aarch64-unknown-linux-musl/openwrt/fips-relay \
  aarch64_cortex-a53 0.1.0-r1 REPLACE_WITH_SOURCE_COMMIT \
  /output/fips-relay-0.1.0-r1.apk
```

Use the target's `/etc/apk/arch` value. Keep the binary, its source revision and
the package checksum together. `/usr/share/fips-relay/build.json` records the
binary hash, size, architecture and supplied source revision. The package contains
no private identities, wallet state or active service JSON. It declares `procd`,
`jsonfilter`, `iw`, `uclient-fetch` and `ca-bundle` dependencies.

## Install and configure

Back up the entire existing account while the relay is stopped. Install the local
prototype package with `apk add --allow-untrusted /path/to/fips-relay.apk`.
This is a locally built unsigned test package. Installation does not initialize
accounts, enable boot startup or start a new service. Unmanaged files under
`/etc` may be preserved while the packaged version becomes `.apk-new`: review
and adopt the new init script, and retain the operator's UCI configuration.

For a new instance, copy `/usr/share/fips-relay/config.example.json` to
`/etc/fips-relay/config.json`, set explicit peers, native interfaces and mint,
then run `fips-relay init /etc/fips-relay/config.json` once. For an existing
instance, retain its configuration and complete state directory; never initialize
again. Default state resides under persistent `/etc/fips-relay/state`.

```sh
uci set fips-relay.main.executable='/usr/sbin/fips-relay'
uci set fips-relay.main.config='/etc/fips-relay/config.json'
uci set fips-relay.main.enabled='1'
uci commit fips-relay
/etc/init.d/fips-relay enable
/etc/init.d/fips-relay start
```

The supervisor waits for all of these before executing the relay:

- Existing account metadata on persistent storage. RAM-backed state is rejected.
- A valid BusyBox `ntpd` stratum event in this boot, recorded by the NTP hotplug
  hook. On an already synchronized router, restarting `sysntpd` obtains a fresh
  event for the newly installed hook. Other time daemons need an equivalent
  integration; checking that the date merely looks plausible is insufficient.
- Every configured native interface exists, has carrier, and is neither a bridge
  nor a bridge member. An 802.11s interface must report `mesh_fwding=0` so native
  FIPS performs forwarding. The wrapper changes no radio or bridge settings.
- The configured mint answers its information endpoint. The relay subsequently
  performs its own keyset, financial-state and configuration validation.

Waiting consumes no channel funds and does not exhaust procd's crash restart
counter. A changing wait reason is logged; identical reasons are not repeatedly
logged. `procd` showing a running wrapper does not prove that the relay is ready:
query its private `status` control and inspect neighbour connectivity.

Keep native link addresses stable when peers use numeric MAC addresses. A virtual
Wi-Fi interface's automatically assigned MAC can change when interface creation
order changes at boot. On the test bench this affected two mesh radios; one
connection initially survived because only the other endpoint's configured
address was stale. Pin each affected mesh `wifi-iface` section's `macaddr` to its
unique intended address, matching the FIPS peer configuration. Set this on the
interface section, not the physical `wifi-device` section. Apply the change in a
maintenance window, then verify the live address and both neighbours after boot.
The package deliberately does not choose or change these radio addresses.

Package upgrades stop a running instance and restart it afterward with the same
UCI settings and accounts. A stopped instance stays stopped. Removal stops the
service and disables its boot link, but never deletes saved accounts. Default
`/etc/fips-relay/` state is listed for sysupgrade backups; custom configuration
and state paths must be added to the operator's backup policy. Keep an external
private backup too. Firmware upgrade and old opkg/IPK packaging are separate
validation work.

## Device acceptance checks

Verify the installed package version and executable checksum, preserved account
identity/limits, and mint/network readiness. Exercise a missing clock marker and
an unreachable mint: the wrapper must wait without starting the daemon. Exercise
a bridged native interface without changing the live radio configuration.
Check an upgrade of a running instance preserves its account and budget.

Reboot one test router at a time. Compare boot IDs to prove an actual reboot,
then verify that NTP, native interface isolation, the relay control socket and
the same account return. Compare live MAC addresses with saved numeric peer
addresses; a connection initiated from one side can conceal a stale address on
the other. Verify management access, ordinary Internet/DNS and
the existing access point separately. A successful empty-account boot is not
proof of paid traffic, throughput, or an interrupted financial-operation recovery.

These checks passed on three ARM64 OpenWrt 25.12.5 routers using package r3,
after fixing the two automatic mesh-address changes described above. The package
upgrade check used a running r1 instance. See [../TESTBENCH.md](../TESTBENCH.md)
for the measured scope and remaining acceptance work.
