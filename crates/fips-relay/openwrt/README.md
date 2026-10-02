# OpenWrt package

For the current completed prototype scope and later phone/performance evidence,
see [the acceptance report](../PROTOTYPE-RESULTS.md). Earlier run sections below are historical.

The APKv3 package targets OpenWrt 25.12 and newer. It uses standard Linux network
interfaces and OpenWrt services; it contains no device-specific driver changes.
The binary must be cross-compiled for the selected CPU architecture. The package
builder checks its ELF machine against the APK architecture. Hardware validation
currently uses ARM64; other architectures need their own build and runtime check.

## Build

Use the [source-bundle workflow](../FUNDING-COSTS.md#portable-development-source-bundle)
for the current development dependencies. From its `checkout/` directory, with
Rust 1.96.0's target, Zig and cargo-zigbuild installed:

```sh
cargo +1.96.0 zigbuild -p fips-relay --bin fips-relay --offline --locked \
  --target aarch64-unknown-linux-musl --profile openwrt -j 1
```

The size-oriented profile keeps normal panic semantics and builds a static musl
executable. Inspect the result with `file` before packaging. The accepted revision,
package size, tool versions and isolated Linux results are recorded in the
[readiness record](../READINESS.md#scope-and-outstanding-acceptance). These checks
do not establish forwarding performance or current-router acceptance.

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
`jsonfilter`, `iw` and `ca-bundle` dependencies.

On a Linux build host, a dynamically linked APK tool can also run under
`fakeroot --` with the same builder command. This records root ownership in the
archive without granting host privileges. Inspect the resulting package with
`apk --allow-untrusted adbdump --format=json PACKAGE.apk` and require every file
and directory ACL to name `root` as both user and group. A statically linked APK
tool cannot use fakeroot's library interception.

## Linux paid-routing check

The existing automatic quality test runs real controllers, native FIPS feedback
and a local test mint over simulated links. It checks loss and delay separately,
switches to a working provider, reuses the recovered cheaper channel, reloads the
controller and settles both channels. Build its ARM64 Linux executable from the
same source bundle, keeping test artifacts separate from the package build:

```sh
CARGO_TARGET_DIR="$PWD/target/linux-tests" CARGO_INCREMENTAL=0 \
  CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0 \
  cargo +1.96.0 zigbuild --offline --locked -j 1 \
  --target aarch64-unknown-linux-musl -p fips-relay --all-features --test priced_paths
```

Choose the executable `priced_paths-<hash>` from
`target/linux-tests/aarch64-unknown-linux-musl/debug/deps/`, excluding `.d` files.
Set `relay_test_binary` to its absolute path and `relay_test_image` to an already
available local ARM64 Linux image. Run with only that executable mounted:

```sh
docker run --rm --pull never --network none --read-only --cap-drop ALL \
  --security-opt no-new-privileges --user 65534:65534 \
  --tmpfs /tmp:rw,nosuid,nodev,size=512m,mode=1777 \
  --memory 1g --cpus 2 --pids-limit 256 \
  --mount "type=bind,source=$relay_test_binary,target=/candidate/priced_paths,readonly" \
  --entrypoint /candidate/priced_paths "$relay_test_image" \
  automatic_quality::automatic_watch_leaves_impaired_routes_and_reuses_recovered_channel \
  --exact --test-threads=1 --nocapture
```

For combined loss and neighbor departure/rejoin, use the same container command
with the test filter
`automatic_quality::churn::quality_failover_survives_alternative_departure_without_refunding_or_rebuying`.
It checks delivery and new payments through the original channels while the
working alternative leaves and returns, then restores the cheaper route.

Loopback remains available to the fixture mint; wallets live only in temporary
container storage. Each loss/delay scenario has a 180-second deadline; the combined
churn scenario has a 360-second deadline. Verify the source manifest and executable
checksum again afterward. This checks Linux execution and simulated routing;
OpenWrt services, physical links and router performance require separate acceptance.

### Production executable and storage recovery

The process-based service, customer and funding-cost tests accept
`FIPS_RELAY_TEST_PROGRAM` as the executable to launch. Without it, they use the
binary built by Cargo. This lets a native Linux harness exercise a separately
built candidate, including an ARM64 binary through an explicit QEMU launcher:

```sh
cat > run-relay-arm64 <<'SH'
#!/bin/sh
exec /path/to/qemu-aarch64 /absolute/path/to/fips-relay "$@"
SH
chmod 0755 run-relay-arm64
FIPS_RELAY_TEST_PROGRAM="$PWD/run-relay-arm64" \
  cargo test --offline --locked -p fips-relay --test service \
  explicit_initialization_cannot_reset_missing_state_or_raise_saved_limits \
  -- --exact --test-threads=1
```

Replace both launcher paths with the verified artifacts. Keep `exec` so shutdown
signals reach the candidate. Build the native harness from the same source bundle
and retain the candidate's hash; the override does not select a harness version.
Only the launched daemon and CLI execute under emulation. In-process checks stay
native, and emulated timings do not establish router performance. The existing
container recipes below also support running the harness itself on ARM64.

Build `--test funding_costs` with the same all-features Linux test command above.
Its fixture initializes a local test mint and wallets; the four child relays can
use the separately built default-feature OpenWrt executable. Mount that executable
at the absolute path baked into the test's `CARGO_BIN_EXE_fips-relay`. With the
target directories used above, set:

```sh
relay_program="$PWD/target/aarch64-unknown-linux-musl/openwrt/fips-relay"
compiled_relay_path="$PWD/target/linux-tests/aarch64-unknown-linux-musl/debug/fips-relay"
```

Set `funding_test_binary` to the absolute `funding_costs-<hash>` executable in the
Linux test target's `debug/deps/`. Use an already available ARM64 Linux image with
`sh` and `stat`. The following runs each case in a fresh container. Only the two
executables are mounted from the host; the full-volume case fills its own tmpfs:

```sh
run_recovery() {
  docker run --rm --pull never --network none --read-only --cap-drop ALL \
    --security-opt no-new-privileges --user 65534:65534 \
    --tmpfs /tmp:rw,nosuid,nodev,size=512m,mode=1777 \
    --tmpfs /isolated:rw,nosuid,nodev,size=128m,mode=700,uid=65534,gid=65534 \
    --memory 2g --cpus 2 --pids-limit 256 \
    --mount "type=bind,source=$funding_test_binary,target=/candidate/funding_costs,readonly" \
    --mount "type=bind,source=$relay_program,target=$compiled_relay_path,readonly" \
    --env FIPS_TEST_STORAGE_VOLUME=/isolated \
    --env "FIPS_TEST_STORAGE_TOKEN=$(python3 -c 'import uuid; print(uuid.uuid4())')" \
    --entrypoint /bin/sh "$relay_test_image" -ec '
      device=$(stat -c %d /isolated)
      blocks=$(stat -f -c %b /isolated)
      block_bytes=$(stat -f -c %S /isolated)
      capacity=$((blocks * block_bytes))
      printf "{\"schema\":1,\"device\":%s,\"capacity_bytes\":%s,\"token\":\"%s\"}\n" \
        "$device" "$capacity" "$FIPS_TEST_STORAGE_TOKEN" > /isolated/.fips-storage-test.json
      exec /candidate/funding_costs "$@"
    ' sh "$@"
}
run_recovery wallet_costs_and_refunds_survive_restart_without_resetting_the_lifetime_limit \
  --exact --test-threads=1 --nocapture
run_recovery filesystem_exhaustion::full_filesystem_preserves_wallet_and_channels \
  --exact --ignored --test-threads=1 --nocapture
run_recovery used_expiry::seller_recovers_after_missing_the_shared_channel_collection_deadline \
  --exact --test-threads=1 --nocapture
run_recovery used_expiry::shared_paid_channel_expires_with_each_counterparty_offline \
  --exact --test-threads=1 --nocapture
run_recovery restore::interrupted_funding_restores_after_route_expiry_without_new_spending \
  --exact --test-threads=1 --nocapture
```

The second case verifies Linux ENOSPC and SQLite rollback before interrupted
startup and recovery. Both storage cases require paid delivery after restart and settle
the original channels without resetting lifetime spending limits. Tmpfs exercises
Linux errors and process recovery; it does not model flash persistence or power
loss. The expiry cases verify seller recovery after missing collection and buyer
refund, seller collection with the buyer offline followed by refund with the seller
offline, and unused-funding recovery after an interrupted opening. The two shared
channel cases conserve 512 test sats each; interrupted opening conserves 384.
All include mint fees and retain original obligations and lifetime budgets.
Missed-collection recovery distinguishes accepted signed credit from actual zero
collection. Verify the source manifest and both executable hashes afterward.

### TCP, WebSocket and TLS with the packaged executable

Build the service harness from the same source bundle with optional relay features
disabled, matching the packaged daemon. The accepted bundle includes the corrected
restart fixture, which keeps automatic renewals enabled and verifies original
funding records and spending limits through recovery. The fixture supplies its own
temporary mint and TLS proxy:

```sh
CARGO_TARGET_DIR="$PWD/target/linux-tests" CARGO_INCREMENTAL=0 \
  CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0 \
  cargo +1.96.0 zigbuild --offline --locked -j 1 \
  --target aarch64-unknown-linux-musl -p fips-relay --no-default-features \
  --test service --test customer
```

Set `service_test_binary` to the resulting executable `service-<hash>` in
`target/linux-tests/aarch64-unknown-linux-musl/debug/deps/`. Use `relay_program`,
`compiled_relay_path` and the local image from the production-executable recipe
above. Each case mounts only the harness and the packaged executable:

```sh
run_relay_case() {
  relay_case_binary=$1
  shift
  docker run --rm --pull never --network none --read-only --cap-drop ALL \
    --security-opt no-new-privileges --user 65534:65534 \
    --tmpfs /tmp:rw,nosuid,nodev,size=512m,mode=1777 \
    --memory 2g --cpus "${relay_test_cpus:-2}" --pids-limit 256 \
    --mount "type=bind,source=$relay_case_binary,target=/candidate/relay-test,readonly" \
    --mount "type=bind,source=$relay_program,target=$compiled_relay_path,readonly" \
    --entrypoint /candidate/relay-test "$relay_test_image" \
    "$@" --exact --test-threads=1 --nocapture
}
for relay_case in \
  mixed_udp_tcp_daemons_preserve_paid_limits_through_exhaustion_and_restart \
  mixed_udp_websocket_daemons_preserve_paid_limits_through_exhaustion_and_restart \
  mixed_udp_websocket_seed_daemons_preserve_paid_limits_without_a_websocket_peer_roster \
  mixed_udp_websocket_tls_daemons_validate_certificates_and_preserve_paid_limits \
  mixed_udp_websocket_self_signed_daemons_authenticate_fips_and_preserve_paid_limits
do
  run_relay_case "$service_test_binary" "mixed_transport::$relay_case" || exit
done
```

Each three-process case crosses UDP and TCP or WebSocket, denies unfunded forwarding,
exhausts and renews paid allowances, crashes/restarts the middle relay and settles
all original test funds. The three seeded WebSocket cases also drop the physical
stream while every service keeps running, then require delivery and a new
cumulative payment through the original channels with preserved spending limits.
They also restart the middle relay while the carrier rejects reconnects, preserve
funding identities and budgets during the partition, then recover fresh
authentication and paid traffic after the carrier returns.
The TLS cases also check certificate/handshake rejection
before peer admission or spending. Verify both executables and the source manifest
afterward. Loopback TLS does not establish remote proxy or radio acceptance.

### CPU-pressure check

The r32 packaged executable passes repeated UDP/TLS renewal and seeded WebSocket
recovery with a half-CPU limit shared by the harness, local mint and three relays.
Using the function and binaries above, run each case in a fresh container:

```sh
relay_test_cpus=0.5
run_relay_case "$service_test_binary" \
  mixed_transport::renewal_load::concurrent_bidirectional_renewals_preserve_payment_progress \
  --ignored || exit
run_relay_case "$service_test_binary" \
  mixed_transport::mixed_udp_websocket_seed_daemons_preserve_paid_limits_without_a_websocket_peer_roster || exit
unset relay_test_cpus
```

This retains the ordinary deadlines, retries and payment rules, and stops after
the first failure. Both cases conserve 384 test sats each; source and executable
hashes remain unchanged. The accepted run captures `cpu.max`, `cpu.stat`,
`memory.peak` and `memory.events` inside each container before and after its test.
The CPU quota remains 50,000 microseconds per 100,000-microsecond period.

| Case | Test duration | CPU time | Throttled periods | Memory peak |
| --- | ---: | ---: | ---: | ---: |
| Eight channel replacements | 43.41 s | 7.62 s | 29 | 93.2 MiB |
| Carrier loss and partitioned restart | 108.08 s | 13.84 s | 26 | 108.5 MiB |

Neither container records a memory-limit or out-of-memory event. CPU time and
memory are aggregate container measurements, including the test harness, mint,
relays and filesystem cache. The saved wrapper and records are in
`work/paid-relay-verification/2026-09-29-arm64-pressure`. This finite check does not
explain the earlier intermittent stalls or establish sustained router capacity
or per-byte payment overhead.

### Customer entry restart

The command above also builds `customer-<hash>` in the same `debug/deps/`
directory. Set `customer_test_binary` to that executable's absolute path and
reuse `run_relay_case` with the same packaged daemon and isolated Linux image:

```sh
for customer_case in \
  customer_app_uses_forwarding_data_mesh_and_preserves_terms_across_reopen \
  customer_app_uses_real_accounts_and_preserves_them_across_reopen
do
  run_relay_case "$customer_test_binary" "$customer_case" || exit
done
```

Each case runs an embedded customer and two real relay processes. It reopens the
customer, then kills and restarts the entry while the customer remains running.
Fresh delivery and two advances of automatic payment must recover without another
Buy or payment flush. Original accounts and spending limits survive, the entry
earns, and all 384 test sats are collected. These are ARM64 Linux checks of shared
customer logic; Android lifecycle, Wi-Fi binding and current devices still need
their own acceptance. Verify the source manifest and both executable hashes again.

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

The wrapper does not probe the mint before launching the relay. The relay owns
keyset, financial-state and configuration validation, including any recovery or
purchase that requires a reachable mint. This lets it attempt saved-account
recovery during a mint outage without an extra HTTP readiness gate.

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
identity/limits, and network readiness. A missing clock marker must block startup.
An unreachable mint must not block the wrapper from launching the daemon; verify
the service preserves its financial limits during recovery. Exercise
a bridged native interface without changing the live radio configuration.
Check an upgrade of a running instance preserves its account and budget.

Run the host-side wrapper checks with
`python3 -m unittest discover -s testing/openwrt`. They substitute the clock marker
and OpenWrt commands; device startup and outage recovery need separate acceptance.

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

The later r5 upgrade preserved complete original accounts after stopped-account
backups. New forwarding-attempt accounts then passed wireless streams beyond the
old packet-history ceiling and automatically renewed source channels. All test
funds were collected and original services restored. This is separate from the
r3 reboot evidence; see [../WIRELESS-ACCOUNTING.md](../WIRELESS-ACCOUNTING.md).
