# Running a paid relay service

`fips-relay` assembles the native endpoint, durable buyer/seller accounting,
Spilman receiver, quotes and autonomous controller in one Unix process. Linux
and macOS local process tests use UDP. Three OpenWrt routers have also earned
test payments over native Wi-Fi links. See [TESTBENCH.md](TESTBENCH.md) for the
hardware evidence and remaining checks; this is not yet a complete customer hotspot.

The example selects `terms.billing: "forwarding_attempt"` for fresh accounts.
It retains totals and unfinished sends instead of every completed packet.
Offers, accepted contracts and source watches bind that tariff explicitly.
Omitted billing fields preserve the legacy fingerprint tariff and its packet
limit. Saved account terms cannot be changed by editing the configuration.
See [ACCOUNTING.md](ACCOUNTING.md) for retransmission semantics, compatibility
and backup requirements before using a newer executable with existing journals.

## OpenWrt build

The ARM64 Linux executable cross-builds with an installed Rust musl target,
Zig and `cargo-zigbuild`:

```sh
cargo zigbuild -p fips-relay --bin fips-relay --locked \
  --target aarch64-unknown-linux-musl --profile openwrt -j 4
```

This produces a statically linked executable of about 19 MiB, using a size-oriented
profile that preserves normal panic semantics. The previous hardware payment
runs used the larger release build. Forwarding performance of the new profile
still needs measurement. See [openwrt/README.md](openwrt/README.md) for APKv3
packaging, installation, backups and device acceptance checks.

## OpenWrt service supervision

The package installs a procd service, readiness wrapper, NTP hotplug hook and
disabled-by-default UCI configuration. Set the executable and service-JSON paths
explicitly. Initialize a new account once; retain an existing account unchanged.
Enable the UCI instance before starting `/etc/init.d/fips-relay start`, and use
`/etc/init.d/fips-relay enable` separately for boot startup. Installation never
initializes accounts or enables boot startup. Procd bounds crash respawns and
allows 65 seconds for orderly shutdown.

The wrapper requires persistent account storage and waits for a valid NTP event,
unbridged native interfaces with carrier, disabled mesh forwarding where relevant,
and the configured mint. Waiting does not consume financial allowance or the crash
restart budget. Query the actual relay's private control socket to establish
readiness; a running wrapper alone is insufficient. The package changes no radio,
bridge, DHCP or firewall configuration. Firmware sysupgrade and older opkg/IPK
packaging remain separate work.

## Initialization and configuration

Build with `cargo build -p fips-relay --bin fips-relay`. Copy
`service.example.json` to a private local configuration file and replace its
documentation-only mint address with the local test mint. The mint must be
reachable when the receiver loads its keysets. Create the parent of the chosen
state directory, but leave the state directory itself absent.

Run `fips-relay init /absolute/path/config.json` once. It prints the new public
FIPS identity. Init creates private keys and empty accounts; it never overwrites
existing or partially initialized state. Run never performs initialization.
Keep the whole state directory together when backing up or restoring it.
On OpenWrt, use persistent storage; `/tmp` and `/var` may disappear on reboot.
Restored forwarding remains gated until all service components have loaded and
validated, so a failed startup cannot briefly expose an old allowance.

Add each adjacent peer to `neighbors` using its printed public identity and
explicit transport address. For a native interface the form is:

```json
{"npub":"REPLACE_WITH_NEIGHBOR_NPUB","addresses":[
  {"transport":"ethernet","addr":"mesh0/02:00:00:00:00:01"}
]}
```

The MAC above is an example. Configure only the real adjacent peers for the
intended path. `ethernet_interfaces` accepts ordinary interface names, including
Wi-Fi mesh/AP/STA interfaces exposed by Linux. The underlying native FIPS raw
socket supplies EtherType `0x2121`; the service does not configure radios,
bridges, DHCP or IP forwarding. Native interfaces require raw-socket permission.
For numeric peer addresses, configure stable interface MACs and verify them after
reboot; automatically assigned virtual Wi-Fi addresses can change with interface
creation order. See the OpenWrt package guide for the observed failure and fix.
Lower-layer Wi-Fi forwarding must be disabled and the intended physical path
must still be verified on hardware.

`udp_bind` is an optional explicit numeric socket address. Set it to null for a
native-only node; there is no implicit UDP fallback. Endpoint adapters can
instead bind a selected UDP socket and list numeric UDP neighbor addresses.
Nostr, LAN/local discovery and Ethernet beacon discovery are disabled. No system
TUN, DNS server or ordinary Internet gateway is installed by this process.

Financial terms are saved at initialization. Changing prices, capital, lifetime
budget or exposure settings afterward stops startup for explicit reconciliation.
Changing network addresses does not reset the saved financial terms. The
forwarding policy still rejects a next hop without an accepted agreement.

Choose a saved window large enough for a whole session packet at the offered
rate. For example, a 4,000-msat window admits a roughly 1,100-byte envelope at
3 msat/byte. A smaller window cannot admit that packet merely because the
channel has spare funds. Larger windows also increase maximum uncertain crash
exposure. Window size and write frequency need hardware measurement.

## Local controls

Run `fips-relay run /absolute/path/config.json` in the foreground. Send SIGTERM
or Ctrl-C for an orderly stop. It drains controller/payment work, stops the
endpoint and saves final accounting. Shutdown preserves open channels; it does
not imply settlement or erase unpaid exposure.

The process owns a private `control.sock` inside its state directory. `ctl`
reads one JSON request from standard input and returns JSON. Examples:

```sh
printf '%s\n' '{"type":"status"}' | fips-relay ctl /absolute/path/config.json
printf '%s\n' '{"type":"buy","destination":"REPLACE_WITH_NPUB"}' | fips-relay ctl /absolute/path/config.json
printf '%s\n' '{"type":"send","destination":"REPLACE_WITH_NPUB","payload":"hello"}' | fips-relay ctl /absolute/path/config.json
printf '%s\n' '{"type":"settle"}' | fips-relay ctl /absolute/path/config.json
```

Status includes peer paths/counters, active and historical purchases, watched
destinations with their price ceilings and pause state, locked
capital, remaining lifetime budget and received test-packet totals/digest. It
contains no bearer proofs or private keys. `last_error` is the last retained
controller error; it may describe a transient condition that has recovered.
It also includes volatile probe results and control-stream traffic counters.
See [MEASUREMENTS.md](MEASUREMENTS.md) for bounded paced traffic, metric definitions
and the local native topology-control wrapper.

`send` queues a 1–1,000-byte diagnostic payload to FIPS service port 44740.
Queue acceptance does not establish delivery. Each endpoint must buy its own
direction before sending through paid relays; receiving a request never buys a
reverse direction automatically. The test receiver records totals and a digest
without automatically replying. Control services use ports 44741–44743 over
adjacent TCP/FIPS links, independently of transit credit.

`watch` authorizes future route purchases for one source destination, with an
explicit maximum aggregate rate in millisats per 1,024 bytes:

```json
{"type":"watch","destination":"REPLACE_WITH_NPUB","max_rate_msat_per_kib":3072}
```

It saves authorization before requesting the first quote. If that request fails
or exceeds the ceiling, the watch remains active and will retry. Periodic checks
can accept a changed native path or price within the ceiling, subject to the
saved lifetime spending and working-capital limits. Unchanged offers are reused;
ordinary `buy` remains a one-time request. Forwarded traffic never creates a
source watch or authorizes the reverse direction. Channels remain shared across
destination agreements.

`pause_route_refresh` waits for current watch work, then durably pauses all
watches. Reissuing `watch` resumes a destination; pause before changing its price
ceiling, and finish any retained purchase first. Failed purchases retain their
exact offer and funding intent across restart. An expired offer or unfinished
renewal may still require explicit recovery; the monitor never discards funds
to bypass one. Watch polling yields to existing channel renewal when due.

`settle` pauses route watches and renewals, seals outgoing channels, completes mint closure and
recovers refunds. `pause_renewals` and `resume_renewals` control replacement work
without deleting saved intents. All commands are local administrative actions;
this socket is not the public Wi-Fi payment/onboarding service.

After settlement and confirmed refund recovery, a fresh `buy` can purchase the
same route again using the existing account. It retains closed channel history,
unpaid exposure and lifetime spending limits, and funds a new channel. The offer
must keep the provider, next hop, price, mint and byte allowance. An unfinished
automatic renewal must complete through its own recovery path first. Background
recovery alone does not reopen an explicitly settled purchase; importing more
wallet funds also does not authorize one.

After an abrupt stop, a provider may retain usage that the buyer lost from its
last checkpoint. Payments and final settlement cover the portion supported by
the buyer's own evidence, subject to the original capacity and lifetime limits.
Unconfirmed usage is not reconstructed from the provider's report. The unpaid
remainder still consumes the provider's bounded exposure allowance; repeated
losses can exhaust that allowance and stop forwarding.

## Reproducible process check

Run `cargo test -p fips-relay --test service`. The test fixture owns an isolated
local CDK mint with simulated Lightning funding. It initializes five separate
service processes and seeds their wallets through the existing Cashu wallet API.
No public mint, user wallet or real payment backend is involved. The offline
`wallet` command and isolated hardware mint are documented in
[TESTBENCH.md](TESTBENCH.md). The phone/customer interface remains separate work.

The test exercises a source, three paid routers and another endpoint, separately
buys both directions, sends traffic, stops/restarts every process and abruptly
kills/restarts the middle router. It compares retained accounts and capital,
continues paid traffic, settles all six channels and redeems/spends every final
wallet balance. Endpoint retries are bounded application behavior; each freshly
encrypted network attempt remains billable under the existing contract.

Controller recovery primes native destination discovery from saved agreements.
Otherwise a restarted transit router can have intact funded accounts while
missing the destination information learned during quote exchange. Discovery
recovery does not authorize changed prices or next hops. Route-change propagation,
expired pending offers and interruption at every wallet/acceptance stage still
need further coverage.

The native peer-restart path clears old tree state and Bloom-filter sequence
numbers after a completed handshake proves a changed startup epoch. Surviving
neighbors then accept the restarted node's first routing announcements. An
unaccepted epoch hint cannot reset this state. Link-connected status alone is
not an end-to-end readiness guarantee; the test verifies actual paid delivery.
Simultaneous restart can cause several routers' discovery requests to hit the
same per-target rate limit. A failed lookup ladder then invokes the native
30-second backoff. The process test permits at most six application attempts
over 60 seconds for each delivery, rather than treating the first connected
links as immediate route readiness. It does not promise seamless recovery.

For failed-test diagnostics, set `FIPS_RELAY_TEST_LOG=fips_core::node=debug` and
`FIPS_RELAY_TEST_LOG_DIR` to an existing private directory. Failed tests save only
node logs there. Normal test wallets and account state remain temporary.
