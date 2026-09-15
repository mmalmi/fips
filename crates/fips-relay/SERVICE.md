# Running a paid relay service

`fips-relay` assembles the native endpoint, durable buyer/seller accounting,
Spilman receiver, quotes and autonomous controller in one Unix process. Linux
and macOS local process tests use UDP. Linux Wi-Fi deployment and packaging still
need separate verification; this is not yet a complete customer hotspot.

## OpenWrt build

The ARM64 Linux executable cross-builds with an installed Rust musl target,
Zig and `cargo-zigbuild`:

```sh
CARGO_PROFILE_RELEASE_LTO=thin CARGO_PROFILE_RELEASE_STRIP=symbols \
  cargo zigbuild -p fips-relay --bin fips-relay \
  --target aarch64-unknown-linux-musl --release
```

This produces a statically linked executable. The current build is approximately
35 MB; check device storage and memory before installation. Its checksum and
command-line startup were verified on three ARM64 OpenWrt test routers. This
does not verify radio compatibility, forwarding performance or package startup.

## OpenWrt service supervision

`openwrt/fips-relay.init` and `openwrt/fips-relay.config` provide a procd service
definition and disabled-by-default UCI configuration. Install them as
`/etc/init.d/fips-relay` (mode 0755) and `/etc/config/fips-relay`, respectively.
Set the executable and service-JSON paths explicitly, initialize the saved state
once, and enable the UCI instance before starting `/etc/init.d/fips-relay start`.
The supervisor never initializes accounts. It bounds crash respawns and allows
65 seconds for orderly shutdown. The wrapper has run on three OpenWrt routers.

The first hardware trial used temporary executable paths and manually started
instances. No boot-start links were installed. A temporary executable disappears
on reboot; persistent package installation and boot recovery remain required.
Confirm radio capabilities, disabled mesh forwarding, an isolated native
interface, working management access, a reachable mint and a synchronized clock
before admitting paid traffic. Firmware package builds are still pending.

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

Status includes peer paths/counters, active and historical purchases, locked
capital, remaining lifetime budget and received test-packet totals/digest. It
contains no bearer proofs or private keys. `last_error` is the last retained
controller error; it may describe a transient condition that has recovered.

`send` queues a 1–1,000-byte diagnostic payload to FIPS service port 44740.
Queue acceptance does not establish delivery. Each endpoint must buy its own
direction before sending through paid relays; receiving a request never buys a
reverse direction automatically. The test receiver records totals and a digest
without automatically replying. Control services use ports 44741–44743 over
adjacent TCP/FIPS links, independently of transit credit.

`settle` pauses renewals, seals outgoing channels, completes mint closure and
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
