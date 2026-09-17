# Running a paid relay service

`fips-relay` assembles the native endpoint, durable buyer/seller accounting,
Spilman receiver, quotes and autonomous controller in one Unix process. Linux
and macOS local process tests cover UDP and native TCP. Three OpenWrt routers have also earned
test payments over native Wi-Fi links. See [TESTBENCH.md](TESTBENCH.md) for the
historical hardware evidence and [PROTOTYPE-RESULTS.md](PROTOTYPE-RESULTS.md) for
the completed bounded customer demonstration and current limits.

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
profile that preserves normal panic semantics. The early hardware payment
runs used the larger release build; r5 has separate
[wireless measurements](WIRELESS-ACCOUNTING.md) on the size-oriented profile.
See [openwrt/README.md](openwrt/README.md) for APKv3
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
documentation-only mint address with the local test mint. Direct service startup
loads local receiver state without contacting the mint; new paid funding refreshes
mint keys before verification. Funding and settlement remain mint-dependent.
The OpenWrt readiness wrapper separately still waits for the mint. Create the
parent of the chosen state directory, but leave that state directory absent.
See [destination pricing](DESTINATION-PRICING.md) for free local destinations,
explicit route opening and configuration compatibility.
For fresh forwarding-data service, `return_allowance: true` enables the
[bounded reverse-path policy](RETURN-ALLOWANCE.md). It defaults to false and
does not enable an unrestricted reverse route or authorize wallet spending.
Optional `price_selection` compares source offers using native end-to-end quality
and capped trials on forwarding-data accounts. See [PRICE-SELECTION.md](PRICE-SELECTION.md)
for defaults, watch authority, peer compatibility and current limitations.

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
intended path. `transports.ethernet` uses the core transport schema: one instance
or named instances, each with an `interface` such as a Wi-Fi mesh/AP/STA interface
exposed by Linux. The underlying native FIPS raw
socket supplies EtherType `0x2121`; the service does not configure radios,
bridges, DHCP or IP forwarding. Native interfaces require raw-socket permission.
For numeric peer addresses, configure stable interface MACs and verify them after
reboot; automatically assigned virtual Wi-Fi addresses can change with interface
creation order. See the OpenWrt package guide for the observed failure and fix.
Lower-layer Wi-Fi forwarding must be disabled and the intended physical path
must still be verified on hardware.

All link settings belong in `transports`, using the same single/named instance
schema as the FIPS core. For UDP, set `transports.udp.bind_addr` to an explicit
numeric socket address and list numeric UDP neighbor addresses. Omit UDP for a
native-only node; there is no implicit UDP fallback. The old `udp_bind` and
`ethernet_interfaces` service fields are not accepted.

The paid service currently accepts UDP, native TCP and Ethernet, with at most
four total transport instances and eight configured neighbors. Native TCP uses
`transports.tcp.bind_addr` for a listener; an omitted TCP bind makes that instance
outbound-only. Neighbor addresses identify the transport type (`tcp`, for example),
not its optional instance name. Other core adapters are rejected until their
paid-service acceptance is supplied.

Before starting payment workers, the service checks that every requested
transport instance is operational. A failed listener or unavailable adapter
stops startup and closes any sibling transports that did start. Network changes
leave saved financial terms and spending authority intact.

Set Ethernet `discovery`, `announce`, `auto_connect` and `accept_connections`
explicitly. The example retains static peers with discovery disabled. For beacon
joining, enable these flags on each intended interface and select
`neighbor_admission: "authenticated_adjacent"` for payment-control access.
That admission setting does not enable discovery or authorize wallet spending.
Nostr and LAN/local discovery remain disabled. No system TUN, DNS server or
ordinary Internet gateway is installed by this process. Paid-service acceptance
covers UDP and Ethernet, plus a mixed UDP/TCP route with payment, exhausted
allowance, renewal and relay restart.

An optional `customer_network` subnet enables bounded incoming quote/payment
control from authenticated direct UDP customers without preconfiguring their
identities. It requires a specific UDP bind address inside that subnet. In the
default `configured_only` mode, outgoing purchases require configured neighbors.
The `authenticated_adjacent` mode also permits authenticated adjacent providers;
customer-subnet peers remain inbound-only unless explicitly configured as
neighbors. These admission rules do not authorize spending by themselves. See
[CUSTOMER-ENTRY.md](CUSTOMER-ENTRY.md) for admission limits and bootstrap, and
[the acceptance report](PROTOTYPE-RESULTS.md) for the physical customer checks.

Financial terms are saved at initialization. Changing prices, capital, lifetime
budget or exposure settings afterward stops startup for explicit reconciliation.
Changing network addresses does not reset the saved financial terms. The
forwarding policy still rejects a next hop without an accepted agreement.

Choose a saved window large enough for a whole session packet at the offered
rate. For example, a 4,000-msat window admits a roughly 1,100-byte envelope at
3 msat/byte. A smaller window cannot admit that packet merely because the
channel has spare funds. Larger windows also increase maximum uncertain crash
exposure. Window size and write frequency need hardware measurement.

## Payment timing

[Adaptive payment cadence](CADENCE.md) combines priced-usage and age triggers,
keeps confirmed idle channels quiet, and advances durable forwarding windows
locally. Optional `payment_cadence` settings change scheduling on restart, never
the account's saved financial terms. Renewal/settlement remain separate.

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

Background recovery first reconciles unresolved funding intents against the
local wallet's committed channel records, even if their offers have expired,
are paused, or are no longer retained. It uses the original request identity,
receiver, mint, capacity and expiry. This step cannot contact the mint, spend
another token, accept a quote or activate a route. Missing or conflicting records
keep their capital reservation; preserve the entire state directory for
reconciliation. Recovering a channel record does not refund it or renew routing
permission. An orphan channel without an accepted contract still needs separate
refund/reconciliation work; automatic expiry refunds are not implemented.

`settle` pauses route watches and renewals, seals outgoing channels, completes mint closure and
recovers refunds. `pause_renewals` and `resume_renewals` control replacement work
without deleting saved intents. All commands are local administrative actions;
this socket is not the public Wi-Fi payment/onboarding service.

Route replacement and renewal cannot reserve the same channel concurrently.
The first saved intent keeps ownership across restart; a paused or unfinished
route replacement also blocks renewal until its new agreement is accepted or
the interrupted purchase is retired after a confirmed refund.
This changes no wire messages or journal fields. A saved journal containing
both unfinished intents for one channel is rejected at startup with
`conflicting route and renewal intents`. Preserve that state for reconciliation;
deleting either intent can lose funding or spending evidence. The loader does
not automatically choose which financial operation to discard.

New destination purchases are rejected before saving another request when the
provider's shared channel is already closing or renewing. Funding selection and
purchase recording recheck this state, including after waiting for the wallet.
Acceptance completion checks the saved channel state before activating the
purchase. Settlement can proceed while a multi-hop acceptance request is in
flight; a reply arriving after closure starts cannot reactivate that purchase.
No channel lock spans the remote acceptance exchange.

If an acceptance is cancelled, its funding and purchase records remain saved.
Once channel settlement confirms the refund, any unacknowledged purchases on
that channel are marked retired and their pending requests are removed. Their
records, signed balances and lifetime limits remain. A source watch loses only
the retired pending offer, preserving its pause and price settings. A stale
recovery task cannot authorize that retired offer again; a subsequent purchase
needs a fresh offer and existing spending authorization.

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
