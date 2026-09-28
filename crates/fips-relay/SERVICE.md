# Running a paid relay service

`fips-relay` assembles the native endpoint, durable buyer/seller accounting,
Spilman receiver, quotes and autonomous controller in one Unix process. Isolated
ARM64 Linux and macOS process tests cover UDP, native TCP and WebSocket, including
ordinary TLS and explicit FIPS-authenticated self-signed TLS. Earlier builds
earned test payments over native Wi-Fi links on three OpenWrt routers.
See [TESTBENCH.md](TESTBENCH.md) for the
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

Use the [OpenWrt build instructions](openwrt/README.md#build) and their matched
source-bundle workflow for the current development dependencies. The ARM64
executable is statically linked; the size-oriented profile preserves normal panic
semantics. The package guide records its verified revision and size.

The early hardware payment runs used the larger release build; r5 has separate
[wireless measurements](WIRELESS-ACCOUNTING.md) on the size-oriented profile.
See [the package guide](openwrt/README.md) for APKv3 packaging, installation,
backups and device acceptance checks.

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

After building from the matched source bundle, copy `service.example.json`
to a private local configuration file and replace its example mint address with
the local test mint. Direct service startup
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

For an explicitly limited fresh wallet, set `terms.wallet_capacity_bytes` before
initialization (for example, `16777216` selects 16 MiB). The limit covers native
SQLite logical records and reserved completion space for admitted operations.
It does not reserve filesystem/WAL space or bound the separate controller and
channel files. Omission leaves native wallet capacity unconfigured.

The maximum is saved with the account terms and in the wallet. Startup and offline
wallet commands require both to agree; changing or removing the configured limit
cannot resize or convert an existing account. A too-small limit can reject
initialization or new work; retain partial state and existing financial evidence.
See [readiness](READINESS.md) for the tested workloads and remaining deployment
requirements. A 16 MiB test setting is not a measured router sizing recommendation.

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

The paid service accepts UDP, native TCP, Ethernet and WebSocket, with at most
four total transport instances and eight configured neighbors. Native TCP uses
`transports.tcp.bind_addr` for a listener; an omitted TCP bind makes that instance
outbound-only. Neighbor addresses identify the transport type (`tcp`, for example),
not its optional instance name. Other core adapters are rejected until their
paid-service acceptance is supplied.

WebSocket uses `transports.websocket` and `websocket` neighbor addresses. Set a
numeric `bind_addr` for a listener, or omit it for an outbound-only instance.
Use `wss://` URLs for remote peers; plaintext `ws://` is restricted to loopback.
The native listener serves plaintext WebSocket, so remote inbound access needs
a TLS reverse proxy. Listener paths, seed URLs and connection/queue limits use
the core WebSocket configuration. An optional `seed_urls` list discovers peers
without preconfigured identities; payment control then requires explicit
`neighbor_admission: "authenticated_adjacent"`. A seed URL supplies a bootstrap
location, not spending authority or arbitrary endpoint discovery.

Native outbound WSS defaults to `tls_verification: "web_pki"`, checking the
certificate chain, server name and validity dates. To use self-signed or otherwise
untrusted certificates without installing a CA, set `tls_verification: "fips"`
on that WebSocket instance. This accepts a well-formed certificate regardless of
issuer, name or dates, while still verifying TLS handshake signatures. Peer
identity is authenticated by FIPS Noise; admission rules and spending limits
still apply. Configure the expected FIPS public identity when a particular peer
is required: a URL-only hint and link-quality measurements cannot establish that
identity. Browser clients retain the browser's certificate policy. Native
Wi-Fi/Ethernet links do not require TLS certificates.

WebSocket keeps reading during blocked writes. The key-hint and idle deadlines
still apply; incoming activity can refresh the idle deadline. Control-reply
buffers stay bounded, and overflowing them closes the connection.
Closing a connection or rebinding after a network change interrupts its pending
writes, including when the idle timeout is disabled. A partially written frame
is discarded with the old stream; it is not resumed on a replacement connection.

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
covers UDP and Ethernet, plus mixed UDP/TCP and UDP/WebSocket routes with payment,
exhausted allowance, renewal and relay restart. WebSocket checks include both
configured peers and URL-only bootstrap with authenticated adjacent admission.
The default TLS bootstrap case uses a loopback reverse proxy: untrusted issuers and
server-name mismatches are rejected before peer admission or spending, and a
valid certificate permits the same paid route and recovery checks. Its temporary
CA is supplied only to the child client's process; system trust is unchanged.
The explicit FIPS TLS mode passes the same checks with an untrusted self-signed
certificate and a mismatched name; a forged handshake signature is rejected
before admission or spending. These are local checks; remote TLS proxy deployment
remains unverified.

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

On `forwarding_data` accounts, a zero watch ceiling permits automatic free
grants only. `watch` returns `free_route` for a free grant or `purchase` for a
paid agreement, matching `buy`. Free upkeep restores explicit watches after
restart and replaces normal grants near expiry or quota exhaustion without
funding channels. See [free-route bounds](DESTINATION-PRICING.md#automatic-source-watches)
for idle behavior, offer capacity and the separate quality-trial limits.

`pause_route_refresh` waits for current watch work, then durably pauses all
watches. Reissuing `watch` resumes a destination; pause before changing its price
ceiling, and finish any retained purchase first. Failed purchases retain their
exact offer and funding intent across restart. An expired offer or unfinished
renewal may still require explicit recovery; the monitor never discards funds
to bypass one. Watch polling yields to existing channel renewal when due.

Background recovery first reconciles unresolved funding intents against the
local wallet's committed channel records, even if their offers have expired,
are paused, or are no longer retained. It uses the original request identity,
receiver, mint, capacity and expiry. Completed funding is recovered locally;
an incomplete persisted opening can query the mint to restore its original
committed outputs. Recovery cannot create an opening, spend another token, fall
back to a funding swap, accept a quote or activate a route. Missing or conflicting
evidence keeps its capital reservation; preserve the entire state directory for
reconciliation.

A fully identified, never-used channel whose funding is exclusively withdrawn
from routing can then recover its refund after the original wallet expiry. This
also covers channels with no accepted route. The controller saves an expiry
intent before refunding, fences delayed route installation and records the SDK's
actual recovered amount without inventing provider usage or acceptance. Used or
shared channels are ineligible for this automatic expiry path. Missing or
conflicting funding evidence and used/shared-channel unilateral recovery still
require separate reconciliation; see [recovery acceptance](READINESS.md#earlier-funding-recovery-after-quote-expiry).

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
[TESTBENCH.md](TESTBENCH.md). The separate [Pixel acceptance](READINESS.md)
checks a bounded phone session and customer-network isolation; this process test
does not establish paid Internet access or TollGate interoperability.

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

## Filesystem exhaustion regression

The ignored `funding_costs` filesystem test uses four local services and test
money. One transit relay lives on a disposable filesystem. It fills that volume
with real writes, requires ENOSPC from a controller journal write and SQLite's
disk-full error from a wallet write, then interrupts the relay. Restart must fail
while the volume is full. After removing only the test ballast, the shared
recovery scenario resumes paid traffic, settles the original channels and checks
balances and lifetime spending limits. This tests failed writes and process
recovery, not power loss or physical flash behavior.

Use a dedicated mounted 32–128 MiB filesystem. The test rejects the parent
filesystem and requires a matching marker and token; it never creates a mount.
For example, on macOS:

```sh
image_dir="$(mktemp -d)"
export FIPS_TEST_STORAGE_VOLUME="$(mktemp -d /tmp/fips-space.XXXXXX)"
hdiutil create -size 128m -fs HFS+ -volname 'FIPS storage test' \
  -nospotlight -type UDIF "$image_dir/relay-test.dmg"
hdiutil attach "$image_dir/relay-test.dmg" \
  -mountpoint "$FIPS_TEST_STORAGE_VOLUME" -nobrowse -noautoopen -owners on
export FIPS_TEST_STORAGE_TOKEN="$(python3 -c 'import uuid; print(uuid.uuid4())')"
python3 - <<'PY'
import json, os
from pathlib import Path
root = Path(os.environ['FIPS_TEST_STORAGE_VOLUME']).resolve()
device = root.stat().st_dev
space = os.statvfs(root)
capacity = space.f_blocks * space.f_frsize
assert device != root.parent.stat().st_dev
assert 32 * 1024**2 <= capacity <= 128 * 1024**2
os.chmod(root, 0o700)
marker = dict(schema=1, device=device, capacity_bytes=capacity,
              token=os.environ['FIPS_TEST_STORAGE_TOKEN'])
with (root / '.fips-storage-test.json').open('x') as output:
    json.dump(marker, output)
PY
cargo test -p fips-relay --all-features --test funding_costs \
  filesystem_exhaustion::full_filesystem_preserves_wallet_and_channels \
  -- --exact --ignored --test-threads=1 --nocapture
hdiutil detach "$FIPS_TEST_STORAGE_VOLUME"
```

Use the matching dependency graph described in [readiness](READINESS.md).
The marker permits filling the whole selected volume. Never place real accounts
on it. The test leaves its relay state in the private image for diagnosis; keep
the image until the result is understood, then remove that disposable image.
