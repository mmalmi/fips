# Isolated hardware test mint and wallet funding

`fips-relay-test-mint` runs a genuine local CDK mint with a simulated Lightning
backend. Its tokens have no external backing. Only the private administrator
socket can issue a bounded test grant; the HTTP listener exposes the ordinary
mint protocol. The relay executable does not include this funding capability
in its normal build.

## Build and start

Build the relay normally, and select the explicit test feature for the mint:

```sh
cargo build -p fips-relay --bin fips-relay
cargo build -p fips-relay --features testbench --bin fips-relay-test-mint
```

Both also cross-build with the ARM64 musl command in [SERVICE.md](SERVICE.md).
Use `--features testbench --bin fips-relay-test-mint` for the mint executable.

Example mint configuration:

```json
{
  "state_directory": "/var/lib/fips-bench/run1/mint",
  "bind": "127.0.0.1:30338",
  "max_issued_sat": 100000
}
```

Create the parent directory, then run:

```sh
fips-relay-test-mint run /absolute/path/mint.json
```

For a hardware bench, choose an assigned private LAN address reachable from the
routers. Wildcard, multicast and public binds are rejected. The TCP proxy has a
fixed loopback CDK upstream, at most 32 active connections, and a 45-second
connection limit. Funding controls use a separate private Unix socket. All
participants must use the same advertised mint URL, including its port.

Each mint process requires a new state directory. The simulated Lightning
network has in-memory state; existing directories are neither reset nor silently
resumed. Keep this mint process alive across the relay restart tests. Settle and
collect the run's balances before ending it. SIGTERM/Ctrl-C ends the fixture;
this tool does not claim production mint restart support.

## Fund a relay

Initialize the relay as described in SERVICE.md, then leave it stopped. Request
a grant through the mint's local control socket:

```sh
printf '%s\n' '{"type":"issue","id":"router-1","amount_sat":512}' |
  fips-relay-test-mint ctl /absolute/path/mint.json
```

The response names a private export file, its amount and operation ID. It does
not print bearer tokens. Repeating an ID with the same amount returns that same
export; changing its amount fails. At most 64 grants can reserve the configured
issuance limit. A failed or interrupted grant keeps its reserved amount.

Transfer the export privately to the target. Build an import request from its
`token` field and send it on standard input to:

```sh
fips-relay wallet /absolute/path/relay.json
```

The request shape is `{"type":"import","token":"ENCODED_TOKEN"}`. This command
accepts only sat tokens from the relay's saved mint. It acquires the same
exclusive state lock as the service, so it refuses to race a running relay.
Adding wallet funds does not change the lifetime spending budget, signed
evidence, existing channel limits or seller credit. Never initialize a new
relay directory as a substitute for reconciling an existing account.

## Collect and verify

After requesting settlement through the running relay's private control socket,
stop the relay. Query and export its remaining wallet balance:

```sh
printf '%s\n' '{"type":"balance"}' | fips-relay wallet /absolute/path/relay.json
printf '%s\n' '{"type":"export","id":"return-1","amount_sat":512}' |
  fips-relay wallet /absolute/path/relay.json
```

Use the actual balance rather than the example amount. Export writes a new
private file inside the saved state directory; the result contains only its
path, amount and operation ID. Reusing the ID returns the existing export.
A reserved export without a completed file fails closed; inspect the Cashu
activity and saga journals before any recovery action. It is not automatically
reissued as another spend.

Send `{"type":"collect","token":"ENCODED_TOKEN"}` to the mint's private
control socket to redeem each return. `{"type":"report"}` reports reserved
issuance, collected balance and simulated settlement conservation. A complete
run also checks every old wallet is empty, the final collected balance matches
actual funding, and each router's final balance includes its positive net
forwarding margin before collection. Conservation alone is not evidence that
traffic used the intended wireless path.

## Verification

```sh
cargo test -p fips-relay --features testbench --test bench
```

Tests exercise real mint funding, wallet import/replay rejection, an active
relay's exclusive lock, retained spending state, private idempotent export and
redemption, issuance bounds, refused public binds, and both command-line tools
through the private mint control socket. These supplement the native paid
forwarding tests; they do not replace hardware path or customer-flow checks.

## First hardware result

An isolated run used two endpoint processes on one ARM64 Linux host and three
ARM64 OpenWrt routers as distinct paid relays. Each endpoint had only its
adjacent router as a UDP peer. Inter-router FIPS peers used native Ethernet
frames over encrypted 802.11s interfaces, with mesh forwarding disabled and
management Ethernet outside those interfaces. The middle relay had no UDP
transport. Live peer snapshots matched only the configured five-node line.

Three 959-byte application payloads in each direction arrived on their first
attempt and matched the receiving endpoint's digest. Captures on the middle
router confirmed native FIPS frames in both directions on both Wi-Fi hops.
Captures include routing and payment traffic; packet totals are not application
throughput measurements.

| Participant | Initial test sats | After settlement | Net |
| --- | ---: | ---: | ---: |
| Endpoint A | 512 | 493 | -19 |
| Relay 1 | 512 | 525 | +13 |
| Relay 2 | 512 | 524 | +12 |
| Relay 3 | 512 | 525 | +13 |
| Endpoint B | 512 | 493 | -19 |

All six channels settled. Every final balance was exported and redeemed into
the test mint's collector wallet: 2,560 test sats, with all participant wallets
empty afterward. Prices were artificial test prices; billing covered opaque
FIPS session envelopes, including session control traffic, rather than only
the 5,754 application bytes.

This establishes basic bidirectional paid forwarding on hardware. Hardware
renewal, restart and route-change exercises, resource/performance measurements,
the public customer entry and phone flow remain separate acceptance work.
