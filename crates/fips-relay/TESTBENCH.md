# Isolated hardware test mint and wallet funding

For the current completed prototype scope and later phone/performance evidence,
see [the acceptance report](PROTOTYPE-RESULTS.md). Earlier run sections below are historical.

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

## Hardware recovery and renewal run

A second run reused the same saved identities, accounts and financial limits,
with another 256 test sats per participant. A fresh purchase after confirmed
refund replaced the explicitly closed channels. The middle physical router
then passed an orderly process restart and a forced process kill followed by
supervisor restart. The same six funded channels and retained spending limits
survived, and traffic resumed in both directions.

Longer traffic exposed a buyer/provider accounting gap after the crash: a
provider retained a submission that the buyer had lost from its checkpoint.
The controller now pays only the portion supported by its own evidence, so
later known submissions can continue earning payments. The unsupported
remainder stays unpaid and consumes the existing exposure allowance. This was
reproduced in a native mint-backed integration test and corrected on the same
funded hardware accounts. A simultaneous service restart also needed native
session recovery time; instantaneous or lossless recovery is not claimed.

With renewal paused, both directions stopped at their source channels' credit
limits while lifetime budgets remained positive. Enabling renewal replaced all
six starting channels, confirmed their refunds and restored both directions.
The renewal script matched 60 application payload digests across its phases
and observed four delivery gaps during automatic replacement. Additional
restart probes also verified both directions. These orchestration observations
are not throughput or packet-latency measurements.

| Participant | Second grant | After settlement | Net |
| --- | ---: | ---: | ---: |
| Endpoint A | 256 | 85 | -171 |
| Relay 1 | 256 | 368 | +112 |
| Relay 2 | 256 | 371 | +115 |
| Relay 3 | 256 | 375 | +119 |
| Endpoint B | 256 | 81 | -175 |

All 16 channels opened in the second run settled, including automatic
replacements. All 1,280 second-run test sats were collected, bringing total
collection across both runs to 3,840; every participant wallet was empty.
Routers retained home LAN management, client Wi-Fi and ordinary Internet access.

At that phase, physical route changes and performance had not been measured.
The later r4 experiment is documented below. Duplicate/unsolicited-traffic
exercises and the public customer/phone flow remain separate acceptance work.

## Persistent OpenWrt package and boot recovery

The three ARM64 routers subsequently installed a local APKv3 package on OpenWrt
25.12.5. The size-oriented static executable is 19,943,000 bytes; the archive is
9,292,518 bytes. This application build includes automatic source route refresh,
but paid hardware demonstrations above used the earlier, larger executable.
The size comparison does not establish forwarding performance.

Existing UCI paths and complete settled accounts were retained. A running r1 to
r3 package upgrade stopped and restarted the process with identical identity,
purchase history and remaining budget. The startup wrapper was exercised under
the real supervisor with a missing clock marker, an unreachable mint and a
bridged native-interface probe. It waited without loading a new account or
changing the live radio configuration.

Each router passed a real reboot, established by changed boot IDs. Final checks
confirmed the saved accounts, exact expected native neighbour connections, live
MAC addresses, clock synchronization, isolated mesh interfaces and disabled mesh
forwarding. An AP interface remained active; DNS and HTTPS Internet requests from
each router succeeded. Existing network files matched the final pre-reboot
configuration. The isolated mint process and existing host web service survived.
Final observed reboot-to-check-completion times were about 105 seconds per router;
this is service recovery timing, not a network latency benchmark.

The tests exposed automatically assigned virtual mesh MACs changing after boot
on two radios. A one-sided connection initially concealed one stale configured
peer address. After both radios rebooted, their accounts loaded but native peering
failed. Pinning the affected mesh interfaces to their intended addresses and
repeating their reboot checks restored stable peering. The LAN/AP configuration
was retained. See [openwrt/README.md](openwrt/README.md) for the configuration
requirement and package procedure.

At the end of the r3 phase the packaged router services ran idle with boot
startup enabled. Test endpoints were stopped, wallets empty and prior channels
settled. These checks
do not establish reboot recovery during an unfinished financial operation, paid
traffic on the new profile, other CPU architectures, firmware sysupgrade or old
opkg/IPK packaging. Those claims need separate evidence.

## r4 traffic measurements and physical route change

The subsequent `835726a` application build adds bounded operator probes,
control-stream counters and a private wrapper for native topology controls.
Three r4 upgrades preserved stopped-service state and existing accounts. Five
new funded accounts then exercised both directions over the wireless line and
over an explicitly established alternate wireless link after the middle service
stopped. Source watches changed route agreements automatically while preserving
their original Spilman channels. Four streams each delivered all 1,200 packets
at 0.96 Mbps; mean one-way delays were 4.2–5.6 ms on the shared-clock endpoints.

A longer stream confirmed the 4,096-attempt accounting cutoff despite available
credit. This is an explicit sustained-service limitation, not channel exhaustion.
After the middle service reconnected, all eight channels settled. Each relay
retained positive net income, all 2,560 new test sats were collected, and total
collection reached 6,400. Original router accounts were restored on r4; isolated
endpoint processes stayed stopped. See [MEASUREMENTS.md](MEASUREMENTS.md) for
packet counts, resource use, control-counter boundaries and remaining limitations.

## r5 forwarding-attempt accounting

New explicitly funded accounts on r5 carried 6,000 and 12,000 packets per
direction over all three wireless relays at offered rates of 2–8 Mbit/s. Those
streams had no missing packets and the accounting files stayed compact.
Source channels renewed automatically under further traffic, with packet loss
during the handover and successful subsequent delivery. All eight channels
settled; relay net earnings were 75, 74 and 75 test sats. All 2,560 new test sats
were collected, bringing cumulative collection to 8,960. Original router
accounts and ordinary services were restored and verified on r5.
See [WIRELESS-ACCOUNTING.md](WIRELESS-ACCOUNTING.md) for precise counts, CPU cost,
memory, package provenance and limitations.
