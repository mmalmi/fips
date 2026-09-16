# Prototype acceptance and runbook

The bounded paid-forwarding prototype has been demonstrated on three OpenWrt
routers and an unrooted Pixel. This records the completed prototype acceptance
scope and the limits of that evidence as of 16 September 2026. Earlier run reports
remain historical records; their statements about unfinished phone/performance
work are superseded here.

## Model choice

| Option | Benefit | Cost for this prototype |
|---|---|---|
| Neighbor accounts | Reuses persistent channels and local accounting across flows; every relay sells onward service. | Relays need working capital and accept bounded risk from their neighbors. |
| Session-sponsored route payments | A source explicitly funds a particular complete path. | Requires path-wide agreement/recovery and handling funding when that path changes. |
| Delivery-receipt payments | Can condition compensation on an agreed receipt. | Requires receipt semantics, authentication, return traffic and loss/dispute rules; TCP may be absent or encrypted. |
| Hybrid | Local channels plus optional application sponsorship or receipts. | Useful later, but adding both mechanisms now would increase state and failure cases. |

The prototype chooses neighbor channels with explicit sender authorization and
recursive aggregate quotes. It reuses the existing FIPS/Cashu machinery and
avoids inventing a delivery-proof protocol before the basic paid path is tested.

## What the system does

The sender authorizes an aggregate route price and a spending limit. Each relay
sells forwarding to the preceding neighbor and buys the onward service, keeping
its fee. Persistent one-way Cashu Spilman channels are reused between neighbors;
each paying direction needs its own channel and authorization. Relays need working
capital because an incoming claim cannot immediately fund an outgoing channel.

The chosen tariff buys local forwarding attempts of opaque FIPS session bytes.
It neither inspects higher-layer acknowledgments nor promises destination
delivery. Delivery receipts remain optional future research. Source-funded
reverse traffic must be authorized separately, including session replies.
See [the accounting contract](ACCOUNTING.md) and [controller design](README.md).

The mint is trusted to honor valid tokens and channel settlement. Neighbors
trust each other only within the configured payment/allowance exposure; local
submission evidence and a signed balance are not proof of honest onward delivery.
Durable lifetime spending, funded capacity, capital caps, grace and checkpoint
windows bound distinct risks. Repeated router identities are rejected in quote
paths, which stop at eight paid hops. A receiver can sponsor a sender at a higher
layer later; receiving traffic alone never grants permission to spend its money.

## Acceptance evidence

| Requirement | Verified evidence |
|---|---|
| Three routers paid automatically | Physical native Wi-Fi runs and five-process tests; independent controllers open/pay/settle every neighbor relationship; each relay earns a positive net amount. |
| Both traffic directions | Separate sender authorization and six one-way channels; physical endpoint streams and actual phone datagrams in both directions. |
| Public local entry before Internet purchase | Pixel joins isolated customer Wi-Fi, reaches the local mint and authenticated FIPS UDP entry, then purchases forwarding. Management and ordinary Internet probes are rejected. |
| Actual unrooted phone | Real app setup/funding/Connect/Buy/send/settlement; eight 1,000-byte datagrams each way after warm-up; stop, process reopen and reuse of the same funded account. |
| Exhaustion and renewal | Physical and software checks exhaust credit with renewal paused, then automatically replace channels and recover traffic. Gaps are observed and documented. |
| Duplicate and unsolicited traffic | Native receive-path test replays encrypted frames and injects an unauthenticated high counter; ledger/buyer tests check duplicate outcomes and unsolicited transit. Five-process customer test verifies no unpaid traffic/purchases. |
| Route changes | Physical and software paths remove the middle router and explicitly make an alternate native link available; source watches accept a cheaper path without another purchase command and retain unchanged neighbor channels. |
| Recovery | Software lost funding/acceptance replies, repeated settlement, all-process restart and middle-process kill; physical middle-router restart/kill, phone reopen, and earlier empty-account router reboot/package gates. |
| Financial bounds and conservation | Durable budgets, grace, working-capital limits and preserved history; all 12,800 historically issued test sats collected, with every participant wallet empty after each completed phase. |
| Performance and organization | Matched 8 Mbit/s trials, profiling and rejected tuning; 600-line relay/Android source ceiling, 1,000-line integration ceiling, focused modules and shared Android financial engine. |
| Portable package and recovery | Static ARM64 OpenWrt package, standard interfaces, procd/readiness checks, saved account backups, no Cudy-specific driver change. Other CPU architectures remain untested. |

The phone run funded five participants with 512 test sats each. Before collection,
balances were 435 at the phone, 561 at each of the three routers, and 442 at the
destination. Each router earned 49 test sats net. All 2,560 were collected.
Native frame captures confirmed both intended wireless links and excluded an
entry-management UDP shortcut. Existing AP/LAN/Internet and host services passed
post-test checks. The later [performance run](PERFORMANCE.md) added 1,280 test sats,
all collected, and restored the same customer configuration.

The first two large phone data attempts did not arrive. Observed counters and
captures are consistent with a small checkpoint allowance shared by setup and
data; a focused test reproduces that mechanism. This is a supported diagnosis,
not a direct measurement of the live window at the drop. A later warm-session
attempt and all eight measured sends each way arrived. Source commit `065279e9`
adds refusal counters and window-sizing guidance. Devices and the tested Android
APK remain on `7538992d` / package r6; those new diagnostics are not installed.

## Reproduce the bench

1. Follow [OpenWrt packaging](openwrt/README.md), [service setup](SERVICE.md) and
   [isolated test funding](TESTBENCH.md). Record binary/package hashes and save
   complete stopped-account backups. Initialize only genuinely new accounts.
2. Keep management networking available. Use separate customer and native mesh
   interfaces. The native mesh must be unbridged with lower-layer forwarding
   disabled; configure only the intended neighboring FIPS identities/addresses.
   Verify actual radio capabilities, interface state and stable MAC addresses.
3. Apply [customer entry](CUSTOMER-ENTRY.md): isolated DHCP, only the selected
   FIPS UDP endpoint and a bounded path to the accepted mint. Verify mint access
   before purchase and rejection of management/ordinary Internet access.
4. Start the test mint once and retain that process throughout recovery tests.
   Fund bounded amounts into the five independent accounts. Check remaining
   lifetime budgets and working capital before purchase; funding resets neither.
5. Build/install [the Android client](../fips-relay-app/README.md). Use a profile
   containing the entry identity/address, destination, mint and explicit terms.
   Join the customer Wi-Fi, import the test grant privately, Connect and Buy.
   Authorize the destination's return route separately. Verify six paid channels.
6. Capture both native links and check the exact peer graph. Warm up, send bounded
   1,000-byte payloads in both directions, and check receiver hashes/counters.
   Exercise app Stop/reopen with the same account; do not press Buy again solely
   because the process restarted. Follow [performance methodology](PERFORMANCE.md)
   for throughput/resource comparisons.
7. Exercise exhaustion, renewal and the planned recovery/path-change cases with
   saved limits intact. Inspect durable operation state after any timeout instead
   of blindly repeating financial actions. Preserve failed attempts in results.
8. Pause automatic source watches and request settlement at every participant.
   Check zero locked capital and no active purchases, stop isolated processes,
   export actual remaining balances privately, and collect them at the test mint.
   Prove conservation, empty wallets and positive net relay earnings separately.
9. Restore saved service settings, customer firewall and normal Wi-Fi. Verify
   identity/history/budgets, native isolation, Internet and existing host services.
   Remove only owned inactive temporary artifacts after verified local copies.

Current bench state: three customer router services are idle with preserved empty
accounts; endpoint processes are stopped; the phone retains its app/profile/history
and is back on its normal Wi-Fi. The test mint remains running with all funds
collected. Repeating a run needs explicit new test funding and sufficient retained
budget, not an account reset. Private addresses, keys, logs and snapshots stay in
the operator's local records rather than these repository instructions.

## Limits and follow-on work

- Delivery is best effort. Renewal/settlement causes service gaps; a forwarding
  attempt can be charged even when a later hop or destination fails to receive it.
- Allowance must cover session setup and the full opaque envelope at the agreed
  price. Application retries are new billable attempts; path MTU still applies.
- Completed packet history is compacted, but route/channel history has finite
  limits and fails closed. Safe retirement for indefinite renewals/route churn
  is unfinished. The prototype does not claim an indefinitely running hotspot.
- A changed route during unfinished renewal and expired pending offers can stop
  recovery. Combined failure stress and seamless migration are follow-on work;
  separate route-change, renewal and restart cases are the demonstrated scope.
- Encrypted wire-abuse tests use the real native software receive path, not an
  RF injection test. Empty-account reboot checks do not prove power-loss recovery
  during a wallet transaction. Broader adversarial testing remains necessary.
- Android is a foreground test client. Background operation, Wi-Fi/cellular
  handover, an Internet exit/VPN and production wallet UX are not implemented.
- Measurements are short offered-rate trials on this ARM64 hardware, not maximum
  capacity, whole-device energy, other OpenWrt hardware or complete radio airtime.
- Test-mint Lightning is simulated. No real-money transaction or public service
  has been exercised. A local TollGate service/entitlement adapter proposal is
  prepared; implementation/interoperability and upstream submission are separate.
