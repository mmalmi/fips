# FIPS Bench for Android

A test customer for the paid-relay prototype. The app embeds the same
`fips-relay` service used by the routers. `CustomerClient` owns account lifecycle,
wallet operations and the existing private service controls; JNI serializes UI
commands. Java owns Wi-Fi selection, the screen and a user-started foreground
service. There is no second payment,
voucher, forwarding or recovery implementation.

This is a local test tool, not an Internet VPN or a production wallet. It installs
as `org.fips.relaybench` alongside other apps. It requires Android 11 or later on
arm64, without root or VPN permission. It sends identifiable 1,000-byte test
datagrams; the destination's digest/counters establish delivery independently.

## Build

Install Rust's `aarch64-linux-android` target, `cargo-ndk`, Java 17, Gradle, Android
SDK platform 36 and NDK 28.2.13676358. Set `ANDROID_HOME` to the SDK directory:

```sh
crates/fips-relay-app/build-android.sh
```

The script builds the native release library before packaging the debug APK and
running Android lint. The APK is under
`android/app/build/outputs/apk/debug/app-debug.apk`. Debug signing and `run-as`
access are intentional for this isolated, test-funded bench. Do not distribute
this artifact as a production wallet. Ordinary Gradle packaging alone is not the
supported build entry point: it could reuse an old native library.

The optional Cargo feature `measurements` enables the private bounded TCP stream
diagnostic described in [MEASUREMENTS.md](../fips-relay/MEASUREMENTS.md). It is off
in the build script above. A diagnostic build must add `--features measurements`
to the native build before packaging and verify the resulting native library.

For fresh-account acceptance alongside an existing installation, build with
`crates/fips-relay-app/build-android.sh --isolated`. This uses the same code with
package `org.fips.relaybench.acceptance`, label **FIPS Bench Acceptance** and setup
scheme `fipsbench-acceptance`. Its private account storage is separate. Use that
package for installation, explicit activity intents and `run-as` transfers; the
activity class remains `org.fips.relaybench.MainActivity`. Reinstalling either
package retains its own account. Never clear its data to retry a pending payment.

If that acceptance account is already configured, use a named installation:
`crates/fips-relay-app/build-android.sh --isolated trial2`. The instance must
start with a lowercase letter and contain at most 24 lowercase letters or digits.
This builds package `org.fips.relaybench.acceptance.trial2` with setup scheme
`fipsbench-acceptance-trial2`. Use the same `phone.instance` in the physical
acceptance scenario. Each name has separate Android account storage; reusing a
name retains that account. Runs verify that all other installed bench accounts
remain unchanged, including earlier named installations.

The existing `scripts/check-rust-file-lines.sh` gate also checks Java. Paid-relay
Rust and Android source files have a 600-line limit. Integration scenarios retain
the workspace's 1,000-line limit. Android lint treats warnings as errors, with
only its ChromeOS ABI recommendation excluded for this arm64 phone prototype.

## Bench preparation

Follow [customer entry](../fips-relay/CUSTOMER-ENTRY.md) for the entry listener and
network restrictions. The customer Wi-Fi must reach the local FIPS UDP entry.
Funding also requires either a bounded free FIPS route to the isolated mint or
explicit local HTTP access to it, without buying ordinary Internet access.
Prevent access to unrelated LAN services and ordinary Internet forwarding. Keep
router management and the native wireless relay path separate from the customer
network.

The app binds its process to the Wi-Fi whose on-link route contains the configured
entry IP before opening native sockets. It excludes VPN networks and rejects an
ambiguous Wi-Fi selection. Losing that network retains the failed binding; it
does not deliberately fall back to cellular. Verify this on the actual customer
subnet and with packet captures; merely launching the app is not a network test.

For the bidirectional bench workload, the destination explicitly funds and
authorizes its **return direction** to the customer's identity. The operator adds
a bounded destination route watch after reading the customer's public identity;
a customer profile cannot authorize another endpoint's spending.
With `forwarding_data`, [bounded session establishment](../fips-relay/BOOTSTRAP.md)
can succeed without that reverse purchase. The purchase is still needed for the
bench's paid return payloads; see [customer admission and return policies](../fips-relay/CUSTOMER-ENTRY.md#admission-and-financial-boundaries).

## Immutable setup profile

Profiles contain public configuration only. The operator verifies the actual
mint is an isolated test mint; `test_only: true` is a declaration, not proof of a
mint's backing. Example shape (replace identities and addresses before use):

```json
{
  "version": 1,
  "test_only": true,
  "billing": "forwarding_data",
  "entry_npub": "<entry identity>",
  "entry_address": "192.168.77.1:39211",
  "destination_npub": "<test destination identity>",
  "mint_url": "http://192.168.77.1:30338",
  "budget_sat": 128,
  "channel_capacity_sat": 32,
  "max_rate_msat_per_kib": 8192
}
```

The entry and mint require explicit numeric local addresses; the mint uses a
root HTTP URL. Profile limits are 512 test sats lifetime spending, 8–128 sats per
channel and at most 8,192 msat/KiB. A maximum of twice the channel capacity may be
locked. Loading funds never resets spending history or those limits.

For mint access through FIPS, use `forwarding_data` billing, replace `mint_url`
in a **fresh** profile with the mint's agreed loopback URL, and add its pinned
export identity:

```json
{
  "mint_url": "http://127.0.0.1:3338",
  "mint_mesh": {
    "npub": "<mint export identity>",
    "service_port": 44745
  }
}
```

These are fields of the full profile, not a standalone setup profile. The shared
engine owns the local HTTP adapter, including during stopped-wallet import and
export. It carries HTTP over authenticated TCP/FIPS with no direct-mint fallback.
The mint and all participating wallets must use the same URL; the URL and pinned
identity cannot change on a saved account. Configure bounded free requests to
the mint and earned reply allowances at the forwarding routers as described in
[mint HTTP over FIPS](../fips-relay/TESTBENCH.md#mint-http-over-fips).
Native customer lifecycle and router tests cover this arrangement; physical
Android acceptance remains outstanding.

`billing` must match the relay network: `forwarding_data` includes bounded free
connection setup; `forwarding_attempt` uses the original per-attempt policy.
Omitting it preserves `forwarding_attempt` for existing saved profiles. Both
choices are immutable after setup; the legacy unique-envelope tariff is rejected.

For a phone that also sells forwarding, explicitly add
`"neighbor_admission": "authenticated_adjacent"`. This admits paid control from
authenticated neighboring nodes within the service's peer/session limits. The
default, `configured_only`, accepts only configured neighbors. The choice is
immutable after setup and preserves the same spending, locked-capital and price
limits; admitting a neighbor does not give it free payload forwarding. The entry
remains the phone's only configured outgoing peer; another relay can connect to
the phone's reachable UDP endpoint.

Provide the JSON through the `setup_profile` intent string extra or through
`fipsbench://setup?profile=<base64url-encoded-JSON>`. An intent only previews a
profile. Preview and setup validate the resulting service configuration before
saving the immutable profile; rejected input leaves the customer unconfigured.
**Set up test account** is an explicit UI action. Once initialized, the
profile and identity cannot be silently replaced; missing or partial state fails
closed and requires operator recovery.

## Customer flow

1. Join the isolated customer Wi-Fi and open the setup profile. Review the budget
   and price ceiling, then tap **Set up test account**.
2. The operator puts `{"token":"<test Cashu token>"}` in the app-private
   `files/funding.json`, using a private `run-as` stdin transfer. Keep tokens out
   of command arguments, shell history, shared storage and UI logs.
3. Tap **Load test funds**, then **Connect**. The operator reads the public
   identity from private status and authorizes the destination's return route.
4. Tap **Buy forwarding**, then **Send test data**. A queued result is not a
   delivery receipt. Read the destination's packet/digest counters and each
   router's accounting records. Application retries are separately billable
   forwarding attempts.
5. Tap **Settle and stop**. The destination/router accounts also require their
   normal operator settlement and collection steps.
6. Tap **Prepare fund return**. Before exporting, the app saves a positive numbered
   request ID and amount in private `files/fund-return.json`. After success, that file also holds
   the export path and operation ID; the bearer token stays in the referenced
   wallet export file. Collect it privately, redeem it with the test mint and
   verify the combined conservation report. If interrupted, **Retry fund return**
   reuses the saved ID and amount, including after restart at zero balance. A
   pending file has no export path yet. Preserve unreadable or incomplete files
   for operator recovery; do not delete them to authorize another export.

Later loaded funds can create a new return request after the previous one
completes. The app checks the current wallet balance first and replaces only the
summary; the wallet retains each original export and its recovery evidence. The
next return increments the saved number; malformed IDs and overflow refuse a new
export. This fresh-profile protocol does not convert old named return requests.
The local customer API accepts `{"type":"acknowledge_exports","through":N}` only
while stopped. A trusted collector can use it after taking durable custody of all
tokens through N or redeeming them. Saving a phone summary does **not** acknowledge
custody and the activity never automatically discards those wallet records. See
[collection and acknowledgement](../fips-relay/TESTBENCH.md#collect-and-verify).

**Connect** starts a foreground service with a persistent notification and
**Stop** action. On Android 13 or later it first requests notification permission
so that control remains visible. Leaving or recreating the screen keeps the
session running, with its existing purchases and limits. The process-wide Wi-Fi
binding stays in place; losing Wi-Fi does not switch traffic to cellular.
**Stop** ends the session without settling; **Settle and stop** closes channels
first. Neither action deletes the account.

The service does not automatically restart after process death or on boot.
Reopen the app and explicitly connect to resume through the existing recovery
path. Background operation still requires physical screen-off, radio-recovery
and battery testing; a foreground service alone is not proof of continuous
delivery while Android manages power.

Wallet imports/exports run only while the relay service is stopped. A stop timeout
retains the live task, account ownership and Wi-Fi binding; retry joins that same
task. Do not erase app data, uninstall it or start a replacement account to work
around a pending financial operation. Android process death uses the existing
relay/wallet recovery journals on the next start.

Private `files/last-action.json` and `files/last-status.json` support bench
verification. They include operation results, identity/account metadata and the
chosen Wi-Fi network/interface, but no bearer token. Do not publish these files.
Cloud backup and device transfer of account state are disabled.

## Verification

The Android activity tests exercise the real screen lifecycle and private files
with a simulated native wallet and Wi-Fi binding. They cover an interrupted return,
restart at zero balance, atomic-file backup recovery, incomplete saved requests,
later funds and a failed balance refresh after export. Service checks cover
screen recreation, the notification's Stop action, stop failure, service
destruction, replacement races and notification permission. They do not execute JNI,
contact a mint or prove physical power-loss behavior. Run with Java 17 and the
Android SDK available:

```sh
gradle -p crates/fips-relay-app/android :app:testDebugUnitTest :app:lintDebug
```

The `fips-relay` customer integration test uses a real local simulated mint, an
entry that has no static customer enrollment, and a real destination. It imports
funds, buys forwarding and delivers payloads before/after a stop and reopen.
It also kills and restarts the entry process while the customer remains running,
then verifies fresh delivery and two advances of automatic payment without
another Buy or manual payment flush. Both supported tariffs preserve the original
identity, profile, purchases and spending limits. Settlement and an idempotent
export collect all 384 issued test sats with positive entry earnings. These are
local process checks, not current Android or radio acceptance. The test also
exercises exclusive ownership and rejects unsafe profiles. Existing process tests cover the longer
three-relay path, both paid directions, longer streams and router crash recovery.

With `measurements`, the customer suite also tests a four-node line:
endpoint → phone client → onward relay → endpoint. The onward relay connects
without static enrollment in the phone profile. Unfunded payloads are denied;
after funding, both endpoints deliver and acknowledge 128 KiB, the phone earns
provider credit and pays for onward forwarding, and all 512 test sats reconcile.
This exercises the same native `CustomerClient` used by JNI, on a local host.
It does not establish actual phone background or screen-off delivery.

```sh
cargo test -p fips-relay --lib --test customer --test control_transport --test service
cargo clippy -p fips-relay --all-targets --all-features -- -D warnings
scripts/check-rust-file-lines.sh
```

Also run Android-target Clippy, build/lint the APK, and verify the actual phone UI
with screenshots. Source-side tests and a successful app launch do not establish
public Wi-Fi isolation or three-router delivery. The subsequent actual Pixel run
verified purchase, both traffic directions, app reopen and final settlement over
the intended native wireless links. Each router earned 49 test sats net and all
2,560 run funds were collected. See [the acceptance report](../fips-relay/PROTOTYPE-RESULTS.md)
for the initial dropped attempts, capture evidence, network isolation and limits.
The newer named-installation regression verifies the current APK, automatic
payments in both directions through three routers, complete test-fund collection
and preservation of both saved phone accounts. See the current scoped evidence
in [paid-relay readiness](../fips-relay/READINESS.md#scope-and-outstanding-acceptance).
