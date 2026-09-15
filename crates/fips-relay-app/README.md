# FIPS Bench for Android

A foreground customer for the paid-relay prototype. The app embeds the same
`fips-relay` service used by the routers. `CustomerClient` owns account lifecycle,
wallet operations and the existing private service controls; JNI serializes UI
commands. Java owns Wi-Fi selection and the screen. There is no second payment,
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

The existing `scripts/check-rust-file-lines.sh` gate also checks Java. Paid-relay
Rust and Android source files have a 600-line limit. Integration scenarios retain
the workspace's 1,000-line limit. Android lint treats warnings as errors, with
only its ChromeOS ABI recommendation excluded for this arm64 phone prototype.

## Bench preparation

Follow [customer entry](../fips-relay/CUSTOMER-ENTRY.md) for the entry listener and
network restrictions. The customer Wi-Fi must reach both the local FIPS UDP entry
and the isolated mint without buying ordinary Internet access. Prevent access to
unrelated LAN services and ordinary Internet forwarding. Keep router management
and the native wireless relay path separate from the customer network.

The app binds its process to the Wi-Fi whose on-link route contains the configured
entry IP before opening native sockets. It excludes VPN networks and rejects an
ambiguous Wi-Fi selection. Losing that network retains the failed binding; it
does not deliberately fall back to cellular. Verify this on the actual customer
subnet and with packet captures; merely launching the app is not a network test.

The destination must explicitly fund and authorize its **return direction** to
the customer's identity. FIPS session replies also traverse the paid path, so a
forward purchase alone does not establish an end-to-end session. This follows
sender-pays: the destination authorizes its own spending. A customer profile does
not authorize spending by another endpoint. In the bench, the operator adds a
bounded destination route watch after reading the new customer's public identity.

## Immutable setup profile

Profiles contain public configuration only. The operator verifies the actual
mint is an isolated test mint; `test_only: true` is a declaration, not proof of a
mint's backing. Example shape (replace identities and addresses before use):

```json
{
  "version": 1,
  "test_only": true,
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

Provide the JSON through the `setup_profile` intent string extra or through
`fipsbench://setup?profile=<base64url-encoded-JSON>`. An intent only previews a
profile. **Set up test account** is an explicit UI action. Once initialized, the
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
6. Tap **Prepare fund return**. The app saves an export summary in its private
   `files/fund-return.json`; the bearer token remains in the wallet export file
   referenced by that summary. Collect it privately, redeem it with the test mint
   and verify the combined conservation report.

**Stop**, leaving the foreground and ordinary app restarts preserve the account.
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

The `fips-relay` customer integration test uses a real local simulated mint, an
entry that has no static customer enrollment, and a real destination. It imports
funds, buys forwarding, delivers payloads before/after a stop and reopen, verifies
identity/history preservation, settles, repeats an export safely, and collects
all 384 issued test sats with positive entry earnings. It also exercises exclusive
ownership and rejects unsafe profiles. Existing process tests cover the longer
three-relay path, both paid directions, longer streams and router crash recovery.

```sh
cargo test -p fips-relay --lib --test customer --test control_transport --test service
cargo clippy -p fips-relay --all-targets --all-features -- -D warnings
scripts/check-rust-file-lines.sh
```

Also run Android-target Clippy, build/lint the APK, and verify the actual phone UI
with screenshots. Source-side tests and a successful app launch do not establish
the public Wi-Fi isolation or three-router Pixel demonstration; those require
the physical run and its capture/accounting evidence.
