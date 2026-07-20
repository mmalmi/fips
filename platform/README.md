# FIPS BLE platform adapters

These packages execute the operating-system half of the
[`host-ble-transport`](../docs/design/fips-ble-v2.md) command/event contract.
They do not implement FIPS routing, framing, authentication, or sessions.

## Android

`platform/android/fips-ble` is an Android library with `minSdk 26`. BLE v2
L2CAP CoC listen and connect operations require API 29 or newer; on older
versions they fail explicitly instead of selecting another wire protocol.

The consuming app must request the Bluetooth runtime permissions appropriate
for its Android version. The library manifest declares scan, connect,
advertise, and pre-Android-12 compatibility permissions, but it does not show
permission UI.

Build and test from `platform/android`:

```sh
gradle :fips-ble:testDebugUnitTest :fips-ble:lintDebug
```

## Apple

`platform/apple` is a Swift Package supporting iOS 13 and macOS 10.15 or
newer. The consuming app must provide the Bluetooth usage description. Apps
that intentionally support background gateway behavior must also select and
test the corresponding Core Bluetooth background modes; the package does not
silently alter application lifecycle policy.

Build and test:

```sh
cd platform/apple
swift test
xcodebuild -scheme FipsBle -destination 'generic/platform=iOS' build \
  CODE_SIGNING_ALLOWED=NO
```

## Integration

Create one platform adapter per Rust `HostBleIo` attachment. Pump Rust commands
into `FipsBleAdapter.submit`, and map adapter events back into `HostBleEvent`.
The mapper belongs in the embedding app or its generated binding layer; BLE
behavior and protocol constants remain in these FIPS-owned packages.
