# Freedom guest internet

A guest joins Wi-Fi, opens the Freedom checkout and buys a time pass with Cashu or Lightning. Their phone can then use ordinary IPv4 internet. The post-payment page includes an optional Nostr VPN download. The router manager chooses how the hotspot reaches the internet in **Services → Freedom guest internet**.

| Internet source | Behavior |
| --- | --- |
| Off | Stops checkout and forwarding. The radio is managed separately under Wireless. |
| Local internet connection | Sends paid guests through the configured local uplink. |
| My paid Nostr VPN exits | Tries up to eight provisioned buyers in saved order. A guest keeps their pass when the router switches providers. |
| Nostr VPN automatic selection | Uses the dedicated automatic buyer. Its Nostr VPN daemon selects the seller under that buyer's spending and eligibility settings. |

Guest receipts and upstream purchase budgets are independent. The hotspot sells time. Its buyer pays the seller for upstream traffic. FIPS peer forwarding and its existing free or paid tariffs are managed separately in Services → Freedom.

## Provision a hotspot

1. Install the APK on a supported OpenWrt 25.12 ARM64 router with fw4 and LuCI. It starts off. Reserve a dedicated IPv4 bridge named `br-freedom`, a non-overlapping guest subnet, routing tables 19971 and 19973, rule priorities 19971–19974 and mark 0x4e13. Use an isolated Wi-Fi AP on that bridge, separate from LAN, management and mesh. Give it a dedicated firewall zone with input and forward set to REJECT and output set to ACCEPT so the router can reply to guests. Keep software/hardware flow offloading disabled for guest traffic. Use client isolation and encrypted Wi-Fi where supported. Access passes identify the associated device by IPv4 and MAC address.
2. Give the bridge a fixed IPv4 address. Provide DHCPv4 on that subnet with this address as gateway and an external IPv4 resolver in DHCP option 6. Disable guest IPv6, router advertisements and cross-zone forwarding. Publish the checkout DNS name pointing to the bridge address in a resolver guests can use after purchase. Before payment the built-in captive DNS answers with that address and HTTP opens the checkout. Payments require a certificate trusted by guest devices. Install its full chain and private key in a root-only directory. A guest with a prepared Cashu token can pay offline. A Lightning wallet needs its own connection to send payment (or the invoice can be paid from another device).
3. Configure a dedicated Nostr VPN merchant wallet on Linux with an accepted mint. Install the adjacent executable `freedom-merchant` on that host. It needs Python 3, `nvpn` on PATH, the merchant's CDK SQLite wallet and a private writable journal directory. The default database is `cashu/wallet.sqlite` alongside the Nostr VPN config. Set `FREEDOM_WALLET_DB` for a different data directory. The helper can also run directly on a router with these dependencies. The tested CLI and CDK receipt format are from Nostr VPN 4.1.19. Initialize/add the accepted mint in the wallet before use. Regularly refresh the merchant wallet to mint settled Lightning quotes.
4. Edit `/etc/config/freedom_guest`. Set `address`, `tls_name`, `tls_cert`, `tls_key`, `mint`, `nvpn_config`, `price_sat`, `minutes` and a persistent private `state` path. `wallet` points to the local helper or an operator-owned transport adapter. For a remote wallet, set `wallet` to `/usr/libexec/freedom-merchant-ssh`, set `merchant_host` to the Linux SSH account and host, and install a dedicated SSH private key at `/etc/freedom-guest/merchant.key` (mode 0600). Pin the Linux server host key in the router root user’s known_hosts. On Linux restrict its authorized_keys entry with `restrict,command="/usr/local/libexec/freedom-merchant --stdio /etc/nvpn/merchant.toml https://mint.example"`, substituting the real config and accepted mint. The remote config and mint are fixed by that command. The router sends only the top-up amount or receipt request over encrypted stdin. The router must reach the same mint as the merchant. The portal grants access after verified receipt. Both the merchant order journal and the router pass store need persistent backups.
5. For direct mode, set the `direct` profile's `device` to the Linux uplink device and `gateway` to its IPv4 next hop on broadcast networks. For paid mode, provision the buyers below. Apply an internet source in LuCI. Confirm it reports an active connection, then enable the guest SSID in Wireless. To take the hotspot down completely, switch it off and disable its SSID.

## Paid buyers

Use one dedicated Linux network namespace per buyer with Nostr VPN, the FIPS transport, WireGuard, nftables, iproute2, jq, a persistent wallet and scoped funds. Enable IPv4 forwarding inside that namespace. For a named provider, import its signed offer, fund the buyer, use `nvpn paid-exit buy` with an explicit mint and channel capacity, and activate that paid exit. For the automatic buyer, configure a bounded budget and eligible providers, then select `nvpn set --internet-source paid_automatic`. Confirm the buyer's daemon reports an active matching exit. Consult its CLI for current funding, settlement and provider controls.

Create a dedicated WireGuard pair per profile with distinct point-to-point IPv4 addresses. On the router use a peer AllowedIPs of `0.0.0.0/0` with automatic route installation **disabled**. On the Linux buyer restrict the peer's AllowedIPs to the router tunnel address (/32). Set the MTU to fit the underlying path. The Freedom router masquerades guest traffic to the chosen tunnel address.

Before accepting the router peer, run the guard under a supervisor **inside the buyer namespace**. It needs to read the same config and reach the same Nostr VPN daemon as the buyer.

```sh
buyer-gateway wg-guest /etc/nvpn/buyer.toml manual
# In the separate automatic buyer's namespace
buyer-gateway wg-guest /etc/nvpn/automatic.toml automatic
```

The guard admits traffic only on a live paid Nostr VPN TUN with a matching internet route. A liveness lease expires after 12 seconds if the supervisor stops. Reserve priorities 70–72, table 19951, WireGuard mark 0xf113 and nftables table `freedom_paid_guest` in each namespace. Bring up the guard before exposing the router peer on boot. The router performs a small HTTPS HEAD probe every ten seconds when enabled. It may consume paid bytes even with no guests. Set `probe_url` to an operator-controlled public HTTPS endpoint if desired.

Declare uplinks in the router UCI file and select them in LuCI. Use `automatic` as the section name for an automatic buyer. Other profile names must be unique and use separate devices.

```
config uplink 'first'
    option label 'First provider'
    option device 'wg-exit1'
config uplink 'second'
    option label 'Second provider'
    option device 'wg-exit2'
config uplink 'automatic'
    option label 'Automatic buyer'
    option device 'wg-exitauto'
```

For a specific priority, put ordered `list provider 'first'` and `list provider 'second'` entries in the `main` section with `option mode 'selected'`. Empty or unavailable paid profiles close access. Guest traffic cannot fall through to the direct uplink. Payment records are capped at 8,192 orders per router. A full journal stops new purchases. Retain both journals for reconciliation and replay protection.

## Build and verify

The verified target is `aarch64_cortex-a53`. From this directory, use Go 1.27.3 with the checked-in go.sum. Run Go tests on Linux, where the routing code uses SO_MARK.

```sh
go mod verify
CGO_ENABLED=0 go test -mod=readonly ./...
python3 -B test_merchant.py
GOTOOLCHAIN=local GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build \
  -mod=readonly -buildvcs=false -trimpath -ldflags='-s -w' -o /tmp/freedom-guest .
```

On a root-owned Linux staging filesystem, provide the hash of the input source manifest and run the package builder. The verified Alpine aarch64 apk-tools-static 3.0.8-r0 archive has SHA-256 `8b5da539b70bb9dfca6567d336821bb316193544fd420213784584f285e99bb1`; its extracted `sbin/apk.static` has SHA-256 `0b5895ca7d881b2cf7af67cfae9e1629f602f7242b92a038243689527b86732c`. The APK records both the manifest digest and executable digest in `/usr/share/freedom-guest/build.json`. Inspect the APK and verify its digest before private installation. Distribution via a public feed uses the release owner's signing and provenance checks.

```sh
./build-apk.sh /path/to/apk.static /tmp/freedom-guest aarch64_cortex-a53 \
  0.1.0-r1 "$SOURCE_SHA256" /tmp/freedom-guest-0.1.0-r1.apk
```
