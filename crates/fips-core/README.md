# nvpn-fips-core

Core mesh protocol package from the independently evolved FIPS implementation
used by [Nostr VPN](https://github.com/mmalmi/nostr-vpn).

This crate contains the reusable mesh node, transport, discovery, routing,
Noise session, endpoint, control, and TUN integration code used by FIPS-based
applications.

The package is named `nvpn-fips-core`; its Rust library and import name remains
`fips_core` for source compatibility.

```toml
[dependencies]
fips-core = { package = "nvpn-fips-core", version = "0.4.65" }
```

FIPS is under active development. APIs and wire behavior are not yet stable.

## Projects

- [Nostr VPN FIPS implementation](https://github.com/mmalmi/fips)
- [Original FIPS project](https://github.com/jmcorgan/fips), maintained by
  Johnathan Corgan
