# nvpn-fips-identity

Identity primitives from the independently evolved FIPS implementation used by
[Nostr VPN](https://github.com/mmalmi/nostr-vpn).

This crate provides Nostr-style secp256k1 identity handling, npub/nsec
encoding helpers, FIPS node addresses, and authentication challenge types used
by the FIPS mesh crates.

The package is named `nvpn-fips-identity`; its Rust library and import name
remains `fips_identity` for source compatibility.

```toml
[dependencies]
fips-identity = { package = "nvpn-fips-identity", version = "0.3.3" }
```

FIPS is under active development. APIs and wire behavior are not yet stable.

## Projects

- [Nostr VPN FIPS implementation](https://github.com/mmalmi/fips)
- [Original FIPS project](https://github.com/jmcorgan/fips), maintained by
  Johnathan Corgan
