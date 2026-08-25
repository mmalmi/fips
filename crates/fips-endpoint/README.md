# nvpn-fips-endpoint

Small app-facing endpoint facade from the independently evolved FIPS
implementation used by [Nostr VPN](https://github.com/mmalmi/nostr-vpn).

This crate re-exports the public endpoint, configuration, and identity types
needed by applications that embed a FIPS endpoint without depending directly on
the full `fips_core` API surface.

The package is named `nvpn-fips-endpoint`; its Rust library and import name
remains `fips_endpoint` for source compatibility.

```toml
[dependencies]
fips-endpoint = { package = "nvpn-fips-endpoint", version = "0.4.65" }
```

FIPS is under active development. APIs and wire behavior are not yet stable.

## Same-Host Composition

Applications on one host can discover and reuse each other's authenticated FSP
services without a daemon, filesystem registry, or privileged interface:

```rust
let endpoint = fips_endpoint::FipsEndpoint::builder()
    .local_rendezvous()
    .bind()
    .await?;
```

The first process exclusively binds `127.0.0.1:21211`; later processes use an
ephemeral loopback UDP socket. A minimal nonce exchange yields only the
owner's untrusted public-key hint. The ordinary Noise IK handshake then proves
that identity, applies the normal ACL, and carries bounded capability adverts
over encrypted FSP.

The fixed-port owner is only a sticky rendezvous anchor. It does not own or
suppress another application's configured Internet, VPN, Nostr, LAN, or other
transports. If it exits, one surviving process acquires the released socket
after jitter and peers authenticate again. Simultaneous processes need
distinct FIPS transport identities.

## Projects

- [Nostr VPN FIPS implementation](https://github.com/mmalmi/fips)
- [Original FIPS project](https://github.com/jmcorgan/fips), maintained by
  Johnathan Corgan
