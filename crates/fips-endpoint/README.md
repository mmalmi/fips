# fips-endpoint

Small app-facing FIPS endpoint facade.

This crate re-exports the public endpoint, configuration, and identity types
needed by applications that embed a FIPS endpoint without depending directly on
the full `fips-core` API surface.

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

## Repository

https://git.iris.to/#/npub1xdhnr9mrv47kkrn95k6cwecearydeh8e895990n3acntwvmgk2dsdeeycm/fips
