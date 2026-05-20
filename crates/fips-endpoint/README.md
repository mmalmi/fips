# fips-endpoint

Small app-facing FIPS endpoint facade.

This crate re-exports the public endpoint, configuration, and identity types
needed by applications that embed a FIPS endpoint without depending directly on
the full `fips-core` API surface.

FIPS is under active development. APIs and wire behavior are not yet stable.

## Host-Local Ethernet Discovery

Applications running on a private host bridge or veth segment can enable scoped
Ethernet discovery through the endpoint builder:

```rust
let endpoint = fips_endpoint::FipsEndpoint::builder()
    .discovery_scope("iris-chat:host")
    .local_ethernet("fips-app0")
    .bind()
    .await?;
```

The interface must already exist and be up. The endpoint will announce scoped
Ethernet beacons, auto-connect to matching peers on that L2 segment, and still
use the normal scoped UDP/Nostr defaults when `discovery_scope` is set.

`discovery_scope` is the Nostr advert app scope. A generic daemon can advertise
`fips-overlay-v1`, while an application endpoint behind it can advertise a
separate scope such as `hashtree-v1` with its own endpoint identity.

## Repository

https://git.iris.to/#/npub1xdhnr9mrv47kkrn95k6cwecearydeh8e895990n3acntwvmgk2dsdeeycm/fips
