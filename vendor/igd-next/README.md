# nvpn-igd-next

This fork of igd-next 0.16.2 adds host socket policy hooks for Nostr VPN. Upstream library behavior, protocol messages and timing are retained. Unused command-line examples and the discontinued async-std/Surf backend are omitted; this fork supports synchronous and Tokio callers. With `aio_tokio`, call `aio::tokio::search_gateway_with_provider(options, provider)`. Implement `SearchProvider::prepare_socket` for the bound SSDP socket, `SearchProvider::get` for both description downloads, and `RequestProvider::send_request` for SOAP. The returned gateway retains the provider for later queries, mappings, renewals and deletion. Transport errors never select the native provider. The existing search timeout still covers discovery and both downloads.

The original static `Provider` trait and synchronous/Tokio search functions retain native behavior. The original project documentation follows.

## Internet Gateway Device client

This is a simple library that communicates with an UPNP enabled gateway device (a router). Contributions and feedback are welcome.
At the moment, you can search for the gateway, request the gateway's external address and, add/remove port mappings. See the upstream repository for examples.

Contributions are welcome! This is pretty delicate to test, please submit an issue if you have trouble using this.

* [Documentation](https://docs.rs/igd/)
* [Repository](https://github.com/sbstp/rust-igd)
* [Crates.io](https://crates.io/crates/igd)

## License
MIT
