# Nostr VPN WebRTC utility extension

This package reexports `webrtc-util` 0.17.1 so connection, error, cryptographic,
packet, interface, and virtual-router types retain their upstream identities.
Only `vnet::net::Net` adds an optional host-owned native network backend.

`Net::new` preserves upstream behavior. `Net::new_native` uses a `NativeNet`
implementation for interface enumeration, name resolution, socket binding, and
connected sockets. A rejected operation returns its error without using an
ordinary native socket. Packet handling continues through upstream `Conn`.

The separately named WebRTC, ICE, and TURN packages select this dependency
explicitly; the extension does not rely on unpublished workspace patches.
