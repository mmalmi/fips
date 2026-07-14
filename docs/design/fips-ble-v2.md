# FIPS BLE Transport v2

## Status

This document defines the interoperability target for Android, Apple, and
BlueZ implementations. BLE v2 uses a distinct service identifier and does not
silently fall back to the packet-preserving BLE v1 wire format.

## Ownership

FIPS owns:

- packet framing and validation;
- FMP link authentication and FSP end-to-end sessions;
- peer discovery state, connection arbitration, routing, path MTU, and bounds;
- write completion and transport failure semantics.

Platform adapters own only operating-system BLE operations:

- permission and lifecycle integration;
- advertising and scanning;
- the GATT bootstrap service;
- L2CAP listener, connection, byte-stream read/write, and close callbacks.

Platform adapters treat peer identifiers as opaque tokens. FIPS replaces those
tokens with authenticated node addresses after the link handshake.

## GATT Bootstrap

BLE v2 advertises service UUID `9c90b792-2cc5-42c0-9f87-c9cc40648f4c`.
Characteristic UUID `9c90b793-2cc5-42c0-9f87-c9cc40648f4c` is readable and has
this eight-byte value:

| Offset | Field | Encoding |
| --- | --- | --- |
| 0 | magic | ASCII `FB` |
| 2 | version | `2` |
| 3 | capability flags | `0` until a flag is specified |
| 4 | assigned PSM | unsigned 16-bit, network byte order |
| 6 | maximum FIPS packet | unsigned 16-bit, network byte order |

The listening platform chooses the L2CAP PSM. A scanner reads the bootstrap
characteristic before asking FIPS whether to connect. PSM discovery is not a
security boundary; FMP Noise authentication is.

The initial mobile implementation uses an L2CAP channel without requiring
operating-system pairing. FMP and FSP remain the authentication and encryption
boundaries. Implementations must not present a pairing prompt as an implicit
substitute for the FIPS handshake.

## L2CAP Byte Stream

Every FIPS packet is carried in one BLE v2 frame:

| Offset | Field | Encoding |
| --- | --- | --- |
| 0 | magic | ASCII `FB` |
| 2 | version | `2` |
| 3 | flags | `0` |
| 4 | payload length | unsigned 16-bit, network byte order |
| 6 | FIPS packet | exactly `payload length` bytes |

Receivers must support fragmented headers, fragmented payloads, and multiple
frames in one stream read. Empty, oversized, malformed, unknown-version, or
unknown-flag frames close the connection. Receivers do not scan ahead for a new
magic value after a protocol violation.

The configured maximum FIPS packet is independent of an operating system's
L2CAP segment size. A platform may split writes internally, but it must preserve
byte order and report completion or failure for each FIPS-owned write command.

## Host Adapter Contract

The Rust host bridge uses bounded command and event queues. Commands cover:

- start or stop a listener and report its assigned PSM;
- start or stop advertising the bootstrap value;
- start or stop scanning;
- connect to an opaque peer token and discovered PSM;
- write bytes on a connection and report completion;
- close a connection.

Events cover listener/advertiser/scanner completion, discovered bootstrap
records, inbound and outbound connections, received byte chunks, completed or
failed writes, and disconnection. Unknown request identifiers are ignored;
unknown connection identifiers are closed. Neither may create unbounded state.

## Routing and Delivery Boundary

A FIPS node may receive a session datagram over BLE and forward it through any
eligible next-hop transport. This is live best-effort routing, not durable
store-and-forward. Applications that require verified delivery retain stable
message identifiers, durable retry, receiver deduplication, and committed
receipts above FSP.

## Required Merge Gates

No mobile adapter or application integration is merged until all applicable
gates pass on physical devices:

1. Android to Apple and Apple to Android discovery, connection, FMP handshake,
   and bidirectional FSP service datagrams.
2. Android and Apple interoperability with BlueZ BLE v2.
3. `A --BLE--> B --IP transport--> C` with an authenticated application receipt
   returned from C to A and the normal relay path disabled.
4. Simultaneous scan/advertise/connect, duplicate-link arbitration, disconnect,
   reconnect, Bluetooth toggle, and airplane-mode recovery.
5. Fragmented and coalesced stream reads, maximum packet, queue saturation,
   failed writes, and no middle-of-frame dropping.
6. Foreground, background, and resume behavior documented separately for each
   platform, with battery and data use measured for the supported gateway mode.
