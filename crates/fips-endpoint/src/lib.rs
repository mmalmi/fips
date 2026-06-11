//! App-facing FIPS endpoint API.

pub use fips_core::config::{
    Config, ConnectPolicy, EthernetConfig, NostrDiscoveryConfig, NostrDiscoveryPolicy, PeerAddress,
    PeerConfig, RoutingMode, TransportInstances, TransportsConfig, UdpConfig,
};
pub use fips_core::endpoint::{
    FipsEndpoint, FipsEndpointBuilder, FipsEndpointError, FipsEndpointMessage, FipsEndpointPayload,
    FipsEndpointPeer, FipsEndpointRelayStatus, UpdatePeersOutcome,
};
pub use fips_core::identity::{
    FipsAddress, Identity, IdentityError, NodeAddr, PeerIdentity, decode_npub, decode_nsec,
    decode_secret, encode_npub, encode_nsec,
};
pub use fips_core::{
    EndpointPayloadClass, EndpointPayloadLane, classify_endpoint_payload,
    endpoint_payload_is_latency_sensitive,
};
