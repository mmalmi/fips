//! App-facing FIPS endpoint API.

pub use fips_core::config::{
    Config, ConnectPolicy, EthernetConfig, NostrDiscoveryConfig, NostrDiscoveryPolicy, PeerAddress,
    PeerAddressProvenance, PeerConfig, RoutingMode, TransportInstances, TransportsConfig,
    UdpConfig,
};
pub use fips_core::endpoint::{
    FipsEndpoint, FipsEndpointBuilder, FipsEndpointData, FipsEndpointDirectDeliveryError,
    FipsEndpointDirectPacketBatch, FipsEndpointDirectPacketRun, FipsEndpointDirectSink,
    FipsEndpointError, FipsEndpointMessage, FipsEndpointPeer, FipsEndpointRelayStatus,
    UpdatePeersOutcome,
};
pub use fips_core::identity::{
    FipsAddress, Identity, IdentityError, NodeAddr, PeerIdentity, decode_npub, decode_nsec,
    decode_secret, encode_npub, encode_nsec,
};
