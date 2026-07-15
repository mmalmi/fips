//! App-facing FIPS endpoint API.

pub use fips_core::config::{
    Config, ConnectPolicy, EthernetConfig, NostrDiscoveryConfig, NostrDiscoveryPolicy,
    NostrPeerfindingSource, NostrRelayConfig, PeerAddress, PeerAddressProvenance, PeerConfig,
    RoutingMode, TransportInstances, TransportsConfig, UdpConfig,
};
pub use fips_core::endpoint::{
    FIPS_ENDPOINT_DIRECT_PACKET_QUEUE_MAX_PACKETS, FIPS_ENDPOINT_DIRECT_PACKET_RUN_MAX_PACKETS,
    FipsEndpoint, FipsEndpointBuilder, FipsEndpointData, FipsEndpointDirectDeliveryError,
    FipsEndpointDirectPacketBatch, FipsEndpointDirectPacketRun, FipsEndpointDirectReceiver,
    FipsEndpointDirectSink, FipsEndpointError, FipsEndpointMessage, FipsEndpointPeer,
    FipsEndpointRelayStatus, FipsEndpointServiceDatagram, FipsEndpointServiceReceiver,
    UpdatePeersOutcome,
};
pub use fips_core::identity::{
    FipsAddress, Identity, IdentityError, NodeAddr, PeerIdentity, decode_npub, decode_nsec,
    decode_secret, encode_npub, encode_nsec,
};
