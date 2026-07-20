//! App-facing FIPS endpoint API.

mod recent_peers_file;

pub use recent_peers_file::{RecentPeersFileError, RecentPeersFileStore};

pub use fips_core::config::{
    Config, ConnectPolicy, EthernetConfig, NostrDiscoveryConfig, NostrDiscoveryPolicy,
    NostrPeerfindingSource, PeerAddress, PeerAddressProvenance, PeerConfig, RoutingMode,
    TransportInstances, TransportsConfig, UdpConfig, WebSocketConfig,
};
pub use fips_core::endpoint::{
    FIPS_ENDPOINT_DIRECT_PACKET_QUEUE_MAX_PACKETS, FIPS_ENDPOINT_DIRECT_PACKET_RUN_MAX_PACKETS,
    FipsEndpoint, FipsEndpointBuilder, FipsEndpointData, FipsEndpointDirectDeliveryError,
    FipsEndpointDirectPacketBatch, FipsEndpointDirectPacketRun, FipsEndpointDirectReceiver,
    FipsEndpointDirectSink, FipsEndpointError, FipsEndpointMessage, FipsEndpointPeer,
    FipsEndpointRelayStatus, FipsEndpointServiceDatagram, FipsEndpointServiceReceiver,
    RECENT_PEERS_MAX_ENDPOINTS_PER_PEER, RECENT_PEERS_MAX_PEERS, RECENT_PEERS_VERSION, RecentPeer,
    RecentPeerEndpoint, RecentPeerTransport, RecentPeers, RecentPeersError, UpdatePeersOutcome,
};
pub use fips_core::identity::{
    FipsAddress, Identity, IdentityError, NodeAddr, PeerIdentity, decode_npub, decode_nsec,
    decode_secret, encode_npub, encode_nsec,
};
