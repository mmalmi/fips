//! App-facing FIPS endpoint API.

pub use fips_core::endpoint::{
    FipsEndpoint, FipsEndpointBuilder, FipsEndpointError, FipsEndpointMessage,
};
pub use fips_core::identity::{
    FipsAddress, Identity, IdentityError, NodeAddr, PeerIdentity, decode_npub, decode_nsec,
    decode_secret, encode_npub, encode_nsec,
};
