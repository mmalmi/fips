//! WebRTC utility types with a host-owned native socket backend.
//!
//! Connection, error, packet, and cryptographic types retain their upstream
//! identities so the rest of the WebRTC stack uses the original crates.
pub use upstream::*;

#[cfg(feature = "vnet")]
pub mod vnet {
    pub use upstream::vnet::*;
    pub mod net;
}
