mod failure_state;
mod runtime;
mod signal;
mod stun;
mod traversal;
mod types;

#[cfg(test)]
mod tests;

pub use runtime::NostrDiscovery;
#[cfg(feature = "webrtc-transport")]
pub(crate) use signal::{build_signal_event, unwrap_signal_event};
pub(crate) use types::signal_relay_union;
pub use types::{
    ADVERT_IDENTIFIER, ADVERT_KIND, ADVERT_VERSION, BootstrapError, BootstrapEvent,
    CachedOverlayAdvert, MeshTraversalSignal, NostrAdvertIngestOutcome, NostrFailureDecision,
    NostrPeerFailureView, NostrRefetchOutcome, NostrRelayStatus, OverlayAdvert,
    OverlayEndpointAdvert, OverlayTransportKind, PROTOCOL_VERSION, PUNCH_ACK_MAGIC, PUNCH_MAGIC,
    PunchHint, PunchPacket, PunchPacketKind, SIGNAL_KIND, TraversalAddress, TraversalAnswer,
    TraversalOffer,
};
