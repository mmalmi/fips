//! End-to-end session message handlers.
//!
//! Handles locally-delivered session payloads from SessionDatagram envelopes.
//! Dispatches based on FSP common prefix phase to specific handlers for
//! SessionSetup (Noise XK msg1), SessionAck (msg2), SessionMsg3 (msg3),
//! encrypted data, and error signals (CoordsRequired, PathBroken).

include!("session/prelude_dispatch.rs");
include!("session/send_plan_core.rs");
include!("session/pipelined_send.rs");
include!("session/receive_registry.rs");
include!("session/node_receive.rs");
include!("session/node_handshake.rs");
include!("session/node_reports_errors.rs");
include!("session/node_send.rs");
include!("session/node_endpoint.rs");
include!("session/node_datagram_tun.rs");

include!("session/post_node.rs");

#[cfg(test)]
mod tests {
    include!("session/tests/registry.rs");
    include!("session/tests/receive_dispatch.rs");
    include!("session/tests/pipelined_core.rs");
    include!("session/tests/peer_runtime.rs");
    include!("session/tests/runtime_send.rs");
    include!("session/tests/rekey_recovery.rs");
}
