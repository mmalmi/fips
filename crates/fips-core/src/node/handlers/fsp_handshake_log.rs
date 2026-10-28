// Opt-in, handshake-only diagnostics. These identifiers are for bounded private
// correlation; exported evidence must replace them with ordinals/match booleans.
// NodeAddr Display gives the complete 128-bit node ID, never a key, display alias,
// or inner IP address. Received source IDs remain claims until Noise authenticates
// them. Categories and messages are a fixed catalog; no error/payload formatting.
macro_rules! fsp_handshake_event {
    ($level:ident, $node:expr, $peer:expr, $category:ident) => {
        tracing::$level!(
            target: "fips_core::fsp_handshake",
            local = %$node.node_addr(),
            peer = %{ let peer: &crate::NodeAddr = $peer; peer },
            category = stringify!($category),
            "{}", fsp_handshake_event!(@message $category)
        );
    };
    (@message handshake_resubmit_failed) => { "Session handshake resend failed" };
    (@message handshake_resubmitted) => { "Resent session handshake" };
    (@message handshake_resubmitting) => { "Resubmitting session handshake" };
    (@message handshake_timed_out) => { "Session handshake timed out, removing" };
    (@message initiator_established) => { "Session established (initiator, XK)" };
    (@message msg1_becoming_responder) => { "Simultaneous session initiation: we lose, becoming responder" };
    (@message msg1_deferred_epoch_drain) => { "Deferring FSP rekey msg1 until previous key epoch drain completes" };
    (@message msg1_duplicate_missing_ack) => { "Duplicate SessionSetup, no stored ack to resend" };
    (@message msg1_existing_established) => { "SessionSetup for an established session" };
    (@message msg1_processed) => { "Processed initial Noise XK msg1" };
    (@message msg1_received) => { "Received SessionSetup" };
    (@message msg1_refused_decode) => { "Malformed SessionSetup" };
    (@message msg1_refused_length) => { "Invalid handshake payload size in SessionSetup" };
    (@message msg1_refused_noise) => { "Failed to process Noise XK msg1 in SessionSetup" };
    (@message msg1_refused_rate_limit) => { "SessionSetup rate limited" };
    (@message msg1_refused_route) => { "SessionSetup route unavailable" };
    (@message msg1_refused_settling) => { "Late simultaneous SessionSetup while initial handshake is settling" };
    (@message msg1_refused_simultaneous) => { "Simultaneous session initiation: we win (smaller addr), dropping their setup" };
    (@message msg1_submit_failed) => { "Failed to submit SessionSetup" };
    (@message msg1_submitted) => { "Session initiation started" };
    (@message msg1_submitting_initiating) => { "Submitting SessionSetup with initiator state retained" };
    (@message msg2_duplicate_submit_failed) => { "Failed to resend SessionAck" };
    (@message msg2_duplicate_submitted) => { "Resent duplicate SessionAck" };
    (@message msg2_duplicate_submitting) => { "Duplicate SessionSetup, resending SessionAck" };
    (@message msg2_generation_failed) => { "Failed to generate Noise XK msg2 for SessionAck" };
    (@message msg2_ignored_established) => { "SessionAck for already-established session" };
    (@message msg2_received) => { "Received SessionAck" };
    (@message msg2_refused_decode) => { "Malformed SessionAck" };
    (@message msg2_refused_length) => { "Invalid handshake payload size in SessionAck" };
    (@message msg2_refused_noise) => { "Failed to process Noise XK msg2 in SessionAck" };
    (@message msg2_refused_state) => { "SessionAck but session not in Initiating state" };
    (@message msg2_refused_unknown_session) => { "SessionAck for unknown session" };
    (@message msg2_submit_failed) => { "Failed to send SessionAck" };
    (@message msg2_submitted_awaiting_msg3) => { "SessionSetup processed (XK), SessionAck sent, awaiting msg3" };
    (@message msg2_submitting_awaiting_msg3) => { "Submitting SessionAck with responder state retained" };
    (@message msg2_validated) => { "Authenticated initial Noise XK msg2" };
    (@message msg3_duplicate_submit_failed) => { "Failed to resend final SessionMsg3 after duplicate SessionAck" };
    (@message msg3_duplicate_submitted) => { "Duplicate SessionAck after establishment, resent final SessionMsg3" };
    (@message msg3_duplicate_submitting) => { "Resubmitting final SessionMsg3 after duplicate SessionAck" };
    (@message msg3_generation_failed) => { "Failed to generate Noise XK msg3" };
    (@message msg3_identity_registration_failed) => { "Failed to register authenticated SessionMsg3 identity" };
    (@message msg3_received) => { "Received SessionMsg3" };
    (@message msg3_refused_decode) => { "Malformed SessionMsg3" };
    (@message msg3_refused_identity) => { "Rejected SessionMsg3 whose authenticated static key does not match the claimed source" };
    (@message msg3_refused_length) => { "Invalid handshake payload size in SessionMsg3" };
    (@message msg3_refused_missing_identity) => { "No remote static key after processing XK msg3" };
    (@message msg3_refused_noise) => { "Failed to process Noise XK msg3" };
    (@message msg3_refused_state) => { "SessionMsg3 but session not in AwaitingMsg3 state" };
    (@message msg3_refused_unknown_session) => { "SessionMsg3 for unknown session" };
    (@message msg3_responder_session_failed) => { "Failed to create session from XK handshake" };
    (@message msg3_session_failed) => { "Failed to create session after XK msg3" };
    (@message msg3_submit_failed) => { "Failed to send SessionMsg3" };
    (@message msg3_submitted) => { "Submitted SessionMsg3" };
    (@message msg3_submitting_established) => { "Submitting SessionMsg3 with initiator state retained" };
    (@message responder_established) => { "Session established (responder, XK)" };
    (@message session_refused_half_open) => { "Half-open session share exhausted, refusing new session" };
    (@message session_refused_table_full) => { "Session table full, refusing new session" };
}
