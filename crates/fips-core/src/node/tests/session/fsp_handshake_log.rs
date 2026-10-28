//! Exercise the private log schema through real admission and receive handlers.
use super::*;
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use tracing::{Event, Metadata, Subscriber, field::Visit, span};

const TARGET: &str = "fips_core::fsp_handshake";

#[derive(Clone, Default)]
pub(super) struct Capture(Arc<Mutex<Vec<BTreeMap<String, String>>>>);

#[derive(Default)]
struct Fields(BTreeMap<String, String>);

impl Visit for Fields {
    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
        self.0.insert(field.name().to_owned(), value.to_owned());
    }

    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        self.0.insert(field.name().to_owned(), format!("{value:?}"));
    }
}

impl Subscriber for Capture {
    fn enabled(&self, metadata: &Metadata<'_>) -> bool {
        metadata.is_event() && metadata.target() == TARGET
    }

    fn new_span(&self, _: &span::Attributes<'_>) -> span::Id {
        panic!("handshake diagnostics must not create spans")
    }

    fn record(&self, _: &span::Id, _: &span::Record<'_>) {}
    fn record_follows_from(&self, _: &span::Id, _: &span::Id) {}
    fn enter(&self, _: &span::Id) {}
    fn exit(&self, _: &span::Id) {}

    fn event(&self, event: &Event<'_>) {
        assert_eq!(event.metadata().target(), TARGET);
        let mut fields = Fields::default();
        event.record(&mut fields);
        assert_eq!(
            fields.0.keys().map(String::as_str).collect::<Vec<_>>(),
            ["category", "local", "message", "peer"]
        );
        for key in ["local", "peer"] {
            let value = &fields.0[key];
            assert_eq!(value.len(), 32, "full node IDs, never display aliases");
            assert!(value.bytes().all(|b| b.is_ascii_hexdigit()));
        }
        assert!(
            fields.0["category"]
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
        );
        self.0.lock().unwrap().push(fields.0);
    }
}

impl Capture {
    pub(super) fn categories(&self, local: &NodeAddr, peer: &NodeAddr) -> Vec<String> {
        self.0
            .lock()
            .unwrap()
            .iter()
            .filter(|fields| {
                fields["local"] == local.to_string() && fields["peer"] == peer.to_string()
            })
            .map(|fields| fields["category"].clone())
            .collect()
    }
}

#[tokio::test]
async fn fsp_log_correlates_full_ids_without_aliases_payloads_or_packet_logs() {
    let capture = Capture::default();
    let _guard = tracing::subscriber::set_default(capture.clone());
    let mut node = make_node();
    let first = NodeAddr::from_bytes([0x42; 16]);
    let mut second_bytes = [0x42; 16];
    second_bytes[15] = 0x43;
    let second = NodeAddr::from_bytes(second_bytes);
    assert_eq!(first.short_hex(), second.short_hex());
    for peer in [first, second] {
        node.peer_aliases
            .insert(peer, "private-host-alias".to_owned());
        node.handle_session_setup(&peer, &peer, b"private-packet-body")
            .await;
        assert_eq!(
            capture.categories(node.node_addr(), &peer),
            ["msg1_received", "msg1_refused_decode"]
        );
    }
    struct Private;
    impl std::fmt::Debug for Private {
        fn fmt(&self, _: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            panic!("unrelated packet fields must not be formatted");
        }
    }
    tracing::debug!(target: "fips_core::node::handlers::session", src = ?Private, "Rate limiting ICMP Packet Too Big");
    let records = capture.0.lock().unwrap();
    assert_eq!(records.len(), 4);
    let rendered = format!("{records:?}");
    assert!(!rendered.contains("private-host-alias"));
    assert!(!rendered.contains("private-packet-body"));
}

#[test]
fn fsp_log_table_refusal_keeps_exact_correlation() {
    let capture = Capture::default();
    let _guard = tracing::subscriber::set_default(capture.clone());
    let mut config = Config::new();
    config.node.limits.max_sessions = 1;
    let mut node = Node::new(config).unwrap();
    insert_initiating_session(&mut node, &Identity::generate());
    let stranger = Identity::generate();
    assert!(!node.admit_new_session(stranger.node_addr()));
    assert_eq!(
        capture.categories(node.node_addr(), stranger.node_addr()),
        ["session_refused_table_full"]
    );
    assert_eq!(node.stats().sessions.table_full, 1);
}

#[tokio::test]
async fn fsp_log_received_msg1_precedes_processing_and_pending_submission() {
    let capture = Capture::default();
    let _guard = tracing::subscriber::set_default(capture.clone());
    let mut node = make_node();
    let initiator = Identity::generate();
    let mut handshake = crate::noise::HandshakeState::new_xk_initiator(
        initiator.keypair(),
        node.identity().pubkey_full(),
    );
    let setup = SessionSetup::new(
        TreeCoordinate::root(*initiator.node_addr()),
        node.tree_state().my_coords().clone(),
    )
    .with_handshake(handshake.write_xk_message_1().unwrap())
    .encode();
    node.handle_session_setup(
        initiator.node_addr(),
        initiator.node_addr(),
        &setup[FSP_COMMON_PREFIX_SIZE..],
    )
    .await;
    assert_eq!(
        capture.categories(node.node_addr(), initiator.node_addr()),
        [
            "msg1_received",
            "msg1_processed",
            "msg2_submitting_awaiting_msg3",
            "msg2_submit_failed",
        ]
    );
    assert!(
        node.sessions
            .get(initiator.node_addr())
            .unwrap()
            .is_awaiting_msg3()
    );
    // No active peer exists: legacy display lookup uses our placeholder key.
    assert_ne!(
        node.peer_display_name(initiator.node_addr()),
        initiator.node_addr().to_string()
    );
}

#[tokio::test]
async fn fsp_log_msg2_receipt_does_not_claim_noise_validation() {
    let capture = Capture::default();
    let _guard = tracing::subscriber::set_default(capture.clone());
    let mut node = make_node();
    let responder = Identity::generate();
    let mut handshake = crate::noise::HandshakeState::new_xk_initiator(
        node.identity().keypair(),
        responder.pubkey_full(),
    );
    handshake.write_xk_message_1().unwrap();
    node.sessions.insert(
        *responder.node_addr(),
        crate::node::session::SessionEntry::new(
            *responder.node_addr(),
            responder.pubkey_full(),
            EndToEndState::Initiating(handshake),
            0,
            true,
        ),
    );
    let ack = SessionAck::new(
        TreeCoordinate::root(*responder.node_addr()),
        node.tree_state().my_coords().clone(),
    )
    .with_handshake(vec![0; crate::noise::XK_HANDSHAKE_MSG2_SIZE])
    .encode();
    node.handle_session_payload(crate::node::LocalSessionPayload::new(
        *responder.node_addr(),
        *responder.node_addr(),
        &ack,
    ))
    .await;
    assert_eq!(
        capture.categories(node.node_addr(), responder.node_addr()),
        ["msg2_received", "msg2_refused_noise"]
    );
    assert!(
        node.sessions
            .get(responder.node_addr())
            .unwrap()
            .is_initiating()
    );
}
