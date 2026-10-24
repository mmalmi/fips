use super::*;
use crate::config::TcpConfig;
use crate::node::rate_limit::{HandshakeRateLimiter, TokenBucket};
use crate::node::wire::build_msg1;
use crate::transport::tcp::TcpTransport;
use crate::transport::{PacketBuffer, ReceivedPacket};
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use tracing::span::{Attributes, Id, Record};
use tracing::{Event, Metadata, Subscriber};

type Fields = BTreeMap<String, String>;

#[derive(Default)]
struct Capture {
    events: Vec<Fields>,
}

struct DiagnosticSubscriber {
    enabled: bool,
    capture: Arc<Mutex<Capture>>,
}

struct Visitor<'a>(&'a mut Fields);

impl tracing::field::Visit for Visitor<'_> {
    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        self.0.insert(field.name().into(), format!("{value:?}"));
    }
}

impl Subscriber for DiagnosticSubscriber {
    fn enabled(&self, metadata: &Metadata<'_>) -> bool {
        self.enabled && metadata.target() == "fips_core::msg1_diagnostic"
    }

    fn new_span(&self, _attrs: &Attributes<'_>) -> Id {
        panic!("compact Msg1 diagnostics must not create a span");
    }

    fn record(&self, _span: &Id, _values: &Record<'_>) {}
    fn record_follows_from(&self, _span: &Id, _follows: &Id) {}

    fn event(&self, event: &Event<'_>) {
        assert!(event.is_root(), "private context must not be inherited");
        let mut fields = Fields::new();
        event.record(&mut Visitor(&mut fields));
        self.capture.lock().unwrap().events.push(fields);
    }

    fn enter(&self, _span: &Id) {}
    fn exit(&self, _span: &Id) {}
}

fn refusing_node(pending_limit: usize) -> Node {
    let mut node = make_node();
    node.msg1_rate_limiter = HandshakeRateLimiter::with_params(
        TokenBucket::with_params(0, 0.0),
        TokenBucket::with_params(0, 0.0),
        pending_limit,
    );
    let (tx, _rx) = packet_channel(8);
    let transport = TcpTransport::new(TransportId::new(1), None, TcpConfig::default(), tx);
    node.transports
        .insert(TransportId::new(1), TransportHandle::Tcp(transport));
    node
}

fn packet(index: u32) -> ReceivedPacket {
    ReceivedPacket::with_timestamp(
        TransportId::new(1),
        TransportAddr::from_string("private-customer-address"),
        PacketBuffer::new(build_msg1(SessionIndex::new(index), &[0xa5; 106])),
        Node::now_ms(),
    )
}

async fn observe(node: &mut Node, packet: ReceivedPacket, enabled: bool) -> Arc<Mutex<Capture>> {
    let capture = Arc::new(Mutex::new(Capture::default()));
    let subscriber = DiagnosticSubscriber {
        enabled,
        capture: Arc::clone(&capture),
    };
    let _guard = tracing::subscriber::set_default(subscriber);
    node.handle_msg1(packet).await;
    assert_eq!(node.peer_count(), 0);
    assert_eq!(node.connection_count(), 0);
    assert_eq!(node.msg1_rate_limiter.pending_count(), 0);
    capture
}

#[tokio::test]
async fn diagnostic_distinguishes_rate_and_pending_refusals_without_private_fields() {
    for (limit, reason) in [(1, "rate_limit"), (0, "pending_limit")] {
        let mut node = refusing_node(limit);
        let capture = observe(&mut node, packet(0x01020304), true).await;
        let capture = capture.lock().unwrap();
        assert_eq!(capture.events.len(), 1);
        assert_eq!(capture.events[0]["reason"], reason);
        assert_eq!(capture.events[0]["class"], "Stranger");
        assert_eq!(capture.events[0]["carrier"], "close_requested");
        for event in &capture.events {
            assert_eq!(event["sender_index"], "16909060");
            assert!(event.keys().all(|key| matches!(
                key.as_str(),
                "sender_index" | "message" | "carrier" | "reason" | "class"
            )));
        }
        let serialized = serde_json::to_string(&capture.events).unwrap();
        assert!(!serialized.contains("private-customer-address"));
        assert!(
            serialized.len() <= 200,
            "compact fixture record budget: {serialized}"
        );
        println!(
            "{reason}: records=1 fields_json_bytes={} {serialized}",
            serialized.len()
        );
    }
}

#[tokio::test]
async fn diagnostic_disabled_preserves_refusal_without_records() {
    let mut node = refusing_node(1);
    let capture = observe(&mut node, packet(42), false).await;
    let capture = capture.lock().unwrap();
    assert!(capture.events.is_empty());
}

#[tokio::test]
async fn diagnostic_previous_carrier_is_one_record_without_a_close_request() {
    let mut node = refusing_node(1);
    let packet = packet(42);
    node.transport_rebind_packet_cutoffs_ms
        .insert(packet.transport_id, packet.timestamp_ms);
    let capture = observe(&mut node, packet, true).await;
    let capture = capture.lock().unwrap();
    assert_eq!(capture.events.len(), 1);
    assert_eq!(capture.events[0]["reason"], "previous_carrier_incarnation");
    assert_eq!(capture.events[0]["class"], "unchecked");
    assert_eq!(capture.events[0]["carrier"], "unchecked");
}

#[tokio::test]
async fn diagnostic_noise_failure_collapses_admission_milestones_into_one_record() {
    let mut node = refusing_node(1);
    node.transports.clear();
    node.msg1_rate_limiter = HandshakeRateLimiter::with_params(
        TokenBucket::with_params(1, 0.0),
        TokenBucket::with_params(1, 0.0),
        1,
    );
    let capture = observe(&mut node, packet(42), true).await;
    let capture = capture.lock().unwrap();
    assert_eq!(capture.events.len(), 1);
    assert_eq!(capture.events[0]["reason"], "noise_init_failed");
    assert_eq!(capture.events[0]["carrier"], "transport_missing");
}

#[tokio::test]
async fn diagnostic_does_not_treat_malformed_header_as_a_wire_index() {
    let mut node = refusing_node(1);
    let mut packet = packet(u32::MAX);
    packet.data = PacketBuffer::new(vec![0xa5; 7]);
    let capture = observe(&mut node, packet, true).await;
    let capture = capture.lock().unwrap();
    assert_eq!(capture.events[0]["sender_index"], u64::MAX.to_string());
    // Observing the header must not move validation ahead of the limiter.
    assert_eq!(capture.events[0]["reason"], "rate_limit");
}

#[tokio::test]
async fn diagnostic_preserves_owned_carrier_on_refusal() {
    let mut node = refusing_node(1);
    let packet = packet(u32::MAX);
    let link = node.allocate_link_id();
    node.links.insert(
        link,
        Link::connectionless(
            link,
            packet.transport_id,
            packet.remote_addr.clone(),
            LinkDirection::Inbound,
            Duration::from_millis(1),
        ),
    );
    let capture = observe(&mut node, packet, true).await;
    let capture = capture.lock().unwrap();
    assert_eq!(capture.events[0]["class"], "EstablishedLink");
    assert_eq!(capture.events[0]["carrier"], "retained");
    assert_eq!(capture.events[0]["sender_index"], u32::MAX.to_string());
    assert_eq!(
        node.links.get_addr(&(
            TransportId::new(1),
            TransportAddr::from_string("private-customer-address")
        )),
        Some(&link)
    );
}
