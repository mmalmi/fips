use super::*;
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tracing::span::{Attributes, Id, Record};
use tracing::{Event, Metadata, Subscriber};

pub(crate) type Fields = BTreeMap<String, String>;
pub(crate) type Capture = Arc<Mutex<Vec<Fields>>>;

struct CaptureSubscriber {
    enabled: bool,
    events: Capture,
}

struct Visitor<'a>(&'a mut Fields);

impl tracing::field::Visit for Visitor<'_> {
    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        self.0.insert(field.name().into(), format!("{value:?}"));
    }
}

impl Subscriber for CaptureSubscriber {
    fn enabled(&self, metadata: &Metadata<'_>) -> bool {
        self.enabled && metadata.target() == "fips_core::msg1_ingress"
    }
    fn new_span(&self, _attrs: &Attributes<'_>) -> Id {
        panic!("ingress diagnostics must not create spans");
    }
    fn record(&self, _span: &Id, _values: &Record<'_>) {}
    fn record_follows_from(&self, _span: &Id, _follows: &Id) {}
    fn event(&self, event: &Event<'_>) {
        assert!(
            event.is_root(),
            "diagnostics must exclude inherited context"
        );
        let mut fields = Fields::new();
        event.record(&mut Visitor(&mut fields));
        self.events.lock().unwrap().push(fields);
    }
    fn enter(&self, _span: &Id) {}
    fn exit(&self, _span: &Id) {}
}

pub(crate) fn capture(enabled: bool) -> (Capture, tracing::subscriber::DefaultGuard) {
    let events = Arc::new(Mutex::new(Vec::new()));
    let guard = tracing::subscriber::set_default(CaptureSubscriber {
        enabled,
        events: Arc::clone(&events),
    });
    (events, guard)
}

// The two hook tests run separately with --exact --ignored. Production never
// accepts a caller-provided anchor and cannot reset its process-wide window.
pub(crate) fn install_isolated_test_window() {
    assert!(
        WINDOW
            .set(Window::new(Instant::now() - Duration::from_secs(45)))
            .is_ok(),
        "run this hook test alone in a fresh process"
    );
}

pub(crate) fn msg1(index: u32) -> Vec<u8> {
    crate::node::wire::build_msg1(
        crate::utils::index::SessionIndex::new(index),
        &[0xa5; crate::noise::HANDSHAKE_MSG1_SIZE],
    )
}

fn stages(events: &[Fields]) -> Vec<&str> {
    events.iter().map(|event| event["stage"].as_str()).collect()
}

#[test]
fn ingress_window_has_exact_bounds_and_one_observed_marker_per_boundary() {
    let (events, _guard) = capture(true);
    let start = Instant::now();
    let window = Window::new(start);
    Window::boundary("armed", 0);
    for ms in [0, 29_999, 30_000, 30_001, 74_999, 75_000, 75_001] {
        window.record(Stage::Read, 7, start + Duration::from_millis(ms), None);
    }
    let events = events.lock().unwrap();
    assert_eq!(
        stages(&events),
        ["armed", "open", "read", "read", "read", "closed"]
    );
    let elapsed: Vec<_> = events
        .iter()
        .map(|event| event["elapsed_ms"].as_str())
        .collect();
    assert_eq!(elapsed, ["0", "30000", "30000", "30001", "74999", "75000"]);
    assert_eq!(events[0]["open_ms"], "30000");
    assert_eq!(events[0]["close_ms"], "75000");
}

#[test]
fn ingress_window_keeps_cross_boundary_admission_and_reports_no_false_open() {
    let (events, _guard) = capture(true);
    let start = Instant::now();
    let window = Window::new(start);
    window.record(Stage::Read, 11, start + Duration::from_millis(29_000), None);
    window.record(
        Stage::Admitted,
        11,
        start + Duration::from_secs(35),
        Some(6_000_000),
    );
    window.record(
        Stage::HandlerEntry,
        11,
        start + Duration::from_secs(36),
        None,
    );
    window.record(
        Stage::Admitted,
        12,
        start + Duration::from_secs(75),
        Some(8_000_000),
    );
    let captured = events.lock().unwrap();
    assert_eq!(
        stages(&captured),
        ["open", "admitted", "handler_entry", "closed"]
    );
    assert_eq!(captured[1]["queue_wait_us"], "6000000");
    drop(captured);
    events.lock().unwrap().clear();
    let quiet = Window::new(start);
    quiet.record(Stage::Read, 1, start + Duration::from_secs(80), None);
    quiet.record(Stage::Read, 2, start + Duration::from_secs(81), None);
    assert_eq!(stages(&events.lock().unwrap()), ["closed"]);
}

#[test]
fn ingress_records_are_root_only_with_bounded_static_fields() {
    let (events, _guard) = capture(true);
    let start = Instant::now();
    let window = Window::new(start);
    for stage in [Stage::Read, Stage::Admitted, Stage::HandlerEntry] {
        window.record(
            stage,
            u32::MAX,
            start + Duration::from_millis(74_999),
            matches!(stage, Stage::Admitted).then_some(u64::MAX),
        );
    }
    for event in events.lock().unwrap().iter() {
        assert!(event.keys().all(|key| matches!(
            key.as_str(),
            "message"
                | "stage"
                | "sender_index"
                | "elapsed_ms"
                | "queue_wait_us"
                | "open_ms"
                | "close_ms"
        )));
        let serialized = serde_json::to_string(event).unwrap();
        assert!(serialized.len() <= 180, "{serialized}");
    }
    let wire = msg1(0x5a76918b);
    assert_eq!(
        Msg1Header::parse(&wire).unwrap().sender_idx.as_u32(),
        1517719947
    );
}

#[test]
fn ingress_disabled_and_malformed_frames_emit_nothing() {
    {
        let (events, _guard) = capture(false);
        assert!(websocket_read(&msg1(42)).is_none());
        assert!(events.lock().unwrap().is_empty());
    }
    let (events, _guard) = capture(true);
    for invalid in [vec![], vec![1; 9], vec![1; 41], vec![0xa5; 114]] {
        assert!(websocket_read(&invalid).is_none());
    }
    let mut invalid = msg1(42);
    invalid[1] = 1;
    assert!(websocket_read(&invalid).is_none());
    assert!(events.lock().unwrap().is_empty());
}
