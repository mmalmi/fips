use super::*;
use std::sync::atomic::{AtomicBool, Ordering};

#[test]
fn validates_compressed_pubkey_addresses() {
    let good = "02aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    assert!(validate_compressed_pubkey_hex(good).is_ok());
    assert!(validate_compressed_pubkey_hex(&good[2..]).is_err());
    assert!(
        validate_compressed_pubkey_hex(
            "04aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        )
        .is_err()
    );
}

#[test]
fn webrtc_signal_serializes_like_ts_transport() {
    let signal = WebRtcSignal {
        protocol: WEBRTC_PROTOCOL.to_string(),
        version: WEBRTC_SIGNAL_VERSION,
        session_id: "abc".to_string(),
        kind: WebRtcSignalKind::Offer,
        sender: "02aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string(),
        recipient: "03bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".to_string(),
        sdp: Some("v=0".to_string()),
        candidates: None,
        created_at_ms: 1,
        expires_at_ms: 2,
    };
    let json = serde_json::to_string(&signal).unwrap();
    assert!(json.contains(r#""sessionId":"abc""#));
    assert!(json.contains(r#""createdAtMs":1"#));
    assert!(json.contains(r#""expiresAtMs":2"#));
}

#[tokio::test]
async fn stalled_webrtc_send_times_out_and_starts_cleanup() {
    let cleanup_started = Arc::new(AtomicBool::new(false));
    let cleanup_flag = Arc::clone(&cleanup_started);
    let started = tokio::time::Instant::now();

    let result = bounded_webrtc_send(
        Duration::from_millis(10),
        std::future::pending::<Result<usize, std::io::Error>>(),
        move || async move {
            cleanup_flag.store(true, Ordering::SeqCst);
            std::future::pending::<()>().await;
        },
    )
    .await;

    assert!(matches!(result, Err(TransportError::Timeout)));
    assert!(cleanup_started.load(Ordering::SeqCst));
    assert!(started.elapsed() < Duration::from_millis(100));
}
