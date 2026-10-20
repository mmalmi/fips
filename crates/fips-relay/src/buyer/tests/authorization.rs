use super::*;
use std::sync::atomic::{AtomicUsize, Ordering::Relaxed};

#[derive(Default)]
struct FailedSigner(AtomicUsize);

impl CashuSpilmanPaymentSigner for FailedSigner {
    fn sign_cashu_spilman_payment(
        &self,
        id: &str,
        balance: u64,
        _: bool,
    ) -> Result<CashuSpilmanPayment, String> {
        if balance > 0 {
            // The event must already exist when signing starts, and taking a
            // diagnostic snapshot here must not wait on its own commit lock.
            assert!(
                crate::measurements::snapshot()
                    .unwrap()
                    .authorization_commits
                    .events
                    .iter()
                    .any(|event| event.channel_id == id && event.new_sat == balance)
            );
        }
        self.0.fetch_add(1, Relaxed);
        Err("injected signer failure".into())
    }
}

fn fixture() -> (tempfile::TempDir, BuyerAuthorizer, NodeAddr, String, u64) {
    let root = tempfile::tempdir().unwrap();
    let local = NodeAddr::from_bytes([1; 16]);
    let provider = NodeAddr::from_bytes([2; 16]);
    let buyer =
        BuyerAuthorizer::create(&root.path().join("buyer"), local, 10, Limits::default()).unwrap();
    let id = format!(
        "trace-{}",
        root.path().file_name().unwrap().to_str().unwrap()
    );
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    buyer
        .accept_channel(
            provider,
            ChannelTerms {
                refund_after_unix: None,
                id: id.clone(),
                buyer: local,
                mint_url: "http://test.invalid".into(),
                expires_unix: now + 600,
                capacity_sat: 10,
                grace_msat: 1000,
            },
            3000,
        )
        .unwrap();
    (root, buyer, provider, id, now)
}

#[test]
fn successful_persistence_is_traced_before_failed_signer_but_noop_and_reproduce_are_not() {
    let (_root, buyer, provider, id, now) = fixture();
    let signer = FailedSigner::default();
    assert!(matches!(
        buyer.sign_claim(&signer, provider, &id, 0, now),
        Err(BuyerError::Signer(_))
    ));
    assert!(matches!(
        buyer.sign_claim(&signer, provider, &id, 1000, now),
        Err(BuyerError::Signer(_))
    ));
    assert_eq!(buyer.authorized_sat(&id), Some(1));
    assert!(matches!(
        buyer.sign_claim(&signer, provider, &id, 1000, now),
        Err(BuyerError::Signer(_))
    ));
    assert!(matches!(
        buyer.reproduce_payment(&signer, provider, &id, now),
        Err(BuyerError::Signer(_))
    ));
    assert_eq!(signer.0.load(Relaxed), 4);
    let sample = crate::measurements::snapshot().unwrap();
    let events: Vec<_> = sample
        .authorization_commits
        .events
        .iter()
        .filter(|e| e.channel_id == id)
        .collect();
    assert_eq!(events.len(), 1);
    assert_eq!((events[0].old_sat, events[0].new_sat), (0, 1));
    assert!(events[0].started_ns <= events[0].finished_ns);
    assert!(Some(events[0].finished_ns) <= sample.authorization_commits.measured_at_ns);
    let persisted: serde_json::Value =
        serde_json::from_slice(&std::fs::read(buyer.directory.join("buyer.json")).unwrap())
            .unwrap();
    assert_eq!(persisted["channels"][id.as_str()]["authorized_sat"], 1);
}

#[test]
fn failed_persistence_aborts_trace_and_never_calls_signer() {
    let (root, buyer, provider, id, now) = fixture();
    let signer = FailedSigner::default();
    let before = crate::measurements::snapshot()
        .unwrap()
        .authorization_commits
        .aborted;
    let journal = buyer.directory.join("buyer.json");
    std::fs::rename(&journal, root.path().join("original-buyer.json")).unwrap();
    std::fs::create_dir(&journal).unwrap();
    assert!(matches!(
        buyer.sign_claim(&signer, provider, &id, 1000, now),
        Err(BuyerError::Journal(_))
    ));
    assert_eq!(signer.0.load(Relaxed), 0);
    let sample = crate::measurements::snapshot()
        .unwrap()
        .authorization_commits;
    assert!(sample.aborted > before);
    assert!(sample.events.iter().all(|e| e.channel_id != id));
    assert!(!*buyer.writer_ready.lock().unwrap());
}
