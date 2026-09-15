use super::*;
use std::{sync::mpsc, time::Duration};

#[test]
fn packet_evidence_does_not_wait_for_the_disk_or_signer_worker() {
    let root = tempfile::tempdir().unwrap();
    let local = NodeAddr::from_bytes([1; 16]);
    let provider = NodeAddr::from_bytes([2; 16]);
    let destination = NodeAddr::from_bytes([3; 16]);
    let buyer = Arc::new(
        BuyerAuthorizer::create(&root.path().join("buyer"), local, 10, Limits::default()).unwrap(),
    );
    let expires_unix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
        + 600;
    buyer
        .accept_channel(
            provider,
            ChannelTerms {
                id: "channel".into(),
                buyer: local,
                mint_url: "http://test.invalid".into(),
                expires_unix,
                capacity_sat: 10,
                grace_msat: 100,
            },
            0,
        )
        .unwrap();
    buyer
        .accept_quote(Contract {
            billing: Default::default(),
            id: "quote".into(),
            channel_id: "channel".into(),
            destination,
            next_hop: destination,
            expires_unix,
            price: crate::ledger::BytePrice {
                msat: 1,
                per_bytes: 1,
            },
            max_units: 100,
        })
        .unwrap();
    let guard = buyer.writer_ready.lock().unwrap();
    let worker = buyer.clone();
    let (sent, received) = mpsc::channel();
    let thread = std::thread::spawn(move || {
        let token = worker
            .observe(&OriginatedSessionRequest {
                source: local,
                destination,
                next_hop: provider,
                session_payload: b"packet",
            })
            .unwrap();
        worker.complete(token, ForwardingOutcome::Submitted);
        sent.send(worker.evidence_msat("channel")).unwrap();
    });
    assert_eq!(
        received.recv_timeout(Duration::from_secs(1)).unwrap(),
        Some(6)
    );
    drop(guard);
    thread.join().unwrap();
}
