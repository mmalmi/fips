use super::*;
use fips_core::{Identity, NodeAddr, PeerIdentity};
use std::sync::{Arc, mpsc};
use std::time::Duration;

#[test]
fn node_callbacks_do_not_wait_for_a_checkpoint_writer() {
    let root = tempfile::tempdir().unwrap();
    let relay =
        Arc::new(DurableRelay::create(&root.path().join("relay"), Limits::default(), 10).unwrap());
    let identity = Identity::from_secret_bytes(&[1; 32]).unwrap();
    let terms = ChannelTerms {
        refund_after_unix: None,
        id: "channel".into(),
        buyer: *identity.node_addr(),
        mint_url: "http://test.invalid".into(),
        expires_unix: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 600,
        capacity_sat: 1,
        grace_msat: 100,
    };
    relay.open_channel_verified(terms.clone(), 0).unwrap();
    relay
        .add_contract(Contract {
            billing: Default::default(),
            id: "quote".into(),
            channel_id: terms.id,
            destination: NodeAddr::from_bytes([2; 16]),
            next_hop: NodeAddr::from_bytes([3; 16]),
            expires_unix: terms.expires_unix,
            price: crate::ledger::BytePrice {
                msat: 1,
                per_bytes: 1,
            },
            max_units: 100,
        })
        .unwrap();
    let gate = relay.writer.lock().unwrap();
    let worker = Arc::clone(&relay);
    let (sent, received) = mpsc::channel();
    let thread = std::thread::spawn(move || {
        let identity = Identity::from_secret_bytes(&[1; 32]).unwrap();
        let mut request = ForwardingRequest {
            ingress: PeerIdentity::from_pubkey_full(identity.pubkey_full()),
            source: NodeAddr::from_bytes([1; 16]),
            destination: NodeAddr::from_bytes([2; 16]),
            next_hop: NodeAddr::from_bytes([3; 16]),
            session_payload: b"packet",
        };
        let token = worker
            .admit(&request)
            .expect("previous durable window stays usable during the writer's work");
        worker.complete(token, ForwardingOutcome::Submitted);
        assert_eq!(worker.channel_usage("channel").unwrap().submitted_msat, 6);
        request.session_payload = b"later";
        assert_eq!(
            worker.decide(&request),
            fips_core::node::ForwardingDecision::Retry
        );
        assert_eq!(worker.channel_usage("channel").unwrap().reserved_msat, 6);
        // Both callbacks finish while the writer is held. The checkpoint
        // and manual re-admission below check recovery after its release.
        sent.send(()).unwrap();
        assert!(worker.checkpoint_if_due().unwrap());
        let token = worker
            .admit(&request)
            .expect("checkpoint restores allowance");
        worker.complete(token, ForwardingOutcome::Submitted);
        assert_eq!(worker.channel_usage("channel").unwrap().submitted_msat, 11);
    });
    let result = received.recv_timeout(Duration::from_secs(1));
    drop(gate);
    thread.join().unwrap();
    result.expect("callbacks must return while the controller owns the disk gate");
}
