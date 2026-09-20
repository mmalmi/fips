use super::*;
use crate::ledger::{BillingBasis, BytePrice, Contract};
use fips_core::Identity;
use serde_json::json;

struct Fixture {
    incoming: mpsc::Sender<IncomingRequest>,
    controller: mpsc::Receiver<IncomingRequest>,
    gate: AcceptBarrier,
    buyer: PeerIdentity,
    destination: PeerIdentity,
    provider: NodeAddr,
}

impl Fixture {
    fn new(timeout: Duration) -> Self {
        let peer = |seed| {
            PeerIdentity::from_pubkey_full(
                Identity::from_secret_bytes(&[seed; 32])
                    .unwrap()
                    .pubkey_full(),
            )
        };
        let (incoming, receive) = mpsc::channel(QUEUE);
        let provider = *peer(41).node_addr();
        let (controller, gate) = AcceptBarrier::start(receive, provider, timeout);
        // A full peer key may have odd parity while npub decoding uses even parity.
        let buyer = (42..=255)
            .map(peer)
            .find(|peer| *peer != PeerIdentity::from_npub(&peer.npub()).unwrap())
            .expect("fixture includes an odd-parity identity");
        Self {
            incoming,
            controller,
            gate,
            buyer,
            destination: peer(43),
            provider,
        }
    }

    fn arm(&self, hold_ms: u64) {
        self.gate
            .arm(
                &self.buyer.npub(),
                &self.destination.npub(),
                32_768,
                hold_ms,
            )
            .unwrap();
    }

    fn purchase(&self) -> Purchase {
        let channel = ChannelTerms {
            id: "original-channel".into(),
            buyer: *self.buyer.node_addr(),
            mint_url: "http://127.0.0.1:1234".into(),
            expires_unix: 123_456,
            capacity_sat: 32,
            grace_msat: 8_000,
        };
        Purchase {
            provider: self.provider,
            contract: Contract {
                id: "full-contract".into(),
                channel_id: channel.id.clone(),
                destination: *self.destination.node_addr(),
                next_hop: *self.destination.node_addr(),
                expires_unix: 123_000,
                price: BytePrice {
                    msat: 128,
                    per_bytes: 1024,
                },
                max_units: 131_072,
                billing: BillingBasis::ForwardingData,
            },
            channel,
        }
    }

    fn accept(&self, offer: &str) -> Vec<u8> {
        serde_json::to_vec(
            &json!({"type":"accept", "offer_id":offer, "channel":self.purchase().channel,
            "payment":{"channel_id":"original-channel","balance":0,"signature":"fixture",
                       "params":null,"funding_proofs":null}}),
        )
        .unwrap()
    }

    async fn submit(
        &mut self,
        peer: PeerIdentity,
        body: Vec<u8>,
    ) -> (IncomingRequest, oneshot::Receiver<Vec<u8>>) {
        let (respond, receive) = oneshot::channel();
        self.incoming
            .send(IncomingRequest {
                peer,
                body,
                respond,
            })
            .await
            .unwrap();
        let request = tokio::time::timeout(Duration::from_secs(1), self.controller.recv())
            .await
            .unwrap()
            .unwrap();
        (request, receive)
    }

    async fn request(&mut self) -> (IncomingRequest, oneshot::Receiver<Vec<u8>>) {
        self.submit(self.buyer, self.accept("full-offer")).await
    }
}

fn bytes(purchase: Purchase) -> Vec<u8> {
    // Noncanonical whitespace detects accidental reserialization by the gate.
    let mut response = serde_json::to_vec_pretty(&ControllerResponse::Accepted {
        purchase: Box::new(purchase),
    })
    .unwrap();
    response.push(b'\n');
    response
}

async fn observed(gate: &AcceptBarrier, ready: impl Fn(&Snapshot) -> bool) -> Snapshot {
    tokio::time::timeout(Duration::from_secs(1), async {
        loop {
            let status = gate.status().unwrap();
            if ready(&status) {
                return status;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap()
}

async fn reply(receive: oneshot::Receiver<Vec<u8>>) -> Vec<u8> {
    tokio::time::timeout(Duration::from_secs(1), receive)
        .await
        .unwrap()
        .unwrap()
}

#[tokio::test]
async fn holds_only_the_committed_response_and_preserves_exact_bytes() {
    let mut f = Fixture::new(Duration::from_secs(1));
    f.arm(1_000);
    let request_body = f.accept("full-offer");
    let (handled, mut receive) = f.request().await;
    assert_eq!(handled.body, request_body);
    let status = f.gate.status().unwrap();
    assert_eq!(status.candidate_requests, 1);
    assert!(
        status.captured.is_none(),
        "matching request is not provider commitment"
    );
    let original = bytes(f.purchase());
    handled.respond.send(original.clone()).unwrap();
    let status = observed(&f.gate, |s| s.held_responses == 1).await;
    assert_eq!(status.captured.unwrap().purchase, f.purchase());
    assert!(matches!(
        receive.try_recv(),
        Err(oneshot::error::TryRecvError::Empty)
    ));

    // A held acceptance never waits inside the controller's request handler.
    let body = serde_json::to_vec(&ControllerRequest::Seal {
        channel_id: "other".into(),
    })
    .unwrap();
    let (other, received) = f.submit(f.buyer, body.clone()).await;
    assert_eq!(other.body, body);
    other
        .respond
        .send(b"unchanged unrelated response".to_vec())
        .unwrap();
    assert_eq!(reply(received).await, b"unchanged unrelated response");
    assert!(
        f.gate
            .arm(&f.buyer.npub(), &f.destination.npub(), 32_768, 1_000)
            .is_err()
    );
    let released = f.gate.release().unwrap();
    assert_eq!(released.terminal_reason, Some("released"));
    assert_eq!(released.forwarded_replies, 1);
    assert_eq!(reply(receive).await, original);
    assert!(f.gate.status().unwrap().captured.is_some());
    assert!(
        f.gate
            .arm(&f.buyer.npub(), &f.destination.npub(), 32_768, 1_000)
            .is_err()
    );
    f.gate.shutdown().await;
}

#[tokio::test]
async fn trial_failed_malformed_and_mismatched_responses_pass_unchanged() {
    let mut f = Fixture::new(Duration::from_secs(1));
    f.arm(10_000);
    let mut responses = vec![
        b"malformed".to_vec(),
        serde_json::to_vec(&ControllerResponse::Rejected).unwrap(),
        serde_json::to_vec(&ControllerResponse::Pending).unwrap(),
    ];
    for change in 0..6 {
        let mut purchase = f.purchase();
        match change {
            0 => purchase.contract.max_units = 32_768,
            1 => purchase.contract.destination = NodeAddr::from_bytes([9; 16]),
            2 => purchase.provider = NodeAddr::from_bytes([9; 16]),
            3 => purchase.channel.id = "wrong-channel".into(),
            4 => purchase.contract.channel_id = "wrong-channel".into(),
            _ => purchase.channel.buyer = NodeAddr::from_bytes([9; 16]),
        }
        responses.push(bytes(purchase));
    }
    for original in responses {
        let (handled, receive) = f.request().await;
        handled.respond.send(original.clone()).unwrap();
        assert_eq!(reply(receive).await, original);
        let status = f.gate.status().unwrap();
        assert!(status.active && status.captured.is_none());
        assert_eq!(status.held_responses, 0);
    }
    let (handled, receive) = f.submit(f.destination, f.accept("full-offer")).await;
    let original = bytes(f.purchase());
    handled.respond.send(original.clone()).unwrap();
    assert_eq!(reply(receive).await, original);
    assert!(f.gate.status().unwrap().captured.is_none());
    f.gate.shutdown().await;
}

#[tokio::test]
async fn combined_waiter_and_held_cap_fails_open_without_forging_a_reply() {
    let mut f = Fixture::new(Duration::from_secs(1));
    f.arm(10_000);
    let original = bytes(f.purchase());
    let mut pending = Vec::new();
    let mut clients = Vec::new();
    for index in 0..CAPACITY {
        let (handled, receive) = f.request().await;
        clients.push(receive);
        if index < CAPACITY / 2 {
            handled.respond.send(original.clone()).unwrap();
            observed(&f.gate, |s| s.held_responses == index + 1).await;
        } else {
            pending.push(handled.respond);
        }
    }
    let (ninth, receive) = f.request().await;
    let status = f.gate.status().unwrap();
    assert_eq!(status.terminal_reason, Some("capacity_exceeded"));
    assert_eq!(status.capacity_bypassed, 1);
    assert_eq!(status.held_responses, 0);
    ninth.respond.send(original.clone()).unwrap();
    assert_eq!(reply(receive).await, original);
    for respond in pending {
        respond.send(original.clone()).unwrap();
    }
    for client in clients {
        assert_eq!(reply(client).await, original);
    }
    f.gate.shutdown().await;
}

#[tokio::test]
async fn expiry_releases_without_a_status_poll_and_late_reply_cannot_rearm() {
    let mut f = Fixture::new(Duration::from_secs(1));
    f.arm(200);
    let original = bytes(f.purchase());
    let (handled, receive) = f.request().await;
    handled.respond.send(original.clone()).unwrap();
    observed(&f.gate, |s| s.held_responses == 1).await;
    let (late, late_client) = f.request().await;
    assert_eq!(reply(receive).await, original);
    assert_eq!(f.gate.status().unwrap().terminal_reason, Some("expired"));
    assert!(
        f.gate
            .arm(&f.buyer.npub(), &f.destination.npub(), 32_768, 1_000)
            .is_err()
    );
    late.respond.send(original.clone()).unwrap();
    assert_eq!(reply(late_client).await, original);
    assert_eq!(f.gate.status().unwrap().held_responses, 0);
    f.gate.shutdown().await;
}

#[tokio::test]
async fn release_before_commit_forwards_late_success_without_false_capture() {
    let mut f = Fixture::new(Duration::from_secs(1));
    f.arm(1_000);
    let (handled, receive) = f.request().await;
    f.gate.release().unwrap();
    assert!(
        f.gate
            .arm(&f.buyer.npub(), &f.destination.npub(), 32_768, 1_000)
            .is_err()
    );
    let original = bytes(f.purchase());
    handled.respond.send(original.clone()).unwrap();
    assert_eq!(reply(receive).await, original);
    assert!(f.gate.status().unwrap().captured.is_none());
    f.gate.shutdown().await;
}

#[tokio::test]
async fn shutdown_releases_held_and_drains_late_real_responses() {
    let mut f = Fixture::new(Duration::from_secs(1));
    f.arm(10_000);
    let original = bytes(f.purchase());
    let (handled, receive) = f.request().await;
    handled.respond.send(original.clone()).unwrap();
    observed(&f.gate, |s| s.held_responses == 1).await;
    let (late, late_client) = f.request().await;
    let task = tokio::spawn(f.gate.shutdown());
    assert_eq!(reply(receive).await, original);
    late.respond.send(original.clone()).unwrap();
    assert_eq!(reply(late_client).await, original);
    tokio::time::timeout(Duration::from_secs(1), task)
        .await
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn controller_timeout_or_cancellation_is_explicit_and_never_success() {
    for timeout in [false, true] {
        let mut f = Fixture::new(Duration::from_millis(20));
        f.arm(1_000);
        let (handled, receive) = f.request().await;
        let respond = if timeout {
            Some(handled.respond)
        } else {
            drop(handled.respond);
            None
        };
        assert!(
            tokio::time::timeout(Duration::from_secs(1), receive)
                .await
                .unwrap()
                .is_err()
        );
        let status = f.gate.status().unwrap();
        assert!(!status.active && status.captured.is_none());
        assert_eq!(
            status.terminal_reason,
            Some(if timeout {
                "response_timeout"
            } else {
                "response_canceled"
            })
        );
        assert_eq!(status.forwarded_replies, 0);
        drop(respond);
        f.gate.shutdown().await;
    }
}

#[tokio::test]
async fn second_different_full_acceptance_preserves_first_capture_and_releases() {
    let mut f = Fixture::new(Duration::from_secs(1));
    f.arm(1_000);
    let original = bytes(f.purchase());
    let (handled, receive) = f.request().await;
    handled.respond.send(original.clone()).unwrap();
    observed(&f.gate, |s| s.held_responses == 1).await;
    let (other, other_client) = f.submit(f.buyer, f.accept("another-offer")).await;
    other.respond.send(original.clone()).unwrap();
    assert_eq!(reply(other_client).await, original);
    assert_eq!(reply(receive).await, original);
    let status = f.gate.status().unwrap();
    assert_eq!(status.terminal_reason, Some("different_full_acceptance"));
    assert_eq!(status.captured.unwrap().offer_id, "full-offer");
    f.gate.shutdown().await;
}

#[tokio::test]
async fn invalid_arm_does_not_consume_the_one_shot() {
    let f = Fixture::new(Duration::from_secs(1));
    for (buyer, units, hold) in [("bad", 32_768, 1_000), ("", 32_768, 1_000)] {
        assert!(
            f.gate
                .arm(buyer, &f.destination.npub(), units, hold)
                .is_err()
        );
    }
    for (units, hold) in [(0, 1), (u64::MAX, 1), (1, 0), (1, MAX_HOLD_MS + 1)] {
        assert!(
            f.gate
                .arm(&f.buyer.npub(), &f.destination.npub(), units, hold)
                .is_err()
        );
    }
    assert!(
        f.gate
            .arm(&f.buyer.npub(), "invalid", 32_768, 1_000)
            .is_err()
    );
    assert!(!f.gate.status().unwrap().armed);
    f.arm(1_000);
    f.gate.shutdown().await;
}

#[tokio::test]
async fn expiry_releases_even_when_the_controller_input_queue_is_full() {
    let mut f = Fixture::new(Duration::from_secs(1));
    f.arm(200);
    let original = bytes(f.purchase());
    let (handled, receive) = f.request().await;
    handled.respond.send(original.clone()).unwrap();
    observed(&f.gate, |s| s.held_responses == 1).await;
    let body = serde_json::to_vec(&ControllerRequest::Seal {
        channel_id: "other".into(),
    })
    .unwrap();
    let mut clients = Vec::new();
    for _ in 0..=QUEUE {
        let (respond, client) = oneshot::channel();
        f.incoming
            .send(IncomingRequest {
                peer: f.buyer,
                body: body.clone(),
                respond,
            })
            .await
            .unwrap();
        clients.push(client);
    }
    tokio::time::timeout(Duration::from_secs(1), async {
        while f.controller.len() < QUEUE {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert_eq!(reply(receive).await, original);
    assert_eq!(f.gate.status().unwrap().terminal_reason, Some("expired"));
    drop(f.controller);
    f.gate.shutdown().await;
    for client in clients {
        assert!(client.await.is_err());
    }
}
