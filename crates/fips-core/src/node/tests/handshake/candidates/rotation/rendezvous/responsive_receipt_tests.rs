//! Real bounded endpoint queues isolate receipt observation from unrelated work.
use super::*;
use crate::node::{
    EndpointDataDelivery, EndpointEventReceiver, EndpointEventSender, NodeEndpointEvent,
};
use crate::transport::PacketBuffer;

const CUT_MS: u64 = 1_500;

fn drain(
    receivers: &mut [EndpointEventReceiver],
    payloads: &mut Payloads,
    ids: &[PeerIdentity],
    started: tokio::time::Instant,
) {
    for (direction, receiver) in receivers.iter_mut().enumerate() {
        receive_endpoint_round_with_observer(
            FLOWS[direction].1,
            receiver,
            ids,
            &[],
            &[],
            &mut Vec::new(),
            &mut |destination, source, payload| {
                payloads.receive(destination, source, payload, ids, started)
            },
        );
    }
}

async fn observe_around_unrelated_work(publication_ms: u64) -> Payloads {
    let ids: Vec<_> = (1..=4)
        .map(|scalar| {
            let identity = crate::Identity::from_secret_bytes(&[scalar; 32]).unwrap();
            PeerIdentity::from_pubkey(identity.pubkey())
        })
        .collect();
    let (senders, mut receivers): (Vec<_>, Vec<_>) =
        (0..2).map(|_| EndpointEventSender::channel(16)).unzip();
    let started = tokio::time::Instant::now();
    let mut payloads = Payloads {
        submitted_ms: [[Some(0), Some(0)]; 2],
        ..Default::default()
    };
    let (gate_tx, gate_rx) = tokio::sync::oneshot::channel();
    let batch = async {
        tokio::time::sleep_until(started + Duration::from_millis(publication_ms)).await;
        for (direction, sender) in senders.iter().enumerate() {
            sender
                .send(NodeEndpointEvent {
                    messages: vec![EndpointDataDelivery::new(
                        ids[FLOWS[direction].0],
                        PacketBuffer::new(ORIGINALS[direction].to_vec()),
                    )],
                    queued_at: None,
                })
                .unwrap();
            assert_eq!(sender.queued_messages(), 1);
        }
        // This is the same prompt callback used after real packet/completion
        // turns. Message timestamps are never acceptance evidence.
        observe_completed_turn(|| drain(&mut receivers, &mut payloads, &ids, started));
        gate_rx.await.unwrap();
        // Preserve the original end-of-batch observation as the fallback.
        drain(&mut receivers, &mut payloads, &ids, started);
    };
    let unrelated = async {
        tokio::time::sleep_until(started + Duration::from_millis(CUT_MS + 20)).await;
        gate_tx.send(()).unwrap();
    };
    tokio::join!(batch, unrelated);
    assert!(started.elapsed() >= Duration::from_millis(CUT_MS + 20));
    assert_eq!(payloads.received, [1, 1]);
    assert!(senders.iter().all(|sender| sender.queued_messages() == 0));
    payloads
}

#[tokio::test(start_paused = true)]
async fn prompt_receipts_survive_unrelated_turn_crossing_cut() {
    let payloads = observe_around_unrelated_work(CUT_MS - 10).await;
    assert!(
        payloads.accepted(u128::from(CUT_MS)),
        "prompt observation must retain both pre-cut endpoint receipts"
    );
}

#[tokio::test(start_paused = true)]
async fn post_cut_publication_cannot_pass_prompt_observation() {
    let payloads = observe_around_unrelated_work(CUT_MS + 10).await;
    assert!(
        !payloads.accepted(u128::from(CUT_MS)),
        "prompt observation cannot accept post-cut endpoint publication"
    );
}
