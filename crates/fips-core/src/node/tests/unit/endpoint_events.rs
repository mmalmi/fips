use super::*;
use crate::node::endpoint_event::release_endpoint_event_messages;

fn release_observed_endpoint_event(rx: &EndpointEventReceiver, event: &NodeEndpointEvent) {
    rx.release_messages(event.message_count());
}

fn one_message_endpoint_event(
    source: PeerIdentity,
    payload: impl Into<crate::transport::PacketBuffer>,
) -> NodeEndpointEvent {
    NodeEndpointEvent {
        messages: vec![EndpointDataDelivery::new(source, payload)],
        queued_at: crate::perf_profile::stamp(),
    }
}

fn expect_one_message(event: NodeEndpointEvent) -> EndpointDataDelivery {
    match event {
        NodeEndpointEvent { mut messages, .. } if messages.len() == 1 => {
            messages.pop().expect("one endpoint message")
        }
        NodeEndpointEvent { messages, .. } => {
            panic!("expected one endpoint message, got {}", messages.len())
        }
    }
}

#[test]
fn endpoint_event_runtime_owns_attach_delivery_and_backlog() {
    let (event_tx, mut event_rx) = EndpointEventSender::channel(8);
    let source = PeerIdentity::from_pubkey_full(Identity::generate().pubkey_full());
    let mut runtime = EndpointEventRuntime::default();

    assert!(!runtime.is_attached());
    runtime
        .deliver_endpoint_data_batch(vec![EndpointDataDelivery::new(
            source,
            b"detached".to_vec(),
        )])
        .expect("detached endpoint runtime delivery should be a no-op");
    assert!(
        event_rx.try_recv().is_err(),
        "detached runtime must not enqueue endpoint events"
    );
    assert_eq!(event_tx.queued_messages(), 0);

    runtime.attach(event_tx.clone());
    runtime
        .deliver_endpoint_data_batch(vec![EndpointDataDelivery::new(source, b"first".to_vec())])
        .expect("endpoint event");
    assert_eq!(event_tx.queued_messages(), 1);
    let event = event_rx.try_recv().expect("batched event");
    release_observed_endpoint_event(&event_rx, &event);
    let NodeEndpointEvent { messages, .. } = event;
    assert_eq!(messages.len(), 1);
    assert_eq!(messages[0].source_peer, source);
    assert_eq!(messages[0].payload, b"first");
    assert_eq!(event_tx.queued_messages(), 0);

    runtime
        .deliver_endpoint_data_batch(vec![
            EndpointDataDelivery::new(source, b"second".to_vec()),
            EndpointDataDelivery::new(source, b"third".to_vec()),
        ])
        .expect("endpoint event batch");
    assert_eq!(event_tx.queued_messages(), 2);
    let event = event_rx.try_recv().expect("batched event");
    release_observed_endpoint_event(&event_rx, &event);
    let NodeEndpointEvent { messages, .. } = event;
    assert_eq!(messages.len(), 2);
    assert_eq!(messages[0].source_peer, source);
    assert_eq!(messages[0].payload, b"second");
    assert_eq!(messages[1].source_peer, source);
    assert_eq!(messages[1].payload, b"third");
    assert_eq!(event_tx.queued_messages(), 0);
}

#[test]
fn endpoint_event_queue_owns_backlog_message_count() {
    let mut node = Node::new(Config::new()).expect("node");
    let mut endpoint_io = node.attach_endpoint_data_io(8).expect("endpoint io");
    let source = PeerIdentity::from_pubkey_full(Identity::generate().pubkey_full());

    assert_eq!(endpoint_io.event_tx.queued_messages(), 0);
    node.endpoint_events
        .deliver_endpoint_data_batch(vec![EndpointDataDelivery::new(source, b"single".to_vec())])
        .expect("single endpoint event");
    assert_eq!(endpoint_io.event_tx.queued_messages(), 1);

    node.endpoint_events
        .deliver_endpoint_data_batch(vec![
            EndpointDataDelivery::new(source, vec![0xaa; ENDPOINT_EVENT_TEST_PAYLOAD_LEN + 1]),
            EndpointDataDelivery::new(source, vec![0xbb; ENDPOINT_EVENT_TEST_PAYLOAD_LEN + 2]),
        ])
        .expect("batched endpoint event");
    assert_eq!(
        endpoint_io.event_tx.queued_messages(),
        3,
        "backlog count should account for batch payloads, not channel items"
    );

    let event = endpoint_io.event_rx.try_recv().expect("single event");
    release_observed_endpoint_event(&endpoint_io.event_rx, &event);
    assert_eq!(endpoint_io.event_tx.queued_messages(), 2);
    let event = endpoint_io.event_rx.try_recv().expect("batched event");
    release_observed_endpoint_event(&endpoint_io.event_rx, &event);
    assert_eq!(endpoint_io.event_tx.queued_messages(), 0);
}

#[test]
fn endpoint_event_message_count_treats_batch_items_as_public_messages() {
    let source = PeerIdentity::from_pubkey_full(Identity::generate().pubkey_full());

    let event = one_message_endpoint_event(source, vec![0x11; ENDPOINT_EVENT_TEST_PAYLOAD_LEN]);
    assert_eq!(event.message_count(), 1);

    let event = NodeEndpointEvent {
        messages: vec![
            EndpointDataDelivery::new(source, vec![0xaa; ENDPOINT_EVENT_TEST_PAYLOAD_LEN + 1]),
            EndpointDataDelivery::new(source, vec![0x11; 32]),
            EndpointDataDelivery::new(source, vec![0xbb; ENDPOINT_EVENT_TEST_PAYLOAD_LEN + 2]),
        ],
        queued_at: None,
    };
    assert_eq!(event.message_count(), 3);
}

#[test]
fn direct_endpoint_sink_receives_packet_batch_with_run_metadata() {
    let source = PeerIdentity::from_pubkey_full(Identity::generate().pubkey_full());
    let previous_hop = NodeAddr::from_bytes([0x44; 16]);
    let captured = std::sync::Arc::new(std::sync::Mutex::new(None));
    let captured_batch = std::sync::Arc::clone(&captured);
    let sink = EndpointDirectSink::new(move |batch| {
        *captured_batch.lock().expect("direct batch lock") = Some(batch);
        Ok::<(), FipsEndpointDirectDeliveryError>(())
    });
    let run = FipsEndpointDirectPacketRun::from_segmented_payload(
        FipsEndpointDirectPacketRunMeta::new(source, previous_hop, true, false, 123),
        b"a1a2".to_vec().into(),
        vec![0..2, 2..4],
    );
    let batch = FipsEndpointDirectPacketBatch::from_packet_runs(vec![run]);

    sink.deliver_direct_packet_batch(batch)
        .expect("direct packet batch delivery");

    let batch = captured
        .lock()
        .expect("direct batch lock")
        .take()
        .expect("captured direct packet batch");
    assert!(batch.is_single_source());
    assert_eq!(batch.len(), 2);
    assert_eq!(batch.packet_bytes(), 4);
    assert_eq!(batch.run_count(), 1);
    let runs = batch.packet_runs();
    assert_eq!(runs[0].source_peer(), &source);
    assert_eq!(runs[0].previous_hop_node_addr(), &previous_hop);
    assert!(runs[0].received_k_bit());
    assert!(!runs[0].is_direct_path());
    assert_eq!(runs[0].enqueued_at_ms(), 123);
    assert_eq!(runs[0].packet_slice(0), Some(b"a1".as_slice()));
    assert_eq!(runs[0].packet_slice(1), Some(b"a2".as_slice()));
}

#[test]
fn release_endpoint_event_messages_subtracts_exact_count() {
    let counter = AtomicUsize::new(5);

    release_endpoint_event_messages(&counter, 0);
    assert_eq!(counter.load(Relaxed), 5);

    release_endpoint_event_messages(&counter, 3);
    assert_eq!(counter.load(Relaxed), 2);
}

#[test]
fn endpoint_event_queue_preserves_fifo_for_mixed_payload_sizes() {
    let (event_tx, mut event_rx) = EndpointEventSender::channel(8);
    let source = PeerIdentity::from_pubkey_full(Identity::generate().pubkey_full());

    event_tx
        .send(NodeEndpointEvent {
            messages: vec![
                EndpointDataDelivery::new(source, vec![0xaa; ENDPOINT_EVENT_TEST_PAYLOAD_LEN + 1]),
                EndpointDataDelivery::new(source, vec![0x11; 32]),
            ],
            queued_at: crate::perf_profile::stamp(),
        })
        .expect("mixed endpoint event batch should enqueue");
    event_tx
        .send(NodeEndpointEvent {
            messages: vec![
                EndpointDataDelivery::new(source, b"first".to_vec()),
                EndpointDataDelivery::new(source, b"second".to_vec()),
            ],
            queued_at: crate::perf_profile::stamp(),
        })
        .expect("second endpoint event batch should enqueue");

    let event = event_rx.try_recv().expect("first batch");
    release_observed_endpoint_event(&event_rx, &event);
    let NodeEndpointEvent { messages, .. } = event;
    assert_eq!(messages.len(), 2);
    assert_eq!(messages[0].payload[0], 0xaa);
    assert_eq!(messages[1].payload[0], 0x11);
    let event = event_rx.try_recv().expect("second batch");
    release_observed_endpoint_event(&event_rx, &event);
    let NodeEndpointEvent { messages, .. } = event;
    assert_eq!(messages.len(), 2);
    assert_eq!(messages[0].payload, b"first");
    assert_eq!(messages[1].payload, b"second");
    assert_eq!(event_tx.queued_messages(), 0);
}

#[test]
fn endpoint_event_queue_drops_app_data_when_full() {
    let (event_tx, mut event_rx) = EndpointEventSender::channel(1);
    let source = PeerIdentity::from_pubkey_full(Identity::generate().pubkey_full());

    event_tx
        .send(one_message_endpoint_event(
            source,
            vec![0xaa; ENDPOINT_EVENT_TEST_PAYLOAD_LEN + 1],
        ))
        .expect("first endpoint event should enqueue");
    assert_eq!(event_tx.queued_messages(), 1);

    event_tx
        .send(one_message_endpoint_event(
            source,
            vec![0xbb; ENDPOINT_EVENT_TEST_PAYLOAD_LEN + 1],
        ))
        .expect("full endpoint lane should drop rather than fail");
    assert_eq!(
        event_tx.queued_messages(),
        1,
        "dropped event should roll back queued message accounting"
    );

    let event = event_rx.try_recv().expect("first event");
    release_observed_endpoint_event(&event_rx, &event);
    let message = expect_one_message(event);
    assert_eq!(message.payload[0], 0xaa);
    assert_eq!(event_tx.queued_messages(), 0);
    assert!(matches!(
        event_rx.try_recv(),
        Err(tokio::sync::mpsc::error::TryRecvError::Empty)
    ));
}

#[test]
fn endpoint_event_queue_dropped_batch_counts_as_success() {
    let (event_tx, mut event_rx) = EndpointEventSender::channel(2);
    let source = PeerIdentity::from_pubkey_full(Identity::generate().pubkey_full());

    event_tx
        .send(NodeEndpointEvent {
            messages: vec![
                EndpointDataDelivery::new(source, vec![0xaa; ENDPOINT_EVENT_TEST_PAYLOAD_LEN + 1]),
                EndpointDataDelivery::new(source, vec![0xab; ENDPOINT_EVENT_TEST_PAYLOAD_LEN + 2]),
            ],
            queued_at: crate::perf_profile::stamp(),
        })
        .expect("first endpoint batch should enqueue");
    assert_eq!(event_tx.queued_messages(), 2);

    event_tx
        .send(NodeEndpointEvent {
            messages: vec![
                EndpointDataDelivery::new(source, vec![0xba; ENDPOINT_EVENT_TEST_PAYLOAD_LEN + 1]),
                EndpointDataDelivery::new(source, vec![0xbb; ENDPOINT_EVENT_TEST_PAYLOAD_LEN + 2]),
            ],
            queued_at: crate::perf_profile::stamp(),
        })
        .expect("full endpoint lane should drop batch rather than fail");
    assert_eq!(
        event_tx.queued_messages(),
        2,
        "dropped batch should roll back all message accounting"
    );

    let event = event_rx.try_recv().expect("first batch");
    release_observed_endpoint_event(&event_rx, &event);
    let NodeEndpointEvent { messages, .. } = event;
    assert_eq!(messages.len(), 2);
    assert_eq!(messages[0].payload[0], 0xaa);
    assert_eq!(messages[1].payload[0], 0xab);
    assert_eq!(event_tx.queued_messages(), 0);
    assert!(matches!(
        event_rx.try_recv(),
        Err(tokio::sync::mpsc::error::TryRecvError::Empty)
    ));
}

#[test]
fn endpoint_event_queue_partially_admits_batch_at_message_boundary() {
    let (event_tx, mut event_rx) = EndpointEventSender::channel(3);
    let source = PeerIdentity::from_pubkey_full(Identity::generate().pubkey_full());

    event_tx
        .send(NodeEndpointEvent {
            messages: vec![
                EndpointDataDelivery::new(source, vec![0xaa; ENDPOINT_EVENT_TEST_PAYLOAD_LEN + 1]),
                EndpointDataDelivery::new(source, vec![0xab; ENDPOINT_EVENT_TEST_PAYLOAD_LEN + 2]),
            ],
            queued_at: crate::perf_profile::stamp(),
        })
        .expect("first endpoint batch should enqueue");
    assert_eq!(event_tx.queued_messages(), 2);

    event_tx
        .send(NodeEndpointEvent {
            messages: vec![
                EndpointDataDelivery::new(source, vec![0xba; ENDPOINT_EVENT_TEST_PAYLOAD_LEN + 1]),
                EndpointDataDelivery::new(source, vec![0xbb; ENDPOINT_EVENT_TEST_PAYLOAD_LEN + 2]),
            ],
            queued_at: crate::perf_profile::stamp(),
        })
        .expect("second endpoint batch should partially admit");
    assert_eq!(event_tx.queued_messages(), 3);

    let event = event_rx.try_recv().expect("first batch");
    release_observed_endpoint_event(&event_rx, &event);
    let NodeEndpointEvent { messages, .. } = event;
    assert_eq!(messages.len(), 2);
    assert_eq!(messages[0].payload[0], 0xaa);
    assert_eq!(messages[1].payload[0], 0xab);
    let event = event_rx.try_recv().expect("partially admitted event");
    release_observed_endpoint_event(&event_rx, &event);
    let message = expect_one_message(event);
    assert_eq!(message.payload[0], 0xba);
    assert_eq!(event_tx.queued_messages(), 0);
    assert!(matches!(
        event_rx.try_recv(),
        Err(tokio::sync::mpsc::error::TryRecvError::Empty)
    ));
}

#[test]
fn endpoint_event_capacity_counts_messages_not_batches() {
    let (event_tx, mut event_rx) = EndpointEventSender::channel(1);
    let source = PeerIdentity::from_pubkey_full(Identity::generate().pubkey_full());

    event_tx
        .send(NodeEndpointEvent {
            messages: vec![
                EndpointDataDelivery::new(source, vec![0xaa; ENDPOINT_EVENT_TEST_PAYLOAD_LEN + 1]),
                EndpointDataDelivery::new(source, vec![0xab; ENDPOINT_EVENT_TEST_PAYLOAD_LEN + 2]),
            ],
            queued_at: crate::perf_profile::stamp(),
        })
        .expect("oversized endpoint batch should split rather than fail");
    assert_eq!(
        event_tx.queued_messages(),
        1,
        "oversized batch should admit the headroom-sized prefix"
    );
    let event = event_rx.try_recv().expect("admitted split event");
    release_observed_endpoint_event(&event_rx, &event);
    let message = expect_one_message(event);
    assert_eq!(message.payload[0], 0xaa);
    assert_eq!(event_tx.queued_messages(), 0);

    event_tx
        .send(one_message_endpoint_event(source, b"small".to_vec()))
        .expect("small endpoint event should enqueue after capacity frees");
    assert_eq!(event_tx.queued_messages(), 1);
    let event = event_rx.try_recv().expect("small event");
    release_observed_endpoint_event(&event_rx, &event);
    let message = expect_one_message(event);
    assert_eq!(message.payload, b"small");
}

#[test]
fn endpoint_event_queue_send_fails_after_receiver_drop() {
    let (event_tx, mut event_rx) = EndpointEventSender::channel(8);
    let source = PeerIdentity::from_pubkey_full(Identity::generate().pubkey_full());

    event_tx
        .send(one_message_endpoint_event(source, b"queued".to_vec()))
        .expect("endpoint event should enqueue while receiver is alive");
    assert_eq!(event_tx.queued_messages(), 1);
    assert!(event_rx.try_recv().is_ok());

    drop(event_rx);
    assert_eq!(
        event_tx.queued_messages(),
        0,
        "receiver drop should discard any owned backlog"
    );

    let error = event_tx
        .send(one_message_endpoint_event(source, b"after-drop".to_vec()))
        .expect_err("send should fail once endpoint event receiver is dropped");
    let message = expect_one_message(error.0);
    assert_eq!(message.payload, b"after-drop");
    assert_eq!(event_tx.queued_messages(), 0);
}

#[test]
fn endpoint_event_queue_closes_after_all_senders_drop() {
    let (event_tx, mut event_rx) = EndpointEventSender::channel(8);
    let event_tx_clone = event_tx.clone();

    drop(event_tx);
    assert!(
        matches!(
            event_rx.try_recv(),
            Err(tokio::sync::mpsc::error::TryRecvError::Empty)
        ),
        "receiver should stay open while a sender clone is alive"
    );

    drop(event_tx_clone);
    assert!(
        matches!(
            event_rx.try_recv(),
            Err(tokio::sync::mpsc::error::TryRecvError::Disconnected)
        ),
        "receiver should close once the final sender is dropped"
    );
    assert!(
        event_rx.blocking_recv().is_none(),
        "blocking receive should return after sender close"
    );
}

#[tokio::test]
async fn endpoint_event_queue_async_recv_closes_when_senders_drop() {
    let (event_tx, mut event_rx) = EndpointEventSender::channel(8);

    let waiter = tokio::spawn(async move { event_rx.recv().await });
    tokio::task::yield_now().await;
    drop(event_tx);

    let result = tokio::time::timeout(std::time::Duration::from_secs(1), waiter)
        .await
        .expect("async recv should wake after final sender drops")
        .expect("async recv task should not panic");
    assert!(result.is_none());
}
