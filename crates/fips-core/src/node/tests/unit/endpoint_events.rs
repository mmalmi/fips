use super::*;

#[test]
fn endpoint_event_runtime_owns_attach_delivery_and_backlog() {
    let (event_tx, mut event_rx) = EndpointEventSender::channel(8);
    let source = PeerIdentity::from_pubkey_full(Identity::generate().pubkey_full());
    let mut runtime = EndpointEventRuntime::default();

    assert!(!runtime.is_attached());
    runtime
        .deliver_endpoint_data(EndpointDataDelivery::new(source, b"detached".to_vec()))
        .expect("detached endpoint runtime delivery should be a no-op");
    assert!(
        event_rx.try_recv().is_err(),
        "detached runtime must not enqueue endpoint events"
    );
    assert_eq!(event_tx.queued_messages(), 0);

    runtime.attach(event_tx.clone());
    runtime
        .deliver_endpoint_data(EndpointDataDelivery::new(source, b"first".to_vec()))
        .expect("endpoint event");
    assert_eq!(event_tx.queued_messages(), 1);
    match event_rx.try_recv().expect("batched event") {
        NodeEndpointEvent::Data {
            source_peer,
            payload,
            ..
        } => {
            assert_eq!(source_peer, source);
            assert_eq!(payload, b"first");
        }
        event => panic!("expected endpoint data event, got {event:?}"),
    }
    assert_eq!(event_tx.queued_messages(), 0);

    runtime
        .deliver_endpoint_data_batch(vec![
            EndpointDataDelivery::new(source, b"second".to_vec()),
            EndpointDataDelivery::new(source, b"third".to_vec()),
        ])
        .expect("endpoint event batch");
    assert_eq!(event_tx.queued_messages(), 2);
    match event_rx.try_recv().expect("batched event") {
        NodeEndpointEvent::DataBatch { messages, .. } => {
            assert_eq!(messages.len(), 2);
            assert_eq!(messages[0].source_peer, source);
            assert_eq!(messages[0].payload, b"second");
            assert_eq!(messages[1].source_peer, source);
            assert_eq!(messages[1].payload, b"third");
        }
        event => panic!("expected endpoint event batch, got {event:?}"),
    }
    assert_eq!(event_tx.queued_messages(), 0);
}

#[test]
fn endpoint_event_queue_owns_backlog_message_count() {
    let mut node = Node::new(Config::new()).expect("node");
    let mut endpoint_io = node.attach_endpoint_data_io(8).expect("endpoint io");
    let source = PeerIdentity::from_pubkey_full(Identity::generate().pubkey_full());

    assert_eq!(endpoint_io.event_tx.queued_messages(), 0);
    node.deliver_endpoint_event_message(EndpointDataDelivery::new(source, b"single".to_vec()))
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

    endpoint_io.event_rx.try_recv().expect("single event");
    assert_eq!(endpoint_io.event_tx.queued_messages(), 2);
    endpoint_io.event_rx.try_recv().expect("batched event");
    assert_eq!(endpoint_io.event_tx.queued_messages(), 0);
}

#[test]
fn endpoint_event_dequeue_counts_treat_app_data_as_one_channel() {
    let source = PeerIdentity::from_pubkey_full(Identity::generate().pubkey_full());

    let event = NodeEndpointEvent::Data {
        source_peer: source,
        payload: vec![0x11; ENDPOINT_EVENT_TEST_PAYLOAD_LEN].into(),
        enqueued_at_ms: crate::time::now_ms(),
        queued_at: None,
    };
    assert_eq!(
        event.dequeue_counts(),
        EndpointEventDequeueCounts { total: 1 }
    );

    let event = NodeEndpointEvent::DataBatch {
        messages: vec![
            EndpointDataDelivery::new(source, vec![0xaa; ENDPOINT_EVENT_TEST_PAYLOAD_LEN + 1]),
            EndpointDataDelivery::new(source, vec![0x11; 32]),
            EndpointDataDelivery::new(source, vec![0xbb; ENDPOINT_EVENT_TEST_PAYLOAD_LEN + 2]),
        ],
        queued_at: None,
    };
    assert_eq!(
        event.dequeue_counts(),
        EndpointEventDequeueCounts { total: 3 }
    );
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
        .send(NodeEndpointEvent::DataBatch {
            messages: vec![
                EndpointDataDelivery::new(source, vec![0xaa; ENDPOINT_EVENT_TEST_PAYLOAD_LEN + 1]),
                EndpointDataDelivery::new(source, vec![0x11; 32]),
            ],
            queued_at: crate::perf_profile::stamp(),
        })
        .expect("mixed endpoint event batch should enqueue");
    event_tx
        .send(NodeEndpointEvent::DataBatch {
            messages: vec![
                EndpointDataDelivery::new(source, b"first".to_vec()),
                EndpointDataDelivery::new(source, b"second".to_vec()),
            ],
            queued_at: crate::perf_profile::stamp(),
        })
        .expect("second endpoint event batch should enqueue");

    match event_rx.try_recv().expect("first batch") {
        NodeEndpointEvent::DataBatch { messages, .. } => {
            assert_eq!(messages.len(), 2);
            assert_eq!(messages[0].payload[0], 0xaa);
            assert_eq!(messages[1].payload[0], 0x11);
        }
        event => panic!("expected first endpoint event batch, got {event:?}"),
    }
    match event_rx.try_recv().expect("second batch") {
        NodeEndpointEvent::DataBatch { messages, .. } => {
            assert_eq!(messages.len(), 2);
            assert_eq!(messages[0].payload, b"first");
            assert_eq!(messages[1].payload, b"second");
        }
        event => panic!("expected second endpoint event batch, got {event:?}"),
    }
    assert_eq!(event_tx.queued_messages(), 0);
}

#[test]
fn endpoint_event_queue_drops_app_data_when_full() {
    let (event_tx, mut event_rx) = EndpointEventSender::channel(1);
    let source = PeerIdentity::from_pubkey_full(Identity::generate().pubkey_full());

    event_tx
        .send(NodeEndpointEvent::Data {
            source_peer: source,
            payload: vec![0xaa; ENDPOINT_EVENT_TEST_PAYLOAD_LEN + 1].into(),
            enqueued_at_ms: crate::time::now_ms(),
            queued_at: crate::perf_profile::stamp(),
        })
        .expect("first endpoint event should enqueue");
    assert_eq!(event_tx.queued_messages(), 1);

    event_tx
        .send(NodeEndpointEvent::Data {
            source_peer: source,
            payload: vec![0xbb; ENDPOINT_EVENT_TEST_PAYLOAD_LEN + 1].into(),
            enqueued_at_ms: crate::time::now_ms(),
            queued_at: crate::perf_profile::stamp(),
        })
        .expect("full endpoint lane should drop rather than fail");
    assert_eq!(
        event_tx.queued_messages(),
        1,
        "dropped event should roll back queued message accounting"
    );

    match event_rx.try_recv().expect("first event") {
        NodeEndpointEvent::Data { payload, .. } => assert_eq!(payload[0], 0xaa),
        event => panic!("expected data event, got {event:?}"),
    }
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
        .send(NodeEndpointEvent::DataBatch {
            messages: vec![
                EndpointDataDelivery::new(source, vec![0xaa; ENDPOINT_EVENT_TEST_PAYLOAD_LEN + 1]),
                EndpointDataDelivery::new(source, vec![0xab; ENDPOINT_EVENT_TEST_PAYLOAD_LEN + 2]),
            ],
            queued_at: crate::perf_profile::stamp(),
        })
        .expect("first endpoint batch should enqueue");
    assert_eq!(event_tx.queued_messages(), 2);

    event_tx
        .send(NodeEndpointEvent::DataBatch {
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

    match event_rx.try_recv().expect("first batch") {
        NodeEndpointEvent::DataBatch { messages, .. } => {
            assert_eq!(messages.len(), 2);
            assert_eq!(messages[0].payload[0], 0xaa);
            assert_eq!(messages[1].payload[0], 0xab);
        }
        event => panic!("expected endpoint event batch, got {event:?}"),
    }
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
        .send(NodeEndpointEvent::DataBatch {
            messages: vec![
                EndpointDataDelivery::new(source, vec![0xaa; ENDPOINT_EVENT_TEST_PAYLOAD_LEN + 1]),
                EndpointDataDelivery::new(source, vec![0xab; ENDPOINT_EVENT_TEST_PAYLOAD_LEN + 2]),
            ],
            queued_at: crate::perf_profile::stamp(),
        })
        .expect("first endpoint batch should enqueue");
    assert_eq!(event_tx.queued_messages(), 2);

    event_tx
        .send(NodeEndpointEvent::DataBatch {
            messages: vec![
                EndpointDataDelivery::new(source, vec![0xba; ENDPOINT_EVENT_TEST_PAYLOAD_LEN + 1]),
                EndpointDataDelivery::new(source, vec![0xbb; ENDPOINT_EVENT_TEST_PAYLOAD_LEN + 2]),
            ],
            queued_at: crate::perf_profile::stamp(),
        })
        .expect("second endpoint batch should partially admit");
    assert_eq!(event_tx.queued_messages(), 3);

    match event_rx.try_recv().expect("first batch") {
        NodeEndpointEvent::DataBatch { messages, .. } => {
            assert_eq!(messages.len(), 2);
            assert_eq!(messages[0].payload[0], 0xaa);
            assert_eq!(messages[1].payload[0], 0xab);
        }
        event => panic!("expected first endpoint batch, got {event:?}"),
    }
    match event_rx.try_recv().expect("partially admitted event") {
        NodeEndpointEvent::Data { payload, .. } => assert_eq!(payload[0], 0xba),
        event => panic!("expected split data event, got {event:?}"),
    }
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
        .send(NodeEndpointEvent::DataBatch {
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
    match event_rx.try_recv().expect("admitted split event") {
        NodeEndpointEvent::Data { payload, .. } => assert_eq!(payload[0], 0xaa),
        event => panic!("expected split data event, got {event:?}"),
    }
    assert_eq!(event_tx.queued_messages(), 0);

    event_tx
        .send(NodeEndpointEvent::Data {
            source_peer: source,
            payload: b"small".to_vec().into(),
            enqueued_at_ms: crate::time::now_ms(),
            queued_at: crate::perf_profile::stamp(),
        })
        .expect("small endpoint event should enqueue after capacity frees");
    assert_eq!(event_tx.queued_messages(), 1);
    match event_rx.try_recv().expect("small event") {
        NodeEndpointEvent::Data { payload, .. } => assert_eq!(payload, b"small"),
        event => panic!("expected small data event, got {event:?}"),
    }
}

#[test]
fn endpoint_event_queue_send_fails_after_receiver_drop() {
    let (event_tx, mut event_rx) = EndpointEventSender::channel(8);
    let source = PeerIdentity::from_pubkey_full(Identity::generate().pubkey_full());

    event_tx
        .send(NodeEndpointEvent::Data {
            source_peer: source,
            payload: b"queued".to_vec().into(),
            enqueued_at_ms: crate::time::now_ms(),
            queued_at: crate::perf_profile::stamp(),
        })
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
        .send(NodeEndpointEvent::Data {
            source_peer: source,
            payload: b"after-drop".to_vec().into(),
            enqueued_at_ms: crate::time::now_ms(),
            queued_at: crate::perf_profile::stamp(),
        })
        .expect_err("send should fail once endpoint event receiver is dropped");
    match error.0 {
        NodeEndpointEvent::Data { payload, .. } => assert_eq!(payload, b"after-drop"),
        event => panic!("expected failed data event, got {event:?}"),
    }
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
