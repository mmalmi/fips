use super::*;

#[test]
fn endpoint_event_batch_scope_emits_one_batch_and_keeps_immediate_delivery_outside_scope() {
    let mut node = Node::new(Config::new()).expect("node");
    let mut endpoint_io = node.attach_endpoint_data_io(8).expect("endpoint io");
    let source = PeerIdentity::from_pubkey_full(Identity::generate().pubkey_full());

    node.deliver_endpoint_event_message(EndpointDataDelivery::new(source, b"single".to_vec()))
        .expect("single endpoint event");
    match endpoint_io.event_rx.try_recv().expect("single event") {
        NodeEndpointEvent::Data {
            source_peer,
            payload,
            ..
        } => {
            assert_eq!(source_peer, source);
            assert_eq!(payload, b"single");
        }
        event => panic!("expected single endpoint event, got {event:?}"),
    }

    node.begin_endpoint_event_batch();
    node.deliver_endpoint_event_message(EndpointDataDelivery::new(source, b"first".to_vec()))
        .expect("first batched endpoint event");
    node.deliver_endpoint_event_message(EndpointDataDelivery::new(source, b"second".to_vec()))
        .expect("second batched endpoint event");
    assert!(
        endpoint_io.event_rx.try_recv().is_err(),
        "batch scope should not flush before finish"
    );

    node.finish_endpoint_event_batch();
    match endpoint_io.event_rx.try_recv().expect("batched event") {
        NodeEndpointEvent::DataBatch { messages, .. } => {
            assert_eq!(messages.len(), 2);
            assert_eq!(messages[0].source_peer, source);
            assert_eq!(messages[0].payload, b"first");
            assert_eq!(messages[1].source_peer, source);
            assert_eq!(messages[1].payload, b"second");
        }
        event => panic!("expected endpoint event batch, got {event:?}"),
    }
}

#[test]
fn endpoint_event_runtime_owns_attach_batch_and_backlog() {
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
    runtime.begin_batch();
    runtime
        .deliver_endpoint_data(EndpointDataDelivery::new(source, b"first".to_vec()))
        .expect("first batched endpoint event");
    runtime
        .deliver_endpoint_data(EndpointDataDelivery::new(source, b"second".to_vec()))
        .expect("second batched endpoint event");
    assert!(
        event_rx.try_recv().is_err(),
        "runtime batch scope should not flush before finish"
    );

    runtime.finish_batch();
    assert_eq!(event_tx.queued_messages(), 2);
    match event_rx.try_recv().expect("batched event") {
        NodeEndpointEvent::DataBatch { messages, .. } => {
            assert_eq!(messages.len(), 2);
            assert_eq!(messages[0].source_peer, source);
            assert_eq!(messages[0].payload, b"first");
            assert_eq!(messages[1].source_peer, source);
            assert_eq!(messages[1].payload, b"second");
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
    assert_eq!(endpoint_io.event_tx.bulk_queued_messages(), 0);
    node.deliver_endpoint_event_message(EndpointDataDelivery::new(source, b"single".to_vec()))
        .expect("single endpoint event");
    assert_eq!(endpoint_io.event_tx.queued_messages(), 1);
    assert_eq!(
        endpoint_io.event_tx.bulk_queued_messages(),
        0,
        "priority-sized events must not consume the bulk message budget"
    );

    node.begin_endpoint_event_batch();
    node.deliver_endpoint_event_message(EndpointDataDelivery::new(
        source,
        vec![0xaa; ENDPOINT_EVENT_PRIORITY_MAX_LEN + 1],
    ))
    .expect("first batched endpoint event");
    node.deliver_endpoint_event_message(EndpointDataDelivery::new(
        source,
        vec![0xbb; ENDPOINT_EVENT_PRIORITY_MAX_LEN + 2],
    ))
    .expect("second batched endpoint event");
    node.finish_endpoint_event_batch();
    assert_eq!(
        endpoint_io.event_tx.queued_messages(),
        3,
        "backlog count should account for batch payloads, not channel items"
    );
    assert_eq!(endpoint_io.event_tx.bulk_queued_messages(), 2);

    endpoint_io.event_rx.try_recv().expect("single event");
    assert_eq!(endpoint_io.event_tx.queued_messages(), 2);
    assert_eq!(endpoint_io.event_tx.bulk_queued_messages(), 2);
    endpoint_io.event_rx.try_recv().expect("batched event");
    assert_eq!(endpoint_io.event_tx.queued_messages(), 0);
    assert_eq!(endpoint_io.event_tx.bulk_queued_messages(), 0);
}

#[test]
fn endpoint_event_dequeue_counts_preserve_message_and_lane_counts() {
    let source = PeerIdentity::from_pubkey_full(Identity::generate().pubkey_full());

    let event = NodeEndpointEvent::Data {
        source_peer: source,
        payload: vec![0x11; ENDPOINT_EVENT_PRIORITY_MAX_LEN].into(),
        queued_at: None,
    };
    assert_eq!(
        event.dequeue_counts(),
        EndpointEventDequeueCounts {
            total: 1,
            priority: 1,
            bulk: 0,
        }
    );

    let event = NodeEndpointEvent::DataBatch {
        messages: vec![
            EndpointDataDelivery::new(source, vec![0xaa; ENDPOINT_EVENT_PRIORITY_MAX_LEN + 1]),
            EndpointDataDelivery::new(source, vec![0x11; 32]),
            EndpointDataDelivery::new(source, vec![0xbb; ENDPOINT_EVENT_PRIORITY_MAX_LEN + 2]),
        ],
        queued_at: None,
    };
    assert_eq!(
        event.dequeue_counts(),
        EndpointEventDequeueCounts {
            total: 3,
            priority: 1,
            bulk: 2,
        }
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
fn endpoint_send_batch_coalesce_predicate_requires_same_peer_lane_and_cap() {
    let peer_a = PeerIdentity::from_pubkey_full(Identity::generate().pubkey_full());
    let peer_b = PeerIdentity::from_pubkey_full(Identity::generate().pubkey_full());
    let bulk_payload = || EndpointDataPayload::new(vec![0xaa; ENDPOINT_EVENT_PRIORITY_MAX_LEN + 1]);
    let priority_payload = || {
        let mut packet = vec![0u8; 28];
        let total_len = packet.len() as u16;
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&total_len.to_be_bytes());
        packet[9] = 1;
        EndpointDataPayload::new(packet)
    };

    let bulk_a =
        EndpointSendBatchCommand::new(peer_a, vec![bulk_payload()], None).expect("bulk batch");
    let bulk_a_more = EndpointSendBatchCommand::new(
        peer_a,
        vec![bulk_payload(), bulk_payload(), bulk_payload()],
        None,
    )
    .expect("second bulk batch");
    let bulk_b =
        EndpointSendBatchCommand::new(peer_b, vec![bulk_payload()], None).expect("other peer bulk");
    let priority_a = EndpointSendBatchCommand::new(peer_a, vec![priority_payload()], None)
        .expect("priority batch");

    assert!(bulk_a.can_coalesce_with(&bulk_a_more, 4));
    assert!(!bulk_a.can_coalesce_with(&bulk_a_more, 3));
    assert!(!bulk_a.can_coalesce_with(&bulk_b, 4));
    assert!(!bulk_a.can_coalesce_with(&priority_a, 4));
}

#[test]
fn endpoint_event_queue_splits_mixed_batch_into_priority_and_bulk_lanes() {
    let (event_tx, mut event_rx) = EndpointEventSender::channel(8);
    let source = PeerIdentity::from_pubkey_full(Identity::generate().pubkey_full());

    event_tx
        .send(NodeEndpointEvent::DataBatch {
            messages: vec![
                EndpointDataDelivery::new(source, vec![0xaa; ENDPOINT_EVENT_PRIORITY_MAX_LEN + 1]),
                EndpointDataDelivery::new(source, vec![0x11; 32]),
            ],
            queued_at: crate::perf_profile::stamp(),
        })
        .expect("mixed endpoint event batch should enqueue");

    match event_rx.try_recv().expect("priority event") {
        NodeEndpointEvent::Data { payload, .. } => assert_eq!(payload[0], 0x11),
        event => panic!("expected priority data event, got {event:?}"),
    }
    match event_rx.try_recv().expect("bulk event") {
        NodeEndpointEvent::Data { payload, .. } => assert_eq!(payload[0], 0xaa),
        event => panic!("expected bulk data event, got {event:?}"),
    }
    assert_eq!(event_tx.queued_messages(), 0);
}

#[test]
fn endpoint_event_queue_keeps_single_lane_batches_grouped() {
    let (event_tx, mut event_rx) = EndpointEventSender::channel(8);
    let source = PeerIdentity::from_pubkey_full(Identity::generate().pubkey_full());

    event_tx
        .send(NodeEndpointEvent::DataBatch {
            messages: vec![
                EndpointDataDelivery::new(source, vec![0xaa; ENDPOINT_EVENT_PRIORITY_MAX_LEN + 1]),
                EndpointDataDelivery::new(source, vec![0xbb; ENDPOINT_EVENT_PRIORITY_MAX_LEN + 2]),
            ],
            queued_at: crate::perf_profile::stamp(),
        })
        .expect("bulk endpoint event batch should enqueue");
    event_tx
        .send(NodeEndpointEvent::DataBatch {
            messages: vec![
                EndpointDataDelivery::new(source, b"first".to_vec()),
                EndpointDataDelivery::new(source, b"second".to_vec()),
            ],
            queued_at: crate::perf_profile::stamp(),
        })
        .expect("priority endpoint event batch should enqueue");

    match event_rx.try_recv().expect("priority batch") {
        NodeEndpointEvent::DataBatch { messages, .. } => {
            assert_eq!(messages.len(), 2);
            assert_eq!(messages[0].payload, b"first");
            assert_eq!(messages[1].payload, b"second");
        }
        event => panic!("expected priority endpoint event batch, got {event:?}"),
    }
    match event_rx.try_recv().expect("bulk batch") {
        NodeEndpointEvent::DataBatch { messages, .. } => {
            assert_eq!(messages.len(), 2);
            assert_eq!(messages[0].payload[0], 0xaa);
            assert_eq!(messages[1].payload[0], 0xbb);
        }
        event => panic!("expected bulk endpoint event batch, got {event:?}"),
    }
    assert_eq!(event_tx.queued_messages(), 0);
}

#[test]
fn endpoint_event_queue_drops_bulk_when_full_without_blocking_priority() {
    let (event_tx, mut event_rx) = EndpointEventSender::channel(1);
    let source = PeerIdentity::from_pubkey_full(Identity::generate().pubkey_full());

    event_tx
        .send(NodeEndpointEvent::Data {
            source_peer: source,
            payload: vec![0xaa; ENDPOINT_EVENT_PRIORITY_MAX_LEN + 1].into(),
            queued_at: crate::perf_profile::stamp(),
        })
        .expect("first bulk endpoint event should enqueue");
    assert_eq!(event_tx.queued_messages(), 1);

    event_tx
        .send(NodeEndpointEvent::Data {
            source_peer: source,
            payload: vec![0xbb; ENDPOINT_EVENT_PRIORITY_MAX_LEN + 1].into(),
            queued_at: crate::perf_profile::stamp(),
        })
        .expect("full bulk endpoint lane should drop rather than fail");
    assert_eq!(
        event_tx.queued_messages(),
        1,
        "dropped bulk event should roll back queued message accounting"
    );

    event_tx
        .send(NodeEndpointEvent::Data {
            source_peer: source,
            payload: b"priority".to_vec().into(),
            queued_at: crate::perf_profile::stamp(),
        })
        .expect("priority endpoint event should keep reserved progress");
    assert_eq!(event_tx.queued_messages(), 2);

    match event_rx.try_recv().expect("priority event") {
        NodeEndpointEvent::Data { payload, .. } => assert_eq!(payload, b"priority"),
        event => panic!("expected priority data event, got {event:?}"),
    }
    assert_eq!(event_tx.queued_messages(), 1);

    match event_rx.try_recv().expect("first bulk event") {
        NodeEndpointEvent::Data { payload, .. } => assert_eq!(payload[0], 0xaa),
        event => panic!("expected bulk data event, got {event:?}"),
    }
    assert_eq!(event_tx.queued_messages(), 0);
    assert!(matches!(
        event_rx.try_recv(),
        Err(tokio::sync::mpsc::error::TryRecvError::Empty)
    ));
}

#[test]
fn endpoint_event_queue_dropped_bulk_batch_counts_as_success() {
    let (event_tx, mut event_rx) = EndpointEventSender::channel(2);
    let source = PeerIdentity::from_pubkey_full(Identity::generate().pubkey_full());

    event_tx
        .send(NodeEndpointEvent::DataBatch {
            messages: vec![
                EndpointDataDelivery::new(source, vec![0xaa; ENDPOINT_EVENT_PRIORITY_MAX_LEN + 1]),
                EndpointDataDelivery::new(source, vec![0xab; ENDPOINT_EVENT_PRIORITY_MAX_LEN + 2]),
            ],
            queued_at: crate::perf_profile::stamp(),
        })
        .expect("first bulk endpoint batch should enqueue");
    assert_eq!(event_tx.queued_messages(), 2);
    assert_eq!(event_tx.bulk_queued_messages(), 2);

    event_tx
        .send(NodeEndpointEvent::DataBatch {
            messages: vec![
                EndpointDataDelivery::new(source, vec![0xba; ENDPOINT_EVENT_PRIORITY_MAX_LEN + 1]),
                EndpointDataDelivery::new(source, vec![0xbb; ENDPOINT_EVENT_PRIORITY_MAX_LEN + 2]),
            ],
            queued_at: crate::perf_profile::stamp(),
        })
        .expect("full bulk endpoint lane should drop batch rather than fail");
    assert_eq!(
        event_tx.queued_messages(),
        2,
        "dropped bulk batch should roll back all message accounting"
    );
    assert_eq!(event_tx.bulk_queued_messages(), 2);

    match event_rx.try_recv().expect("first bulk batch") {
        NodeEndpointEvent::DataBatch { messages, .. } => {
            assert_eq!(messages.len(), 2);
            assert_eq!(messages[0].payload[0], 0xaa);
            assert_eq!(messages[1].payload[0], 0xab);
        }
        event => panic!("expected bulk endpoint event batch, got {event:?}"),
    }
    assert_eq!(event_tx.queued_messages(), 0);
    assert_eq!(event_tx.bulk_queued_messages(), 0);
    assert!(matches!(
        event_rx.try_recv(),
        Err(tokio::sync::mpsc::error::TryRecvError::Empty)
    ));
}

#[test]
fn endpoint_event_queue_partially_admits_bulk_batch_at_message_boundary() {
    let (event_tx, mut event_rx) = EndpointEventSender::channel(3);
    let source = PeerIdentity::from_pubkey_full(Identity::generate().pubkey_full());

    event_tx
        .send(NodeEndpointEvent::DataBatch {
            messages: vec![
                EndpointDataDelivery::new(source, vec![0xaa; ENDPOINT_EVENT_PRIORITY_MAX_LEN + 1]),
                EndpointDataDelivery::new(source, vec![0xab; ENDPOINT_EVENT_PRIORITY_MAX_LEN + 2]),
            ],
            queued_at: crate::perf_profile::stamp(),
        })
        .expect("first bulk endpoint batch should enqueue");
    assert_eq!(event_tx.bulk_queued_messages(), 2);

    event_tx
        .send(NodeEndpointEvent::DataBatch {
            messages: vec![
                EndpointDataDelivery::new(source, vec![0xba; ENDPOINT_EVENT_PRIORITY_MAX_LEN + 1]),
                EndpointDataDelivery::new(source, vec![0xbb; ENDPOINT_EVENT_PRIORITY_MAX_LEN + 2]),
            ],
            queued_at: crate::perf_profile::stamp(),
        })
        .expect("second bulk endpoint batch should partially admit");
    assert_eq!(event_tx.queued_messages(), 3);
    assert_eq!(event_tx.bulk_queued_messages(), 3);

    match event_rx.try_recv().expect("first bulk batch") {
        NodeEndpointEvent::DataBatch { messages, .. } => {
            assert_eq!(messages.len(), 2);
            assert_eq!(messages[0].payload[0], 0xaa);
            assert_eq!(messages[1].payload[0], 0xab);
        }
        event => panic!("expected first bulk endpoint batch, got {event:?}"),
    }
    match event_rx.try_recv().expect("partially admitted bulk event") {
        NodeEndpointEvent::Data { payload, .. } => assert_eq!(payload[0], 0xba),
        event => panic!("expected split bulk data event, got {event:?}"),
    }
    assert_eq!(event_tx.queued_messages(), 0);
    assert_eq!(event_tx.bulk_queued_messages(), 0);
    assert!(matches!(
        event_rx.try_recv(),
        Err(tokio::sync::mpsc::error::TryRecvError::Empty)
    ));
}

#[test]
fn endpoint_event_bulk_capacity_counts_messages_not_batches() {
    let (event_tx, mut event_rx) = EndpointEventSender::channel(1);
    let source = PeerIdentity::from_pubkey_full(Identity::generate().pubkey_full());

    event_tx
        .send(NodeEndpointEvent::DataBatch {
            messages: vec![
                EndpointDataDelivery::new(source, vec![0xaa; ENDPOINT_EVENT_PRIORITY_MAX_LEN + 1]),
                EndpointDataDelivery::new(source, vec![0xab; ENDPOINT_EVENT_PRIORITY_MAX_LEN + 2]),
            ],
            queued_at: crate::perf_profile::stamp(),
        })
        .expect("oversized bulk endpoint batch should split rather than fail");
    assert_eq!(
        event_tx.queued_messages(),
        1,
        "oversized bulk batch should admit the headroom-sized prefix"
    );
    assert_eq!(event_tx.bulk_queued_messages(), 1);
    match event_rx.try_recv().expect("admitted split bulk event") {
        NodeEndpointEvent::Data { payload, .. } => assert_eq!(payload[0], 0xaa),
        event => panic!("expected split bulk data event, got {event:?}"),
    }
    assert_eq!(event_tx.queued_messages(), 0);
    assert_eq!(event_tx.bulk_queued_messages(), 0);

    event_tx
        .send(NodeEndpointEvent::Data {
            source_peer: source,
            payload: b"priority".to_vec().into(),
            queued_at: crate::perf_profile::stamp(),
        })
        .expect("priority endpoint event should keep reserved progress");
    assert_eq!(event_tx.queued_messages(), 1);
    assert_eq!(event_tx.bulk_queued_messages(), 0);
    match event_rx.try_recv().expect("priority event") {
        NodeEndpointEvent::Data { payload, .. } => assert_eq!(payload, b"priority"),
        event => panic!("expected priority data event, got {event:?}"),
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
