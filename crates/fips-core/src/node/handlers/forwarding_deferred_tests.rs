fn pending_test_forward(owner: u8, source: u8, dest: u8) -> PreparedSessionForward {
    PreparedSessionForward {
        permit: None,
        ingress_peer: NodeAddr::from_bytes([source; 16]),
        next_hop_addr: NodeAddr::from_bytes([owner; 16]),
        src_addr: NodeAddr::from_bytes([source; 16]),
        dest_addr: NodeAddr::from_bytes([dest; 16]),
        outgoing_ce: false,
        received_len: 100,
        encoded_len: 101,
        plaintext: PacketBuffer::default(),
    }
}

#[derive(Debug, Default)]
struct CompletionAudit(std::sync::Mutex<Vec<crate::node::ForwardingOutcome>>);

impl crate::node::ForwardingPolicy for CompletionAudit {
    fn admit(&self, _: &crate::node::ForwardingRequest<'_>) -> Option<u64> {
        Some(7)
    }

    fn complete(&self, token: u64, outcome: crate::node::ForwardingOutcome) {
        assert_eq!(token, 7);
        self.0.lock().unwrap().push(outcome);
    }
}

fn admitted_test_forward(
    node: &Node,
    audit: &std::sync::Arc<CompletionAudit>,
) -> PreparedSessionForward {
    let mut forward = pending_test_forward(1, 2, 3);
    let policy: std::sync::Arc<dyn crate::node::ForwardingPolicy> = audit.clone();
    forward.permit = crate::node::forwarding_policy::ForwardingPermit::admit(
        &policy,
        &crate::node::ForwardingRequest {
            ingress: crate::PeerIdentity::from_pubkey_full(node.identity().pubkey_full()),
            next_hop: forward.next_hop_addr,
            source: forward.src_addr,
            destination: forward.dest_addr,
            session_payload: b"opaque-test-payload",
        },
    );
    forward
}

#[tokio::test]
async fn forwarding_policy_completes_success_error_abort_and_teardown_once() {
    use crate::node::ForwardingOutcome::{Submitted, Unconfirmed};
    let mut node = Node::new(crate::Config::new()).unwrap();
    let audit = std::sync::Arc::new(CompletionAudit::default());
    let replacement = std::sync::Arc::new(CompletionAudit::default());

    let success = admitted_test_forward(&node, &audit);
    node.set_forwarding_policy(Some(replacement.clone()));
    node.finish_prepared_session_forward(success, Ok(()), false)
        .await;
    assert_eq!(*audit.0.lock().unwrap(), vec![Submitted]);
    assert!(
        replacement.0.lock().unwrap().is_empty(),
        "completion belongs to the admitting policy"
    );

    let failure = admitted_test_forward(&node, &audit);
    let next_hop = failure.next_hop_addr;
    node.finish_prepared_session_forward(
        failure,
        Err(NodeError::SendFailed {
            node_addr: next_hop,
            reason: "test transport error".to_string(),
        }),
        false,
    )
    .await;

    let aborted = admitted_test_forward(&node, &audit);
    node.deferred_session_forwards
        .insert(1, aborted, ForwardingLane::Bulk);
    node.abort_deferred_session_forwards("test cancellation")
        .await;

    let queued = admitted_test_forward(&node, &audit);
    node.deferred_session_forwards
        .insert(2, queued, ForwardingLane::Bulk);
    drop(node);
    assert_eq!(
        *audit.0.lock().unwrap(),
        vec![Submitted, Unconfirmed, Unconfirmed, Unconfirmed]
    );
}

#[test]
fn forwarding_window_bounds_saturated_owner_and_source_but_admits_peer() {
    let mut deferred = DeferredSessionForwards::default();
    for token in 0..FORWARDING_BULK_OWNER_IN_FLIGHT as u64 {
        deferred.insert(token, pending_test_forward(1, 2, 3), ForwardingLane::Bulk);
    }
    let saturated = pending_test_forward(1, 2, 3);
    assert!(!deferred.has_capacity(&saturated, ForwardingLane::Bulk));
    assert!(!deferred.has_capacity(&pending_test_forward(1, 5, 6), ForwardingLane::Bulk));
    assert!(!deferred.has_capacity(&pending_test_forward(4, 2, 6), ForwardingLane::Bulk));
    assert!(deferred.has_capacity(&pending_test_forward(4, 5, 6), ForwardingLane::Bulk,));
    assert!(deferred.has_capacity(&saturated, ForwardingLane::Priority));
    for token in 1_000..1_000 + FORWARDING_PRIORITY_OWNER_IN_FLIGHT as u64 {
        deferred.insert(
            token,
            pending_test_forward(1, 2, 3),
            ForwardingLane::Priority,
        );
    }
    assert!(!deferred.has_capacity(&saturated, ForwardingLane::Priority));
}

#[derive(Debug)]
struct ClassifiedAudit {
    class: crate::node::ForwardingClass,
    completions: std::sync::Arc<CompletionAudit>,
}

impl crate::node::ForwardingPolicy for ClassifiedAudit {
    fn admit(&self, _: &crate::node::ForwardingRequest<'_>) -> Option<u64> {
        panic!("core must use the atomic classified admission")
    }

    fn admit_classified(
        &self,
        _: &crate::node::ForwardingRequest<'_>,
    ) -> Option<crate::node::ForwardingAdmission> {
        Some(crate::node::ForwardingAdmission {
            token: 7,
            class: self.class,
        })
    }

    fn complete(&self, token: u64, outcome: crate::node::ForwardingOutcome) {
        crate::node::ForwardingPolicy::complete(self.completions.as_ref(), token, outcome);
    }
}

#[test]
fn local_admission_class_overrides_remote_control_shapes_and_keeps_completion() {
    use crate::node::ForwardingClass;
    use crate::node::session_wire::{FSP_FLAG_CP, FSP_FLAG_U, build_fsp_header};
    let node = Node::new(crate::Config::new()).unwrap();
    for (class, lane) in [
        (ForwardingClass::Normal, ForwardingLane::Bulk),
        (ForwardingClass::Background, ForwardingLane::Background),
    ] {
        let audit = std::sync::Arc::new(CompletionAudit::default());
        let policy: std::sync::Arc<dyn crate::node::ForwardingPolicy> =
            std::sync::Arc::new(ClassifiedAudit {
                class,
                completions: audit.clone(),
            });
        for flags in [0, FSP_FLAG_CP, FSP_FLAG_U] {
            let mut forward = pending_test_forward(1, 2, 3);
            let opaque = build_fsp_header(1, flags, 0).to_vec();
            forward.plaintext = PacketBuffer::new(
                SessionDatagram::new(forward.src_addr, forward.dest_addr, opaque.clone()).encode(),
            );
            if flags != 0 {
                assert_eq!(forwarding_lane(&forward), ForwardingLane::Priority);
            }
            forward.permit = crate::node::forwarding_policy::ForwardingPermit::admit(
                &policy,
                &crate::node::ForwardingRequest {
                    ingress: crate::PeerIdentity::from_pubkey_full(node.identity().pubkey_full()),
                    next_hop: forward.next_hop_addr,
                    source: forward.src_addr,
                    destination: forward.dest_addr,
                    session_payload: &opaque,
                },
            );
            assert_eq!(forwarding_lane(&forward), lane);
            drop(forward);
        }
        assert_eq!(
            *audit.0.lock().unwrap(),
            vec![crate::node::ForwardingOutcome::Unconfirmed; 3]
        );
    }
}

#[test]
fn background_forwarding_cannot_fill_normal_or_control_in_flight_reserves() {
    let mut deferred = DeferredSessionForwards::default();
    for token in 0..FORWARDING_BACKGROUND_GLOBAL_IN_FLIGHT as u64 {
        deferred.insert(
            token,
            pending_test_forward(token as u8, token as u8, 90),
            ForwardingLane::Background,
        );
    }
    let waiting = pending_test_forward(0, 0, 90);
    assert!(!deferred.has_capacity(&waiting, ForwardingLane::Background));
    assert!(!deferred.has_capacity(
        &pending_test_forward(91, 92, 93),
        ForwardingLane::Background
    ));
    assert!(deferred.has_capacity(&waiting, ForwardingLane::Bulk));
    assert!(deferred.has_capacity(&waiting, ForwardingLane::Priority));
    drop(deferred.take_pending(0).unwrap());
    assert!(deferred.has_capacity(&waiting, ForwardingLane::Background));
}

#[tokio::test(start_paused = true)]
async fn background_overflow_returns_to_receive_loop_without_draining_free_backlog() {
    let mut node = Node::new(crate::Config::new()).unwrap();
    for token in 0..FORWARDING_BACKGROUND_OWNER_IN_FLIGHT as u64 {
        node.deferred_session_forwards.insert(
            token,
            pending_test_forward(1, 2, 3),
            ForwardingLane::Background,
        );
    }
    let audit = std::sync::Arc::new(CompletionAudit::default());
    let policy: std::sync::Arc<dyn crate::node::ForwardingPolicy> =
        std::sync::Arc::new(ClassifiedAudit {
            class: crate::node::ForwardingClass::Background,
            completions: audit.clone(),
        });
    let mut forward = pending_test_forward(1, 2, 3);
    forward.permit = crate::node::forwarding_policy::ForwardingPermit::admit(
        &policy,
        &crate::node::ForwardingRequest {
            ingress: crate::PeerIdentity::from_pubkey_full(node.identity().pubkey_full()),
            next_hop: forward.next_hop_addr,
            source: forward.src_addr,
            destination: forward.dest_addr,
            session_payload: b"free overflow",
        },
    );
    let mut waiting = vec![forward];
    tokio::time::timeout(
        Duration::from_millis(1),
        node.flush_prepared_session_forwards(&mut waiting),
    )
    .await
    .expect("free backlog must not make the receive loop wait for completion");
    assert!(waiting.is_empty());
    assert_eq!(
        node.deferred_session_forwards.pending_len(),
        FORWARDING_BACKGROUND_OWNER_IN_FLIGHT
    );
    assert_eq!(
        *audit.0.lock().unwrap(),
        vec![crate::node::ForwardingOutcome::Unconfirmed]
    );
    assert_eq!(node.stats().forwarding.drop_send_error_packets, 1);
    let snapshot = node.stats().forwarding.snapshot();
    assert_eq!(snapshot.drop_background_full_packets, 1);
    assert_eq!(snapshot.drop_background_full_bytes, 100);
}

#[test]
fn deferred_forward_receipts_complete_out_of_order_without_count_leaks() {
    let mut deferred = DeferredSessionForwards::default();
    for token in 1..=3 {
        deferred.insert(
            token,
            pending_test_forward(token as u8, token as u8, 9),
            ForwardingLane::Bulk,
        );
    }
    for token in [3, 1, 2] {
        let forward = deferred.take_pending(token).expect("pending forward");
        deferred.push_completed(forward, Ok(()));
    }
    assert!(deferred.take_pending(999).is_none());
    assert_eq!(deferred.pending_len(), 0);
    assert!(deferred.window.is_empty());
    let completed_owners: Vec<_> = std::iter::from_fn(|| deferred.pop_completed())
        .map(|(forward, _)| forward.next_hop_addr)
        .collect();
    assert_eq!(
        completed_owners,
        vec![
            NodeAddr::from_bytes([3; 16]),
            NodeAddr::from_bytes([1; 16]),
            NodeAddr::from_bytes([2; 16]),
        ]
    );
}

#[tokio::test]
async fn shutdown_abort_finishes_every_forward_and_matches_stats() {
    let mut node = Node::new(crate::Config::new()).expect("test node");
    node.deferred_session_forwards
        .insert(1, pending_test_forward(1, 2, 3), ForwardingLane::Bulk);
    node.deferred_session_forwards.insert(
        2,
        pending_test_forward(4, 5, 6),
        ForwardingLane::Priority,
    );

    assert_eq!(
        node.abort_deferred_session_forwards("test shutdown").await,
        2
    );
    assert_eq!(node.deferred_session_forwards.pending_len(), 0);
    assert!(node.deferred_session_forwards.window.is_empty());
    assert!(node.deferred_session_forwards.completed.is_empty());
    assert_eq!(node.stats().forwarding.drop_send_error_packets, 2);
}

#[tokio::test(start_paused = true)]
async fn background_backlog_survives_control_drains_and_completes_once() {
    for with_orphan_foreground in [false, true] {
        let mut node = Node::new(crate::Config::new()).unwrap();
        let audit = std::sync::Arc::new(CompletionAudit::default());
        for token in 0..FORWARDING_BACKGROUND_OWNER_IN_FLIGHT as u64 {
            let forward = admitted_test_forward(&node, &audit);
            node.deferred_session_forwards
                .insert(token, forward, ForwardingLane::Background);
        }
        if with_orphan_foreground {
            node.deferred_session_forwards.insert(
                100,
                pending_test_forward(4, 5, 6),
                ForwardingLane::Priority,
            );
        }
        let endpoint = node.attach_endpoint_data_io(1).unwrap();
        let mut control = node.endpoint_control_rx.take().unwrap();
        let (response_tx, response_rx) = tokio::sync::oneshot::channel();
        endpoint
            .control_tx
            .send(crate::node::NodeEndpointControlCommand::PeerSnapshot { response_tx })
            .await
            .unwrap();
        let bound = if with_orphan_foreground {
            Duration::from_secs(2)
        } else {
            Duration::from_millis(1)
        };
        tokio::time::timeout(bound, async {
            node.drain_deferred_session_forwards().await;
            assert!(
                node.handle_endpoint_control(control.recv().await.unwrap())
                    .await
                    .is_none()
            );
            assert!(response_rx.await.unwrap().is_empty());
        })
        .await
        .expect("background work must not hold up endpoint control");
        assert_eq!(
            node.deferred_session_forwards.pending_len(),
            FORWARDING_BACKGROUND_OWNER_IN_FLIGHT
        );
        assert!(audit.0.lock().unwrap().is_empty());
        assert_eq!(
            node.stats().forwarding.drop_send_error_packets,
            u64::from(with_orphan_foreground)
        );

        let sent = node.deferred_session_forwards.take_pending(0).unwrap();
        node.deferred_session_forwards.push_completed(sent, Ok(()));
        node.finish_completed_session_forwards().await;
        node.abort_deferred_session_forwards("test shutdown").await;
        let outcomes = audit.0.lock().unwrap();
        assert_eq!(outcomes.len(), FORWARDING_BACKGROUND_OWNER_IN_FLIGHT);
        assert_eq!(outcomes[0], crate::node::ForwardingOutcome::Submitted);
        assert!(
            outcomes[1..]
                .iter()
                .all(|outcome| *outcome == crate::node::ForwardingOutcome::Unconfirmed)
        );
        assert!(node.deferred_session_forwards.window.is_empty());
    }
}

#[tokio::test(start_paused = true)]
async fn orphan_forward_receipt_does_not_block_queued_endpoint_peer_snapshot() {
    let mut node = Node::new(crate::Config::new()).expect("test node");
    let endpoint_io = node
        .attach_endpoint_data_io(1)
        .expect("endpoint I/O should attach");
    let mut endpoint_control_rx = node
        .endpoint_control_rx
        .take()
        .expect("endpoint control receiver should attach");
    node.deferred_session_forwards.insert(
        1,
        pending_test_forward(1, 2, 3),
        ForwardingLane::Priority,
    );

    let (response_tx, response_rx) = tokio::sync::oneshot::channel();
    endpoint_io
        .control_tx
        .send(crate::node::NodeEndpointControlCommand::PeerSnapshot { response_tx })
        .await
        .expect("peer snapshot should queue behind forwarding drain");

    let queued_snapshot = async move {
        let drained = node.drain_deferred_session_forwards().await;
        let command = endpoint_control_rx
            .recv()
            .await
            .expect("queued endpoint control command");
        assert!(node.handle_endpoint_control(command).await.is_none());
        let peers = response_rx.await.expect("peer snapshot response");
        (node, drained, peers)
    };
    let (node, drained, peers) =
        tokio::time::timeout(std::time::Duration::from_secs(2), queued_snapshot)
            .await
            .expect("orphan forwarding receipt must not starve endpoint control");

    assert_eq!(drained, 1);
    assert!(peers.is_empty());
    assert_eq!(node.deferred_session_forwards.pending_len(), 0);
    assert!(node.deferred_session_forwards.window.is_empty());
    assert!(node.deferred_session_forwards.completed.is_empty());
    assert_eq!(node.stats().forwarding.drop_send_error_packets, 1);
}

#[tokio::test]
async fn queued_forward_survives_unrelated_priority_completion_turns() {
    use crate::dataplane::{
        ActivityTick, DataplaneLiveOutboundFirsts, DataplaneLiveOwnerRoutes, OutboundPacket,
        OwnerConfig, OwnerCryptoKeys, OwnerId, PacketClass, TransportPath,
    };
    use crate::transport::{TransportAddr, TransportHandle, TransportId};

    let mut node = Node::new(crate::Config::new()).unwrap();
    let audit = std::sync::Arc::new(CompletionAudit::default());
    let forward = admitted_test_forward(&node, &audit);
    let owner = OwnerId::fmp_node(forward.next_hop_addr);
    let transport_id = TransportId::new(181);
    let (recv_tx, mut recv_rx) = crate::transport::packet_channel(64);
    let mut receiver = crate::transport::udp::UdpTransport::new(
        TransportId::new(182),
        None,
        crate::config::UdpConfig {
            bind_addr: Some("127.0.0.1:0".into()),
            mtu: Some(1400),
            ..Default::default()
        },
        recv_tx,
    );
    receiver.start_async().await.unwrap();
    let remote = TransportAddr::from_string(&receiver.local_addr().unwrap().to_string());
    let (send_tx, _send_rx) = crate::transport::packet_channel(64);
    let mut sender = TransportHandle::Udp(crate::transport::udp::UdpTransport::new(
        transport_id,
        None,
        crate::config::UdpConfig {
            bind_addr: Some("127.0.0.1:0".into()),
            mtu: Some(1400),
            ..Default::default()
        },
        send_tx,
    ));
    sender.start().await.unwrap();
    node.transports.insert(transport_id, sender);
    node.dataplane.register_owner(
        owner,
        OwnerConfig::new(1, 64).with_fmp_session_start_ms(1_000),
    );
    let key = std::sync::Arc::new(ring::aead::LessSafeKey::new(
        ring::aead::UnboundKey::new(&ring::aead::CHACHA20_POLY1305, &[9; 32]).unwrap(),
    ));
    node.dataplane
        .install_owner_fmp_session_routes(
            owner,
            OwnerConfig::new(1, 64).with_fmp_session_start_ms(1_000),
            OwnerCryptoKeys::new(key.clone(), key),
            TransportPath::live(transport_id, remote),
            DataplaneLiveOwnerRoutes::new(),
        )
        .unwrap();

    let mut outbound: Vec<_> = (0..16)
        .map(|n| {
            OutboundPacket::fmp(
                owner,
                1,
                PacketClass::Liveness,
                181,
                0,
                PacketBuffer::new(vec![n as u8; 8]),
            )
            .with_activity_tick(ActivityTick::new(1_234))
        })
        .collect();
    let payload =
        SessionDatagram::new(forward.src_addr, forward.dest_addr, vec![0x42; 1248]).encode();
    outbound.push(
        OutboundPacket::fmp(
            owner,
            1,
            PacketClass::Bulk,
            181,
            0,
            PacketBuffer::new(payload),
        )
        .with_activity_tick(ActivityTick::new(1_234))
        .with_send_token(999),
    );
    node.deferred_session_forwards
        .insert(999, forward, ForwardingLane::Bulk);
    let first = node
        .pump_dataplane_pending_outbound_firsts(
            DataplaneLiveOutboundFirsts {
                initial_outbound_batch: outbound,
                collect_transport_sent_receipts: true,
                ..Default::default()
            },
            0,
            0,
            0,
        )
        .await;
    assert_eq!(first.summary().outbound_admitted(), 17);

    node.drain_deferred_session_forwards().await;
    assert!(
        audit.0.lock().unwrap().is_empty(),
        "queued forward must not be declared failed because unrelated priority work completed first"
    );
    assert_eq!(node.deferred_session_forwards.pending_len(), 1);
    for _ in 0..40 {
        node.drain_one_deferred_session_forward_turn().await;
        if !node.has_deferred_session_forwards() {
            break;
        }
    }
    assert_eq!(
        *audit.0.lock().unwrap(),
        vec![crate::node::ForwardingOutcome::Submitted]
    );
    assert_eq!(node.stats().forwarding.drop_send_error_packets, 0);
    tokio::time::timeout(Duration::from_secs(1), async {
        while let Some(packet) = recv_rx.recv().await {
            if packet.data.len() == 1320 {
                return;
            }
        }
        panic!("UDP receiver closed before the forwarded record arrived");
    })
    .await
    .expect("the admitted opaque session record must reach the real UDP receiver");
    node.transports
        .get_mut(&transport_id)
        .unwrap()
        .stop()
        .await
        .unwrap();
    receiver.stop_async().await.unwrap();
}
