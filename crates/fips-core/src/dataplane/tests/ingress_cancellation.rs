use super::*;
use std::time::Duration;

fn stage_completed_packets(node: &mut DataplaneLiveNode, expected: usize) {
    let prepared = capture_prepared_work(&mut node.driver.mover, 8);
    assert_eq!(prepared.len(), expected);
    let mut slots = prepared
        .into_iter()
        .map(execute_test_prepared_crypto_work)
        .map(CryptoReadySlot::completed)
        .collect();
    node.driver.mover.stage_retire_slots(&mut slots);
}

async fn cancelled_send_preserves_ingress(direct: bool, another_send: bool) {
    let network_name = format!("ingress-cancellation-{direct}-{another_send}");
    let network = crate::SimNetwork::new(0xc1);
    network.set_node_send_completion_delay("sender", 60_000);
    crate::register_sim_network(&network_name, network.clone());
    let transport_id = TransportId::new(0xc1);
    let (packet_tx, _packet_rx) = crate::transport::packet_channel(1);
    let mut transport = TransportHandle::Sim(crate::SimTransport::new(
        transport_id,
        None,
        crate::SimTransportConfig {
            network: Some(network_name.clone()),
            addr: Some("sender".to_string()),
            ..Default::default()
        },
        packet_tx,
    ));
    transport.start().await.unwrap();
    let mut transports = HashMap::from([(transport_id, transport)]);
    let received = Arc::new(std::sync::Mutex::new(Vec::new()));
    let mut endpoint = crate::Node::new(crate::Config::new()).unwrap();
    let endpoint_io = if direct {
        let received = received.clone();
        endpoint.attach_endpoint_data_io_with_direct_sink(
            8,
            EndpointDirectSink::new(move |batch: crate::FipsEndpointDirectPacketBatch| {
                for run in batch.into_packet_runs() {
                    received
                        .lock()
                        .unwrap()
                        .extend(run.packet_slices().map(<[u8]>::to_vec));
                }
                Ok::<(), crate::FipsEndpointDirectDeliveryError>(())
            }),
        )
    } else {
        endpoint.attach_endpoint_data_io(8)
    }
    .unwrap();
    let mut node = DataplaneLiveNode::new(AdmissionConfig::new(4, 8));
    let source_peer = PeerIdentity::from_pubkey_full(crate::Identity::generate().pubkey_full());
    let source = *source_peer.node_addr();
    let receive_owner = OwnerId::fsp_node(source);
    let send_owner = fmp_owner(0xc2);
    register_keyed_owner(
        &mut node.driver,
        receive_owner,
        OwnerConfig::new(1, 8).with_source_peer(source_peer),
        0xc1,
    );
    register_keyed_owner(&mut node.driver, send_owner, OwnerConfig::new(1, 8), 0xc2);
    node.driver
        .owner_mut(send_owner)
        .unwrap()
        .set_active_path(TransportPath::live(
            transport_id,
            TransportAddr::from_string("receiver"),
        ));
    let outbound = || {
        OutboundPacket::fmp(
            send_owner,
            1,
            PacketClass::Bulk,
            0xc2,
            0,
            PacketBuffer::new(b"unrelated outbound".to_vec()),
        )
    };
    submit_endpoint_data_payload(
        &mut node.driver.mover,
        EndpointDataSubmit {
            owner: receive_owner,
            counter: 1,
            timestamp: 123,
            key: 0xc1,
            previous_hop: send_owner.node_addr(),
            local_addr: *endpoint.node_addr(),
            payload: b"received once",
        },
    );
    node.driver
        .mover
        .submit_outbound_packet(outbound())
        .unwrap();
    stage_completed_packets(&mut node, 2);

    // The simulated carrier records submission before blocking completion.
    // Dropping this polled future cancels at that exact production await.
    {
        let turn = pump_live_node_outbound_firsts(
            &mut node,
            DataplaneLiveOutboundFirsts::default(),
            &endpoint_io.event_tx,
            &transports,
            8,
            8,
        );
        tokio::pin!(turn);
        assert!(futures::poll!(&mut turn).is_pending());
        assert_eq!(network.stats().packets_sent, 1);
    }
    let counters = node
        .driver
        .owner_fsp_activity(receive_owner)
        .unwrap()
        .traffic_counters();
    assert_eq!(
        counters.1, 1,
        "received DATA was authenticated before cancellation"
    );
    assert_eq!(received.lock().unwrap().len(), usize::from(direct));

    // Even another ready slow send must not hold the retained receive hostage.
    if another_send {
        node.driver
            .mover
            .submit_outbound_packet(outbound())
            .unwrap();
        stage_completed_packets(&mut node, 1);
    }
    let mut resumed = tokio::time::timeout(
        Duration::from_millis(100),
        pump_live_node_outbound_firsts(
            &mut node,
            DataplaneLiveOutboundFirsts {
                initial_outbound: another_send.then(outbound),
                ..Default::default()
            },
            &endpoint_io.event_tx,
            &transports,
            8,
            8,
        ),
    )
    .await
    .expect("retained ingress must return before another slow send");
    let ingress = resumed.take_fsp_authenticated_ingress();
    if direct {
        assert_eq!(ingress.endpoint_data_packet_count(), 1);
        let (_, mut batches, sessions) = ingress.into_parts();
        assert!(sessions.is_empty());
        assert_eq!(batches.len(), 1);
        assert_eq!(batches[0].commit_runs()[0].len(), 1);
        assert!(!batches[0].has_direct_packet_runs());
        assert!(
            batches[0]
                .take_direct_packet_batch()
                .into_packet_runs()
                .is_empty()
        );
    } else {
        let (_, batches, sessions) = ingress.into_parts();
        assert!(batches.is_empty());
        assert_eq!(sessions.len(), 1);
        let (addr, _, _, _, _, _, _, _, plaintext) =
            sessions.into_iter().next().unwrap().into_parts();
        assert_eq!(addr, source);
        assert_eq!(
            &plaintext.as_slice()[FSP_INNER_HEADER_SIZE..],
            b"received once"
        );
    }
    assert_eq!(
        network.stats().packets_sent,
        1,
        "no ambiguous send is retried"
    );
    assert_eq!(
        resumed.summary().outbound_admitted(),
        usize::from(another_send),
        "fresh firsts stay queued"
    );
    assert_eq!(resumed.summary().dispatched(), 0);
    assert_eq!(
        node.driver
            .owner_fsp_activity(receive_owner)
            .unwrap()
            .traffic_counters(),
        counters
    );

    network.set_node_send_completion_delay("sender", 0);
    let expected_sends = if another_send { 3 } else { 1 };
    for _ in 0..3 {
        let mut next = pump_live_node_outbound_firsts(
            &mut node,
            DataplaneLiveOutboundFirsts::default(),
            &endpoint_io.event_tx,
            &transports,
            8,
            8,
        )
        .await;
        assert!(next.take_fsp_authenticated_ingress().is_empty());
        if network.stats().packets_sent == expected_sends {
            break;
        }
        wait_for_live_worker_completion(&node).await;
    }
    assert_eq!(
        network.stats().packets_sent,
        expected_sends,
        "queued sends still make progress"
    );
    assert_eq!(received.lock().unwrap().len(), usize::from(direct));
    transports
        .get_mut(&transport_id)
        .unwrap()
        .stop()
        .await
        .unwrap();
    crate::unregister_sim_network(&network_name);
}

#[tokio::test]
async fn authenticated_ingress_survives_cancelled_transport_send() {
    cancelled_send_preserves_ingress(false, false).await;
}

#[tokio::test]
async fn direct_ingress_commit_survives_cancelled_send_without_duplicate_delivery() {
    cancelled_send_preserves_ingress(true, false).await;
}

#[tokio::test]
async fn retained_ingress_returns_before_another_slow_send() {
    cancelled_send_preserves_ingress(false, true).await;
}
