//! Cancel a real send after delivery without dropping unvisited queued originals.
//! This isolates the production flush/retry handlers, not RX-loop scheduling.
use super::*;
use crate::config::{SimTransportConfig, TransportInstances};
use crate::node::tests::sim_discovery::configured_discovering_node;
use crate::node::tests::spanning_tree::process_dataplane_packet;
use crate::node::wire::{CommonPrefix, PHASE_ESTABLISHED};
use crate::node::{ForwardingOutcome, OriginatedSessionObserver, OriginatedSessionRequest};
use crate::{SimNetwork, register_sim_network, unregister_sim_network};
use futures::FutureExt;
use std::collections::BTreeSet;
use std::panic::AssertUnwindSafe;
use std::sync::{Arc, Mutex};

#[derive(Clone, Copy, Debug)]
enum Case {
    Endpoint,
    TunFresh,
    TunStale,
}

#[test]
fn canceled_endpoint_flush_retains_unvisited_batch_and_original_age() {
    run(Case::Endpoint);
}

#[test]
fn canceled_tun_flush_retains_and_retries_unvisited_originals() {
    run(Case::TunFresh);
}

#[test]
fn canceled_tun_flush_does_not_renew_unvisited_packet_age() {
    run(Case::TunStale);
}

// Evidence only. Returning no token leaves normal admission/accounting intact;
// this is not a replacement payment authorizer or a financial acceptance test.
#[derive(Debug)]
struct Carriers {
    destination: NodeAddr,
    application: Mutex<Vec<NodeAddr>>,
    first_envelope: Mutex<Option<Vec<u8>>>,
}

impl OriginatedSessionObserver for Carriers {
    fn observe(&self, request: &OriginatedSessionRequest<'_>) -> Option<u64> {
        if request.destination == self.destination && request.session_payload.len() >= 700 {
            self.application.lock().unwrap().push(request.next_hop);
            self.first_envelope
                .lock()
                .unwrap()
                .get_or_insert_with(|| request.session_payload.to_vec());
        }
        None
    }

    fn complete(&self, _: u64, _: ForwardingOutcome) {
        panic!("passive observer has no accounting reservation to complete");
    }
}

// Inspect a copy with the existing authenticated receive key. Neither replay
// state nor counters advance, and no key/cipher material is logged. Match the
// exact sealed FSP envelope selected by the passive observer, not global Sim
// counts: unrelated native upkeep can be delivered during the same turn.
fn selected_application_frame(
    receiver: &TestNode,
    source: &NodeAddr,
    observed: &Carriers,
    packet: &crate::transport::ReceivedPacket,
) -> Option<()> {
    let wire = packet.data.as_slice();
    if CommonPrefix::parse(wire)?.phase != PHASE_ESTABLISHED {
        return None;
    }
    let header = crate::dataplane::FmpWireHeader::parse_encrypted(wire).unwrap();
    let offset = usize::from(header.ciphertext_offset());
    let cipher = receiver
        .node
        .get_peer(source)?
        .noise_session()?
        .recv_cipher_clone()?;
    let mut nonce = [0; 12];
    nonce[4..].copy_from_slice(&header.counter().to_le_bytes());
    let mut encrypted = wire[offset..].to_vec();
    let body = cipher
        .open_in_place(
            ring::aead::Nonce::assume_unique_for_key(nonce),
            ring::aead::Aad::from(&wire[..offset]),
            &mut encrypted,
        )
        .unwrap();
    if body.get(4) != Some(&crate::protocol::LinkMessageType::SessionDatagram.to_byte()) {
        return None;
    }
    let datagram = SessionDatagram::decode(&body[5..]).unwrap();
    (datagram.src_addr == *source
        && datagram.dest_addr == observed.destination
        && observed.first_envelope.lock().unwrap().as_deref() == Some(datagram.payload.as_slice()))
    .then_some(())
}

fn run(case: Case) {
    run_large_stack_async_test("pending-flush-cancellation", move || async move {
        let name = format!("pending-flush-{}-{case:?}", std::process::id());
        let network = SimNetwork::new(307);
        register_sim_network(name.clone(), network.clone());
        let mut nodes = Vec::new();
        let result = AssertUnwindSafe(async {
            for address in ["source", "survivor", "departing", "destination"] {
                let mut config = Config::new();
                config.node.system_files_enabled = false;
                config.node.discovery.lan.enabled = false;
                config.node.discovery.nostr.enabled = false;
                config.node.discovery.local.enabled = false;
                // Match the existing source_routes/queued_retry fixture: the
                // explicit source carrier must survive unrelated tree changes.
                config.node.routing.mode = RoutingMode::ReplyLearned;
                config.transports.sim = TransportInstances::Single(SimTransportConfig {
                    network: Some(name.clone()),
                    addr: Some(address.to_string()),
                    auto_connect: Some(false),
                    ..Default::default()
                });
                nodes.push(configured_discovering_node(config, address).await);
            }
            exercise(&mut nodes, &network, case).await;
        })
        .catch_unwind()
        .await;
        for node in &nodes {
            network.set_node_send_completion_delay(node.addr.as_str().unwrap(), 0);
        }
        cleanup_nodes(&mut nodes).await;
        unregister_sim_network(&name);
        if let Err(panic) = result {
            std::panic::resume_unwind(panic);
        }
    });
}

async fn connect(nodes: &mut [TestNode], from: usize, to: usize) {
    let remote = PeerIdentity::from_pubkey_full(nodes[to].node.identity().pubkey_full());
    let address = nodes[to].addr.clone();
    let transport = nodes[from].transport_id;
    nodes[from]
        .node
        .initiate_connection(transport, address, remote)
        .await
        .unwrap();
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            turn(nodes).await;
            if nodes[from]
                .node
                .get_peer(nodes[to].node.node_addr())
                .is_some()
                && nodes[to]
                    .node
                    .get_peer(nodes[from].node.node_addr())
                    .is_some()
                && nodes.iter().all(|node| node.node.connection_count() == 0)
            {
                break;
            }
        }
    })
    .await
    .expect("real reciprocal Noise ownership");
}

async fn turn(nodes: &mut [TestNode]) {
    process_available_packets(nodes).await;
    for node in nodes.iter_mut() {
        node.node.check_mmp_reports().await;
        node.node.check_tree_state().await;
        node.node.check_bloom_state().await;
        node.node.send_pending_tree_announces().await;
        node.node.send_due_filter_announces().await;
    }
    process_available_packets(nodes).await;
    tokio::time::sleep(Duration::from_millis(5)).await;
}

#[derive(Debug, PartialEq, Eq)]
struct Owners {
    peers: Vec<(NodeAddr, LinkId, Option<SessionIndex>, u64)>,
    links: usize,
    indices: usize,
}

fn owners(nodes: &[TestNode]) -> Vec<Owners> {
    nodes
        .iter()
        .map(|node| {
            assert_eq!(node.node.connection_count(), 0);
            assert!(node.node.peer_count() <= 2 && node.node.link_count() <= 2);
            let mut peers = node
                .node
                .peers
                .iter()
                .map(|(addr, peer)| {
                    assert!(peer.is_healthy() && peer.can_send());
                    (
                        *addr,
                        peer.link_id(),
                        peer.our_index(),
                        peer.session_generation(),
                    )
                })
                .collect::<Vec<_>>();
            peers.sort_by_key(|peer| peer.0);
            Owners {
                peers,
                links: node.node.link_count(),
                indices: node.node.index_allocator.count(),
            }
        })
        .collect()
}

// Inspect existing batch timestamps by moving and returning the exact objects
// synchronously. No pending payload, timestamp, or ownership is manufactured.
fn endpoint_ages(node: &mut Node, dest: &NodeAddr) -> Vec<u64> {
    let Some(queue) = node.pending_session_traffic.take_endpoint_data(dest) else {
        return Vec::new();
    };
    let batches = queue.into_pending_payloads();
    let ages = batches.iter().map(|batch| batch.enqueued_at_ms()).collect();
    node.pending_session_traffic
        .restore_endpoint_data(*dest, batches);
    ages
}

async fn exercise(nodes: &mut [TestNode], network: &SimNetwork, case: Case) {
    for node in nodes.iter() {
        assert_eq!(node.node.config.node.session.pending_packets_per_dest, 16);
    }
    for (from, to) in [(0, 1), (1, 3), (0, 2), (2, 3)] {
        connect(nodes, from, to).await;
    }
    tokio::time::timeout(Duration::from_secs(8), async {
        while !nodes
            .iter()
            .all(|node| node.node.tree_state().root() == nodes[0].node.tree_state().root())
        {
            turn(nodes).await;
        }
    })
    .await
    .expect("native tree convergence");
    drain_to_quiescence(nodes).await;
    let peers = nodes
        .iter()
        .map(|node| PeerIdentity::from_pubkey_full(node.node.identity().pubkey_full()))
        .collect::<Vec<_>>();
    let source = *peers[0].node_addr();
    let destination = *peers[3].node_addr();
    let mut endpoint = nodes[3].node.attach_endpoint_data_io(32).unwrap();
    let (tun_tx, tun_rx) = crate::upper::tun::write_channel();
    nodes[3].node.tun_tx = Some(tun_tx);
    nodes[3]
        .node
        .set_endpoint_source_route(peers[0], Some(peers[1]))
        .unwrap();
    let observed = Arc::new(Carriers {
        destination,
        application: Mutex::new(Vec::new()),
        first_envelope: Mutex::new(None),
    });
    nodes[0]
        .node
        .set_originated_session_observer(Some(observed.clone()));

    // Establish genuine FSP and exercise both authenticated carriers before one
    // leaves. Binding an unknown/unusable identity is deliberately not allowed.
    for (relay, value) in [(1, 201), (2, 202)] {
        nodes[0]
            .node
            .set_endpoint_source_route(peers[3], Some(peers[relay]))
            .unwrap();
        send_endpoint_data_via_dataplane(&mut nodes[0].node, peers[3], vec![value; 700])
            .await
            .unwrap();
        let event = recv_endpoint_event_while_draining(
            nodes,
            &mut endpoint.event_rx,
            Duration::from_secs(5),
            "warm native FSP",
        )
        .await;
        endpoint.event_rx.release_messages(event.messages.len());
        assert_eq!(
            expect_single_endpoint_data_event(event).payload.as_slice(),
            vec![value; 700]
        );
        drain_to_quiescence(nodes).await;
    }
    let session_hash = *nodes[0]
        .node
        .get_session(&destination)
        .unwrap()
        .handshake_hash()
        .unwrap();
    let disconnect = crate::protocol::Disconnect::new(crate::protocol::DisconnectReason::Shutdown);
    nodes[2]
        .node
        .send_dataplane_fmp_link_plaintext(&source, &disconnect.encode(), false)
        .await
        .unwrap();
    tokio::time::timeout(Duration::from_secs(3), async {
        while nodes[0].node.get_peer(peers[2].node_addr()).is_some() {
            process_available_packets(nodes).await;
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("genuine bound-carrier departure");
    drain_to_quiescence(nodes).await;
    assert_eq!(
        nodes[0].node.source_routes.get(&destination),
        Some(peers[2].node_addr())
    );
    assert!(!nodes[0].node.has_application_next_hop(&destination));
    assert!(nodes[0].node.dataplane_has_fsp_owner(&destination));
    observed.application.lock().unwrap().clear();
    *observed.first_envelope.lock().unwrap() = None;

    let originals = (0..if matches!(case, Case::Endpoint) {
        16
    } else {
        3
    })
        .map(|id| vec![id; 700])
        .collect::<Vec<_>>();
    let queued_from = Node::now_ms();
    if matches!(case, Case::Endpoint) {
        // Two ingress batches, not an enlarged queue: the second batch is never
        // selected when completion of the first one-payload send is canceled.
        for payloads in [&originals[..1], &originals[1..]] {
            let batch = crate::node::NodeEndpointDataBatch::from_payloads(
                peers[3],
                payloads
                    .iter()
                    .cloned()
                    .map(|payload| {
                        crate::node::EndpointDataPayload::from_packet_payload(payload).unwrap()
                    })
                    .collect(),
                None,
            )
            .unwrap();
            nodes[0]
                .node
                .handle_endpoint_data_batch_no_established_flush(batch)
                .await;
        }
        assert_eq!(
            nodes[0]
                .node
                .pending_session_traffic
                .endpoint_data_for(&destination)
                .unwrap()
                .len(),
            16
        );
    } else {
        for payload in &originals {
            let packet = build_ipv6_packet(
                &crate::FipsAddress::from_node_addr(&source),
                &crate::FipsAddress::from_node_addr(&destination),
                payload,
            );
            send_tun_packet_via_dataplane(nodes, 0, packet).await;
        }
        assert_eq!(nodes[0].node.pending_session_traffic.tun_packet_count(), 3);
    }
    let queued_until = Node::now_ms();
    let ages = endpoint_ages(&mut nodes[0].node, &destination);
    if matches!(case, Case::Endpoint) {
        assert_eq!(ages.len(), 2);
        assert!(
            ages.iter()
                .all(|age| (queued_from..=queued_until).contains(age))
        );
    }
    assert!(
        observed.application.lock().unwrap().is_empty(),
        "no unauthorized fallback while bound carrier is absent"
    );
    assert!(matches!(
        endpoint.event_rx.try_recv(),
        Err(tokio::sync::mpsc::error::TryRecvError::Empty)
    ));
    assert!(matches!(
        tun_rx.try_recv_packet(),
        Err(std::sync::mpsc::TryRecvError::Empty)
    ));

    nodes[0]
        .node
        .set_endpoint_source_route(peers[3], Some(peers[1]))
        .unwrap();
    let retained = owners(nodes);
    let sender_address = nodes[0].addr.as_str().unwrap().to_string();
    network.set_node_send_completion_delay(&sender_address, 60_000);
    let delivered_before = network.stats().packets_delivered;
    let source_address = nodes[0].addr.clone();
    let mut held = Vec::new();
    {
        let (source_nodes, others) = nodes.split_at_mut(1);
        let receiver = &mut others[0];
        let flush = source_nodes[0].node.flush_pending_packets(&destination);
        tokio::pin!(flush);
        tokio::time::timeout(Duration::from_secs(1), async {
            tokio::select! {
                _ = &mut flush => panic!("flush must still await actual Sim send completion"),
                _ = async {
                    loop {
                        while let Ok(packet) = receiver.packet_rx.try_recv() {
                            let selected = packet.remote_addr == source_address
                                && selected_application_frame(receiver, &source, &observed, &packet).is_some();
                            assert!(held.len() < 32, "bounded carrier inspection");
                            held.push(packet);
                            if selected { return; }
                        }
                        tokio::time::sleep(Duration::from_millis(1)).await;
                    }
                } => {}
            }
        }).await.expect("first encrypted application send reaches the carrier");
        // Drop only the production flush, never the fixture's ingress wrapper.
    }
    network.set_node_send_completion_delay(&sender_address, 0);
    assert!(
        network.stats().packets_delivered > delivered_before,
        "the exact selected encrypted envelope reached its actual carrier"
    );
    assert_eq!(
        observed.application.lock().unwrap().as_slice(),
        [*peers[1].node_addr()]
    );

    // Deliver each inspected wire frame through ordinary authenticated ingress
    // exactly once. Do not process the source or retry its queue yet: prove the
    // selected original's receipt independently before checking untouched work.
    for packet in held {
        process_dataplane_packet(&mut nodes[1], packet).await;
    }
    tokio::time::timeout(Duration::from_secs(1), async {
        loop {
            process_available_packets(&mut nodes[1..]).await;
            if matches!(case, Case::Endpoint) {
                if let Ok(event) = endpoint.event_rx.try_recv() {
                    endpoint.event_rx.release_messages(event.messages.len());
                    assert_eq!(
                        expect_single_endpoint_data_event(event).payload.as_slice(),
                        originals[0]
                    );
                    break;
                }
            } else if let Ok(packet) = tun_rx.try_recv_packet() {
                let expected = build_ipv6_packet(
                    &crate::FipsAddress::from_node_addr(&source),
                    &crate::FipsAddress::from_node_addr(&destination),
                    &originals[0],
                );
                assert_eq!(packet.as_slice(), expected);
                break;
            }
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    })
    .await
    .expect("selected original actually reaches the destination before any retry");
    assert!(
        nodes[0]
            .node
            .pending_session_traffic
            .has_traffic_for(&destination),
        "canceled flush must retain unvisited destination work"
    );
    if matches!(case, Case::Endpoint) {
        assert_eq!(
            nodes[0]
                .node
                .pending_session_traffic
                .endpoint_data_for(&destination)
                .unwrap()
                .len(),
            15,
            "selected uncertain original is not automatically requeued"
        );
        assert_eq!(
            endpoint_ages(&mut nodes[0].node, &destination),
            ages[1..],
            "unvisited batch keeps its original ingress age"
        );
    } else {
        assert_eq!(
            nodes[0].node.pending_session_traffic.tun_packet_count(),
            2,
            "only the selected original may leave queue ownership"
        );
    }
    assert_eq!(owners(nodes), retained);

    if matches!(case, Case::TunStale) {
        // Established-session TUN ingress already stamped these originals.
        // Wait past their real, unchanged 2,000 ms ready-age budget. No traffic
        // processing/re-enqueue can renew that age while completion is absent.
        while Node::now_ms() <= queued_until.saturating_add(2_000) {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    } else if matches!(case, Case::TunFresh) {
        assert!(
            Node::now_ms().saturating_sub(queued_from) < 2_000,
            "tail must still be fresh before its ordinary retry"
        );
    }
    nodes[0].node.retry_pending_session_traffic().await;
    let expected = if matches!(case, Case::TunStale) {
        1
    } else {
        originals.len()
    };
    let mut received = BTreeSet::from([0]);
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            process_available_packets(nodes).await;
            if matches!(case, Case::Endpoint) {
                while let Ok(event) = endpoint.event_rx.try_recv() {
                    endpoint.event_rx.release_messages(event.messages.len());
                    for message in event.messages {
                        let payload = message.payload.as_slice();
                        let id = usize::from(payload[0]);
                        assert!(id < originals.len());
                        assert_eq!(payload, originals[id]);
                        assert!(
                            received.insert(id),
                            "original endpoint payload must not replay"
                        );
                    }
                }
            } else {
                while let Ok(packet) = tun_rx.try_recv_packet() {
                    let id = usize::from(packet.as_slice()[40]);
                    assert!(
                        id < expected,
                        "expired tail must not be sent after cancellation"
                    );
                    let expected_packet = build_ipv6_packet(
                        &crate::FipsAddress::from_node_addr(&source),
                        &crate::FipsAddress::from_node_addr(&destination),
                        &originals[id],
                    );
                    assert_eq!(packet.as_slice(), expected_packet);
                    assert!(received.insert(id), "original TUN packet must not replay");
                }
            }
            if received.len() == expected {
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("ordinary retry delivers retained originals, selected delivery independently observed");
    assert_eq!(received, (0..expected).collect());
    assert!(
        !nodes[0]
            .node
            .pending_session_traffic
            .has_traffic_for(&destination)
    );
    for _ in 0..3 {
        nodes[0].node.retry_pending_session_traffic().await;
        process_available_packets(nodes).await;
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(
        matches!(
            endpoint.event_rx.try_recv(),
            Err(tokio::sync::mpsc::error::TryRecvError::Empty)
        ),
        "no selected-payload replay"
    );
    assert!(
        matches!(
            tun_rx.try_recv_packet(),
            Err(std::sync::mpsc::TryRecvError::Empty)
        ),
        "no stale or duplicate TUN tail"
    );
    assert_eq!(
        observed
            .application
            .lock()
            .unwrap()
            .iter()
            .copied()
            .collect::<BTreeSet<_>>(),
        BTreeSet::from([*peers[1].node_addr()])
    );
    if matches!(case, Case::TunStale) {
        assert_eq!(
            observed.application.lock().unwrap().len(),
            1,
            "stale tail never enters application send accounting"
        );
    }
    assert_eq!(owners(nodes), retained);
    for (index, remote) in [(0, destination), (3, source)] {
        let session = nodes[index].node.get_session(&remote).unwrap();
        assert!(session.is_established());
        assert_eq!(session.handshake_hash(), Some(&session_hash));
    }
}
