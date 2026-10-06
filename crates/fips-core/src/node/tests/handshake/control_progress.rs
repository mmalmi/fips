//! Exercise endpoint control through the actual actor while valid Noise ingress
//! waits for bounded carrier completion. This is not a production stall replay.
use super::*;
use crate::config::{SimTransportConfig, TransportInstances};
use crate::node::tests::sim_discovery::configured_discovering_node;
use crate::{SimNetwork, register_sim_network, unregister_sim_network};
use std::sync::{Arc, Mutex};
use tokio::sync::oneshot;

#[derive(Debug, Default)]
struct SessionCompletions(Mutex<Vec<(NodeAddr, Option<ForwardingOutcome>)>>);

impl OriginatedSessionObserver for SessionCompletions {
    fn observe(&self, request: &OriginatedSessionRequest<'_>) -> Option<u64> {
        let prefix = crate::node::session_wire::FspCommonPrefix::parse(request.session_payload)?;
        if prefix.phase != crate::node::session_wire::FSP_PHASE_MSG2 {
            return None;
        }
        let mut records = self.0.lock().unwrap();
        records.push((request.destination, None));
        Some(records.len() as u64)
    }

    fn complete(&self, token: u64, outcome: ForwardingOutcome) {
        let mut records = self.0.lock().unwrap();
        assert!(
            records[token as usize - 1].1.replace(outcome).is_none(),
            "each observed ACK attempt completes exactly once"
        );
    }
}

#[test]
fn endpoint_snapshot_progresses_during_bounded_handshake_completions() {
    super::super::session::run_large_stack_async_test("endpoint-control-progress", || {
        exercise(false, 200, false)
    });
}

#[test]
fn endpoint_snapshot_progresses_during_bounded_session_completions() {
    super::super::session::run_large_stack_async_test("endpoint-session-control-progress", || {
        exercise(true, 200, false)
    });
}

#[test]
fn endpoint_snapshot_and_sessions_progress_with_immediate_completions() {
    super::super::session::run_large_stack_async_test("endpoint-control-positive", || {
        exercise(true, 0, false)
    });
}

#[test]
fn endpoint_snapshots_progress_during_stall_and_raw_data_drains_after_recovery() {
    super::super::session::run_large_stack_async_test("sustained-session-control", || {
        exercise(true, 200, true)
    });
}

async fn exercise(session: bool, completion_delay_ms: u64, sustained: bool) {
    const CLIENTS: usize = 32;
    let name = format!(
        "endpoint-control-progress-{}-{session}-{completion_delay_ms}-{sustained}",
        std::process::id()
    );
    let network = SimNetwork::new(719);
    let completions = Arc::new(SessionCompletions::default());
    register_sim_network(name.clone(), network.clone());
    let directory = tempfile::tempdir().unwrap();
    let mut nodes = Vec::new();
    let mut controls = Vec::new();
    let mut endpoints = Vec::new();
    for index in 0..=CLIENTS {
        let address = format!("node-{index}");
        let mut config = Config::new();
        config.node.system_files_enabled = false;
        config.node.discovery.lan.enabled = false;
        config.node.discovery.nostr.enabled = false;
        config.node.discovery.local.enabled = false;
        config.node.control.socket_path = directory
            .path()
            .join(format!("{index}.sock"))
            .to_string_lossy()
            .into_owned();
        config.transports.sim = TransportInstances::Single(SimTransportConfig {
            network: Some(name.clone()),
            addr: Some(address.clone()),
            auto_connect: Some(false),
            ..Default::default()
        });
        let mut test = configured_discovering_node(config, &address).await;
        if index == 0 {
            test.node
                .set_originated_session_observer(Some(completions.clone()));
        }
        let endpoint = test.node.attach_endpoint_data_io(128).unwrap();
        controls.push(endpoint.control_tx.clone());
        endpoints.push(endpoint);
        nodes.push(test);
    }

    let server = *nodes[0].node.node_addr();
    let server_identity = PeerIdentity::from_pubkey_full(nodes[0].node.identity().pubkey_full());
    let server_address = nodes[0].addr.clone();
    let clients: Vec<_> = nodes[1..]
        .iter()
        .map(|node| *node.node.node_addr())
        .collect();
    for client in &mut nodes[1..] {
        client
            .node
            .initiate_connection(client.transport_id, server_address.clone(), server_identity)
            .await
            .unwrap();
    }
    if session {
        crate::node::tests::spanning_tree::drain_all_packets(&mut nodes, false).await;
        assert_eq!(nodes[0].node.peer_count(), CLIENTS);
        for client in &nodes[1..] {
            assert!(client.node.get_peer(&server).unwrap().has_session());
        }
    }
    let delivered_target = if session {
        let before = network.stats().packets_sent;
        for client in &mut nodes[1..] {
            client
                .node
                .initiate_session(server, server_identity.pubkey_full())
                .await
                .unwrap();
        }
        before + CLIENTS as u64
    } else {
        CLIENTS as u64
    };
    // All inputs are genuinely generated Noise msg1 packets, already delivered
    // to the production packet channel before the server actor is started.
    tokio::time::timeout(Duration::from_secs(2), async {
        while network.stats().packets_delivered < delivered_target {
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    })
    .await
    .unwrap();
    assert_eq!(network.stats().packets_sent, delivered_target);
    network.set_node_send_completion_delay(server_address.as_str().unwrap(), completion_delay_ms);

    let mut actors = Vec::new();
    for mut test in nodes {
        test.node.packet_rx = Some(test.packet_rx);
        test.node.state = NodeState::Running;
        let (stop, stopped) = oneshot::channel();
        actors.push((
            stop,
            tokio::spawn(async move {
                tokio::select! {
                    result = test.node.run_rx_loop() => panic!("actor exited: {result:?}"),
                    _ = stopped => {}
                }
                test.node
            }),
        ));
    }
    // The existing public observer identifies an ACK send attempt in the FSP
    // handler; unrelated maintenance frames cannot arm the session case.
    let entered = tokio::time::timeout(Duration::from_secs(2), async {
        while if session {
            completions.0.lock().unwrap().is_empty()
        } else {
            network.stats().packets_delivered <= delivered_target
        } {
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    })
    .await
    .is_ok();
    let (response_tx, mut response_rx) = oneshot::channel();
    controls[0]
        .send(NodeEndpointControlCommand::PeerSnapshot { response_tx })
        .await
        .unwrap();
    let started = std::time::Instant::now();
    // Match the serving FipsEndpoint control API's five-second deadline.
    let timely = tokio::time::timeout(Duration::from_secs(5), &mut response_rx).await;
    let elapsed = started.elapsed();
    let progressed = matches!(&timely, Ok(Ok(_)));
    let acks_at_deadline = completions.0.lock().unwrap().len();
    let mut sustained_ok = !sustained;
    if sustained {
        // Keep the delay in force throughout the complete initial ACK batch
        // and repeatedly query control. A Submitted ACK is a local carrier
        // result, not proof that the responder has processed the client's MSG3.
        let mut snapshot_queries = 0;
        let ack_progress = tokio::time::timeout(Duration::from_secs(25), async {
            loop {
                let done = {
                    let records = completions.0.lock().unwrap();
                    let destinations: std::collections::HashSet<_> = records
                        .iter()
                        .filter(|(_, result)| *result == Some(ForwardingOutcome::Submitted))
                        .map(|(peer, _)| *peer)
                        .collect();
                    destinations.len() == CLIENTS
                };
                let (response_tx, response_rx) = oneshot::channel();
                controls[0]
                    .send(NodeEndpointControlCommand::PeerSnapshot { response_tx })
                    .await
                    .unwrap();
                tokio::time::timeout(Duration::from_secs(5), response_rx)
                    .await
                    .expect("sustained snapshot deadline")
                    .expect("sustained snapshot response");
                snapshot_queries += 1;
                if done {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        })
        .await
        .is_ok();
        assert!(
            snapshot_queries >= 2,
            "exercise repeated queries while delayed"
        );
        // The stock runtime can retain data behind handshake retransmissions
        // while every carrier completion is delayed. Raw datagrams have no
        // fixed fifteen-second delivery contract under that injected load.
        // This gate proves post-stall drain, not sustained-delay data latency.
        sustained_ok = ack_progress
            && tokio::time::timeout(Duration::from_secs(15), async {
                eprintln!(
                    "recovery: 32 ACK destinations after {}ms; {snapshot_queries} successful delayed snapshots",
                    started.elapsed().as_millis()
                );
                // Each client sends two ordered payloads through the existing
                // endpoint queue while completion is still delayed. Require
                // these same admitted payloads to drain after recovery.
                for (index, endpoint) in endpoints[1..].iter().enumerate() {
                    endpoint
                        .data_batch_tx
                        .send_or_drop(
                            NodeEndpointDataBatch::from_payloads(
                                server_identity,
                                (0..2)
                                    .map(|sequence| {
                                        EndpointDataPayload::from_packet_payload(vec![
                                            index as u8,
                                            sequence,
                                        ])
                                        .unwrap()
                                    })
                                    .collect(),
                                None,
                            )
                            .unwrap(),
                        )
                        .unwrap();
                }
                tokio::task::yield_now().await;
                network.set_node_send_completion_delay(server_address.as_str().unwrap(), 0);
                let mut received = vec![0_u8; CLIENTS];
                while received.iter().any(|count| *count != 2) {
                    let event = endpoints[0].event_rx.recv().await.unwrap();
                    for delivery in event.messages {
                        let bytes = delivery.payload.as_slice();
                        assert_eq!(bytes.len(), 2);
                        let index = usize::from(bytes[0]);
                        assert_eq!(*delivery.source_peer.node_addr(), clients[index]);
                        assert_eq!(
                            bytes[1], received[index],
                            "per-source delivery once and in order"
                        );
                        received[index] += 1;
                    }
                }
            })
            .await
            .is_ok();
        eprintln!(
            "recovery: delayed ACK progress={ack_progress} post-stall data progress={sustained_ok}, records={}",
            completions.0.lock().unwrap().len()
        );
    }
    // Let accepted work finish even for the expected baseline failure. Never
    // model fairness by canceling the actor's owned ingress Vec or send future.
    // In the recovery case the delay was already removed after repeated
    // successful snapshots, the complete ACK batch and data admission.
    // Other cases lift it here so teardown cannot cancel an in-flight send.
    network.set_node_send_completion_delay(server_address.as_str().unwrap(), 0);
    if timely.is_err() {
        tokio::time::timeout(Duration::from_secs(10), &mut response_rx)
            .await
            .unwrap()
            .unwrap();
    }
    let complete = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let (response_tx, response_rx) = oneshot::channel();
            controls[0]
                .send(NodeEndpointControlCommand::PeerSnapshot { response_tx })
                .await
                .unwrap();
            let peers = response_rx.await.unwrap();
            if peers.len() == CLIENTS && peers.iter().all(|peer| clients.contains(&peer.node_addr))
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .is_ok();

    if session {
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    let mut authenticated = 0;
    let mut sessions = 0;
    for (index, (stop, task)) in actors.into_iter().enumerate() {
        let _ = stop.send(());
        let mut node = task.await.unwrap();
        assert!(
            controls[index].is_closed(),
            "cancelled actor closes endpoint control even while Node is retained"
        );
        if index == 0 {
            if sustained_ok && sustained {
                assert!(
                    node.deferred_dataplane_control_turns.is_empty(),
                    "retained control backlog must drain"
                );
            }
            authenticated = clients
                .iter()
                .filter(|client| node.get_peer(client).is_some_and(|p| p.has_session()))
                .count();
            assert_eq!(
                node.peer_count(),
                CLIENTS,
                "one owner per accepted identity"
            );
            assert_eq!(node.connection_count(), 0, "no abandoned handshake owners");
            assert_eq!(node.index_allocator.count(), CLIENTS);
            if session {
                sessions = clients
                    .iter()
                    .filter(|client| {
                        node.get_session(client)
                            .is_some_and(|entry| entry.is_established())
                    })
                    .count();
            }
        } else {
            assert!(
                node.get_peer(&server)
                    .is_some_and(|peer| peer.has_session())
            );
        }
        for transport in node.transports.values_mut() {
            transport.stop().await.unwrap();
        }
    }
    unregister_sim_network(&name);
    let records = completions.0.lock().unwrap();
    let completed_acks = records
        .iter()
        .filter(|(_, result)| result.is_some())
        .count();
    let mut outcomes = std::collections::BTreeMap::new();
    for (_, outcome) in records.iter() {
        *outcomes.entry(format!("{outcome:?}")).or_insert(0usize) += 1;
    }
    eprintln!("ACK terminal outcomes: {outcomes:?}");
    let ack_destinations: std::collections::HashSet<_> = records
        .iter()
        .map(|(destination, _)| *destination)
        .collect();
    eprintln!(
        "endpoint progress: session={session} sustained={sustained} completion_delay_ms={completion_delay_ms} entered={entered} snapshot_ms={} timely={progressed} completed={complete} authenticated={authenticated} sessions={sessions} acks_at_deadline={acks_at_deadline} ack_attempts={} completed_acks={completed_acks}",
        elapsed.as_millis(),
        records.len()
    );
    assert!(entered && complete && authenticated == CLIENTS);
    if session {
        assert_eq!(sessions, CLIENTS);
        assert_eq!(ack_destinations.len(), CLIENTS);
        assert_eq!(completed_acks, records.len());
        assert!(
            records
                .iter()
                .all(|(_, result)| *result == Some(ForwardingOutcome::Submitted))
        );
    }
    assert!(
        progressed,
        "bounded carrier completions starved endpoint PeerSnapshot for {elapsed:?}"
    );
    assert!(
        sustained_ok,
        "delayed snapshots and post-stall raw data drain must both succeed"
    );
}
