use super::*;
use crate::node::{ForwardingOutcome, ForwardingPolicy, ForwardingRequest};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

#[derive(Debug, Clone)]
struct Record {
    ingress: NodeAddr,
    next_hop: NodeAddr,
    source: NodeAddr,
    destination: NodeAddr,
    bytes: usize,
}

#[derive(Debug, Default)]
struct Audit {
    allowance: usize,
    denied: usize,
    next_token: u64,
    pending: HashMap<u64, Record>,
    completed: Vec<(Record, ForwardingOutcome)>,
}

/// Tests core admission, not payment validation. No test balance is Cashu.
#[derive(Debug, Default)]
struct Allowance(Mutex<Audit>);

impl ForwardingPolicy for Allowance {
    fn admit(&self, request: &ForwardingRequest<'_>) -> Option<u64> {
        let mut audit = self.0.lock().unwrap();
        let bytes = request.session_payload.len();
        if bytes > audit.allowance {
            audit.denied += 1;
            return None;
        }
        audit.allowance -= bytes;
        audit.next_token += 1;
        let token = audit.next_token;
        audit.pending.insert(
            token,
            Record {
                ingress: *request.ingress.node_addr(),
                next_hop: request.next_hop,
                source: request.source,
                destination: request.destination,
                bytes,
            },
        );
        Some(token)
    }

    fn complete(&self, token: u64, outcome: ForwardingOutcome) {
        let mut audit = self.0.lock().unwrap();
        let record = audit.pending.remove(&token).expect("complete exactly once");
        audit.completed.push((record, outcome));
    }
}

#[test]
fn native_forwarding_policy_gates_three_transit_hops_in_both_directions() {
    run_large_stack_async_test("fips-transit-policy", || async {
        let _guard = lock_large_network_test().await;
        let mut nodes = run_tree_test(5, &[(0, 1), (1, 2), (2, 3), (3, 4)], false).await;
        verify_tree_convergence(&nodes);
        populate_all_coord_caches(&mut nodes);
        let addresses: Vec<_> = nodes.iter().map(|node| *node.node.node_addr()).collect();
        let identities: Vec<_> = nodes
            .iter()
            .map(|node| PeerIdentity::from_pubkey_full(node.node.identity().pubkey_full()))
            .collect();
        let mut alice = nodes[0].node.attach_endpoint_data_io(16).unwrap();
        let mut middle = nodes[2].node.attach_endpoint_data_io(16).unwrap();
        let mut bob = nodes[4].node.attach_endpoint_data_io(16).unwrap();
        let policies: Vec<_> = (0..3).map(|_| Arc::new(Allowance::default())).collect();
        for (index, policy) in policies.iter().enumerate() {
            policy.0.lock().unwrap().allowance = 1_000_000;
            nodes[index + 1]
                .node
                .set_forwarding_policy(Some(policy.clone()));
        }

        send_endpoint_data_via_dataplane(&mut nodes[0].node, identities[4], b"forward".to_vec())
            .await
            .unwrap();
        let event = recv_endpoint_event_while_draining(
            &mut nodes,
            &mut bob.event_rx,
            Duration::from_secs(30),
            "forward across three gates",
        )
        .await;
        assert_eq!(
            expect_single_endpoint_data_event(event).payload.as_slice(),
            b"forward"
        );

        send_endpoint_data_via_dataplane(&mut nodes[4].node, identities[0], b"reverse".to_vec())
            .await
            .unwrap();
        let event = recv_endpoint_event_while_draining(
            &mut nodes,
            &mut alice.event_rx,
            Duration::from_secs(30),
            "reverse across three gates",
        )
        .await;
        assert_eq!(
            expect_single_endpoint_data_event(event).payload.as_slice(),
            b"reverse"
        );
        drain_to_quiescence(&mut nodes).await;

        for (index, policy) in policies.iter().enumerate() {
            let audit = policy.0.lock().unwrap();
            for (source, destination, ingress, next_hop) in [
                (
                    addresses[0],
                    addresses[4],
                    addresses[index],
                    addresses[index + 2],
                ),
                (
                    addresses[4],
                    addresses[0],
                    addresses[index + 2],
                    addresses[index],
                ),
            ] {
                let submitted: Vec<_> = audit
                    .completed
                    .iter()
                    .filter(|(record, outcome)| {
                        record.source == source
                            && record.destination == destination
                            && *outcome == ForwardingOutcome::Submitted
                    })
                    .collect();
                assert!(
                    !submitted.is_empty(),
                    "each native transit hop must be observed"
                );
                for (record, _) in submitted {
                    assert_eq!(record.ingress, ingress, "charge the authenticated neighbor");
                    assert_eq!(record.next_hop, next_hop);
                    assert!(record.bytes > 0);
                }
            }
            assert!(
                audit.pending.is_empty(),
                "transport completions release every token"
            );
        }
        assert!(
            middle.event_rx.try_recv().is_err(),
            "transit does not expose endpoint plaintext"
        );

        policies[1].0.lock().unwrap().allowance = 0;
        send_endpoint_data_via_dataplane(&mut nodes[0].node, identities[4], b"denied".to_vec())
            .await
            .unwrap();
        drain_to_quiescence(&mut nodes).await;
        assert!(policies[1].0.lock().unwrap().denied > 0);
        let counters = serde_json::to_value(nodes[2].node.stats().forwarding.snapshot()).unwrap();
        assert_eq!(
            counters["drop_policy_denied_packets"].as_u64(),
            Some(policies[1].0.lock().unwrap().denied as u64),
            "the operator API must distinguish policy refusal from routing loss"
        );
        assert!(counters["drop_policy_denied_bytes"].as_u64().unwrap() >= 6);
        assert!(
            bob.event_rx.try_recv().is_err(),
            "exhausted middle hop must block transit"
        );

        // The exhausted relay's own control/application service is still reachable.
        send_endpoint_data_via_dataplane(
            &mut nodes[0].node,
            identities[2],
            b"local-control".to_vec(),
        )
        .await
        .unwrap();
        let event = recv_endpoint_event_while_draining(
            &mut nodes,
            &mut middle.event_rx,
            Duration::from_secs(30),
            "local service while exhausted",
        )
        .await;
        assert_eq!(
            expect_single_endpoint_data_event(event).payload.as_slice(),
            b"local-control"
        );

        policies[1].0.lock().unwrap().allowance = 1_000_000;
        send_endpoint_data_via_dataplane(&mut nodes[0].node, identities[4], b"renewed".to_vec())
            .await
            .unwrap();
        let event = recv_endpoint_event_while_draining(
            &mut nodes,
            &mut bob.event_rx,
            Duration::from_secs(30),
            "renewed transit",
        )
        .await;
        assert_eq!(
            expect_single_endpoint_data_event(event).payload.as_slice(),
            b"renewed"
        );
        cleanup_nodes(&mut nodes).await;
        for policy in policies {
            assert!(policy.0.lock().unwrap().pending.is_empty());
        }
    });
}

#[test]
fn authenticated_link_replay_cannot_create_another_forwarding_attempt() {
    run_large_stack_async_test("fips-transit-wire-replay", || async {
        use crate::node::tests::spanning_tree::process_dataplane_packet;

        let _guard = lock_large_network_test().await;
        let mut nodes = run_tree_test(3, &[(0, 1), (1, 2)], false).await;
        verify_tree_convergence(&nodes);
        populate_all_coord_caches(&mut nodes);
        drain_to_quiescence(&mut nodes).await;
        let source = *nodes[0].node.node_addr();
        let destination = *nodes[2].node.node_addr();
        let policy = Arc::new(Allowance::default());
        policy.0.lock().unwrap().allowance = 1_000_000;
        nodes[1].node.set_forwarding_policy(Some(policy.clone()));

        // Deliberately opaque session contents: a transit router authenticates
        // its paying neighbor, not the end-to-end ciphertext or claimed sender.
        let mut payload = vec![0; 64];
        payload[2..4].copy_from_slice(&36u16.to_le_bytes());
        let mut datagram = SessionDatagram::new(source, destination, payload.clone());
        let attempts = || {
            policy
                .0
                .lock()
                .unwrap()
                .completed
                .iter()
                .filter(|(r, outcome)| {
                    r.source == source
                        && r.destination == destination
                        && r.bytes == payload.len()
                        && *outcome == ForwardingOutcome::Submitted
                })
                .count()
        };

        nodes[0]
            .node
            .send_session_datagram(&mut datagram)
            .await
            .unwrap();
        let mut captured = Vec::new();
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                while let Ok(packet) = nodes[1].packet_rx.try_recv() {
                    captured.push(packet.clone());
                    process_dataplane_packet(&mut nodes[1], packet).await;
                }
                if captured.is_empty() {
                    process_available_packets(&mut nodes[..1]).await;
                    process_available_packets(&mut nodes[2..]).await;
                } else {
                    // Complete deferred transport sends through ordinary node
                    // turns after capturing the initial physical frame.
                    process_available_packets(&mut nodes).await;
                }
                if attempts() == 1 {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .unwrap_or_else(|error| {
            let audit = format!("{:?}", policy.0.lock().unwrap());
            panic!(
                "forwarding deadline: {error}; captured={}; audit={audit}",
                captured.len()
            );
        });
        assert!(
            !captured.is_empty(),
            "exercise captured wire bytes, not a policy mock"
        );
        drain_to_quiescence(&mut nodes).await;
        assert_eq!(attempts(), 1);
        let admissions = || {
            let audit = policy.0.lock().unwrap();
            (audit.next_token, audit.denied)
        };
        let before_replay = admissions();

        for _ in 0..3 {
            for packet in &captured {
                process_dataplane_packet(&mut nodes[1], packet.clone()).await;
            }
        }
        drain_to_quiescence(&mut nodes).await;
        assert_eq!(
            attempts(),
            1,
            "link replay must be rejected before paid admission"
        );
        assert_eq!(admissions(), before_replay);

        // An unauthenticated high nonce cannot advance the receive window and
        // prevent the next legitimate frame from being counted.
        let mut forged_frames = 0;
        for packet in &captured {
            let mut bytes = packet.data.as_slice().to_vec();
            if bytes.len() >= 32 && bytes[0] & 0x0f == 0 {
                bytes[8..16].copy_from_slice(&(u64::MAX - 1).to_le_bytes());
                let mut forged = packet.clone();
                forged.data = crate::transport::PacketBuffer::new(bytes);
                process_dataplane_packet(&mut nodes[1], forged).await;
                forged_frames += 1;
            }
        }
        assert!(forged_frames > 0, "exercise an established encrypted frame");
        drain_to_quiescence(&mut nodes).await;
        assert_eq!(
            attempts(),
            1,
            "failed authentication cannot create an attempt"
        );
        assert_eq!(admissions(), before_replay);

        // The same inner ciphertext deliberately sent again by the neighbor is
        // a fresh authenticated link transmission. It is distinct from replay
        // of the captured link frame; a forwarding-attempt tariff can charge it.
        nodes[0]
            .node
            .send_session_datagram(&mut datagram)
            .await
            .unwrap();
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                process_available_packets(&mut nodes).await;
                if attempts() == 2 {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("fresh transmission must survive the forged high nonce");
        for packet in captured {
            process_dataplane_packet(&mut nodes[1], packet).await;
        }
        drain_to_quiescence(&mut nodes).await;
        assert_eq!(attempts(), 2);
        cleanup_nodes(&mut nodes).await;
        assert!(policy.0.lock().unwrap().pending.is_empty());
    });
}
