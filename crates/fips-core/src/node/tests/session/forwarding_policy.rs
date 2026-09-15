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
