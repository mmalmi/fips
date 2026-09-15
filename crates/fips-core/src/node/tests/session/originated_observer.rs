use super::*;
use crate::node::{ForwardingOutcome, OriginatedSessionObserver, OriginatedSessionRequest};
use std::sync::{Arc, Mutex};

type ObservationRecord = (
    NodeAddr,
    NodeAddr,
    NodeAddr,
    Vec<u8>,
    Option<ForwardingOutcome>,
);

#[derive(Debug, Default)]
struct Observed {
    records: Mutex<Vec<ObservationRecord>>,
}

impl OriginatedSessionObserver for Observed {
    fn observe(&self, request: &OriginatedSessionRequest<'_>) -> Option<u64> {
        let mut records = self.records.lock().unwrap();
        records.push((
            request.source,
            request.destination,
            request.next_hop,
            request.session_payload.to_vec(),
            None,
        ));
        Some(records.len() as u64)
    }

    fn complete(&self, token: u64, outcome: ForwardingOutcome) {
        let mut records = self.records.lock().unwrap();
        assert!(
            records[token as usize - 1].4.replace(outcome).is_none(),
            "complete exactly once"
        );
    }
}

#[test]
fn originated_session_observer_tracks_actual_source_envelopes_and_excludes_transit() {
    run_large_stack_async_test("fips-originated-observer", || async {
        let _guard = lock_large_network_test().await;
        let mut nodes = run_tree_test(3, &[(0, 1), (1, 2)], false).await;
        verify_tree_convergence(&nodes);
        populate_all_coord_caches(&mut nodes);
        let addresses: Vec<_> = nodes.iter().map(|node| *node.node.node_addr()).collect();
        let identities: Vec<_> = nodes
            .iter()
            .map(|node| PeerIdentity::from_pubkey_full(node.node.identity().pubkey_full()))
            .collect();
        let observers: Vec<_> = (0..3).map(|_| Arc::new(Observed::default())).collect();
        for (i, node) in nodes.iter_mut().enumerate() {
            node.node
                .set_originated_session_observer(Some(observers[i].clone()));
        }
        let mut alice = nodes[0].node.attach_endpoint_data_io(16).unwrap();
        let mut bob = nodes[2].node.attach_endpoint_data_io(16).unwrap();
        for (source, destination, events) in
            [(0, 2, &mut bob.event_rx), (2, 0, &mut alice.event_rx)]
        {
            for payload in [b"first-opaque-application".to_vec(), vec![27; 500]] {
                send_endpoint_data_via_dataplane(
                    &mut nodes[source].node,
                    identities[destination],
                    payload.clone(),
                )
                .await
                .unwrap();
                let event = recv_endpoint_event_while_draining(
                    &mut nodes,
                    events,
                    Duration::from_secs(15),
                    "observed originating data",
                )
                .await;
                assert_eq!(
                    expect_single_endpoint_data_event(event).payload.as_slice(),
                    payload
                );
            }
        }
        let batch = crate::node::NodeEndpointDataBatch::from_payloads(
            identities[2],
            (40..46)
                .map(|byte| {
                    crate::node::EndpointDataPayload::from_packet_payload(vec![byte; 500]).unwrap()
                })
                .collect(),
            None,
        )
        .unwrap();
        nodes[0]
            .node
            .handle_endpoint_data_batch_no_established_flush(batch)
            .await;
        nodes[0].node.flush_pending_packets(&addresses[2]).await;
        let mut seen = std::collections::BTreeSet::new();
        while seen.len() < 6 {
            let event = recv_endpoint_event_while_draining(
                &mut nodes,
                &mut bob.event_rx,
                Duration::from_secs(15),
                "observed native send batch",
            )
            .await;
            for message in event.messages {
                let bytes = message.payload.as_slice();
                assert_eq!(bytes.len(), 500);
                assert!((40..46).contains(&bytes[0]));
                seen.insert(bytes[0]);
            }
        }
        let observed_before = observers[1].records.lock().unwrap().len();
        let forwarded_before = nodes[1].node.stats().forwarding.forwarded_packets;
        let spoofed =
            SessionDatagram::new(addresses[1], addresses[2], vec![0x10, 0, 4, 0, 1, 2, 3, 4])
                .encode();
        nodes[1]
            .node
            .handle_session_datagram(AuthenticatedSessionDatagram::new(
                identities[0],
                &spoofed[1..],
                false,
            ))
            .await;
        assert_eq!(
            nodes[1].node.stats().forwarding.forwarded_packets,
            forwarded_before + 1
        );
        assert_eq!(
            observers[1].records.lock().unwrap().len(),
            observed_before,
            "a transit packet claiming our address is still not locally originated"
        );
        let before_oversize = observers[0].records.lock().unwrap().len();
        send_endpoint_data_via_dataplane(&mut nodes[0].node, identities[2], vec![99; 3_000])
            .await
            .unwrap();
        drain_to_quiescence(&mut nodes).await;
        {
            let records = observers[0].records.lock().unwrap();
            let oversized: Vec<_> = records[before_oversize..]
                .iter()
                .filter(|(_, _, _, bytes, _)| bytes.len() >= 3_000)
                .collect();
            assert!(
                !oversized.is_empty(),
                "record the source attempt after sealing"
            );
            assert!(
                oversized
                    .iter()
                    .all(|(_, _, _, _, result)| *result == Some(ForwardingOutcome::Unconfirmed)),
                "MTU-rejected packets cannot authorize payment as submitted bytes"
            );
        }
        cleanup_nodes(&mut nodes).await;
        for (i, observer) in observers.iter().enumerate() {
            let records = observer.records.lock().unwrap();
            for (source, _, _, _, outcome) in records.iter() {
                assert_eq!(
                    *source, addresses[i],
                    "transit must never be attributed to this node as sender"
                );
                assert!(outcome.is_some());
            }
            if i != 1 {
                let remote = if i == 0 { 2 } else { 0 };
                assert!(
                    records
                        .iter()
                        .any(|(_, destination, next, bytes, result)| *destination
                            == addresses[remote]
                            && *next == addresses[1]
                            && bytes.len() >= 500
                            && *result == Some(ForwardingOutcome::Submitted)),
                    "observe sealed application bytes, not just the handshake"
                );
                assert!(records.iter().all(|(_, _, _, bytes, _)| {
                    !bytes
                        .windows(b"first-opaque-application".len())
                        .any(|window| window == b"first-opaque-application")
                }));
            }
        }
    });
}
