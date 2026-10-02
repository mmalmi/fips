//! Strict local rounds share prompt original-receipt observation.
use super::*;

impl Observation {
    fn receive_round(
        &mut self,
        endpoints: &mut [EndpointDataIo],
        ids: &[PeerIdentity],
        tag: &[u8],
        flows: &[(usize, usize)],
        received: &mut Vec<(usize, usize)>,
    ) {
        receive_round_with_tag_and_observer(
            endpoints,
            ids,
            tag,
            flows,
            received,
            |destination, source, payload| {
                self.brief_payloads.as_mut().is_some_and(|originals| {
                    originals.receive(destination, source, payload, ids, self.started)
                }) || self.queued_originals.iter_mut().any(|original| {
                    original.receive(destination, source, payload, ids, self.started)
                })
            },
        );
    }

    pub(super) async fn round(
        &mut self,
        nodes: &mut [TestNode],
        endpoints: &mut [EndpointDataIo],
        ids: &[PeerIdentity],
        sequence: &mut u16,
        flows: &[(usize, usize)],
    ) {
        let current = *sequence;
        *sequence = sequence.checked_add(1).expect("bounded unique payloads");
        send_round_with_tag(nodes, ids, &current.to_le_bytes(), flows).await;
        let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
        let mut received = Vec::new();
        let mut turns = 0usize;
        loop {
            let turn_started = self.started.elapsed().as_millis();
            self.turn_with_endpoint_observer(nodes, ids, |observation| {
                observation.receive_round(
                    endpoints,
                    ids,
                    &current.to_le_bytes(),
                    flows,
                    &mut received,
                );
            })
            .await;
            turns += 1;
            let turn_finished = self.started.elapsed().as_millis();
            self.receive_round(endpoints, ids, &current.to_le_bytes(), flows, &mut received);
            if received.len() == flows.len() {
                return;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "exact direct payloads must continue while candidates compete: {}",
                json!({"sequence":current,"expected":flows,"received":received,
                    "turns":turns,"last_turn_ms":[turn_started,turn_finished],
                    "failure_state":round_failure_state(nodes, ids, flows)})
            );
            self.contact_idle
                .wait(nodes, self.contact_phase.as_mut(), "local-round")
                .await;
        }
    }
}

// Sample only after failure; these queue predicates do not prove global idleness.
fn round_failure_state(
    nodes: &[TestNode],
    ids: &[PeerIdentity],
    flows: &[(usize, usize)],
) -> Value {
    let state = |source: usize, destination: usize| {
        let node = &nodes[source].node;
        let remote = ids[destination].node_addr();
        let session = node.get_session(remote).map(|entry| {
            json!({"established":entry.is_established(),"initiating":entry.is_initiating(),
                "awaiting_msg3":entry.is_awaiting_msg3(),"rekey":entry.has_rekey_in_progress(),
                "pending_epoch":entry.pending_new_session().is_some(),
                "current_k":entry.current_k_bit(),"resends":entry.resend_count(),
                "retained_handshake":entry.handshake_payload().is_some()})
        });
        let peer = node.get_peer(remote).map(|peer| {
            json!({"link":peer.link_id().as_u64(),"authenticated_ms":peer.authenticated_at(),
                "our_index":peer.our_index().map(|index|index.as_u32()),
                "their_index":peer.their_index().map(|index|index.as_u32())})
        });
        json!({"node":source,"remote":destination,"peer":peer,"session":session,
            "pending_traffic":node.pending_session_traffic.has_traffic_for(remote),
            "raw_queued":nodes[source].packet_rx.queued_packets_for_test(),
            "runnable":node.dataplane.has_runnable_work(),
            "deferred_controls":node.deferred_dataplane_control_turns.len(),
            "endpoint_queued":node.endpoint_events.sender().map(|sender|sender.queued_messages())})
    };
    Value::Array(
        flows
            .iter()
            .map(|&(source, destination)| {
                json!({"flow":[source,destination],"source":state(source,destination),
            "destination":state(destination,source)})
            })
            .collect(),
    )
}
