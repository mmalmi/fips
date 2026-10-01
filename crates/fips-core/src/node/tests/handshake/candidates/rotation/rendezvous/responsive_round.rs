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
        loop {
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
            self.receive_round(endpoints, ids, &current.to_le_bytes(), flows, &mut received);
            if received.len() == flows.len() {
                return;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "exact direct payloads must continue while candidates compete"
            );
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    }
}
