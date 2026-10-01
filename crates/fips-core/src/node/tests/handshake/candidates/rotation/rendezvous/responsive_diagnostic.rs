//! Temporary investigation data; never contributes to contact acceptance.
use super::*;
use crate::test_trace::{Stamp, Trace, wire_key};

pub(super) struct PacketProbe {
    trace: Trace,
    before: Stamp,
    edge: (usize, usize),
    key: [u64; 3],
    received_ms: u64,
}

impl PacketProbe {
    pub(super) fn completed(&self) -> Stamp {
        self.trace.stamp()
    }
}

impl Observation {
    pub(super) fn trace_phase(&self, name: &'static str) {
        if let Some(trace) = &self.contact_trace {
            trace.record_at(trace.stamp(), name, None, &[], [0; 8]);
        }
    }

    pub(super) fn trace_routing(&self, nodes: &[TestNode], ids: &[PeerIdentity]) {
        let Some(trace) = &self.contact_trace else {
            return;
        };
        for (from, to) in [(0, 1), (1, 0), (0, 2), (2, 0), (1, 3), (3, 1)] {
            let node = &nodes[from].node;
            node.bloom_state.trace_pending_filter(ids[to].node_addr());
            let Some(peer) = node.get_peer(ids[to].node_addr()) else {
                continue;
            };
            let bits: [u64; 2] = std::array::from_fn(|target| {
                peer.inbound_filter()
                    .is_some_and(|filter| filter.contains(ids[target + 2].node_addr()))
                    as u64
            });
            trace.record_at(
                trace.stamp(),
                "bloom_incoming_snapshot",
                Some((to, from)),
                &["sequence", "tree_peer", "target2", "target3"],
                [
                    peer.filter_sequence(),
                    node.is_tree_peer(ids[to].node_addr()) as u64,
                    bits[0],
                    bits[1],
                    0,
                    0,
                    0,
                    0,
                ],
            );
        }
    }

    pub(super) fn trace_completion(&self, destination: usize) -> Option<CompletionProbe> {
        if destination >= 4 {
            return None;
        }
        let trace = self.contact_trace.as_ref()?;
        Some(CompletionProbe {
            trace: trace.clone(),
            before: trace.stamp(),
            destination,
        })
    }

    pub(super) fn trace_packet(
        &self,
        nodes: &[TestNode],
        destination: usize,
        packet: &crate::transport::ReceivedPacket,
    ) -> Option<PacketProbe> {
        let trace = self.contact_trace.as_ref()?;
        let source = nodes
            .iter()
            .position(|node| node.addr == packet.remote_addr)?;
        let edge = Trace::edge_indices(source, destination)?;
        Some(PacketProbe {
            trace: trace.clone(),
            before: trace.stamp(),
            edge,
            key: wire_key(packet.data.as_slice()),
            received_ms: packet.timestamp_ms,
        })
    }
}

pub(super) fn packet_finished(probe: Option<PacketProbe>, completed: Option<Stamp>) {
    if let Some(PacketProbe {
        trace,
        before,
        edge,
        key,
        received_ms,
    }) = probe
    {
        let after = completed.unwrap();
        trace.record_at(
            after,
            "packet_turn",
            Some(edge),
            &[
                "header0",
                "header1",
                "bytes",
                "received_ms",
                "before_us",
                "after_us",
            ],
            [
                key[0],
                key[1],
                key[2],
                received_ms,
                before.us,
                after.us,
                0,
                0,
            ],
        );
    }
}

pub(super) fn attach(
    observation: &mut Observation,
    nodes: &mut [TestNode],
    endpoints: &[EndpointDataIo],
    ids: &[PeerIdentity],
    network: &SimNetwork,
    addresses: &[&str],
) -> Trace {
    let trace = Trace::new(
        observation.started,
        std::array::from_fn(|i| *ids[i].node_addr()),
        std::array::from_fn(|i| addresses[i].to_owned()),
        ready::ORIGINALS,
        4096,
    );
    network.set_contact_trace(Some(trace.clone()));
    for (index, node) in nodes.iter_mut().enumerate().take(4) {
        node.node
            .bloom_state
            .set_diagnostic_trace(Some(trace.clone()));
        endpoints[index]
            .event_tx
            .set_contact_trace(Some((trace.clone(), index)));
    }
    observation.contact_trace = Some(trace.clone());
    trace.set_active(true);
    trace
}

pub(super) fn detach(
    observation: &mut Observation,
    nodes: &mut [TestNode],
    endpoints: &[EndpointDataIo],
    network: &SimNetwork,
    trace: &Trace,
) {
    // Includes only this contact and its already-existing 500 ms separation,
    // so a publication just after the cut remains visible as a late event.
    let result = trace.finish();
    network.set_contact_trace(None);
    observation.contact_trace = None;
    for (index, node) in nodes.iter_mut().enumerate().take(4) {
        node.node.bloom_state.set_diagnostic_trace(None);
        endpoints[index].event_tx.set_contact_trace(None);
    }
    eprintln!("responsive temporary contact trace: {result}");
}

pub(super) struct CompletionProbe {
    trace: Trace,
    before: Stamp,
    destination: usize,
}

impl CompletionProbe {
    pub(super) fn completed(&self) -> Stamp {
        self.trace.stamp()
    }
}

pub(super) fn completion_finished(probe: Option<CompletionProbe>, completed: Option<Stamp>) {
    if let Some(CompletionProbe {
        trace,
        before,
        destination,
    }) = probe
    {
        let after = completed.unwrap();
        trace.record_at(
            after,
            "completion_turn",
            None,
            &["destination", "before_us", "after_us"],
            [destination as u64, before.us, after.us, 0, 0, 0, 0, 0],
        );
    }
}
