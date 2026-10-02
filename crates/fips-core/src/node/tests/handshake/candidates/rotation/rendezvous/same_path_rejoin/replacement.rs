//! Keep the useful peer useful until the asynchronous replacement actually admits.
use super::*;
use crate::transport::{ReceivedPacket, TransportAddr};

#[test]
fn useful_peer_survives_delayed_replacement_and_queued_original_recovers() {
    run_with_delayed_dial(Scenario::QueuedRecovery, true);
}

pub(super) struct HeldDial {
    release_at: tokio::time::Instant,
    packets: Vec<ReceivedPacket>,
    captured: usize,
    released: usize,
}

impl HeldDial {
    pub(super) fn new() -> Self {
        Self {
            // Longer than the existing one-second demand window, inside the
            // unchanged two-second admission budget; not a historical timing claim.
            release_at: tokio::time::Instant::now() + Duration::from_millis(1100),
            packets: Vec::new(),
            captured: 0,
            released: 0,
        }
    }

    pub(super) fn capture(
        &mut self,
        destination: usize,
        replacement: &TransportAddr,
        packet: ReceivedPacket,
    ) -> Option<ReceivedPacket> {
        if destination == 0
            && &packet.remote_addr == replacement
            && tokio::time::Instant::now() < self.release_at
            && Msg1Header::parse(packet.data.as_slice()).is_some()
        {
            assert!(self.packets.len() < 8, "bounded real replacement requests");
            self.packets.push(packet);
            self.captured += 1;
            None
        } else {
            Some(packet)
        }
    }

    pub(super) async fn release(&mut self, nodes: &mut [TestNode]) {
        if tokio::time::Instant::now() >= self.release_at {
            for packet in self.packets.drain(..) {
                crate::node::tests::spanning_tree::process_dataplane_packet_once(
                    &mut nodes[0].node,
                    packet,
                )
                .await;
                self.released += 1;
            }
        }
    }

    pub(super) fn assert_released(self) {
        assert!(
            self.captured > 0,
            "the actual replacement request was withheld"
        );
        assert_eq!(self.released, self.captured);
        assert!(self.packets.is_empty());
    }
}

pub(super) async fn admit(
    pump: &mut Pump,
    nodes: &mut [TestNode],
    endpoints: &mut [EndpointDataIo],
    ids: &[PeerIdentity],
    sequence: &mut u8,
    deadline: tokio::time::Instant,
) -> tokio::time::Instant {
    let mut before_turn = serde_json::Value::Null;
    let result = tokio::time::timeout_at(deadline, async {
        let mut admitted = None;
        let mut received = USEFUL.to_vec();
        let mut next_offer = tokio::time::Instant::now();
        let mut offered = false;
        loop {
            assert!(
                tokio::time::Instant::now() < deadline,
                "replacement admission deadline"
            );
            if admitted.is_none()
                && received.len() == USEFUL.len()
                && tokio::time::Instant::now() >= next_offer
            {
                send_round(nodes, ids, *sequence, &USEFUL).await;
                offered = true;
                received.clear();
                next_offer = tokio::time::Instant::now() + Duration::from_millis(100);
            }
            let now = Node::now_ms();
            before_turn = json!({
                "native_ms":now,
                "candidate_victim":nodes[0].node.discovery_rotation_victim(now).map(|p|label(ids,&p)),
                "returning_demand":nodes[0].node.peer_has_application_demand(ids[1].node_addr(),now,1000),
                "useful_demand":nodes[0].node.peer_has_application_demand(ids[2].node_addr(),now,1000),
            });
            pump.turn(nodes).await;
            assert!(
                tokio::time::Instant::now() < deadline,
                "replacement admission deadline"
            );
            if offered {
                pump.receive(endpoints, ids, *sequence, &USEFUL, &mut received);
                if received.len() == USEFUL.len() {
                    *sequence = sequence.checked_add(1).expect("bounded useful rounds");
                    offered = false;
                }
            }
            if reciprocal(nodes, ids, 0, 3) {
                admitted.get_or_insert_with(tokio::time::Instant::now);
            }
            if let Some(at) = admitted
                && !offered
            {
                return at;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await;
    if result.is_err() || nodes[0].node.get_peer(ids[1].node_addr()).is_some() {
        eprintln!("replacement last pre-turn state: {before_turn}");
        delivery_snapshot(nodes, ids, "replacement-admission-timeout");
    }
    result.expect("replacement must really confirm with useful traffic still progressing")
}
