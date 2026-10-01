//! A fixture fence for one authenticated frame, not for an advisory wakeup.
use super::*;
use crate::dataplane::{DataplaneLiveNodeTurn, FmpWireHeader};
use crate::transport::{TransportAddr, TransportId};

#[path = "stale_child_completion_controls.rs"]
mod controls;

struct SelectedFrame {
    peer: NodeAddr,
    transport: TransportId,
    remote: TransportAddr,
    counter: u64,
    flags: u8,
}

impl SelectedFrame {
    fn new(peer: NodeAddr, packet: &ReceivedPacket) -> Self {
        let header = FmpWireHeader::parse_encrypted(packet.data.as_slice()).unwrap();
        Self {
            peer,
            transport: packet.transport_id,
            remote: packet.remote_addr.clone(),
            counter: header.counter(),
            flags: header.flags(),
        }
    }

    fn present_in(&self, turn: &DataplaneLiveNodeTurn) -> bool {
        turn.fmp_link_ingress().iter().any(|ingress| {
            let receipt = ingress.receipt();
            receipt.source_addr() == &self.peer
                && receipt.transport_id() == self.transport
                && receipt.remote_addr() == &self.remote
                && receipt.fmp_counter() == self.counter
                && receipt.fmp_flags() == self.flags
        })
    }
}

pub(super) async fn process_frame(
    node: &mut Node,
    peer: NodeAddr,
    packet: ReceivedPacket,
    deadline: Instant,
) -> bool {
    let selected = SelectedFrame::new(peer, &packet);
    let mut queues = Queues::take(node);
    let completed = tokio::time::timeout_at(deadline, async {
        if Instant::now() >= deadline {
            return false;
        }
        let initial = queues.pump(node, Some(packet), 64).await;
        complete(node, &mut queues, &selected, initial, deadline).await
    })
    .await
    .unwrap_or(false);
    queues.restore(node);
    completed
}

async fn complete(
    node: &mut Node,
    queues: &mut Queues,
    selected: &SelectedFrame,
    mut turn: DataplaneLiveNodeTurn,
    deadline: Instant,
) -> bool {
    loop {
        if finish(node, selected, &mut turn, deadline).await {
            return true;
        }
        if Instant::now() >= deadline {
            return false;
        }
        // Finish every returned control turn before waiting: its handlers can
        // dispatch more crypto. An advisory wake is never a completion fence.
        if !node.dataplane.has_runnable_work() {
            let notify = node.dataplane.readiness_notify();
            let _ = tokio::time::timeout_at(deadline, notify.notified()).await;
        } else {
            tokio::task::yield_now().await;
        }
        if Instant::now() >= deadline {
            return false;
        }
        turn = queues.pump(node, None, 64).await;
    }
}

async fn finish(
    node: &mut Node,
    selected: &SelectedFrame,
    turn: &mut DataplaneLiveNodeTurn,
    deadline: Instant,
) -> bool {
    let matched = selected.present_in(turn);
    // Inspect without consuming the receipt, then await the real handler. For
    // TreeAnnounce, stale is incremented only after a possible repair send.
    // Match the existing synthetic harness's heap boundary for the large live
    // handler future on libtest's default small stack.
    Box::pin(node.process_dataplane_control_ingress(turn)).await;
    Box::pin(node.drain_deferred_dataplane_control_turns()).await;
    matched && Instant::now() < deadline
}

// Keep ownership outside timeout_at so cancellation restores the node's real
// endpoint/TUN receivers instead of dropping them inside a canceled turn.
struct Queues {
    endpoint: Option<crate::node::EndpointDataBatchRx>,
    tun: Option<crate::upper::tun::TunOutboundRx>,
}

impl Queues {
    fn take(node: &mut Node) -> Self {
        Self {
            endpoint: node.endpoint_data_rx.take(),
            tun: node.tun_outbound_rx.take(),
        }
    }

    fn restore(self, node: &mut Node) {
        node.endpoint_data_rx = self.endpoint;
        node.tun_outbound_rx = self.tun;
    }

    async fn pump(
        &mut self,
        node: &mut Node,
        packet: Option<ReceivedPacket>,
        crypto_limit: usize,
    ) -> DataplaneLiveNodeTurn {
        let (_packet_tx, mut packet_rx) = crate::transport::packet_channel(1);
        let (_fast_tx, mut fast_rx) = tokio::sync::mpsc::channel(1);
        let (_endpoint_tx, mut empty_endpoint_rx) = crate::node::endpoint_data_batch_channel(1);
        let (_tun_tx, mut empty_tun_rx) = crate::upper::tun::tun_outbound_channel(1);
        let (dummy_tx, _dummy_rx) = crate::node::EndpointEventSender::channel(1);
        let endpoint_tx = node.endpoint_events.sender().unwrap_or(dummy_tx);
        let mut io = crate::node::handlers::rx_loop_dataplane_io(
            &mut packet_rx,
            &mut fast_rx,
            self.endpoint.as_mut().unwrap_or(&mut empty_endpoint_rx),
            self.tun.as_mut().unwrap_or(&mut empty_tun_rx),
            &endpoint_tx,
        );
        let packet_limit = usize::from(packet.is_some());
        Box::pin(node.drain_dataplane_turn_with_firsts(
            &mut io,
            crate::dataplane::DataplaneLiveTurnFirsts {
                raw_packet: packet,
                ..Default::default()
            },
            crate::node::handlers::RxLoopDataplaneTurnLimits::new(
                packet_limit,
                64,
                64,
                crypto_limit,
            ),
        ))
        .await
    }
}
