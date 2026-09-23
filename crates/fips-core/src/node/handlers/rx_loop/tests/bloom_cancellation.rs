//! Exercise the real fast-turn timebox with a delivered, unfinished Sim send.
use super::super::budget::{PACKET_DRAIN_BUDGET, RX_LOOP_FAST_MAINTENANCE_TIMEOUT};
use crate::SimNetwork;
use crate::node::Node;
use crate::transport::{PacketBuffer, ReceivedPacket, TransportAddr, TransportId, packet_channel};
use std::time::{Duration, Instant};

impl Node {
    // Test-only adapter keeps the private RX turn private in production. Native
    // authentication, successful anchors and cleanup belong to bloom_refresh.
    pub(in crate::node) async fn assert_canceled_routing_turn_drains_data(
        &mut self,
        network: &SimNetwork,
        source: &str,
        tree_first: bool,
    ) {
        assert_eq!(PACKET_DRAIN_BUDGET, 512);
        assert_eq!(self.config.node.tick_interval_secs, 1);
        assert_eq!(self.bloom_state.update_debounce_ms(), 500);
        assert!(self.pending_tree_announce_deadline_ms().is_none());
        let pending = self.bloom_state.pending_peers_due(Self::now_ms());
        assert_eq!(pending.len(), 2, "both real peers must be due");
        let original_due: Vec<_> = pending
            .iter()
            .map(|peer| {
                (
                    *peer,
                    self.bloom_state.pending_peer_deadline_ms(peer).unwrap(),
                )
            })
            .collect();
        let tree_sent = self.stats().tree.sent;
        if tree_first {
            self.mark_all_tree_announces_pending();
            assert!(self.pending_tree_announce_deadline_ms().unwrap() <= Self::now_ms());
        }
        let sent = self.stats().bloom.sent;
        let failed = self.stats().bloom.send_failed;
        let wire_before = network.stats().packets_delivered;
        assert_eq!(wire_before, network.stats().packets_sent);
        let (packet_tx, mut packet_rx) = packet_channel(PACKET_DRAIN_BUDGET + 1);
        for _ in 0..=PACKET_DRAIN_BUDGET {
            // As in the existing failed-tree-turn control, these are rejected
            // raw ingress packets. This proves queue progress and its cap, not
            // application payload delivery.
            packet_tx
                .send(ReceivedPacket::with_timestamp(
                    TransportId::new(7),
                    TransportAddr::from_string("127.0.0.1:9000"),
                    PacketBuffer::new(vec![0]),
                    Self::now_ms(),
                ))
                .unwrap();
        }
        let (_endpoint_tx, mut endpoint_rx) = crate::node::endpoint_data_batch_channel(1);
        let (_tun_tx, mut tun_rx) = crate::upper::tun::tun_outbound_channel(1);
        let (_fast_tx, mut fast_rx) = tokio::sync::mpsc::channel(1);
        let endpoint_io = self.attach_endpoint_data_io(1).unwrap();
        network.set_node_send_completion_delay(source, 60_000);
        let before_ms = Self::now_ms();
        let started = Instant::now();
        let (completed, drained) = {
            let mut io = super::super::rx_loop_dataplane_io(
                &mut packet_rx,
                &mut fast_rx,
                &mut endpoint_rx,
                &mut tun_rx,
                &endpoint_io.event_tx,
            );
            tokio::time::timeout(
                RX_LOOP_FAST_MAINTENANCE_TIMEOUT + Duration::from_secs(1),
                self.run_rx_loop_routing_announce_turn(&mut io),
            )
            .await
            .expect("routing turn must obey its existing fast budget")
        };
        let after_ms = Self::now_ms();
        network.set_node_send_completion_delay(source, 0);
        assert!(
            !completed,
            "the existing fast budget cancels the stalled completion"
        );
        assert!(started.elapsed() >= RX_LOOP_FAST_MAINTENANCE_TIMEOUT);
        assert_eq!(network.stats().packets_delivered, wire_before + 1);
        assert_eq!(network.stats().packets_sent, wire_before + 1);
        assert_eq!(self.stats().bloom.sent, sent, "no successful-send commit");
        assert_eq!(self.stats().bloom.send_failed, failed);
        assert_eq!(drained.packets, PACKET_DRAIN_BUDGET);
        assert!(drained.has_data_drained());
        assert!(
            packet_rx.try_recv().is_ok(),
            "one excess packet remains queued"
        );
        assert!(packet_rx.try_recv().is_err());

        let timeout_ms = u64::try_from(RX_LOOP_FAST_MAINTENANCE_TIMEOUT.as_millis()).unwrap();
        for (peer, successful_due) in original_due {
            assert!(self.bloom_state.needs_update(&peer));
            // These are read-only queries at the recorded successful deadline,
            // not fabricated history. Neither selected nor unvisited history
            // can move while the selected send is unfinished.
            assert!(
                !self
                    .bloom_state
                    .should_send_update(&peer, successful_due - 1)
            );
            assert!(self.bloom_state.should_send_update(&peer, successful_due));
            let retry = self.bloom_state.pending_peer_deadline_ms(&peer).unwrap();
            if tree_first {
                assert_eq!(
                    retry, successful_due,
                    "unvisited Bloom remains immediately due"
                );
                assert!(retry <= after_ms);
            } else {
                assert!(
                    retry >= before_ms + timeout_ms + 999,
                    "retry floor must be set after timeout"
                );
                assert!(retry <= after_ms + 1_000);
                assert!(
                    retry > after_ms,
                    "pre-await retry floor would already be expired"
                );
            }
        }
        let tree_retry = tree_first.then(|| self.pending_tree_announce_deadline_ms().unwrap());
        if let Some(retry) = tree_retry {
            assert!(retry >= before_ms + timeout_ms + 999);
            assert!(retry <= after_ms + 1_000);
            assert!(retry > after_ms);
            assert_eq!(self.stats().tree.sent, tree_sent);
            assert!(
                self.peers
                    .values()
                    .all(|peer| peer.has_pending_tree_announce())
            );
        }
        let next = self.bloom_state.pending_update_deadline_ms().unwrap();
        assert_eq!(self.pending_routing_announce_deadline_ms(), Some(next));
        let mut io = super::super::rx_loop_dataplane_io(
            &mut packet_rx,
            &mut fast_rx,
            &mut endpoint_rx,
            &mut tun_rx,
            &endpoint_io.event_tx,
        );
        let (completed, drained) = self.run_rx_loop_routing_announce_turn(&mut io).await;
        assert!(
            completed,
            "a stale fast wake must not enter another stalled send"
        );
        assert_eq!(drained.packets, 0);
        if let Some(retry) = tree_retry {
            assert!(
                Self::now_ms() < retry,
                "Bloom must run before the tree retry floor"
            );
            assert_eq!(self.pending_tree_announce_deadline_ms(), Some(retry));
            assert_eq!(self.stats().tree.sent, tree_sent);
            assert!(
                self.peers
                    .values()
                    .all(|peer| peer.has_pending_tree_announce())
            );
            assert_eq!(network.stats().packets_sent, wire_before + 3);
            assert_eq!(self.stats().bloom.sent, sent + 2);
            assert_eq!(self.bloom_state.pending_update_deadline_ms(), None);
        } else {
            assert_eq!(network.stats().packets_sent, wire_before + 1);
            assert_eq!(self.stats().bloom.sent, sent);
            assert_eq!(self.bloom_state.pending_update_deadline_ms(), Some(next));
        }
    }
}
