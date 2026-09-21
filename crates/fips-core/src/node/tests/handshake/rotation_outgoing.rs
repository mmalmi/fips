use super::*;
use crate::node::tests::session::{
    expect_single_endpoint_data_event, recv_endpoint_event_while_draining,
    run_large_stack_async_test, send_endpoint_data_via_dataplane,
};
use crate::node::wire::Msg1Header;

#[path = "rotation_outgoing/crossed.rs"]
mod crossed;

#[path = "rotation_outgoing/reply_transport.rs"]
mod reply_transport;

const IDLE_MS: u64 = 2_000;
const TIMEOUT_MS: u64 = 4_000;

async fn dial(nodes: &mut [TestNode], source: usize, destination: usize) {
    let identity = PeerIdentity::from_pubkey_full(nodes[destination].node.identity.pubkey_full());
    let remote = nodes[destination].addr.clone();
    let node = &mut nodes[source];
    node.node
        .initiate_connection(node.transport_id, remote, identity)
        .await
        .expect("an idle immature incumbent permits bounded outgoing preparation");
}

async fn next_packet(node: &mut TestNode) -> ReceivedPacket {
    tokio::time::timeout(Duration::from_secs(1), node.packet_rx.recv())
        .await
        .expect("native UDP handshake packet must arrive")
        .unwrap()
}

async fn quiesce(nodes: &mut [TestNode]) {
    tokio::time::timeout(Duration::from_secs(2), async {
        let mut idle = 0;
        while idle < 3 {
            tokio::time::sleep(Duration::from_millis(10)).await;
            if process_available_packets(nodes).await == 0 {
                idle += 1;
            } else {
                idle = 0;
            }
        }
    })
    .await
    .expect("owned UDP bootstrap must settle");
}

#[derive(Debug, PartialEq, Eq)]
struct Owner {
    link: LinkId,
    index: Option<SessionIndex>,
    epoch: Option<[u8; 8]>,
    generation: u64,
    authenticated_at: u64,
}

impl Owner {
    fn capture(node: &TestNode, peer: &NodeAddr) -> Self {
        let owner = node
            .node
            .get_peer(peer)
            .expect("original owner remains active");
        Self {
            link: owner.link_id(),
            index: owner.our_index(),
            epoch: owner.remote_epoch(),
            generation: owner.session_generation(),
            authenticated_at: owner.authenticated_at(),
        }
    }
}

struct Prepared {
    nodes: [TestNode; 3],
    old: NodeAddr,
    new: NodeAddr,
    owner: Owner,
    link: LinkId,
    index: SessionIndex,
    started_at: u64,
    attempt_at: u64,
    response: ReceivedPacket,
}

impl Prepared {
    async fn new() -> Self {
        let mut nodes = [
            make_test_node().await,
            make_test_node().await,
            make_test_node().await,
        ];
        for node in &mut nodes {
            node.node.config.node.rekey.enabled = false;
            node.node.config.node.session.idle_timeout_secs = 0;
        }
        nodes[0].node.max_peers = 1;
        nodes[0].node.max_connections = 1;
        nodes[0].node.max_links = 2;
        nodes[0].node.config.node.neighbor_rotation = Some(NeighborRotationConfig {
            idle_secs: IDLE_MS / 1000,
            interval_secs: 1,
        });
        nodes[0].node.config.node.rate_limit.handshake_timeout_secs = TIMEOUT_MS / 1000;
        let old = *nodes[2].node.node_addr();
        let new = *nodes[1].node.node_addr();
        dial(&mut nodes, 0, 2).await;
        quiesce(&mut nodes).await;
        assert_eq!(resources(&nodes[0]), (1, 0, 1, 1));
        let owner = Owner::capture(&nodes[0], &old);
        assert!(Node::now_ms() - owner.authenticated_at < IDLE_MS);

        // This is the target admission boundary: use the native initiator,
        // without backdating the real incumbent or inserting a connection.
        dial(&mut nodes, 0, 1).await;
        let pending = nodes[0].node.peers.connection_values().next().unwrap();
        let link = pending.link_id();
        let index = pending.our_index().unwrap();
        let started_at = pending.started_at();
        let attempt_at = nodes[0].node.neighbor_rotation_started_at(&new).unwrap();
        assert_eq!(resources(&nodes[0]), (1, 1, 2, 2));

        // Make receipt observably later than the original attempt. The real
        // responder supplies authenticated Noise bytes over its UDP socket.
        tokio::time::sleep(Duration::from_millis(75)).await;
        let request = next_packet(&mut nodes[1]).await;
        assert!(Msg1Header::parse(request.data.as_slice()).is_some());
        nodes[1].node.handle_msg1(request).await;
        let response = next_packet(&mut nodes[0]).await;
        assert_eq!(response.remote_addr, nodes[1].addr);
        assert_eq!(
            Msg2Header::parse(response.data.as_slice())
                .unwrap()
                .receiver_idx,
            index
        );
        assert!(response.timestamp_ms > attempt_at);
        assert!(Node::now_ms() - owner.authenticated_at < IDLE_MS);
        nodes[0].node.handle_msg2(response.clone()).await;
        let fixture = Self {
            nodes,
            old,
            new,
            owner,
            link,
            index,
            started_at,
            attempt_at,
            response,
        };
        fixture.assert_held();
        fixture
    }

    fn assert_held(&self) {
        assert_eq!(Owner::capture(&self.nodes[0], &self.old), self.owner);
        assert!(self.nodes[0].node.get_peer(&self.new).is_none());
        assert_eq!(resources(&self.nodes[0]), (1, 1, 2, 2));
        let pending = self.nodes[0].node.get_connection(&self.link).unwrap();
        assert!(pending.is_outbound() && pending.is_complete() && pending.has_session());
        assert_eq!(pending.our_index(), Some(self.index));
        assert_eq!(pending.started_at(), self.started_at);
        assert_eq!(pending.last_activity(), self.attempt_at);
        assert_eq!(
            self.nodes[0].node.neighbor_rotation_started_at(&self.new),
            Some(self.attempt_at)
        );
        assert_eq!(
            pending.remote_epoch(),
            Some(self.nodes[1].node.startup_epoch)
        );
    }

    async fn duplicate(&mut self) {
        // A duplicate is a later network arrival, not a second Noise fixture.
        let mut duplicate = self.response.clone();
        duplicate.timestamp_ms = Node::now_ms();
        self.nodes[0].node.handle_msg2(duplicate).await;
        self.assert_held();
    }

    async fn maintenance(&mut self) {
        // Same ordering as the runtime's ordinary fast maintenance, without
        // calling a promotion helper or manufacturing an admission decision.
        self.nodes[0].node.check_timeouts().await;
        self.nodes[0]
            .node
            .resend_pending_handshakes(Node::now_ms())
            .await;
    }
}

#[test]
fn outgoing_preparation_waits_for_real_age_then_confirms_and_delivers_once() {
    run_large_stack_async_test("outgoing-preparation-age", || async {
        let mut f = Prepared::new().await;
        f.duplicate().await;
        f.maintenance().await;
        f.assert_held();
        assert!(
            tokio::time::timeout(Duration::from_millis(50), f.nodes[1].packet_rx.recv())
                .await
                .is_err(),
            "held Msg2 must not emit an encrypted confirmation or bootstrap"
        );

        let eligible_at = f.owner.authenticated_at + IDLE_MS;
        while Node::now_ms() <= eligible_at {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        let promotion_at = Node::now_ms();
        f.maintenance().await;
        f.assert_held();
        // Maturity permits the readiness send, but only the peer's actual
        // encrypted response can authorize the outgoing replacement.
        quiesce(&mut f.nodes).await;
        let active = f.nodes[0]
            .node
            .get_peer(&f.new)
            .expect("fresh peer proof promotes the mature outgoing candidate");
        assert_eq!(active.link_id(), f.link);
        assert_eq!(active.our_index(), Some(f.index));
        assert!(
            active.authenticated_at() >= promotion_at,
            "the new neighbor gets its full age grace from promotion, not old Msg2 receipt"
        );
        assert!(f.nodes[0].node.get_peer(&f.old).is_none());
        assert_eq!(resources(&f.nodes[0]), (1, 0, 1, 1));
        assert!(f.nodes[0].node.pending_outbound.is_empty());
        quiesce(&mut f.nodes).await;

        let local = *f.nodes[0].node.node_addr();
        let heartbeat = [crate::protocol::LinkMessageType::Heartbeat.to_byte()];
        for (source, destination) in [(0, f.new), (1, local)] {
            f.nodes[source]
                .node
                .send_dataplane_fmp_link_plaintext(&destination, &heartbeat, false)
                .await
                .unwrap();
        }
        quiesce(&mut f.nodes).await;
        let a = f.nodes[0].node.get_peer(&f.new).unwrap();
        let b = f.nodes[1].node.get_peer(&local).unwrap();
        assert_eq!(a.our_index(), b.their_index());
        assert_eq!(a.their_index(), b.our_index());
        for (source, destination) in [(0, f.new), (1, local)] {
            assert!(
                f.nodes[source]
                    .node
                    .dataplane_fmp_link_metrics(&destination, Instant::now())
                    .unwrap()
                    .current_epoch_authenticated
            );
        }

        let remote = PeerIdentity::from_pubkey_full(f.nodes[1].node.identity.pubkey_full());
        let mut endpoint = f.nodes[1].node.attach_endpoint_data_io(8).unwrap();
        send_endpoint_data_via_dataplane(&mut f.nodes[0].node, remote, b"prepared-once".to_vec())
            .await
            .unwrap();
        let event = recv_endpoint_event_while_draining(
            &mut f.nodes,
            &mut endpoint.event_rx,
            Duration::from_secs(3),
            "prepared outgoing payload",
        )
        .await;
        endpoint.event_rx.release_messages(event.messages.len());
        assert_eq!(
            expect_single_endpoint_data_event(event).payload.as_slice(),
            b"prepared-once"
        );
        for _ in 0..3 {
            f.maintenance().await;
            quiesce(&mut f.nodes).await;
        }
        assert!(matches!(
            endpoint.event_rx.try_recv(),
            Err(tokio::sync::mpsc::error::TryRecvError::Empty)
        ));
        cleanup_nodes(&mut f.nodes).await;
    });
}

#[test]
fn outgoing_preparation_preserves_new_application_demand_and_original_expiry() {
    run_large_stack_async_test("outgoing-preparation-demand-expiry", || async {
        let mut f = Prepared::new().await;
        let old = PeerIdentity::from_pubkey_full(f.nodes[2].node.identity.pubkey_full());
        let mut endpoint = f.nodes[2].node.attach_endpoint_data_io(8).unwrap();
        let deadline = f.attempt_at + TIMEOUT_MS;
        let bound = tokio::time::Instant::now() + Duration::from_secs(7);
        let mut sequence = 0u8;
        loop {
            assert!(
                tokio::time::Instant::now() < bound,
                "candidate must expire at its original deadline"
            );
            // Real new application work arrives after Noise authentication.
            // Do not protect the old peer by setting a private demand marker.
            let payload = vec![sequence; 64];
            send_endpoint_data_via_dataplane(&mut f.nodes[0].node, old, payload.clone())
                .await
                .unwrap();
            let event = recv_endpoint_event_while_draining(
                &mut f.nodes,
                &mut endpoint.event_rx,
                Duration::from_secs(2),
                "incumbent application demand",
            )
            .await;
            endpoint.event_rx.release_messages(event.messages.len());
            assert_eq!(
                expect_single_endpoint_data_event(event).payload.as_slice(),
                payload
            );
            assert!(
                f.nodes[0]
                    .node
                    .peer_has_application_demand(&f.old, Node::now_ms(), IDLE_MS)
            );
            let now = Node::now_ms();
            if now.saturating_add(50) >= deadline {
                tokio::time::sleep(Duration::from_millis(deadline.saturating_sub(now) + 10)).await;
                break;
            }
            f.duplicate().await;
            f.maintenance().await;
            f.assert_held();
            sequence += 1;
            tokio::time::sleep(Duration::from_millis(250)).await;
        }

        f.maintenance().await;
        assert_eq!(Owner::capture(&f.nodes[0], &f.old), f.owner);
        assert!(f.nodes[0].node.get_peer(&f.new).is_none());
        assert_eq!(resources(&f.nodes[0]), (1, 0, 1, 1));
        assert!(f.nodes[0].node.get_connection(&f.link).is_none());
        assert!(!f.nodes[0].node.index_allocator.is_allocated(f.index));
        assert!(f.nodes[0].node.pending_outbound.is_empty());
        let mut late = f.response;
        late.timestamp_ms = Node::now_ms();
        f.nodes[0].node.handle_msg2(late).await;
        assert_eq!(Owner::capture(&f.nodes[0], &f.old), f.owner);
        assert_eq!(resources(&f.nodes[0]), (1, 0, 1, 1));
        assert!(f.nodes[0].node.get_peer(&f.new).is_none());
        cleanup_nodes(&mut f.nodes).await;
    });
}
