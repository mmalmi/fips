use super::*;
use crate::node::rate_limit::{HandshakeRateLimiter, TokenBucket};
use crate::node::tests::session::{
    expect_single_endpoint_data_event, recv_endpoint_event_while_draining,
    run_large_stack_async_test, send_endpoint_data_via_dataplane,
};
use crate::node::tests::spanning_tree::complete_direct_handshake;
use futures::FutureExt;
use std::panic::AssertUnwindSafe;

#[test]
fn authenticated_identity_churn_preserves_useful_peer_and_reclaims_links() {
    run_large_stack_async_test("rotation-identity-churn", || async {
        let mut nodes = [make_test_node().await, make_test_node().await];
        let result = AssertUnwindSafe(exercise(&mut nodes)).catch_unwind().await;
        cleanup_nodes(&mut nodes).await;
        if let Err(panic) = result {
            std::panic::resume_unwind(panic);
        }
    });
}

async fn deliver(
    nodes: &mut [TestNode; 2],
    endpoints: &mut [crate::node::EndpointDataIo; 2],
    sequence: u8,
) {
    for source in 0..2 {
        let target = 1 - source;
        let identity = PeerIdentity::from_pubkey_full(nodes[target].node.identity.pubkey_full());
        let payload = vec![sequence; 256];
        send_endpoint_data_via_dataplane(&mut nodes[source].node, identity, payload.clone())
            .await
            .unwrap();
        let rx = &mut endpoints[target].event_rx;
        let event = recv_endpoint_event_while_draining(
            nodes,
            rx,
            Duration::from_secs(2),
            "useful peer must carry application data throughout authenticated churn",
        )
        .await;
        rx.release_messages(event.messages.len());
        assert_eq!(
            expect_single_endpoint_data_event(event).payload.as_slice(),
            payload
        );
    }
}

async fn exercise(nodes: &mut [TestNode; 2]) {
    for node in nodes.iter_mut() {
        node.node.config.node.rekey.enabled = false;
    }
    complete_direct_handshake(nodes, 0, 1).await;
    let useful = *nodes[1].node.node_addr();
    let mut endpoints = [
        nodes[0].node.attach_endpoint_data_io(8).unwrap(),
        nodes[1].node.attach_endpoint_data_io(8).unwrap(),
    ];
    deliver(nodes, &mut endpoints, 0).await;
    let owner = nodes[0].node.get_peer(&useful).unwrap();
    let useful_owner = (
        owner.link_id(),
        owner.our_index(),
        owner.session_generation(),
    );
    let session_hash = *nodes[0]
        .node
        .get_session(&useful)
        .unwrap()
        .handshake_hash()
        .unwrap();

    let first = make_node();
    let (_first_socket, first_source) = local_path().await;
    let mut retired = incumbent(&mut nodes[0], &first, &first_source, 1_000, 60_000).await;
    let mut retired_identity = *first.node_addr();
    enable(&mut nodes[0], 2);
    nodes[0]
        .node
        .config
        .node
        .neighbor_rotation
        .as_mut()
        .unwrap()
        .interval_secs = 1;
    // The common fixture raises admission limits for large topologies. Restore
    // ordinary stranger capacity here; this is paced churn, not a CPU flood.
    nodes[0].node.msg1_rate_limiter = HandshakeRateLimiter::with_params(
        TokenBucket::with_params(100, 10.0),
        TokenBucket::with_params(2, 10.0),
        1,
    );

    // Reuse a carrier on alternate admissions, and use a fresh source port
    // otherwise. Identity changes must release ownership in both cases.
    let (_shared_socket, shared_source) = local_path().await;
    for round in 1..=32 {
        let mature = nodes[0]
            .node
            .get_peer(&retired_identity)
            .unwrap()
            .authenticated_at()
            + 1_050;
        while Node::now_ms() < mature {
            deliver(nodes, &mut endpoints, round).await;
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
        deliver(nodes, &mut endpoints, round).await;
        assert!(
            nodes[0]
                .node
                .peer_has_application_demand(&useful, Node::now_ms(), 1_000)
        );

        let newcomer = make_node();
        let (_socket, fresh_source) = local_path().await;
        let source = if round % 2 == 0 {
            &shared_source
        } else {
            &fresh_source
        };
        let mut candidate =
            connect(&mut nodes[0], &newcomer, source, 1_000 + u32::from(round)).await;
        assert_eq!(resources(&nodes[0]), (2, 1, 3, 3));
        let pending = candidate.link;
        // A different valid Noise identity cannot steal the in-flight slot.
        let competitor = make_node();
        request(&mut nodes[0], &competitor, source, 2_000 + u32::from(round)).await;
        assert_eq!(resources(&nodes[0]), (2, 1, 3, 3));
        assert!(nodes[0].node.get_connection(&pending).is_some());
        assert!(nodes[0].node.get_peer(competitor.node_addr()).is_none());

        let proof = candidate.frame(
            nodes[0].transport_id,
            &[crate::protocol::LinkMessageType::Heartbeat.to_byte()],
        );
        assert!(nodes[0].node.confirm_pending_handshake(proof).await);
        process_available_packets(nodes).await;
        assert_eq!(resources(&nodes[0]), (2, 0, 2, 2));
        assert!(nodes[0].node.pending_outbound.is_empty());
        assert!(nodes[0].node.pending_connects.is_empty());
        assert!(nodes[0].node.get_peer(&retired_identity).is_none());
        assert!(!nodes[0].node.index_allocator.is_allocated(retired.index));
        assert!(nodes[0].node.links.get(&retired.link).is_none());
        let stale = retired.frame(
            nodes[0].transport_id,
            &[crate::protocol::LinkMessageType::Heartbeat.to_byte()],
        );
        assert!(!nodes[0].node.confirm_pending_handshake(stale).await);
        assert_eq!(resources(&nodes[0]), (2, 0, 2, 2));

        deliver(nodes, &mut endpoints, round).await;
        let owner = nodes[0].node.get_peer(&useful).unwrap();
        assert_eq!(
            (
                owner.link_id(),
                owner.our_index(),
                owner.session_generation()
            ),
            useful_owner
        );
        assert_eq!(
            nodes[0].node.get_session(&useful).unwrap().handshake_hash(),
            Some(&session_hash)
        );
        assert_eq!(
            heartbeat(&mut nodes[0], &newcomer, &mut candidate, 2).await,
            2
        );
        retired = candidate;
        retired_identity = *newcomer.node_addr();
    }

    // After the churn, an ordinary newcomer still obtains a usable slot.
    tokio::time::sleep(Duration::from_millis(1_050)).await;
    deliver(nodes, &mut endpoints, 33).await;
    let honest = make_node();
    let (_socket, source) = local_path().await;
    let mut admitted = connect(&mut nodes[0], &honest, &source, 3_000).await;
    let proof = admitted.frame(
        nodes[0].transport_id,
        &[crate::protocol::LinkMessageType::Heartbeat.to_byte()],
    );
    assert!(nodes[0].node.confirm_pending_handshake(proof).await);
    process_available_packets(nodes).await;
    assert_eq!(resources(&nodes[0]), (2, 0, 2, 2));
    assert_eq!(heartbeat(&mut nodes[0], &honest, &mut admitted, 2).await, 2);
    deliver(nodes, &mut endpoints, 34).await;
}
