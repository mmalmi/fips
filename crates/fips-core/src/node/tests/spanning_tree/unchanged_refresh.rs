//! A fresh signature alone must not invalidate a usable application route.
use super::*;
use crate::dataplane::DataplaneLiveOutboundFirsts;
use crate::node::tests::session::{
    expect_single_endpoint_data_event, recv_endpoint_event_while_draining,
    run_large_stack_async_test, send_endpoint_data_via_dataplane,
};
use futures::FutureExt;
use std::panic::AssertUnwindSafe;

#[test]
fn unchanged_signed_parent_refresh_preserves_routed_application_state() {
    run_large_stack_async_test("unchanged-tree-refresh", || async {
        let _guard = lock_large_network_test().await;
        let mut nodes = run_tree_test(3, &[(0, 1), (1, 2)], false).await;
        let result = AssertUnwindSafe(exercise(&mut nodes)).catch_unwind().await;
        cleanup_nodes(&mut nodes).await;
        if let Err(panic) = result {
            std::panic::resume_unwind(panic);
        }
    });
}

async fn exercise(nodes: &mut [TestNode]) {
    verify_tree_convergence(nodes);
    // The existing fixture seeds coordinates only for setup. From this point
    // onwards, the signed handler and normal application dataplane do the work.
    populate_all_coord_caches(nodes);
    let source = [0, 2]
        .into_iter()
        .find(|&index| !nodes[index].node.tree_state().is_root())
        .expect("at least one leaf is not root");
    let destination_index = 2 - source;
    let parent = PeerIdentity::from_pubkey_full(nodes[1].node.identity().pubkey_full());
    let remote =
        PeerIdentity::from_pubkey_full(nodes[destination_index].node.identity().pubkey_full());
    let destination = *remote.node_addr();
    assert_eq!(
        nodes[source].node.tree_state().my_declaration().parent_id(),
        parent.node_addr()
    );
    let _source_io = nodes[source].node.attach_endpoint_data_io(8).unwrap();
    let mut destination_io = nodes[destination_index]
        .node
        .attach_endpoint_data_io(8)
        .unwrap();
    nodes[source]
        .node
        .set_endpoint_source_route(remote, Some(parent))
        .unwrap();
    send_endpoint_data_via_dataplane(&mut nodes[source].node, remote, b"before".to_vec())
        .await
        .unwrap();
    let first = recv_endpoint_event_while_draining(
        nodes,
        &mut destination_io.event_rx,
        Duration::from_secs(5),
        "establish unchanged-path session",
    )
    .await;
    assert_eq!(
        expect_single_endpoint_data_event(first).payload.as_slice(),
        b"before"
    );

    let cached = nodes[source]
        .node
        .coord_cache
        .get(&destination, Node::now_ms())
        .unwrap()
        .clone();
    let own_path: Vec<_> = nodes[source]
        .node
        .tree_state()
        .my_coords()
        .node_addrs()
        .copied()
        .collect();
    let epoch = nodes[source]
        .node
        .get_session(&destination)
        .unwrap()
        .session_start_ms();
    let carrier = nodes[source]
        .node
        .dataplane
        .fsp_owner_next_hop(&destination);
    assert_eq!(carrier, Some(*parent.node_addr()));
    assert!(
        !nodes[source]
            .node
            .pending_lookups
            .contains_key(&destination)
    );
    nodes[source]
        .node
        .discovery_backoff
        .record_failure(&destination);
    let failures = nodes[source]
        .node
        .discovery_backoff
        .failure_count(&destination);
    assert!(failures > 0);
    let lookups = nodes[source].node.stats().discovery.req_initiated;
    let accepted = nodes[source].node.stats().tree.accepted;
    let parent_state = nodes[1].node.tree_state();
    let sequence = parent_state.my_declaration().sequence().max(
        nodes[source]
            .node
            .tree_state()
            .peer_declaration(parent.node_addr())
            .unwrap()
            .sequence(),
    ) + 1;
    let mut declaration = ParentDeclaration::new(
        *parent.node_addr(),
        *parent_state.my_declaration().parent_id(),
        sequence,
        crate::time::now_secs(),
    );
    declaration.sign(nodes[1].node.identity()).unwrap();
    let encoded = TreeAnnounce::new(declaration, parent_state.my_coords().clone())
        .encode()
        .unwrap();
    nodes[source]
        .node
        .handle_tree_announce(parent.node_addr(), &encoded[1..])
        .await;

    // A stale/rejected announcement would be a false pass for preservation.
    let node = &nodes[source].node;
    assert_eq!(node.stats().tree.accepted, accepted + 1);
    assert_eq!(
        node.tree_state()
            .peer_declaration(parent.node_addr())
            .unwrap()
            .sequence(),
        sequence
    );
    assert_eq!(
        node.tree_state()
            .my_coords()
            .node_addrs()
            .copied()
            .collect::<Vec<_>>(),
        own_path,
        "fresh declaration metadata must retain the same address path"
    );
    assert_eq!(
        node.coord_cache.get(&destination, Node::now_ms()),
        Some(&cached)
    );
    assert_eq!(node.discovery_backoff.failure_count(&destination), failures);
    assert_eq!(node.dataplane.fsp_owner_next_hop(&destination), carrier);
    assert_eq!(
        node.get_session(&destination).unwrap().session_start_ms(),
        epoch
    );
    assert!(!node.pending_lookups.contains_key(&destination));

    // Bypass the slow endpoint helper: a missing application map would defer
    // this batch and potentially recreate the route, masking invalidation.
    let batch = NodeEndpointDataBatch::from_payloads(
        remote,
        vec![EndpointDataPayload::from_packet_payload(b"after".to_vec()).unwrap()],
        None,
    )
    .unwrap();
    let turn = nodes[source]
        .node
        .pump_dataplane_pending_outbound_firsts(
            DataplaneLiveOutboundFirsts {
                endpoint_data_batch: Some(batch),
                ..Default::default()
            },
            1,
            0,
            1,
        )
        .await;
    assert_eq!(turn.deferred_endpoint_data_batches_count(), 0);
    assert!(turn.endpoint_data_drops().is_empty());
    nodes[source].node.defer_dataplane_control_turn(turn);
    let delivered = recv_endpoint_event_while_draining(
        nodes,
        &mut destination_io.event_rx,
        Duration::from_secs(5),
        "cached application route after unchanged signed refresh",
    )
    .await;
    assert_eq!(
        expect_single_endpoint_data_event(delivered)
            .payload
            .as_slice(),
        b"after"
    );
    assert_eq!(nodes[source].node.stats().discovery.req_initiated, lookups);
    assert!(
        !nodes[source]
            .node
            .pending_lookups
            .contains_key(&destination)
    );
}
