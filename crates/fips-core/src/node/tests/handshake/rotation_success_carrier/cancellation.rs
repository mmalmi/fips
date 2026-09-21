//! A promoted receiver keeps its first packet when bootstrap is cancelled.
use super::*;
use crate::node::tests::session::run_large_stack_async_test;
use crate::node::tests::spanning_tree::{
    process_dataplane_completions, process_dataplane_packet, process_node_packets,
};
use futures::FutureExt;
use std::panic::AssertUnwindSafe;

#[test]
fn cancelled_post_promotion_bootstrap_delivers_first_tcp_packet_once() {
    run_large_stack_async_test("rotation-cancelled-bootstrap-proof", || async {
        let mut node = make_test_node().await;
        let result = AssertUnwindSafe(exercise(&mut node)).catch_unwind().await;
        cleanup_nodes(std::slice::from_mut(&mut node)).await;
        if let Err(panic) = result {
            std::panic::resume_unwind(panic);
        }
    });
}

async fn exercise(node: &mut TestNode) {
    let old = make_node();
    let newcomer = make_node();
    let (_old_socket, old_source) = local_path().await;
    let old_owner = incumbent(node, &old, &old_source, 190, 0).await;
    let original_authenticated_at = node
        .node
        .get_peer(old.node_addr())
        .unwrap()
        .authenticated_at();
    enable(node, 1);

    // The old carrier is UDP so the candidate's TCP pool lock cannot block
    // pre-promotion carrier cleanup. Let the actual one-second idle age pass.
    tokio::time::timeout(Duration::from_secs(2), async {
        while Node::now_ms().saturating_sub(original_authenticated_at) < 1_050 {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("incumbent must become eligible through real elapsed time");
    assert!(node.node.has_neighbor_rotation_opportunity(Node::now_ms()));

    let tcp_id = TransportId::new(2);
    let (tx, mut rx) = packet_channel(16);
    let mut tcp = TcpTransport::new(
        tcp_id,
        None,
        TcpConfig {
            bind_addr: Some("127.0.0.1:0".into()),
            max_inbound_connections: Some(1),
            ..Default::default()
        },
        tx,
    );
    tcp.start_async().await.unwrap();
    let listen = tcp.local_addr().unwrap();
    let stats = tcp.stats().clone();
    node.node
        .transports
        .insert(tcp_id, TransportHandle::Tcp(tcp));

    let (mut stream, mut candidate) =
        tcp_candidate(node, &mut rx, tcp_id, listen, &newcomer, 191, 0).await;
    assert_eq!(resources(node), (1, 1, 2, 2));
    assert!(node.node.get_peer(newcomer.node_addr()).is_none());
    assert_eq!(stats.snapshot().pool_inbound, 1);
    write_heartbeat(&mut stream, &mut candidate, tcp_id).await;
    let first = next_packet(&mut rx).await;
    assert_eq!(first.transport_id, tcp_id);
    assert_eq!(first.remote_addr, candidate.source);
    let first_wire = first.data.as_slice().to_vec();

    let guard = match node.node.transports.get(&tcp_id).unwrap() {
        TransportHandle::Tcp(tcp) => tcp.test_pool_guard().await,
        _ => unreachable!(),
    };
    let mut promotion = Box::pin(node.node.confirm_pending_handshake(first));
    assert!(
        futures::poll!(promotion.as_mut()).is_pending(),
        "bootstrap cannot finish its TCP send while the pool is locked"
    );
    drop(promotion);

    // A Pending poll alone would not prove the desired cancellation point.
    // These exact owner assertions establish that promotion already consumed
    // the connection; the first suspension may be bootstrap crypto or TCP I/O.
    assert_eq!(resources(node), (1, 0, 1, 1));
    assert!(node.node.get_peer(old.node_addr()).is_none());
    assert!(!node.node.index_allocator.is_allocated(old_owner.index));
    assert!(node.node.get_connection(&candidate.link).is_none());
    let active = node.node.get_peer(newcomer.node_addr()).unwrap();
    assert_eq!(active.link_id(), candidate.link);
    assert_eq!(active.our_index(), Some(candidate.index));
    assert_eq!(active.transport_id(), Some(tcp_id));
    assert_eq!(active.current_addr(), Some(&candidate.source));
    let original_generation = active.session_generation();
    assert!(node.node.dataplane_has_fmp_owner(newcomer.node_addr()));
    drop(guard);

    // No proof resubmission or handshake retry: only ordinary ingress and
    // completion turns may deliver the packet saved before cancellation.
    process_node_packets(&mut node.node, &mut rx).await;
    assert_eq!(await_heartbeat(node, &newcomer, 1).await, 1);

    // Replay the exact bytes over the same real stream. They must go through
    // normal replay protection, without another received heartbeat.
    stream.write_all(&first_wire).await.unwrap();
    let replay = next_packet(&mut rx).await;
    assert!(replay.data.as_slice() == first_wire.as_slice());
    process_dataplane_packet(node, replay).await;
    process_dataplane_completions(&mut node.node).await;
    assert_eq!(await_heartbeat(node, &newcomer, 1).await, 1);

    write_heartbeat(&mut stream, &mut candidate, tcp_id).await;
    let fresh = next_packet(&mut rx).await;
    process_dataplane_packet(node, fresh).await;
    assert_eq!(await_heartbeat(node, &newcomer, 2).await, 2);
    process_node_packets(&mut node.node, &mut rx).await;
    assert_eq!(await_heartbeat(node, &newcomer, 2).await, 2);
    let active = node.node.get_peer(newcomer.node_addr()).unwrap();
    assert_eq!(active.link_id(), candidate.link);
    assert_eq!(active.our_index(), Some(candidate.index));
    assert_eq!(active.session_generation(), original_generation);
    assert_eq!(resources(node), (1, 0, 1, 1));
    assert_eq!(stats.snapshot().pool_inbound, 1);
}
