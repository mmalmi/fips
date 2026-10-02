//! Cancel a real lookup send without losing the other due target.

use super::*;
use crate::node::tests::session::run_large_stack_async_test;
use crate::node::tests::spanning_tree::poll_available_packets;
use futures::FutureExt;
use std::future::Future;
use std::panic::AssertUnwindSafe;

#[test]
fn canceled_lookup_batch_keeps_unreserved_target_due() {
    run_large_stack_async_test("lookup-cancel", || async {
        let name = format!("lookup-deadline-cancel-{}", std::process::id());
        let network = SimNetwork::new(271);
        network.set_default_link(SimLink {
            up: false,
            ..Default::default()
        });
        register_sim_network(name.clone(), network.clone());
        let mut nodes = Vec::new();
        for address in ["local", "one", "two"] {
            let mut config = Config::new();
            config.node.system_files_enabled = false;
            config.node.discovery.lan.enabled = false;
            config.node.discovery.nostr.enabled = false;
            config.node.discovery.local.enabled = false;
            config.node.limits.max_peers = 2;
            config.node.limits.max_connections = 2;
            config.node.limits.max_links = 2;
            config.transports.sim = TransportInstances::Single(SimTransportConfig {
                network: Some(name.clone()),
                addr: Some(address.to_string()),
                auto_connect: Some(false),
                ..Default::default()
            });
            nodes.push(configured_discovering_node(config, address).await);
        }
        nodes.sort_by_key(|node| *node.node.node_addr());
        let result = AssertUnwindSafe(exercise(&mut nodes, &network))
            .catch_unwind()
            .await;
        for node in &nodes {
            network.set_node_send_completion_delay(node.addr.as_str().unwrap(), 0);
        }
        cleanup_nodes(&mut nodes).await;
        unregister_sim_network(&name);
        if let Err(panic) = result {
            std::panic::resume_unwind(panic);
        }
    });
}

async fn turn(nodes: &mut [TestNode]) {
    poll_available_packets(nodes).await;
    for node in nodes.iter_mut() {
        node.node.check_mmp_reports().await;
        node.node.check_tree_state().await;
        node.node.send_pending_tree_announces().await;
        node.node.check_bloom_state().await;
    }
    poll_available_packets(nodes).await;
}

async fn delivered(network: &SimNetwork) {
    tokio::time::timeout(Duration::from_secs(2), async {
        while network.stats().packets_delivered != network.stats().packets_sent {
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    })
    .await
    .expect("lossless native Sim deliveries finish");
}

async fn cancel_after_delivery<F: Future<Output = ()>>(network: &SimNetwork, operation: F) {
    // Same completion fault used by session/handshake_retention.rs: encrypted
    // wire delivery succeeds, but the local send future has not completed.
    let before = network.stats().packets_delivered;
    tokio::pin!(operation);
    tokio::time::timeout(Duration::from_secs(2), async {
        tokio::select! {
            _ = &mut operation => panic!("real send must await delayed completion"),
            _ = async {
                while network.stats().packets_delivered == before {
                    tokio::time::sleep(Duration::from_millis(1)).await;
                }
            } => {}
        }
    })
    .await
    .expect("first retry reaches its actual carrier");
    // Drop the unfinished future at a send await, as a maintenance budget does.
}

async fn exercise(nodes: &mut [TestNode], network: &SimNetwork) {
    let ids: Vec<_> = nodes.iter().map(|node| *node.node.node_addr()).collect();
    for remote in [1, 2] {
        network.set_link(
            nodes[0].addr.as_str().unwrap(),
            nodes[remote].addr.as_str().unwrap(),
            SimLink::default(),
        );
        let identity = PeerIdentity::from_pubkey_full(nodes[remote].node.identity().pubkey_full());
        let address = nodes[remote].addr.clone();
        let transport = nodes[0].transport_id;
        nodes[0]
            .node
            .initiate_connection(transport, address, identity)
            .await
            .unwrap();
    }
    let until = tokio::time::Instant::now() + Duration::from_secs(6);
    loop {
        turn(nodes).await;
        let ready = [1, 2].into_iter().all(|remote| {
            nodes[remote].node.get_peer(&ids[0]).is_some()
                && nodes[0]
                    .node
                    .get_peer(&ids[remote])
                    .is_some_and(|peer| peer.can_send() && peer.may_reach(&ids[remote]))
                && nodes[0].node.is_tree_peer(&ids[remote])
        });
        if ready
            && nodes
                .iter()
                .all(|node| *node.node.tree_state().root() == ids[0])
        {
            break;
        }
        assert!(
            tokio::time::Instant::now() < until,
            "native Noise/tree/filter setup"
        );
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    let owners: Vec<_> = [1, 2]
        .into_iter()
        .map(|remote| {
            let peer = nodes[0].node.get_peer(&ids[remote]).unwrap();
            (peer.link_id(), peer.our_index(), peer.authenticated_at())
        })
        .collect();
    delivered(network).await;
    let ttl = nodes[0].node.config.node.discovery.ttl;
    for remote in [1, 2] {
        assert_eq!(nodes[0].node.initiate_lookup(&ids[remote], ttl).await, 1);
    }
    // Do not process remote requests yet: both original lookups stay pending.
    delivered(network).await;
    let order: Vec<_> = nodes[0]
        .node
        .pending_lookups
        .iter()
        .map(|(target, entry)| (*target, entry.clone()))
        .collect();
    assert_eq!(order.len(), 2);
    assert_eq!(
        nodes[0].node.config.node.discovery.attempt_timeouts_secs,
        [1, 2, 4, 8]
    );
    let timeouts = nodes[0]
        .node
        .config
        .node
        .discovery
        .attempt_timeouts_secs
        .clone();
    let due = order
        .iter()
        .map(|(_, entry)| entry.deadline_ms(&timeouts))
        .max()
        .unwrap();
    while Node::now_ms() < due {
        tokio::time::sleep(Duration::from_millis(1)).await;
    }
    let batch_now = Node::now_ms();
    let source = nodes[0].addr.as_str().unwrap().to_owned();
    let before = network.stats().packets_sent;
    network.set_node_send_completion_delay(&source, 60_000);
    cancel_after_delivery(network, nodes[0].node.check_pending_lookups(batch_now)).await;
    assert_eq!(
        network.stats().packets_sent,
        before + 1,
        "only first retry reserved/sent"
    );

    let node = &nodes[0].node;
    let first = node.pending_lookups.get(&order[0].0).unwrap();
    let second = node.pending_lookups.get(&order[1].0).unwrap();
    assert_eq!(first.attempt, 2);
    assert_eq!(first.last_sent_ms, batch_now);
    assert_eq!(first.initiated_ms, order[0].1.initiated_ms);
    assert_eq!(second.attempt, 1, "unvisited target cannot spend a retry");
    assert_eq!(second.last_sent_ms, order[1].1.last_sent_ms);
    assert_eq!(second.initiated_ms, order[1].1.initiated_ms);
    assert!(second.deadline_ms(&timeouts) <= batch_now);
    assert!(
        node.pending_lookup_deadline_ms()
            .is_some_and(|due| due <= batch_now),
        "cancellation must retain a wake for unvisited due work"
    );

    network.set_node_send_completion_delay(&source, 0);
    // Resume at the same logical batch instant, deliberately preserving this
    // component API's existing caller-supplied clock contract. Real RX-loop
    // timing is separately exercised by lookup_deadline_rx_loop.rs.
    nodes[0].node.check_pending_lookups(batch_now).await;
    assert_eq!(
        network.stats().packets_sent,
        before + 2,
        "resume sends only untouched target"
    );
    for (target, original) in &order {
        let entry = nodes[0].node.pending_lookups.get(target).unwrap();
        assert_eq!(entry.attempt, 2);
        assert_eq!(entry.last_sent_ms, batch_now);
        assert_eq!(entry.initiated_ms, original.initiated_ms);
    }
    assert_eq!(
        nodes[0].node.pending_lookup_deadline_ms(),
        Some(batch_now + 2_000)
    );
    nodes[0].node.check_pending_lookups(batch_now).await;
    assert_eq!(
        network.stats().packets_sent,
        before + 2,
        "same-time stale wake cannot resend"
    );

    let until = tokio::time::Instant::now() + Duration::from_secs(3);
    while nodes[0].node.pending_lookups.len() != 0 {
        poll_available_packets(nodes).await;
        assert!(
            tokio::time::Instant::now() < until,
            "real signed replies complete both lookups"
        );
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    assert_eq!(nodes[0].node.pending_lookup_deadline_ms(), None);
    for (offset, remote) in [1, 2].into_iter().enumerate() {
        assert!(
            nodes[0]
                .node
                .coord_cache()
                .contains(&ids[remote], Node::now_ms())
        );
        let peer = nodes[0].node.get_peer(&ids[remote]).unwrap();
        assert_eq!(
            (peer.link_id(), peer.our_index(), peer.authenticated_at()),
            owners[offset]
        );
    }
}
