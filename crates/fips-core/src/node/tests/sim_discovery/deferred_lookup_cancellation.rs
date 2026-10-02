//! Cancellation after real wire delivery preserves discovery work ownership.
use super::*;
use crate::node::tests::session::run_large_stack_async_test;
use crate::node::tests::spanning_tree::{poll_available_packets, process_available_packets};
use crate::protocol::LookupRequest;
use futures::FutureExt;
use std::future::Future;
use std::panic::AssertUnwindSafe;

#[test]
fn canceled_deferred_send_preserves_local_retry_and_untouched_waiter() {
    run_cancellation(false);
}

#[test]
fn deferred_competition_drains_ready_work_without_a_new_wakeup() {
    run_cancellation(true);
}

fn run_cancellation(retain_competing_wakeup: bool) {
    run_large_stack_async_test("deferred-lookup-cancel", move || async move {
        let name = format!(
            "deferred-lookup-cancel-{}-{retain_competing_wakeup}",
            std::process::id()
        );
        let network = SimNetwork::new(272);
        network.set_default_link(SimLink {
            up: false,
            ..Default::default()
        });
        register_sim_network(name.clone(), network.clone());
        let mut nodes = Vec::new();
        for address in ["relay", "noisy", "quiet", "one", "two"] {
            let mut config = Config::new();
            config.node.system_files_enabled = false;
            config.node.discovery.lan.enabled = false;
            config.node.discovery.nostr.enabled = false;
            config.node.discovery.local.enabled = false;
            config.node.limits.max_peers = 4;
            config.node.limits.max_connections = 4;
            config.node.limits.max_links = 4;
            config.transports.sim = TransportInstances::Single(SimTransportConfig {
                network: Some(name.clone()),
                addr: Some(address.to_string()),
                auto_connect: Some(false),
                ..Default::default()
            });
            nodes.push(configured_discovering_node(config, address).await);
        }
        nodes.sort_by_key(|node| *node.node.node_addr());
        let result = AssertUnwindSafe(exercise(&mut nodes, &network, retain_competing_wakeup))
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
    .expect("all scheduled lossless deliveries complete");
}

type PeerOwner = (
    NodeAddr,
    LinkId,
    Option<crate::utils::index::SessionIndex>,
    u64,
);

fn owners(nodes: &[TestNode]) -> Vec<Vec<PeerOwner>> {
    nodes
        .iter()
        .enumerate()
        .map(|(index, node)| {
            let mut peers = node
                .node
                .peers
                .values()
                .map(|peer| {
                    assert!(peer.is_healthy() && peer.can_send());
                    (
                        *peer.node_addr(),
                        peer.link_id(),
                        peer.our_index(),
                        peer.authenticated_at(),
                    )
                })
                .collect::<Vec<_>>();
            peers.sort_by_key(|peer| peer.0);
            assert_eq!(peers.len(), if index == 0 { 4 } else { 1 });
            assert_eq!(node.node.link_count(), peers.len());
            assert_eq!(node.node.connection_count(), 0);
            peers
        })
        .collect()
}

async fn setup(nodes: &mut [TestNode], network: &SimNetwork) {
    let ids: Vec<_> = nodes.iter().map(|node| *node.node.node_addr()).collect();
    for remote in 1..nodes.len() {
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
        if (1..nodes.len()).all(|remote| {
            nodes[remote].node.get_peer(&ids[0]).is_some()
                && nodes[0].node.is_tree_peer(&ids[remote])
                && nodes[0].node.get_peer(&ids[remote]).is_some_and(|peer| {
                    peer.is_healthy() && peer.can_send() && peer.may_reach(&ids[remote])
                })
        }) && nodes
            .iter()
            .all(|node| *node.node.tree_state().root() == ids[0])
        {
            break;
        }
        assert!(
            tokio::time::Instant::now() < until,
            "real Noise/tree/filter setup"
        );
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    delivered(network).await;
}

async fn send_request(nodes: &mut [TestNode], ingress: usize, target: usize, request_id: u64) {
    // The target is a genuine direct peer of relay 0. Both other ingress
    // peers submit their own authenticated request IDs over the real carrier.
    let request = LookupRequest::new(
        request_id,
        *nodes[target].node.node_addr(),
        *nodes[ingress].node.node_addr(),
        nodes[ingress].node.tree_state().my_coords().clone(),
        1,
        0,
    );
    let relay = *nodes[0].node.node_addr();
    nodes[ingress]
        .node
        .send_dataplane_fmp_link_plaintext(&relay, &request.encode(), false)
        .await
        .unwrap();
}

async fn cancel_second_delivery<F: Future<Output = ()>>(
    network: &SimNetwork,
    source: &str,
    operation: F,
) {
    let before = network.stats().packets_delivered;
    tokio::pin!(operation);
    tokio::time::timeout(Duration::from_secs(2), async {
        tokio::select! {
            _ = &mut operation => panic!("second send must await delayed completion"),
            _ = async {
                while network.stats().packets_delivered == before {
                    tokio::time::sleep(Duration::from_millis(1)).await;
                }
                // The first send captured its 200ms delay before wire delivery.
                // Only subsequent sends capture this longer completion delay.
                network.set_node_send_completion_delay(source, 60_000);
                while network.stats().packets_delivered < before + 2 {
                    tokio::time::sleep(Duration::from_millis(1)).await;
                }
            } => {}
        }
    })
    .await
    .expect("local retry then deferred wire delivery");
    // Drop the still-pending send future, as a maintenance timebox does.
}

async fn exercise(nodes: &mut [TestNode], network: &SimNetwork, retain_competing_wakeup: bool) {
    setup(nodes, network).await;
    let ids: Vec<_> = nodes.iter().map(|node| *node.node.node_addr()).collect();
    let before_owners = owners(nodes);
    assert_eq!(
        nodes[0].node.config.node.discovery.attempt_timeouts_secs,
        [1, 2, 4, 8]
    );
    assert_eq!(
        nodes[0]
            .node
            .config
            .node
            .discovery
            .forward_min_interval_secs,
        2
    );
    // Ingress 1 takes each existing global target slot. Ingress 2 then waits;
    // no synthetic limiter, recent-request owner or expiry is inserted.
    for target in [3, 4] {
        send_request(nodes, 1, target, 100 + target as u64).await;
    }
    let until = tokio::time::Instant::now() + Duration::from_secs(1);
    while nodes[0].node.stats().discovery.req_forwarded < 2 {
        poll_available_packets(nodes).await;
        assert!(
            tokio::time::Instant::now() < until,
            "both real global slots are consumed"
        );
        tokio::time::sleep(Duration::from_millis(1)).await;
    }
    // A registered observer may retain a coalesced crypto wake. The fixture
    // still has to drain ready requests within the original competing window.
    let notify = nodes[0].node.dataplane.readiness_notify();
    let mut retained_wakeup = retain_competing_wakeup.then(|| Box::pin(notify.notified()));
    if let Some(wakeup) = &mut retained_wakeup {
        while wakeup.as_mut().enable() {
            *wakeup = Box::pin(notify.notified());
        }
    }
    for target in [3, 4] {
        send_request(nodes, 2, target, 200 + target as u64).await;
    }
    let until = tokio::time::Instant::now() + Duration::from_secs(1);
    while nodes[0].node.stats().discovery.req_forward_rate_limited < 2 {
        poll_available_packets(nodes).await;
        assert!(
            tokio::time::Instant::now() < until,
            "both competing requests wait: forwarded={}, limited={}, received={}",
            nodes[0].node.stats().discovery.req_forwarded,
            nodes[0].node.stats().discovery.req_forward_rate_limited,
            nodes[0].node.stats().discovery.req_received,
        );
        tokio::time::sleep(Duration::from_millis(1)).await;
    }
    drop(retained_wakeup);
    let received: Vec<_> = [3, 4]
        .into_iter()
        .map(|target| {
            let request = nodes[0]
                .node
                .recent_requests
                .get(&(200 + target as u64))
                .unwrap();
            assert_eq!(request.from_peer, ids[2]);
            assert_eq!(request.target, ids[target]);
            assert!(!request.response_forwarded);
            assert!(
                !nodes[target]
                    .node
                    .recent_requests
                    .contains_key(&(200 + target as u64))
            );
            request.timestamp_ms
        })
        .collect();
    let deferred_due = nodes[0]
        .node
        .discovery_work_deadline_ms()
        .expect("transit-only wake");
    assert_eq!(nodes[0].node.pending_lookup_deadline_ms(), None);
    let ttl = nodes[0].node.config.node.discovery.ttl;
    assert_eq!(nodes[0].node.initiate_lookup(&ids[1], ttl).await, 1);
    let original = nodes[0].node.pending_lookups.get(&ids[1]).unwrap().clone();
    let timeouts = nodes[0]
        .node
        .config
        .node
        .discovery
        .attempt_timeouts_secs
        .clone();
    // Stage coincident due work by withholding service, not by changing any
    // clock or attempt. The later waiting request arrived after both forwards,
    // so one normal target interval after it makes both waiters genuinely due.
    let due = received.iter().copied().max().unwrap()
        + nodes[0]
            .node
            .config
            .node
            .discovery
            .forward_min_interval_secs
            * 1_000;
    let due = due.max(original.deadline_ms(&timeouts));
    assert!(deferred_due <= due);
    delivered(network).await;
    // Do not process any target response while staging the real due work.
    while Node::now_ms() <= due {
        tokio::time::sleep(Duration::from_millis(1)).await;
    }
    let batch_now = Node::now_ms();
    let relay = nodes[0].addr.as_str().unwrap().to_owned();
    let sent = network.stats().packets_sent;
    network.set_node_send_completion_delay(&relay, 200);
    cancel_second_delivery(
        network,
        &relay,
        nodes[0].node.check_discovery_work(batch_now),
    )
    .await;
    network.set_node_send_completion_delay(&relay, 0);
    assert_eq!(
        network.stats().packets_sent,
        sent + 2,
        "one local retry and one deferred request"
    );
    let local = nodes[0].node.pending_lookups.get(&ids[1]).unwrap();
    assert_eq!(
        local.attempt, 2,
        "local retry cannot be skipped behind deferred transport I/O"
    );
    assert_eq!(local.last_sent_ms, batch_now);
    assert_eq!(local.initiated_ms, original.initiated_ms);
    assert_eq!(local.deadline_ms(&timeouts), batch_now + 2_000);
    assert!(
        nodes[0]
            .node
            .discovery_work_deadline_ms()
            .is_some_and(|deadline| deadline <= Node::now_ms()),
        "untouched waiter remains due"
    );

    // Let the two real destinations identify which request crossed the wire.
    // Relay and ingress queues remain untouched, preserving reverse-path proof.
    let until = tokio::time::Instant::now() + Duration::from_secs(1);
    let selected = loop {
        poll_available_packets(&mut nodes[3..]).await;
        let seen: Vec<_> = [3, 4]
            .into_iter()
            .filter(|target| {
                nodes[*target]
                    .node
                    .recent_requests
                    .contains_key(&(200 + *target as u64))
            })
            .collect();
        if !seen.is_empty() {
            assert_eq!(seen.len(), 1);
            break seen[0];
        }
        assert!(
            tokio::time::Instant::now() < until,
            "canceled completion still delivered real request"
        );
        tokio::time::sleep(Duration::from_millis(1)).await;
    };
    for (offset, target) in [3, 4].into_iter().enumerate() {
        let request = nodes[0]
            .node
            .recent_requests
            .get(&(200 + target as u64))
            .unwrap();
        assert_eq!(
            (
                request.from_peer,
                request.target,
                request.timestamp_ms,
                request.response_forwarded
            ),
            (ids[2], ids[target], received[offset], false)
        );
    }
    let sent = network.stats().packets_sent;
    nodes[0].node.check_discovery_work(batch_now).await;
    assert_eq!(
        network.stats().packets_sent,
        sent + 1,
        "resume sends only untouched waiter"
    );
    assert_eq!(
        nodes[0].node.discovery_work_deadline_ms(),
        Some(batch_now + 2_000)
    );
    nodes[0].node.check_discovery_work(batch_now).await;
    assert_eq!(
        network.stats().packets_sent,
        sent + 1,
        "canceled selected waiter is not retried"
    );

    // Same-ingress fresh traffic waits for a new slot; it cannot reclaim the
    // already charged slot of the canceled completion.
    let forwarded = nodes[0].node.stats().discovery.req_forwarded;
    let limited = nodes[0].node.stats().discovery.req_forward_rate_limited;
    send_request(nodes, 2, selected, 900).await;
    let until = tokio::time::Instant::now() + Duration::from_secs(1);
    while nodes[0].node.stats().discovery.req_forward_rate_limited == limited {
        poll_available_packets(&mut nodes[..1]).await;
        assert!(
            tokio::time::Instant::now() < until,
            "normal target spacing remains charged"
        );
        tokio::time::sleep(Duration::from_millis(1)).await;
    }
    assert_eq!(nodes[0].node.stats().discovery.req_forwarded, forwarded);
    assert!(!nodes[selected].node.recent_requests.contains_key(&900));

    let until = tokio::time::Instant::now() + Duration::from_secs(2);
    loop {
        poll_available_packets(nodes).await;
        if nodes[0].node.pending_lookups.get(&ids[1]).is_none()
            && [3, 4].into_iter().all(|target| {
                nodes[0]
                    .node
                    .recent_requests
                    .get(&(200 + target as u64))
                    .is_some_and(|entry| entry.response_forwarded)
            })
        {
            break;
        }
        assert!(
            tokio::time::Instant::now() < until,
            "real signed responses complete local and reverse paths"
        );
        tokio::time::sleep(Duration::from_millis(1)).await;
    }
    assert!(
        nodes[0]
            .node
            .coord_cache()
            .contains(&ids[1], Node::now_ms())
    );
    finish_fresh_waiter(nodes, selected, forwarded).await;
    assert_eq!(owners(nodes), before_owners);
}

async fn finish_fresh_waiter(nodes: &mut [TestNode], selected: usize, forwarded: u64) {
    let due = nodes[0]
        .node
        .discovery_work_deadline_ms()
        .expect("fresh request owns the next permitted slot");
    assert!(
        due > Node::now_ms(),
        "the canceled send's interval stays charged"
    );
    let original = nodes[0].node.recent_requests.get(&900).unwrap().clone();
    let limited = nodes[0].node.stats().discovery.req_forward_rate_limited;
    let duplicates = nodes[0].node.stats().discovery.req_duplicate;
    send_request(nodes, 2, selected, 900).await;
    send_request(nodes, 2, selected, 901).await;
    let until = tokio::time::Instant::now() + Duration::from_millis(500);
    loop {
        poll_available_packets(&mut nodes[..1]).await;
        let stats = &nodes[0].node.stats().discovery;
        if stats.req_duplicate == duplicates + 1 && stats.req_forward_rate_limited == limited + 1 {
            break;
        }
        assert!(
            tokio::time::Instant::now() < until,
            "repeated and fresh IDs reach relay"
        );
        tokio::time::sleep(Duration::from_millis(1)).await;
    }
    let next = nodes[0].node.discovery_work_deadline_ms().unwrap();
    assert!(
        next.abs_diff(due) <= 2,
        "a later ID cannot extend the first reservation"
    );
    assert!(
        Node::now_ms() < due,
        "both arrivals precede the reserved slot"
    );
    let retained = nodes[0].node.recent_requests.get(&900).unwrap();
    assert_eq!(retained.admission_generation, original.admission_generation);
    assert_eq!(retained.timestamp_ms, original.timestamp_ms);
    assert_eq!(retained.from_peer, original.from_peer);
    assert!(!retained.response_forwarded);
    let received = nodes[selected].node.stats().discovery.req_received;
    let duplicate_forwards = nodes[selected].node.stats().discovery.req_duplicate;
    nodes[0].node.check_discovery_work(Node::now_ms()).await;
    process_available_packets(nodes).await;
    assert_eq!(nodes[0].node.stats().discovery.req_forwarded, forwarded);
    assert!(!nodes[selected].node.recent_requests.contains_key(&900));
    assert!(!nodes[selected].node.recent_requests.contains_key(&901));

    let until = tokio::time::Instant::now() + Duration::from_secs(3);
    loop {
        // Service actual production deadlines. No limiter, timer or queue
        // state is advanced to make the reserved slot artificially available.
        nodes[0].node.check_discovery_work(Node::now_ms()).await;
        poll_available_packets(nodes).await;
        if nodes[0]
            .node
            .recent_requests
            .get(&900)
            .unwrap()
            .response_forwarded
        {
            break;
        }
        assert!(
            tokio::time::Instant::now() < until,
            "fresh request dispatches at its slot"
        );
        tokio::time::sleep(Duration::from_millis(2)).await;
    }
    let target_received = nodes[selected].node.recent_requests.get(&900).unwrap();
    assert!(
        target_received.timestamp_ms + 2 >= due,
        "reserved request was not forwarded early"
    );
    for _ in 0..2 {
        nodes[0].node.check_discovery_work(Node::now_ms()).await;
        process_available_packets(nodes).await;
    }
    assert_eq!(nodes[0].node.stats().discovery.req_forwarded, forwarded + 1);
    assert_eq!(
        nodes[selected].node.stats().discovery.req_received,
        received + 1
    );
    assert_eq!(
        nodes[selected].node.stats().discovery.req_duplicate,
        duplicate_forwards,
        "the canceled original and newly completed waiter are never resent"
    );
    assert!(
        !nodes[selected].node.recent_requests.contains_key(&901),
        "a fresh ID cannot replace the first waiting request"
    );
    assert_eq!(nodes[0].node.discovery_work_deadline_ms(), None);
}
