//! Cancel a real lookup send without losing the other due target.

use super::*;
use crate::node::tests::session::run_large_stack_async_test;
use crate::node::tests::spanning_tree::poll_available_packets;
use futures::FutureExt;
use std::future::Future;
use std::panic::AssertUnwindSafe;

#[test]
fn canceled_lookup_batch_keeps_unreserved_target_due() {
    run_scenario(None);
}

#[test]
fn endpoint_snapshot_precedes_ready_lookup_transport_await() {
    run_scenario(Some(ControlProbe::Queued));
}

#[test]
fn endpoint_snapshot_during_lookup_completes_within_its_existing_deadline() {
    run_scenario(Some(ControlProbe::InFlight));
}

#[test]
fn due_lookup_progresses_under_continuous_endpoint_snapshots() {
    run_scenario(Some(ControlProbe::Continuous));
}

#[derive(Clone, Copy)]
enum ControlProbe {
    Queued,
    InFlight,
    Continuous,
}

fn run_scenario(control_progress: Option<ControlProbe>) {
    run_large_stack_async_test("lookup-cancel", move || async move {
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
        let result = AssertUnwindSafe(exercise(&mut nodes, &network, control_progress))
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

async fn exercise(
    nodes: &mut [TestNode],
    network: &SimNetwork,
    control_progress: Option<ControlProbe>,
) {
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
    if let Some(probe) = control_progress {
        if matches!(probe, ControlProbe::Continuous) {
            exercise_control_flood(&mut nodes[0]).await;
        } else {
            exercise_control_progress(
                &mut nodes[0],
                network,
                matches!(probe, ControlProbe::InFlight),
            )
            .await;
        }
        return;
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

async fn exercise_control_flood(test: &mut TestNode) {
    use crate::node::NodeEndpointControlCommand;
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };
    use tokio::sync::{mpsc, oneshot};

    let (control_tx, control_rx) = mpsc::channel(8);
    test.node.endpoint_control_rx = Some(control_rx);
    let (_unused_tx, unused_rx) = packet_channel(8);
    test.node.packet_rx = Some(std::mem::replace(&mut test.packet_rx, unused_rx));
    test.node.state = NodeState::Running;
    let completed = Arc::new(AtomicUsize::new(0));
    let observed = completed.clone();
    // Fill the bounded lane before starting the real actor. The producer keeps
    // at most64 reply waiters, so neither it nor the actor gets an empty-lane
    // shortcut. No production scheduling hook or injected actor delay.
    let mut replies = std::collections::VecDeque::new();
    for _ in 0..8 {
        let (response_tx, response_rx) = oneshot::channel();
        control_tx
            .send(NodeEndpointControlCommand::PeerSnapshot { response_tx })
            .await
            .unwrap();
        replies.push_back(response_rx);
    }
    let producer = tokio::spawn(async move {
        loop {
            if replies.len() == 64 {
                if replies.pop_front().unwrap().await.is_err() {
                    break;
                }
                observed.fetch_add(1, Ordering::Relaxed);
            }
            let (response_tx, response_rx) = oneshot::channel();
            if control_tx
                .send(NodeEndpointControlCommand::PeerSnapshot { response_tx })
                .await
                .is_err()
            {
                break;
            }
            replies.push_back(response_rx);
        }
    });
    // The coarse maintenance tick is not yet due, isolating the continuously
    // ready endpoint lane from the already-due lookup work.
    let result = tokio::time::timeout(Duration::from_millis(250), test.node.run_rx_loop()).await;
    producer.abort();
    let _ = producer.await;
    assert!(result.is_err(), "real RX loop remains active");
    assert!(
        completed.load(Ordering::Relaxed) >= 64,
        "status lane stayed busy"
    );
    assert!(
        test.node
            .pending_lookups
            .iter()
            .any(|(_, entry)| entry.attempt > 1),
        "continuous endpoint snapshots starved a due real lookup retry"
    );
}

async fn exercise_control_progress(test: &mut TestNode, network: &SimNetwork, after_send: bool) {
    use crate::node::NodeEndpointControlCommand;
    use tokio::sync::{mpsc, oneshot};

    // Genuine Noise/tree/filter setup and original retry deadlines above.
    // A carrier delivers encrypted packets but delays send completion, as in
    // the cancellation test. A management request already waiting at a select
    // boundary must not start behind that unrelated transport await.
    let source = test.addr.as_str().unwrap();
    network.set_node_send_completion_delay(source, 60_000);
    let before = network.stats().packets_sent;
    let (control_tx, control_rx) = mpsc::channel(8);
    let (response_tx, response_rx) = oneshot::channel();
    test.node.endpoint_control_rx = Some(control_rx);
    let (_unused_tx, unused_rx) = packet_channel(8);
    test.node.packet_rx = Some(std::mem::replace(&mut test.packet_rx, unused_rx));
    test.node.state = NodeState::Running;

    let running = test.node.run_rx_loop();
    tokio::pin!(running);
    if after_send {
        tokio::select! {
            result = tokio::time::timeout(Duration::from_secs(1), async {
                while network.stats().packets_sent == before {
                    tokio::time::sleep(Duration::from_millis(1)).await;
                }
            }) => result.expect("real retry must enter its carrier before the snapshot"),
            result = &mut running => panic!("RX loop ended unexpectedly: {result:?}"),
        }
    }
    control_tx
        .send(NodeEndpointControlCommand::PeerSnapshot { response_tx })
        .await
        .unwrap();
    let deadline = if after_send {
        Duration::from_secs(5)
    } else {
        Duration::from_millis(250)
    };
    let result = tokio::select! {
        result = tokio::time::timeout(deadline, response_rx) => result,
        result = &mut running => panic!("RX loop ended unexpectedly: {result:?}"),
    };
    let snapshot = result
        .expect("endpoint snapshot missed its deadline behind due lookup transport sends")
        .expect("RX loop must answer the snapshot");
    assert_eq!(snapshot.len(), 2, "both authenticated peers remain visible");
    network.set_node_send_completion_delay(source, 0);
    let before_resume = network.stats().packets_sent;
    // The priority of a finite management request must not suppress discovery:
    // with the same RX loop still alive, its pending retry must hit the carrier.
    tokio::select! {
        _ = tokio::time::timeout(Duration::from_secs(3), async {
            while network.stats().packets_sent == before_resume {
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        }) => assert!(network.stats().packets_sent > before_resume, "due lookup still progresses"),
        result = &mut running => panic!("RX loop ended unexpectedly: {result:?}"),
    }
}
