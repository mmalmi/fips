//! A rotated-out endpoint still owns its old epoch until normal link expiry.
use super::*;
use crate::dataplane::FmpWireHeader;

#[path = "same_path_rejoin/lifecycle.rs"]
mod lifecycle;
#[path = "same_path_rejoin/replacement.rs"]
mod replacement;
use lifecycle::{QueuedPayload, Scenario, assert_fsp_history, fsp_history};

const PATHS: [&str; 4] = ["boundary", "returning", "useful", "replacement"];
const USEFUL: [(usize, usize); 2] = [(0, 2), (2, 0)];

#[test]
fn same_path_rejoin_confirms_before_retained_remote_link_expires() {
    run(Scenario::RejoinWithHistory);
}

#[test]
fn idle_same_path_rejoin_confirms_and_delivers_without_prior_fsp_owner() {
    run(Scenario::RejoinIdle);
}

fn run(scenario: Scenario) {
    run_with_delayed_dial(scenario, false);
}

fn run_with_delayed_dial(scenario: Scenario, delay_dial: bool) {
    run_with_delays(scenario, delay_dial, false);
}

#[test]
fn useful_peer_is_refreshed_after_a_real_idle_gap_before_rejoin() {
    run_with_delays(Scenario::RejoinWithHistory, false, true);
}

fn run_with_delays(scenario: Scenario, delay_dial: bool, delay_rejoin: bool) {
    run_large_stack_async_test("rotation-same-path-rejoin", move || async move {
        let _guard = lock_large_network_test().await;
        let name = format!("rotation-same-path-rejoin-{}", std::process::id());
        let network = SimNetwork::new(97);
        network.set_default_link(SimLink {
            up: false,
            ..Default::default()
        });
        for &other in PATHS.iter().skip(1) {
            network.set_link(PATHS[0], other, SimLink::default());
        }
        register_sim_network(name.clone(), network);
        let mut nodes = Vec::new();
        for (i, address) in PATHS.iter().enumerate() {
            nodes.push(
                make_node_with(&name, address, i == 0, |config| {
                    config.node.identity.nsec = Some(format!("{:02x}", i + 1).repeat(32));
                    config.node.rate_limit = Config::new().node.rate_limit;
                    assert_eq!(config.node.rate_limit.handshake_timeout_secs, 30);
                    assert_eq!(config.node.link_dead_timeout_secs, 30);
                    config.node.neighbor_rotation = (i == 0).then_some(NeighborRotationConfig {
                        idle_secs: 1,
                        interval_secs: 2,
                    });
                    if scenario == Scenario::QueuedExpiry {
                        config.node.session.idle_timeout_secs = lifecycle::IDLE_SECS;
                    }
                    // Isolate normal same-path dialing from candidate competition.
                    config.transports.sim = TransportInstances::Single(SimTransportConfig {
                        network: Some(name.clone()),
                        addr: Some(address.to_string()),
                        auto_connect: Some(false),
                        ..Default::default()
                    });
                })
                .await,
            );
        }
        let result = AssertUnwindSafe(exercise_rejoin(
            &mut nodes,
            scenario,
            delay_dial,
            delay_rejoin,
        ))
        .catch_unwind()
        .await;
        cleanup_nodes(&mut nodes).await;
        unregister_sim_network(&name);
        if let Err(panic) = result {
            std::panic::resume_unwind(panic);
        }
    });
}

#[derive(Default)]
struct Flights {
    request: Option<SessionIndex>,
    response: Option<SessionIndex>,
    msg1: usize,
    msg2: usize,
    addressed_confirmations: usize,
}

struct Pump {
    next_tick: tokio::time::Instant,
    flights: Flights,
    queued: Option<QueuedPayload>,
    replacement_hold: Option<replacement::HeldDial>,
}

impl Pump {
    fn new() -> Self {
        Self {
            next_tick: tokio::time::Instant::now(),
            flights: Flights::default(),
            queued: None,
            replacement_hold: None,
        }
    }

    async fn turn(&mut self, nodes: &mut [TestNode]) {
        if let Some(hold) = &mut self.replacement_hold {
            hold.release(nodes).await;
        }
        if tokio::time::Instant::now() >= self.next_tick {
            self.next_tick = tokio::time::Instant::now() + Duration::from_secs(1);
            for n in nodes.iter_mut() {
                let now = Node::now_ms();
                n.node.check_timeouts().await;
                n.node.check_link_heartbeats().await;
                n.node.resend_pending_handshakes(now).await;
                n.node.resend_pending_rekeys(now).await;
                n.node.resend_pending_session_handshakes(now).await;
                n.node.resend_pending_session_msg3(now).await;
                n.node.retry_pending_session_traffic().await;
                n.node.purge_idle_sessions(now);
                n.node.check_mmp_reports().await;
                n.node.check_session_mmp_reports().await;
                n.node.check_rekey().await;
                n.node.check_session_rekey().await;
                n.node.check_pending_lookups(now).await;
                n.node.poll_pending_connects().await;
                n.node.process_pending_retries(now).await;
                n.node.poll_transport_discovery().await;
                n.node.check_tree_state().await;
                n.node.send_pending_tree_announces().await;
            }
        }
        for destination in 0..nodes.len() {
            for _ in 0..256 {
                let Ok(packet) = nodes[destination].packet_rx.try_recv() else {
                    break;
                };
                let packet = if let Some(hold) = &mut self.replacement_hold {
                    let Some(packet) = hold.capture(destination, &nodes[3].addr, packet) else {
                        continue;
                    };
                    packet
                } else {
                    packet
                };
                if let Some(request) = self.flights.request {
                    if destination == 0 && packet.remote_addr == nodes[1].addr {
                        if Msg1Header::parse(packet.data.as_slice())
                            .is_some_and(|h| h.sender_idx == request)
                        {
                            self.flights.msg1 += 1;
                        }
                        if FmpWireHeader::parse_encrypted(packet.data.as_slice()).is_ok_and(|h| {
                            self.flights.response.map(|index| index.as_u32())
                                == Some(h.receiver_idx())
                        }) {
                            self.flights.addressed_confirmations += 1;
                        }
                    } else if destination == 1
                        && packet.remote_addr == nodes[0].addr
                        && let Some(reply) = Msg2Header::parse(packet.data.as_slice())
                        && reply.receiver_idx == request
                    {
                        self.flights.msg2 += 1;
                        self.flights.response = Some(reply.sender_idx);
                    }
                }
                crate::node::tests::spanning_tree::process_dataplane_packet_once(
                    &mut nodes[destination].node,
                    packet,
                )
                .await;
            }
            crate::node::tests::spanning_tree::process_dataplane_completions(
                &mut nodes[destination].node,
            )
            .await;
        }
        caps(nodes);
        for n in nodes.iter() {
            assert!(n.node.peer_count() <= n.node.max_peers);
            assert!(n.node.connection_count() <= n.node.max_connections);
            assert!(n.node.link_count() <= n.node.max_links);
        }
    }
}

fn owner(
    nodes: &[TestNode],
    ids: &[PeerIdentity],
    at: usize,
    peer: usize,
) -> (LinkId, SessionIndex, u64) {
    let p = nodes[at].node.get_peer(ids[peer].node_addr()).unwrap();
    (p.link_id(), p.our_index().unwrap(), p.session_generation())
}

fn reciprocal(nodes: &[TestNode], ids: &[PeerIdentity], a: usize, b: usize) -> bool {
    let (Some(left), Some(right)) = (
        nodes[a].node.get_peer(ids[b].node_addr()),
        nodes[b].node.get_peer(ids[a].node_addr()),
    ) else {
        return false;
    };
    left.can_send()
        && right.can_send()
        && left.our_index() == right.their_index()
        && left.their_index() == right.our_index()
}

async fn round(
    pump: &mut Pump,
    nodes: &mut [TestNode],
    endpoints: &mut [EndpointDataIo],
    ids: &[PeerIdentity],
    sequence: u8,
    flows: &[(usize, usize)],
) {
    send_round(nodes, ids, sequence, flows).await;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    let mut received = Vec::new();
    loop {
        pump.turn(nodes).await;
        pump.receive(endpoints, ids, sequence, flows, &mut received);
        if received.len() == flows.len() {
            // Observe a further turn so queued duplicates cannot pass as success.
            tokio::time::sleep(Duration::from_millis(10)).await;
            pump.turn(nodes).await;
            pump.receive(endpoints, ids, sequence, flows, &mut received);
            return;
        }
        if tokio::time::Instant::now() >= deadline {
            let missing: Vec<_> = flows
                .iter()
                .filter(|flow| !received.contains(flow))
                .collect();
            eprintln!(
                "same-path payload timeout: {}",
                json!({
                    "sequence":sequence,"offered":flows,"received":received,"missing":missing,
                })
            );
            delivery_snapshot(nodes, ids, "payload-timeout");
            panic!("exact one-shot payload delivery");
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
}

fn delivery_snapshot(nodes: &[TestNode], ids: &[PeerIdentity], phase: &str) {
    let now = Node::now_ms();
    let records: Vec<_> = nodes.iter().enumerate().map(|(at, n)| {
        let node = &n.node;
        let peers: Vec<_> = node.peers.values().map(|peer| {
            let remote = peer.node_addr();
            let metrics = node.dataplane_fmp_link_metrics(remote, Instant::now());
            json!({"peer":label(ids,remote),"link":peer.link_id().as_u64(),
                "our_index":peer.our_index().map(|i|i.as_u32()),
                "their_index":peer.their_index().map(|i|i.as_u32()),
                "pending_our_index":peer.pending_our_index().map(|i|i.as_u32()),
                "pending_their_index":peer.pending_their_index().map(|i|i.as_u32()),
                "previous_our_index":peer.previous_our_index().map(|i|i.as_u32()),
                "active_current_session":peer.has_session(),
                "active_pending_session":peer.pending_new_session().is_some(),
                "active_previous_session":peer.previous_session().is_some(),
                "current_k":peer.current_k_bit(),"rekey":peer.rekey_in_progress(),
                "generation":peer.session_generation(),"can_send":peer.can_send(),
                "authenticated_age_ms":now.saturating_sub(peer.authenticated_at()),
                "application_demand":node.config.node.neighbor_rotation.as_ref().map(|config|
                    node.peer_has_application_demand(remote,now,config.idle_secs.saturating_mul(1000))),
                "session_activity_age_ms":node.session_dataplane_activity_ms(remote).map(|at|now.saturating_sub(at)),
                "decrypt_failures":peer.consecutive_decrypt_failures(),
                "replay_suppressed":peer.replay_suppressed_count(),
                "metrics":metrics.map(|m|json!({"current_authenticated":m.current_epoch_authenticated,
                    "tx":m.tx_packets,"rx":m.rx_packets,"last_rx_age_ms":m.last_recv_age_ms}))})
        }).collect();
        let routes: Vec<_> = ids.iter().enumerate().filter(|(to,_)|*to!=at).map(|(to,id)| {
            let remote = id.node_addr();
            let entry = node.get_session(remote);
            let coords = node.coord_cache.get(remote,now);
            let activity = node.dataplane.fsp_owner_activity(remote);
            json!({"destination":to,
                "session_state":entry.map(|s| if s.is_established(){"established"}
                    else if s.is_initiating(){"initiating"}
                    else if s.is_awaiting_msg3(){"awaiting_msg3"}else{"unknown"}),
                "session_created_ms":entry.map(|s|s.created_at()),
                "session_epoch":node.session_dataplane_epoch(remote),
                "session_counts_tx_rx_bytes":node.session_dataplane_counters(remote),
                "fsp_owner":node.dataplane.fsp_owner_destinations().contains(remote),
                "fsp_next_hop":node.dataplane.fsp_owner_next_hop(remote).map(|p|label(ids,&p)),
                "application_route_ready":node.dataplane_application_route_ready(remote),
                "current_epoch_confirmed":activity.map(|a|a.current_epoch_confirmed()),
                "coords_root":coords.map(|c|label(ids,c.root_id())),
                "lookup_pending":node.pending_lookups.contains_key(remote),
                "pending_endpoint_packets":node.pending_session_traffic.endpoint_data_for(remote).map_or(0,|q|q.len()),
                "pending_tun_packets":node.pending_session_traffic.tun_packets_for(remote).map_or(0,|q|q.len())})
        }).collect();
        json!({"node":at,"root":label(ids,node.tree_state.root()),"peers":peers,"routes":routes})
    }).collect();
    eprintln!(
        "same-path delivery state: {}",
        json!({"phase":phase,"nodes":records})
    );
}

fn assert_no_returning_fsp(nodes: &[TestNode], ids: &[PeerIdentity]) {
    for (at, remote) in [(0, 1), (1, 0)] {
        assert!(
            nodes[at]
                .node
                .get_session(ids[remote].node_addr())
                .is_none()
        );
        assert!(
            !nodes[at]
                .node
                .dataplane
                .fsp_owner_destinations()
                .contains(ids[remote].node_addr())
        );
    }
}

async fn exercise_rejoin(
    nodes: &mut [TestNode],
    scenario: Scenario,
    delay_dial: bool,
    delay_rejoin: bool,
) {
    let with_prior_payload = scenario != Scenario::RejoinIdle;
    let ids = identities(nodes);
    let mut pump = Pump::new();
    for (a, b) in [(0, 2), (1, 0)] {
        dial(nodes, a, b).await;
        let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
        while !reciprocal(nodes, &ids, a, b) {
            pump.turn(nodes).await;
            assert!(
                tokio::time::Instant::now() < deadline,
                "initial real handshake"
            );
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    }
    let mut endpoints: Vec<_> = nodes
        .iter_mut()
        .map(|n| n.node.attach_endpoint_data_io(16).unwrap())
        .collect();
    round(
        &mut pump,
        nodes,
        &mut endpoints,
        &ids,
        0,
        if with_prior_payload {
            &[(0, 1), (1, 0), (0, 2), (2, 0)]
        } else {
            &USEFUL
        },
    )
    .await;
    if with_prior_payload {
        for (at, remote) in [(0, 1), (1, 0)] {
            assert!(
                nodes[at]
                    .node
                    .get_session(ids[remote].node_addr())
                    .is_some_and(|s| s.is_established())
            );
            assert!(
                nodes[at]
                    .node
                    .dataplane
                    .fsp_owner_destinations()
                    .contains(ids[remote].node_addr())
            );
        }
    } else {
        assert_no_returning_fsp(nodes, &ids);
    }
    let retained_fsp = with_prior_payload.then(|| fsp_history(nodes, &ids));
    delivery_snapshot(nodes, &ids, "before-eviction");
    let protected = owner(nodes, &ids, 0, 2);
    let retained_remote = owner(nodes, &ids, 1, 0);
    let retired_index = owner(nodes, &ids, 0, 1).1;
    let mut sequence = 1;

    // Real idle age, with genuine application demand protecting the other peer.
    let age = tokio::time::Instant::now();
    while age.elapsed() < Duration::from_millis(1200) {
        round(&mut pump, nodes, &mut endpoints, &ids, sequence, &USEFUL).await;
        sequence += 1;
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let victim = nodes[0].node.discovery_rotation_victim(Node::now_ms());
    if victim != Some(*ids[1].node_addr()) {
        delivery_snapshot(nodes, &ids, "unexpected-rotation-victim");
    }
    assert_eq!(victim, Some(*ids[1].node_addr()));
    dial(nodes, 3, 0).await;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    if delay_dial {
        pump.replacement_hold = Some(replacement::HeldDial::new());
    }
    let evicted = replacement::admit(
        &mut pump,
        nodes,
        &mut endpoints,
        &ids,
        &mut sequence,
        deadline,
    )
    .await;
    if let Some(hold) = pump.replacement_hold.take() {
        hold.assert_released();
    }
    if nodes[0].node.get_peer(ids[1].node_addr()).is_some() {
        delivery_snapshot(nodes, &ids, "unexpected-admitted-rotation-victim");
    }
    assert!(nodes[0].node.get_peer(ids[1].node_addr()).is_none());
    assert!(!nodes[0].node.index_allocator.is_allocated(retired_index));
    assert_eq!(owner(nodes, &ids, 1, 0), retained_remote);
    assert_eq!(owner(nodes, &ids, 0, 2), protected);
    if let Some(history) = &retained_fsp {
        assert_fsp_history(nodes, &ids, history);
        assert!(!nodes[0].node.dataplane_has_fmp_owner(ids[1].node_addr()));
        assert_ne!(
            nodes[0]
                .node
                .dataplane
                .fsp_owner_next_hop(ids[1].node_addr()),
            Some(*ids[1].node_addr()),
            "retained FSP must not keep retired direct egress"
        );
    }
    delivery_snapshot(nodes, &ids, "after-eviction");
    if matches!(scenario, Scenario::QueuedRecovery | Scenario::QueuedExpiry) {
        lifecycle::queue_original(&mut pump, nodes, &ids).await;
    }
    if scenario == Scenario::QueuedExpiry {
        lifecycle::await_idle_expiry(
            &mut pump,
            nodes,
            &mut endpoints,
            &ids,
            &mut sequence,
            protected,
        )
        .await;
        return;
    }

    // Leave every carrier up. Only normal confirmed rotation removed the old
    // local owner; its remote endpoint must still retain the original epoch.
    let stale_after =
        Duration::from_millis(nodes[1].node.config.node.heartbeat_interval_secs * 1000 + 1100);
    while evicted.elapsed() < stale_after {
        round(&mut pump, nodes, &mut endpoints, &ids, sequence, &USEFUL).await;
        sequence += 1;
        assert_eq!(owner(nodes, &ids, 1, 0), retained_remote);
        if let Some(history) = &retained_fsp {
            assert_fsp_history(nodes, &ids, history);
        }
        if scenario == Scenario::QueuedRecovery {
            lifecycle::assert_queued(nodes, &ids);
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    if delay_rejoin {
        // A scheduler gap may outlive the useful peer's one-second demand
        // window. Prove that an old successful round is not a freshness fence.
        tokio::time::sleep(Duration::from_millis(1100)).await;
        let now = Node::now_ms();
        assert!(
            !nodes[0]
                .node
                .peer_has_application_demand(ids[2].node_addr(), now, 1000,)
        );
        assert_eq!(
            nodes[0].node.discovery_rotation_victim(now),
            Some(*ids[2].node_addr()),
            "without fresh application use the older peer is legitimately idle"
        );
    }
    // The wait above ends with a sleep, which need not resume within 100 ms.
    // Renew protection through exact real payload delivery before selecting a
    // victim; neither peer timestamps nor the rotation policy are changed.
    round(&mut pump, nodes, &mut endpoints, &ids, sequence, &USEFUL).await;
    sequence += 1;
    let selection_at = Node::now_ms();
    let victim = nodes[0].node.discovery_rotation_victim(selection_at);
    if victim != Some(*ids[3].node_addr()) {
        delivery_snapshot(nodes, &ids, "unexpected-rejoin-rotation-victim");
    }
    assert!(
        nodes[0]
            .node
            .peer_has_application_demand(ids[2].node_addr(), selection_at, 1000,)
    );
    assert!(
        nodes[1]
            .node
            .active_peer_needs_same_path_refresh(ids[0].node_addr())
    );
    assert!(
        !nodes[1]
            .node
            .active_peer_has_fresh_carrier_liveness(ids[0].node_addr())
    );
    assert!(
        nodes[0]
            .node
            .can_receive_neighbor_rotation(ids[1].node_addr(), Node::now_ms())
    );
    assert_eq!(victim, Some(*ids[3].node_addr()));
    if !with_prior_payload {
        assert_no_returning_fsp(nodes, &ids);
    }
    if let Some(history) = &retained_fsp {
        assert_fsp_history(nodes, &ids, history);
    }
    delivery_snapshot(nodes, &ids, "before-reconnect");
    dial(nodes, 1, 0).await;
    if let Some(queued) = &mut pump.queued {
        queued.allow_delivery = true;
    }
    pump.flights.request = nodes[1]
        .node
        .peers
        .connection_values()
        .find(|c| {
            c.is_outbound()
                && c.expected_identity()
                    .is_some_and(|id| id.node_addr() == ids[0].node_addr())
        })
        .and_then(PeerConnection::our_index);
    assert!(
        pump.flights.request.is_some(),
        "normal dial must dispatch a fresh request"
    );

    let reconnect = tokio::time::Instant::now();
    while reconnect.elapsed() < Duration::from_secs(5) && !reciprocal(nodes, &ids, 0, 1) {
        round(&mut pump, nodes, &mut endpoints, &ids, sequence, &USEFUL).await;
        sequence += 1;
        assert_eq!(owner(nodes, &ids, 0, 2), protected);
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    snapshot(nodes, &ids, reconnect, "same-path-rejoin-before-assertions");
    eprintln!(
        "same-path rejoin flights: {}",
        json!({
            "msg1":pump.flights.msg1,"msg2":pump.flights.msg2,
            "addressed_confirmations":pump.flights.addressed_confirmations,
            "reciprocal":reciprocal(nodes,&ids,0,1),
            "elapsed_ms":reconnect.elapsed().as_millis(),
            "since_eviction_ms":evicted.elapsed().as_millis(),
        })
    );
    assert!(
        pump.flights.msg1 > 0 && pump.flights.msg2 > 0,
        "real correlated Noise exchange must reach both endpoints"
    );
    assert!(
        evicted.elapsed() < Duration::from_secs(25),
        "recovery must precede the unchanged 30s dead-link interval"
    );
    assert!(
        reciprocal(nodes, &ids, 0, 1),
        "same-path rejoin must confirm while the remote retains its old active epoch"
    );
    assert!(pump.flights.addressed_confirmations > 0);
    assert_eq!(
        nodes[0]
            .node
            .get_peer(ids[1].node_addr())
            .unwrap()
            .our_index(),
        pump.flights.response
    );
    assert_eq!(
        nodes[1]
            .node
            .get_peer(ids[0].node_addr())
            .unwrap()
            .our_index(),
        pump.flights.request
    );
    assert!(nodes[0].node.get_peer(ids[3].node_addr()).is_none());
    if !with_prior_payload {
        assert_no_returning_fsp(nodes, &ids);
    }
    if scenario == Scenario::QueuedRecovery {
        lifecycle::await_queued_delivery(&mut pump, nodes, &mut endpoints, &ids, &mut sequence)
            .await;
    }
    delivery_snapshot(nodes, &ids, "before-recovered-payload");
    round(
        &mut pump,
        nodes,
        &mut endpoints,
        &ids,
        sequence,
        &[(0, 1), (1, 0), (0, 2), (2, 0)],
    )
    .await;
    assert_eq!(owner(nodes, &ids, 0, 2), protected);
    if let Some(history) = &retained_fsp {
        assert_fsp_history(nodes, &ids, history);
        for (at, current) in fsp_history(nodes, &ids).iter().enumerate() {
            let (tx, rx, tx_bytes, rx_bytes) = history[at].counters;
            let queued_tx = u64::from(scenario == Scenario::QueuedRecovery && at == 0);
            let queued_rx = u64::from(scenario == Scenario::QueuedRecovery && at == 1);
            assert_eq!(
                current.counters,
                (
                    tx + 1 + queued_tx,
                    rx + 1 + queued_rx,
                    tx_bytes + 3 + queued_tx * 3,
                    rx_bytes + 3 + queued_rx * 3,
                ),
                "exact fresh and queued payload accounting on the original FSP session"
            );
        }
    }
    for (at, peer) in [(0, 1), (1, 0)] {
        assert!(
            nodes[at]
                .node
                .dataplane_fmp_link_metrics(ids[peer].node_addr(), Instant::now())
                .is_some_and(|m| m.current_epoch_authenticated)
        );
    }
}
