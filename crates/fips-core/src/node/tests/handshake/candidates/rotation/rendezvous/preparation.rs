//! Hold a genuine incoming exchange across an incumbent's remaining age window.
use super::*;
use crate::dataplane::FmpWireHeader;
use crate::node::tests::spanning_tree::process_dataplane_completions;
use crate::node::wire::Msg2Header;

const IDLE_MS: u64 = 10_000;
const INTERVAL_MS: u64 = 2_000;

#[test]
fn staggered_rosters_reserve_before_admission_and_activate_after_readiness() {
    run_large_stack_async_test("rotation-held-preparation", || async {
        let _guard = lock_large_network_test().await;
        let name = format!("rotation-held-preparation-{}", std::process::id());
        let network = SimNetwork::new(101);
        network.set_default_link(SimLink {
            up: false,
            ..Default::default()
        });
        register_sim_network(name.clone(), network.clone());
        let mut nodes = Vec::new();
        for (i, address) in ADDRESSES.iter().enumerate() {
            nodes.push(
                make_node_with(&name, address, i < 2, |config| {
                    config.node.identity.nsec = Some(format!("{:02x}", i + 1).repeat(32));
                    config.node.rate_limit = Config::new().node.rate_limit;
                    assert_eq!(config.node.rate_limit.handshake_timeout_secs, 30);
                    config.node.neighbor_rotation = (i < 2).then_some(NeighborRotationConfig {
                        idle_secs: IDLE_MS / 1000,
                        interval_secs: INTERVAL_MS / 1000,
                    });
                    // Isolate incoming preparation: the receiver must not use
                    // its sole candidate slot for a simultaneous outgoing dial.
                    // The source still discovers/dials normally; symmetric
                    // discovery competition belongs to the responsive cases.
                    config.transports.sim = TransportInstances::Single(SimTransportConfig {
                        network: Some(name.clone()),
                        addr: Some(address.to_string()),
                        auto_connect: Some(i == 0),
                        ..Default::default()
                    });
                })
                .await,
            );
        }
        let result = AssertUnwindSafe(exercise(&mut nodes, &network))
            .catch_unwind()
            .await;
        cleanup_nodes(&mut nodes).await;
        unregister_sim_network(&name);
        if let Err(panic) = result {
            std::panic::resume_unwind(panic);
        }
    });
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Pending {
    link: LinkId,
    index: SessionIndex,
    started: u64,
    activity: u64,
    attempt: u64,
}

impl Pending {
    fn capture(
        nodes: &[TestNode],
        ids: &[PeerIdentity],
        at: usize,
        outbound: bool,
    ) -> Option<Self> {
        let node = &nodes[at].node;
        let connection = node.peers.connection_values().find(|conn| {
            conn.is_outbound() == outbound
                && conn
                    .expected_identity()
                    .is_some_and(|id| id.node_addr() == ids[1 - at].node_addr())
        })?;
        let attempt = node.neighbor_rotation_started_at(ids[1 - at].node_addr())?;
        Some(Self {
            link: connection.link_id(),
            index: connection.our_index().unwrap(),
            started: connection.started_at(),
            // Msg2 retention caps the outgoing activity clock to this original
            // attempt; connection creation can follow it by a scheduling tick.
            activity: if outbound {
                attempt
            } else {
                connection.last_activity()
            },
            attempt,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Incumbent {
    link: LinkId,
    index: SessionIndex,
    generation: u64,
    authenticated: u64,
}

fn incumbent(nodes: &[TestNode], ids: &[PeerIdentity], at: usize) -> Incumbent {
    let peer = nodes[at].node.get_peer(ids[at + 4].node_addr()).unwrap();
    Incumbent {
        link: peer.link_id(),
        index: peer.our_index().unwrap(),
        generation: peer.session_generation(),
        authenticated: peer.authenticated_at(),
    }
}

struct Pump {
    next_tick: tokio::time::Instant,
    ready_at: Option<u64>,
    outgoing: Option<Pending>,
    incoming: Option<Pending>,
    first_request_at: Option<u64>,
    first_reply_at: Option<u64>,
    confirmation_frames: usize,
    competing_requests: [usize; 2],
    maintenance: usize,
}

impl Pump {
    fn new() -> Self {
        Self {
            next_tick: tokio::time::Instant::now(),
            ready_at: None,
            outgoing: None,
            incoming: None,
            first_request_at: None,
            first_reply_at: None,
            confirmation_frames: 0,
            competing_requests: [0; 2],
            maintenance: 0,
        }
    }

    async fn turn(&mut self, nodes: &mut [TestNode], ids: &[PeerIdentity]) {
        if tokio::time::Instant::now() >= self.next_tick {
            self.next_tick = tokio::time::Instant::now() + Duration::from_secs(1);
            self.maintenance += 1;
            for node in nodes.iter_mut().map(|n| &mut n.node) {
                node.check_timeouts().await;
                node.check_link_heartbeats().await;
                let now = Node::now_ms();
                node.resend_pending_handshakes(now).await;
                node.resend_pending_rekeys(now).await;
                node.resend_pending_session_handshakes(now).await;
                node.resend_pending_session_msg3(now).await;
                node.retry_pending_session_traffic().await;
                node.purge_idle_sessions(now);
                node.check_mmp_reports().await;
                node.check_session_mmp_reports().await;
                node.check_rekey().await;
                node.check_session_rekey().await;
                node.check_pending_lookups(now).await;
                node.poll_pending_connects().await;
                node.process_pending_retries(now).await;
                node.poll_transport_discovery().await;
                node.check_tree_state().await;
                node.send_pending_tree_announces().await;
            }
        }
        for destination in 0..nodes.len() {
            for _ in 0..256 {
                let Ok(packet) = nodes[destination].packet_rx.try_recv() else {
                    break;
                };
                let bridge_request = self.ready_at.is_some()
                    && destination == 1
                    && packet.remote_addr == nodes[0].addr
                    && Msg1Header::parse(packet.data.as_slice()).is_some();
                let first_request = bridge_request && self.outgoing.is_none();
                if first_request {
                    assert!(
                        nodes[1].node.peers.connection_is_empty(),
                        "incoming-only receiver must have its candidate slot available"
                    );
                    let pending = Pending::capture(nodes, ids, 0, true)
                        .expect("the bridge request must have a real outgoing owner");
                    assert_eq!(
                        Msg1Header::parse(packet.data.as_slice())
                            .unwrap()
                            .sender_idx,
                        pending.index
                    );
                    let remaining = self.ready_at.unwrap().saturating_sub(Node::now_ms());
                    assert!(
                        (3_500..6_000).contains(&remaining),
                        "setup must offer the bridge while the receiving incumbent is immature: {remaining}ms"
                    );
                    self.first_request_at = Some(packet.timestamp_ms);
                    self.outgoing = Some(pending);
                }
                if destination < 2
                    && packet.remote_addr == nodes[destination + 6].addr
                    && Msg1Header::parse(packet.data.as_slice()).is_some()
                {
                    self.competing_requests[destination] += 1;
                }
                if let Some(outgoing) = &self.outgoing {
                    if destination == 0
                        && packet.remote_addr == nodes[1].addr
                        && let Some(reply) = Msg2Header::parse(packet.data.as_slice())
                        && reply.receiver_idx == outgoing.index
                    {
                        if self.first_reply_at.is_none() {
                            assert!(
                                packet.timestamp_ms < self.ready_at.unwrap(),
                                "Msg2 must acknowledge the pending reservation before maturity"
                            );
                        }
                        assert_eq!(reply.sender_idx, self.incoming.as_ref().unwrap().index);
                        self.first_reply_at.get_or_insert(packet.timestamp_ms);
                    }
                    if destination == 1
                        && packet.remote_addr == nodes[0].addr
                        && let Some(incoming) = &self.incoming
                        && FmpWireHeader::parse_encrypted(packet.data.as_slice())
                            .is_ok_and(|h| h.receiver_idx() == incoming.index.as_u32())
                    {
                        self.confirmation_frames += 1;
                    }
                }
                process_dataplane_packet(&mut nodes[destination], packet).await;
                if first_request {
                    self.incoming = Pending::capture(nodes, ids, 1, false);
                    assert!(
                        self.incoming.is_some(),
                        "an authenticated age-blocked bridge request must retain its bounded incoming owner"
                    );
                    assert!(nodes[1].node.get_peer(ids[0].node_addr()).is_none());
                }
            }
            process_dataplane_completions(&mut nodes[destination].node).await;
        }
        caps(nodes);
    }

    async fn round(
        &mut self,
        nodes: &mut [TestNode],
        endpoints: &mut [EndpointDataIo],
        ids: &[PeerIdentity],
        sequence: &mut u8,
        flows: &[(usize, usize)],
    ) {
        let current = *sequence;
        *sequence = sequence.checked_add(1).expect("bounded distinct payloads");
        send_round(nodes, ids, current, flows).await;
        let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
        let mut received = Vec::new();
        loop {
            self.turn(nodes, ids).await;
            receive_round(endpoints, ids, current, flows, &mut received);
            if received.len() == flows.len() {
                tokio::time::sleep(Duration::from_millis(10)).await;
                self.turn(nodes, ids).await;
                receive_round(endpoints, ids, current, flows, &mut received);
                return;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "exact useful payloads"
            );
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    }
}

async fn connect(
    pump: &mut Pump,
    nodes: &mut [TestNode],
    ids: &[PeerIdentity],
    network: &SimNetwork,
    source: usize,
    destination: usize,
) {
    network.set_link(
        ADDRESSES[source],
        ADDRESSES[destination],
        SimLink::default(),
    );
    dial(nodes, source, destination).await;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
    loop {
        pump.turn(nodes, ids).await;
        if nodes[source]
            .node
            .get_peer(ids[destination].node_addr())
            .is_some()
            && nodes[destination]
                .node
                .get_peer(ids[source].node_addr())
                .is_some()
            && nodes[source].node.connection_count() == 0
            && nodes[destination].node.connection_count() == 0
        {
            return;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "initial real handshake"
        );
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
}

fn assert_prepared(
    pump: &Pump,
    nodes: &[TestNode],
    ids: &[PeerIdentity],
    incumbents: &[Incumbent; 2],
) {
    assert!(Node::now_ms() < pump.ready_at.unwrap());
    if let Some(reply_at) = pump.first_reply_at {
        assert!(reply_at < pump.ready_at.unwrap());
        let pending = pump.outgoing.as_ref().unwrap();
        assert_eq!(
            nodes[0]
                .node
                .get_connection(&pending.link)
                .unwrap()
                .last_activity(),
            pending.attempt,
            "early Msg2 preserves the original outgoing deadline"
        );
    }
    for at in 0..2 {
        assert_eq!(
            incumbent(nodes, ids, at),
            incumbents[at],
            "no incumbent refresh"
        );
        assert!(nodes[at].node.get_peer(ids[1 - at].node_addr()).is_none());
        let expected = if at == 0 {
            &pump.outgoing
        } else {
            &pump.incoming
        };
        assert_eq!(
            &Pending::capture(nodes, ids, at, at == 0),
            expected,
            "candidate identity/index/connection and original attempt deadlines stay owned"
        );
        assert_eq!(nodes[at].node.connection_count(), 1);
        assert_eq!(
            nodes[at].node.discovery_rotation_victim(Node::now_ms()),
            Some(*ids[at + 4].node_addr()),
            "discovery must not refresh the otherwise eligible incumbent during preparation"
        );
    }
    caps(nodes);
}

async fn exercise(nodes: &mut [TestNode], network: &SimNetwork) {
    let ids = identities(nodes);
    let mut pump = Pump::new();
    connect(&mut pump, nodes, &ids, network, 0, 2).await;
    connect(&mut pump, nodes, &ids, network, 1, 3).await;
    let mut endpoints: Vec<_> = nodes
        .iter_mut()
        .map(|n| n.node.attach_endpoint_data_io(16).unwrap())
        .collect();
    let useful: Vec<_> = (0..2).map(|at| original_owner(nodes, &ids, at)).collect();
    let mut sequence = 0;
    pump.round(nodes, &mut endpoints, &ids, &mut sequence, &LOCAL_FLOWS)
        .await;
    connect(&mut pump, nodes, &ids, network, 0, 4).await;
    let first = incumbent(nodes, &ids, 0);
    while Node::now_ms().saturating_sub(first.authenticated) < 5_000 {
        pump.round(nodes, &mut endpoints, &ids, &mut sequence, &LOCAL_FLOWS)
            .await;
        useful_retained(nodes, &ids, &useful);
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    connect(&mut pump, nodes, &ids, network, 1, 5).await;
    let incumbents = [first, incumbent(nodes, &ids, 1)];
    assert!(
        (5_000..6_000).contains(
            &incumbents[1]
                .authenticated
                .saturating_sub(incumbents[0].authenticated)
        )
    );
    let ready_at = incumbents[1].authenticated + IDLE_MS;
    // Leave room for the next ordinary discovery poll while the receiver is
    // still immature; the allowed authentication offset varies by one second.
    while ready_at.saturating_sub(Node::now_ms()) > 5_500 {
        pump.round(nodes, &mut endpoints, &ids, &mut sequence, &LOCAL_FLOWS)
            .await;
        useful_retained(nodes, &ids, &useful);
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    pump.ready_at = Some(ready_at);
    network.set_link(ADDRESSES[0], ADDRESSES[1], SimLink::default());
    while pump.incoming.is_none() {
        pump.round(nodes, &mut endpoints, &ids, &mut sequence, &LOCAL_FLOWS)
            .await;
        useful_retained(nodes, &ids, &useful);
        assert!(
            Node::now_ms() < pump.ready_at.unwrap() - 3_000,
            "discovery must start within the age-misaligned window"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert_prepared(&pump, nodes, &ids, &incumbents);
    let attempt = pump.outgoing.as_ref().unwrap().attempt;
    let mut competed = false;
    while Node::now_ms() + 300 < pump.ready_at.unwrap() {
        if !competed && Node::now_ms().saturating_sub(attempt) > INTERVAL_MS + 200 {
            // Genuine new requests arrive after the two-second attempt
            // interval, while the receiver still cannot replace its incumbent.
            for (candidate, boundary) in [(6, 0), (7, 1)] {
                network.set_link(
                    ADDRESSES[candidate],
                    ADDRESSES[boundary],
                    SimLink::default(),
                );
                dial(nodes, candidate, boundary).await;
            }
            competed = true;
        }
        pump.round(nodes, &mut endpoints, &ids, &mut sequence, &LOCAL_FLOWS)
            .await;
        useful_retained(nodes, &ids, &useful);
        if Node::now_ms() < pump.ready_at.unwrap() {
            assert_prepared(&pump, nodes, &ids, &incumbents);
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(competed && pump.competing_requests.iter().all(|count| *count > 0));
    let deadline = pump.ready_at.unwrap() + 3_000;
    while !reciprocal_bridge(nodes, &ids) {
        pump.round(nodes, &mut endpoints, &ids, &mut sequence, &LOCAL_FLOWS)
            .await;
        useful_retained(nodes, &ids, &useful);
        assert!(
            Node::now_ms() < deadline,
            "prepared bridge must complete within three seconds of real maturity"
        );
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    assert!(pump.first_reply_at.is_some() && pump.confirmation_frames > 0);
    for at in 0..2 {
        assert!(nodes[at].node.get_peer(ids[at + 4].node_addr()).is_none());
        assert_eq!(nodes[at].node.peer_count(), 2);
    }
    pump.round(
        nodes,
        &mut endpoints,
        &ids,
        &mut sequence,
        &[(0, 1), (1, 0)],
    )
    .await;
    pump.round(nodes, &mut endpoints, &ids, &mut sequence, &LOCAL_FLOWS)
        .await;
    useful_retained(nodes, &ids, &useful);
    assert!(reciprocal_bridge(nodes, &ids));
    caps(nodes);
    eprintln!(
        "prepared rendezvous outcome: {}",
        json!({
            "request_ms":pump.first_request_at,"reply_ms":pump.first_reply_at,
            "receiver_ready_ms":pump.ready_at,"complete_ms":Node::now_ms(),
            "competing_requests":pump.competing_requests,"confirmation_frames":pump.confirmation_frames,
            "maintenance_turns":pump.maintenance,"payload_rounds":sequence,
        })
    );
}
