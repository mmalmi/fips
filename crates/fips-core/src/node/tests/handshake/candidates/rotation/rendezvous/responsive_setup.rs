//! Schedule the second setup dial independently of whole payload rounds.
use super::*;

pub(super) struct ScheduledHandshake {
    first_authenticated: u64,
    network: SimNetwork,
    started: Option<tokio::time::Instant>,
    finished: Option<Duration>,
}

impl ScheduledHandshake {
    pub(super) fn new(first_authenticated: u64, network: SimNetwork) -> Self {
        Self {
            first_authenticated,
            network,
            started: None,
            finished: None,
        }
    }

    pub(super) async fn drive(&mut self, nodes: &mut [TestNode]) {
        if self.started.is_none()
            && Node::now_ms().saturating_sub(self.first_authenticated) >= 5_000
        {
            self.network.set_link(
                nodes[1].addr.as_str().unwrap(),
                nodes[5].addr.as_str().unwrap(),
                SimLink::default(),
            );
            self.started = Some(tokio::time::Instant::now());
            dial(nodes, 1, 5).await;
        }
        self.observe(nodes);
    }

    pub(super) fn observe(&mut self, nodes: &[TestNode]) {
        if self.finished.is_none()
            && let Some(started) = self.started
        {
            let elapsed = started.elapsed();
            assert!(elapsed < Duration::from_secs(3), "initial real handshake");
            if self.complete(nodes) {
                self.finished = Some(elapsed);
            }
        }
    }

    pub(super) fn complete(&self, nodes: &[TestNode]) -> bool {
        self.started.is_some()
            && [(1, 5), (5, 1)].into_iter().all(|(at, other)| {
                nodes[at]
                    .node
                    .get_peer(nodes[other].node.node_addr())
                    .is_some()
                    && nodes[at].node.connection_count() == 0
            })
    }

    pub(super) fn assert_finished(&self, nodes: &[TestNode]) {
        assert!(self.complete(nodes));
        assert!(
            self.finished
                .is_some_and(|elapsed| elapsed < Duration::from_secs(3))
        );
    }
}

#[test]
fn authentic_setup_offset_is_preserved_when_a_payload_round_spans_release() {
    run_large_stack_async_test("responsive-scheduled-setup", || async {
        let _guard = lock_large_network_test().await;
        let name = format!("responsive-scheduled-setup-{}", std::process::id());
        let network = SimNetwork::new(89);
        network.set_default_link(SimLink {
            up: false,
            ..Default::default()
        });
        register_sim_network(name.clone(), network.clone());
        let mut nodes = population::make_nodes(&name, Population::baseline(1)).await;
        let result = AssertUnwindSafe(spanning_round(&mut nodes, &network))
            .catch_unwind()
            .await;
        cleanup_nodes(&mut nodes).await;
        unregister_sim_network(&name);
        if let Err(panic) = result {
            std::panic::resume_unwind(panic);
        }
    });
}

async fn spanning_round(nodes: &mut [TestNode], network: &SimNetwork) {
    let ids = identities(nodes);
    let mut observation = Observation::new(Duration::ZERO, CapacityLimits::ORIGINAL);
    for (source, destination) in [(0, 2), (1, 3)] {
        connect(
            &mut observation,
            nodes,
            &ids,
            network,
            &RESPONSIVE_ADDRESSES,
            source,
            destination,
        )
        .await;
    }
    let mut endpoints: Vec<_> = nodes
        .iter_mut()
        .map(|n| n.node.attach_endpoint_data_io(16).unwrap())
        .collect();
    let useful: Vec<_> = (0..2).map(|at| original_owner(nodes, &ids, at)).collect();
    let mut sequence = 0;
    observation
        .round(nodes, &mut endpoints, &ids, &mut sequence, &LOCAL_FLOWS)
        .await;
    connect(
        &mut observation,
        nodes,
        &ids,
        network,
        &RESPONSIVE_ADDRESSES,
        0,
        4,
    )
    .await;
    let first = nodes[0]
        .node
        .get_peer(ids[4].node_addr())
        .unwrap()
        .authenticated_at();
    observation.initial_handshake = Some(ScheduledHandshake::new(first, network.clone()));
    while Node::now_ms().saturating_sub(first) < 4_800 {
        observation.turn(nodes, &ids).await;
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    assert!(
        observation
            .initial_handshake
            .as_ref()
            .unwrap()
            .started
            .is_none()
    );
    let round_started = Node::now_ms();
    assert!(round_started.saturating_sub(first) < 5_000);
    // A legal local round lasts beyond the phase boundary, but remains within
    // its unchanged two-second budget. Only these established payload paths
    // are delayed; the genuine setup handshake still uses its default link.
    for (a, b) in [(0, 2), (1, 3)] {
        network.set_link(
            RESPONSIVE_ADDRESSES[a],
            RESPONSIVE_ADDRESSES[b],
            SimLink {
                latency_ms: 1_250,
                ..Default::default()
            },
        );
    }
    observation
        .round(nodes, &mut endpoints, &ids, &mut sequence, &LOCAL_FLOWS)
        .await;
    assert!(
        Node::now_ms().saturating_sub(first) >= 6_000,
        "all original payloads span the release instant"
    );
    // Also drive at the round boundary. A negative control removing per-turn
    // scheduling now starts the real handshake too late for the same assertion.
    observation
        .initial_handshake
        .as_mut()
        .unwrap()
        .drive(nodes)
        .await;
    while !observation
        .initial_handshake
        .as_ref()
        .unwrap()
        .complete(nodes)
    {
        observation.turn(nodes, &ids).await;
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    observation
        .initial_handshake
        .take()
        .unwrap()
        .assert_finished(nodes);
    let second = nodes[1]
        .node
        .get_peer(ids[5].node_addr())
        .unwrap()
        .authenticated_at();
    assert!(
        (5_000..6_000).contains(&second.saturating_sub(first)),
        "actual incumbent authentication keeps the original five-second phase offset"
    );
    useful_retained(nodes, &ids, &useful);
}
