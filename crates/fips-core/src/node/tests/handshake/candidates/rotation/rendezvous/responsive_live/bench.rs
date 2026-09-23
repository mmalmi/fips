//! Real RX-loop lifecycle and bounded read-only control observations.
use super::*;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;

impl Bench {
    pub(super) async fn start() -> Self {
        let name = format!("mature-brief-live-{}", std::process::id());
        let network = SimNetwork::new(89);
        network.set_default_link(SimLink {
            up: false,
            ..Default::default()
        });
        register_sim_network(name.clone(), network.clone());
        let population = Population {
            capacity: CAPACITY,
            ..Population::baseline(4)
        };
        let mut nodes = population::make_nodes(&name, population).await;
        let ids = identities(&nodes);
        let root = tempfile::tempdir().unwrap();
        let started = Instant::now();
        let mut endpoints = Vec::new();
        for (index, test) in nodes.iter_mut().enumerate() {
            let config = &mut test.node.config;
            config.node.control.socket_path = root
                .path()
                .join(format!("{index}.sock"))
                .to_string_lossy()
                .into_owned();
            config.node.discovery.lan.enabled = false;
            config.node.discovery.nostr.enabled = false;
            config.node.discovery.local.enabled = false;
            assert!(config.peers.is_empty());
            assert_eq!(config.node.tick_interval_secs, 1);
            assert_eq!(config.node.discovery.attempt_timeouts_secs, [1, 2, 4, 8]);
            assert_eq!(config.node.discovery.forward_min_interval_secs, 2);
            endpoints.push(test.node.attach_endpoint_data_io(16).unwrap());
        }
        let controls = endpoints.iter().map(|io| io.control_tx.clone()).collect();
        let traffic = traffic::Traffic::start(endpoints, ids.clone(), started);
        let mut bench = Self {
            name,
            network,
            root,
            started,
            ids,
            controls,
            traffic,
            nodes: JoinSet::new(),
            stops: Vec::new(),
            driver: None,
            samples: 0,
            bridge_observed: None,
        };
        let startup = AssertUnwindSafe(async {
            // Offset the actual event loops, not an invented maintenance clock.
            // Their production timers and ordinary skip behavior remain in charge.
            let second_cohort = Instant::now() + Duration::from_millis(500);
            let mut slots: Vec<_> = nodes.into_iter().map(Some).collect();
            for cohort in 0..2 {
                if cohort == 1 {
                    tokio::time::sleep_until(second_cohort).await;
                }
                for (index, slot) in slots
                    .iter_mut()
                    .enumerate()
                    .filter(|(index, _)| index % 2 == cohort)
                {
                    let mut test = slot.take().unwrap();
                    let (_, empty) = crate::transport::packet_channel(1);
                    test.node.packet_rx = Some(std::mem::replace(&mut test.packet_rx, empty));
                    test.node.state = NodeState::Running;
                    let (stop, stopped) = oneshot::channel();
                    bench.stops.push(stop);
                    bench.nodes.spawn(async move {
                        let result = AssertUnwindSafe(async {
                            tokio::select! {
                                result = test.node.run_rx_loop() => panic!("node {index} RX loop ended: {result:?}"),
                                _ = stopped => {}
                            }
                        }).catch_unwind().await;
                        (index, test, result.is_ok())
                    });
                }
            }
            let deadline = Instant::now() + Duration::from_secs(3);
            while (0..bench.ids.len()).any(|i| !bench.socket(i).exists()) {
                assert!(Instant::now() < deadline, "live control sockets start");
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        }).catch_unwind().await;
        if let Err(panic) = startup {
            // Construction now owns every live task; failed startup must use
            // the same stop/join/unregister path as a failed encounter.
            bench.stop().await;
            std::panic::resume_unwind(panic);
        }
        bench
    }

    fn socket(&self, index: usize) -> std::path::PathBuf {
        self.root.path().join(format!("{index}.sock"))
    }

    pub(super) async fn request(&self, index: usize, command: &str, params: Value) -> Value {
        tokio::time::timeout(Duration::from_secs(2), async {
            let mut socket = UnixStream::connect(self.socket(index)).await.unwrap();
            let mut bytes =
                serde_json::to_vec(&json!({"command":command,"params":params})).unwrap();
            bytes.push(b'\n');
            socket.write_all(&bytes).await.unwrap();
            let mut line = String::new();
            BufReader::new(socket).read_line(&mut line).await.unwrap();
            let response: Value = serde_json::from_str(&line).unwrap();
            assert_eq!(response["status"], "ok", "{response}");
            response["data"].clone()
        })
        .await
        .expect("bounded live control observation")
    }

    pub(super) async fn peers(&self, index: usize) -> Vec<Value> {
        self.request(index, "show_peers", Value::Null).await["peers"]
            .as_array()
            .unwrap()
            .clone()
    }

    pub(super) fn peer<'a>(&self, peers: &'a [Value], remote: usize) -> Option<&'a Value> {
        peers
            .iter()
            .find(|p| p["node_addr"] == self.ids[remote].node_addr().to_string())
    }

    pub(super) async fn connect_initial(&self, source: usize, destination: usize) {
        self.network.set_link(
            RESPONSIVE_ADDRESSES[source],
            RESPONSIVE_ADDRESSES[destination],
            SimLink::default(),
        );
        self.request(
            source,
            "connect",
            json!({"npub":self.ids[destination].npub(),
            "address":RESPONSIVE_ADDRESSES[destination],"transport":"sim"}),
        )
        .await;
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            if self.peer(&self.peers(source).await, destination).is_some()
                && self.peer(&self.peers(destination).await, source).is_some()
                && self.request(source, "show_status", Value::Null).await["connection_count"]
                    .as_u64()
                    .unwrap()
                    == 0
                && self.request(destination, "show_status", Value::Null).await["connection_count"]
                    .as_u64()
                    .unwrap()
                    == 0
            {
                return;
            }
            assert!(Instant::now() < deadline, "initial live handshake");
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    pub(super) async fn quality(
        &self,
        source: usize,
        destination: usize,
    ) -> crate::endpoint::SourceRouteQuality {
        let (response_tx, response_rx) = oneshot::channel();
        self.controls[source]
            .send(
                crate::node::NodeEndpointControlCommand::SourceRouteQuality {
                    destination: *self.ids[destination].node_addr(),
                    feedback_window_ms: 10_000,
                    response_tx,
                },
            )
            .await
            .unwrap();
        tokio::time::timeout(Duration::from_secs(2), response_rx)
            .await
            .unwrap()
            .unwrap()
    }

    pub(super) async fn sample(&mut self, useful: &[Value]) {
        let before = self.started.elapsed().as_millis();
        let mut bridge = true;
        for (index, _) in self.ids.iter().enumerate() {
            let state = self.request(index, "show_status", Value::Null).await;
            let role = usize::from(index >= 2);
            assert!(state["peer_count"].as_u64().unwrap() <= if index < 2 { 2 } else { 1 });
            assert!(
                state["connection_count"].as_u64().unwrap() <= CAPACITY.connections[role] as u64
            );
            assert!(state["link_count"].as_u64().unwrap() <= CAPACITY.links[role] as u64);
            if index < 2 {
                let peers = self.peers(index).await;
                let current = self
                    .peer(&peers, index + 2)
                    .expect("useful neighbor remains");
                assert_eq!(owner(current), useful[index]);
                bridge &= self.peer(&peers, 1 - index).is_some();
            }
        }
        if bridge && self.bridge_observed.is_none() {
            self.bridge_observed = Some([before, self.started.elapsed().as_millis()]);
        }
        self.traffic.assert_local_progress(false);
        self.samples += 1;
    }

    pub(super) async fn stop(&mut self) {
        if let Some(driver) = self.driver.take() {
            let _ = driver.await;
        }
        let local_result = AssertUnwindSafe(self.traffic.stop_local())
            .catch_unwind()
            .await;
        for stop in self.stops.drain(..) {
            let _ = stop.send(());
        }
        let mut nodes = Vec::new();
        let mut healthy = true;
        while let Some(result) = self.nodes.join_next().await {
            match result {
                Ok((index, node, ok)) => {
                    healthy &= ok;
                    nodes.push((index, node));
                }
                Err(_) => healthy = false,
            }
        }
        nodes.sort_by_key(|(index, _)| *index);
        let mut nodes: Vec<_> = nodes.into_iter().map(|(_, node)| node).collect();
        let caps =
            std::panic::catch_unwind(AssertUnwindSafe(|| caps_with_limits(&nodes, CAPACITY)));
        cleanup_nodes(&mut nodes).await;
        unregister_sim_network(&self.name);
        self.traffic.stop().await;
        assert!(
            healthy && local_result.is_ok(),
            "all live tasks stopped normally"
        );
        if let Err(panic) = caps {
            std::panic::resume_unwind(panic);
        }
    }
}

pub(super) fn owner(peer: &Value) -> Value {
    json!([
        peer["node_addr"],
        peer["link_id"],
        peer["authenticated_at_ms"]
    ])
}
