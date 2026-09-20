//! Native resource observations shared by paid mesh encounter scenarios.
use super::*;
use std::{future::Future, path::PathBuf};

pub(super) struct Observer {
    root: PathBuf,
    pub(super) nodes: Vec<Arc<FipsEndpoint>>,
    pub(super) peers: Vec<PeerIdentity>,
    pub(super) maxima: BTreeMap<&'static str, u64>,
    pub(super) samples: u64,
}

impl Observer {
    pub(super) fn new(bench: &Bench) -> Self {
        Self {
            root: bench.root.path().into(),
            nodes: bench.nodes.clone(),
            peers: bench.peers.clone(),
            maxima: BTreeMap::new(),
            samples: 0,
        }
    }

    async fn sample(&mut self) {
        for node in 0..self.nodes.len() {
            let status = native_query(&self.root, node, "show_status").await;
            for (field, cap) in [
                ("peer_count", 2),
                ("connection_count", 4),
                ("session_count", 128),
            ] {
                let value = status[field].as_u64().unwrap();
                assert!(value <= cap, "node {node}: {field}={value} exceeds {cap}");
                let maximum = self.maxima.entry(field).or_default();
                *maximum = (*maximum).max(value);
            }
            // Simultaneous authenticated dials may retain the pending outbound
            // beside the promoted inbound until both sides resolve Msg2.
            let links = status["link_count"].as_u64().unwrap();
            let connections = status["connection_count"].as_u64().unwrap();
            assert!(
                links <= 4 + connections,
                "node {node}: {links} links with {connections} pending exceed the admission allowance"
            );
            let maximum = self.maxima.entry("link_count").or_default();
            *maximum = (*maximum).max(links);
        }
        self.samples += 1;
    }

    pub(super) async fn during<T>(&mut self, operation: impl Future<Output = T>) -> T {
        self.during_checked(operation, || async {}).await
    }

    pub(super) async fn during_checked<T, Check, Checked>(
        &mut self,
        operation: impl Future<Output = T>,
        mut check: Check,
    ) -> T
    where
        Check: FnMut() -> Checked,
        Checked: Future<Output = ()>,
    {
        tokio::pin!(operation);
        let mut interval = tokio::time::interval(Duration::from_millis(200));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tokio::select! {
                result = &mut operation => {
                    self.sample().await;
                    check().await;
                    return result;
                }
                _ = interval.tick() => {
                    self.sample().await;
                    check().await;
                },
            }
        }
    }

    pub(super) async fn settled(&mut self) {
        let outcome = tokio::time::timeout(Duration::from_secs(60), async {
            loop {
                self.sample().await;
                let mut settled = true;
                for node in 0..self.nodes.len() {
                    let status = native_query(&self.root, node, "show_status").await;
                    settled &= status["connection_count"] == 0
                        && status["link_count"] == status["peer_count"];
                }
                if settled {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(200)).await;
            }
        })
        .await;
        if outcome.is_err() {
            for node in 0..self.nodes.len() {
                for command in ["show_links", "show_connections", "show_peers"] {
                    eprintln!(
                        "mesh cleanup node={node} {command}: {}",
                        native_query(&self.root, node, command).await
                    );
                }
            }
            panic!("temporary handshake links must retire after convergence");
        }
    }
}
