//! Observe authenticated session key changes during paid workloads.
use super::*;
use std::{
    collections::{BTreeMap, BTreeSet},
    path::Path,
};

pub(crate) struct RekeyObservation {
    expected: BTreeSet<(usize, usize)>,
    epochs: BTreeMap<(usize, usize), (u64, bool)>,
    rotated: BTreeSet<(usize, usize)>,
}

impl RekeyObservation {
    pub(crate) fn configure(config: &mut Config, enabled: bool) {
        if enabled {
            config.node.rekey.after_messages = 16;
        }
    }

    pub(crate) async fn start(root: &Path, peers: &[PeerIdentity], enabled: bool) -> Option<Self> {
        if !enabled {
            return None;
        }
        let last = peers.len() - 1;
        let expected = (0..last)
            .flat_map(|node| [(node, node + 1), (node + 1, node)])
            .chain([(0, last), (last, 0)])
            .collect();
        Some(Self::start_with_pairs(root, peers, expected).await)
    }

    #[cfg(feature = "measurements")]
    pub(crate) async fn start_pair(
        root: &Path,
        peers: &[PeerIdentity],
        buyer: usize,
        seller: usize,
    ) -> Self {
        let mut observation =
            Self::start_with_pairs(root, peers, [(buyer, seller), (seller, buyer)].into()).await;
        // Setup traffic can already have rotated this session. Let the previous
        // epoch drain before arming a fault that lasts less than that drain window.
        let started = tokio::time::Instant::now();
        tokio::time::timeout(Duration::from_secs(60), async {
            while !observation.observe(root, peers).await {
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        })
        .await
        .expect("payment session must finish its previous-key drain before the fault");
        observation.rotated.clear();
        eprintln!(
            "payment loss rekey preparation waited_ms={}",
            started.elapsed().as_millis()
        );
        observation
    }

    async fn start_with_pairs(
        root: &Path,
        peers: &[PeerIdentity],
        expected: BTreeSet<(usize, usize)>,
    ) -> Self {
        let mut observation = Self {
            expected,
            epochs: BTreeMap::new(),
            rotated: Default::default(),
        };
        observation.observe(root, peers).await;
        // Payment sessions already exist; the first payload may establish the
        // routed data session. Both endpoints must then rotate it during traffic.
        assert!(
            observation
                .expected
                .iter()
                .filter(|(node, remote)| node.abs_diff(*remote) == 1)
                .all(|pair| observation.epochs.contains_key(pair))
        );
        observation
    }

    pub(crate) async fn observe(&mut self, root: &Path, peers: &[PeerIdentity]) -> bool {
        let mut ready = BTreeSet::new();
        for node in 0..peers.len() {
            let reply = tokio::time::timeout(
                Duration::from_secs(2),
                native_query(root, node, serde_json::json!({"command": "show_sessions"})),
            )
            .await
            .expect("rekey observation deadline")
            .expect("native session snapshot");
            assert_eq!(reply["status"], "ok");
            for session in reply["data"]["sessions"].as_array().unwrap() {
                let Some(remote) = peers.iter().position(|peer| session["npub"] == peer.npub())
                else {
                    continue;
                };
                if !self.expected.contains(&(node, remote)) || session["state"] != "established" {
                    continue;
                }
                let epoch = (
                    session["session_start_ms"].as_u64().unwrap(),
                    session["current_k_bit"].as_bool().unwrap(),
                );
                if session["is_draining"] == false {
                    ready.insert((node, remote));
                }
                if let Some(previous) = self.epochs.insert((node, remote), epoch)
                    && epoch.0 > previous.0
                    && epoch.1 != previous.1
                {
                    self.rotated.insert((node, remote));
                }
            }
        }
        ready == self.expected
    }

    pub(crate) fn assert_rotated(self, workload: &str) {
        assert_eq!(
            self.rotated, self.expected,
            "every payment and routed data session must change its authenticated key epoch"
        );
        let adjacent = self
            .rotated
            .iter()
            .filter(|(node, remote)| node.abs_diff(*remote) == 1)
            .count();
        eprintln!("{workload} observed rotated payment sessions={}", adjacent);
        eprintln!(
            "{workload} observed rotated routed data sessions={}",
            self.rotated.len() - adjacent
        );
    }
}
