//! Observe payment and routed data FSP key changes during the renewal workload.
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
        let mut observation = Self {
            expected: (0..last)
                .flat_map(|node| [(node, node + 1), (node + 1, node)])
                .chain([(0, last), (last, 0)])
                .collect(),
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
        Some(observation)
    }

    pub(crate) async fn observe(&mut self, root: &Path, peers: &[PeerIdentity]) {
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
                if let Some(previous) = self.epochs.insert((node, remote), epoch)
                    && epoch.0 > previous.0
                    && epoch.1 != previous.1
                {
                    self.rotated.insert((node, remote));
                }
            }
        }
    }

    pub(crate) fn assert_rotated(self) {
        assert_eq!(
            self.rotated, self.expected,
            "every payment and routed data session must change its authenticated key epoch"
        );
        let adjacent = self
            .rotated
            .iter()
            .filter(|(node, remote)| node.abs_diff(*remote) == 1)
            .count();
        eprintln!(
            "paid renewal observed rotated payment sessions={}",
            adjacent
        );
        eprintln!(
            "paid renewal observed rotated routed data sessions={}",
            self.rotated.len() - adjacent
        );
    }
}
