//! Observe real adjacent FSP key changes during the existing renewal workload.
use super::*;
use std::{collections::BTreeMap, path::Path};

pub(crate) struct RekeyObservation {
    epochs: BTreeMap<(usize, usize), (u64, bool)>,
    rotated: std::collections::BTreeSet<(usize, usize)>,
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
        let mut observation = Self {
            epochs: BTreeMap::new(),
            rotated: Default::default(),
        };
        observation.observe(root, peers).await;
        assert_eq!(observation.epochs.len(), (peers.len() - 1) * 2);
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
                if node.abs_diff(remote) != 1 || session["state"] != "established" {
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
            self.rotated.len(),
            self.epochs.len(),
            "every adjacent payment session must change its authenticated key epoch"
        );
        eprintln!(
            "paid renewal observed rotated payment sessions={}",
            self.rotated.len()
        );
    }
}
