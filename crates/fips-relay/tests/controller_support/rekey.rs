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
    handshake_loss: Option<(Arc<DeliveryTrace>, bool)>,
    traffic_after_rotation: bool,
}

impl RekeyObservation {
    pub(crate) fn configure(config: &mut Config, renewal: bool, payment_loss: bool) {
        if renewal {
            // Leave traffic after all three native handshake retransmissions;
            // the original 16-message threshold can trigger near the last round.
            config.node.rekey.after_messages = 8;
        } else if payment_loss {
            config.node.rekey.after_messages = 16;
        }
    }

    pub(crate) async fn start(
        root: &Path,
        peers: &[PeerIdentity],
        enabled: bool,
        transit: &Arc<DeliveryTrace>,
    ) -> Option<Self> {
        if !enabled {
            return None;
        }
        let last = peers.len() - 1;
        // Begin during a setup rotation's drain window, covering an observer
        // that arrives after cutover. Routed fault recovery still starts below.
        tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                let reply =
                    native_query(root, last, serde_json::json!({"command": "show_sessions"}))
                        .await
                        .expect("setup session snapshot");
                assert_eq!(reply["status"], "ok");
                if reply["data"]["sessions"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|session| {
                        session["npub"] == peers[last - 1].npub()
                            && session["state"] == "established"
                            && session["is_draining"] == true
                    })
                {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        })
        .await
        .expect("setup payment session must rotate before late observation");
        let expected = (0..last)
            .flat_map(|node| [(node, node + 1), (node + 1, node)])
            .chain([(0, last), (last, 0)])
            .collect();
        let mut observation = Self::start_with_pairs(root, peers, expected).await;
        observation.handshake_loss = Some((transit.clone(), false));
        Some(observation)
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
            handshake_loss: None,
            traffic_after_rotation: false,
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
        let last = peers.len() - 1;
        // This observer runs after each completed bidirectional traffic round.
        // A rotation seen in an earlier round therefore has fresh delivery after it.
        self.traffic_after_rotation |=
            self.rotated.contains(&(0, last)) && self.rotated.contains(&(last, 0));
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
                match self.epochs.insert((node, remote), epoch) {
                    Some(previous) if epoch.0 > previous.0 && epoch.1 != previous.1 => {
                        self.rotated.insert((node, remote));
                    }
                    None => {
                        // Fresh fixture nodes retain an old key only after an
                        // authenticated cutover, even if setup preceded us.
                        if session["is_draining"] == true {
                            self.rotated.insert((node, remote));
                        }
                        eprintln!(
                            "rekey baseline node={node} remote={remote} epoch={epoch:?} draining={}",
                            session["is_draining"]
                        );
                    }
                    _ => {}
                }
            }
        }
        if let Some((transit, armed)) = &mut self.handshake_loss
            && !*armed
            && ready.contains(&(0, last))
            && ready.contains(&(last, 0))
        {
            // Initial establishment already delivered application traffic. Drop
            // each handshake phase once when this established session next rekeys.
            transit.lose_rekey_handshakes([*peers[0].node_addr(), *peers[last].node_addr()]);
            // A setup rotation cannot satisfy recovery from the newly armed loss.
            self.rotated.remove(&(0, last));
            self.rotated.remove(&(last, 0));
            self.traffic_after_rotation = false;
            *armed = true;
        }
        ready == self.expected
    }

    pub(crate) fn recovered(&self) -> bool {
        self.rotated == self.expected
            && self.traffic_after_rotation
            && self
                .handshake_loss
                .as_ref()
                .is_some_and(|(transit, armed)| *armed && transit.handshakes_recovered())
    }

    pub(crate) fn assert_rotated(self, workload: &str) {
        if let Some((transit, armed)) = self.handshake_loss {
            assert!(armed);
            transit.assert_handshakes_recovered();
            assert!(
                self.traffic_after_rotation,
                "fresh traffic must follow the observed rekey"
            );
        }
        assert_eq!(
            self.rotated, self.expected,
            "every payment and routed data session must change its authenticated key epoch; final epochs={:?}",
            self.epochs
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
