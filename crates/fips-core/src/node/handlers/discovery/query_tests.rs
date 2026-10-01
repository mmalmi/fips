use super::*;
use crate::Identity;
use crate::config::{Config, NostrDiscoveryPolicy, PeerConfig};
use crate::peer::ActivePeer;
use crate::transport::LinkId;
use crate::tree::{ParentDeclaration, TreeCoordinate};
use std::{hint::black_box, time::Instant};

fn populated(count: usize, target: NodeAddr) -> Node {
    let identities: Vec<_> = (1..=count)
        .map(|index| {
            let mut secret = [0x17; 32];
            secret[..8].copy_from_slice(&(index as u64).to_le_bytes());
            Identity::from_secret_bytes(&secret).unwrap()
        })
        .collect();
    let mut config = Config::new();
    config.node.identity.persistent = false;
    config.node.control.enabled = false;
    config.node.limits.max_peers = count.max(1);
    config.peers = identities
        .iter()
        .enumerate()
        .filter(|(index, _)| index % 3 == 0)
        .map(|(index, identity)| PeerConfig {
            npub: identity.npub(),
            discovery_fallback_transit: index % 6 == 0,
            ..Default::default()
        })
        .collect();
    let mut node = Node::new(config).unwrap();
    let own = *node.node_addr();
    for (index, identity) in identities.iter().enumerate() {
        let identity = PeerIdentity::from_pubkey_full(identity.pubkey_full());
        let addr = *identity.node_addr();
        let mut peer = ActivePeer::new(identity, LinkId::new(index as u64 + 1), 1);
        if index % 6 != 0 {
            let bits = [24, 256, 8192, 32768][index % 4];
            let hashes = [1, 3, 5, 7, 255][index % 5];
            let mut filter = BloomFilter::with_params(bits, hashes).unwrap();
            if index % 3 != 0 {
                filter.insert(&target);
            }
            filter.insert(&addr);
            peer.update_filter(filter, 1, 1);
        }
        match index % 4 {
            1 => peer.mark_stale(),
            2 => peer.mark_reconnecting(),
            3 => peer.mark_disconnected(),
            _ => {}
        }
        if index % 2 == 0 {
            node.tree_state_mut().update_peer(
                ParentDeclaration::new(addr, own, 1, 1),
                TreeCoordinate::from_addrs(vec![own, addr]).unwrap(),
            );
        }
        node.peers.insert(addr, peer);
    }
    node
}

// Original candidate construction, including public per-peer membership calls.
fn per_peer_hash_candidates(node: &Node, target: &NodeAddr) -> Vec<LookupPeerCandidate> {
    node.peers
        .iter()
        .map(|(addr, peer)| LookupPeerCandidate {
            addr: *addr,
            can_send: peer.can_send(),
            is_healthy: peer.is_healthy(),
            is_tree_peer: node.is_tree_peer(addr),
            may_reach_target: peer.may_reach(target),
            reply_learned_fallback_allowed: node
                .should_use_reply_learned_lookup_fallback_peer(addr, peer, target),
            configured_reply_learned_fallback_transit: node
                .configured_discovery_fallback_transit(addr)
                == Some(true),
        })
        .collect()
}

#[test]
fn shared_hash_preserves_complete_candidate_vectors_and_lookup_plans() {
    let present = NodeAddr::from_bytes([0xa5; 16]);
    let absent = NodeAddr::from_bytes([0xf1; 16]);
    let mut node = populated(24, present);
    let direct = *node.peers.keys().next().unwrap();
    for mode in [RoutingMode::Tree, RoutingMode::ReplyLearned] {
        node.config.node.routing.mode = mode;
        for policy in [
            NostrDiscoveryPolicy::Open,
            NostrDiscoveryPolicy::ConfiguredOnly,
        ] {
            node.config.node.discovery.nostr.policy = policy;
            for target in [present, absent, direct] {
                let expected = per_peer_hash_candidates(&node, &target);
                let actual = node.lookup_peer_candidates(&target);
                assert_eq!(
                    actual, expected,
                    "all fields and iteration order must agree"
                );
                assert_eq!(
                    node.origin_lookup_peer_plan(&target, &actual),
                    node.origin_lookup_peer_plan(&target, &expected),
                );
                for fallback in [false, true] {
                    assert_eq!(
                        plan_forward_peers(direct, absent, target, mode, fallback, &actual, 16),
                        plan_forward_peers(direct, absent, target, mode, fallback, &expected, 16),
                    );
                }
            }
        }
    }
}

#[test]
#[ignore = "explicit bounded comparison; run an optimized build with --ignored --exact --nocapture"]
fn shared_hash_candidate_benchmark() {
    assert!(!black_box(cfg!(debug_assertions)), "use an optimized build");
    const CALLS: usize = 256;
    const SAMPLES: usize = 7;
    let present = NodeAddr::from_bytes([0xa5; 16]);
    for count in [0, 100, 350, 500] {
        let node = populated(count, present);
        let baseline_hashes = node
            .peers
            .values()
            .filter(|p| p.inbound_filter().is_some())
            .count();
        for target in [present, NodeAddr::from_bytes([0xf1; 16])] {
            assert_eq!(
                node.lookup_peer_candidates(&target),
                per_peer_hash_candidates(&node, &target)
            );
            let mut before = Vec::new();
            let mut after = Vec::new();
            for sample in 0..SAMPLES {
                for optimized in [sample % 2 == 0, sample % 2 != 0] {
                    let start = Instant::now();
                    for _ in 0..CALLS {
                        black_box(if optimized {
                            black_box(&node).lookup_peer_candidates(black_box(&target))
                        } else {
                            per_peer_hash_candidates(black_box(&node), black_box(&target))
                        });
                    }
                    let ns_per_call = start.elapsed().as_nanos() as u64 / CALLS as u64;
                    if optimized {
                        after.push(ns_per_call);
                    } else {
                        before.push(ns_per_call);
                    }
                }
            }
            before.sort_unstable();
            after.sort_unstable();
            println!(
                "{}",
                serde_json::json!({
                    "peers": count, "target_inserted": target == present,
                    "calls_per_sample": CALLS, "samples": SAMPLES,
                    "old_median_ns": before[SAMPLES / 2], "new_median_ns": after[SAMPLES / 2],
                    "source_operation_model": {"old_sha256_per_call": baseline_hashes, "new_sha256_per_call": 1},
                    "includes": "unchanged candidate fields, vector allocation and destruction; setup excluded"
                })
            );
        }
    }
}
