//! Routing work remains owned when a real parent-change announcement is canceled.
use super::*;
use crate::config::{SimTransportConfig, TransportInstances};
use crate::node::tests::session::run_large_stack_async_test;
use crate::node::tests::sim_discovery::configured_discovering_node;
use crate::node::wire::{CommonPrefix, PHASE_ESTABLISHED};
use crate::protocol::{FilterAnnounce, LinkMessageType};
use crate::{SimNetwork, register_sim_network, unregister_sim_network};
use futures::FutureExt;
use std::panic::AssertUnwindSafe;

const ROOT: usize = 0;
const LOCAL: usize = 1;
const OBSERVER: usize = 2;
type PeerOwner = (NodeAddr, LinkId, Option<SessionIndex>, u64);

#[test]
fn canceled_parent_change_retains_tree_and_bloom_work() {
    run(true);
}

#[test]
fn uninterrupted_parent_change_dispatches_tree_and_bloom_work() {
    run(false);
}

fn run(cancel: bool) {
    run_large_stack_async_test("tree-routing-cancellation", move || async move {
        let name = format!("tree-routing-cancellation-{}-{cancel}", std::process::id());
        let network = SimNetwork::new(293);
        register_sim_network(name.clone(), network.clone());
        let mut nodes = Vec::new();
        let result = AssertUnwindSafe(async {
            for address in ["one", "two", "three"] {
                let mut config = Config::new();
                config.node.system_files_enabled = false;
                config.node.discovery.lan.enabled = false;
                config.node.discovery.nostr.enabled = false;
                config.node.discovery.local.enabled = false;
                config.node.limits.max_peers = 2;
                config.node.limits.max_connections = 2;
                config.node.limits.max_links = 2;
                config.transports.sim = TransportInstances::Single(SimTransportConfig {
                    network: Some(name.clone()),
                    addr: Some(address.to_string()),
                    auto_connect: Some(false),
                    ..Default::default()
                });
                nodes.push(configured_discovering_node(config, address).await);
            }
            nodes.sort_by_key(|node| *node.node.node_addr());
            exercise(&mut nodes, &network, cancel).await;
        })
        .catch_unwind()
        .await;
        for node in &nodes {
            network.set_node_send_completion_delay(node.addr.as_str().unwrap(), 0);
        }
        cleanup_nodes(&mut nodes).await;
        unregister_sim_network(&name);
        if let Err(panic) = result {
            std::panic::resume_unwind(panic);
        }
    });
}

#[derive(Default)]
struct Evidence {
    held: Vec<ReceivedPacket>,
    positive_filter: bool,
}

// Inspect copies of genuine encrypted frames. This never changes the owner's
// replay window, counter, cipher, or signed declaration, and logs no key material.
fn plaintext(receiver: &TestNode, sender: &NodeAddr, packet: &ReceivedPacket) -> Option<Vec<u8>> {
    let wire = packet.data.as_slice();
    if CommonPrefix::parse(wire).unwrap().phase != PHASE_ESTABLISHED {
        return None;
    }
    let header = crate::dataplane::FmpWireHeader::parse_encrypted(wire).unwrap();
    let offset = usize::from(header.ciphertext_offset());
    let cipher = receiver
        .node
        .get_peer(sender)?
        .noise_session()?
        .recv_cipher_clone()?;
    let mut nonce = [0; 12];
    nonce[4..].copy_from_slice(&header.counter().to_le_bytes());
    let mut encrypted = wire[offset..].to_vec();
    Some(
        cipher
            .open_in_place(
                ring::aead::Nonce::assume_unique_for_key(nonce),
                ring::aead::Aad::from(&wire[..offset]),
                &mut encrypted,
            )
            .unwrap()
            .to_vec(),
    )
}

async fn drain(nodes: &mut [TestNode], hold_root: bool, evidence: &mut Evidence) {
    let root = *nodes[ROOT].node.node_addr();
    let local = *nodes[LOCAL].node.node_addr();
    for index in 0..nodes.len() {
        while let Ok(packet) = nodes[index].packet_rx.try_recv() {
            if hold_root
                && index == LOCAL
                && packet.remote_addr == nodes[ROOT].addr
                && plaintext(&nodes[index], &root, &packet).is_some_and(|body| {
                    body.get(4) == Some(&LinkMessageType::TreeAnnounce.to_byte())
                })
            {
                assert!(evidence.held.len() < 32, "bounded held declarations");
                evidence.held.push(packet);
                continue;
            }
            if index == OBSERVER
                && packet.remote_addr == nodes[LOCAL].addr
                && let Some(body) = plaintext(&nodes[index], &local, &packet)
                && body.get(4) == Some(&LinkMessageType::FilterAnnounce.to_byte())
            {
                let filter = FilterAnnounce::decode(&body[5..]).unwrap();
                assert!(filter.is_v1_compliant());
                evidence.positive_filter |= filter.filter.contains(&root);
            }
            process_dataplane_packet(&mut nodes[index], packet).await;
        }
        process_dataplane_completions(&mut nodes[index].node).await;
    }
}

async fn turn(nodes: &mut [TestNode], hold_root: bool, evidence: &mut Evidence) {
    drain(nodes, hold_root, evidence).await;
    for node in nodes.iter_mut() {
        node.node.check_mmp_reports().await;
        node.node.check_tree_state().await;
        node.node.check_bloom_state().await;
    }
    drain(nodes, hold_root, evidence).await;
    tokio::time::sleep(Duration::from_millis(5)).await;
}

async fn connect(nodes: &mut [TestNode], from: usize, to: usize) {
    let identity = PeerIdentity::from_pubkey_full(nodes[to].node.identity().pubkey_full());
    let remote = nodes[to].addr.clone();
    let transport = nodes[from].transport_id;
    nodes[from]
        .node
        .initiate_connection(transport, remote, identity)
        .await
        .unwrap();
}

fn settled(nodes: &[TestNode], counts: &[usize]) -> bool {
    nodes.iter().zip(counts).all(|(node, &count)| {
        node.node.peer_count() == count
            && node.node.connection_count() == 0
            && node.node.peers.iter().all(|(addr, peer)| {
                !peer.has_pending_tree_announce() && !node.node.bloom_state.needs_update(addr)
            })
    })
}

fn owners(nodes: &[TestNode]) -> Vec<Vec<PeerOwner>> {
    nodes
        .iter()
        .enumerate()
        .map(|(index, node)| {
            let count = if index == LOCAL { 2 } else { 1 };
            assert_eq!(node.node.peer_count(), count);
            assert_eq!(node.node.connection_count(), 0);
            assert_eq!(node.node.link_count(), count);
            assert_eq!(node.node.index_allocator.count(), count);
            let mut peers = node
                .node
                .peers
                .iter()
                .map(|(addr, peer)| {
                    assert!(peer.is_healthy() && peer.can_send());
                    (
                        *addr,
                        peer.link_id(),
                        peer.our_index(),
                        peer.session_generation(),
                    )
                })
                .collect::<Vec<_>>();
            peers.sort_by_key(|peer| peer.0);
            peers
        })
        .collect()
}

async fn exercise(nodes: &mut [TestNode], network: &SimNetwork, cancel: bool) {
    let root = *nodes[ROOT].node.node_addr();
    let local = *nodes[LOCAL].node.node_addr();
    let observer = *nodes[OBSERVER].node.node_addr();
    for node in nodes.iter() {
        assert_eq!(node.node.config.node.bloom.update_debounce_ms, 500);
        assert_eq!(
            node.node.config.node.bloom.announce_refresh_interval_secs,
            5
        );
        assert_eq!(node.node.config.node.tree.announce_min_interval_ms, 500);
        assert_eq!(node.node.config.node.discovery.forward_min_interval_secs, 2);
    }
    let mut evidence = Evidence::default();
    connect(nodes, LOCAL, OBSERVER).await;
    tokio::time::timeout(Duration::from_secs(6), async {
        loop {
            turn(nodes, false, &mut evidence).await;
            if settled(nodes, &[0, 1, 1]) && *nodes[OBSERVER].node.tree_state().root() == local {
                break;
            }
        }
    })
    .await
    .expect("original native component must settle");

    // The smaller root joins through real Noise. Hold only its declarations,
    // allowing its filter and RTT reports to arrive before tree eligibility.
    connect(nodes, ROOT, LOCAL).await;
    tokio::time::timeout(Duration::from_secs(6), async {
        loop {
            turn(nodes, true, &mut evidence).await;
            if !evidence.held.is_empty()
                && nodes.iter().enumerate().all(|(index, node)| {
                    node.node.peer_count() == (if index == LOCAL { 2 } else { 1 })
                        && node.node.connection_count() == 0
                })
                && nodes[LOCAL].node.get_peer(&root).unwrap().may_reach(&root)
                && nodes[LOCAL]
                    .node
                    .dataplane_fmp_peer_costs()
                    .contains_key(&root)
            {
                break;
            }
        }
    })
    .await
    .expect("authenticated non-tree filter and measured carrier");
    // Finish the already-generated control flight, then let the real send
    // debounce expire. Further MMP generation is deliberately staged here:
    // missing-root reports would keep rearming declaration repair and obscure
    // whether this one accepted parent change owns its own pending work.
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            drain(nodes, true, &mut evidence).await;
            for node in nodes.iter_mut() {
                node.node.send_pending_tree_announces().await;
                node.node.send_due_filter_announces().await;
            }
            drain(nodes, true, &mut evidence).await;
            if nodes[LOCAL].node.peers.iter().all(|(addr, peer)| {
                !peer.has_pending_tree_announce()
                    && !nodes[LOCAL].node.bloom_state.needs_update(addr)
                    && peer.can_send_tree_announce(Node::now_ms())
            }) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("prior pending work clears and real send gates expire");
    assert_eq!(*nodes[LOCAL].node.tree_state().root(), local);
    assert!(!nodes[LOCAL].node.is_tree_peer(&root));
    assert!(
        !nodes[OBSERVER]
            .node
            .get_peer(&local)
            .unwrap()
            .may_reach(&root)
    );
    assert!(!evidence.positive_filter);
    let before = owners(nodes);
    let accepted_before = nodes[LOCAL].node.stats().tree.accepted;
    let sent_before = nodes[LOCAL].node.stats().tree.sent;
    let delivered_before = network.stats().packets_delivered;

    let packet = evidence.held.remove(0);
    let body = plaintext(&nodes[LOCAL], &root, &packet).unwrap();
    let announce = TreeAnnounce::decode(&body[5..]).unwrap();
    assert_eq!(*announce.ancestry.root_id(), root);
    announce
        .declaration
        .verify(&nodes[LOCAL].node.get_peer(&root).unwrap().pubkey())
        .unwrap();
    announce.validate_semantics().unwrap();
    if cancel {
        network.set_node_send_completion_delay(nodes[LOCAL].addr.as_str().unwrap(), 2_500);
    }
    // Isolate handler cancellation after the genuine encrypted/signed input:
    // invoke its production plaintext handler with the observed bytes. No tree
    // state or pending flag is supplied by the test. This is not an RX fairness test.
    let completed = tokio::time::timeout(
        Duration::from_secs(2),
        nodes[LOCAL].node.handle_tree_announce(&root, &body[5..]),
    )
    .await;
    if cancel {
        assert!(
            completed.is_err(),
            "real encrypted send completion must stay suspended"
        );
        assert_eq!(
            network.stats().packets_delivered,
            delivered_before + 1,
            "one real encrypted announcement was delivered before its completion was canceled"
        );
        assert_eq!(nodes[LOCAL].node.stats().tree.sent, sent_before);
    } else {
        completed.expect("uninterrupted parent change completes");
    }
    assert_eq!(*nodes[LOCAL].node.tree_state().root(), root);
    assert_eq!(
        *nodes[LOCAL].node.tree_state().my_declaration().parent_id(),
        root
    );
    assert_eq!(nodes[LOCAL].node.stats().tree.accepted, accepted_before + 1);
    assert_eq!(owners(nodes), before);
    for peer in [root, observer] {
        assert!(
            nodes[LOCAL].node.bloom_state.needs_update(&peer),
            "committed parent change must retain Bloom work before its first send await"
        );
        assert!(
            nodes[LOCAL]
                .node
                .bloom_state
                .pending_peer_deadline_ms(&peer)
                .is_some()
        );
        if cancel {
            assert!(
                nodes[LOCAL]
                    .node
                    .get_peer(&peer)
                    .unwrap()
                    .has_pending_tree_announce(),
                "selected and unvisited tree work must survive cancellation"
            );
        }
    }
    if cancel {
        assert_eq!(nodes[LOCAL].node.stats().tree.sent, sent_before);
        assert!(
            nodes[LOCAL]
                .node
                .pending_tree_announce_deadline_ms()
                .is_some()
        );
    }
    network.set_node_send_completion_delay(nodes[LOCAL].addr.as_str().unwrap(), 0);

    // No repeated parent update, bootstrap or test-side marking. Retained work
    // must be sufficient for ordinary routing dispatch and real receive handlers.
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            nodes[LOCAL].node.send_pending_tree_announces().await;
            nodes[LOCAL].node.send_due_filter_announces().await;
            drain(nodes, true, &mut evidence).await;
            if evidence.positive_filter
                && nodes[OBSERVER]
                    .node
                    .get_peer(&local)
                    .unwrap()
                    .may_reach(&root)
                && *nodes[OBSERVER].node.tree_state().root() == root
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("retained routing work must repair before periodic Bloom refresh");
    assert!(!nodes[LOCAL].node.bloom_state.needs_update(&observer));
    assert_eq!(owners(nodes), before);
}
