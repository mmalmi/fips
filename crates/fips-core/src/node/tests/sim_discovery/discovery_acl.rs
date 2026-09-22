//! Denied advertisements must not spend the poll's bounded connection budget.
use super::*;
use crate::config::NeighborRotationConfig;
use crate::node::acl::{PeerAclContext, PeerAclReloader};
use crate::node::tests::session::{run_large_stack_async_test, send_endpoint_data_via_dataplane};
use futures::FutureExt;
use std::panic::AssertUnwindSafe;

const LOCAL: usize = 0;
const ACTIVE: usize = 1;
const DENIED: usize = 2;
const IDLE: usize = 3;
const ALLOWED: usize = 4;
const ADDRESSES: [&str; 5] = ["local", "a-active", "b-denied", "c-idle", "z-allowed"];

#[derive(Clone, Copy, Debug)]
enum Case {
    Empty,
    Refresh,
    Rotation,
}

#[test]
fn denied_new_advert_leaves_the_only_slot_for_an_allowed_peer() {
    run(Case::Empty);
}

#[test]
fn denied_active_refresh_leaves_the_only_slot_for_an_allowed_peer() {
    run(Case::Refresh);
}

#[test]
fn denied_active_refresh_cannot_starve_allowed_full_roster_rotation() {
    run(Case::Rotation);
}

fn run(case: Case) {
    run_large_stack_async_test("transport-discovery-acl", move || async move {
        let _guard = spanning_tree::lock_large_network_test().await;
        let name = format!("transport-discovery-acl-{case:?}-{}", std::process::id());
        let network = SimNetwork::new(157);
        network.set_default_link(SimLink {
            up: false,
            ..Default::default()
        });
        register_sim_network(name.clone(), network.clone());
        let mut nodes = Vec::new();
        for (index, address) in ADDRESSES.iter().enumerate() {
            let mut config = Config::new();
            config.node.system_files_enabled = false;
            // The denied alternate advert names the genuinely active identity.
            let scalar = [1, 2, 2, 3, 4][index];
            config.node.identity.nsec = Some(format!("{scalar:02x}").repeat(32));
            config.node.rekey.enabled = false;
            config.node.limits.max_peers = if index == LOCAL { 2 } else { 1 };
            config.node.limits.max_connections = 1;
            config.node.limits.max_links = if index == LOCAL { 3 } else { 1 };
            if index == LOCAL && matches!(case, Case::Rotation) {
                config.node.neighbor_rotation = Some(NeighborRotationConfig {
                    idle_secs: 1,
                    interval_secs: 1,
                });
            }
            config.transports.sim = TransportInstances::Single(SimTransportConfig {
                network: Some(name.clone()),
                addr: Some((*address).to_string()),
                auto_connect: Some(index == LOCAL),
                ..Default::default()
            });
            nodes.push(configured_discovering_node(config, address).await);
        }
        let result = AssertUnwindSafe(exercise(&mut nodes, &network, case))
            .catch_unwind()
            .await;
        cleanup_nodes(&mut nodes).await;
        unregister_sim_network(&name);
        if let Err(panic) = result {
            std::panic::resume_unwind(panic);
        }
    });
}

async fn exercise(nodes: &mut [TestNode], network: &SimNetwork, case: Case) {
    if matches!(case, Case::Rotation) {
        expose(network, IDLE);
        nodes[LOCAL].node.poll_transport_discovery().await;
        authenticate(nodes, IDLE).await;
        // Keep victim order independent of identities and millisecond ties.
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    if !matches!(case, Case::Empty) {
        expose(network, ACTIVE);
        nodes[LOCAL].node.poll_transport_discovery().await;
        authenticate(nodes, ACTIVE).await;
    }
    let active_id = *nodes[ACTIVE].node.node_addr();
    let original = nodes[LOCAL]
        .node
        .get_peer(&active_id)
        .map(|peer| (peer.link_id(), peer.our_index(), peer.authenticated_at()));
    if matches!(case, Case::Rotation) {
        tokio::time::sleep(Duration::from_millis(1_050)).await;
        assert_eq!(
            nodes[LOCAL].node.discovery_rotation_victim(Node::now_ms()),
            Some(*nodes[IDLE].node.node_addr()),
            "the denied refresh is not the idle victim deferred by discovery"
        );
    }

    // ACL reload governs future handshakes; it does not revoke an existing owner.
    let acl = tempfile::tempdir().unwrap();
    let deny = acl.path().join("peers.deny");
    std::fs::write(&deny, nodes[DENIED].node.npub()).unwrap();
    nodes[LOCAL].node.peer_acl = PeerAclReloader::with_paths(acl.path().join("peers.allow"), deny);
    expose(network, DENIED);
    expose(network, ALLOWED);
    for (index, permitted) in [(DENIED, false), (ALLOWED, true)] {
        let identity = identity(nodes, index);
        assert_eq!(
            nodes[LOCAL]
                .node
                .authorize_peer(
                    &identity,
                    PeerAclContext::OutboundConnect,
                    nodes[LOCAL].transport_id,
                    &nodes[index].addr,
                )
                .is_ok(),
            permitted
        );
    }
    assert_eq!(nodes[LOCAL].node.outbound_handshake_slots(), 1);
    assert!(nodes[LOCAL].node.outbound_link_slots() >= 1);
    assert_eq!(nodes[LOCAL].node.connection_count(), 0);
    let before = nodes[LOCAL].node.peer_count();
    nodes[LOCAL].node.poll_transport_discovery().await;
    let candidate = nodes[LOCAL].node.peers.connection_values().next().expect(
        "denied advertisement consumed the only poll slot without starting the allowed handshake",
    );
    assert_eq!(
        candidate.expected_identity().unwrap().node_addr(),
        nodes[ALLOWED].node.node_addr()
    );
    assert!(candidate.is_outbound());
    assert!(
        !candidate.has_session(),
        "the remote response has not been dispatched"
    );
    let owner = (
        candidate.link_id(),
        candidate.our_index(),
        candidate.started_at(),
    );
    assert_eq!(nodes[LOCAL].node.peer_count(), before);
    assert_caps(nodes);
    // Repeated real advertisements neither renew the attempt nor add resources.
    nodes[LOCAL].node.poll_transport_discovery().await;
    let candidate = nodes[LOCAL].node.peers.connection_values().next().unwrap();
    assert_eq!(
        (
            candidate.link_id(),
            candidate.our_index(),
            candidate.started_at()
        ),
        owner
    );
    authenticate(nodes, ALLOWED).await;
    if let Some(original) = original {
        let peer = nodes[LOCAL].node.get_peer(&active_id).unwrap();
        assert_eq!(
            (peer.link_id(), peer.our_index(), peer.authenticated_at()),
            original
        );
    }
    if matches!(case, Case::Rotation) {
        assert!(
            nodes[LOCAL]
                .node
                .get_peer(nodes[IDLE].node.node_addr())
                .is_none()
        );
    }
    assert_eq!(nodes[DENIED].node.peer_count(), 0);
    assert_eq!(nodes[DENIED].node.connection_count(), 0);
    assert!(
        nodes[DENIED].packet_rx.try_recv().is_err(),
        "denied path received a handshake"
    );
    assert_caps(nodes);

    let _source_io = nodes[LOCAL].node.attach_endpoint_data_io(8).unwrap();
    let mut endpoint = nodes[ALLOWED].node.attach_endpoint_data_io(8).unwrap();
    let target = identity(nodes, ALLOWED);
    let payload = b"allowed discovery delivers one original";
    send_endpoint_data_via_dataplane(&mut nodes[LOCAL].node, target, payload.to_vec())
        .await
        .unwrap();
    tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            turn(nodes).await;
            if let Ok(event) = endpoint.event_rx.try_recv() {
                assert_eq!(event.message_count(), 1);
                for message in event.messages {
                    assert_eq!(
                        message.source_peer.node_addr(),
                        nodes[LOCAL].node.node_addr()
                    );
                    assert_eq!(message.payload.as_slice(), payload);
                }
                endpoint.event_rx.release_messages(1);
                break;
            }
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
    })
    .await
    .expect("the newly authenticated allowed path must deliver application data");
}

fn expose(network: &SimNetwork, remote: usize) {
    network.set_link(ADDRESSES[LOCAL], ADDRESSES[remote], SimLink::default());
}

fn identity(nodes: &[TestNode], index: usize) -> PeerIdentity {
    PeerIdentity::from_pubkey_full(nodes[index].node.identity().pubkey_full())
}

fn assert_caps(nodes: &[TestNode]) {
    for (index, node) in nodes.iter().enumerate() {
        assert!(node.node.config.peers.is_empty());
        assert!(node.node.peer_count() <= if index == LOCAL { 2 } else { 1 });
        assert!(node.node.connection_count() <= 1);
        assert!(node.node.link_count() <= if index == LOCAL { 3 } else { 1 });
        assert!(node.node.pending_connects.is_empty());
    }
}

async fn turn(nodes: &mut [TestNode]) {
    dispatch(nodes).await;
    for node in nodes.iter_mut() {
        node.node.check_tree_state().await;
        node.node.send_due_tree_announces().await;
        node.node.send_pending_tree_announces().await;
        node.node.check_bloom_state().await;
    }
    dispatch(nodes).await;
    assert_caps(nodes);
}

async fn dispatch(nodes: &mut [TestNode]) {
    // Leave the denied advertiser's receive queue untouched as wire evidence.
    let (before, after) = nodes.split_at_mut(DENIED);
    spanning_tree::process_available_packets(before).await;
    spanning_tree::process_available_packets(&mut after[1..]).await;
}

async fn authenticate(nodes: &mut [TestNode], remote: usize) {
    tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            turn(nodes).await;
            if nodes[LOCAL]
                .node
                .get_peer(nodes[remote].node.node_addr())
                .is_some()
                && nodes[remote]
                    .node
                    .get_peer(nodes[LOCAL].node.node_addr())
                    .is_some()
                && nodes[LOCAL].node.connection_count() == 0
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
    })
    .await
    .expect("ordinary discovery and Noise must authenticate the allowed peer");
}
