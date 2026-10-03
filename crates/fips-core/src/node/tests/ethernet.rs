//! Ethernet transport integration tests.
//!
//! Tests that the Ethernet transport works end-to-end using veth pairs.
//! All tests require root or CAP_NET_RAW and are marked `#[ignore]`.

use super::*;
use crate::config::EthernetConfig;
use crate::transport::ethernet::EthernetTransport;
use crate::transport::{TransportAddr, TransportHandle, TransportId, packet_channel};
use spanning_tree::{TestNode, cleanup_nodes, drain_all_packets, initiate_handshake};

use std::process::Command;
use std::sync::atomic::{AtomicU32, Ordering};

/// Atomic counter for unique veth names across tests.
static VETH_COUNTER: AtomicU32 = AtomicU32::new(0);

/// RAII wrapper for a veth pair.
///
/// Creates a pair of connected virtual Ethernet interfaces. Destroying
/// one end automatically destroys the other.
struct VethPair {
    name_a: String,
    name_b: String,
}

impl VethPair {
    /// Create a new veth pair with unique interface names.
    ///
    /// Names are kept under 15 chars (IFNAMSIZ limit). Format: `ftXXa`/`ftXXb`
    /// where XX is an atomic counter combined with PID for cross-process uniqueness.
    fn create() -> Self {
        let id = VETH_COUNTER.fetch_add(1, Ordering::Relaxed);
        let pid = std::process::id() % 10000;
        let name_a = format!("ft{}{}a", pid, id);
        let name_b = format!("ft{}{}b", pid, id);

        assert!(name_a.len() <= 15, "veth name too long: {}", name_a);
        assert!(name_b.len() <= 15, "veth name too long: {}", name_b);

        // Create veth pair
        let status = Command::new("ip")
            .args([
                "link", "add", &name_a, "type", "veth", "peer", "name", &name_b,
            ])
            .status()
            .expect("failed to run 'ip link add'");
        assert!(status.success(), "failed to create veth pair");

        // Bring both ends up
        let status = Command::new("ip")
            .args(["link", "set", &name_a, "up"])
            .status()
            .expect("failed to run 'ip link set up'");
        assert!(status.success(), "failed to bring up {}", name_a);

        let status = Command::new("ip")
            .args(["link", "set", &name_b, "up"])
            .status()
            .expect("failed to run 'ip link set up'");
        assert!(status.success(), "failed to bring up {}", name_b);

        VethPair { name_a, name_b }
    }
}

impl Drop for VethPair {
    fn drop(&mut self) {
        // Deleting one end destroys both
        let _ = Command::new("ip")
            .args(["link", "delete", &self.name_a])
            .status();
    }
}

/// Create a test node with a live Ethernet transport on the given interface.
///
/// Parallel to `make_test_node()` in spanning_tree.rs but uses
/// EthernetTransport instead of UDP.
async fn make_test_node_ethernet(interface: &str) -> TestNode {
    let config = EthernetConfig {
        interface: interface.to_string(),
        discovery: Some(false),
        announce: Some(false),
        accept_connections: Some(true),
        ..Default::default()
    };
    make_configured_ethernet_node(make_node(), config).await
}

async fn make_configured_ethernet_node(mut node: Node, config: EthernetConfig) -> TestNode {
    let transport_id = TransportId::new(1);

    let (packet_tx, packet_rx) = packet_channel(256);
    let (tun_outbound_tx, tun_outbound_rx) = crate::upper::tun::tun_outbound_channel(256);
    node.tun_outbound_rx = Some(tun_outbound_rx);

    let mut transport = EthernetTransport::new(transport_id, None, config, packet_tx);
    transport.set_local_pubkey(node.identity.pubkey());
    transport.start_async().await.unwrap();

    let mac = transport
        .local_mac()
        .expect("transport should have MAC after start");
    let addr = TransportAddr::from_bytes(&mac);

    node.transports
        .insert(transport_id, TransportHandle::Ethernet(transport));

    TestNode {
        node,
        transport_id,
        packet_rx,
        tun_outbound_tx,
        addr,
    }
}

/// A startup beacon received while the old owner is fresh survives until retry.
#[test]
#[ignore] // Requires an isolated network namespace with CAP_NET_ADMIN and CAP_NET_RAW.
fn ethernet_startup_beacon_recovers_recently_authenticated_neighbor() {
    super::session::run_large_stack_async_test("ethernet-startup-recovery", || async {
        use futures::FutureExt;
        use spanning_tree::poll_available_packets;
        use std::panic::AssertUnwindSafe;

        let veth = VethPair::create();
        let config = |interface: &str, announce| EthernetConfig {
            interface: interface.to_owned(),
            discovery: Some(true),
            announce: Some(announce),
            auto_connect: Some(true),
            accept_connections: Some(true),
            beacon_interval_secs: Some(60),
            ..Default::default()
        };
        let mut survivor = make_node();
        survivor.config.node.heartbeat_interval_secs = 1;
        let mut nodes = [
            make_configured_ethernet_node(survivor, config(&veth.name_a, false)).await,
            make_configured_ethernet_node(make_node(), config(&veth.name_b, false)).await,
        ];
        let result = AssertUnwindSafe(async {
            initiate_handshake(&mut nodes, 0, 1).await;
            tokio::time::timeout(Duration::from_secs(1), async {
                while nodes
                    .iter()
                    .any(|node| node.node.peer_count() != 1 || node.node.connection_count() != 0)
                {
                    poll_available_packets(&mut nodes).await;
                    tokio::time::sleep(Duration::from_millis(5)).await;
                }
            })
            .await
            .expect("initial Ethernet handshake completes");
            let remote = *nodes[1].node.node_addr();
            let old = nodes[0].node.get_peer(&remote).unwrap();
            let old_owner = (old.link_id(), old.remote_epoch());
            let mut restart_config = nodes[1].node.config.clone();
            restart_config
                .node
                .identity
                .replace_nsec(Some(crate::encode_nsec(
                    &nodes[1].node.identity.keypair().secret_key(),
                )));
            cleanup_nodes(&mut nodes[1..]).await;
            nodes[1] = make_configured_ethernet_node(
                Node::new(restart_config).unwrap(),
                config(&veth.name_b, true),
            )
            .await;
            assert_eq!(*nodes[1].node.node_addr(), remote);
            assert_ne!(Some(nodes[1].node.startup_epoch), old_owner.1);

            let beacons = |node: &TestNode| {
                let TransportHandle::Ethernet(transport) =
                    &node.node.transports[&node.transport_id]
                else {
                    unreachable!()
                };
                transport.stats().snapshot().beacons_recv
            };
            tokio::time::timeout(Duration::from_secs(1), async {
                while beacons(&nodes[0]) == 0 {
                    tokio::time::sleep(Duration::from_millis(5)).await;
                }
            })
            .await
            .expect("one real startup beacon arrives");
            assert!(!nodes[0].node.active_peer_needs_same_path_refresh(&remote));
            nodes[0].node.poll_transport_discovery().await;
            let retained = nodes[0].node.get_peer(&remote).unwrap();
            assert_eq!((retained.link_id(), retained.remote_epoch()), old_owner);
            assert_eq!(nodes[0].node.connection_count(), 0);

            // A retained hint shares the ordinary link budget. It must wait
            // without allocating a candidate, then make exactly one attempt.
            nodes[0].node.set_max_links(1);
            let blocked_until = std::time::Instant::now() + Duration::from_millis(2250);
            while std::time::Instant::now() < blocked_until {
                nodes[0].node.poll_transport_discovery().await;
                assert_eq!(nodes[0].node.connection_count(), 0);
                assert_eq!(nodes[0].node.link_count(), 1);
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            assert_eq!(nodes[0].node.deferred_ethernet_hints.len(), 1);
            nodes[0].node.set_max_links(2);

            tokio::time::timeout(Duration::from_secs(4), async {
                loop {
                    nodes[0].node.poll_transport_discovery().await;
                    poll_available_packets(&mut nodes).await;
                    if nodes[0].node.get_peer(&remote).is_some_and(|peer| {
                        peer.remote_epoch() == Some(nodes[1].node.startup_epoch)
                            && peer.is_healthy()
                            && peer.can_send()
                    }) {
                        break;
                    }
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            })
            .await
            .expect("startup hint must recover the silent peer before another periodic beacon");
            assert_eq!(beacons(&nodes[0]), 1);
            assert_eq!(nodes[0].node.connection_count(), 0);
        })
        .catch_unwind()
        .await;
        cleanup_nodes(&mut nodes).await;
        if let Err(panic) = result {
            std::panic::resume_unwind(panic);
        }
    });
}

#[test]
#[ignore] // Requires an isolated network namespace with CAP_NET_ADMIN and CAP_NET_RAW.
fn ethernet_repeated_beacons_preserve_a_responsive_owner() {
    super::session::run_large_stack_async_test("ethernet-healthy-discovery", || async {
        use crate::transport::ethernet::discovery::build_beacon;
        use crate::transport::ethernet::socket::{ETHERNET_BROADCAST, PacketSocket};
        use futures::FutureExt;
        use spanning_tree::poll_available_packets;
        use std::panic::AssertUnwindSafe;

        let veth = VethPair::create();
        let config = EthernetConfig {
            interface: veth.name_a.clone(),
            auto_connect: Some(true),
            accept_connections: Some(true),
            ..Default::default()
        };
        let raw = PacketSocket::open(&veth.name_b, config.ethertype()).unwrap();
        let mut local = make_node();
        local.config.node.heartbeat_interval_secs = 1;
        let mut nodes = [
            make_configured_ethernet_node(local, config).await,
            make_test_node_ethernet(&veth.name_b).await,
        ];
        let result = AssertUnwindSafe(async {
            initiate_handshake(&mut nodes, 0, 1).await;
            drain_all_packets(&mut nodes, false).await;
            let remote = *nodes[1].node.node_addr();
            let local = *nodes[0].node.node_addr();
            let peer = nodes[0].node.get_peer(&remote).unwrap();
            let owner = (peer.link_id(), peer.session_generation(), peer.our_index());
            let beacon = build_beacon(&nodes[1].node.identity.pubkey());
            // Normal heartbeat cadence plus delivery jitter must not spend
            // an old discovery hint after authenticated traffic disproved it.
            for _ in 0..3 {
                nodes[1]
                    .node
                    .send_dataplane_fmp_link_plaintext(
                        &local,
                        &[crate::protocol::LinkMessageType::Heartbeat.to_byte()],
                        false,
                    )
                    .await
                    .unwrap();
                for _ in 0..10 {
                    tokio::time::sleep(Duration::from_millis(5)).await;
                    poll_available_packets(&mut nodes).await;
                    nodes[0].node.poll_transport_discovery().await;
                }
                assert!(nodes[0].node.deferred_ethernet_hints.is_empty());
                raw.send_to(&beacon, &ETHERNET_BROADCAST).unwrap();
                for _ in 0..110 {
                    tokio::time::sleep(Duration::from_millis(10)).await;
                    poll_available_packets(&mut nodes).await;
                    nodes[0].node.poll_transport_discovery().await;
                    assert_eq!(nodes[0].node.connection_count(), 0);
                    assert_eq!(nodes[0].node.link_count(), 1);
                    assert!(nodes[0].node.deferred_ethernet_hints.len() <= 1);
                }
            }
            let peer = nodes[0].node.get_peer(&remote).unwrap();
            assert_eq!(
                (peer.link_id(), peer.session_generation(), peer.our_index()),
                owner
            );
            assert_eq!(nodes[0].node.deferred_ethernet_hints.len(), 1);
            // Disabling this transport must cancel the retained retry.
            nodes[0]
                .node
                .transports
                .get_mut(&nodes[0].transport_id)
                .unwrap()
                .stop()
                .await
                .unwrap();
            nodes[0].node.poll_transport_discovery().await;
            assert!(nodes[0].node.deferred_ethernet_hints.is_empty());
            assert_eq!(nodes[0].node.connection_count(), 0);
        })
        .catch_unwind()
        .await;
        cleanup_nodes(&mut nodes).await;
        if let Err(panic) = result {
            std::panic::resume_unwind(panic);
        }
    });
}

/// Two nodes on a veth pair complete a Noise handshake and establish peering.
#[tokio::test]
#[ignore] // Requires root or CAP_NET_RAW
async fn test_ethernet_two_node_handshake() {
    let veth = VethPair::create();

    let mut nodes = vec![
        make_test_node_ethernet(&veth.name_a).await,
        make_test_node_ethernet(&veth.name_b).await,
    ];

    // Initiate handshake from node 0 to node 1
    initiate_handshake(&mut nodes, 0, 1).await;

    // Drain all packets (handshake + tree announce)
    let total = drain_all_packets(&mut nodes, false).await;
    assert!(total > 0, "should have processed packets");

    // Verify bidirectional peering
    let addr_0 = *nodes[0].node.node_addr();
    let addr_1 = *nodes[1].node.node_addr();
    assert!(
        nodes[0].node.get_peer(&addr_1).is_some(),
        "node 0 should have node 1 as peer"
    );
    assert!(
        nodes[1].node.get_peer(&addr_0).is_some(),
        "node 1 should have node 0 as peer"
    );

    cleanup_nodes(&mut nodes).await;
}

/// Two Ethernet nodes converge to a correct spanning tree (2-node tree).
#[tokio::test]
#[ignore] // Requires root or CAP_NET_RAW
async fn test_ethernet_data_exchange() {
    use spanning_tree::verify_tree_convergence;

    let veth = VethPair::create();

    let mut nodes = vec![
        make_test_node_ethernet(&veth.name_a).await,
        make_test_node_ethernet(&veth.name_b).await,
    ];

    initiate_handshake(&mut nodes, 0, 1).await;
    let total = drain_all_packets(&mut nodes, false).await;
    assert!(total > 0);

    // Verify spanning tree convergence
    verify_tree_convergence(&nodes);

    // The root should be the node with the smallest NodeAddr
    let expected_root = std::cmp::min(*nodes[0].node.node_addr(), *nodes[1].node.node_addr());
    assert_eq!(*nodes[0].node.tree_state().root(), expected_root);
    assert_eq!(*nodes[1].node.tree_state().root(), expected_root);

    cleanup_nodes(&mut nodes).await;
}

/// Mixed transport: 2 Ethernet nodes + 2 UDP nodes coexist.
///
/// Each transport forms its own connected component. Validates that
/// `process_available_packets()` handles heterogeneous transport types.
#[tokio::test]
#[ignore] // Requires root or CAP_NET_RAW
async fn test_mixed_transport_coexistence() {
    use spanning_tree::{make_test_node, verify_tree_convergence_components};

    let veth = VethPair::create();

    // Create 2 Ethernet nodes and 2 UDP nodes
    let eth_0 = make_test_node_ethernet(&veth.name_a).await;
    let eth_1 = make_test_node_ethernet(&veth.name_b).await;
    let udp_0 = make_test_node().await;
    let udp_1 = make_test_node().await;

    let mut nodes = vec![eth_0, eth_1, udp_0, udp_1];

    // Handshake within each component
    initiate_handshake(&mut nodes, 0, 1).await; // Ethernet pair
    initiate_handshake(&mut nodes, 2, 3).await; // UDP pair

    // Drain all packets across both transports
    let total = drain_all_packets(&mut nodes, false).await;
    assert!(total > 0);

    // Verify each component converges independently
    verify_tree_convergence_components(&nodes, &[vec![0, 1], vec![2, 3]]);

    // Ethernet component has its own root
    let eth_root = std::cmp::min(*nodes[0].node.node_addr(), *nodes[1].node.node_addr());
    assert_eq!(*nodes[0].node.tree_state().root(), eth_root);
    assert_eq!(*nodes[1].node.tree_state().root(), eth_root);

    // UDP component has its own root
    let udp_root = std::cmp::min(*nodes[2].node.node_addr(), *nodes[3].node.node_addr());
    assert_eq!(*nodes[2].node.tree_state().root(), udp_root);
    assert_eq!(*nodes[3].node.tree_state().root(), udp_root);

    cleanup_nodes(&mut nodes).await;
}
