//! Ordinary LAN discovery must not spend its only slot on an ACL-denied peer.
//! Feed the production event-batch boundary; no mDNS runtime is started.
use super::*;
use crate::discovery::lan::{LanDiscoveredPeer, LanEvent};
use crate::node::acl::{PeerAclContext, PeerAclReloader};
use crate::node::wire::Msg1Header;
use futures::FutureExt;
use std::panic::AssertUnwindSafe;

#[test]
fn denied_lan_candidate_cannot_consume_the_only_discovery_slot() {
    crate::node::tests::session::run_large_stack_async_test("rotation-lan-acl", || async {
        let _guard = crate::node::tests::spanning_tree::lock_large_network_test().await;
        let mut node = make_test_node().await;
        let result = AssertUnwindSafe(exercise(&mut node)).catch_unwind().await;
        cleanup_nodes(std::slice::from_mut(&mut node)).await;
        if let Err(panic) = result {
            std::panic::resume_unwind(panic);
        }
    });
}

async fn exercise(node: &mut TestNode) {
    let incumbent_peer = make_node();
    let mut denied = make_node();
    let mut allowed = make_node();
    let (_incumbent_socket, incumbent_source) = local_path().await;
    let (denied_socket, denied_source) = local_path().await;
    let (allowed_socket, allowed_source) = local_path().await;
    let mut owner = incumbent(node, &incumbent_peer, &incumbent_source, 801, 0).await;
    enable(node, 1);
    node.node.config.node.neighbor_rotation = Some(NeighborRotationConfig {
        idle_secs: 1,
        interval_secs: 1,
    });
    node.node.config.node.rate_limit.handshake_timeout_secs = 6;
    node.node.config.node.rekey.enabled = false;
    tokio::time::sleep(Duration::from_millis(1_050)).await;
    assert_eq!(resources(node), (1, 0, 1, 1));
    assert!(
        node.node
            .has_neighbor_preparation_opportunity(Node::now_ms())
    );
    assert!(node.node.lan_discovery.is_none());

    // Sort actual identities once, not generated outcomes or internal flags.
    if node.node.neighbor_rotation_order(*denied.node_addr())
        > node.node.neighbor_rotation_order(*allowed.node_addr())
    {
        std::mem::swap(&mut denied, &mut allowed);
    }
    assert!(
        node.node.neighbor_rotation_order(*denied.node_addr())
            < node.node.neighbor_rotation_order(*allowed.node_addr())
    );
    let acl = tempfile::tempdir().unwrap();
    let allow_path = acl.path().join("peers.allow");
    let deny_path = acl.path().join("peers.deny");
    std::fs::write(&allow_path, "").unwrap();
    std::fs::write(&deny_path, denied.identity.npub()).unwrap();
    node.node.peer_acl = PeerAclReloader::with_paths(allow_path, deny_path);
    for (peer, source, permitted) in [
        (&denied, &denied_source, false),
        (&allowed, &allowed_source, true),
    ] {
        let identity = PeerIdentity::from_pubkey_full(peer.identity.pubkey_full());
        assert_eq!(
            node.node
                .authorize_peer(
                    &identity,
                    PeerAclContext::OutboundConnect,
                    node.transport_id,
                    source,
                )
                .is_ok(),
            permitted
        );
    }
    let events = vec![
        // Reverse arrival order ensures the production full-roster sorter,
        // rather than this vector's order, puts the denied candidate first.
        discovered(&allowed, allowed_socket.local_addr().unwrap()),
        discovered(&denied, denied_socket.local_addr().unwrap()),
    ];
    assert_eq!(
        node.node
            .find_udp_transport_for_remote_addr(
                allowed_socket.local_addr().unwrap(),
                crate::config::PeerAddressProvenance::Learned,
            )
            .map(|(transport, _)| transport),
        Some(node.transport_id)
    );

    node.node.process_lan_discovery_events(events.clone()).await;
    let first_owner = node
        .node
        .peers
        .connection_values()
        .next()
        .map(|conn| (conn.link_id(), conn.our_index(), conn.last_activity()));
    node.node.process_lan_discovery_events(events).await;
    let pending = node
        .node
        .peers
        .connection_values()
        .next()
        .expect("ACL-denied R must leave the sole slot available for allowed D");
    assert_eq!(
        pending.expected_identity().unwrap().node_addr(),
        allowed.node_addr()
    );
    assert_eq!(pending.transport_id(), Some(node.transport_id));
    assert_eq!(pending.source_addr(), Some(&allowed_source));
    assert_eq!(
        first_owner,
        Some((
            pending.link_id(),
            pending.our_index(),
            pending.last_activity()
        )),
        "repeated adverts must retain the exact original allowed attempt"
    );
    let pending_index = pending.our_index().unwrap();
    assert_eq!(resources(node), (1, 1, 2, 2));
    assert_eq!(
        node.node
            .get_peer(incumbent_peer.node_addr())
            .unwrap()
            .our_index(),
        Some(owner.index)
    );
    assert!(node.node.get_peer(allowed.node_addr()).is_none());
    assert!(
        denied_socket.try_recv(&mut [0; 512]).is_err(),
        "no denied-peer Noise is emitted"
    );

    let mut wire = [0; 512];
    let length = tokio::time::timeout(Duration::from_secs(1), allowed_socket.recv(&mut wire))
        .await
        .unwrap()
        .unwrap();
    let wire = &wire[..length];
    let header = Msg1Header::parse(wire).expect("actual allowed-peer UDP Noise Msg1");
    assert_eq!(header.sender_idx, pending_index);
    let mut responder = HandshakeState::new_responder(allowed.identity.keypair());
    responder.set_local_epoch(allowed.startup_epoch);
    responder.read_message_1(header.noise_msg1(wire)).unwrap();
    assert!(
        allowed_socket.try_recv(&mut [0; 512]).is_err(),
        "the second batch cannot start another attempt"
    );
    assert_eq!(heartbeat(node, &incumbent_peer, &mut owner, 2).await, 2);
}

fn discovered(peer: &Node, addr: std::net::SocketAddr) -> LanEvent {
    LanEvent::Discovered(LanDiscoveredPeer {
        npub: peer.identity.npub(),
        scope: None,
        addr,
        observed_at: std::time::Instant::now(),
    })
}
