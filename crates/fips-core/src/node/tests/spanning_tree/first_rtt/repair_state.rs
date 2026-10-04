//! Exercise declaration repair through the production report handler.
use super::*;

fn fixture(smaller: bool) -> (Node, NodeAddr) {
    let mut identities = [Identity::generate(), Identity::generate()];
    identities.sort_by_key(|identity| *identity.node_addr());
    let [lower, higher] = identities;
    let (local, remote) = if smaller {
        (higher, lower)
    } else {
        (lower, higher)
    };
    let mut node = Node::with_identity(local, Config::new()).unwrap();
    let addr = connect_peer(&mut node, &remote, LinkId::new(1));
    assert_eq!(addr < *node.tree_state().root(), smaller);
    assert!(node.tree_state().peer_coords(&addr).is_none());
    assert!(!node.dataplane_fmp_has_srtt(&addr));
    assert!(!node.get_peer(&addr).unwrap().has_pending_tree_announce());
    (node, addr)
}

fn connect_peer(node: &mut Node, remote: &Identity, link: LinkId) -> NodeAddr {
    let (connection, peer) = make_completed_connection_for_identity(
        node,
        link,
        TransportId::new(1),
        Node::now_ms(),
        remote,
    );
    node.add_connection(connection).unwrap();
    node.promote_connection(link, peer, Node::now_ms()).unwrap();
    *peer.node_addr()
}

async fn announce_root(node: &mut Node, identity: &Identity) {
    let peer = *identity.node_addr();
    let timestamp = crate::time::now_secs();
    let mut declaration = ParentDeclaration::new(peer, peer, 1, timestamp);
    declaration.sign(identity).unwrap();
    let encoded = TreeAnnounce::new(
        declaration,
        TreeCoordinate::root_with_meta(peer, 1, timestamp),
    )
    .encode()
    .unwrap();
    node.handle_tree_announce(&peer, &encoded[1..]).await;
}

fn report(counter: u64, echo: u32) -> Vec<u8> {
    ReceiverReport {
        highest_counter: counter,
        cumulative_packets_recv: counter,
        cumulative_bytes_recv: counter * 100,
        timestamp_echo: echo,
        dwell_time: 0,
        max_burst_loss: 0,
        mean_burst_loss: 0,
        jitter: 0,
        ecn_ce_count: 0,
        owd_trend: 0,
        burst_loss_count: 0,
        cumulative_reorder_count: 0,
        interval_packets_recv: 1,
        interval_bytes_recv: 100,
    }
    .encode()
}

#[tokio::test]
async fn unmeasured_smaller_peer_does_not_spend_old_declaration_send_interval() {
    let (mut node, peer) = fixture(true);
    // Ensure echo=1 is a valid session-relative RTT sample without seeding metrics.
    tokio::time::sleep(Duration::from_millis(5)).await;
    for (counter, echo, measured, pending) in [
        (1, 0, false, false),
        (2, 1, true, false),
        (3, 1, true, true),
    ] {
        node.handle_receiver_report(&peer, &report(counter, echo)[1..])
            .await;
        assert_eq!(node.dataplane_fmp_has_srtt(&peer), measured);
        assert_eq!(
            node.get_peer(&peer).unwrap().has_pending_tree_announce(),
            pending,
            "report {counter}: no RTT and first RTT defer; later measured reports repair"
        );
    }
}

#[tokio::test]
async fn unmeasured_larger_peer_still_rearms_missing_declaration_repair() {
    let (mut node, peer) = fixture(false);
    node.handle_receiver_report(&peer, &report(1, 0)[1..]).await;
    assert!(!node.dataplane_fmp_has_srtt(&peer));
    assert!(node.get_peer(&peer).unwrap().has_pending_tree_announce());
}

#[tokio::test]
async fn unmeasured_better_root_does_not_rearm_obsolete_declaration() {
    let mut identities = [
        Identity::generate(),
        Identity::generate(),
        Identity::generate(),
    ];
    identities.sort_by_key(|identity| *identity.node_addr());
    let [remote, original, local] = identities;
    let mut node = Node::with_identity(local, Config::new()).unwrap();
    let parent = connect_peer(&mut node, &original, LinkId::new(1));
    tokio::time::sleep(Duration::from_millis(5)).await;
    node.handle_receiver_report(&parent, &report(1, 1)[1..])
        .await;
    announce_root(&mut node, &original).await;
    assert!(node.dataplane_fmp_has_srtt(&parent));
    assert_eq!(node.tree_state().root(), &parent);

    let peer = connect_peer(&mut node, &remote, LinkId::new(2));
    announce_root(&mut node, &remote).await;
    assert_eq!(
        node.tree_state().peer_coords(&peer).unwrap().root_id(),
        &peer
    );
    assert_ne!(
        node.tree_state().root(),
        &peer,
        "parent must first be measured"
    );
    assert!(!node.get_peer(&peer).unwrap().has_pending_tree_announce());

    node.handle_receiver_report(&peer, &report(1, 0)[1..]).await;
    assert!(!node.dataplane_fmp_has_srtt(&peer));
    assert!(
        !node.get_peer(&peer).unwrap().has_pending_tree_announce(),
        "an unmeasured better root must not trigger an obsolete-root repair"
    );
    tokio::time::sleep(Duration::from_millis(5)).await;
    node.handle_receiver_report(&peer, &report(2, 1)[1..]).await;
    assert!(node.dataplane_fmp_has_srtt(&peer));
    assert_eq!(node.tree_state().root(), &peer);
}
