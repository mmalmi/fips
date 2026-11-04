use super::*;
use crate::discovery::local_udp::LocalListenerProvider;
use crate::peer::ActivePeer;
use crate::transport::LinkId;

#[test]
fn listener_roster_requires_matching_owner_revision_and_provider_incarnation() {
    let mut config = Config::new();
    config.node.discovery.local.enabled = true;
    config.node.system_files_enabled = false;
    let mut node = Node::new(config).unwrap();
    let anchor = Identity::generate();
    let provider = Identity::generate();
    let anchor_id = PeerIdentity::from_pubkey_full(anchor.pubkey_full());
    let transport = TransportId::new(77);
    node.local_rendezvous.role = Some(LocalRendezvousRole::Client);
    node.local_rendezvous.transport_id = Some(transport);
    node.local_rendezvous.anchor_peer = Some(AnchorPeer {
        identity: anchor_id,
        startup_epoch: [1; 8],
    });
    // Handler-state fixture; the companion endpoint test verifies real FMP/FSP
    // authentication and a direct anonymous GET for every anchor start order.
    let mut peer = ActivePeer::new(anchor_id, LinkId::new(1), 1);
    peer.set_current_addr(
        transport,
        &TransportAddr::from_socket_addr(node.local_rendezvous.fixed_addr),
    );
    peer.set_remote_epoch(Some([1; 8]));
    node.peers.insert(*anchor.node_addr(), peer);
    let roster = |revision, epoch| {
        LocalCapabilityMessage::Roster {
            anchor_epoch: [1; 8],
            revision,
            providers: vec![LocalCapabilityProvider {
                pubkey: provider.pubkey().serialize(),
                process_epoch: [epoch; 8],
                capabilities: vec![LocalInstanceCapability::service("blob/1", 3333)],
            }],
        }
        .encode()
        .unwrap()
    };
    let listeners = |revision, epoch, port| {
        LocalCapabilityMessage::ListenerRoster {
            anchor_epoch: [1; 8],
            revision,
            providers: vec![LocalListenerProvider {
                pubkey: provider.pubkey().serialize(),
                process_epoch: [epoch; 8],
                ports: vec![port],
            }],
        }
        .encode()
        .unwrap()
    };
    let expected = |port| {
        (
            vec![SocketAddr::new(node.local_rendezvous.fixed_addr.ip(), port)],
            false,
        )
    };
    let first = expected(3333);
    let second = expected(4444);
    let third = expected(5555);
    node.handle_local_capability_message(anchor.node_addr(), &listeners(1, 9, 3333));
    assert_eq!(
        node.rostered_local_udp_listeners(provider.node_addr()),
        (vec![], false)
    );
    node.handle_local_capability_message(anchor.node_addr(), &roster(1, 9));
    assert_eq!(
        node.rostered_local_udp_listeners(provider.node_addr()),
        first
    );

    node.handle_local_capability_message(anchor.node_addr(), &roster(2, 9));
    assert_eq!(
        node.rostered_local_udp_listeners(provider.node_addr()),
        (vec![], true)
    );
    node.handle_local_capability_message(anchor.node_addr(), &listeners(2, 9, 4444));
    assert_eq!(
        node.rostered_local_udp_listeners(provider.node_addr()),
        second
    );
    // Replayed or same-revision altered metadata cannot replace the accepted snapshot.
    node.handle_local_capability_message(anchor.node_addr(), &listeners(1, 9, 3333));
    node.handle_local_capability_message(anchor.node_addr(), &listeners(2, 9, 3333));
    node.handle_local_capability_message(provider.node_addr(), &listeners(3, 9, 3333));
    assert_eq!(
        node.rostered_local_udp_listeners(provider.node_addr()),
        second
    );

    node.handle_local_capability_message(anchor.node_addr(), &roster(3, 10));
    node.handle_local_capability_message(anchor.node_addr(), &listeners(3, 9, 3333));
    assert_eq!(
        node.rostered_local_udp_listeners(provider.node_addr()),
        (vec![], true)
    );
    node.handle_local_capability_message(anchor.node_addr(), &roster(4, 10));
    node.handle_local_capability_message(anchor.node_addr(), &listeners(4, 10, 5555));
    assert_eq!(
        node.rostered_local_udp_listeners(provider.node_addr()),
        third
    );
    node.local_rendezvous
        .anchor_peer
        .as_mut()
        .unwrap()
        .startup_epoch = [2; 8];
    assert_eq!(
        node.rostered_local_udp_listeners(provider.node_addr()),
        (vec![], true)
    );
}
