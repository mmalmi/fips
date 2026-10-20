use super::*;
use crate::dataplane::{DataplaneDirectFspSources, lookup_direct_fsp_source};
use std::panic::{AssertUnwindSafe, catch_unwind};

#[test]
fn opaque_address_ambiguity_without_authenticated_link_ownership_stays_rejected() {
    let transport = TransportId::new(1);
    let addr = shared_mobile_addr();
    let first = NodeAddr::from_bytes([1; 16]);
    let second = NodeAddr::from_bytes([2; 16]);
    for owners in [[first, second], [second, first]] {
        let sources =
            crate::dataplane::dataplane_direct_fsp_sources_from_exact(owners.map(|source_addr| {
                (
                    transport,
                    addr.clone(),
                    crate::dataplane::DataplaneDirectFspSource {
                        source_addr,
                        path_mtu: 2048,
                    },
                )
            }));
        assert!(lookup_direct_fsp_source(&sources, transport, &addr).is_none());
    }
}

fn shared_mobile_addr() -> TransportAddr {
    BleAddr::from_opaque("android", "same-physical-handset")
        .expect("valid opaque mobile BLE address")
        .to_transport_addr()
}

fn authenticated_peer(
    test: &mut TestNode,
    link_id: LinkId,
    remote_addr: &TransportAddr,
) -> NodeAddr {
    let (mut connection, identity) =
        make_completed_connection(&mut test.node, link_id, test.transport_id, 1_000);
    connection.set_source_addr(remote_addr.clone());
    let peer = *identity.node_addr();
    test.node.links.insert(
        link_id,
        Link::connectionless(
            link_id,
            test.transport_id,
            remote_addr.clone(),
            LinkDirection::Outbound,
            Duration::from_millis(100),
        ),
    );
    test.node.add_connection(connection).unwrap();
    test.node
        .promote_connection(link_id, identity, 2_000)
        .unwrap();
    test.node
        .links
        .insert_addr((test.transport_id, remote_addr.clone()), link_id);
    let authenticated = test.node.get_peer(&peer).expect("promoted Noise peer");
    assert!(authenticated.has_session());
    assert!(authenticated.is_healthy());
    peer
}

fn source_at(
    sources: &DataplaneDirectFspSources,
    test: &TestNode,
    remote_addr: &TransportAddr,
) -> Option<NodeAddr> {
    lookup_direct_fsp_source(sources, test.transport_id, remote_addr)
        .map(|source| source.source_addr)
}

fn run(name: &'static str, exercise: impl FnOnce(&mut TestNode) + Send + 'static) {
    super::super::session::run_large_stack_async_test(name, move || async move {
        let mut nodes = vec![make_test_node_ble(1).await];
        let result = catch_unwind(AssertUnwindSafe(|| {
            exercise(nodes.first_mut().expect("one BLE receiver"));
        }));
        cleanup_nodes(&mut nodes).await;
        if let Err(panic) = result {
            std::panic::resume_unwind(panic);
        }
    });
}

#[test]
fn same_ble_address_projects_only_its_current_authenticated_link_owner() {
    run("ble-identity-address-owner", |test| {
        let remote_addr = shared_mobile_addr();
        let old_link = LinkId::new(10);
        let new_link = LinkId::new(11);
        let old_peer = authenticated_peer(test, old_link, &remote_addr);
        let new_peer = authenticated_peer(test, new_link, &remote_addr);
        assert_ne!(old_peer, new_peer, "the physical handset changed identity");
        assert!(test.node.get_peer(&old_peer).unwrap().is_healthy());
        assert!(test.node.get_peer(&new_peer).unwrap().is_healthy());
        assert_eq!(
            test.node.links.lookup_addr(test.transport_id, &remote_addr),
            Some(new_link)
        );

        let sources = test.node.dataplane_direct_fsp_sources();
        assert_eq!(
            source_at(&sources, test, &remote_addr),
            Some(new_peer),
            "a retained authenticated identity must not make the current BLE owner ambiguous"
        );
        let exact = &sources.get(&test.transport_id).unwrap().exact;
        assert_eq!(exact.len(), 1);
        assert!(exact.values().all(|source| source.source_addr == new_peer));
    });
}

#[test]
fn pending_ble_address_owner_cannot_inherit_a_retained_authenticated_source() {
    run("ble-identity-pending-owner", |test| {
        let remote_addr = shared_mobile_addr();
        let old_peer = authenticated_peer(test, LinkId::new(10), &remote_addr);
        let pending_link = LinkId::new(11);
        let mut pending = PeerConnection::inbound(pending_link, 3_000);
        pending.set_transport_id(test.transport_id);
        pending.set_source_addr(remote_addr.clone());
        assert!(!pending.has_session());
        test.node.add_connection(pending).unwrap();
        test.node.links.insert(
            pending_link,
            Link::connectionless(
                pending_link,
                test.transport_id,
                remote_addr.clone(),
                LinkDirection::Inbound,
                Duration::from_millis(100),
            ),
        );
        test.node
            .links
            .insert_addr((test.transport_id, remote_addr.clone()), pending_link);
        assert_eq!(test.node.peer_count(), 1);
        assert!(test.node.get_peer(&old_peer).unwrap().has_session());
        assert!(test.node.get_connection(&pending_link).is_some());

        let sources = test.node.dataplane_direct_fsp_sources();
        assert_eq!(
            source_at(&sources, test, &remote_addr),
            None,
            "an unauthenticated current BLE link must never receive the old identity's source attribution"
        );
    });
}

#[test]
fn cached_ble_sources_follow_address_handoff_and_removal_without_manual_dirtying() {
    run("ble-identity-cached-owner", |test| {
        let remote_addr = shared_mobile_addr();
        let key = (test.transport_id, remote_addr.clone());
        let old_link = LinkId::new(10);
        let new_link = LinkId::new(11);
        let old_peer = authenticated_peer(test, old_link, &remote_addr);
        let sources = test.node.dataplane_direct_fsp_sources_for_rx_turn();
        assert_eq!(source_at(&sources, test, &remote_addr), Some(old_peer));

        assert_eq!(test.node.links.remove_addr(&key), Some(old_link));
        let removed = test.node.dataplane_direct_fsp_sources_for_rx_turn();
        assert_eq!(
            source_at(&removed, test, &remote_addr),
            None,
            "address removal must retire a cached source without an unrelated peer mutation"
        );
        test.node.links.insert_addr(key.clone(), old_link);
        let restored = test.node.dataplane_direct_fsp_sources_for_rx_turn();
        assert_eq!(source_at(&restored, test, &remote_addr), Some(old_peer));

        let new_peer = authenticated_peer(test, new_link, &remote_addr);
        test.node.links.insert_addr(key.clone(), old_link);
        let before_handoff = test.node.dataplane_direct_fsp_sources_for_rx_turn();
        assert_eq!(
            source_at(&before_handoff, test, &remote_addr),
            Some(old_peer)
        );
        test.node.links.insert_addr(key, new_link);
        let handed_off = test.node.dataplane_direct_fsp_sources_for_rx_turn();
        assert_eq!(
            source_at(&handed_off, test, &remote_addr),
            Some(new_peer),
            "the RX-turn cache must observe a new authenticated address owner immediately"
        );
        assert!(test.node.links.remove(&new_link).is_some());
        let winner_removed = test.node.dataplane_direct_fsp_sources_for_rx_turn();
        assert_eq!(source_at(&winner_removed, test, &remote_addr), None);
        assert!(test.node.get_peer(&old_peer).unwrap().is_healthy());
        assert!(test.node.get_peer(&new_peer).unwrap().is_healthy());
    });
}
