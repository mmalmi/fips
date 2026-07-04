use super::*;

#[test]
fn test_node_cross_connection_resolution() {
    let mut node = make_node();
    let transport_id = TransportId::new(1);

    // First connection and promotion (becomes active peer)
    let link_id1 = LinkId::new(1);
    let (conn1, identity) = make_completed_connection(&mut node, link_id1, transport_id, 1000);
    let node_addr = *identity.node_addr();

    node.add_connection(conn1).unwrap();
    node.promote_connection(link_id1, identity, 1500).unwrap();

    assert_eq!(node.peer_count(), 1);
    assert_eq!(node.get_peer(&node_addr).unwrap().link_id(), link_id1);

    // Cross-connection tie-breaker logic is tested in peer/mod.rs tests.
    // The integration test will cover the real cross-connection path with
    // two actual nodes. Here we verify promotion works correctly.

    // Verify first promotion populated active peer registry session-index dispatch
    let peer = node.get_peer(&node_addr).unwrap();
    let our_idx = peer.our_index().unwrap();
    assert_eq!(
        node.peers
            .get_session_index(&(transport_id, our_idx.as_u32())),
        Some(&node_addr)
    );

    // Still only one peer
    assert_eq!(node.peer_count(), 1);
}

#[test]
fn test_node_peer_limit() {
    let mut node = make_node();
    let transport_id = TransportId::new(1);
    node.set_max_peers(2);

    // Add two peers via promotion
    for i in 0..2 {
        let link_id = LinkId::new(i as u64 + 1);
        let (conn, identity) = make_completed_connection(&mut node, link_id, transport_id, 1000);
        node.add_connection(conn).unwrap();
        node.promote_connection(link_id, identity, 2000).unwrap();
    }

    assert_eq!(node.peer_count(), 2);

    // Third should fail
    let link_id = LinkId::new(3);
    let (conn, identity) = make_completed_connection(&mut node, link_id, transport_id, 3000);
    node.add_connection(conn).unwrap();

    let result = node.promote_connection(link_id, identity, 4000);
    assert!(matches!(result, Err(NodeError::MaxPeersExceeded { .. })));
}

#[test]
fn test_node_link_id_allocation() {
    let mut node = make_node();

    let id1 = node.allocate_link_id();
    let id2 = node.allocate_link_id();
    let id3 = node.allocate_link_id();

    assert_ne!(id1, id2);
    assert_ne!(id2, id3);
    assert_eq!(id1.as_u64(), 1);
    assert_eq!(id2.as_u64(), 2);
    assert_eq!(id3.as_u64(), 3);
}

#[test]
fn test_node_transport_management() {
    let mut node = make_node();

    // Initially no transports (transports are created during start())
    assert_eq!(node.transport_count(), 0);

    // Allocating IDs still works
    let id1 = node.allocate_transport_id();
    let id2 = node.allocate_transport_id();
    assert_ne!(id1, id2);

    // get_transport returns None when transport doesn't exist
    assert!(node.get_transport(&id1).is_none());
    assert!(node.get_transport(&id2).is_none());

    // transport_ids() iterator is empty
    assert_eq!(node.transport_ids().count(), 0);
}

#[test]
fn test_node_sendable_peers() {
    let mut node = make_node();
    let transport_id = TransportId::new(1);

    // Add a healthy peer
    let link_id1 = LinkId::new(1);
    let (conn1, identity1) = make_completed_connection(&mut node, link_id1, transport_id, 1000);
    let node_addr1 = *identity1.node_addr();
    node.add_connection(conn1).unwrap();
    node.promote_connection(link_id1, identity1, 2000).unwrap();

    // Add another peer and mark it stale (still sendable)
    let link_id2 = LinkId::new(2);
    let (conn2, identity2) = make_completed_connection(&mut node, link_id2, transport_id, 1000);
    node.add_connection(conn2).unwrap();
    node.promote_connection(link_id2, identity2, 2000).unwrap();

    // Add a third peer and mark it disconnected (not sendable)
    let link_id3 = LinkId::new(3);
    let (conn3, identity3) = make_completed_connection(&mut node, link_id3, transport_id, 1000);
    let node_addr3 = *identity3.node_addr();
    node.add_connection(conn3).unwrap();
    node.promote_connection(link_id3, identity3, 2000).unwrap();
    node.get_peer_mut(&node_addr3).unwrap().mark_disconnected();

    assert_eq!(node.peer_count(), 3);
    assert_eq!(node.sendable_peer_count(), 2);

    let sendable: Vec<_> = node.sendable_peers().collect();
    assert_eq!(sendable.len(), 2);
    assert!(sendable.iter().any(|p| p.node_addr() == &node_addr1));
}

// === RX Loop Tests ===

#[test]
fn test_node_index_allocator_initialized() {
    let node = make_node();
    // Index allocator should be empty on creation
    assert_eq!(node.index_allocator.count(), 0);
}

#[test]
fn test_node_pending_outbound_tracking() {
    let mut node = make_node();
    let transport_id = TransportId::new(1);
    let link_id = LinkId::new(1);

    // Allocate an index
    let index = node.index_allocator.allocate().unwrap();

    // Track in pending_outbound
    node.pending_outbound
        .insert((transport_id, index.as_u32()), link_id);

    // Verify we can look it up
    let found = node.pending_outbound.get(&(transport_id, index.as_u32()));
    assert_eq!(found, Some(&link_id));

    // Clean up
    node.pending_outbound
        .remove(&(transport_id, index.as_u32()));
    let _ = node.index_allocator.free(index);

    assert_eq!(node.index_allocator.count(), 0);
    assert!(node.pending_outbound.is_empty());
}

#[test]
fn pending_outbound_handshakes_own_msg2_index_matching_and_cleanup() {
    let original_transport = TransportId::new(1);
    let reply_transport = TransportId::new(2);
    let ambiguous_transport = TransportId::new(3);
    let link_id = LinkId::new(11);
    let ambiguous_link_id = LinkId::new(12);
    let exact_link_id = LinkId::new(13);
    let receiver_idx = 42;

    let mut pending = PendingOutboundHandshakes::default();
    pending.insert((original_transport, receiver_idx), link_id);

    assert_eq!(
        pending.match_msg2(reply_transport, receiver_idx),
        Some(((original_transport, receiver_idx), link_id)),
        "a unique sender index must survive a reply that arrives on an equivalent transport"
    );

    pending.insert((ambiguous_transport, receiver_idx), ambiguous_link_id);
    assert_eq!(
        pending.match_msg2(reply_transport, receiver_idx),
        None,
        "cross-transport fallback must refuse ambiguous sender indexes"
    );

    pending.insert((reply_transport, receiver_idx), exact_link_id);
    assert_eq!(
        pending.match_msg2(reply_transport, receiver_idx),
        Some(((reply_transport, receiver_idx), exact_link_id)),
        "exact transport/index match must win even when other transports share the index"
    );

    pending.remove(&(reply_transport, receiver_idx));
    assert!(pending.contains_key(&(original_transport, receiver_idx)));
    assert!(pending.contains_key(&(ambiguous_transport, receiver_idx)));
    pending.remove(&(original_transport, receiver_idx));
    pending.remove(&(ambiguous_transport, receiver_idx));
    assert!(pending.is_empty());
}

#[test]
fn test_node_active_peer_registry_tracking() {
    let mut node = make_node();
    let transport_id = TransportId::new(1);
    let node_addr = make_node_addr(42);

    // Allocate an index
    let index = node.index_allocator.allocate().unwrap();

    // Track in active peer registry session-index dispatch
    node.peers
        .insert_session_index((transport_id, index.as_u32()), node_addr);

    // Verify lookup
    let found = node
        .peers
        .get_session_index(&(transport_id, index.as_u32()));
    assert_eq!(found, Some(&node_addr));

    // Clean up
    node.peers
        .remove_session_index(&(transport_id, index.as_u32()));
    let _ = node.index_allocator.free(index);

    assert!(node.peers.session_index_is_empty());
}

#[test]
fn session_index_registry_owns_lookup_replace_remove_and_peer_membership() {
    let transport_id = TransportId::new(1);
    let current_key = (transport_id, 10);
    let pending_key = (transport_id, 11);
    let peer_addr = make_node_addr(42);
    let stale_peer_addr = make_node_addr(43);

    let mut registry = SessionIndexRegistry::default();

    assert_eq!(registry.insert(current_key, peer_addr), None);
    assert_eq!(registry.insert(pending_key, peer_addr), None);
    assert_eq!(registry.lookup(current_key), Some(peer_addr));
    assert!(registry.peer_has_any_index(&peer_addr));

    assert_eq!(registry.remove(&current_key), Some(peer_addr));
    assert!(
        registry.peer_has_any_index(&peer_addr),
        "removing the old index during rekey drain must see the peer's new index"
    );

    assert_eq!(
        registry.insert(pending_key, stale_peer_addr),
        Some(peer_addr),
        "a repaired session index must report the stale previous owner"
    );
    assert_eq!(registry.lookup(pending_key), Some(stale_peer_addr));
    assert!(!registry.peer_has_any_index(&peer_addr));

    assert_eq!(registry.remove(&pending_key), Some(stale_peer_addr));
    assert!(!registry.peer_has_any_index(&stale_peer_addr));
    assert!(registry.is_empty());
}

#[test]
fn active_peer_registry_owns_storage_session_index_and_stale_safe_cleanup() {
    let transport_id = TransportId::new(1);
    let current_key = (transport_id, 10);
    let pending_key = (transport_id, 11);

    let peer_full = Identity::generate();
    let peer_identity = PeerIdentity::from_pubkey_full(peer_full.pubkey_full());
    let peer_addr = *peer_identity.node_addr();

    let stale_peer_full = Identity::generate();
    let stale_peer_identity = PeerIdentity::from_pubkey_full(stale_peer_full.pubkey_full());
    let stale_peer_addr = *stale_peer_identity.node_addr();

    let mut registry = ActivePeerRegistry::default();
    assert!(
        registry
            .insert(
                peer_addr,
                ActivePeer::new(peer_identity, LinkId::new(10), 1_000),
            )
            .is_none()
    );
    assert!(registry.contains_key(&peer_addr));

    assert_eq!(registry.insert_session_index(current_key, peer_addr), None);
    assert_eq!(registry.insert_session_index(pending_key, peer_addr), None);
    assert_eq!(registry.lookup_session_index(current_key), Some(peer_addr));
    assert!(registry.peer_has_any_session_index(&peer_addr));

    assert_eq!(registry.remove_session_index(&current_key), Some(peer_addr));
    assert!(
        registry.peer_has_any_session_index(&peer_addr),
        "removing an old index during rekey drain must see the peer's new index"
    );

    assert_eq!(
        registry.insert_session_index(pending_key, stale_peer_addr),
        Some(peer_addr),
        "a repaired session index must report the stale previous owner"
    );
    assert_eq!(
        registry.lookup_session_index(pending_key),
        Some(stale_peer_addr)
    );
    assert!(!registry.peer_has_any_session_index(&peer_addr));

    let removed = registry
        .remove(&peer_addr)
        .expect("peer storage should live in the same owner");
    assert_eq!(removed.node_addr(), &peer_addr);
    assert!(!registry.contains_key(&peer_addr));

    assert_eq!(
        registry.remove_session_index(&pending_key),
        Some(stale_peer_addr)
    );
    assert!(!registry.peer_has_any_session_index(&stale_peer_addr));
    assert!(registry.session_index_is_empty());
}

#[test]
fn peer_lifecycle_registry_owns_session_index_removal_and_remaining_owner_state() {
    let transport_id = TransportId::new(1);
    let current_key = (transport_id, 10);
    let pending_key = (transport_id, 11);

    let peer_full = Identity::generate();
    let peer_identity = PeerIdentity::from_pubkey_full(peer_full.pubkey_full());
    let peer_addr = *peer_identity.node_addr();

    let stale_peer_full = Identity::generate();
    let stale_peer_identity = PeerIdentity::from_pubkey_full(stale_peer_full.pubkey_full());
    let stale_peer_addr = *stale_peer_identity.node_addr();

    let mut registry = PeerLifecycleRegistry::default();
    assert!(
        registry
            .insert(
                peer_addr,
                ActivePeer::new(peer_identity, LinkId::new(10), 1_000),
            )
            .is_none()
    );
    assert_eq!(registry.insert_session_index(current_key, peer_addr), None);
    assert_eq!(registry.insert_session_index(pending_key, peer_addr), None);

    let removed_current = registry
        .remove_session_index_with_owner_state(&current_key)
        .expect("old index should be owned by the active peer");
    assert_eq!(removed_current.owner, peer_addr);
    assert!(
        removed_current.owner_has_remaining_index,
        "removing the old index during rekey drain must atomically see the new index"
    );

    assert_eq!(
        registry.insert_session_index(pending_key, stale_peer_addr),
        Some(peer_addr),
        "repairing a stale owner should still report the replaced peer"
    );

    let removed_pending = registry
        .remove_session_index_with_owner_state(&pending_key)
        .expect("pending index should be owned by the stale peer after replacement");
    assert_eq!(removed_pending.owner, stale_peer_addr);
    assert!(
        !removed_pending.owner_has_remaining_index,
        "last-index removal should atomically report no remaining peer index"
    );
    assert!(registry.session_index_is_empty());
}

#[test]
fn peer_lifecycle_registry_owns_active_peer_insert_and_current_session_index() {
    let node = make_node();
    let peer_full = Identity::generate();
    let peer_identity = PeerIdentity::from_pubkey_full(peer_full.pubkey_full());
    let peer_addr = *peer_identity.node_addr();
    let stale_peer_full = Identity::generate();
    let stale_peer_identity = PeerIdentity::from_pubkey_full(stale_peer_full.pubkey_full());
    let stale_peer_addr = *stale_peer_identity.node_addr();
    let transport_id = TransportId::new(1);
    let link_id = LinkId::new(10);
    let remote_addr = TransportAddr::from_string("insert-peer");
    let current_our_index = SessionIndex::new(10);
    let their_index = SessionIndex::new(20);
    let current_key = (transport_id, current_our_index.as_u32());

    let mut registry = PeerLifecycleRegistry::default();
    let active_peer = make_active_test_peer(
        &node,
        &peer_full,
        peer_identity,
        transport_id,
        link_id,
        remote_addr,
        current_our_index,
        their_index,
    );

    assert_eq!(
        registry.insert_session_index(current_key, stale_peer_addr),
        None
    );
    let inserted = registry.insert_with_current_session_index(peer_addr, active_peer);

    assert!(
        inserted.previous_peer.is_none(),
        "first insert should not replace active peer storage"
    );
    assert_eq!(
        inserted.current_session_index,
        Some(RegisteredPeerSessionIndex {
            session_index: PeerSessionIndex {
                kind: PeerSessionIndexKind::Current,
                key: current_key,
                index: current_our_index,
            },
            previous_owner: Some(stale_peer_addr),
        }),
        "peer lifecycle insertion must own current receiver-index registration and stale-owner repair"
    );
    assert!(registry.contains_key(&peer_addr));
    assert_eq!(registry.lookup_session_index(current_key), Some(peer_addr));
}

#[test]
fn peer_lifecycle_registry_owns_current_session_index_repair() {
    let node = make_node();
    let peer_full = Identity::generate();
    let peer_identity = PeerIdentity::from_pubkey_full(peer_full.pubkey_full());
    let peer_addr = *peer_identity.node_addr();
    let stale_peer_full = Identity::generate();
    let stale_peer_identity = PeerIdentity::from_pubkey_full(stale_peer_full.pubkey_full());
    let stale_peer_addr = *stale_peer_identity.node_addr();

    let transport_id = TransportId::new(1);
    let link_id = LinkId::new(10);
    let remote_addr = TransportAddr::from_string("current-index-repair-peer");
    let current_our_index = SessionIndex::new(10);
    let their_index = SessionIndex::new(20);
    let current_key = (transport_id, current_our_index.as_u32());
    let current_session_index = PeerSessionIndex {
        kind: PeerSessionIndexKind::Current,
        key: current_key,
        index: current_our_index,
    };

    let mut registry = PeerLifecycleRegistry::default();
    let active_peer = make_active_test_peer(
        &node,
        &peer_full,
        peer_identity,
        transport_id,
        link_id,
        remote_addr,
        current_our_index,
        their_index,
    );
    assert!(registry.insert(peer_addr, active_peer).is_none());

    let missing_repair = registry.ensure_current_session_index_registered(&peer_addr);
    assert_eq!(
        missing_repair,
        CurrentSessionIndexRegistration::Repaired(RegisteredPeerSessionIndex {
            session_index: current_session_index,
            previous_owner: None,
        }),
        "missing current receiver-index repair should be a lifecycle-owner operation"
    );
    assert_eq!(registry.lookup_session_index(current_key), Some(peer_addr));

    let already_registered = registry.ensure_current_session_index_registered(&peer_addr);
    assert_eq!(
        already_registered,
        CurrentSessionIndexRegistration::AlreadyRegistered(current_session_index),
        "already-correct current receiver-index state should not be repaired again"
    );

    assert_eq!(
        registry.insert_session_index(current_key, stale_peer_addr),
        Some(peer_addr)
    );
    let stale_owner_repair = registry.ensure_current_session_index_registered(&peer_addr);
    assert_eq!(
        stale_owner_repair,
        CurrentSessionIndexRegistration::Repaired(RegisteredPeerSessionIndex {
            session_index: current_session_index,
            previous_owner: Some(stale_peer_addr),
        }),
        "stale current receiver-index owner repair should stay with the lifecycle owner"
    );
    assert_eq!(registry.lookup_session_index(current_key), Some(peer_addr));

    assert_eq!(
        registry.ensure_current_session_index_registered(&make_node_addr(99)),
        CurrentSessionIndexRegistration::MissingActivePeer
    );

    let no_transport_full = Identity::generate();
    let no_transport_identity = PeerIdentity::from_pubkey_full(no_transport_full.pubkey_full());
    let no_transport_addr = *no_transport_identity.node_addr();
    assert!(
        registry
            .insert(
                no_transport_addr,
                ActivePeer::new(no_transport_identity, LinkId::new(77), 3_000),
            )
            .is_none()
    );
    assert_eq!(
        registry.ensure_current_session_index_registered(&no_transport_addr),
        CurrentSessionIndexRegistration::MissingTransportId
    );

    registry
        .get_mut(&no_transport_addr)
        .expect("no-transport peer should exist")
        .set_current_addr(
            TransportId::new(77),
            &TransportAddr::from_string("current-index-repair-no-index"),
        );
    assert_eq!(
        registry.ensure_current_session_index_registered(&no_transport_addr),
        CurrentSessionIndexRegistration::MissingLocalIndex
    );
}

#[test]
fn peer_lifecycle_registry_owns_current_session_replacement_and_index_handoff() {
    let node = make_node();
    let peer_full = Identity::generate();
    let peer_identity = PeerIdentity::from_pubkey_full(peer_full.pubkey_full());
    let peer_addr = *peer_identity.node_addr();
    let stale_peer_full = Identity::generate();
    let stale_peer_identity = PeerIdentity::from_pubkey_full(stale_peer_full.pubkey_full());
    let stale_peer_addr = *stale_peer_identity.node_addr();

    let old_transport_id = TransportId::new(1);
    let new_transport_id = TransportId::new(2);
    let old_link_id = LinkId::new(10);
    let new_link_id = LinkId::new(20);
    let old_addr = TransportAddr::from_string("old-session-path");
    let new_addr = TransportAddr::from_string("new-session-path");
    let old_our_index = SessionIndex::new(10);
    let old_their_index = SessionIndex::new(20);
    let new_our_index = SessionIndex::new(11);
    let new_their_index = SessionIndex::new(21);
    let old_key = (old_transport_id, old_our_index.as_u32());
    let new_key = (new_transport_id, new_our_index.as_u32());

    let mut registry = PeerLifecycleRegistry::default();
    let active_peer = make_active_test_peer(
        &node,
        &peer_full,
        peer_identity,
        old_transport_id,
        old_link_id,
        old_addr,
        old_our_index,
        old_their_index,
    );
    registry.insert_with_current_session_index(peer_addr, active_peer);
    assert_eq!(registry.lookup_session_index(old_key), Some(peer_addr));
    assert_eq!(
        registry.insert_session_index(new_key, stale_peer_addr),
        None
    );
    registry
        .get_mut(&peer_addr)
        .expect("active peer should exist")
        .increment_replay_suppressed();

    let new_session = make_test_fmp_session(&node.identity, &peer_full, [0x03; 8], [0x04; 8]);
    let replaced = registry
        .replace_current_session_and_path(
            &peer_addr,
            new_session,
            new_our_index,
            new_their_index,
            new_link_id,
            new_transport_id,
            &new_addr,
            Some([0x04; 8]),
            2_000,
        )
        .expect("active peer replacement should be owned by the lifecycle registry");

    assert_eq!(replaced.old_link_id, old_link_id);
    assert_eq!(replaced.replay_suppressed_count, 1);
    assert_eq!(
        replaced.old_session_index,
        Some(PeerSessionIndex {
            kind: PeerSessionIndexKind::Current,
            key: old_key,
            index: old_our_index,
        }),
        "replacement should return the old current index for Node-owned teardown"
    );
    assert_eq!(
        replaced.new_session_index,
        RegisteredPeerSessionIndex {
            session_index: PeerSessionIndex {
                kind: PeerSessionIndexKind::Current,
                key: new_key,
                index: new_our_index,
            },
            previous_owner: Some(stale_peer_addr),
        },
        "replacement should install the new current receiver index and report stale-owner repair"
    );
    assert_eq!(registry.lookup_session_index(old_key), Some(peer_addr));
    assert_eq!(registry.lookup_session_index(new_key), Some(peer_addr));

    let removed_old = registry
        .remove_session_index_with_owner_state(&old_key)
        .expect("old key should still be present until Node performs teardown");
    assert_eq!(removed_old.owner, peer_addr);
    assert!(
        removed_old.owner_has_remaining_index,
        "new current index must be visible before old-index teardown runs"
    );

    let peer = registry
        .get(&peer_addr)
        .expect("replacement must keep active peer storage");
    assert_eq!(peer.link_id(), new_link_id);
    assert_eq!(peer.transport_id(), Some(new_transport_id));
    assert_eq!(peer.current_addr(), Some(&new_addr));
    assert_eq!(peer.our_index(), Some(new_our_index));
    assert_eq!(peer.their_index(), Some(new_their_index));
    assert_eq!(peer.remote_epoch(), Some([0x04; 8]));
    assert_eq!(peer.last_seen(), 2_000);
}

#[test]
fn peer_lifecycle_registry_owns_pending_rekey_session_and_index_registration() {
    let node = make_node();
    let peer_full = Identity::generate();
    let peer_identity = PeerIdentity::from_pubkey_full(peer_full.pubkey_full());
    let peer_addr = *peer_identity.node_addr();
    let stale_peer_full = Identity::generate();
    let stale_peer_identity = PeerIdentity::from_pubkey_full(stale_peer_full.pubkey_full());
    let stale_peer_addr = *stale_peer_identity.node_addr();

    let transport_id = TransportId::new(1);
    let link_id = LinkId::new(10);
    let current_addr = TransportAddr::from_string("pending-rekey-path");
    let current_our_index = SessionIndex::new(10);
    let current_their_index = SessionIndex::new(20);
    let pending_our_index = SessionIndex::new(11);
    let pending_their_index = SessionIndex::new(21);
    let current_key = (transport_id, current_our_index.as_u32());
    let pending_key = (transport_id, pending_our_index.as_u32());

    let mut registry = PeerLifecycleRegistry::default();
    let active_peer = make_active_test_peer(
        &node,
        &peer_full,
        peer_identity,
        transport_id,
        link_id,
        current_addr,
        current_our_index,
        current_their_index,
    );
    registry.insert_with_current_session_index(peer_addr, active_peer);
    assert_eq!(registry.lookup_session_index(current_key), Some(peer_addr));
    assert_eq!(
        registry.insert_session_index(pending_key, stale_peer_addr),
        None
    );

    let pending_session = make_test_fmp_session(&node.identity, &peer_full, [0x05; 8], [0x06; 8]);
    let registered = registry
        .install_pending_rekey_session_and_index(
            &peer_addr,
            pending_session,
            pending_our_index,
            pending_their_index,
            false,
            None,
        )
        .expect("pending rekey session should be owned by the lifecycle registry");

    assert_eq!(
        registered,
        RegisteredPeerSessionIndex {
            session_index: PeerSessionIndex {
                kind: PeerSessionIndexKind::Pending,
                key: pending_key,
                index: pending_our_index,
            },
            previous_owner: Some(stale_peer_addr),
        },
        "installing a pending rekey session must also register its receiver index and report stale-owner repair"
    );
    assert_eq!(registry.lookup_session_index(current_key), Some(peer_addr));
    assert_eq!(registry.lookup_session_index(pending_key), Some(peer_addr));

    let peer = registry
        .get(&peer_addr)
        .expect("pending rekey install must keep active peer storage");
    assert_eq!(peer.pending_our_index(), Some(pending_our_index));
    assert_eq!(peer.pending_their_index(), Some(pending_their_index));
    assert!(peer.pending_new_session().is_some());
    assert!(!peer.pending_rekey_initiator());
    assert!(
        !peer.rekey_in_progress(),
        "completed pending rekey install should clear in-progress handshake state"
    );
}

#[test]
fn peer_lifecycle_registry_owns_authenticated_fmp_receive_path_bookkeeping() {
    let node = make_node();
    let peer_full = Identity::generate();
    let peer_identity = PeerIdentity::from_pubkey_full(peer_full.pubkey_full());
    let peer_addr = *peer_identity.node_addr();

    let old_transport_id = TransportId::new(1);
    let new_transport_id = TransportId::new(2);
    let link_id = LinkId::new(10);
    let old_addr = TransportAddr::from_string("authenticated-recv-old-path");
    let new_addr = TransportAddr::from_string("authenticated-recv-new-path");
    let ignored_addr = TransportAddr::from_string("authenticated-recv-ignored-path");
    let current_our_index = SessionIndex::new(10);
    let current_their_index = SessionIndex::new(20);

    let mut registry = PeerLifecycleRegistry::default();
    let mut active_peer = make_active_test_peer(
        &node,
        &peer_full,
        peer_identity,
        old_transport_id,
        link_id,
        old_addr,
        current_our_index,
        current_their_index,
    );
    active_peer.increment_decrypt_failures();
    active_peer.mark_stale();
    registry.insert_with_current_session_index(peer_addr, active_peer);

    let now = std::time::Instant::now();
    let update = registry
        .record_authenticated_fmp_receive(
            &peer_addr,
            new_transport_id,
            &new_addr,
            2_000,
            128,
            7,
            1_234,
            true,
            false,
            now,
            true,
            true,
        )
        .expect("authenticated receive bookkeeping should find active peer");

    assert!(
        update.address_changed,
        "path update should report address drift for owner bookkeeping"
    );
    assert!(update.path_bookkeeping_recorded);

    let peer = registry
        .get(&peer_addr)
        .expect("authenticated receive must keep active peer storage");
    assert_eq!(peer.consecutive_decrypt_failures(), 0);
    assert_eq!(peer.transport_id(), Some(new_transport_id));
    assert_eq!(peer.current_addr(), Some(&new_addr));
    assert_eq!(peer.last_seen(), 2_000);
    assert_eq!(peer.link_stats().packets_recv, 1);
    assert_eq!(peer.link_stats().bytes_recv, 128);
    assert_eq!(peer.link_stats().last_recv_ms, 2_000);
    registry
        .get_mut(&peer_addr)
        .expect("peer should still exist")
        .increment_decrypt_failures();
    let skipped = registry
        .record_authenticated_fmp_receive(
            &peer_addr,
            new_transport_id,
            &ignored_addr,
            3_000,
            64,
            8,
            1_999,
            false,
            true,
            now,
            false,
            false,
        )
        .expect("disallowed path bookkeeping should still reset decrypt failures");

    assert!(!skipped.address_changed);
    assert!(!skipped.path_bookkeeping_recorded);
    let peer = registry
        .get(&peer_addr)
        .expect("skipped receive must keep active peer storage");
    assert_eq!(peer.consecutive_decrypt_failures(), 0);
    assert_eq!(peer.current_addr(), Some(&new_addr));
    assert_eq!(peer.last_seen(), 2_000);
    assert_eq!(peer.link_stats().packets_recv, 1);
    assert_eq!(peer.link_stats().bytes_recv, 128);
    assert_eq!(peer.link_stats().last_recv_ms, 2_000);

    registry
        .get_mut(&peer_addr)
        .expect("peer should still exist")
        .increment_decrypt_failures();
    let liveness_only = registry
        .record_authenticated_fmp_receive(
            &peer_addr,
            new_transport_id,
            &ignored_addr,
            4_000,
            64,
            9,
            2_999,
            false,
            true,
            now,
            true,
            false,
        )
        .expect("same-peer authenticated receive should find active peer");

    assert!(!liveness_only.address_changed);
    assert!(!liveness_only.path_bookkeeping_recorded);
    assert!(liveness_only.liveness_bookkeeping_recorded);
    let peer = registry
        .get(&peer_addr)
        .expect("liveness-only receive must keep active peer storage");
    assert_eq!(peer.consecutive_decrypt_failures(), 0);
    assert_eq!(peer.current_addr(), Some(&new_addr));
    assert_eq!(peer.last_seen(), 4_000);
    assert_eq!(peer.link_stats().packets_recv, 2);
    assert_eq!(peer.link_stats().bytes_recv, 192);
    assert_eq!(peer.link_stats().last_recv_ms, 4_000);
}

#[test]
fn peer_lifecycle_registry_owns_fmp_send_link_stats_bookkeeping() {
    let node = make_node();
    let peer_full = Identity::generate();
    let peer_identity = PeerIdentity::from_pubkey_full(peer_full.pubkey_full());
    let peer_addr = *peer_identity.node_addr();
    let transport_id = TransportId::new(17);
    let link_id = LinkId::new(18);
    let remote_addr = TransportAddr::from_string("peer-runtime-batch-bookkeeping");
    let sender = make_test_fmp_session(&node.identity, &peer_full, [0x05; 8], [0x06; 8]);

    let mut registry = PeerLifecycleRegistry::default();
    let active_peer = ActivePeer::with_session(
        peer_identity,
        link_id,
        1_000,
        sender,
        SessionIndex::new(19),
        SessionIndex::new(20),
        transport_id,
        remote_addr,
        crate::transport::LinkStats::new(),
        true,
        &node.config.node.mmp,
        Some([0x06; 8]),
    );
    registry.insert_with_current_session_index(peer_addr, active_peer);

    assert!(
        registry.record_fmp_send_bookkeeping(&peer_addr, 7, 2_000, 64),
        "FMP send bookkeeping should find active peer"
    );

    let peer = registry
        .get(&peer_addr)
        .expect("FMP bookkeeping must keep peer storage");
    assert_eq!(peer.link_stats().packets_sent, 1);
    assert_eq!(peer.link_stats().bytes_sent, 64);

    assert!(
        !registry.record_fmp_send_bookkeeping(&make_node_addr(99), 9, 2_200, 256),
        "missing peers should not record FMP send bookkeeping"
    );
}
