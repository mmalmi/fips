use super::*;

#[test]
fn test_coords_warmup_counter_default_zero_on_new() {
    use crate::noise::HandshakeState;

    let identity_a = Identity::generate();
    let identity_b = Identity::generate();

    let handshake = HandshakeState::new_initiator(identity_a.keypair(), identity_b.pubkey_full());

    let entry = crate::node::session::SessionEntry::new(
        *identity_b.node_addr(),
        identity_b.pubkey_full(),
        EndToEndState::Initiating(handshake),
        1000,
        true,
    );

    assert_eq!(
        entry.coords_warmup_remaining(),
        0,
        "Counter should be 0 for non-Established sessions"
    );
}

#[test]
fn test_coords_warmup_counter_set_and_get() {
    let node = make_node();
    let remote = Identity::generate();
    let remote_addr = *remote.node_addr();

    let session = make_noise_session(node.identity(), &remote);
    let mut entry = crate::node::session::SessionEntry::new(
        remote_addr,
        remote.pubkey_full(),
        EndToEndState::Established(session),
        1000,
        true,
    );

    assert_eq!(entry.coords_warmup_remaining(), 0);

    entry.set_coords_warmup_remaining(5);
    assert_eq!(entry.coords_warmup_remaining(), 5);

    entry.set_coords_warmup_remaining(0);
    assert_eq!(entry.coords_warmup_remaining(), 0);
}

#[test]
fn test_coords_warmup_counter_decrement() {
    let node = make_node();
    let remote = Identity::generate();
    let remote_addr = *remote.node_addr();

    let session = make_noise_session(node.identity(), &remote);
    let mut entry = crate::node::session::SessionEntry::new(
        remote_addr,
        remote.pubkey_full(),
        EndToEndState::Established(session),
        1000,
        true,
    );

    entry.set_coords_warmup_remaining(3);

    // Simulate the decrement pattern used in send_session_data
    for expected in (0..3).rev() {
        assert!(entry.coords_warmup_remaining() > 0);
        entry.set_coords_warmup_remaining(entry.coords_warmup_remaining() - 1);
        assert_eq!(entry.coords_warmup_remaining(), expected);
    }

    assert_eq!(
        entry.coords_warmup_remaining(),
        0,
        "Counter should reach 0 after N decrements"
    );
}

#[test]
fn test_coords_warmup_config_default() {
    let config = crate::config::Config::new();
    assert_eq!(
        config.node.session.coords_warmup_packets, 5,
        "Default coords_warmup_packets should be 5"
    );
}

// ============================================================================
// Unit tests: Identity cache
// ============================================================================

#[test]
fn identity_cache_owns_prefix_validation_lru_touch_and_lookup_views() {
    let id1 = Identity::generate();
    let id2 = Identity::generate();
    let id3 = Identity::generate();
    let wrong = Identity::generate();
    let mut cache = IdentityCache::default();

    assert!(cache.register(*id1.node_addr(), id1.pubkey_full(), 1_000, 2));
    assert!(cache.register(*id2.node_addr(), id2.pubkey_full(), 2_000, 2));
    assert_eq!(cache.len(), 2);

    assert!(
        !cache.register(*id1.node_addr(), wrong.pubkey_full(), 3_000, 2),
        "node_addr/pubkey mismatches must not poison the prefix cache"
    );
    assert_eq!(
        cache.pubkey_for_node_addr(id1.node_addr()),
        Some(id1.pubkey_full()),
        "rejected claims must leave the existing identity intact"
    );

    let id1_prefix = IdentityCache::prefix_for(id1.node_addr());
    assert_eq!(
        cache.lookup_by_prefix(&id1_prefix, 4_000),
        Some((*id1.node_addr(), id1.pubkey_full())),
        "lookup must touch the LRU timestamp for the entry it returns"
    );

    assert!(cache.register(*id3.node_addr(), id3.pubkey_full(), 5_000, 2));
    assert_eq!(cache.len(), 2);
    assert!(
        cache.has_prefix_for(id1.node_addr()),
        "touched id1 should survive LRU eviction"
    );
    assert!(
        !cache.has_prefix_for(id2.node_addr()),
        "untouched oldest entry should be evicted"
    );
    assert_eq!(cache.npub_for_node_addr(id3.node_addr()), Some(id3.npub()));
}

#[test]
fn test_identity_cache_lru_eviction() {
    let mut node = make_node();
    node.config.node.cache.identity_size = 2;

    let id1 = Identity::generate();
    let id2 = Identity::generate();
    let id3 = Identity::generate();

    // Insert first two with explicit timestamps to ensure deterministic ordering
    let mut prefix1 = [0u8; 15];
    prefix1.copy_from_slice(&id1.node_addr().as_bytes()[0..15]);
    let (xonly1, _) = id1.pubkey_full().x_only_public_key();
    node.identity_cache.insert_for_test(
        *id1.node_addr(),
        id1.pubkey_full(),
        encode_npub(&xonly1),
        1000,
    );

    let mut prefix2 = [0u8; 15];
    prefix2.copy_from_slice(&id2.node_addr().as_bytes()[0..15]);
    let (xonly2, _) = id2.pubkey_full().x_only_public_key();
    node.identity_cache.insert_for_test(
        *id2.node_addr(),
        id2.pubkey_full(),
        encode_npub(&xonly2),
        2000,
    );

    assert_eq!(node.identity_cache_len(), 2);

    // Adding a third should evict the oldest (id1, timestamp 1000)
    node.register_identity(*id3.node_addr(), id3.pubkey_full());
    assert_eq!(node.identity_cache_len(), 2);

    assert!(
        node.lookup_by_fips_prefix(&prefix1).is_none(),
        "Oldest entry should have been evicted"
    );

    let mut prefix3 = [0u8; 15];
    prefix3.copy_from_slice(&id3.node_addr().as_bytes()[0..15]);
    assert!(
        node.lookup_by_fips_prefix(&prefix3).is_some(),
        "Newest entry should be present"
    );
}

#[test]
fn test_identity_cache_lookup() {
    let mut node = make_node();

    let remote = Identity::generate();
    let remote_addr = *remote.node_addr();

    node.register_identity(remote_addr, remote.pubkey_full());

    let mut prefix = [0u8; 15];
    prefix.copy_from_slice(&remote_addr.as_bytes()[0..15]);

    let result = node.lookup_by_fips_prefix(&prefix);
    assert!(result.is_some(), "Registered identity should be available");

    let (addr, pk) = result.unwrap();
    assert_eq!(addr, remote_addr);
    assert_eq!(pk, remote.pubkey_full());
}

#[test]
fn test_identity_cache_rejects_mismatched_pubkey_claim() {
    let mut node = make_node();
    let claimed = Identity::generate();
    let actual = Identity::generate();

    assert!(
        !node.register_identity(*claimed.node_addr(), actual.pubkey_full()),
        "identity cache must reject node_addr/pubkey pairs that do not derive from each other"
    );

    let mut claimed_prefix = [0u8; 15];
    claimed_prefix.copy_from_slice(&claimed.node_addr().as_bytes()[0..15]);
    assert!(
        node.lookup_by_fips_prefix(&claimed_prefix).is_none(),
        "mismatched identity claim must not be cached under the claimed address"
    );
}

// ============================================================================
// Session-layer handshake resend tests
// ============================================================================
