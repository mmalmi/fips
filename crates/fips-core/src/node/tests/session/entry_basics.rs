use super::*;

#[test]
fn test_session_entry_new_initiating() {
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

    assert!(entry.is_initiating());
    assert!(!entry.is_established());
    assert!(!entry.is_awaiting_msg3());
    assert_eq!(entry.created_at(), 1000);
}

#[test]
fn test_session_entry_rekey_jitter_in_range() {
    use crate::node::REKEY_JITTER_SECS;
    use crate::noise::HandshakeState;

    for _ in 0..100 {
        let identity_a = Identity::generate();
        let identity_b = Identity::generate();
        let handshake =
            HandshakeState::new_initiator(identity_a.keypair(), identity_b.pubkey_full());

        let entry = crate::node::session::SessionEntry::new(
            *identity_b.node_addr(),
            identity_b.pubkey_full(),
            EndToEndState::Initiating(handshake),
            1000,
            true,
        );

        let jitter = entry.rekey_jitter_secs();
        assert!(
            (-REKEY_JITTER_SECS..=REKEY_JITTER_SECS).contains(&jitter),
            "jitter {} outside [-{}, +{}]",
            jitter,
            REKEY_JITTER_SECS,
            REKEY_JITTER_SECS
        );
    }
}

#[test]
fn test_session_entry_rekey_jitter_mean_near_zero() {
    use crate::noise::HandshakeState;

    let mut sum = 0i64;
    let n = 200i64;

    for _ in 0..n {
        let identity_a = Identity::generate();
        let identity_b = Identity::generate();
        let handshake =
            HandshakeState::new_initiator(identity_a.keypair(), identity_b.pubkey_full());

        let entry = crate::node::session::SessionEntry::new(
            *identity_b.node_addr(),
            identity_b.pubkey_full(),
            EndToEndState::Initiating(handshake),
            1000,
            true,
        );

        sum += entry.rekey_jitter_secs();
    }

    let mean = sum / n;
    assert!(
        mean.abs() < 5,
        "empirical mean {} not within 5 of 0 over {} samples",
        mean,
        n
    );
}

#[test]
fn test_session_table_operations() {
    use crate::noise::HandshakeState;

    let mut node = make_node();
    let identity_b = Identity::generate();

    let handshake =
        HandshakeState::new_initiator(node.identity().keypair(), identity_b.pubkey_full());

    let dest_addr = *identity_b.node_addr();
    let entry = crate::node::session::SessionEntry::new(
        dest_addr,
        identity_b.pubkey_full(),
        EndToEndState::Initiating(handshake),
        1000,
        true,
    );

    node.sessions.insert(dest_addr, entry);
    assert_eq!(node.session_count(), 1);
    assert!(node.get_session(&dest_addr).is_some());
    assert!(node.get_session(&make_node_addr(0xFF)).is_none());

    let removed = node.remove_session(&dest_addr);
    assert!(removed.is_some());
    assert_eq!(node.session_count(), 0);
}

// ============================================================================
// Integration tests: 2-node direct session establishment
// ============================================================================
