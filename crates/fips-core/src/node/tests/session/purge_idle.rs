use super::*;

#[test]
fn test_purge_idle_sessions_removes_expired() {
    let mut node = make_node();
    let remote = Identity::generate();
    let remote_addr = *remote.node_addr();

    let session = make_noise_session(node.identity(), &remote);
    let entry = crate::node::session::SessionEntry::new(
        remote_addr,
        remote.pubkey_full(),
        EndToEndState::Established(session),
        1000, // created at t=1000ms
        true,
    );

    node.sessions.insert(remote_addr, entry);
    assert_eq!(node.session_count(), 1);
    assert!(node.get_session(&remote_addr).unwrap().is_established());

    // Purge at t=92s — should exceed default 90s idle timeout
    let now_ms = 1000 + 92_000;
    node.purge_idle_sessions(now_ms);

    assert_eq!(node.session_count(), 0, "Idle session should be purged");
}

#[test]
fn test_purge_idle_sessions_keeps_active() {
    let mut node = make_node();
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

    // Touch at t=80s — recent activity
    entry.touch(81_000);

    node.sessions.insert(remote_addr, entry);

    // Purge at t=92s — only 11s since last activity, well within 90s timeout
    let now_ms = 92_000;
    node.purge_idle_sessions(now_ms);

    assert_eq!(
        node.session_count(),
        1,
        "Active session should survive purge"
    );
}

#[test]
fn test_purge_idle_sessions_ignores_initiating() {
    use crate::noise::HandshakeState;

    let mut node = make_node();
    let remote = Identity::generate();
    let remote_addr = *remote.node_addr();

    let handshake = HandshakeState::new_initiator(node.identity().keypair(), remote.pubkey_full());
    let entry = crate::node::session::SessionEntry::new(
        remote_addr,
        remote.pubkey_full(),
        EndToEndState::Initiating(handshake),
        1000,
        true,
    );

    node.sessions.insert(remote_addr, entry);

    // Purge well past the idle timeout — Initiating sessions should not be touched
    let now_ms = 1000 + 200_000;
    node.purge_idle_sessions(now_ms);

    assert_eq!(
        node.session_count(),
        1,
        "Initiating session should not be purged by idle timeout"
    );
}

#[test]
fn test_purge_idle_sessions_cleans_pending_packets() {
    let mut node = make_node();
    let remote = Identity::generate();
    let remote_addr = *remote.node_addr();

    let session = make_noise_session(node.identity(), &remote);
    let entry = crate::node::session::SessionEntry::new(
        remote_addr,
        remote.pubkey_full(),
        EndToEndState::Established(session),
        1000,
        true,
    );

    node.sessions.insert(remote_addr, entry);

    // Insert some pending packets for this destination
    node.pending_session_traffic.push_tun_packet(
        remote_addr,
        vec![1, 2, 3],
        usize::MAX,
        usize::MAX,
    );
    assert!(
        node.pending_session_traffic
            .tun_packets_for(&remote_addr)
            .is_some()
    );

    // Purge after idle timeout
    let now_ms = 1000 + 92_000;
    node.purge_idle_sessions(now_ms);

    assert_eq!(node.session_count(), 0);
    assert!(
        node.pending_session_traffic
            .tun_packets_for(&remote_addr)
            .is_none(),
        "Pending packets should be cleaned up with idle session"
    );
}

#[test]
fn test_purge_idle_sessions_disabled_when_zero() {
    let mut node = make_node();
    node.config.node.session.idle_timeout_secs = 0;

    let remote = Identity::generate();
    let remote_addr = *remote.node_addr();

    let session = make_noise_session(node.identity(), &remote);
    let entry = crate::node::session::SessionEntry::new(
        remote_addr,
        remote.pubkey_full(),
        EndToEndState::Established(session),
        1000,
        true,
    );

    node.sessions.insert(remote_addr, entry);

    // Even way past any timeout, sessions should survive when disabled
    let now_ms = 1000 + 1_000_000;
    node.purge_idle_sessions(now_ms);

    assert_eq!(
        node.session_count(),
        1,
        "Sessions should not be purged when idle timeout is disabled"
    );
}

#[test]
fn test_purge_idle_sessions_mmp_activity_does_not_prevent_purge() {
    let mut node = make_node();
    let remote = Identity::generate();
    let remote_addr = *remote.node_addr();

    let session = make_noise_session(node.identity(), &remote);
    let entry = crate::node::session::SessionEntry::new(
        remote_addr,
        remote.pubkey_full(),
        EndToEndState::Established(session),
        1000, // created at t=1s
        true,
    );

    // Do NOT call entry.touch() — simulates a session where only MMP
    // reports have flowed (MMP no longer calls touch). last_activity
    // remains at creation time (1000ms).
    node.sessions.insert(remote_addr, entry);

    // Purge at t=92s — 91s since creation, exceeds 90s idle timeout.
    // Even though MMP reports would have been flowing, they no longer
    // reset the idle timer.
    let now_ms = 92_000;
    node.purge_idle_sessions(now_ms);

    assert_eq!(
        node.session_count(),
        0,
        "Session with MMP-only activity should be purged"
    );
}

#[test]
fn test_purge_idle_sessions_removes_outbound_only_stale_session() {
    let mut node = make_node();
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

    // Simulate periodic outbound endpoint/application data keeping the old
    // idle timer fresh while no authenticated FSP frame comes back.
    entry.record_sent(128);
    entry.touch(91_000);

    node.sessions.insert(remote_addr, entry);

    let now_ms = 92_000;
    node.purge_idle_sessions(now_ms);

    assert_eq!(
        node.session_count(),
        0,
        "Outbound-only stale session should be purged so sends can re-handshake"
    );
}

#[test]
fn test_purge_idle_sessions_keeps_outbound_session_with_recent_inbound_frame() {
    let mut node = make_node();
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

    entry.record_sent(128);
    entry.touch(91_000);
    entry.touch_inbound_frame(91_500);

    node.sessions.insert(remote_addr, entry);

    let now_ms = 92_000;
    node.purge_idle_sessions(now_ms);

    assert_eq!(
        node.session_count(),
        1,
        "Recent authenticated inbound FSP traffic should keep the session alive"
    );
}

// ============================================================================
// Unit tests: COORDS_PRESENT warmup counter
// ============================================================================
