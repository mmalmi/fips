use super::*;
use crate::Identity;

fn session() -> NoiseSession {
    let local = Identity::generate();
    let remote = Identity::generate();
    let mut outgoing = NoiseHandshakeState::new_initiator(local.keypair(), remote.pubkey_full());
    let mut incoming = NoiseHandshakeState::new_responder(remote.keypair());
    outgoing.set_local_epoch([1; 8]);
    incoming.set_local_epoch([2; 8]);
    incoming
        .read_message_1(&outgoing.write_message_1().unwrap())
        .unwrap();
    outgoing
        .read_message_2(&incoming.write_message_2().unwrap())
        .unwrap();
    outgoing.into_session().unwrap()
}

#[test]
fn pending_wire_origin_preserves_admission_clock_and_resets_on_key_change() {
    let identity = Identity::generate();
    let mut active = ActivePeer::new(
        PeerIdentity::from_pubkey_full(identity.pubkey_full()),
        LinkId::new(1),
        50_000,
    );
    let admission_clock = active.session_start();
    // A clock-only unit fixture; all replacement keys still come from real Noise.
    let earlier_wire_origin = admission_clock - std::time::Duration::from_secs(5);
    active.adopt_pending_fmp_timestamp_origin(earlier_wire_origin);
    assert_eq!(active.session_start(), admission_clock);
    assert_eq!(active.authenticated_at(), 50_000);
    assert_eq!(active.session_established_at, admission_clock);
    assert!(active.session_elapsed_ms() >= 5_000);
    active.replace_session(session(), SessionIndex::new(1), SessionIndex::new(2));
    assert_eq!(active.pending_fmp_timestamp_origin, None);
    active.adopt_pending_fmp_timestamp_origin(earlier_wire_origin);
    active.set_pending_session(session(), SessionIndex::new(3), SessionIndex::new(4), true);
    assert_eq!(active.cutover_to_new_session(), Some(SessionIndex::new(1)));
    assert_eq!(active.pending_fmp_timestamp_origin, None);
    assert_eq!(active.authenticated_at(), 50_000);
}
