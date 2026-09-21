use super::*;
use crate::Identity;
use crate::peer::{ActivePeer, ActivePeerSession};
use crate::transport::{LinkId, TransportAddr, TransportId};
use crate::utils::index::SessionIndex;

fn pair() -> (PeerConnection, PeerConnection) {
    let local = Identity::generate();
    let remote = Identity::generate();
    let mut outgoing = PeerConnection::outbound(
        LinkId::new(1),
        crate::PeerIdentity::from_pubkey_full(remote.pubkey_full()),
        1_000,
    );
    let mut incoming = PeerConnection::inbound(LinkId::new(2), 1_000);
    let msg1 = outgoing
        .start_handshake(local.keypair(), [1; 8], 1_100)
        .unwrap();
    let msg2 = incoming
        .receive_handshake_init(remote.keypair(), [2; 8], &msg1, 1_200)
        .unwrap();
    outgoing.complete_handshake(&msg2, 1_300).unwrap();
    outgoing.set_their_index(SessionIndex::new(29));
    (outgoing, incoming)
}

#[test]
fn ready_heartbeat_retries_keep_wire_nonce_and_unique_mmp_accounting() {
    let (mut outgoing, mut incoming) = pair();
    let counter = outgoing.session().unwrap().current_send_counter();
    let deadline_origin = outgoing.last_activity();
    let wire = outgoing.prepare_ready_heartbeat().unwrap().to_vec();
    assert_eq!(wire.len(), 37);
    assert_eq!(&wire[4..8], &29u32.to_le_bytes());
    assert_eq!(&wire[8..16], &counter.to_le_bytes());
    assert_eq!(
        outgoing.session().unwrap().current_send_counter(),
        counter + 1
    );
    assert_eq!(outgoing.prepare_ready_heartbeat().unwrap(), wire);
    assert_eq!(
        outgoing.session().unwrap().current_send_counter(),
        counter + 1
    );
    assert_eq!(outgoing.last_activity(), deadline_origin);
    assert!(!outgoing.record_ready_heartbeat_sent(wire.len() - 1));
    assert_eq!(outgoing.link_stats().packets_sent, 0);
    assert!(outgoing.record_ready_heartbeat_sent(wire.len()));
    assert!(outgoing.record_ready_heartbeat_sent(wire.len()));
    assert_eq!(outgoing.link_stats().packets_sent, 2);
    assert_eq!(outgoing.link_stats().bytes_sent, 74);

    let mut receiver = incoming.take_session().unwrap();
    let plaintext = receiver
        .decrypt_with_replay_check_and_aad(&wire[16..], counter, &wire[..16])
        .unwrap();
    assert_eq!(plaintext.len(), 5);
    assert_eq!(plaintext[4], LinkMessageType::Heartbeat.to_byte());
    assert!(
        receiver
            .decrypt_with_replay_check_and_aad(&wire[16..], counter, &wire[..16])
            .is_err()
    );

    let (origin, mut sender) = outgoing.take_ready_heartbeat_accounting().unwrap();
    assert!(origin <= Instant::now());
    assert_eq!(sender.cumulative_packets_sent(), 1);
    assert_eq!(sender.cumulative_bytes_sent(), 37);
    let report = sender.build_report(Instant::now()).unwrap();
    assert_eq!(report.interval_start_counter, counter);
    assert_eq!(report.interval_end_counter, counter);
    assert_eq!(
        report.interval_start_timestamp,
        u32::from_le_bytes(plaintext[..4].try_into().unwrap())
    );
    assert!(outgoing.take_ready_heartbeat_accounting().is_none());

    // Moving the actual session into the active owner preserves its nonce authority.
    let mut active = ActivePeer::with_session(
        *outgoing.expected_identity().unwrap(),
        outgoing.link_id(),
        2_000,
        ActivePeerSession {
            session: outgoing.take_session().unwrap(),
            our_index: SessionIndex::new(19),
            their_index: SessionIndex::new(29),
            transport_id: TransportId::new(1),
            current_addr: TransportAddr::from("127.0.0.1:1234"),
            link_stats: outgoing.link_stats().clone(),
            is_initiator: true,
            remote_epoch: Some([2; 8]),
        },
    );
    let liveness_origin = active.session_start();
    active.adopt_pending_fmp_timestamp_origin(origin);
    assert_eq!(active.session_start(), liveness_origin);
    assert_eq!(active.authenticated_at(), 2_000);
    let header = build_fmp_established_header(29, counter + 1, 0, 5);
    let mut next_plaintext = [0u8; 5];
    next_plaintext[..4].copy_from_slice(&active.session_elapsed_ms().to_le_bytes());
    next_plaintext[4] = LinkMessageType::Heartbeat.to_byte();
    let session = active.noise_session_mut().unwrap();
    assert_eq!(session.current_send_counter(), counter + 1);
    let next_wire = session.encrypt_with_aad(&next_plaintext, &header).unwrap();
    assert_eq!(
        receiver
            .decrypt_with_replay_check_and_aad(&next_wire, counter + 1, &header)
            .unwrap(),
        next_plaintext
    );
}

#[test]
fn invalid_ready_heartbeat_does_not_consume_nonce_or_send_budget() {
    let (mut outgoing, mut incoming) = pair();
    let counter = outgoing.session().unwrap().current_send_counter();
    outgoing.their_index = None;
    assert!(outgoing.prepare_ready_heartbeat().is_err());
    assert_eq!(outgoing.session().unwrap().current_send_counter(), counter);
    assert!(outgoing.take_ready_heartbeat_accounting().is_none());
    assert!(!outgoing.record_ready_heartbeat_sent(37));
    assert!(incoming.prepare_ready_heartbeat().is_err());
    assert_eq!(incoming.session().unwrap().current_send_counter(), 0);
    assert!(incoming.take_ready_heartbeat_accounting().is_none());
    let mut unfinished = PeerConnection::outbound(
        LinkId::new(3),
        *outgoing.expected_identity().unwrap(),
        5_000,
    );
    assert!(unfinished.prepare_ready_heartbeat().is_err());
    assert!(!unfinished.record_ready_heartbeat_sent(37));
}

#[test]
fn confirmation_retry_budget_preserves_msg1_and_original_deadline() {
    let (mut outgoing, _) = pair();
    outgoing.set_handshake_msg1(vec![1, 2, 3], 1_500);
    outgoing.record_resend(1_700);
    let started = outgoing.started_at();
    let last_activity = outgoing.last_activity();
    outgoing.start_confirmation_retries(1_800);
    assert_eq!(outgoing.resend_count(), 0);
    assert_eq!(outgoing.next_resend_at_ms(), 1_800);
    assert_eq!(outgoing.handshake_msg1(), Some([1, 2, 3].as_slice()));
    assert_eq!(outgoing.started_at(), started);
    assert_eq!(outgoing.last_activity(), last_activity);
}
