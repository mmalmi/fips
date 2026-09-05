use super::*;
use crate::node::session::{EndToEndState, SessionEntry};
use crate::noise::{HandshakeState as NoiseHandshakeState, NoiseSession};
use crate::peer::{ActivePeer, ActivePeerSession};
use crate::transport::{LinkId, LinkStats, TransportAddr, TransportId};
use crate::utils::index::SessionIndex;
use crate::{Identity, NodeAddr, PeerIdentity};

fn node_addr(byte: u8) -> NodeAddr {
    let mut bytes = [0u8; 16];
    bytes[0] = byte;
    NodeAddr::from_bytes(bytes)
}

fn make_xk_session_pair(
    initiator: &Identity,
    responder: &Identity,
) -> (NoiseSession, NoiseSession) {
    let mut initiator_hs =
        NoiseHandshakeState::new_xk_initiator(initiator.keypair(), responder.pubkey_full());
    let mut responder_hs = NoiseHandshakeState::new_xk_responder(responder.keypair());
    initiator_hs.set_local_epoch([1u8; 8]);
    responder_hs.set_local_epoch([2u8; 8]);

    let msg1 = initiator_hs.write_xk_message_1().unwrap();
    responder_hs.read_xk_message_1(&msg1).unwrap();
    let msg2 = responder_hs.write_xk_message_2().unwrap();
    initiator_hs.read_xk_message_2(&msg2).unwrap();
    let msg3 = initiator_hs.write_xk_message_3().unwrap();
    responder_hs.read_xk_message_3(&msg3).unwrap();

    (
        initiator_hs.into_session().unwrap(),
        responder_hs.into_session().unwrap(),
    )
}

fn make_fmp_session_pair(
    initiator: &Identity,
    responder: &Identity,
) -> (NoiseSession, NoiseSession) {
    let mut initiator_hs =
        NoiseHandshakeState::new_initiator(initiator.keypair(), responder.pubkey_full());
    let mut responder_hs = NoiseHandshakeState::new_responder(responder.keypair());
    initiator_hs.set_local_epoch([1u8; 8]);
    responder_hs.set_local_epoch([2u8; 8]);

    let msg1 = initiator_hs.write_message_1().unwrap();
    responder_hs.read_message_1(&msg1).unwrap();
    let msg2 = responder_hs.write_message_2().unwrap();
    initiator_hs.read_message_2(&msg2).unwrap();

    (
        initiator_hs.into_session().unwrap(),
        responder_hs.into_session().unwrap(),
    )
}

fn established_entry(local: &Identity, peer: &Identity, now_ms: u64) -> SessionEntry {
    let (session, _) = make_xk_session_pair(local, peer);
    let mut entry = SessionEntry::new(
        *peer.node_addr(),
        peer.pubkey_full(),
        EndToEndState::Established(session),
        now_ms,
        true,
    );
    entry.mark_established(now_ms);
    entry
}

fn initiating_entry(local: &Identity, peer: &Identity, now_ms: u64) -> SessionEntry {
    let handshake = NoiseHandshakeState::new_initiator(local.keypair(), peer.pubkey_full());
    SessionEntry::new(
        *peer.node_addr(),
        peer.pubkey_full(),
        EndToEndState::Initiating(handshake),
        now_ms,
        true,
    )
}

fn arm_completed_initiator_rekey(
    entry: &mut SessionEntry,
    local: &Identity,
    peer: &Identity,
    completed_ms: u64,
) {
    entry.set_rekey_state(
        NoiseHandshakeState::new_xk_initiator(local.keypair(), peer.pubkey_full()),
        true,
    );
    let (pending_session, _) = make_xk_session_pair(local, peer);
    entry.set_pending_session(pending_session);
    entry.set_rekey_completed_ms(completed_ms);
}

fn active_fmp_peer(local: &Identity, peer: &Identity, tag: u32) -> ActivePeer {
    let peer_identity = PeerIdentity::from_pubkey_full(peer.pubkey_full());
    let (session, _) = make_fmp_session_pair(local, peer);
    ActivePeer::with_session(
        peer_identity,
        LinkId::new(tag.into()),
        1_000,
        ActivePeerSession {
            session,
            our_index: SessionIndex::new(tag * 10 + 1),
            their_index: SessionIndex::new(tag * 10 + 2),
            transport_id: TransportId::new(tag),
            current_addr: TransportAddr::from_string(&format!("127.0.0.1:{}", 4_000 + tag)),
            link_stats: LinkStats::new(),
            is_initiator: true,
            remote_epoch: Some([2u8; 8]),
        },
    )
}

#[test]
fn fsp_pending_epoch_probe_allows_a_retry_without_waiting_for_the_full_burst() {
    let rate_limit = crate::config::RateLimitConfig::default();
    let resend_budget = (0..rate_limit.handshake_max_resends)
        .map(|resend| {
            (rate_limit.handshake_resend_interval_ms as f64
                * rate_limit.handshake_resend_backoff.powi(resend as i32)) as u64
        })
        .sum::<u64>();

    assert!(
        FSP_PENDING_EPOCH_PROBE_DELAY_MS >= rate_limit.handshake_resend_interval_ms,
        "FSP pending-epoch probing must allow the first msg3 retry"
    );
    assert!(
        FSP_PENDING_EPOCH_PROBE_DELAY_MS < resend_budget,
        "FSP pending-epoch probing must not wait for the full exponential retry budget"
    );
}

fn no_session_fmp_peer(peer: &Identity, tag: u32) -> ActivePeer {
    let peer_identity = PeerIdentity::from_pubkey_full(peer.pubkey_full());
    ActivePeer::new(peer_identity, LinkId::new(tag.into()), 1_000)
}

fn arm_completed_fmp_rekey(
    entry: &mut ActivePeer,
    local: &Identity,
    peer: &Identity,
    tag: u32,
    initiated_by_local: bool,
) {
    let (pending_session, _) = make_fmp_session_pair(local, peer);
    entry.set_pending_session(
        pending_session,
        SessionIndex::new(tag * 10 + 3),
        SessionIndex::new(tag * 10 + 4),
        initiated_by_local,
    );
}

fn arm_in_progress_fmp_rekey(entry: &mut ActivePeer, local: &Identity, peer: &Identity) {
    let handshake = NoiseHandshakeState::new_initiator(local.keypair(), peer.pubkey_full());
    entry.set_rekey_state(handshake, SessionIndex::new(9_001), vec![0xAB; 64], 0);
}

#[test]
fn peer_lifecycle_registry_owns_fmp_rekey_tick_selection() {
    let local = Identity::generate();
    let cutover_peer = Identity::generate();
    let responder_pending_peer = Identity::generate();
    let drain_peer = Identity::generate();
    let timer_peer = Identity::generate();
    let counter_peer = Identity::generate();
    let in_progress_peer = Identity::generate();
    let dampened_peer = Identity::generate();
    let stale_peer = Identity::generate();
    let stale_cutover_peer = Identity::generate();
    let stale_drain_peer = Identity::generate();
    let no_session_peer = Identity::generate();

    let mut cutover = active_fmp_peer(&local, &cutover_peer, 1);
    arm_completed_fmp_rekey(&mut cutover, &local, &cutover_peer, 1, true);

    let mut responder_pending = active_fmp_peer(&local, &responder_pending_peer, 2);
    arm_completed_fmp_rekey(
        &mut responder_pending,
        &local,
        &responder_pending_peer,
        2,
        false,
    );

    let mut drain = active_fmp_peer(&local, &drain_peer, 3);
    arm_completed_fmp_rekey(&mut drain, &local, &drain_peer, 3, true);
    assert!(drain.cutover_to_new_session().is_some());

    let mut timer = active_fmp_peer(&local, &timer_peer, 4);
    // Make only this peer's time threshold due without subtracting a large
    // duration from `Instant::now()`. Fresh Windows runners can have less
    // monotonic uptime than that subtraction and panic before the assertion.
    timer.set_rekey_jitter_secs_for_test(-10_000);

    let mut counter = active_fmp_peer(&local, &counter_peer, 5);
    counter
        .noise_session_mut()
        .unwrap()
        .encrypt(b"tick")
        .unwrap();

    let mut in_progress = active_fmp_peer(&local, &in_progress_peer, 6);
    arm_in_progress_fmp_rekey(&mut in_progress, &local, &in_progress_peer);

    let mut dampened = active_fmp_peer(&local, &dampened_peer, 7);
    dampened.record_peer_rekey();

    let mut stale = active_fmp_peer(&local, &stale_peer, 8);
    stale.mark_stale();

    let mut stale_cutover = active_fmp_peer(&local, &stale_cutover_peer, 9);
    arm_completed_fmp_rekey(&mut stale_cutover, &local, &stale_cutover_peer, 9, true);
    stale_cutover.mark_stale();

    let mut stale_drain = active_fmp_peer(&local, &stale_drain_peer, 10);
    arm_completed_fmp_rekey(&mut stale_drain, &local, &stale_drain_peer, 10, true);
    assert!(stale_drain.cutover_to_new_session().is_some());
    stale_drain.mark_stale();

    let no_session = no_session_fmp_peer(&no_session_peer, 11);

    let mut peers = crate::node::PeerLifecycleRegistry::default();
    peers.insert(*cutover_peer.node_addr(), cutover);
    peers.insert(*responder_pending_peer.node_addr(), responder_pending);
    peers.insert(*drain_peer.node_addr(), drain);
    peers.insert(*timer_peer.node_addr(), timer);
    peers.insert(*counter_peer.node_addr(), counter);
    peers.insert(*in_progress_peer.node_addr(), in_progress);
    peers.insert(*dampened_peer.node_addr(), dampened);
    peers.insert(*stale_peer.node_addr(), stale);
    peers.insert(*stale_cutover_peer.node_addr(), stale_cutover);
    peers.insert(*stale_drain_peer.node_addr(), stale_drain);
    peers.insert(*no_session_peer.node_addr(), no_session);

    let mut plan = peers.plan_fmp_rekey_tick(10_000, 1, Duration::ZERO, 0, REKEY_DAMPENING_SECS);
    plan.cutover.sort();
    plan.drain.sort();
    plan.initiate.sort();

    let mut expected_cutover = vec![*cutover_peer.node_addr(), *stale_cutover_peer.node_addr()];
    expected_cutover.sort();
    assert_eq!(plan.cutover, expected_cutover);
    let mut expected_drain = vec![*drain_peer.node_addr(), *stale_drain_peer.node_addr()];
    expected_drain.sort();
    assert_eq!(plan.drain, expected_drain);
    let mut expected_initiate = vec![*timer_peer.node_addr(), *counter_peer.node_addr()];
    expected_initiate.sort();
    assert_eq!(plan.initiate, expected_initiate);
}

#[test]
fn routine_fmp_rekey_preserves_pending_and_draining_epochs() {
    let local = Identity::generate();
    let remote = Identity::generate();
    for phase in 0..3 {
        let mut peer = active_fmp_peer(&local, &remote, 1);
        arm_completed_fmp_rekey(&mut peer, &local, &remote, 1, phase != 0);
        if phase == 2 {
            peer.cutover_to_new_session().unwrap();
        }
        peer.set_rekey_jitter_secs_for_test(0);
        let mut peers = crate::node::PeerLifecycleRegistry::default();
        peers.insert(*remote.node_addr(), peer);
        // Even an immediately due timer/counter cannot overwrite responder
        // pending state, an initiator awaiting cutover, or an unexpired drain.
        let plan = peers.plan_fmp_rekey_tick(0, 0, Duration::from_secs(60), 60, 0);
        assert_eq!(plan, FmpRekeyTickPlan::default(), "epoch phase {phase}");
    }
}

#[test]
fn unconfirmed_fmp_rekey_expiry_keeps_current_and_previous_receiver_indexes() {
    let local = Identity::generate();
    let remote = Identity::generate();
    let mut node = Node::with_identity(local, crate::Config::new()).unwrap();
    let mut peer = active_fmp_peer(node.identity(), &remote, 1);
    arm_completed_fmp_rekey(&mut peer, node.identity(), &remote, 1, true);
    peer.cutover_to_new_session().unwrap();
    let current_index = peer.our_index().unwrap();
    let previous_index = peer.previous_our_index().unwrap();
    arm_completed_fmp_rekey(&mut peer, node.identity(), &remote, 2, false);
    let pending_index = peer.pending_our_index().unwrap();
    let timeout = Duration::from_secs(node.config.node.rate_limit.handshake_timeout_secs);
    let expires_at = peer.pending_rekey_completed_at_for_test().unwrap() + timeout;
    let transport_id = peer.transport_id().unwrap();
    node.peers
        .insert_with_current_session_index(*remote.node_addr(), peer);
    for index in [previous_index, pending_index] {
        node.peers
            .insert_session_index((transport_id, index.as_u32()), *remote.node_addr());
    }
    assert!(node.sync_dataplane_fmp_owner(remote.node_addr()));

    node.expire_unconfirmed_fmp_rekeys(expires_at);
    let peer = node.get_peer(remote.node_addr()).unwrap();
    assert_eq!(peer.our_index(), Some(current_index));
    assert_eq!(peer.previous_our_index(), Some(previous_index));
    assert!(peer.is_draining());
    assert!(peer.previous_session().is_some());
    assert!(peer.pending_new_session().is_none());
    for index in [previous_index, current_index] {
        assert!(
            node.peers
                .contains_session_index(&(transport_id, index.as_u32()))
        );
    }
    assert!(
        !node
            .peers
            .contains_session_index(&(transport_id, pending_index.as_u32()))
    );
}

#[test]
fn peer_lifecycle_registry_owns_fmp_rekey_tick_cutover_and_drain_mutation() {
    let local = Identity::generate();
    let cutover_peer = Identity::generate();
    let responder_pending_peer = Identity::generate();
    let early_cutover_peer = Identity::generate();
    let drain_peer = Identity::generate();
    let early_drain_peer = Identity::generate();

    let mut cutover = active_fmp_peer(&local, &cutover_peer, 1);
    let cutover_k_bit = cutover.current_k_bit();
    arm_completed_fmp_rekey(&mut cutover, &local, &cutover_peer, 1, true);

    let mut responder_pending = active_fmp_peer(&local, &responder_pending_peer, 2);
    arm_completed_fmp_rekey(
        &mut responder_pending,
        &local,
        &responder_pending_peer,
        2,
        false,
    );

    let mut early_cutover = active_fmp_peer(&local, &early_cutover_peer, 3);
    arm_completed_fmp_rekey(&mut early_cutover, &local, &early_cutover_peer, 3, true);

    let mut drain = active_fmp_peer(&local, &drain_peer, 4);
    let drain_old_index = drain.our_index().expect("active peer should have index");
    arm_completed_fmp_rekey(&mut drain, &local, &drain_peer, 4, true);
    assert!(drain.cutover_to_new_session().is_some());

    let mut early_drain = active_fmp_peer(&local, &early_drain_peer, 5);
    arm_completed_fmp_rekey(&mut early_drain, &local, &early_drain_peer, 5, true);
    assert!(early_drain.cutover_to_new_session().is_some());

    let mut peers = crate::node::PeerLifecycleRegistry::default();
    peers.insert(*cutover_peer.node_addr(), cutover);
    peers.insert(*responder_pending_peer.node_addr(), responder_pending);
    peers.insert(*early_cutover_peer.node_addr(), early_cutover);
    peers.insert(*drain_peer.node_addr(), drain);
    peers.insert(*early_drain_peer.node_addr(), early_drain);

    assert!(peers.cutover_due_fmp_rekey(cutover_peer.node_addr(), Duration::ZERO));
    let cutover = peers
        .get(cutover_peer.node_addr())
        .expect("cutover peer should remain");
    assert!(cutover.pending_new_session().is_none());
    assert!(cutover.is_draining());
    assert_eq!(cutover.current_k_bit(), !cutover_k_bit);

    assert!(!peers.cutover_due_fmp_rekey(responder_pending_peer.node_addr(), Duration::ZERO));
    assert!(
        peers
            .get(responder_pending_peer.node_addr())
            .expect("responder-pending peer should remain")
            .pending_new_session()
            .is_some()
    );

    assert!(!peers.cutover_due_fmp_rekey(early_cutover_peer.node_addr(), Duration::from_secs(60)));
    assert!(
        peers
            .get(early_cutover_peer.node_addr())
            .expect("early-cutover peer should remain")
            .pending_new_session()
            .is_some()
    );

    assert_eq!(
        peers.complete_due_fmp_rekey_drain(drain_peer.node_addr(), 0),
        Some(FmpRekeyDrainCompletion {
            transport_id: Some(TransportId::new(4)),
            old_our_index: drain_old_index,
        })
    );
    assert!(
        !peers
            .get(drain_peer.node_addr())
            .expect("drained peer should remain")
            .is_draining()
    );

    assert_eq!(
        peers.complete_due_fmp_rekey_drain(early_drain_peer.node_addr(), 60),
        None
    );
    assert!(
        peers
            .get(early_drain_peer.node_addr())
            .expect("early-drain peer should remain")
            .is_draining()
    );

    assert_eq!(
        peers.complete_due_fmp_rekey_drain(&node_addr(0x77), 0),
        None
    );
}

#[test]
fn peer_lifecycle_registry_owns_fmp_rekey_initiation_target_snapshot() {
    let local = Identity::generate();
    let ready_peer = Identity::generate();
    let missing_transport_peer = Identity::generate();

    let ready = active_fmp_peer(&local, &ready_peer, 7);
    let missing_transport = no_session_fmp_peer(&missing_transport_peer, 8);

    let mut peers = crate::node::PeerLifecycleRegistry::default();
    peers.insert(*ready_peer.node_addr(), ready);
    peers.insert(*missing_transport_peer.node_addr(), missing_transport);

    assert_eq!(
        peers
            .prepare_fmp_rekey_initiation(ready_peer.node_addr())
            .expect("ready FMP peer should have an initiation target"),
        FmpRekeyInitiation {
            transport_id: TransportId::new(7),
            remote_addr: TransportAddr::from_string("127.0.0.1:4007"),
            link_id: LinkId::new(7),
            peer_pubkey: ready_peer.pubkey_full(),
        }
    );
    assert_eq!(
        peers.prepare_fmp_rekey_initiation(&node_addr(0x77)),
        Err(FmpRekeyInitiationSkip::Peer)
    );
    assert_eq!(
        peers.prepare_fmp_rekey_initiation(missing_transport_peer.node_addr()),
        Err(FmpRekeyInitiationSkip::Transport)
    );
}

#[test]
fn peer_lifecycle_registry_owns_fmp_rekey_initiation_state_install() {
    let local = Identity::generate();
    let peer = Identity::generate();
    let ready = active_fmp_peer(&local, &peer, 9);

    let mut peers = crate::node::PeerLifecycleRegistry::default();
    peers.insert(*peer.node_addr(), ready);

    let handshake = NoiseHandshakeState::new_initiator(local.keypair(), peer.pubkey_full());
    assert!(peers.record_fmp_rekey_initiated(
        peer.node_addr(),
        handshake,
        SessionIndex::new(9_009),
        vec![0xC0, 0xC1, 0xC2],
        4_500,
    ));

    let peer = peers
        .get(peer.node_addr())
        .expect("FMP peer should remain installed");
    assert!(peer.rekey_in_progress());
    assert_eq!(peer.rekey_our_index(), Some(SessionIndex::new(9_009)));
    assert_eq!(peer.rekey_msg1(), Some(&[0xC0, 0xC1, 0xC2][..]));
    assert_eq!(peer.rekey_msg1_resend_count(), 0);
    assert!(!peer.needs_msg1_resend(4_499));
    assert!(peer.needs_msg1_resend(4_500));

    let missing_handshake =
        NoiseHandshakeState::new_initiator(local.keypair(), peer.identity().pubkey_full());
    assert!(!peers.record_fmp_rekey_initiated(
        &node_addr(0x77),
        missing_handshake,
        SessionIndex::new(9_010),
        vec![0xD0],
        5_000,
    ));
}

#[test]
fn peer_lifecycle_registry_owns_fmp_rekey_msg1_resend_selection_and_accounting() {
    let local = Identity::generate();
    let due_peer = Identity::generate();
    let future_peer = Identity::generate();
    let exhausted_peer = Identity::generate();
    let missing_target_peer = Identity::generate();

    let mut due = active_fmp_peer(&local, &due_peer, 1);
    arm_in_progress_fmp_rekey(&mut due, &local, &due_peer);
    due.set_msg1_next_resend(1_500);

    let mut future = active_fmp_peer(&local, &future_peer, 2);
    arm_in_progress_fmp_rekey(&mut future, &local, &future_peer);
    future.set_msg1_next_resend(2_500);

    let mut exhausted = active_fmp_peer(&local, &exhausted_peer, 3);
    arm_in_progress_fmp_rekey(&mut exhausted, &local, &exhausted_peer);
    exhausted.record_rekey_msg1_resend(1_500);

    let mut missing_target = no_session_fmp_peer(&missing_target_peer, 4);
    arm_in_progress_fmp_rekey(&mut missing_target, &local, &missing_target_peer);
    missing_target.set_msg1_next_resend(1_500);

    let mut peers = crate::node::PeerLifecycleRegistry::default();
    peers.insert(*due_peer.node_addr(), due);
    peers.insert(*future_peer.node_addr(), future);
    peers.insert(*exhausted_peer.node_addr(), exhausted);
    peers.insert(*missing_target_peer.node_addr(), missing_target);

    assert_eq!(
        peers.due_fmp_rekey_msg1_resends(1_499, 1),
        Vec::<FmpRekeyMsg1Resend>::new()
    );

    let resends = peers.due_fmp_rekey_msg1_resends(1_500, 1);
    assert_eq!(resends.len(), 1);
    assert_eq!(resends[0].node_addr, *due_peer.node_addr());
    assert_eq!(resends[0].transport_id, TransportId::new(1));
    assert_eq!(
        resends[0].remote_addr,
        TransportAddr::from_string("127.0.0.1:4001")
    );
    assert_eq!(resends[0].payload, vec![0xAB; 64]);

    let count = peers
        .record_scheduled_fmp_rekey_msg1_resend(due_peer.node_addr(), 1_500, 1_000, 2.0)
        .expect("due peer should still exist");
    assert_eq!(count, 1);
    let due = peers.get(due_peer.node_addr()).expect("due peer remains");
    assert_eq!(due.rekey_msg1_resend_count(), 1);
    assert!(!due.needs_msg1_resend(3_499));
    assert!(due.needs_msg1_resend(3_500));

    assert!(
        peers
            .record_scheduled_fmp_rekey_msg1_resend(&node_addr(0x77), 1_500, 1_000, 2.0,)
            .is_none()
    );
}

#[test]
fn peer_lifecycle_registry_owns_exhausted_fmp_rekey_msg1_cleanup() {
    let local = Identity::generate();
    let exhausted_peer = Identity::generate();
    let under_budget_peer = Identity::generate();
    let missing_target_peer = Identity::generate();
    let idle_peer = Identity::generate();

    let mut exhausted = active_fmp_peer(&local, &exhausted_peer, 1);
    arm_in_progress_fmp_rekey(&mut exhausted, &local, &exhausted_peer);
    exhausted.record_rekey_msg1_resend(9_000);

    let mut under_budget = active_fmp_peer(&local, &under_budget_peer, 2);
    arm_in_progress_fmp_rekey(&mut under_budget, &local, &under_budget_peer);

    let mut missing_target = no_session_fmp_peer(&missing_target_peer, 3);
    arm_in_progress_fmp_rekey(&mut missing_target, &local, &missing_target_peer);
    missing_target.record_rekey_msg1_resend(9_000);

    let idle = active_fmp_peer(&local, &idle_peer, 4);

    let mut peers = crate::node::PeerLifecycleRegistry::default();
    peers.insert(*exhausted_peer.node_addr(), exhausted);
    peers.insert(*under_budget_peer.node_addr(), under_budget);
    peers.insert(*missing_target_peer.node_addr(), missing_target);
    peers.insert(*idle_peer.node_addr(), idle);

    let mut exhausted = peers.exhaust_fmp_rekey_msg1_resend_budgets(1);
    exhausted.sort_by_key(|item| item.node_addr);
    let mut expected = vec![
        ExhaustedFmpRekeyMsg1 {
            node_addr: *exhausted_peer.node_addr(),
            cleanup: Some(FmpRekeyIndexCleanup {
                transport_id: Some(TransportId::new(1)),
                rekey_our_index: SessionIndex::new(9_001),
            }),
        },
        ExhaustedFmpRekeyMsg1 {
            node_addr: *missing_target_peer.node_addr(),
            cleanup: Some(FmpRekeyIndexCleanup {
                transport_id: None,
                rekey_our_index: SessionIndex::new(9_001),
            }),
        },
    ];
    expected.sort_by_key(|item| item.node_addr);
    assert_eq!(exhausted, expected);

    let exhausted = peers
        .get(exhausted_peer.node_addr())
        .expect("exhausted peer should remain");
    assert!(!exhausted.rekey_in_progress());
    assert!(exhausted.rekey_msg1().is_none());
    assert_eq!(exhausted.rekey_our_index(), None);

    let under_budget = peers
        .get(under_budget_peer.node_addr())
        .expect("under-budget peer should remain");
    assert!(under_budget.rekey_in_progress());
    assert!(under_budget.rekey_msg1().is_some());
    assert_eq!(under_budget.rekey_msg1_resend_count(), 0);

    let idle = peers
        .get(idle_peer.node_addr())
        .expect("idle peer should remain");
    assert!(!idle.rekey_in_progress());
}

#[test]
fn session_registry_owns_session_rekey_initiation_eligibility() {
    let local = Identity::generate();
    let ready_peer = Identity::generate();
    let initiating_peer = Identity::generate();
    let in_progress_peer = Identity::generate();
    let pending_peer = Identity::generate();
    let draining_peer = Identity::generate();

    let ready = established_entry(&local, &ready_peer, 1_000);
    let initiating = initiating_entry(&local, &initiating_peer, 1_000);

    let mut in_progress = established_entry(&local, &in_progress_peer, 1_000);
    in_progress.set_rekey_state(
        NoiseHandshakeState::new_xk_initiator(local.keypair(), in_progress_peer.pubkey_full()),
        true,
    );

    let (pending_session, _) = make_xk_session_pair(&local, &pending_peer);
    let mut pending = established_entry(&local, &pending_peer, 1_000);
    pending.set_pending_session(pending_session);

    let (draining_session, _) = make_xk_session_pair(&local, &draining_peer);
    let mut draining = established_entry(&local, &draining_peer, 1_000);
    draining.set_pending_session(draining_session);
    assert!(draining.cutover_to_new_session(2_000));

    let mut sessions = crate::node::SessionRegistry::default();
    sessions.insert(*ready_peer.node_addr(), ready);
    sessions.insert(*initiating_peer.node_addr(), initiating);
    sessions.insert(*in_progress_peer.node_addr(), in_progress);
    sessions.insert(*pending_peer.node_addr(), pending);
    sessions.insert(*draining_peer.node_addr(), draining);

    assert_eq!(
        sessions
            .prepare_session_rekey_initiation(ready_peer.node_addr())
            .expect("ready session should be eligible"),
        SessionRekeyInitiation {
            dest_pubkey: ready_peer.pubkey_full(),
        }
    );
    assert_eq!(
        sessions.prepare_session_rekey_initiation(&node_addr(0x77)),
        Err(SessionRekeyInitiationSkip::MissingSession)
    );
    assert_eq!(
        sessions.prepare_session_rekey_initiation(initiating_peer.node_addr()),
        Err(SessionRekeyInitiationSkip::NotEstablished)
    );
    assert_eq!(
        sessions.prepare_session_rekey_initiation(in_progress_peer.node_addr()),
        Err(SessionRekeyInitiationSkip::RekeyInProgress)
    );
    assert_eq!(
        sessions
            .prepare_session_rekey_initiation(pending_peer.node_addr())
            .expect("a recovery handshake may be armed beside a stalled pending epoch"),
        SessionRekeyInitiation {
            dest_pubkey: pending_peer.pubkey_full(),
        }
    );
    assert_eq!(
        sessions.prepare_session_rekey_initiation(draining_peer.node_addr()),
        Err(SessionRekeyInitiationSkip::RekeyInProgress),
        "a one-bit K epoch cannot start another rekey while the previous epoch drains"
    );
}

#[test]
fn session_registry_owns_session_rekey_initiation_state_install() {
    let local = Identity::generate();
    let peer = Identity::generate();
    let entry = established_entry(&local, &peer, 1_000);

    let mut sessions = crate::node::SessionRegistry::default();
    sessions.insert(*peer.node_addr(), entry);

    let handshake = NoiseHandshakeState::new_xk_initiator(local.keypair(), peer.pubkey_full());
    assert!(sessions.record_session_rekey_initiated(
        peer.node_addr(),
        handshake,
        vec![0xA0, 0xA1],
        2_500,
    ));

    let entry = sessions
        .get(peer.node_addr())
        .expect("session should remain installed");
    assert!(entry.has_rekey_in_progress());
    assert!(entry.is_rekey_initiator());
    assert_eq!(entry.handshake_payload(), Some(&[0xA0, 0xA1][..]));
    assert_eq!(entry.next_resend_at_ms(), 2_500);
    assert_eq!(entry.resend_count(), 0);

    let missing_handshake =
        NoiseHandshakeState::new_xk_initiator(local.keypair(), peer.pubkey_full());
    assert!(!sessions.record_session_rekey_initiated(
        &node_addr(0x77),
        missing_handshake,
        vec![0xB0],
        3_000,
    ));
}

#[test]
fn session_registry_owns_rekey_tick_selection() {
    let local = Identity::generate();
    let cutover_peer = Identity::generate();
    let early_cutover_peer = Identity::generate();
    let drain_peer = Identity::generate();
    let drain_and_rekey_peer = Identity::generate();
    let rekey_peer = Identity::generate();
    let recovering_peer = Identity::generate();
    let under_age_peer = Identity::generate();
    let dampened_peer = Identity::generate();
    let msg3_peer = Identity::generate();

    let now_ms = 20_000_000;
    let drain_ms = FSP_DRAIN_WINDOW_SECS * 1000;
    let tick = SessionRekeyTickConfig {
        initiate_enabled: true,
        now_ms,
        rekey_after_secs: 10_000,
        rekey_after_messages: u64::MAX,
        drain_ms,
        dampening_ms: REKEY_DAMPENING_SECS * 1000,
        probe_delay_ms: FSP_PENDING_EPOCH_PROBE_DELAY_MS,
        probe_interval_ms: FSP_PENDING_EPOCH_PROBE_INTERVAL_MS,
    };

    let mut cutover = established_entry(&local, &cutover_peer, 1_000);
    arm_completed_initiator_rekey(
        &mut cutover,
        &local,
        &cutover_peer,
        now_ms - FSP_PENDING_EPOCH_PROBE_DELAY_MS - 500,
    );

    let mut early_cutover = established_entry(&local, &early_cutover_peer, 1_000);
    arm_completed_initiator_rekey(
        &mut early_cutover,
        &local,
        &early_cutover_peer,
        now_ms - FSP_PENDING_EPOCH_PROBE_DELAY_MS + 500,
    );

    let drain_cutover_ms = now_ms - drain_ms - 1_000;
    let mut drain = established_entry(&local, &drain_peer, drain_cutover_ms);
    arm_completed_initiator_rekey(&mut drain, &local, &drain_peer, drain_cutover_ms);
    assert!(drain.cutover_to_new_session(drain_cutover_ms));

    let mut drain_and_rekey = established_entry(&local, &drain_and_rekey_peer, 1_000);
    arm_completed_initiator_rekey(&mut drain_and_rekey, &local, &drain_and_rekey_peer, 1_000);
    assert!(drain_and_rekey.cutover_to_new_session(1_000));

    let rekey = established_entry(&local, &rekey_peer, 1_000);
    let recovering = established_entry(&local, &recovering_peer, 1_000);
    let under_age = established_entry(&local, &under_age_peer, now_ms - 1_000);

    let mut dampened = established_entry(&local, &dampened_peer, 1_000);
    dampened.record_peer_rekey(now_ms - 1_000);

    let mut msg3 = established_entry(&local, &msg3_peer, 1_000);
    msg3.set_rekey_msg3_payload(vec![0x90], now_ms);

    let mut sessions = crate::node::SessionRegistry::default();
    sessions.insert(*cutover_peer.node_addr(), cutover);
    sessions.insert(*early_cutover_peer.node_addr(), early_cutover);
    sessions.insert(*drain_peer.node_addr(), drain);
    sessions.insert(*drain_and_rekey_peer.node_addr(), drain_and_rekey);
    sessions.insert(*rekey_peer.node_addr(), rekey);
    sessions.insert(*recovering_peer.node_addr(), recovering);
    sessions.insert(*under_age_peer.node_addr(), under_age);
    sessions.insert(*dampened_peer.node_addr(), dampened);
    sessions.insert(*msg3_peer.node_addr(), msg3);

    let mut plan =
        sessions.plan_session_rekey_tick(tick, |_| 0, |addr| addr != recovering_peer.node_addr());
    plan.probe.sort();
    plan.drain.sort();
    plan.initiate.sort();

    let mut expected_probe = vec![*cutover_peer.node_addr()];
    expected_probe.sort();
    assert_eq!(plan.probe, expected_probe);

    let mut expected_drain = vec![*drain_peer.node_addr(), *drain_and_rekey_peer.node_addr()];
    expected_drain.sort();
    assert_eq!(plan.drain, expected_drain);

    let mut expected_initiate = vec![*rekey_peer.node_addr()];
    expected_initiate.sort();
    assert_eq!(plan.initiate, expected_initiate);

    let mut disabled_plan = sessions.plan_session_rekey_tick(
        SessionRekeyTickConfig {
            initiate_enabled: false,
            ..tick
        },
        |_| 0,
        |_| true,
    );
    disabled_plan.probe.sort();
    disabled_plan.drain.sort();
    assert_eq!(disabled_plan.probe, plan.probe);
    assert_eq!(disabled_plan.drain, plan.drain);
    assert!(
        disabled_plan.initiate.is_empty(),
        "disabling local initiation must not disable responder lifecycle work"
    );

    assert!(sessions.complete_due_session_rekey_drain(
        drain_and_rekey_peer.node_addr(),
        now_ms,
        drain_ms
    ));
    let followup = sessions.plan_session_rekey_tick(tick, |_| 0, |_| true);
    assert!(
        followup.initiate.contains(drain_and_rekey_peer.node_addr()),
        "the timer-due rekey should start on the tick after drain retirement"
    );
}

#[tokio::test]
async fn disabled_local_initiation_still_reaps_responder_drain_and_msg3_retry_state() {
    let local = Identity::generate();
    let pending_peer = Identity::generate();
    let draining_peer = Identity::generate();
    let mut config = crate::config::Config::new();
    config.node.rekey.enabled = false;
    config.node.rate_limit.handshake_max_resends = 0;
    let mut node = Node::with_identity(local, config).expect("node");

    let mut pending = established_entry(&node.identity, &pending_peer, 1_000);
    pending.set_rekey_state(
        NoiseHandshakeState::new_xk_initiator(node.identity.keypair(), pending_peer.pubkey_full()),
        true,
    );
    let (pending_session, _) = make_xk_session_pair(&node.identity, &pending_peer);
    pending.set_pending_session(pending_session);
    pending.set_rekey_completed_ms(1_000);
    pending.set_rekey_msg3_payload(vec![0x91], 1_001);

    let mut draining = established_entry(&node.identity, &draining_peer, 1_000);
    draining.set_rekey_state(
        NoiseHandshakeState::new_xk_responder(node.identity.keypair()),
        false,
    );
    let (_, draining_session) = make_xk_session_pair(&draining_peer, &node.identity);
    draining.set_pending_session(draining_session);
    assert!(draining.cutover_to_new_session(1));

    node.sessions.insert(*pending_peer.node_addr(), pending);
    node.sessions.insert(*draining_peer.node_addr(), draining);

    node.resend_pending_session_msg3(u64::MAX).await;
    let pending = node.sessions.get(pending_peer.node_addr()).unwrap();
    assert!(pending.pending_new_session().is_some());
    assert!(pending.rekey_msg3_payload().is_none());

    node.check_session_rekey().await;
    assert!(
        !node
            .sessions
            .get(draining_peer.node_addr())
            .unwrap()
            .is_draining(),
        "peer-driven drain retirement must run with local initiation disabled"
    );
}

#[test]
fn session_registry_owns_rekey_tick_probe_and_drain_mutation() {
    let local = Identity::generate();
    let cutover_peer = Identity::generate();
    let early_cutover_peer = Identity::generate();
    let drain_peer = Identity::generate();
    let early_drain_peer = Identity::generate();

    let drain_ms = FSP_DRAIN_WINDOW_SECS * 1000;
    let now_ms = FSP_PENDING_EPOCH_PROBE_DELAY_MS + drain_ms + 20_000;

    let mut cutover = established_entry(&local, &cutover_peer, 1_000);
    arm_completed_initiator_rekey(
        &mut cutover,
        &local,
        &cutover_peer,
        now_ms - FSP_PENDING_EPOCH_PROBE_DELAY_MS - 500,
    );

    let mut early_cutover = established_entry(&local, &early_cutover_peer, 1_000);
    arm_completed_initiator_rekey(
        &mut early_cutover,
        &local,
        &early_cutover_peer,
        now_ms - FSP_PENDING_EPOCH_PROBE_DELAY_MS + 500,
    );

    let mut drain = established_entry(&local, &drain_peer, 1_000);
    arm_completed_initiator_rekey(&mut drain, &local, &drain_peer, 1_000);
    assert!(drain.cutover_to_new_session(1_000));

    let mut early_drain = established_entry(&local, &early_drain_peer, now_ms - 1_000);
    arm_completed_initiator_rekey(&mut early_drain, &local, &early_drain_peer, now_ms - 1_000);
    assert!(early_drain.cutover_to_new_session(now_ms - 1_000));

    let mut sessions = crate::node::SessionRegistry::default();
    sessions.insert(*cutover_peer.node_addr(), cutover);
    sessions.insert(*early_cutover_peer.node_addr(), early_cutover);
    sessions.insert(*drain_peer.node_addr(), drain);
    sessions.insert(*early_drain_peer.node_addr(), early_drain);

    assert!(sessions.record_due_session_rekey_probe(
        cutover_peer.node_addr(),
        now_ms,
        FSP_PENDING_EPOCH_PROBE_DELAY_MS,
        FSP_PENDING_EPOCH_PROBE_INTERVAL_MS,
    ));
    let cutover = sessions
        .get(cutover_peer.node_addr())
        .expect("probed session should remain");
    assert!(cutover.pending_new_session().is_some());
    assert!(!cutover.is_draining());
    assert_ne!(cutover.rekey_completed_ms(), 0);
    assert!(!sessions.record_due_session_rekey_probe(
        cutover_peer.node_addr(),
        now_ms,
        FSP_PENDING_EPOCH_PROBE_DELAY_MS,
        FSP_PENDING_EPOCH_PROBE_INTERVAL_MS,
    ));

    assert!(!sessions.record_due_session_rekey_probe(
        early_cutover_peer.node_addr(),
        now_ms,
        FSP_PENDING_EPOCH_PROBE_DELAY_MS,
        FSP_PENDING_EPOCH_PROBE_INTERVAL_MS,
    ));
    assert!(
        sessions
            .get(early_cutover_peer.node_addr())
            .expect("early cutover session should remain")
            .pending_new_session()
            .is_some()
    );

    assert!(sessions.complete_due_session_rekey_drain(drain_peer.node_addr(), now_ms, drain_ms));
    assert!(
        !sessions
            .get(drain_peer.node_addr())
            .expect("drained session should remain")
            .is_draining()
    );

    assert!(!sessions.complete_due_session_rekey_drain(
        early_drain_peer.node_addr(),
        now_ms,
        drain_ms
    ));
    assert!(
        sessions
            .get(early_drain_peer.node_addr())
            .expect("early drain session should remain")
            .is_draining()
    );
}

mod msg3_resend;
