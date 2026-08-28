use super::*;

#[test]
fn session_registry_owns_rekey_msg3_resend_selection_and_accounting() {
    let local = Identity::generate();
    let due_peer = Identity::generate();
    let future_peer = Identity::generate();
    let no_payload_peer = Identity::generate();

    let mut due = established_entry(&local, &due_peer, 1_000);
    due.set_rekey_msg3_payload(vec![0x30, 0x31], 1_500);

    let mut future = established_entry(&local, &future_peer, 1_000);
    future.set_rekey_msg3_payload(vec![0x40], 2_500);

    let no_payload = established_entry(&local, &no_payload_peer, 1_000);

    let mut sessions = crate::node::SessionRegistry::default();
    sessions.insert(*due_peer.node_addr(), due);
    sessions.insert(*future_peer.node_addr(), future);
    sessions.insert(*no_payload_peer.node_addr(), no_payload);

    assert_eq!(
        sessions.due_rekey_msg3_resends(1_499, 3),
        Vec::<SessionRekeyMsg3Resend>::new()
    );
    assert_eq!(
        sessions.due_rekey_msg3_resends(1_500, 3),
        vec![SessionRekeyMsg3Resend {
            dest_addr: *due_peer.node_addr(),
            payload: vec![0x30, 0x31],
        }]
    );

    let count = sessions
        .record_scheduled_rekey_msg3_resend(due_peer.node_addr(), 1_500, 1_000, 2.0)
        .expect("due rekey msg3 session should exist");
    assert_eq!(count, 1);
    let due = sessions
        .get(due_peer.node_addr())
        .expect("due session should remain");
    assert_eq!(due.rekey_msg3_resend_count(), 1);
    assert_eq!(due.rekey_msg3_next_resend_ms(), 3_500);
    assert_eq!(due.rekey_msg3_payload(), Some(&[0x30, 0x31][..]));

    assert!(
        sessions
            .record_scheduled_rekey_msg3_resend(&node_addr(0x77), 1_500, 1_000, 2.0)
            .is_none()
    );
}

#[test]
fn session_registry_owns_exhausted_rekey_msg3_cleanup() {
    let local = Identity::generate();
    let exhausted_peer = Identity::generate();
    let future_exhausted_peer = Identity::generate();
    let under_budget_peer = Identity::generate();
    let pending_peer = Identity::generate();

    let mut exhausted = established_entry(&local, &exhausted_peer, 1_000);
    exhausted.set_rekey_completed_ms(1_000);
    exhausted.set_rekey_msg3_payload(vec![0x50], 1_500);
    exhausted.record_rekey_msg3_resend(1_500);

    let mut future_exhausted = established_entry(&local, &future_exhausted_peer, 1_000);
    future_exhausted.set_rekey_msg3_payload(vec![0x60], 2_500);
    future_exhausted.record_rekey_msg3_resend(2_500);

    let mut under_budget = established_entry(&local, &under_budget_peer, 1_000);
    under_budget.set_rekey_msg3_payload(vec![0x70], 1_500);

    let (pending_session, _) = make_xk_session_pair(&local, &pending_peer);
    let mut pending = established_entry(&local, &pending_peer, 1_000);
    pending.set_pending_session(pending_session);
    pending.set_rekey_completed_ms(1_000);
    pending.set_rekey_msg3_payload(vec![0x80], 1_500);
    pending.record_rekey_msg3_resend(1_500);

    let mut sessions = crate::node::SessionRegistry::default();
    sessions.insert(*exhausted_peer.node_addr(), exhausted);
    sessions.insert(*future_exhausted_peer.node_addr(), future_exhausted);
    sessions.insert(*under_budget_peer.node_addr(), under_budget);
    sessions.insert(*pending_peer.node_addr(), pending);

    let mut exhausted = sessions.exhaust_due_rekey_msg3_resend_budgets(1_500, 1);
    exhausted.sort_by_key(|item| item.dest_addr);
    let mut expected = vec![
        ExhaustedSessionRekeyMsg3 {
            dest_addr: *exhausted_peer.node_addr(),
        },
        ExhaustedSessionRekeyMsg3 {
            dest_addr: *pending_peer.node_addr(),
        },
    ];
    expected.sort_by_key(|item| item.dest_addr);
    assert_eq!(exhausted, expected);

    let exhausted = sessions
        .get(exhausted_peer.node_addr())
        .expect("exhausted session should remain");
    assert!(exhausted.rekey_msg3_payload().is_none());
    assert_eq!(exhausted.rekey_msg3_resend_count(), 0);
    assert_eq!(exhausted.rekey_msg3_next_resend_ms(), 0);
    assert_eq!(exhausted.rekey_completed_ms(), 0);

    let pending = sessions
        .get(pending_peer.node_addr())
        .expect("pending session should remain");
    assert!(pending.pending_new_session().is_some());
    assert!(pending.rekey_msg3_payload().is_none());
    assert_eq!(pending.rekey_msg3_resend_count(), 0);
    assert_eq!(pending.rekey_msg3_next_resend_ms(), 0);
    assert_eq!(pending.rekey_completed_ms(), 1_000);

    let future_exhausted = sessions
        .get(future_exhausted_peer.node_addr())
        .expect("future-exhausted session should remain");
    assert_eq!(future_exhausted.rekey_msg3_payload(), Some(&[0x60][..]));
    assert_eq!(future_exhausted.rekey_msg3_resend_count(), 1);

    let under_budget = sessions
        .get(under_budget_peer.node_addr())
        .expect("under-budget session should remain");
    assert_eq!(under_budget.rekey_msg3_payload(), Some(&[0x70][..]));
    assert_eq!(under_budget.rekey_msg3_resend_count(), 0);
}
