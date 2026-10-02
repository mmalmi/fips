#[derive(Debug, Default)]
struct ReplenishedAdmission(std::sync::Mutex<(bool, usize, Vec<ForwardingOutcome>)>);

impl ForwardingPolicy for ReplenishedAdmission {
    fn admit(&self, request: &ForwardingRequest<'_>) -> Option<u64> {
        self.decide(request).admission().map(|admission| admission.token)
    }

    fn decide(&self, _: &ForwardingRequest<'_>) -> crate::node::ForwardingDecision {
        let mut state = self.0.lock().unwrap();
        if !state.0 {
            return crate::node::ForwardingDecision::Retry;
        }
        state.1 += 1;
        crate::node::ForwardingDecision::Admit(ForwardingAdmission {
            token: state.1 as u64,
            class: ForwardingClass::Normal,
        })
    }

    fn complete(&self, _: u64, outcome: ForwardingOutcome) {
        self.0.lock().unwrap().2.push(outcome);
    }
}

#[tokio::test]
async fn temporary_admission_wait_rechecks_without_reserving_or_rewriting() {
    let (mut node, ingress, next) = fixture();
    let policy = std::sync::Arc::new(ReplenishedAdmission::default());
    node.set_forwarding_policy(Some(policy.clone()));
    let encoded = SessionDatagram::new(*ingress.node_addr(), next, vec![1, 2, 3])
        .with_ttl(20).encode();
    assert!(matches!(node.prepare_session_datagram(AuthenticatedSessionDatagram::new(
        ingress, &encoded[1..], true,
    )).await, PreparedSessionDatagram::Done));
    let original_expiry = node.waiting_admissions.packets[0].expires;
    node.waiting_admissions.packets[0].due = tokio::time::Instant::now();
    node.retry_forwarding_admissions().await;
    let waiting = node.waiting_admissions.pop().unwrap();
    assert_eq!(waiting.expires, original_expiry, "a retry cannot extend retention");
    assert_eq!(&*waiting.payload, &encoded[1..]);
    assert_eq!(policy.0.lock().unwrap().1, 0, "waiting is not a reservation");
    policy.0.lock().unwrap().0 = true;
    let PreparedSessionDatagram::Forward(route) = node.prepare_session_datagram_with_deadline(
        AuthenticatedSessionDatagram::new(ingress, &waiting.payload, waiting.ce),
        Some(waiting.expires),
    ).await else { panic!("replenished allowance must admit the waiting packet"); };
    assert_eq!(route.ttl, 19);
    assert!(route.outgoing_ce);
    drop(route);
    let state = policy.0.lock().unwrap();
    assert_eq!(state.1, 1);
    assert_eq!(state.2, [ForwardingOutcome::Unconfirmed]);
    assert_eq!(node.stats().forwarding.received_packets, 1);
    assert_eq!(node.stats().forwarding.deferred_policy_packets, 1);
    assert_eq!(node.stats().forwarding.drop_policy_denied_packets, 0);
    assert_eq!(node.waiting_admissions.bytes, 0);
    assert!(node.waiting_admissions.peers.is_empty());
}

#[tokio::test]
async fn waiting_admission_expires_and_cannot_survive_peer_or_policy_replacement() {
    for replacement in 0..3 {
        let (mut node, ingress, next) = fixture();
        let policy = std::sync::Arc::new(ReplenishedAdmission::default());
        node.set_forwarding_policy(Some(policy.clone()));
        let encoded = SessionDatagram::new(*ingress.node_addr(), next, vec![4; 16]).encode();
        node.prepare_session_datagram(AuthenticatedSessionDatagram::new(
            ingress, &encoded[1..], false,
        )).await;
        node.waiting_admissions.packets[0].due = tokio::time::Instant::now();
        match replacement {
            0 => node.waiting_admissions.packets[0].expires = tokio::time::Instant::now(),
            1 => { node.peers.insert(*ingress.node_addr(), ActivePeer::new(ingress, LinkId::new(99), 2)); }
            _ => node.set_forwarding_policy(None),
        }
        policy.0.lock().unwrap().0 = true;
        node.retry_forwarding_admissions().await;
        assert!(node.waiting_admissions.packets.is_empty());
        assert_eq!(node.waiting_admissions.bytes, 0);
        assert!(node.waiting_admissions.peers.is_empty());
        assert_eq!(node.stats().forwarding.drop_policy_denied_packets, 1);
        assert_eq!(policy.0.lock().unwrap().1, 0);
        assert!(policy.0.lock().unwrap().2.is_empty());
    }
}

#[test]
fn waiting_admission_bounds_packets_and_bytes_without_one_peer_taking_all_space() {
    let (mut node, ingress, next) = fixture();
    let other = *node.peers[&next].identity();
    let neighbors: Vec<_> = (10..18).map(|id| {
        let peer = crate::PeerIdentity::from_pubkey_full(crate::Identity::generate().pubkey_full());
        node.peers.insert(*peer.node_addr(), ActivePeer::new(peer, LinkId::new(id), 1));
        peer
    }).collect();
    for bytes in [1, 16 * 1024] {
        let payload = vec![0; bytes];
        let mut accepted = 0;
        while node.wait_for_forwarding_admission(ingress, &payload, false, None) {
            accepted += 1;
            assert!(accepted <= ADMISSION_WAIT_PEER_PACKETS);
        }
        assert!(accepted > 0);
        assert!(node.waiting_admissions.bytes <= ADMISSION_WAIT_PEER_BYTES);
        assert!(node.wait_for_forwarding_admission(other, &payload, false, None));
        for peer in &neighbors {
            while node.wait_for_forwarding_admission(*peer, &payload, false, None) {}
        }
        assert!(!node.wait_for_forwarding_admission(other, &payload, false, None));
        if bytes == 1 {
            assert_eq!(node.waiting_admissions.packets.len(), ADMISSION_WAIT_PACKETS);
        } else {
            assert_eq!(node.waiting_admissions.bytes, ADMISSION_WAIT_BYTES);
        }
        assert!(node.waiting_admissions.bytes <= ADMISSION_WAIT_BYTES);
        node.cancel_waiting_admissions();
        assert_eq!(node.waiting_admissions.bytes, 0);
        assert!(node.waiting_admissions.peers.is_empty());
    }
}
