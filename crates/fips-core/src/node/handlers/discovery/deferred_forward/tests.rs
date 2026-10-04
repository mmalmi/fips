use super::*;

fn addr(value: u64) -> NodeAddr {
    let mut bytes = [0; 16];
    bytes[..8].copy_from_slice(&value.to_le_bytes());
    NodeAddr::from_bytes(bytes)
}

fn entry(peer: u64, bytes: usize, due: Instant) -> DeferredForward {
    DeferredForward {
        from: addr(peer),
        link_id: LinkId::new(peer),
        authenticated_at: 1,
        received_ms: 1,
        admission_generation: 1,
        request_id: peer,
        encoded: vec![0; bytes].into_boxed_slice(),
        due,
        expires: due + Duration::from_secs(10),
    }
}

#[test]
fn waiting_state_has_independent_total_and_ingress_count_bounds() {
    let mut queue = DeferredDiscoveryForwards::default();
    let due = instant_now() + Duration::from_secs(2);
    for peer in 0..4 {
        for index in 0..MAX_PEER_WAITERS {
            assert!(queue.insert(
                (addr(0), addr(0), addr(peer * 64 + index as u64)),
                entry(peer, 1, due)
            ));
        }
        assert!(!queue.insert((addr(0), addr(0), addr(1000 + peer)), entry(peer, 1, due)));
    }
    assert_eq!(queue.entries.len(), MAX_WAITERS);
    assert!(!queue.insert((addr(0), addr(0), addr(1004)), entry(4, 1, due)));
    assert_eq!(queue.bytes, MAX_WAITERS);
    assert!(queue.take_due(&(addr(0), addr(0), addr(0)), due).is_some());
    assert!(queue.insert((addr(0), addr(0), addr(1004)), entry(4, 1, due)));
}

#[test]
fn variable_payloads_cannot_exceed_total_or_ingress_byte_bounds() {
    let mut queue = DeferredDiscoveryForwards::default();
    let due = instant_now() + Duration::from_secs(2);
    assert!(!queue.insert(
        (addr(0), addr(0), addr(0)),
        entry(0, MAX_PEER_BYTES + 1, due)
    ));
    for peer in 0..4 {
        assert!(queue.insert(
            (addr(0), addr(0), addr(peer)),
            entry(peer, MAX_PEER_BYTES, due)
        ));
        assert!(!queue.insert((addr(0), addr(0), addr(10 + peer)), entry(peer, 1, due)));
    }
    assert_eq!(queue.bytes, MAX_BYTES);
    assert!(!queue.insert((addr(0), addr(0), addr(4)), entry(4, 1, due)));
    assert!(queue.take_due(&(addr(0), addr(0), addr(0)), due).is_some());
    assert!(queue.insert((addr(0), addr(0), addr(4)), entry(4, MAX_PEER_BYTES, due)));
    assert_eq!(queue.bytes, MAX_BYTES);
}

#[test]
fn duplicates_cannot_replace_an_owner_extend_expiry_or_consume_another_waiter() {
    let mut queue = DeferredDiscoveryForwards::default();
    let now = instant_now();
    let due = now + Duration::from_secs(2);
    assert!(queue.insert((addr(0), addr(0), addr(1)), entry(11, 100, due)));
    assert!(queue.insert((addr(0), addr(0), addr(2)), entry(12, 200, due)));
    assert!(!queue.insert(
        (addr(0), addr(0), addr(1)),
        entry(13, 300, due + Duration::from_secs(10))
    ));
    assert_eq!(queue.bytes, 300);
    assert!(queue.take_due(&(addr(0), addr(0), addr(1)), now).is_none());
    let first = queue.take_due(&(addr(0), addr(0), addr(1)), due).unwrap();
    assert_eq!(first.from, addr(11));
    assert_eq!(first.expires, due + Duration::from_secs(10));
    assert_eq!(queue.bytes, 200);
    assert_eq!(queue.next_due, Some(due));
    assert!(queue.take_due(&(addr(0), addr(0), addr(1)), due).is_none());
    assert_eq!(
        queue
            .take_due(&(addr(0), addr(0), addr(2)), due)
            .unwrap()
            .from,
        addr(12)
    );
    assert_eq!(queue.bytes, 0);
    assert_eq!(queue.next_due, None);
}

#[test]
fn same_target_waiters_keep_distinct_origins_and_dispatch_oldest_first() {
    let mut queue = DeferredDiscoveryForwards::default();
    let now = instant_now();
    for origin in 0..MAX_PEER_WAITERS as u64 {
        let due = now + Duration::from_millis(origin);
        assert!(queue.insert((addr(1), addr(origin), addr(99)), entry(1, 100, due)));
    }
    assert!(!queue.insert((addr(1), addr(1000), addr(99)), entry(1, 100, now)));
    let later = now + Duration::from_secs(1);
    for offset in (0..MAX_PEER_WAITERS).step_by(MAX_DISPATCH_PER_TURN) {
        let keys = queue.due_keys(later);
        assert_eq!(keys.len(), MAX_DISPATCH_PER_TURN);
        for (index, key) in keys.iter().enumerate() {
            assert_eq!(*key, (addr(1), addr((offset + index) as u64), addr(99)));
            assert!(queue.take_due(key, later).is_some());
        }
    }
    assert_eq!(queue.bytes, 0);
    assert_eq!(queue.next_due, None);
}
