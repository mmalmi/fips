use super::*;

#[derive(Default)]
struct ScanOracle {
    sent: HashMap<NodeAddr, u64>,
    pending: HashMap<NodeAddr, u64>,
    debounce: u64,
}

impl ScanOracle {
    fn due(&self, peer: &NodeAddr) -> Option<u64> {
        self.pending.get(peer).map(|retry| {
            (*retry).max(
                self.sent
                    .get(peer)
                    .map_or(0, |sent| sent.saturating_add(self.debounce)),
            )
        })
    }

    fn check(&self, state: &BloomState, peers: &[NodeAddr]) {
        let earliest = self.pending.keys().filter_map(|peer| self.due(peer)).min();
        assert_eq!(state.pending_update_deadline_ms(), earliest);
        let boundary = earliest.unwrap_or(1_500);
        for now in [
            0,
            boundary.saturating_sub(1),
            boundary,
            boundary.saturating_add(1),
            10_000,
            u64::MAX,
        ] {
            let mut expected: Vec<_> = self
                .pending
                .keys()
                .filter(|peer| self.due(peer).is_some_and(|due| due <= now))
                .copied()
                .collect();
            let mut actual = state.pending_peers_due(now);
            expected.sort_unstable();
            actual.sort_unstable();
            assert_eq!(actual, expected);
        }
        for peer in peers {
            assert_eq!(state.pending_peer_deadline_ms(peer), self.due(peer));
            assert_eq!(state.needs_update(peer), self.pending.contains_key(peer));
            // Ordinary maintenance deliberately ignores the extra retry floor.
            let now = boundary;
            let allowed = self.pending.contains_key(peer)
                && self
                    .sent
                    .get(peer)
                    .is_none_or(|sent| now >= sent.saturating_add(self.debounce));
            assert_eq!(state.should_send_update(peer, now), allowed);
        }
    }
}

enum Change {
    Mark(NodeAddr),
    Sent(NodeAddr, u64),
    Remove(NodeAddr),
    Reserve(NodeAddr, u64),
    RetryAll(u64),
    Debounce(u64),
    Clear,
}

fn apply(state: &mut BloomState, oracle: &mut ScanOracle, peers: &[NodeAddr], change: Change) {
    match change {
        Change::Mark(peer) => {
            state.mark_update_needed(peer);
            oracle.pending.entry(peer).or_insert(0);
        }
        Change::Sent(peer, now) => {
            state.record_update_sent(peer, now);
            oracle.sent.insert(peer, now);
            oracle.pending.remove(&peer);
        }
        Change::Remove(peer) => {
            state.remove_peer_state(&peer);
            oracle.sent.remove(&peer);
            oracle.pending.remove(&peer);
        }
        Change::Reserve(peer, retry) => {
            state.defer_update_retry(&peer, retry);
            if let Some(floor) = oracle.pending.get_mut(&peer) {
                *floor = (*floor).max(retry);
            }
        }
        Change::RetryAll(retry) => {
            state.defer_pending_retries(retry);
            for floor in oracle.pending.values_mut() {
                *floor = (*floor).max(retry);
            }
        }
        Change::Debounce(ms) => {
            state.set_update_debounce_ms(ms);
            oracle.debounce = ms;
        }
        Change::Clear => {
            state.clear_pending_updates();
            oracle.pending.clear();
        }
    }
    oracle.check(state, peers);
}

#[test]
fn deadline_index_matches_scan_through_large_peer_batches_and_cancellation() {
    let peers: Vec<_> = (1_u64..=500)
        .map(|i| {
            let mut bytes = [0; 16];
            bytes[..8].copy_from_slice(&i.to_le_bytes());
            NodeAddr::from_bytes(bytes)
        })
        .collect();
    for staggered in [false, true] {
        let mut state = BloomState::new(make_node_addr(0));
        let mut oracle = ScanOracle {
            debounce: 500,
            ..Default::default()
        };
        for (i, peer) in peers.iter().enumerate() {
            let sent = 1_000 + if staggered { i as u64 } else { 0 };
            apply(&mut state, &mut oracle, &peers, Change::Sent(*peer, sent));
            apply(&mut state, &mut oracle, &peers, Change::Mark(*peer));
        }
        for (i, peer) in peers.iter().enumerate() {
            apply(
                &mut state,
                &mut oracle,
                &peers,
                Change::Reserve(*peer, 10_000),
            );
            // A cancelled in-flight send retains its reservation even when a
            // new content change marks the peer or a shorter retry is requested.
            apply(&mut state, &mut oracle, &peers, Change::Mark(*peer));
            apply(
                &mut state,
                &mut oracle,
                &peers,
                Change::Reserve(*peer, 9_000),
            );
            if i % 2 == 0 {
                apply(&mut state, &mut oracle, &peers, Change::Sent(*peer, 2_000));
            } else {
                apply(&mut state, &mut oracle, &peers, Change::Remove(*peer));
            }
        }
        assert_eq!(state.pending_update_deadline_ms(), None);

        // Deterministic mixed mutations exercise arbitrary minimum replacement,
        // rescheduling, bulk retry floors, and empty/nonempty transitions.
        let mut seed = 0x0dea_d1e5_u64;
        for _ in 0..2_000 {
            seed = seed.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1);
            let peer = peers[(seed >> 16) as usize % peers.len()];
            let now = (seed >> 32) % 20_000;
            let change = match seed % 9 {
                0..=2 => Change::Mark(peer),
                3 => Change::Sent(peer, now),
                4 => Change::Remove(peer),
                5 => Change::Reserve(peer, now),
                6 => Change::RetryAll(now),
                7 => Change::Debounce(now),
                _ => Change::Clear,
            };
            apply(&mut state, &mut oracle, &peers, change);
        }
        apply(
            &mut state,
            &mut oracle,
            &peers,
            Change::Sent(peers[0], u64::MAX - 1),
        );
        apply(&mut state, &mut oracle, &peers, Change::Mark(peers[0]));
        apply(&mut state, &mut oracle, &peers, Change::RetryAll(u64::MAX));
        apply(&mut state, &mut oracle, &peers, Change::Debounce(0));
        oracle.check(&state.clone(), &peers);
        apply(&mut state, &mut oracle, &peers, Change::Clear);
        apply(&mut state, &mut oracle, &peers, Change::Mark(peers[0]));
        apply(&mut state, &mut oracle, &peers, Change::Remove(peers[0]));
    }
}
