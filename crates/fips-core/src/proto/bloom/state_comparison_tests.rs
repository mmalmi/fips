use super::*;

fn addr(index: usize) -> NodeAddr {
    NodeAddr::from_bytes((index as u128).to_le_bytes())
}

// The pre-change algorithm, including byte-slice equality and comparisons for
// already-pending peers, is retained only as an equivalence/timing reference.
fn original_mark_changed_peers(
    state: &mut BloomState,
    source: &NodeAddr,
    peers: &[NodeAddr],
    inputs: &HashMap<NodeAddr, BloomFilter>,
) {
    let filters = state.prepare_outgoing_filters(inputs);
    for peer in peers {
        if peer == source {
            continue;
        }
        let changed = state.last_sent_filters.get(peer).is_none_or(|last| {
            if last.num_bytes() != filters.combined.len() || last.hash_count() != filters.hash_count
            {
                return true;
            }
            match filters.excluded(peer) {
                Some(excluded) => !last
                    .as_bytes()
                    .iter()
                    .zip(&filters.combined)
                    .zip(&filters.shared)
                    .zip(excluded.as_bytes())
                    .all(|(((last, all), shared), excluded)| {
                        *last == *all & (!*excluded | *shared)
                    }),
                None => last.as_bytes() != filters.combined,
            }
        });
        if changed {
            state.mark_update_needed(*peer);
        }
    }
}

#[test]
fn word_comparison_matches_slice_equality_at_every_byte_and_alignment() {
    for len in [0, 1, 7, 8, 9, 31, 1024, 1027] {
        for offset in 0..8 {
            let mut left = vec![0; len + offset];
            for (index, byte) in left.iter_mut().enumerate() {
                *byte = index.wrapping_mul(73) as u8;
            }
            let left = &left[offset..];
            let mut right = left.to_vec();
            assert!(equal_filter_bytes(left, &right));
            for index in 0..len {
                right[index] ^= 0x80;
                assert_eq!(equal_filter_bytes(left, &right), left == right);
                right[index] ^= 0x80;
            }
            right.push(0);
            assert!(!equal_filter_bytes(left, &right));
        }
    }
}

fn fixture(
    count: usize,
    tree_count: usize,
    leaf_only: bool,
) -> (BloomState, Vec<NodeAddr>, HashMap<NodeAddr, BloomFilter>) {
    let peers: Vec<_> = (0..count).map(addr).collect();
    let mut state = BloomState::new(addr(10_000));
    state.set_leaf_only(leaf_only);
    state.add_leaf_dependent(addr(20_000));
    let inputs = peers
        .iter()
        .take(tree_count)
        .enumerate()
        .map(|(index, peer)| {
            let mut filter = BloomFilter::new();
            filter.insert(&addr(30_000 + index));
            filter.insert(&addr(40_000));
            (*peer, filter)
        })
        .collect();
    let prepared = state.prepare_outgoing_filters(&inputs);
    let sent: Vec<_> = peers
        .iter()
        .map(|peer| (*peer, prepared.for_peer(peer)))
        .collect();
    for (peer, filter) in sent {
        state.record_sent_filter(peer, filter);
        state.record_update_sent(peer, 100);
    }
    (state, peers, inputs)
}

fn assert_same_state(actual: &BloomState, original: &BloomState) {
    assert_eq!(actual.pending_updates, original.pending_updates);
    assert_eq!(
        actual.pending_update_deadlines,
        original.pending_update_deadlines
    );
    assert_eq!(
        actual.pending_update_deadline_ms,
        original.pending_update_deadline_ms
    );
    assert_eq!(actual.last_update_sent, original.last_update_sent);
    assert_eq!(actual.last_sent_filters, original.last_sent_filters);
    assert_eq!(actual.leaf_dependents, original.leaf_dependents);
    assert_eq!(actual.is_leaf_only, original.is_leaf_only);
    assert_eq!(actual.sequence, original.sequence);
}

#[test]
fn comparison_change_preserves_randomized_dirty_history_and_deadlines() {
    let mut random = 0x7a3c_1549_697d_813bu64;
    for count in [1, 12, 64] {
        let (mut actual, peers, mut inputs) = fixture(count, count / 3, false);
        let mut original = actual.clone();
        for step in 0..160 {
            random ^= random << 13;
            random ^= random >> 7;
            random ^= random << 17;
            let peer = peers[random as usize % count];
            let source = if step % 5 == 0 { addr(99_999) } else { peer };
            let dependent = addr(50_000 + step % 4);
            let now = 1_000 + step as u64;
            if step % 3 == 0 {
                let len = if step % 12 == 0 { 64 } else { 1024 };
                let mut bytes = vec![0; len];
                bytes[random as usize % len] = 1 << (step % 8);
                inputs.insert(
                    peer,
                    BloomFilter::from_bytes(bytes, if step % 9 == 0 { 3 } else { 5 }).unwrap(),
                );
            } else if step % 3 == 1 {
                inputs.remove(&peer);
            }
            for state in [&mut actual, &mut original] {
                match step % 12 {
                    0 => state.record_update_sent(peer, now),
                    1 => {
                        state.mark_update_needed(peer);
                        state.defer_update_retry(&peer, now + 5_000);
                    }
                    2 => state.clear_pending_updates(),
                    3 => state.remove_peer_state(&peer),
                    4 => state.set_leaf_only(!state.is_leaf_only()),
                    5 => state.add_leaf_dependent(dependent),
                    6 => {
                        state.remove_leaf_dependent(&dependent);
                    }
                    7 => state.set_update_debounce_ms(random % 1_000),
                    8 => state
                        .record_sent_filter(peer, BloomFilter::from_bytes(vec![0; 64], 3).unwrap()),
                    9 => {
                        let filter = state.compute_outgoing_filter(&peer, &inputs);
                        state.record_sent_filter(peer, filter);
                    }
                    10 => state.defer_pending_retries(now + 8_000),
                    _ => {}
                }
            }
            actual.mark_changed_peers(&source, &peers, &inputs);
            original_mark_changed_peers(&mut original, &source, &peers, &inputs);
            assert_same_state(&actual, &original);
        }
    }
}

#[test]
fn pending_skip_retains_retry_floor_and_source_dirtiness() {
    let (mut actual, peers, inputs) = fixture(12, 4, false);
    for peer in &peers[..3] {
        actual.mark_update_needed(*peer);
        actual.defer_update_retry(peer, 9_000);
    }
    actual.record_sent_filter(peers[1], BloomFilter::new());
    actual.remove_peer_state(&peers[4]); // Unsent must still become pending.
    let mut original = actual.clone();
    actual.mark_changed_peers(&peers[0], &peers, &inputs);
    original_mark_changed_peers(&mut original, &peers[0], &peers, &inputs);
    assert_same_state(&actual, &original);
    assert_eq!(actual.pending_peer_deadline_ms(&peers[0]), Some(9_000));
    assert_eq!(actual.pending_peer_deadline_ms(&peers[1]), Some(9_000));
    assert!(actual.needs_update(&peers[4]));
}

#[test]
#[ignore = "manual paired operation benchmark; not daemon or phone CPU acceptance"]
fn bloom_comparison_operation_benchmark() {
    use std::{hint::black_box, time::Instant};

    for position in [None, Some(0), Some(512), Some(1023)] {
        let left = vec![0x55; 1024];
        let mut right = left.clone();
        if let Some(position) = position {
            right[position] ^= 1;
        }
        let mut old = Vec::new();
        let mut new = Vec::new();
        for trial in 0..7 {
            for changed in [trial % 2 == 0, trial % 2 != 0] {
                let start = Instant::now();
                for _ in 0..20_000 {
                    let equal = if changed {
                        equal_filter_bytes(black_box(&left), black_box(&right))
                    } else {
                        black_box(left.as_slice()) == black_box(right.as_slice())
                    };
                    black_box(equal);
                }
                (if changed { &mut new } else { &mut old }).push(start.elapsed().as_nanos());
            }
        }
        old.sort_unstable();
        new.sort_unstable();
        println!(
            "bloom_bytes mismatch={position:?} calls=20000 original_ns={} changed_ns={}",
            old[3], new[3]
        );
    }

    for (count, tree_count, leaf) in [
        (12, 4, false),
        (480, 8, false),
        (480, 480, false),
        (480, 8, true),
    ] {
        for case in ["equal", "early", "late", "pending", "unsent"] {
            let (mut base, peers, inputs) = fixture(count, tree_count, leaf);
            if case == "pending" {
                base.mark_all_updates_needed(peers.iter().copied());
                base.defer_pending_retries(9_000);
            } else if case == "unsent" {
                for peer in &peers {
                    base.remove_peer_state(peer);
                }
            } else if case != "equal" {
                for peer in &peers {
                    let last = &base.last_sent_filters[peer];
                    let mut bytes = last.as_bytes().to_vec();
                    let index = if case == "early" { 0 } else { bytes.len() - 1 };
                    bytes[index] ^= 1;
                    base.record_sent_filter(*peer, BloomFilter::from_bytes(bytes, 5).unwrap());
                }
            }
            let mut old = Vec::new();
            let mut new = Vec::new();
            for trial in 0..101 {
                let mut original = base.clone();
                let mut actual = original.clone();
                for changed in [trial % 2 == 0, trial % 2 != 0] {
                    let start = Instant::now();
                    if changed {
                        actual.mark_changed_peers(
                            black_box(&peers[0]),
                            black_box(&peers),
                            black_box(&inputs),
                        );
                    } else {
                        original_mark_changed_peers(
                            &mut original,
                            black_box(&peers[0]),
                            black_box(&peers),
                            black_box(&inputs),
                        );
                    }
                    (if changed { &mut new } else { &mut old }).push(start.elapsed().as_nanos());
                }
                assert_same_state(&actual, &original);
            }
            old.sort_unstable();
            new.sort_unstable();
            println!(
                "bloom_mark peers={count} tree={tree_count} leaf={leaf} case={case} original_ns={} changed_ns={}",
                old[50], new[50]
            );
        }
    }
}
