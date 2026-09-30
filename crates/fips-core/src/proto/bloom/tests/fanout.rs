use super::*;

fn addr(index: usize) -> NodeAddr {
    NodeAddr::from_bytes((index as u128).to_le_bytes())
}

fn fixture(count: usize) -> (BloomState, Vec<NodeAddr>, HashMap<NodeAddr, BloomFilter>) {
    let mut state = BloomState::new(addr(10_000));
    for index in 0..16 {
        state.add_leaf_dependent(addr(20_000 + index));
    }
    let peers: Vec<_> = (0..count).map(addr).collect();
    let filters = peers
        .iter()
        .enumerate()
        .map(|(index, peer)| {
            let mut filter = BloomFilter::new();
            filter.insert(&addr(30_000 + index));
            // Both shared peer bits and overlap with the local base must survive
            // exclusion; only bits unique to the excluded peer may disappear.
            filter.insert(&addr(40_000 + index / 3));
            filter.insert(&addr(20_000 + index % 16));
            (*peer, filter)
        })
        .collect();
    (state, peers, filters)
}

fn remember(state: &mut BloomState, peers: &[NodeAddr], filters: &HashMap<NodeAddr, BloomFilter>) {
    for peer in peers {
        state.record_sent_filter(*peer, state.compute_outgoing_filter(peer, filters));
    }
    state.clear_pending_updates();
}

fn assert_changes(
    state: &mut BloomState,
    peers: &[NodeAddr],
    before: &HashMap<NodeAddr, BloomFilter>,
    after: &HashMap<NodeAddr, BloomFilter>,
    source: NodeAddr,
) {
    let expected: Vec<_> = peers
        .iter()
        .map(|peer| {
            *peer != source
                && state.compute_outgoing_filter(peer, before)
                    != state.compute_outgoing_filter(peer, after)
        })
        .collect();
    remember(state, peers, before);
    state.mark_changed_peers(&source, peers, after);
    for (peer, changed) in peers.iter().zip(expected) {
        assert_eq!(state.needs_update(peer), changed, "recipient {peer:?}");
    }
}

#[test]
fn all_recipient_bits_match_individual_filters_after_tree_inputs_change() {
    let (mut state, peers, filters) = fixture(180);
    let source = peers[0];
    assert_changes(&mut state, &peers, &filters, &filters, source);

    // Demotion/removal: this peer's filter is no longer a tree contribution.
    let mut changed = filters.clone();
    changed.remove(&peers[1]);
    assert_changes(&mut state, &peers, &filters, &changed, source);

    // Promotion/addition and changed bytes are re-evaluated on the next call.
    let previous = changed.clone();
    changed.insert(peers[1], BloomFilter::from_bytes(vec![1; 1024], 5).unwrap());
    changed.get_mut(&peers[2]).unwrap().insert(&addr(50_000));
    assert_changes(&mut state, &peers, &previous, &changed, source);

    // Existing merge semantics ignore incompatible sizes, including when the
    // incompatible contribution belongs to the destination being excluded.
    let previous = changed.clone();
    changed.insert(peers[3], BloomFilter::with_params(512, 5).unwrap());
    assert_changes(&mut state, &peers, &previous, &changed, source);

    // merge() historically checks size, not the incoming hash count.
    let previous = changed.clone();
    changed.insert(peers[4], BloomFilter::from_bytes(vec![2; 1024], 3).unwrap());
    assert_changes(&mut state, &peers, &previous, &changed, source);
}

#[test]
fn peer_exclusion_retains_shared_and_local_bits_and_detects_every_bit_change() {
    let (mut state, peers, filters) = fixture(7);
    let source = addr(99);
    for peer in &peers {
        let expected = state.compute_outgoing_filter(peer, &filters);
        // Comparing every byte catches removal of shared/base bits as well as
        // accidental inclusion of a recipient's unique contribution.
        for byte in 0..expected.num_bytes() {
            remember(&mut state, &peers, &filters);
            let mut different = expected.as_bytes().to_vec();
            different[byte] ^= 1 << (byte % 8);
            state.record_sent_filter(*peer, BloomFilter::from_bytes(different, 5).unwrap());
            state.mark_changed_peers(&source, &peers, &filters);
            for recipient in &peers {
                assert_eq!(state.needs_update(recipient), recipient == peer);
            }
        }
    }
}

#[test]
fn base_changes_and_preexisting_pending_updates_remain_visible() {
    let (mut state, peers, filters) = fixture(12);
    remember(&mut state, &peers, &filters);
    state.add_leaf_dependent(addr(90_000));
    state.mark_changed_peers(&peers[0], &peers, &filters);
    assert!(!state.needs_update(&peers[0]));
    for peer in &peers[1..] {
        assert!(state.needs_update(peer));
    }
    remember(&mut state, &peers, &filters);
    state.mark_update_needed(peers[0]);
    state.mark_update_needed(peers[1]);
    state.mark_changed_peers(&peers[0], &peers, &filters);
    assert!(
        state.needs_update(&peers[0]),
        "source exclusion preserves pending work"
    );
    assert!(
        state.needs_update(&peers[1]),
        "unchanged filter preserves pending work"
    );
    assert!(peers[2..].iter().all(|peer| !state.needs_update(peer)));

    remember(&mut state, &peers, &filters);
    let correct = state.compute_outgoing_filter(&peers[1], &filters);
    state.record_sent_filter(
        peers[1],
        BloomFilter::from_bytes(correct.as_bytes().to_vec(), 3).unwrap(),
    );
    state.mark_changed_peers(&peers[0], &peers, &filters);
    assert!(
        state.needs_update(&peers[1]),
        "outgoing hash count still matters"
    );
}

#[test]
#[ignore = "manual same-workload Bloom fanout timing"]
fn bloom_fanout_benchmark() {
    use std::{hint::black_box, time::Instant};

    for count in [12, 180, 425] {
        for changed_burst in [false, true] {
            let (mut state, peers, mut filters) = fixture(count);
            remember(&mut state, &peers, &filters);
            let union = state.compute_outgoing_filter(&addr(99_999), &filters);
            let new_bits: Vec<_> = (0..union.num_bits())
                .filter(|bit| union.as_bytes()[bit / 8] & (1 << (bit % 8)) == 0)
                .take(5)
                .collect();
            let mut samples = Vec::new();
            for bit in new_bits {
                if changed_burst {
                    let mut incoming = filters[&peers[0]].as_bytes().to_vec();
                    incoming[bit / 8] |= 1 << (bit % 8);
                    filters.insert(peers[0], BloomFilter::from_bytes(incoming, 5).unwrap());
                }
                let start = Instant::now();
                state.mark_changed_peers(
                    black_box(&peers[0]),
                    black_box(&peers),
                    black_box(&filters),
                );
                samples.push(start.elapsed().as_nanos());
                assert!(!state.needs_update(&peers[0]));
                assert!(
                    peers[1..]
                        .iter()
                        .all(|peer| state.needs_update(peer) == changed_burst)
                );
            }
            samples.sort_unstable();
            println!(
                "bloom_fanout peers={count} tree_filters={count} leaves=16 changed_burst={changed_burst} samples_ns={samples:?} median_ns={}",
                samples[2]
            );
        }
    }
}
