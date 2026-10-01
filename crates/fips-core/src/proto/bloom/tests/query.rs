use super::*;
use sha2::{Digest, Sha256};

// Independent pre-optimization membership formula; do not call either query API.
fn expected(filter: &BloomFilter, data: &[u8]) -> bool {
    let digest = Sha256::digest(data);
    let first = u64::from_le_bytes(digest[..8].try_into().unwrap());
    let second = u64::from_le_bytes(digest[8..16].try_into().unwrap());
    (0..filter.hash_count()).all(|index| {
        let bit =
            first.wrapping_add(u64::from(index).wrapping_mul(second)) as usize % filter.num_bits();
        filter.as_bytes()[bit / 8] & (1 << (bit % 8)) != 0
    })
}

#[test]
fn shared_hash_matches_membership_with_each_filters_own_parameters() {
    let mut filters = Vec::new();
    for bits in [8, 24, 256, 8192, 32768] {
        for hashes in [1, 3, 5, 7, 255] {
            let mut filter = BloomFilter::with_params(bits, hashes).unwrap();
            for value in (0..64).step_by(3) {
                filter.insert(&make_node_addr(value));
            }
            filters.push(filter);
        }
    }
    for value in 0..96 {
        let target = make_node_addr(value);
        let pair = BloomFilter::hash_pair(target.as_bytes());
        for filter in &filters {
            let oracle = expected(filter, target.as_bytes());
            assert_eq!(filter.contains_hash_pair(pair), oracle);
            assert_eq!(filter.contains(&target), oracle);
            if value < 64 && value % 3 == 0 {
                assert!(oracle, "inserted targets cannot become false negatives");
            }
        }
    }
}

#[test]
fn shared_hash_preserves_raw_byte_queries_and_empty_or_saturated_filters() {
    for data in [b"".as_slice(), b"a", &[0xa5; 16], &[0x39; 129]] {
        let pair = BloomFilter::hash_pair(data);
        for bits in [8, 2048, 8192] {
            for hashes in [1, 5, 255] {
                for fill in [0, 0x5a, 0xff] {
                    let filter = BloomFilter::from_bytes(vec![fill; bits / 8], hashes).unwrap();
                    let oracle = expected(&filter, data);
                    assert_eq!(filter.contains_hash_pair(pair), oracle);
                    assert_eq!(filter.contains_bytes(data), oracle);
                    if fill == 0 || fill == 0xff {
                        assert_eq!(oracle, fill != 0);
                    }
                }
            }
        }
    }
}
