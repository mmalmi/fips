//! Explicit microbenchmark of production admission over populated native state.
//! Setup, crypto, transport discovery and packet movement are outside timing.
use super::*;
use crate::config::NeighborRotationConfig;
use crate::dataplane::{
    ActivityTick, DataplaneAuthenticatedFspSession, DataplaneFspWrapRoute,
    DataplaneLiveOwnerRoutes, FspReceiveSync, OwnerConfig, OwnerId,
};
use crate::node::endpoint_channels::EndpointDataPayload;
use crate::peer::{ActivePeer, PeerConnection};
use crate::protocol::SessionMessageType;
use crate::{Config, Identity, PeerIdentity};
use std::{hint::black_box, time::Instant};

const CANDIDATES: usize = 64;
const SAMPLES: usize = 7;
const NOW_MS: u64 = 100_000;

#[derive(Clone, Copy, Debug)]
enum State {
    Idle,
    Receiving,
    Transit,
    Cooldown,
    OtherPending,
    Disabled,
}

fn address(value: usize) -> NodeAddr {
    let mut bytes = [0xA5; 16];
    bytes[8..].copy_from_slice(&(value as u64).to_be_bytes());
    NodeAddr::from_bytes(bytes)
}

fn populated(peers: usize, sessions: usize, state: State) -> Node {
    let mut config = Config::new();
    config.node.identity.persistent = false;
    config.node.limits.max_peers = peers;
    config.node.neighbor_rotation = Some(NeighborRotationConfig {
        idle_secs: 30,
        interval_secs: 10,
    });
    let mut node = Node::new(config).unwrap();
    let mut neighbors = Vec::new();
    for index in 1..=peers {
        let identity = Identity::from_secret_bytes(&[index as u8; 32]).unwrap();
        let peer = PeerIdentity::from_pubkey_full(identity.pubkey_full());
        let addr = *peer.node_addr();
        node.peers
            .insert(addr, ActivePeer::new(peer, LinkId::new(index as u64), 1));
        if matches!(state, State::Transit) {
            node.record_peer_transit_demand(&addr, NOW_MS);
        }
        neighbors.push(addr);
    }
    for index in 0..sessions {
        let dest = address(index);
        node.dataplane
            .register_owner(OwnerId::fsp_node(dest), OwnerConfig::new(1, 8));
        let at = if matches!(state, State::Receiving) {
            NOW_MS
        } else {
            1
        };
        assert!(
            node.dataplane
                .record_authenticated_fsp_session(DataplaneAuthenticatedFspSession::new(
                    dest,
                    neighbors[index % peers],
                    SessionMessageType::EndpointData.to_byte(),
                    8,
                    FspReceiveSync {
                        counter: 1,
                        received_k_bit: false,
                        timestamp: 0,
                        plaintext_len: 900,
                        ce_flag: false,
                        path_mtu: u16::MAX,
                        spin_bit: false,
                    },
                    Some(ActivityTick::new(at)),
                    Instant::now(),
                ))
                .is_some()
        );
    }
    match state {
        State::Cooldown => node.neighbor_rotation.next_attempt_ms = NOW_MS + 10_000,
        State::OtherPending => {
            let key = Identity::from_secret_bytes(&[200; 32]).unwrap();
            let identity = PeerIdentity::from_pubkey_full(key.pubkey_full());
            let link = LinkId::new(1000);
            node.neighbor_rotation.attempt = Some(Attempt {
                peer: *identity.node_addr(),
                started_ms: NOW_MS,
                deadline_ms: NOW_MS.saturating_add(
                    node.config
                        .node
                        .rate_limit
                        .handshake_timeout_secs
                        .saturating_mul(1000),
                ),
                is_retry: false,
                confirmed_inbound: None,
            });
            node.peers
                .insert_connection(link, PeerConnection::outbound(link, identity, NOW_MS));
        }
        State::Disabled => node.config.node.neighbor_rotation = None,
        _ => {}
    }
    assert_eq!(node.peer_count(), peers);
    assert_eq!(node.dataplane.fsp_owner_destinations().len(), sessions);
    node
}

fn cpu_ns() -> u64 {
    let mut value = std::mem::MaybeUninit::<libc::timespec>::uninit();
    // SAFETY: the CPU clock writes this valid timespec; read only after success.
    assert_eq!(
        unsafe { libc::clock_gettime(libc::CLOCK_THREAD_CPUTIME_ID, value.as_mut_ptr()) },
        0
    );
    let value = unsafe { value.assume_init() };
    u64::try_from(value.tv_sec).unwrap() * 1_000_000_000 + u64::try_from(value.tv_nsec).unwrap()
}

fn query(node: &Node, candidates: &[NodeAddr], batches: usize) -> (u64, u64, usize) {
    let wall_start = Instant::now();
    let cpu_start = cpu_ns();
    let mut allowed = 0;
    for _ in 0..batches {
        for candidate in candidates {
            allowed += usize::from(black_box(node).can_attempt_neighbor_rotation(
                black_box(candidate),
                true,
                black_box(NOW_MS),
            ));
        }
    }
    let cpu = cpu_ns() - cpu_start;
    (
        cpu,
        wall_start.elapsed().as_nanos() as u64,
        black_box(allowed),
    )
}

#[test]
#[ignore = "explicit CPU benchmark; use --release --ignored --exact --nocapture"]
fn admission_cpu_by_roster_and_session_count() {
    assert!(
        !black_box(cfg!(debug_assertions)),
        "measure an optimized release build"
    );
    let candidates: Vec<_> = (20_000..20_000 + CANDIDATES).map(address).collect();
    for (peers, sessions) in [(2, 0), (8, 64), (32, 256), (128, 1024)] {
        for state in [
            State::Idle,
            State::Receiving,
            State::Transit,
            State::Cooldown,
            State::OtherPending,
            State::Disabled,
        ] {
            if sessions == 0 && matches!(state, State::Receiving) {
                continue;
            }
            let node = populated(peers, sessions, state);
            let expected = matches!(state, State::Idle);
            let mut batches = 1;
            // Calibrate only repetition count. State, identities and the fixed
            // policy time do not mutate between samples or with faster code.
            while query(&node, &candidates, batches).0 < 10_000_000 && batches < 1024 {
                batches *= 2;
            }
            let mut cpu = Vec::new();
            let mut wall = Vec::new();
            for _ in 0..SAMPLES {
                let (cpu_ns, wall_ns, allowed) = query(&node, &candidates, batches);
                assert_eq!(allowed, if expected { batches * CANDIDATES } else { 0 });
                cpu.push(cpu_ns / (batches * CANDIDATES) as u64);
                wall.push(wall_ns / (batches * CANDIDATES) as u64);
            }
            cpu.sort_unstable();
            wall.sort_unstable();
            eprintln!(
                "rotation-admission-cpu {}",
                serde_json::json!({
                    "peers": peers, "sessions": sessions, "state": format!("{state:?}"),
                    "candidates_per_batch": CANDIDATES, "batches_per_sample": batches,
                    "samples": SAMPLES, "allowed_per_batch": if expected {CANDIDATES} else {0},
                    "cpu_ns_per_candidate_median": cpu[SAMPLES / 2],
                    "cpu_ns_per_candidate_max": cpu[SAMPLES - 1],
                    "wall_ns_per_candidate_median": wall[SAMPLES / 2],
                })
            );
            assert_eq!(node.peer_count(), peers);
        }
    }
}

/// Post-admission queue/route metadata only: this setup is not evidence of
/// authenticated delivery. Every miss maps to a carrier outside the measured
/// candidate set, so old direct-only and carrier-aware policies agree.
fn queued_discovery_node(queued: usize, direct_hits: bool) -> Node {
    let mut node = populated(2, 0, State::Idle);
    let max_destinations = node.config.node.session.pending_max_destinations;
    let packets_per_dest = node.config.node.session.pending_packets_per_dest;
    assert_eq!(max_destinations, 256);
    assert!(queued <= 2 * max_destinations);
    for index in 0..queued {
        let destination = address(if direct_hits { 20_000 + index } else { index });
        let admission = if index < max_destinations {
            node.pending_session_traffic.push_tun_packet(
                destination,
                vec![1],
                max_destinations,
                packets_per_dest,
                Some(NOW_MS),
            )
        } else {
            node.pending_session_traffic
                .push_endpoint_data_batch_with_enqueued_at_ms(
                    destination,
                    vec![EndpointDataPayload::from_packet_payload(vec![1]).unwrap()],
                    max_destinations,
                    packets_per_dest,
                    NOW_MS,
                )
        };
        assert!(!admission.destination_dropped());
        assert!(!admission.dropped_oldest());
        if direct_hits {
            continue;
        }
        let carrier = address(10_000 + index);
        if index < 64 {
            node.source_routes.insert(destination, carrier);
        } else {
            let owner = OwnerId::fsp_node(destination);
            node.dataplane.register_owner(owner, OwnerConfig::new(1, 8));
            node.dataplane
                .replace_owner_fsp_routes(
                    owner,
                    DataplaneLiveOwnerRoutes::default(),
                    Some(DataplaneFspWrapRoute::new(
                        OwnerId::fmp_node(carrier),
                        1,
                        2,
                        *node.node_addr(),
                        destination,
                    )),
                    None,
                )
                .unwrap();
            assert_eq!(
                node.dataplane.fsp_owner_next_hop(&destination),
                Some(carrier)
            );
        }
    }
    assert_eq!(node.pending_session_traffic.destinations().count(), queued);
    assert_eq!(
        node.source_routes.len(),
        if direct_hits { 0 } else { queued.min(64) }
    );
    assert_eq!(
        node.dataplane.fsp_owner_destinations().len(),
        if direct_hits {
            0
        } else {
            queued.saturating_sub(64)
        }
    );
    node
}

fn discovery_query(node: &Node, candidates: &[NodeAddr], batches: usize) -> (u64, u64, u64) {
    let wall_start = Instant::now();
    let cpu_start = cpu_ns();
    let mut checksum = 0u64;
    for _ in 0..batches {
        for candidate in candidates {
            let key = black_box(
                black_box(node)
                    .neighbor_rotation_discovery_order(black_box(*candidate), black_box(NOW_MS)),
            );
            checksum = checksum.wrapping_add(
                u64::from(key.0)
                    + 2 * u64::from(key.1)
                    + 4 * u64::from(key.2.0)
                    + u64::from(key.2.1.as_bytes()[15]),
            );
        }
    }
    let cpu = cpu_ns() - cpu_start;
    (
        cpu,
        wall_start.elapsed().as_nanos() as u64,
        black_box(checksum),
    )
}

#[test]
#[ignore = "explicit CPU benchmark; use --release --ignored --exact --nocapture"]
fn discovery_key_cpu_by_queued_destination_count() {
    assert!(
        !black_box(cfg!(debug_assertions)),
        "measure an optimized release build"
    );
    let candidates: Vec<_> = (20_000..20_000 + CANDIDATES).map(address).collect();
    for (queued, direct_hits) in [(0, false), (64, false), (512, false), (64, true)] {
        let node = queued_discovery_node(queued, direct_hits);
        let mut expected_per_batch = 0u64;
        for candidate in &candidates {
            assert_eq!(
                node.neighbor_rotation_discovery_order(*candidate, NOW_MS),
                (true, !direct_hits, (false, *candidate))
            );
            expected_per_batch +=
                1 + 2 * u64::from(!direct_hits) + u64::from(candidate.as_bytes()[15]);
        }
        let mut batches = 1;
        // Bound calibration even on extremely fast clocks. Neither the fixed
        // policy time nor the queue, cursor or carrier state changes here.
        while discovery_query(&node, &candidates, batches).0 < 10_000_000 && batches < 262_144 {
            batches *= 2;
        }
        let mut cpu = Vec::new();
        let mut wall = Vec::new();
        for _ in 0..SAMPLES {
            let (cpu_ns, wall_ns, checksum) = discovery_query(&node, &candidates, batches);
            assert_eq!(checksum, expected_per_batch * batches as u64);
            cpu.push(cpu_ns as f64 / batches as f64);
            wall.push(wall_ns as f64 / batches as f64);
        }
        cpu.sort_by(f64::total_cmp);
        wall.sort_by(f64::total_cmp);
        eprintln!(
            "rotation-discovery-key-cpu {}",
            serde_json::json!({
                "queued_destinations": queued, "direct_hits": direct_hits,
                "explicit_bindings": node.source_routes.len(),
                "installed_fsp_carriers": node.dataplane.fsp_owner_destinations().len(),
                "candidates_per_batch": CANDIDATES, "batches_per_sample": batches,
                "samples": SAMPLES, "checksum_per_batch": expected_per_batch,
                "cpu_ns_per_key_median": cpu[SAMPLES / 2] / CANDIDATES as f64,
                "cpu_ns_per_key_max": cpu[SAMPLES - 1] / CANDIDATES as f64,
                "cpu_ns_per_64_keys_median": cpu[SAMPLES / 2],
                "cpu_ns_per_64_keys_max": cpu[SAMPLES - 1],
                "wall_ns_per_key_median": wall[SAMPLES / 2] / CANDIDATES as f64,
                "wall_ns_per_64_keys_median": wall[SAMPLES / 2],
                "includes": "key evaluation, black_box and checksum; setup excluded"
            })
        );
        assert_eq!(node.pending_session_traffic.destinations().count(), queued);
    }
}
