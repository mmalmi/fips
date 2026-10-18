use super::*;
use crate::packet_channel;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

const LOW_FD_CHURN_CHILD: &str = "FIPS_WEBRTC_LOW_FD_CHURN_CHILD";
const CANONICAL_CHURN_CYCLES: usize = 513;
const FD_LIMIT: libc::rlim_t = 128;
const FD_PEAK_LIMIT: usize = 102;
const FD_QUIESCENT_DELTA: usize = 8;
const FD_SETTLE_DEADLINE: Duration = Duration::from_secs(5);

#[derive(Clone, Copy, Debug, Default)]
struct OpenFileModes {
    socket: usize,
    fifo: usize,
    character: usize,
    regular: usize,
    other: usize,
}

struct ChurnPeers<'a> {
    churn_identity: &'a crate::Identity,
    stable_identity: &'a crate::Identity,
    churn_addr: &'a TransportAddr,
    stable_addr: &'a TransportAddr,
}

async fn initial_negotiation_with_signal_loss(
    drop_kind: Option<LinkNegotiationKind>,
    duplicate_answer: bool,
) {
    let (initiator_identity, responder_identity) = ordered_identities();
    let initiator_addr = identity_addr(&initiator_identity);
    let responder_addr = identity_addr(&responder_identity);
    let config = WebRtcConfig {
        accept_connections: Some(true),
        max_connections: Some(1),
        connect_timeout_ms: Some(4_000),
        ice_gather_timeout_ms: Some(250),
        resolve_mdns_candidates: Some(false),
        stun_servers: Some(Vec::new()),
        ..WebRtcConfig::default()
    };
    let (mut initiator, mut initiator_rx) = new_transport(81, &initiator_identity, &config);
    let (mut responder, mut responder_rx) = new_transport(82, &responder_identity, &config);
    initiator.start_async().await.expect("start initiator");
    responder.start_async().await.expect("start responder");
    initiator
        .connect_async(&responder_addr)
        .await
        .expect("begin initial negotiation");

    let mut dropped = false;
    let connected =
        tokio::time::timeout(Duration::from_millis(config.connect_timeout_ms()), async {
            loop {
                for reverse in [false, true] {
                    let (source, destination, identity) = if reverse {
                        (&mut responder, &mut initiator, &responder_identity)
                    } else {
                        (&mut initiator, &mut responder, &initiator_identity)
                    };
                    for outbound in source.drain_link_negotiations(16) {
                        let message =
                            LinkNegotiationMessage::decode(&outbound.payload).expect("SDP signal");
                        assert_canonical_loopback_candidate_profile(&message);
                        if !dropped && drop_kind.as_ref() == Some(&message.kind) {
                            dropped = true;
                            continue;
                        }
                        if duplicate_answer && message.kind == LinkNegotiationKind::Answer {
                            destination
                                .ingest_link_negotiation(identity.pubkey_full(), message.clone())
                                .expect("deliver duplicate answer");
                        }
                        destination
                            .ingest_link_negotiation(identity.pubkey_full(), message)
                            .expect("deliver remaining signal");
                    }
                }
                if initiator.connection_state_sync(&responder_addr) == ConnectionState::Connected
                    && responder.connection_state_sync(&initiator_addr)
                        == ConnectionState::Connected
                {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(2)).await;
            }
        })
        .await;
    if connected.is_ok() {
        assert_round_trip(
            &initiator,
            &responder,
            &mut initiator_rx,
            &mut responder_rx,
            &initiator_addr,
            &responder_addr,
            0,
        )
        .await;
    }
    initiator.stop_async().await.expect("stop initiator");
    responder.stop_async().await.expect("stop responder");
    wait_for_resource_quiescence(&[&initiator, &responder]).await;
    assert_eq!(
        dropped,
        drop_kind.is_some(),
        "the selected loss was exercised"
    );
    assert!(
        connected.is_ok(),
        "initial negotiation must survive one missing {drop_kind:?} signal within its original deadline"
    );
}

#[tokio::test]
async fn initial_negotiation_without_signal_loss() {
    initial_negotiation_with_signal_loss(None, false).await;
}

#[tokio::test]
async fn initial_negotiation_survives_first_offer_loss() {
    initial_negotiation_with_signal_loss(Some(LinkNegotiationKind::Offer), false).await;
}

#[tokio::test]
async fn initial_negotiation_survives_first_answer_loss() {
    initial_negotiation_with_signal_loss(Some(LinkNegotiationKind::Answer), false).await;
}

#[tokio::test]
async fn initial_negotiation_accepts_duplicate_answer() {
    initial_negotiation_with_signal_loss(None, true).await;
}

#[tokio::test]
async fn initial_negotiation_stops_retransmitting_after_stop() {
    let (identity, remote) = ordered_identities();
    let config = WebRtcConfig {
        max_connections: Some(1),
        connect_timeout_ms: Some(4_000),
        ice_gather_timeout_ms: Some(250),
        resolve_mdns_candidates: Some(false),
        stun_servers: Some(Vec::new()),
        ..WebRtcConfig::default()
    };
    let (mut transport, _rx) = new_transport(83, &identity, &config);
    transport.start_async().await.expect("start transport");
    transport
        .connect_async(&identity_addr(&remote))
        .await
        .expect("begin negotiation");
    let _offer = take_link_negotiation(&mut transport, LinkNegotiationKind::Offer).await;
    transport
        .stop_async()
        .await
        .expect("stop pending negotiation");
    wait_for_resource_quiescence(&[&transport]).await;
    transport.drain_link_negotiations(16);
    tokio::time::sleep(Duration::from_millis(600)).await;
    assert!(transport.drain_link_negotiations(16).is_empty());
    assert_resource_quiescent(&transport);
}

#[tokio::test]
async fn fresh_replacement_with_one_slot_finishes_inside_connect_timeout() {
    let (churn_identity, stable_identity) = ordered_identities();
    let churn_addr = identity_addr(&churn_identity);
    let stable_addr = identity_addr(&stable_identity);
    let peers = ChurnPeers {
        churn_identity: &churn_identity,
        stable_identity: &stable_identity,
        churn_addr: &churn_addr,
        stable_addr: &stable_addr,
    };
    let config = WebRtcConfig {
        accept_connections: Some(true),
        max_connections: Some(1),
        connect_timeout_ms: Some(2_000),
        ice_gather_timeout_ms: Some(250),
        stun_servers: Some(Vec::new()),
        ..WebRtcConfig::default()
    };
    let (mut churn_a, _churn_a_rx) = new_transport(66, &churn_identity, &config);
    let (mut churn_b, mut churn_b_rx) = new_transport(67, &churn_identity, &config);
    let (mut stable, mut stable_rx) = new_transport(68, &stable_identity, &config);
    churn_a.start_async().await.expect("start churn A");
    churn_b.start_async().await.expect("start churn B");
    stable.start_async().await.expect("start stable peer");

    reconnect(
        &mut churn_a,
        &mut stable,
        &peers,
        "focused initial connection",
    )
    .await;
    tokio::time::timeout(
        Duration::from_millis(config.connect_timeout_ms()),
        fresh_replace(
            &churn_a,
            &mut churn_b,
            &mut stable,
            &peers,
            "focused fresh replacement",
        ),
    )
    .await
    .expect("fresh replacement stays inside the configured connection timeout");
    assert_round_trip(
        &churn_b,
        &stable,
        &mut churn_b_rx,
        &mut stable_rx,
        &churn_addr,
        &stable_addr,
        0,
    )
    .await;

    churn_b.close_connection_async(&stable_addr).await;
    stable.close_connection_async(&churn_addr).await;
    wait_for_resource_quiescence(&[&churn_a, &churn_b, &stable]).await;
    churn_a.stop_async().await.expect("stop churn A");
    churn_b.stop_async().await.expect("stop churn B");
    stable.stop_async().await.expect("stop stable peer");
}

#[tokio::test]
#[ignore = "release-only repeated one-slot WebRTC replacement timing"]
async fn repeated_fresh_replacements_stay_inside_the_original_connect_deadline() {
    const REPLACEMENTS: usize = 129;
    let (churn_identity, stable_identity) = ordered_identities();
    let churn_addr = identity_addr(&churn_identity);
    let stable_addr = identity_addr(&stable_identity);
    let peers = ChurnPeers {
        churn_identity: &churn_identity,
        stable_identity: &stable_identity,
        churn_addr: &churn_addr,
        stable_addr: &stable_addr,
    };
    let config = WebRtcConfig {
        accept_connections: Some(true),
        max_connections: Some(1),
        connect_timeout_ms: Some(2_000),
        ice_gather_timeout_ms: Some(250),
        stun_servers: Some(Vec::new()),
        ..WebRtcConfig::default()
    };
    let (mut churn_a, _churn_a_rx) = new_transport(91, &churn_identity, &config);
    let (mut churn_b, _churn_b_rx) = new_transport(92, &churn_identity, &config);
    let (mut stable, _stable_rx) = new_transport(93, &stable_identity, &config);
    assert!(churn_a.stun_servers.is_empty());
    assert!(churn_b.stun_servers.is_empty());
    assert!(stable.stun_servers.is_empty());
    churn_a.start_async().await.expect("start churn A");
    churn_b.start_async().await.expect("start churn B");
    stable.start_async().await.expect("start stable peer");
    reconnect(
        &mut churn_a,
        &mut stable,
        &peers,
        "repeated replacement initial connection",
    )
    .await;

    let mut active_a = true;
    for replacement in 0..REPLACEMENTS {
        let context = format!("repeated replacement {replacement}");
        let replacement_result = if active_a {
            tokio::time::timeout(
                Duration::from_millis(config.connect_timeout_ms()),
                fresh_replace(
                    &churn_a,
                    &mut churn_b,
                    &mut stable,
                    &peers,
                    &context,
                ),
            )
            .await
        } else {
            tokio::time::timeout(
                Duration::from_millis(config.connect_timeout_ms()),
                fresh_replace(
                    &churn_b,
                    &mut churn_a,
                    &mut stable,
                    &peers,
                    &context,
                ),
            )
            .await
        };
        if replacement_result.is_err() {
            let (old, replacement_transport) = if active_a {
                (&churn_a, &churn_b)
            } else {
                (&churn_b, &churn_a)
            };
            let replacement_state =
                transport_failure_state(replacement_transport, &stable_addr).await;
            let stable_state = transport_failure_state(&stable, &churn_addr).await;
            panic!(
                "fresh replacement {replacement} exceeded the original 2s deadline: oldResources={:?} replacement=[{replacement_state}] stable=[{stable_state}]",
                old.resource_snapshot()
            );
        }
        active_a = !active_a;
    }

    let active = if active_a { &churn_a } else { &churn_b };
    active.close_connection_async(&stable_addr).await;
    stable.close_connection_async(&churn_addr).await;
    wait_for_resource_quiescence(&[&churn_a, &churn_b, &stable]).await;
    churn_a.stop_async().await.expect("stop churn A");
    churn_b.stop_async().await.expect("stop churn B");
    stable.stop_async().await.expect("stop stable peer");
}

#[tokio::test]
async fn established_on_open_callbacks_release_maps_after_direct_drop() {
    let (churn_identity, stable_identity) = ordered_identities();
    let churn_addr = identity_addr(&churn_identity);
    let stable_addr = identity_addr(&stable_identity);
    let peers = ChurnPeers {
        churn_identity: &churn_identity,
        stable_identity: &stable_identity,
        churn_addr: &churn_addr,
        stable_addr: &stable_addr,
    };
    let config = WebRtcConfig {
        accept_connections: Some(true),
        max_connections: Some(1),
        connect_timeout_ms: Some(2_000),
        ice_gather_timeout_ms: Some(250),
        stun_servers: Some(Vec::new()),
        ..WebRtcConfig::default()
    };
    let (mut churn, _churn_rx) = new_transport(64, &churn_identity, &config);
    let (mut stable, _stable_rx) = new_transport(65, &stable_identity, &config);
    churn.start_async().await.expect("start churn peer");
    stable.start_async().await.expect("start stable peer");
    reconnect(
        &mut churn,
        &mut stable,
        &peers,
        "focused on-open Drop",
    )
    .await;

    let weak_churn_pool = Arc::downgrade(&churn.pool);
    let weak_churn_ready = Arc::downgrade(&churn.ready);
    let weak_stable_pool = Arc::downgrade(&stable.pool);
    let weak_stable_ready = Arc::downgrade(&stable.ready);
    let churn_resources = churn.physical.clone();
    let stable_resources = stable.physical.clone();
    drop(churn);
    drop(stable);

    tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            if weak_churn_pool.upgrade().is_none()
                && weak_churn_ready.upgrade().is_none()
                && weak_stable_pool.upgrade().is_none()
                && weak_stable_ready.upgrade().is_none()
            {
                return;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("on-open callbacks release owner maps after direct Drop");
    assert!(
        churn_resources
            .wait_for_quiescence(Duration::from_secs(3))
            .await
    );
    assert!(
        stable_resources
            .wait_for_quiescence(Duration::from_secs(3))
            .await
    );
}

#[test]
#[ignore = "release-only low-RLIMIT WebRTC FD soak"]
fn webrtc_physical_connections_survive_low_fd_reconnect_churn() {
    if std::env::var_os(LOW_FD_CHURN_CHILD).is_some() {
        set_open_file_limit(FD_LIMIT);
        assert_no_open_files_above_limit();
        let (process_baseline, process_baseline_modes) = open_file_snapshot();
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("Tokio runtime");
        let runtime_baseline = open_file_snapshot().0;
        runtime.block_on(run_low_fd_reconnect_churn(runtime_baseline));
        drop(runtime);

        let (runtime_final, runtime_settle) = settle_fd_count(process_baseline);
        let runtime_final_modes = open_file_snapshot().1;
        eprintln!(
            "WebRTC API/runtime teardown: baseline={process_baseline} baselineModes={process_baseline_modes:?} settleSamples={runtime_settle:?} final={runtime_final} finalModes={runtime_final_modes:?}"
        );
        assert!(
            runtime_final <= process_baseline + FD_QUIESCENT_DELTA,
            "API/runtime teardown FD count {runtime_final} must return within {FD_QUIESCENT_DELTA} of cold baseline {process_baseline}"
        );
        return;
    }

    let output = std::process::Command::new(std::env::current_exe().expect("test binary"))
        .arg("webrtc_physical_connections_survive_low_fd_reconnect_churn")
        .arg("--ignored")
        .arg("--nocapture")
        .arg("--test-threads=1")
        .env(LOW_FD_CHURN_CHILD, "1")
        .output()
        .expect("isolated low-FD child process");
    eprint!("{}", String::from_utf8_lossy(&output.stderr));
    assert!(
        output.status.success(),
        "low-FD WebRTC child failed:\n{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn set_open_file_limit(limit: libc::rlim_t) {
    let mut limits = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: the isolated child is single-threaded and `limits` is initialized.
    assert_eq!(unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut limits) }, 0);
    assert!(limits.rlim_max >= limit, "hard open-file limit is below {limit}");
    limits.rlim_cur = limit;
    assert_eq!(unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &limits) }, 0);
    assert_eq!(unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut limits) }, 0);
    assert_eq!(limits.rlim_cur, limit);
}

fn assert_no_open_files_above_limit() {
    for fd in FD_LIMIT as i32..4_096 {
        // SAFETY: F_GETFD only inspects the integer descriptor.
        assert_eq!(
            unsafe { libc::fcntl(fd, libc::F_GETFD) },
            -1,
            "isolated low-FD child inherited descriptor {fd} above its soft limit"
        );
    }
}

fn open_file_snapshot() -> (usize, OpenFileModes) {
    let mut modes = OpenFileModes::default();
    let mut count = 0;
    for fd in 0..FD_LIMIT as i32 {
        // SAFETY: `stat` is initialized before a successful `fstat` writes it.
        let mut stat = unsafe { std::mem::zeroed::<libc::stat>() };
        // SAFETY: `stat` points to valid writable storage for this call.
        if unsafe { libc::fstat(fd, &mut stat) } != 0 {
            continue;
        }
        count += 1;
        match stat.st_mode & libc::S_IFMT {
            libc::S_IFSOCK => modes.socket += 1,
            libc::S_IFIFO => modes.fifo += 1,
            libc::S_IFCHR => modes.character += 1,
            libc::S_IFREG => modes.regular += 1,
            _ => modes.other += 1,
        }
    }
    (count, modes)
}

fn settle_fd_count(baseline: usize) -> (usize, Vec<(u128, usize, OpenFileModes)>) {
    let started = std::time::Instant::now();
    let mut samples = Vec::new();
    loop {
        let (count, modes) = open_file_snapshot();
        samples.push((started.elapsed().as_millis(), count, modes));
        if count <= baseline + FD_QUIESCENT_DELTA || started.elapsed() >= FD_SETTLE_DEADLINE {
            return (count, samples);
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

async fn run_low_fd_reconnect_churn(runtime_baseline: usize) {
    let (churn_identity, stable_identity) = ordered_identities();
    let churn_addr = identity_addr(&churn_identity);
    let stable_addr = identity_addr(&stable_identity);
    let peers = ChurnPeers {
        churn_identity: &churn_identity,
        stable_identity: &stable_identity,
        churn_addr: &churn_addr,
        stable_addr: &stable_addr,
    };
    let config = WebRtcConfig {
        accept_connections: Some(true),
        max_connections: Some(1),
        connect_timeout_ms: Some(2_000),
        ice_gather_timeout_ms: Some(250),
        stun_servers: Some(Vec::new()),
        ..WebRtcConfig::default()
    };
    let (mut cancelled, _cancelled_rx) = new_transport(70, &churn_identity, &config);
    cancelled.start_async().await.expect("start cancelled dial");
    cancelled
        .connect_async(&stable_addr)
        .await
        .expect("start cancelled dial");
    tokio::task::yield_now().await;
    cancelled.stop_async().await.expect("stop cancelled dial");
    assert_resource_quiescent(&cancelled);
    drop(cancelled);

    let (mut churn_a, mut churn_a_rx) = new_transport(71, &churn_identity, &config);
    let (mut churn_b, mut churn_b_rx) = new_transport(72, &churn_identity, &config);
    let (mut stable, mut stable_rx) = new_transport(73, &stable_identity, &config);
    churn_a.start_async().await.expect("start churn A");
    churn_b.start_async().await.expect("start churn B");
    stable.start_async().await.expect("start stable peer");

    let mut control_two = None;
    let mut control_ten = None;
    for cycle in 0..10 {
        let context = format!("warm-up cycle {cycle}");
        let churn = if cycle % 2 == 0 {
            &mut churn_a
        } else {
            &mut churn_b
        };
        reconnect(
            churn,
            &mut stable,
            &peers,
            &context,
        )
        .await;
        churn.close_connection_async(&stable_addr).await;
        stable.close_connection_async(&churn_addr).await;
        wait_for_resource_quiescence(&[churn, &stable]).await;
        if cycle == 1 || cycle == 9 {
            tokio::time::sleep(Duration::from_millis(250)).await;
            let sample = open_file_snapshot();
            if cycle == 1 {
                control_two = Some(sample);
            } else {
                control_ten = Some(sample);
            }
        }
    }
    let control_two = control_two.expect("two-cycle API warm-up control");
    let control_ten = control_ten.expect("ten-cycle API warm-up control");
    assert!(
        control_two.0.abs_diff(control_ten.0) <= 2
            && control_two.1.socket.abs_diff(control_ten.1.socket) <= 2,
        "2/10-cycle WebRTC API controls must reach one FD plateau: two={control_two:?}, ten={control_ten:?}"
    );
    let baseline = control_ten.0;
    let baseline_modes = control_ten.1;

    let peak = Arc::new(AtomicUsize::new(baseline));
    let peak_modes = Arc::new(std::sync::Mutex::new(baseline_modes));
    let stop_sampler = Arc::new(AtomicBool::new(false));
    let sampler_peak = Arc::clone(&peak);
    let sampler_modes = Arc::clone(&peak_modes);
    let sampler_stop = Arc::clone(&stop_sampler);
    let sampler = tokio::spawn(async move {
        while !sampler_stop.load(Ordering::Acquire) {
            let (count, modes) = open_file_snapshot();
            if count > sampler_peak.fetch_max(count, Ordering::AcqRel) {
                *sampler_modes.lock().expect("peak FD modes") = modes;
            }
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
    });

    reconnect(
        &mut churn_a,
        &mut stable,
        &peers,
        "canonical initial connection",
    )
    .await;
    let mut active_a = true;
    for iteration in 0..CANONICAL_CHURN_CYCLES {
        let context = format!("canonical iteration {iteration}");
        if iteration % 64 == 0 {
            let (fd_count, fd_modes) = open_file_snapshot();
            eprintln!(
                "WebRTC FD progress: iteration={iteration} activeA={active_a} fds={fd_count} modes={fd_modes:?} churnA={:?} churnB={:?} stable={:?}",
                churn_a.resource_snapshot(),
                churn_b.resource_snapshot(),
                stable.resource_snapshot()
            );
        }
        if iteration % 64 == 0 {
            if active_a {
                abandon_then_retry(
                    &churn_a,
                    &mut churn_b,
                    &mut stable,
                    &peers,
                    &context,
                )
                .await;
            } else {
                abandon_then_retry(
                    &churn_b,
                    &mut churn_a,
                    &mut stable,
                    &peers,
                    &context,
                )
                .await;
            }
            active_a = !active_a;
        } else if iteration % 2 == 0 {
            if active_a {
                fresh_replace(
                    &churn_a,
                    &mut churn_b,
                    &mut stable,
                    &peers,
                    &context,
                )
                .await;
            } else {
                fresh_replace(
                    &churn_b,
                    &mut churn_a,
                    &mut stable,
                    &peers,
                    &context,
                )
                .await;
            }
            active_a = !active_a;
        } else if active_a {
            reconnect(
                &mut churn_a,
                &mut stable,
                &peers,
                &context,
            )
            .await;
        } else {
            reconnect(
                &mut churn_b,
                &mut stable,
                &peers,
                &context,
            )
            .await;
        }

        if active_a {
            assert_round_trip(&churn_a, &stable, &mut churn_a_rx, &mut stable_rx, &churn_addr, &stable_addr, iteration).await;
            assert_resource_bound(&churn_a);
        } else {
            assert_round_trip(&churn_b, &stable, &mut churn_b_rx, &mut stable_rx, &churn_addr, &stable_addr, iteration).await;
            assert_resource_bound(&churn_b);
        }
        assert_resource_bound(&stable);
    }

    churn_a.stop_async().await.expect("stop churn A");
    churn_b.stop_async().await.expect("stop churn B");
    stable.stop_async().await.expect("stop stable peer");
    for transport in [&churn_a, &churn_b, &stable] {
        assert_resource_quiescent(transport);
    }
    let final_churn_a = churn_a.resource_snapshot();
    let final_churn_b = churn_b.resource_snapshot();
    let final_stable = stable.resource_snapshot();
    stop_sampler.store(true, Ordering::Release);
    sampler.await.expect("FD sampler");
    let (final_count, settle_samples) = settle_fd_count_async(runtime_baseline).await;
    let peak = peak.load(Ordering::Acquire);
    let peak_modes = *peak_modes.lock().expect("peak FD modes");
    let final_modes = open_file_snapshot().1;
    eprintln!(
        "WebRTC FD churn: cycles={CANONICAL_CHURN_CYCLES} runtimeCold={runtime_baseline} control2={control_two:?} control10={control_ten:?} baseline={baseline} baselineModes={baseline_modes:?} peak={peak} peakModes={peak_modes:?} settleSamples={settle_samples:?} final={final_count} finalModes={final_modes:?} churnA={final_churn_a:?} churnB={final_churn_b:?} stable={final_stable:?}"
    );
    assert!(peak < FD_PEAK_LIMIT, "peak FD count {peak} must stay below 80% of {FD_LIMIT}");
    assert!(
        final_count <= runtime_baseline + FD_QUIESCENT_DELTA,
        "quiescent FD count {final_count} must return within {FD_QUIESCENT_DELTA} of cold runtime baseline {runtime_baseline}; warmed baseline {baseline}; peak {peak}"
    );
}

include!("low_fd_helpers.rs");
