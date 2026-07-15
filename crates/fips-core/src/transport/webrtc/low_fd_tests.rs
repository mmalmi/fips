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

fn ordered_identities() -> (crate::Identity, crate::Identity) {
    loop {
        let churn = crate::Identity::generate();
        let stable = crate::Identity::generate();
        if hex::encode(churn.pubkey_full().serialize()) < hex::encode(stable.pubkey_full().serialize()) {
            return (churn, stable);
        }
    }
}

fn identity_addr(identity: &crate::Identity) -> TransportAddr {
    TransportAddr::from_string(&hex::encode(identity.pubkey_full().serialize()))
}

fn new_transport(id: u32, identity: &crate::Identity, config: &WebRtcConfig) -> (WebRtcTransport, crate::transport::PacketRx) {
    let (packet_tx, packet_rx) = packet_channel(8);
    let transport = WebRtcTransport::new(TransportId::new(id), None, config.clone(), packet_tx, identity, &NostrDiscoveryConfig::default())
        .expect("low-FD WebRTC transport");
    (transport, packet_rx)
}

async fn reconnect(
    churn: &mut WebRtcTransport,
    stable: &mut WebRtcTransport,
    peers: &ChurnPeers<'_>,
    context: &str,
) {
    if churn.connection_state_sync(peers.stable_addr) != ConnectionState::None {
        churn.close_connection_async(peers.stable_addr).await;
        stable.close_connection_async(peers.churn_addr).await;
        wait_for_resource_quiescence(&[churn, stable]).await;
    }
    churn
        .connect_async(peers.stable_addr)
        .await
        .expect("WebRTC reconnect");
    relay_until_connected(
        churn,
        stable,
        peers,
        context,
    )
    .await;
}

async fn fresh_replace(
    old: &WebRtcTransport,
    replacement: &mut WebRtcTransport,
    stable: &mut WebRtcTransport,
    peers: &ChurnPeers<'_>,
    context: &str,
) {
    replacement
        .connect_async(peers.stable_addr)
        .await
        .expect("fresh replacement offer");
    relay_until_connected(
        replacement,
        stable,
        peers,
        context,
    )
    .await;
    wait_for_resource_quiescence(&[old]).await;
}

async fn abandon_then_retry(
    old: &WebRtcTransport,
    replacement: &mut WebRtcTransport,
    stable: &mut WebRtcTransport,
    peers: &ChurnPeers<'_>,
    context: &str,
) {
    replacement
        .connect_async(peers.stable_addr)
        .await
        .expect("abandoned offer");
    let offer = take_link_negotiation(replacement, LinkNegotiationKind::Offer).await;
    stable
        .ingest_link_negotiation(peers.churn_identity.pubkey_full(), offer)
        .expect("deliver abandoned offer");
    let _discarded = take_link_negotiation(stable, LinkNegotiationKind::Answer).await;
    wait_for_resource_quiescence(&[old, replacement, stable]).await;
    reconnect(replacement, stable, peers, context).await;
}

fn assert_resource_bound(transport: &WebRtcTransport) {
    let snapshot = transport.resource_snapshot();
    assert_eq!(snapshot.capacity, 1);
    assert!(snapshot.creating + snapshot.active + snapshot.closing <= snapshot.capacity);
    assert_eq!(snapshot.cleanup_inflight + snapshot.abandoned, snapshot.closing);
    assert_eq!(
        snapshot.created_total.checked_sub(snapshot.closed_total),
        Some((snapshot.active + snapshot.closing) as u64)
    );
    assert!(snapshot.peak_physical <= snapshot.capacity);
}

fn assert_resource_quiescent(transport: &WebRtcTransport) {
    let snapshot = transport.resource_snapshot();
    assert_eq!(snapshot.creating + snapshot.active + snapshot.closing, 0);
    assert_eq!(snapshot.cleanup_inflight, 0);
    assert_eq!(snapshot.abandoned, 0);
    assert_eq!(snapshot.straggler_waiters, 0);
    assert_eq!(snapshot.created_total, snapshot.closed_total);
    assert_eq!(snapshot.ice_stop_failures_total, 0);
    assert!(snapshot.peak_physical <= 1);
}

async fn wait_for_resource_quiescence(transports: &[&WebRtcTransport]) {
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let mut quiescent = true;
            for transport in transports {
                let snapshot = transport.resource_snapshot();
                quiescent &= snapshot.creating
                    + snapshot.active
                    + snapshot.closing
                    + snapshot.cleanup_inflight
                    + snapshot.abandoned
                    + snapshot.straggler_waiters
                    == 0;
                quiescent &= transport.pool.lock().await.is_empty();
                quiescent &= transport.pending.lock().await.is_empty();
                quiescent &= transport.ready.lock().await.is_empty();
            }
            if quiescent {
                return;
            }
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
    })
    .await
    .expect("physical WebRTC cleanup quiesces");
}

async fn take_link_negotiation(transport: &mut WebRtcTransport, kind: LinkNegotiationKind) -> LinkNegotiationMessage {
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            for outbound in transport.drain_link_negotiations(16) {
                let message = LinkNegotiationMessage::decode(&outbound.payload).expect("link negotiation");
                if message.kind == kind {
                    return message;
                }
            }
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
    })
    .await
    .expect("expected WebRTC link negotiation")
}

async fn relay_until_connected(
    churn: &mut WebRtcTransport,
    stable: &mut WebRtcTransport,
    peers: &ChurnPeers<'_>,
    context: &str,
) {
    let mut last_signal = None;
    let connected = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if let Some(signal) = relay_negotiations(churn, stable, peers) {
                last_signal = Some(signal);
            }
            if churn.connection_state_sync(peers.stable_addr) == ConnectionState::Connected
                && stable.connection_state_sync(peers.churn_addr) == ConnectionState::Connected
            {
                return;
            }
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
    })
    .await;
    if connected.is_err() {
        let (fd_count, fd_modes) = open_file_snapshot();
        let churn_state = transport_failure_state(churn, peers.stable_addr).await;
        let stable_state = transport_failure_state(stable, peers.churn_addr).await;
        panic!(
            "two local WebRTC peers connect: context={context} lastSignal={last_signal:?} fds={fd_count} modes={fd_modes:?} churn=[{churn_state}] stable=[{stable_state}]"
        );
    }
}

fn relay_negotiations(
    churn: &mut WebRtcTransport,
    stable: &mut WebRtcTransport,
    peers: &ChurnPeers<'_>,
) -> Option<String> {
    let mut last_signal = None;
    for outbound in churn.drain_link_negotiations(16) {
        let message = LinkNegotiationMessage::decode(&outbound.payload).expect("churn signal");
        last_signal = Some(format!(
            "churn->stable kind={:?} session={}",
            message.kind, message.negotiation_id
        ));
        stable
            .ingest_link_negotiation(peers.churn_identity.pubkey_full(), message)
            .expect("deliver churn signal");
    }
    for outbound in stable.drain_link_negotiations(16) {
        let message = LinkNegotiationMessage::decode(&outbound.payload).expect("stable signal");
        last_signal = Some(format!(
            "stable->churn kind={:?} session={}",
            message.kind, message.negotiation_id
        ));
        churn
            .ingest_link_negotiation(peers.stable_identity.pubkey_full(), message)
            .expect("deliver stable signal");
    }
    last_signal
}

async fn transport_failure_state(
    transport: &WebRtcTransport,
    remote_addr: &TransportAddr,
) -> String {
    let connection_state = transport.connection_state_sync(remote_addr);
    let resources = transport.resource_snapshot();
    let pool_session = transport
        .pool
        .lock()
        .await
        .get(remote_addr)
        .map(|connection| connection.session_id.clone());
    let pending_session = transport.pending.lock().await.get(remote_addr).map(|pending| {
        let origin = match pending.origin {
            PendingDialOrigin::Local => "local",
            PendingDialOrigin::Remote => "remote",
        };
        format!(
            "{}:{origin}:created={}",
            pending.session_id, pending.created_at_ms
        )
    });
    let failure = transport.failed.lock().await.get(remote_addr).cloned();
    let ready = transport.ready.lock().await.contains(remote_addr);
    let (dial_inflight, dial_outcomes) = take_finished_dial_outcomes(transport).await;
    format!(
        "state={connection_state:?} pool={pool_session:?} pending={pending_session:?} failed={failure:?} ready={ready} resources={resources:?} dialInflight={dial_inflight} dialOutcomes={dial_outcomes:?}"
    )
}

async fn take_finished_dial_outcomes(transport: &WebRtcTransport) -> (usize, Vec<String>) {
    let (inflight, finished) = {
        let mut tasks = transport.dial_tasks.lock().expect("WebRTC dial tasks");
        let mut finished = Vec::new();
        let mut index = 0;
        while index < tasks.len() {
            if tasks[index].is_finished() {
                finished.push(tasks.swap_remove(index));
            } else {
                index += 1;
            }
        }
        (tasks.len(), finished)
    };
    let mut outcomes = Vec::with_capacity(finished.len());
    for task in finished {
        outcomes.push(match task.await {
            Ok(Ok(())) => "ok".to_string(),
            Ok(Err(error)) => format!("error: {error}"),
            Err(error) => format!("join error: {error}"),
        });
    }
    (inflight, outcomes)
}

async fn assert_round_trip(
    churn: &WebRtcTransport,
    stable: &WebRtcTransport,
    churn_rx: &mut crate::transport::PacketRx,
    stable_rx: &mut crate::transport::PacketRx,
    churn_addr: &TransportAddr,
    stable_addr: &TransportAddr,
    iteration: usize,
) {
    let mut payload = vec![0x42];
    payload.extend_from_slice(&(iteration as u64).to_be_bytes());
    churn.send_async(stable_addr, &payload).await.expect("churn-to-stable send");
    let received = tokio::time::timeout(Duration::from_secs(2), stable_rx.recv()).await.expect("stable receive timeout").expect("stable receive channel");
    assert_eq!(&received.remote_addr, churn_addr);
    assert_eq!(received.data.as_slice(), payload);
    payload[0] = 0x55;
    stable.send_async(churn_addr, &payload).await.expect("stable-to-churn send");
    let received = tokio::time::timeout(Duration::from_secs(2), churn_rx.recv()).await.expect("churn receive timeout").expect("churn receive channel");
    assert_eq!(&received.remote_addr, stable_addr);
    assert_eq!(received.data.as_slice(), payload);
}

async fn settle_fd_count_async(baseline: usize) -> (usize, Vec<(u128, usize, OpenFileModes)>) {
    let started = tokio::time::Instant::now();
    let mut samples = Vec::new();
    loop {
        let (count, modes) = open_file_snapshot();
        samples.push((started.elapsed().as_millis(), count, modes));
        if count <= baseline + FD_QUIESCENT_DELTA || started.elapsed() >= FD_SETTLE_DEADLINE {
            return (count, samples);
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}
