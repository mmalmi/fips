fn ordered_identities() -> (crate::Identity, crate::Identity) {
    loop {
        let churn = crate::Identity::generate();
        let stable = crate::Identity::generate();
        if canonical_webrtc_pubkey_hex(churn.pubkey_full())
            < canonical_webrtc_pubkey_hex(stable.pubkey_full())
        {
            return (churn, stable);
        }
    }
}

fn identity_addr(identity: &crate::Identity) -> TransportAddr {
    test_webrtc_addr(identity)
}

fn new_transport(id: u32, identity: &crate::Identity, config: &WebRtcConfig) -> (WebRtcTransport, crate::transport::PacketRx) {
    let (packet_tx, packet_rx) = packet_channel(8);
    let mut transport = WebRtcTransport::new(TransportId::new(id), None, config.clone(), packet_tx, identity, &NostrDiscoveryConfig::default())
        .expect("low-FD WebRTC transport");
    transport
        .use_canonical_loopback_candidate_profile()
        .expect("real UDP4 loopback candidate profile");
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
    assert_canonical_loopback_candidate_profile(&offer);
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
        assert_canonical_loopback_candidate_profile(&message);
        last_signal = Some(signal_diagnostic("churn->stable", &message));
        stable
            .ingest_link_negotiation(peers.churn_identity.pubkey_full(), message)
            .expect("deliver churn signal");
    }
    for outbound in stable.drain_link_negotiations(16) {
        let message = LinkNegotiationMessage::decode(&outbound.payload).expect("stable signal");
        assert_canonical_loopback_candidate_profile(&message);
        last_signal = Some(signal_diagnostic("stable->churn", &message));
        churn
            .ingest_link_negotiation(peers.stable_identity.pubkey_full(), message)
            .expect("deliver stable signal");
    }
    last_signal
}

fn assert_canonical_loopback_candidate_profile(message: &LinkNegotiationMessage) {
    if !matches!(
        message.kind,
        LinkNegotiationKind::Offer | LinkNegotiationKind::Answer
    ) {
        return;
    }
    let payload = message
        .clone()
        .typed_payload::<WebRtcSignalPayload>()
        .expect("typed WebRTC signal");
    let component_one: Vec<_> = payload
        .payload
        .sdp
        .as_deref()
        .unwrap_or_default()
        .lines()
        .filter_map(|line| line.trim().strip_prefix("a=candidate:"))
        .filter_map(|candidate| {
            let fields: Vec<_> = candidate.split_whitespace().collect();
            (fields.len() >= 6 && fields[1] == "1")
                .then(|| (fields[2].to_ascii_lowercase(), fields[4].to_string()))
        })
        .collect();
    assert_eq!(
        component_one,
        vec![("udp".to_string(), "127.0.0.1".to_string())],
        "canonical lifecycle timing must use exactly one real UDP4 loopback candidate socket"
    );
}

fn signal_diagnostic(direction: &str, message: &LinkNegotiationMessage) -> String {
    let now = now_ms();
    let payload = message
        .clone()
        .typed_payload::<WebRtcSignalPayload>()
        .ok();
    let candidate_count = payload
        .as_ref()
        .and_then(|message| message.payload.sdp.as_deref())
        .map(|sdp| {
            sdp.lines()
                .filter(|line| line.trim_start().starts_with("a=candidate:"))
                .count()
        })
        .unwrap_or(0);
    let end_of_candidates = payload
        .as_ref()
        .and_then(|message| message.payload.sdp.as_deref())
        .is_some_and(|sdp| sdp.lines().any(|line| line.trim() == "a=end-of-candidates"));
    format!(
        "{direction} kind={:?} session={} ageMs={} expiresInMs={} candidates={} endOfCandidates={end_of_candidates}",
        message.kind,
        message.negotiation_id,
        now.saturating_sub(message.created_at_ms),
        message.expires_at_ms.saturating_sub(now),
        candidate_count,
    )
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
            "{}:{origin}:created={}:deadlineInMs={}",
            pending.session_id,
            pending.created_at_ms,
            pending
                .deadline
                .saturating_duration_since(tokio::time::Instant::now())
                .as_millis()
        )
    });
    let failure = transport.failed.lock().await.get(remote_addr).cloned();
    let ready = transport.ready.lock().await.contains(remote_addr);
    let negotiation = transport.negotiation.snapshot();
    let (dial_inflight, dial_outcomes) = take_finished_dial_outcomes(transport).await;
    format!(
        "state={connection_state:?} pool={pool_session:?} pending={pending_session:?} failed={failure:?} ready={ready} resources={resources:?} negotiation={negotiation:?} dialInflight={dial_inflight} dialOutcomes={dial_outcomes:?}"
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
