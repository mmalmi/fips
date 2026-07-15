#[derive(Default)]
struct WebRtcNegotiationCounters {
    offers_queued: std::sync::atomic::AtomicU64,
    answers_queued: std::sync::atomic::AtomicU64,
    answers_applied: std::sync::atomic::AtomicU64,
    answers_without_session: std::sync::atomic::AtomicU64,
    late_answers_rejected: std::sync::atomic::AtomicU64,
    timeouts_fired: std::sync::atomic::AtomicU64,
    last_offer_queued_ms: std::sync::atomic::AtomicU64,
    last_answer_queued_ms: std::sync::atomic::AtomicU64,
    last_answer_applied_ms: std::sync::atomic::AtomicU64,
    last_timeout_ms: std::sync::atomic::AtomicU64,
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct WebRtcNegotiationSnapshot {
    offers_queued: u64,
    answers_queued: u64,
    answers_applied: u64,
    answers_without_session: u64,
    late_answers_rejected: u64,
    timeouts_fired: u64,
    last_offer_queued_ms: u64,
    last_answer_queued_ms: u64,
    last_answer_applied_ms: u64,
    last_timeout_ms: u64,
}

impl WebRtcNegotiationCounters {
    fn record_offer_queued(&self) {
        self.offers_queued
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        self.last_offer_queued_ms
            .store(now_ms(), std::sync::atomic::Ordering::Relaxed);
    }

    fn record_answer_queued(&self) {
        self.answers_queued
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        self.last_answer_queued_ms
            .store(now_ms(), std::sync::atomic::Ordering::Relaxed);
    }

    fn record_answer_applied(&self) {
        self.answers_applied
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        self.last_answer_applied_ms
            .store(now_ms(), std::sync::atomic::Ordering::Relaxed);
    }

    fn record_answer_without_session(&self) {
        self.answers_without_session
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    fn record_late_answer_rejected(&self) {
        self.late_answers_rejected
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    fn record_timeout(&self) {
        self.timeouts_fired
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        self.last_timeout_ms
            .store(now_ms(), std::sync::atomic::Ordering::Relaxed);
    }

    #[cfg(test)]
    fn snapshot(&self) -> WebRtcNegotiationSnapshot {
        use std::sync::atomic::Ordering::Relaxed;
        WebRtcNegotiationSnapshot {
            offers_queued: self.offers_queued.load(Relaxed),
            answers_queued: self.answers_queued.load(Relaxed),
            answers_applied: self.answers_applied.load(Relaxed),
            answers_without_session: self.answers_without_session.load(Relaxed),
            late_answers_rejected: self.late_answers_rejected.load(Relaxed),
            timeouts_fired: self.timeouts_fired.load(Relaxed),
            last_offer_queued_ms: self.last_offer_queued_ms.load(Relaxed),
            last_answer_queued_ms: self.last_answer_queued_ms.load(Relaxed),
            last_answer_applied_ms: self.last_answer_applied_ms.load(Relaxed),
            last_timeout_ms: self.last_timeout_ms.load(Relaxed),
        }
    }
}

async fn wait_for_ice_gathering(
    timeout: Duration,
    gathering: &mut mpsc::Receiver<()>,
) -> Result<(), TransportError> {
    tokio::time::timeout(timeout, gathering.recv())
        .await
        .map(|_| ())
        .map_err(|_| {
            TransportError::StartFailed("WebRTC ICE gathering timed out".to_string())
        })
}

fn signal_expiry_for_deadline(
    deadline: tokio::time::Instant,
    monotonic_now: tokio::time::Instant,
    wall_now_ms: u64,
) -> u64 {
    let remaining_ms = deadline
        .saturating_duration_since(monotonic_now)
        .as_millis()
        .min(SIGNAL_TTL_MS as u128) as u64;
    wall_now_ms.saturating_add(remaining_ms)
}

fn deadline_from_signal(
    signal: &WebRtcSignal,
    local_timeout: Duration,
    monotonic_now: tokio::time::Instant,
    wall_now_ms: u64,
) -> tokio::time::Instant {
    let signal_remaining = Duration::from_millis(
        signal
            .expires_at_ms
            .saturating_sub(wall_now_ms)
            .min(SIGNAL_TTL_MS),
    );
    monotonic_now + signal_remaining.min(local_timeout)
}

fn require_non_trickle_ice_candidates(
    sdp: &str,
    scope: EmbeddedCandidateScope,
) -> Result<EmbeddedCandidateCount, TransportError> {
    let candidates = validate_embedded_ice_candidates(sdp, scope)?;
    if candidates.unique_routes == 0 {
        return Err(TransportError::StartFailed(
            "WebRTC non-trickle SDP contains no ICE candidates".to_string(),
        ));
    }
    Ok(candidates)
}

fn is_negotiation_timeout(error: &TransportError) -> bool {
    match error {
        TransportError::Timeout => true,
        TransportError::StartFailed(reason) => {
            reason.contains("timed out") || reason.contains("deadline exceeded")
        }
        _ => false,
    }
}

impl WebRtcRuntime {
    fn validate_signal(&self, signal: &WebRtcSignal) -> Result<(), TransportError> {
        if signal.version != crate::transport::link_negotiation::LINK_NEGOTIATION_VERSION {
            return Err(TransportError::InvalidAddress("bad WebRTC version".into()));
        }
        if signal.link_type != "webrtc" {
            return Err(TransportError::InvalidAddress(
                "bad WebRTC link-negotiation type".into(),
            ));
        }
        let now = now_ms();
        let Some(validity_ms) = signal.expires_at_ms.checked_sub(signal.created_at_ms) else {
            return Err(TransportError::Timeout);
        };
        if signal.expires_at_ms < now
            || signal.created_at_ms > now.saturating_add(SIGNAL_TTL_MS)
            || validity_ms > SIGNAL_TTL_MS
        {
            return Err(TransportError::Timeout);
        }
        if matches!(
            signal.kind,
            LinkNegotiationKind::Offer | LinkNegotiationKind::Answer
        ) {
            let Some(sdp) = signal.payload.sdp.as_deref() else {
                return Err(TransportError::InvalidAddress(
                    "WebRTC offer/answer requires bounded SDP".into(),
                ));
            };
            if sdp.is_empty() || sdp.len() > MAX_WEBRTC_SDP_LENGTH {
                return Err(TransportError::InvalidAddress(
                    "WebRTC offer/answer requires bounded SDP".into(),
                ));
            }
            require_non_trickle_ice_candidates(sdp, EmbeddedCandidateScope::Remote)?;
        }
        if let Some(candidates) = &signal.payload.candidates
            && (candidates.len() > crate::config::MAX_WEBRTC_REMOTE_CANDIDATE_ROUTES
                || candidates
                    .iter()
                    .any(|candidate| candidate.candidate.len() > MAX_WEBRTC_CANDIDATE_LENGTH))
        {
            return Err(TransportError::InvalidAddress(
                "WebRTC candidate payload exceeds limits".into(),
            ));
        }
        Ok(())
    }

    async fn mark_session_failed(
        &self,
        addr: TransportAddr,
        expected_owner: &WebRtcSessionOwner,
        reason: String,
    ) -> bool {
        let pending = {
            let mut pending = self.pending.lock().await;
            if pending
                .get(&addr)
                .is_some_and(|pending| expected_owner.matches(&pending.session_id, &pending.pc))
            {
                pending.remove(&addr)
            } else {
                None
            }
        };
        let Some(pending) = pending else {
            return false;
        };
        self.finish_pending_failure(addr, pending, reason).await;
        true
    }

    async fn mark_expired_pending_failed(
        &self,
        addr: TransportAddr,
        expected_phase_owner_id: &str,
        expected_deadline: tokio::time::Instant,
        reason: String,
    ) -> bool {
        let pending = {
            let mut pending = self.pending.lock().await;
            if pending
                .get(&addr)
                .is_some_and(|dial| {
                    dial.phase_owner_id == expected_phase_owner_id
                        && dial.deadline == expected_deadline
                        && dial.deadline <= tokio::time::Instant::now()
                })
            {
                pending.remove(&addr)
            } else {
                None
            }
        };
        let Some(pending) = pending else {
            return false;
        };
        self.finish_pending_failure(addr, pending, reason).await;
        true
    }

    async fn queue_signal_for_pending(
        &self,
        addr: &TransportAddr,
        session_id: &str,
        pc: &ManagedPeer,
        recipient: PublicKey,
        signal: &WebRtcSignal,
    ) -> Result<(), TransportError> {
        let pending = self.pending.lock().await;
        let Some(dial) = pending.get(addr) else {
            return Err(TransportError::ConnectionRefused);
        };
        if dial.session_id != session_id || !Arc::ptr_eq(&dial.pc, pc) {
            return Err(TransportError::ConnectionRefused);
        }
        if tokio::time::Instant::now() >= dial.deadline || now_ms() >= signal.expires_at_ms {
            return Err(TransportError::Timeout);
        }
        if pc.is_closing()
            || !self.physical.is_accepting()
            || self.physical.phase(addr) != Some(PhysicalPhase::Active)
        {
            return Err(TransportError::ConnectionRefused);
        }
        // Queueing is synchronous while the exact pending generation is
        // locked, so cleanup or replacement orders before or after this
        // signal instead of racing through its liveness check.
        self.signaling.send_signal(recipient, signal)
    }

    async fn session_generation_is_active_or_pooled(
        &self,
        addr: &TransportAddr,
        session_id: &str,
        pc: &ManagedPeer,
    ) -> bool {
        let pool = self.pool.lock().await;
        let pending = self.pending.lock().await;
        let logically_owned = pool.get(addr).is_some_and(|connection| {
            connection.session_id == session_id && Arc::ptr_eq(&connection.pc, pc)
        }) || pending.get(addr).is_some_and(|dial| {
            dial.session_id == session_id && Arc::ptr_eq(&dial.pc, pc)
        });
        logically_owned
            && !pc.is_closing()
            && self.physical.is_accepting()
            && self.physical.phase(addr) == Some(PhysicalPhase::Active)
    }

    async fn finish_pending_failure(
        &self,
        addr: TransportAddr,
        pending: PendingDial,
        reason: String,
    ) {
        // A successor may be admitted immediately after this exact pending
        // owner is removed. Publish failure only while pool and pending prove
        // the address is still ownerless; new pending admission uses the same
        // order and clears any preceding failure before releasing its locks.
        let pool = self.pool.lock().await;
        let pending_owners = self.pending.lock().await;
        if !pool.contains_key(&addr) && !pending_owners.contains_key(&addr) {
            self.ready.lock().await.remove(&addr);
            self.failed
                .lock()
                .await
                .insert(addr.clone(), reason.clone());
        }
        drop(pending_owners);
        drop(pool);
        warn!(
            transport_id = %self.transport_id,
            remote_addr = %addr,
            reason = %reason,
            "WebRTC connection failed"
        );
        drop(start_peer_connection_cleanup(pending.pc));
    }

    async fn send_reject(
        &self,
        recipient_xonly: PublicKey,
        session_id: String,
    ) -> Result<(), TransportError> {
        let now = now_ms();
        let reject = WebRtcSignal {
            version: crate::transport::link_negotiation::LINK_NEGOTIATION_VERSION,
            negotiation_id: session_id,
            link_type: "webrtc".to_string(),
            kind: LinkNegotiationKind::Reject,
            created_at_ms: now,
            expires_at_ms: now.saturating_add(SIGNAL_TTL_MS),
            payload: WebRtcSignalPayload {
                sdp: None,
                candidates: None,
            },
        };
        self.signaling.send_signal(recipient_xonly, &reject)
    }

    async fn new_peer_connection(&self) -> Result<RTCPeerConnection, TransportError> {
        let api = self.candidate_policy.build_api()?;
        self.new_peer_connection_with_api(&api).await
    }

    async fn new_peer_connection_with_api(
        &self,
        api: &::webrtc::api::API,
    ) -> Result<RTCPeerConnection, TransportError> {
        api.new_peer_connection(RTCConfiguration {
            ice_servers: self
                .stun_servers
                .iter()
                .map(|url| RTCIceServer {
                    urls: vec![url.clone()],
                    ..Default::default()
                })
                .collect(),
            ..Default::default()
        })
        .await
        .map_err(|e| TransportError::StartFailed(e.to_string()))
    }

    fn spawn_connect_timeout(
        &self,
        addr: TransportAddr,
        session_id: String,
        deadline: tokio::time::Instant,
        pc: &ManagedPeer,
    ) {
        let pool = Arc::downgrade(&self.pool);
        let pending = Arc::downgrade(&self.pending);
        let failed = Arc::downgrade(&self.failed);
        let ready = Arc::downgrade(&self.ready);
        let expected_pc = Arc::downgrade(pc);
        let negotiation = Arc::clone(&self.negotiation);
        let transport_id = self.transport_id;
        tokio::spawn(async move {
            tokio::time::sleep_until(deadline).await;
            let (Some(pool), Some(pending), Some(failed), Some(ready)) = (
                pool.upgrade(),
                pending.upgrade(),
                failed.upgrade(),
                ready.upgrade(),
            ) else {
                return;
            };
            let maybe_pending = {
                let pool = pool.lock().await;
                let mut pending = pending.lock().await;
                match pending.get(&addr) {
                    Some(dial)
                        if !pool.contains_key(&addr)
                            && dial.session_id == session_id
                            && dial.deadline == deadline
                            && expected_pc.ptr_eq(&Arc::downgrade(&dial.pc)) =>
                    {
                        let dial = pending.remove(&addr);
                        ready.lock().await.remove(&addr);
                        failed.lock().await.insert(
                            addr.clone(),
                            "WebRTC connect timed out".to_string(),
                        );
                        dial
                    }
                    _ => None,
                }
            };
            if let Some(dial) = maybe_pending {
                negotiation.record_timeout();
                let reason = "WebRTC connect timed out".to_string();
                let rtc = dial.pc.failure_stage_diagnostic();
                drop(start_peer_connection_cleanup(dial.pc));
                warn!(
                    transport_id = %transport_id,
                    remote_addr = %addr,
                    negotiation = %session_id,
                    deadline_late_ms = tokio::time::Instant::now()
                        .saturating_duration_since(deadline)
                        .as_millis(),
                    stage = "pending-before-data-channel-open",
                    rtc = %rtc,
                    reason = %reason,
                    "WebRTC connection failed"
                );
            }
        });
    }
}
