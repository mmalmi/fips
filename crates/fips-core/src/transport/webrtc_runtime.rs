#[derive(Clone)]
struct WebRtcRuntime {
    transport_id: TransportId,
    config: WebRtcConfig,
    candidate_policy: CandidateAddressPolicy,
    mdns_resolver: SharedMdnsResolver,
    packet_tx: PacketTx,
    pool: ConnectionPool,
    pending: PendingPool,
    failed: FailedPool,
    ready: ReadyPool,
    seen_sessions: SeenSessionPool,
    physical: PhysicalResources,
    negotiation: Arc<WebRtcNegotiationCounters>,
    local_pubkey_hex: String,
    stun_servers: Vec<String>,
    signaling: FipsSignalSender,
}

impl WebRtcRuntime {
    async fn record_partial_local_candidate_diagnostic(pc: &ManagedPeer) {
        let Ok(Some(local_description)) = tokio::time::timeout(
            Duration::from_millis(25),
            pc.local_description(),
        )
        .await
        else {
            return;
        };
        if let Ok(count) = validate_embedded_ice_candidates(
            &local_description.sdp,
            EmbeddedCandidateScope::Local,
        ) {
            pc.record_local_candidates(count);
        }
    }

    fn data_channel_context(&self) -> WebRtcDataChannelContext {
        WebRtcDataChannelContext {
            transport_id: self.transport_id,
            packet_tx: self.packet_tx.clone(),
            physical: self.physical.clone(),
            owners: WebRtcSessionOwners::from_refs(
                &self.pool,
                &self.pending,
                &self.failed,
                &self.ready,
            ),
        }
    }

    async fn start_outbound(
        &self,
        remote_addr: TransportAddr,
        reservation: PhysicalReservation,
        deadline: tokio::time::Instant,
        phase_owner_id: Option<String>,
    ) -> Result<(), TransportError> {
        let remote_pubkey_hex = remote_addr.as_str().unwrap_or_default().to_string();
        let remote_xonly = xonly_from_compressed_hex(&remote_pubkey_hex)?;
        let session_id = random_session_id();
        let phase_owner_id = phase_owner_id.unwrap_or_else(|| session_id.clone());

        let raw_pc = tokio::time::timeout_at(deadline, self.new_peer_connection())
            .await
            .map_err(|_| TransportError::Timeout)??;
        let pc = reservation.activate(raw_pc);
        let data_channel = match tokio::time::timeout_at(
            deadline,
            pc.create_data_channel(
                self.config.data_channel_label(),
                Some(RTCDataChannelInit {
                    ordered: Some(self.config.ordered()),
                    max_retransmits: self.config.max_retransmits(),
                    ..Default::default()
                }),
            ),
        )
        .await
        {
            Err(_) => {
                close_peer_connection_bounded(pc).await;
                return Err(TransportError::Timeout);
            }
            Ok(Ok(data_channel)) => data_channel,
            Ok(Err(error)) => {
                close_peer_connection_bounded(pc).await;
                return Err(TransportError::StartFailed(error.to_string()));
            }
        };

        wire_data_channel(
            self.data_channel_context(),
            remote_addr.clone(),
            session_id.clone(),
            Arc::clone(&pc),
            Arc::clone(&data_channel),
        );

        if !self
            .try_reserve_pending(
                &remote_addr,
                PendingDial {
                    session_id: session_id.clone(),
                    phase_owner_id,
                    pc: Arc::clone(&pc),
                    created_at_ms: now_ms(),
                    origin: PendingDialOrigin::Local,
                    deadline,
                },
            )
            .await
        {
            drop(data_channel);
            close_peer_connection_bounded(pc).await;
            return Ok(());
        }
        wire_peer_connection_state(
            self,
            remote_addr.clone(),
            session_id.clone(),
            Arc::clone(&pc),
        );
        let result = tokio::time::timeout_at(deadline, async {
            let offer = pc
                .create_offer(None)
                .await
                .map_err(|e| TransportError::StartFailed(e.to_string()))?;
            let mut gathering = pc.gathering_complete_promise().await;
            pc.set_local_description(offer)
                .await
                .map_err(|e| TransportError::StartFailed(e.to_string()))?;
            wait_for_ice_gathering(
                Duration::from_millis(self.config.ice_gather_timeout_ms()),
                &mut gathering,
            )
            .await?;

            let sdp = pc
                .local_description()
                .await
                .ok_or_else(|| TransportError::StartFailed("missing local WebRTC offer".into()))?
                .sdp;
            let candidate_count =
                require_non_trickle_ice_candidates(&sdp, EmbeddedCandidateScope::Local)?;
            pc.record_local_candidates(candidate_count);
            let monotonic_now = tokio::time::Instant::now();
            let now = now_ms();
            let expires_at_ms =
                signal_expiry_for_deadline(deadline, monotonic_now, now);
            if expires_at_ms <= now {
                return Err(TransportError::Timeout);
            }
            let signal = WebRtcSignal {
                version: crate::transport::link_negotiation::LINK_NEGOTIATION_VERSION,
                negotiation_id: session_id.clone(),
                link_type: "webrtc".to_string(),
                kind: LinkNegotiationKind::Offer,
                created_at_ms: now,
                expires_at_ms,
                payload: WebRtcSignalPayload {
                    sdp: Some(sdp),
                    candidates: None,
                },
            };
            self.queue_signal_for_pending(
                &remote_addr,
                &session_id,
                &pc,
                remote_xonly,
                &signal,
            )
            .await?;
            self.negotiation.record_offer_queued();
            debug!(
                transport_id = %self.transport_id,
                remote_addr = %remote_addr,
                negotiation = %signal.negotiation_id,
                sdp_bytes = signal.payload.sdp.as_ref().map(|s| s.len()).unwrap_or(0),
                candidate_raw = candidate_count.raw_lines,
                candidate_routes = candidate_count.unique_routes,
                "WebRTC offer sent"
            );
            Ok(())
        })
        .await
        .unwrap_or_else(|_| {
            Err(TransportError::StartFailed(
                "WebRTC outbound negotiation deadline exceeded".into(),
            ))
        });
        if let Err(error) = result {
            if is_negotiation_timeout(&error) {
                self.negotiation.record_timeout();
            }
            Self::record_partial_local_candidate_diagnostic(&pc).await;
            warn!(
                transport_id = %self.transport_id,
                remote_addr = %remote_addr,
                negotiation = %session_id,
                stage = "outbound-offer-before-data-channel-open",
                rtc = %pc.failure_stage_diagnostic(),
                error = %error,
                "WebRTC negotiation failed"
            );
            let expected_owner = WebRtcSessionOwner::new(&session_id, &pc);
            self.mark_session_failed(
                remote_addr,
                &expected_owner,
                format!("WebRTC outbound connection failed: {error}"),
            )
            .await;
            return Err(error);
        }
        self.spawn_connect_timeout(remote_addr, session_id, deadline, &pc);
        Ok(())
    }

    async fn handle_incoming_signal(&self, incoming: IncomingSignal) -> Result<(), TransportError> {
        let signal = incoming.signal;
        debug!(
            transport_id = %self.transport_id,
            kind = ?signal.kind,
            negotiation = %signal.negotiation_id,
            sender = %incoming.sender_full_hex,
            "WebRTC signal received"
        );
        if let Err(error) = self.validate_signal(&signal) {
            if signal.kind == LinkNegotiationKind::Answer
                && matches!(error, TransportError::Timeout)
            {
                self.negotiation.record_late_answer_rejected();
                let addr = TransportAddr::from_string(&incoming.sender_full_hex);
                let expected_owner = self
                    .pending
                    .lock()
                    .await
                    .get(&addr)
                    .filter(|dial| {
                        dial.session_id == signal.negotiation_id
                            && dial.deadline <= tokio::time::Instant::now()
                    })
                    .map(|dial| WebRtcSessionOwner::new(&dial.session_id, &dial.pc));
                if let Some(expected_owner) = expected_owner
                    && self
                        .mark_session_failed(
                            addr,
                            &expected_owner,
                            "WebRTC answer expired".to_string(),
                        )
                        .await
                {
                    self.negotiation.record_timeout();
                }
            }
            return Err(error);
        }
        match signal.kind {
            LinkNegotiationKind::Offer => {
                let remote_addr = TransportAddr::from_string(&incoming.sender_full_hex);
                let phase_owner_id = signal.negotiation_id.clone();
                let monotonic_now = tokio::time::Instant::now();
                let deadline = deadline_from_signal(
                    &signal,
                    Duration::from_millis(self.config.connect_timeout_ms()),
                    monotonic_now,
                    now_ms(),
                );
                match tokio::time::timeout_at(
                    deadline,
                    self.handle_offer(
                        signal,
                        incoming.sender,
                        incoming.sender_full_hex,
                        deadline,
                    ),
                )
                .await
                {
                    Ok(result) => result,
                    Err(_) => {
                        self.negotiation.record_timeout();
                        self.mark_expired_pending_failed(
                            remote_addr,
                            &phase_owner_id,
                            deadline,
                            "WebRTC inbound negotiation deadline exceeded".into(),
                        )
                        .await;
                        Err(TransportError::Timeout)
                    }
                }
            }
            LinkNegotiationKind::Answer => {
                self.handle_answer(signal, &incoming.sender_full_hex).await
            }
            LinkNegotiationKind::Reject => {
                let addr = TransportAddr::from_string(&incoming.sender_full_hex);
                let expected_owner = self
                    .pending
                    .lock()
                    .await
                    .get(&addr)
                    .filter(|dial| dial.session_id == signal.negotiation_id)
                    .map(|dial| WebRtcSessionOwner::new(&dial.session_id, &dial.pc));
                if let Some(expected_owner) = expected_owner {
                    self.mark_session_failed(
                        addr,
                        &expected_owner,
                        "peer rejected WebRTC session".to_string(),
                    )
                    .await;
                }
                Ok(())
            }
            LinkNegotiationKind::Candidate => Err(TransportError::NotSupported(
                "WebRTC candidate trickling is disabled; send complete SDP".into(),
            )),
        }
    }

    async fn handle_offer(
        &self,
        signal: WebRtcSignal,
        sender_xonly: PublicKey,
        sender_full_hex: String,
        deadline: tokio::time::Instant,
    ) -> Result<(), TransportError> {
        let remote_addr = TransportAddr::from_string(&sender_full_hex);
        let pending = self.pending.lock().await.get(&remote_addr).map(|pending| {
            (
                WebRtcSessionOwner::new(&pending.session_id, &pending.pc),
                pending.created_at_ms,
                pending.origin,
            )
        });
        if !self.config.accept_connections() && pending.is_none() {
            let _ = self
                .send_reject(sender_xonly, signal.negotiation_id.clone())
                .await;
            return Err(TransportError::ConnectionRefused);
        }
        if let Some((pending_owner, pending_created_at_ms, pending_origin)) = &pending {
            if pending_owner.session_id.as_deref() == Some(signal.negotiation_id.as_str()) {
                return Ok(());
            }
            if !incoming_offer_replaces_pending(
                &self.local_pubkey_hex,
                &sender_full_hex,
                *pending_origin,
                *pending_created_at_ms,
                signal.created_at_ms,
            ) {
                let _ = self
                    .send_reject(sender_xonly, signal.negotiation_id)
                    .await;
                return Err(TransportError::ConnectionRefused);
            }
        }
        let Some(_offer_admission) = self.physical.try_claim_offer(&remote_addr) else {
            let _ = self
                .send_reject(sender_xonly, signal.negotiation_id)
                .await;
            return Err(TransportError::ConnectionRefused);
        };
        if let Some((pending_owner, _, _)) = pending
            && !evict_pending_webrtc_session_for_offer(
                &self.pool,
                &self.pending,
                &self.failed,
                &self.ready,
                &remote_addr,
                &pending_owner,
            )
            .await
        {
            let _ = self
                .send_reject(sender_xonly, signal.negotiation_id)
                .await;
            return Err(TransportError::ConnectionRefused);
        }
        if !accept_webrtc_offer_once(
            &self.seen_sessions,
            &remote_addr,
            &signal.negotiation_id,
            signal.expires_at_ms,
            now_ms(),
        )
        .await
        {
            debug!(
                transport_id = %self.transport_id,
                remote_addr = %remote_addr,
                negotiation = %signal.negotiation_id,
                "duplicate WebRTC offer ignored"
            );
            return Ok(());
        }
        let offer_sdp = self
            .mdns_resolver
            .resolve_sdp(signal.payload.sdp.as_deref().unwrap_or_default())
            .await?;
        let remote_candidate_count =
            require_non_trickle_ice_candidates(&offer_sdp, EmbeddedCandidateScope::Remote)?;
        let offer = RTCSessionDescription::offer(offer_sdp)
            .map_err(|e| TransportError::StartFailed(e.to_string()))?;
        let disposition = prepare_pooled_webrtc_session_for_offer(
            &self.pool,
            &self.pending,
            &self.failed,
            &self.ready,
            &remote_addr,
            &signal.negotiation_id,
            &self.local_pubkey_hex,
        )
        .await;
        if disposition != PooledOfferDisposition::IgnoreReplay
            && (signal.expires_at_ms < now_ms() || !self.physical.is_accepting())
        {
            let _ = self
                .send_reject(sender_xonly, signal.negotiation_id)
                .await;
            return Err(TransportError::ConnectionRefused);
        }
        if disposition == PooledOfferDisposition::IgnoreReplay {
            return Ok(());
        }
        let reservation = match reserve_physical_for_incoming_offer(
            &self.physical,
            &remote_addr,
            signal.expires_at_ms,
            deadline,
        )
        .await
        {
            Ok(reservation) => reservation,
            Err(_) => {
                let _ = self
                    .send_reject(sender_xonly, signal.negotiation_id)
                    .await;
                return Err(TransportError::ConnectionRefused);
            }
        };
        if disposition == PooledOfferDisposition::Redial {
            let phase_owner_id = signal.negotiation_id.clone();
            let _ = self
                .send_reject(sender_xonly, signal.negotiation_id)
                .await;
            return self
                .start_outbound(remote_addr, reservation, deadline, Some(phase_owner_id))
                .await;
        }

        let session_id = signal.negotiation_id.clone();
        let pc = reservation.activate(self.new_peer_connection().await?);
        pc.record_remote_candidates(remote_candidate_count);
        let callback_transport_id = self.transport_id;
        let callback_packet_tx = self.packet_tx.clone();
        let callback_pool = Arc::downgrade(&self.pool);
        let callback_pending = Arc::downgrade(&self.pending);
        let callback_failed = Arc::downgrade(&self.failed);
        let callback_ready = Arc::downgrade(&self.ready);
        let callback_physical = self.physical.clone();
        let pc_for_data_channel = Arc::downgrade(&pc);
        let session_for_data_channel = session_id.clone();
        let addr_for_data_channel = remote_addr.clone();
        pc.on_data_channel(Box::new(move |data_channel: Arc<RTCDataChannel>| {
            let packet_tx = callback_packet_tx.clone();
            let pool = callback_pool.upgrade();
            let pending = callback_pending.upgrade();
            let failed = callback_failed.upgrade();
            let ready = callback_ready.upgrade();
            let physical = callback_physical.clone();
            let remote_addr = addr_for_data_channel.clone();
            let session_id = session_for_data_channel.clone();
            let pc = pc_for_data_channel.upgrade();
            Box::pin(async move {
                let (Some(pc), Some(pool), Some(pending), Some(failed), Some(ready)) =
                    (pc, pool, pending, failed, ready)
                else {
                    return;
                };
                wire_data_channel(
                    WebRtcDataChannelContext {
                        transport_id: callback_transport_id,
                        packet_tx,
                        physical,
                        owners: WebRtcSessionOwners {
                            pool,
                            pending,
                            failed,
                            ready,
                        },
                    },
                    remote_addr,
                    session_id,
                    pc,
                    data_channel,
                );
            })
        }));

        if !self
            .try_reserve_pending(
                &remote_addr,
                PendingDial {
                    session_id: session_id.clone(),
                    phase_owner_id: session_id.clone(),
                    pc: Arc::clone(&pc),
                    created_at_ms: signal.created_at_ms,
                    origin: PendingDialOrigin::Remote,
                    deadline,
                },
            )
            .await
        {
            close_peer_connection_bounded(pc).await;
            let _ = self.send_reject(sender_xonly, session_id).await;
            return Err(TransportError::ConnectionRefused);
        }
        wire_peer_connection_state(
            self,
            remote_addr.clone(),
            session_id.clone(),
            Arc::clone(&pc),
        );
        let result = async {
            pc.set_remote_description(offer)
                .await
                .map_err(|e| TransportError::StartFailed(e.to_string()))?;
            let answer = pc
                .create_answer(None)
                .await
                .map_err(|e| TransportError::StartFailed(e.to_string()))?;
            let mut gathering = pc.gathering_complete_promise().await;
            pc.set_local_description(answer)
                .await
                .map_err(|e| TransportError::StartFailed(e.to_string()))?;
            wait_for_ice_gathering(
                Duration::from_millis(self.config.ice_gather_timeout_ms()),
                &mut gathering,
            )
            .await?;

            let sdp = pc
                .local_description()
                .await
                .ok_or_else(|| TransportError::StartFailed("missing local WebRTC answer".into()))?
                .sdp;
            let candidate_count =
                require_non_trickle_ice_candidates(&sdp, EmbeddedCandidateScope::Local)?;
            pc.record_local_candidates(candidate_count);
            let now = now_ms();
            if tokio::time::Instant::now() >= deadline || signal.expires_at_ms < now {
                return Err(TransportError::Timeout);
            }
            let reply = WebRtcSignal {
                version: crate::transport::link_negotiation::LINK_NEGOTIATION_VERSION,
                negotiation_id: session_id.clone(),
                link_type: "webrtc".to_string(),
                kind: LinkNegotiationKind::Answer,
                created_at_ms: now,
                expires_at_ms: signal.expires_at_ms,
                payload: WebRtcSignalPayload {
                    sdp: Some(sdp),
                    candidates: None,
                },
            };
            self.queue_signal_for_pending(
                &remote_addr,
                &session_id,
                &pc,
                sender_xonly,
                &reply,
            )
            .await?;
            self.negotiation.record_answer_queued();
            debug!(
                transport_id = %self.transport_id,
                remote_addr = %remote_addr,
                negotiation = %reply.negotiation_id,
                sdp_bytes = reply.payload.sdp.as_ref().map(|s| s.len()).unwrap_or(0),
                candidate_raw = candidate_count.raw_lines,
                candidate_routes = candidate_count.unique_routes,
                "WebRTC answer sent"
            );
            Ok(())
        }
        .await;

        if let Err(err) = &result {
            if is_negotiation_timeout(err) {
                self.negotiation.record_timeout();
            }
            Self::record_partial_local_candidate_diagnostic(&pc).await;
            warn!(
                transport_id = %self.transport_id,
                remote_addr = %remote_addr,
                negotiation = %session_id,
                stage = "inbound-answer-before-data-channel-open",
                rtc = %pc.failure_stage_diagnostic(),
                error = %err,
                "WebRTC negotiation failed"
            );
            let expected_owner = WebRtcSessionOwner::new(&session_id, &pc);
            self.mark_session_failed(
                remote_addr,
                &expected_owner,
                format!("WebRTC inbound connection failed: {err}"),
            )
            .await;
        } else {
            self.spawn_connect_timeout(
                remote_addr.clone(),
                session_id.clone(),
                deadline,
                &pc,
            );
        }
        result
    }

    async fn try_reserve_pending(
        &self,
        addr: &TransportAddr,
        dial: PendingDial,
    ) -> bool {
        if !self.physical.is_accepting()
            || self.physical.phase(addr) != Some(PhysicalPhase::Active)
        {
            return false;
        }
        let pool = self.pool.lock().await;
        let mut pending = self.pending.lock().await;
        if pool.contains_key(addr) || pending.contains_key(addr) {
            return false;
        }
        pending.insert(addr.clone(), dial);
        self.failed.lock().await.remove(addr);
        true
    }

    async fn handle_answer(
        &self,
        signal: WebRtcSignal,
        sender_full_hex: &str,
    ) -> Result<(), TransportError> {
        let remote_addr = TransportAddr::from_string(sender_full_hex);
        let pending_session = {
            let pending = self.pending.lock().await;
            pending.get(&remote_addr).map(|pending| {
                (
                    pending.session_id.clone(),
                    Arc::clone(&pending.pc),
                    pending.deadline,
                )
            })
        };
        let Some((pending_session_id, pc, deadline)) = pending_session else {
            if self
                .pool
                .lock()
                .await
                .get(&remote_addr)
                .is_some_and(|connection| connection.session_id == signal.negotiation_id)
            {
                return Ok(());
            }
            warn!(
                transport_id = %self.transport_id,
                remote_addr = %remote_addr,
                negotiation = %signal.negotiation_id,
                "Late or unknown WebRTC answer has no matching session"
            );
            self.negotiation.record_answer_without_session();
            return Err(TransportError::StartFailed(
                "late or unknown WebRTC answer".into(),
            ));
        };
        if pending_session_id != signal.negotiation_id {
            return Err(TransportError::StartFailed(
                "WebRTC answer session mismatch".into(),
            ));
        }
        let result: Result<EmbeddedCandidateCount, TransportError> =
            tokio::time::timeout_at(deadline, async {
            let answer_sdp = self
                .mdns_resolver
                .resolve_sdp(signal.payload.sdp.as_deref().unwrap_or_default())
                .await?;
            let candidate_count =
                require_non_trickle_ice_candidates(&answer_sdp, EmbeddedCandidateScope::Remote)?;
            pc.record_remote_candidates(candidate_count);
            let answer = RTCSessionDescription::answer(answer_sdp)
                .map_err(|e| TransportError::StartFailed(e.to_string()))?;
            pc.set_remote_description(answer)
                .await
                .map_err(|e| TransportError::StartFailed(e.to_string()))?;
            if !self
                .session_generation_is_active_or_pooled(
                    &remote_addr,
                    &signal.negotiation_id,
                    &pc,
                )
                .await
            {
                return Err(TransportError::ConnectionRefused);
            }
            Ok(candidate_count)
            })
            .await
            .unwrap_or(Err(TransportError::Timeout));
        let candidate_count = match result {
            Ok(candidate_count) => candidate_count,
            Err(error) => {
                warn!(
                    transport_id = %self.transport_id,
                    remote_addr = %remote_addr,
                    negotiation = %signal.negotiation_id,
                    stage = "apply-answer-before-data-channel-open",
                    rtc = %pc.failure_stage_diagnostic(),
                    error = %error,
                    "WebRTC negotiation failed"
                );
                let expected_owner = WebRtcSessionOwner::new(&signal.negotiation_id, &pc);
                let won_failure = self
                    .mark_session_failed(
                        remote_addr,
                        &expected_owner,
                        format!("WebRTC answer failed: {error}"),
                    )
                    .await;
                if matches!(error, TransportError::Timeout) {
                    self.negotiation.record_late_answer_rejected();
                    if won_failure {
                        self.negotiation.record_timeout();
                    }
                }
                return Err(error);
            }
        };
        debug!(
            transport_id = %self.transport_id,
            remote_addr = %sender_full_hex,
            negotiation = %signal.negotiation_id,
            candidate_raw = candidate_count.raw_lines,
            candidate_routes = candidate_count.unique_routes,
            "WebRTC answer applied"
        );
        self.negotiation.record_answer_applied();
        Ok(())
    }

}

fn incoming_offer_wins_glare(local_pubkey_hex: &str, remote_pubkey_hex: &str) -> bool {
    remote_pubkey_hex < local_pubkey_hex
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PooledOfferDisposition {
    Accept,
    IgnoreReplay,
    Redial,
}

async fn prepare_pooled_webrtc_session_for_offer(
    pool: &ConnectionPool,
    pending: &PendingPool,
    failed: &FailedPool,
    ready: &ReadyPool,
    remote_addr: &TransportAddr,
    incoming_session_id: &str,
    local_pubkey_hex: &str,
) -> PooledOfferDisposition {
    let existing_owner = pool
        .lock()
        .await
        .get(remote_addr)
        .map(|connection| WebRtcSessionOwner::new(&connection.session_id, &connection.pc));
    let Some(existing_owner) = existing_owner else {
        return PooledOfferDisposition::Accept;
    };
    if existing_owner.session_id.as_deref() == Some(incoming_session_id) {
        return PooledOfferDisposition::IgnoreReplay;
    }

    let owners = WebRtcSessionOwners::from_refs(pool, pending, failed, ready);
    cleanup_webrtc_session(
        &owners,
        remote_addr,
        Some(&existing_owner),
        None,
        CleanupWait::Started,
    )
    .await;
    pooled_replacement_disposition(
        local_pubkey_hex,
        remote_addr.as_str().unwrap_or_default(),
    )
}

fn pooled_replacement_disposition(
    local_pubkey_hex: &str,
    remote_pubkey_hex: &str,
) -> PooledOfferDisposition {
    if incoming_offer_wins_glare(local_pubkey_hex, remote_pubkey_hex) {
        PooledOfferDisposition::Accept
    } else {
        PooledOfferDisposition::Redial
    }
}

include!("webrtc_data_channel.rs");

include!("webrtc_transport_trait.rs");

#[cfg(test)]
#[path = "webrtc/tests.rs"]
mod tests;

#[cfg(test)]
#[path = "webrtc/drop_tests.rs"]
mod drop_tests;

#[cfg(test)]
#[path = "webrtc/signal_tests.rs"]
mod signal_tests;

#[cfg(test)]
#[path = "webrtc/replacement_tests.rs"]
mod replacement_tests;

#[cfg(test)]
#[path = "webrtc/negotiation_tests.rs"]
mod negotiation_tests;

#[cfg(all(test, unix))]
#[path = "webrtc/low_fd_tests.rs"]
mod low_fd_tests;

#[cfg(test)]
#[path = "webrtc/candidate_policy_tests.rs"]
mod candidate_policy_tests;
