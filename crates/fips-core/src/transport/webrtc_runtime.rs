#[derive(Clone)]
struct WebRtcRuntime {
    transport_id: TransportId,
    config: WebRtcConfig,
    api: Arc<::webrtc::api::API>,
    mdns_resolver: SharedMdnsResolver,
    packet_tx: PacketTx,
    pool: ConnectionPool,
    pending: PendingPool,
    failed: FailedPool,
    ready: ReadyPool,
    seen_sessions: SeenSessionPool,
    physical: PhysicalResources,
    local_pubkey_hex: String,
    stun_servers: Vec<String>,
    signaling: FipsSignalSender,
}

impl WebRtcRuntime {
    async fn start_outbound(
        &self,
        remote_addr: TransportAddr,
        reservation: PhysicalReservation,
    ) -> Result<(), TransportError> {
        let remote_pubkey_hex = remote_addr.as_str().unwrap_or_default().to_string();
        let remote_xonly = xonly_from_compressed_hex(&remote_pubkey_hex)?;
        let session_id = random_session_id();

        let pc = reservation.activate(self.new_peer_connection().await?);
        let data_channel = match pc
            .create_data_channel(
                self.config.data_channel_label(),
                Some(RTCDataChannelInit {
                    ordered: Some(self.config.ordered()),
                    max_retransmits: self.config.max_retransmits(),
                    ..Default::default()
                }),
            )
            .await
        {
            Ok(data_channel) => data_channel,
            Err(error) => {
                close_peer_connection_bounded(pc).await;
                return Err(TransportError::StartFailed(error.to_string()));
            }
        };

        wire_data_channel(
            self.transport_id,
            self.packet_tx.clone(),
            WebRtcSessionOwners::from_refs(
                &self.pool,
                &self.pending,
                &self.failed,
                &self.ready,
            ),
            remote_addr.clone(),
            session_id.clone(),
            Arc::clone(&pc),
            Arc::clone(&data_channel),
        );

        if !self
            .try_reserve_pending(
                &remote_addr,
                session_id.clone(),
                Arc::clone(&pc),
                now_ms(),
                PendingDialOrigin::Local,
            )
            .await
        {
            close_data_channel_bounded(data_channel).await;
            close_peer_connection_bounded(pc).await;
            return Ok(());
        }
        wire_peer_connection_state(
            self,
            remote_addr.clone(),
            session_id.clone(),
            Arc::clone(&pc),
        );
        self.spawn_connect_timeout(remote_addr.clone(), session_id.clone());

        let result = async {
            let offer = pc
                .create_offer(None)
                .await
                .map_err(|e| TransportError::StartFailed(e.to_string()))?;
            let mut gathering = pc.gathering_complete_promise().await;
            pc.set_local_description(offer)
                .await
                .map_err(|e| TransportError::StartFailed(e.to_string()))?;
            let _ = tokio::time::timeout(
                Duration::from_millis(self.config.ice_gather_timeout_ms()),
                gathering.recv(),
            )
            .await;

            let sdp = pc
                .local_description()
                .await
                .ok_or_else(|| TransportError::StartFailed("missing local WebRTC offer".into()))?
                .sdp;
            let now = now_ms();
            let signal = WebRtcSignal {
                version: crate::transport::link_negotiation::LINK_NEGOTIATION_VERSION,
                negotiation_id: session_id.clone(),
                link_type: "webrtc".to_string(),
                kind: LinkNegotiationKind::Offer,
                created_at_ms: now,
                expires_at_ms: now.saturating_add(SIGNAL_TTL_MS),
                payload: WebRtcSignalPayload {
                    sdp: Some(sdp),
                    candidates: None,
                },
            };
            self.signaling.send_signal(remote_xonly, &signal).await?;
            debug!(
                transport_id = %self.transport_id,
                remote_addr = %remote_addr,
                negotiation = %signal.negotiation_id,
                sdp_bytes = signal.payload.sdp.as_ref().map(|s| s.len()).unwrap_or(0),
                "WebRTC offer sent"
            );
            Ok(())
        }
        .await;
        if let Err(error) = result {
            self.mark_session_failed(
                remote_addr,
                &session_id,
                format!("WebRTC outbound connection failed: {error}"),
            )
            .await;
            close_peer_connection_bounded(pc).await;
            return Err(error);
        }
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
        self.validate_signal(&signal)?;
        match signal.kind {
            LinkNegotiationKind::Offer => {
                self.handle_offer(signal, incoming.sender, incoming.sender_full_hex)
                    .await
            }
            LinkNegotiationKind::Answer => {
                self.handle_answer(signal, &incoming.sender_full_hex).await
            }
            LinkNegotiationKind::Reject => {
                let addr = TransportAddr::from_string(&incoming.sender_full_hex);
                self.mark_session_failed(
                    addr,
                    &signal.negotiation_id,
                    "peer rejected WebRTC session".to_string(),
                )
                .await;
                Ok(())
            }
            LinkNegotiationKind::Candidate => Ok(()),
        }
    }

    async fn handle_offer(
        &self,
        signal: WebRtcSignal,
        sender_xonly: PublicKey,
        sender_full_hex: String,
    ) -> Result<(), TransportError> {
        let remote_addr = TransportAddr::from_string(&sender_full_hex);
        let pending = self.pending.lock().await.get(&remote_addr).map(|pending| {
            (
                pending.session_id.clone(),
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
        if let Some((pending_session, pending_created_at_ms, pending_origin)) = pending {
            if pending_session == signal.negotiation_id {
                return Ok(());
            }
            if !incoming_offer_replaces_pending(
                &self.local_pubkey_hex,
                &sender_full_hex,
                pending_origin,
                pending_created_at_ms,
                signal.created_at_ms,
            ) || !evict_pending_webrtc_session_for_offer(
                &self.pending,
                &self.failed,
                &self.ready,
                &remote_addr,
                &pending_session,
            )
            .await
            {
                let _ = self
                    .send_reject(sender_xonly, signal.negotiation_id)
                    .await;
                return Err(TransportError::ConnectionRefused);
            }
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
            let _ = self
                .send_reject(sender_xonly, signal.negotiation_id)
                .await;
            return self.start_outbound(remote_addr, reservation).await;
        }

        let session_id = signal.negotiation_id.clone();
        let pc = reservation.activate(self.new_peer_connection().await?);
        let callback_transport_id = self.transport_id;
        let callback_packet_tx = self.packet_tx.clone();
        let callback_pool = Arc::downgrade(&self.pool);
        let callback_pending = Arc::downgrade(&self.pending);
        let callback_failed = Arc::downgrade(&self.failed);
        let callback_ready = Arc::downgrade(&self.ready);
        let pc_for_data_channel = Arc::downgrade(&pc);
        let session_for_data_channel = session_id.clone();
        let addr_for_data_channel = remote_addr.clone();
        pc.on_data_channel(Box::new(move |data_channel: Arc<RTCDataChannel>| {
            let packet_tx = callback_packet_tx.clone();
            let pool = callback_pool.upgrade();
            let pending = callback_pending.upgrade();
            let failed = callback_failed.upgrade();
            let ready = callback_ready.upgrade();
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
                    callback_transport_id,
                    packet_tx,
                    WebRtcSessionOwners {
                        pool,
                        pending,
                        failed,
                        ready,
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
                session_id.clone(),
                Arc::clone(&pc),
                signal.created_at_ms,
                PendingDialOrigin::Remote,
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
        self.spawn_connect_timeout(remote_addr.clone(), session_id.clone());

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
            let _ = tokio::time::timeout(
                Duration::from_millis(self.config.ice_gather_timeout_ms()),
                gathering.recv(),
            )
            .await;

            let sdp = pc
                .local_description()
                .await
                .ok_or_else(|| TransportError::StartFailed("missing local WebRTC answer".into()))?
                .sdp;
            let now = now_ms();
            let reply = WebRtcSignal {
                version: crate::transport::link_negotiation::LINK_NEGOTIATION_VERSION,
                negotiation_id: session_id.clone(),
                link_type: "webrtc".to_string(),
                kind: LinkNegotiationKind::Answer,
                created_at_ms: now,
                expires_at_ms: now.saturating_add(SIGNAL_TTL_MS),
                payload: WebRtcSignalPayload {
                    sdp: Some(sdp),
                    candidates: None,
                },
            };
            self.signaling.send_signal(sender_xonly, &reply).await?;
            debug!(
                transport_id = %self.transport_id,
                remote_addr = %remote_addr,
                negotiation = %reply.negotiation_id,
                sdp_bytes = reply.payload.sdp.as_ref().map(|s| s.len()).unwrap_or(0),
                "WebRTC answer sent"
            );
            Ok(())
        }
        .await;

        if let Err(err) = &result {
            self.mark_session_failed(
                remote_addr,
                &session_id,
                format!("WebRTC inbound connection failed: {err}"),
            )
            .await;
        }
        result
    }

    async fn try_reserve_pending(
        &self,
        addr: &TransportAddr,
        session_id: String,
        pc: ManagedPeer,
        created_at_ms: u64,
        origin: PendingDialOrigin,
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
        pending.insert(
            addr.clone(),
            PendingDial {
                session_id,
                pc,
                created_at_ms,
                origin,
            },
        );
        true
    }

    async fn handle_answer(
        &self,
        signal: WebRtcSignal,
        sender_full_hex: &str,
    ) -> Result<(), TransportError> {
        let remote_addr = TransportAddr::from_string(sender_full_hex);
        let pc = {
            let pending = self.pending.lock().await;
            let Some(pending) = pending.get(&remote_addr) else {
                return Ok(());
            };
            if pending.session_id != signal.negotiation_id {
                return Err(TransportError::StartFailed(
                    "WebRTC answer session mismatch".into(),
                ));
            }
            Arc::clone(&pending.pc)
        };
        let result: Result<(), TransportError> = async {
            let answer_sdp = self
                .mdns_resolver
                .resolve_sdp(signal.payload.sdp.as_deref().unwrap_or_default())
                .await?;
            let answer = RTCSessionDescription::answer(answer_sdp)
                .map_err(|e| TransportError::StartFailed(e.to_string()))?;
            pc.set_remote_description(answer)
                .await
                .map_err(|e| TransportError::StartFailed(e.to_string()))?;
            Ok(())
        }
        .await;
        if let Err(error) = result {
            self.mark_session_failed(
                remote_addr,
                &signal.negotiation_id,
                format!("WebRTC answer failed: {error}"),
            )
            .await;
            return Err(error);
        }
        debug!(
            transport_id = %self.transport_id,
            remote_addr = %sender_full_hex,
            negotiation = %signal.negotiation_id,
            "WebRTC answer applied"
        );
        Ok(())
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
        self.signaling.send_signal(recipient_xonly, &reject).await
    }

    async fn new_peer_connection(&self) -> Result<RTCPeerConnection, TransportError> {
        self.new_peer_connection_with_api(&self.api).await
    }

    async fn new_peer_connection_with_api(
        &self,
        api: &::webrtc::api::API,
    ) -> Result<RTCPeerConnection, TransportError> {
        api
            .new_peer_connection(RTCConfiguration {
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
        ) && signal
            .payload
            .sdp
            .as_deref()
            .is_none_or(|sdp| sdp.is_empty() || sdp.len() > MAX_WEBRTC_SDP_LENGTH)
        {
            return Err(TransportError::InvalidAddress(
                "WebRTC offer/answer requires bounded SDP".into(),
            ));
        }
        if let Some(candidates) = &signal.payload.candidates
            && (candidates.len() > MAX_WEBRTC_CANDIDATES
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

    async fn mark_session_failed(&self, addr: TransportAddr, session_id: &str, reason: String) {
        let pending = {
            let mut pending = self.pending.lock().await;
            if pending
                .get(&addr)
                .is_some_and(|pending| pending.session_id == session_id)
            {
                pending.remove(&addr)
            } else {
                None
            }
        };
        let Some(pending) = pending else {
            return;
        };
        self.ready.lock().await.remove(&addr);
        self.failed
            .lock()
            .await
            .insert(addr.clone(), reason.clone());
        warn!(
            transport_id = %self.transport_id,
            remote_addr = %addr,
            reason = %reason,
            "WebRTC connection failed"
        );
        close_peer_connection_bounded(pending.pc).await;
    }

    fn spawn_connect_timeout(&self, addr: TransportAddr, session_id: String) {
        let timeout = Duration::from_millis(self.config.connect_timeout_ms());
        let pending = Arc::downgrade(&self.pending);
        let failed = Arc::downgrade(&self.failed);
        let transport_id = self.transport_id;
        tokio::spawn(async move {
            tokio::time::sleep(timeout).await;
            let Some(pending) = pending.upgrade() else {
                return;
            };
            let maybe_pending = {
                let mut pending = pending.lock().await;
                match pending.get(&addr) {
                    Some(dial) if dial.session_id == session_id => pending.remove(&addr),
                    _ => None,
                }
            };
            drop(pending);
            if let Some(dial) = maybe_pending {
                let reason = "WebRTC connect timed out".to_string();
                if let Some(failed) = failed.upgrade() {
                    failed.lock().await.insert(addr.clone(), reason.clone());
                }
                close_peer_connection_bounded(dial.pc).await;
                warn!(
                    transport_id = %transport_id,
                    remote_addr = %addr,
                    reason = %reason,
                    "WebRTC connection failed"
                );
            }
        });
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
    let existing_session = pool
        .lock()
        .await
        .get(remote_addr)
        .map(|connection| connection.session_id.clone());
    let Some(existing_session) = existing_session else {
        return PooledOfferDisposition::Accept;
    };
    if existing_session == incoming_session_id {
        return PooledOfferDisposition::IgnoreReplay;
    }

    let owners = WebRtcSessionOwners::from_refs(pool, pending, failed, ready);
    cleanup_webrtc_session(
        &owners,
        remote_addr,
        Some(&existing_session),
        None,
        CleanupWait::Physical,
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

fn wire_data_channel(
    transport_id: TransportId,
    packet_tx: PacketTx,
    owners: WebRtcSessionOwners,
    remote_addr: TransportAddr,
    session_id: String,
    pc: ManagedPeer,
    data_channel: Arc<RTCDataChannel>,
) {
    let WebRtcSessionOwners {
        pool,
        pending,
        failed,
        ready,
    } = owners;
    let recv_addr = remote_addr.clone();
    let recv_session = session_id.clone();
    let recv_tx = packet_tx;
    let recv_ready = Arc::downgrade(&ready);
    let recv_pool = Arc::downgrade(&pool);
    data_channel.on_message(Box::new(move |msg: DataChannelMessage| {
        let recv_addr = recv_addr.clone();
        let recv_session = recv_session.clone();
        let recv_tx = recv_tx.clone();
        let recv_ready = recv_ready.clone();
        let recv_pool = recv_pool.clone();
        Box::pin(async move {
            if msg.is_string {
                debug!(
                    transport_id = %transport_id,
                    remote_addr = %recv_addr,
                    "WebRTC string data channel message ignored"
                );
                return;
            }
            if msg.data.as_ref() == WEBRTC_READY_FRAME {
                let (Some(recv_pool), Some(recv_ready)) =
                    (recv_pool.upgrade(), recv_ready.upgrade())
                else {
                    return;
                };
                if recv_pool
                    .lock()
                    .await
                    .get(&recv_addr)
                    .is_some_and(|connection| connection.session_id == recv_session)
                {
                    mark_webrtc_ready(transport_id, recv_addr, recv_ready).await;
                }
                return;
            }
            let data = msg.data.to_vec();
            match data.first().copied() {
                Some(1 | 2) => {
                    debug!(
                        transport_id = %transport_id,
                        remote_addr = %recv_addr,
                        bytes = data.len(),
                        first_byte = data.first().copied(),
                        "WebRTC data channel handshake packet received"
                    );
                }
                _ => {
                    trace!(
                        transport_id = %transport_id,
                        remote_addr = %recv_addr,
                        bytes = data.len(),
                        first_byte = data.first().copied(),
                        "WebRTC data channel packet received"
                    );
                }
            }
            if let Err(err) = recv_tx.send(ReceivedPacket::with_timestamp(
                transport_id,
                recv_addr,
                PacketBuffer::new(data),
                crate::time::now_ms(),
            )) {
                warn!(
                    transport_id = %transport_id,
                    error = %err,
                    "WebRTC packet enqueue failed"
                );
            }
        })
    }));

    let open_addr = remote_addr.clone();
    let open_session = session_id.clone();
    // Callbacks live on these objects, so strong back-references would keep
    // failed ICE agents and their sockets alive after close.
    let open_pc = Arc::downgrade(&pc);
    let open_dc = Arc::downgrade(&data_channel);
    let open_pool = Arc::downgrade(&pool);
    let open_pending = Arc::downgrade(&pending);
    let open_failed = Arc::downgrade(&failed);
    let open_ready = Arc::downgrade(&ready);
    data_channel.on_open(Box::new(move || {
        let open_addr = open_addr.clone();
        let open_session = open_session.clone();
        let open_pc = open_pc.clone();
        let open_dc = open_dc.clone();
        let open_pool = open_pool.clone();
        let open_pending = open_pending.clone();
        let open_failed = open_failed.clone();
        let open_ready = open_ready.clone();
        Box::pin(async move {
            let (Some(open_pc), Some(open_dc)) = (open_pc.upgrade(), open_dc.upgrade()) else {
                return;
            };
            let (Some(open_pool), Some(open_pending), Some(open_failed), Some(open_ready)) = (
                open_pool.upgrade(),
                open_pending.upgrade(),
                open_failed.upgrade(),
                open_ready.upgrade(),
            ) else {
                close_data_channel_bounded(open_dc).await;
                close_peer_connection_bounded(open_pc).await;
                return;
            };
            if open_pc.is_closing() {
                return;
            }
            let ready_dc = Arc::clone(&open_dc);
            let is_active_session = {
                let mut pending = open_pending.lock().await;
                if pending
                    .get(&open_addr)
                    .is_some_and(|pending| pending.session_id == open_session)
                {
                    pending.remove(&open_addr);
                    true
                } else {
                    false
                }
            };
            if !is_active_session || open_pc.is_closing() {
                close_data_channel_bounded(open_dc).await;
                close_peer_connection_bounded(open_pc).await;
                return;
            }
            open_failed.lock().await.remove(&open_addr);
            let previous = open_pool.lock().await.insert(
                open_addr.clone(),
                WebRtcConnection {
                    session_id: open_session.clone(),
                    pc: Arc::clone(&open_pc),
                    data_channel: open_dc,
                },
            );
            if let Some(previous) = previous {
                close_data_channel_bounded(previous.data_channel).await;
                close_peer_connection_bounded(previous.pc).await;
            }
            if open_pc.is_closing() {
                spawn_webrtc_session_cleanup(
                    Arc::clone(&open_pool),
                    Arc::clone(&open_pending),
                    Arc::clone(&open_failed),
                    Arc::clone(&open_ready),
                    open_addr,
                    None,
                    None,
                );
                return;
            }
            let ready_sent = tokio::time::timeout(
                WEBRTC_IO_TIMEOUT,
                ready_dc.send(&Bytes::copy_from_slice(WEBRTC_READY_FRAME)),
            )
            .await;
            if !matches!(ready_sent, Ok(Ok(_))) {
                debug!(
                    transport_id = %transport_id,
                    remote_addr = %open_addr,
                    result = ?ready_sent,
                    "Failed to send bounded WebRTC ready marker"
                );
                spawn_webrtc_session_cleanup(
                    open_pool,
                    open_pending,
                    open_failed,
                    open_ready,
                    open_addr,
                    Some(open_session),
                    Some("WebRTC ready marker failed".into()),
                );
                return;
            }
            spawn_webrtc_ready_fallback(
                transport_id,
                open_addr.clone(),
                open_session,
                Arc::clone(&open_pool),
                Arc::clone(&open_ready),
            );
            debug!(remote_addr = %open_addr, "WebRTC data channel open");
        })
    }));

    let close_addr = remote_addr;
    let close_session = session_id;
    let close_pc = Arc::downgrade(&pc);
    let close_pool = Arc::downgrade(&pool);
    let close_pending = Arc::downgrade(&pending);
    let close_failed = Arc::downgrade(&failed);
    let close_ready = Arc::downgrade(&ready);
    data_channel.on_close(Box::new(move || {
        let close_addr = close_addr.clone();
        let close_session = close_session.clone();
        let close_pc = close_pc.clone();
        let close_pool = close_pool.clone();
        let close_pending = close_pending.clone();
        let close_failed = close_failed.clone();
        let close_ready = close_ready.clone();
        Box::pin(async move {
            let Some(close_pc) = close_pc.upgrade() else {
                return;
            };
            if !spawn_managed_peer_cleanup(&close_pc) {
                return;
            }
            let (Some(close_pool), Some(close_pending), Some(close_failed), Some(close_ready)) = (
                close_pool.upgrade(),
                close_pending.upgrade(),
                close_failed.upgrade(),
                close_ready.upgrade(),
            ) else {
                return;
            };
            spawn_webrtc_session_cleanup(
                close_pool,
                close_pending,
                close_failed,
                close_ready,
                close_addr,
                Some(close_session),
                None,
            );
        })
    }));
}

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

#[cfg(all(test, unix))]
#[path = "webrtc/low_fd_tests.rs"]
mod low_fd_tests;
