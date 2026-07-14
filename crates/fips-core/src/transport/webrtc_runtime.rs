#[derive(Clone)]
struct WebRtcRuntime {
    transport_id: TransportId,
    config: WebRtcConfig,
    api: Arc<::webrtc::api::API>,
    incoming_native_api: Arc<::webrtc::api::API>,
    packet_tx: PacketTx,
    pool: ConnectionPool,
    pending: PendingPool,
    failed: FailedPool,
    ready: ReadyPool,
    seen_sessions: SeenSessionPool,
    local_pubkey_hex: String,
    signal_relays: Vec<String>,
    stun_servers: Vec<String>,
    signaling: NostrSignalSender,
}

impl WebRtcRuntime {
    async fn start_outbound(&self, remote_addr: TransportAddr) -> Result<(), TransportError> {
        let remote_pubkey_hex = remote_addr.as_str().unwrap_or_default().to_string();
        let remote_xonly = xonly_from_compressed_hex(&remote_pubkey_hex)?;
        let session_id = random_session_id();

        let pc = Arc::new(self.new_peer_connection().await?);
        let data_channel = pc
            .create_data_channel(
                self.config.data_channel_label(),
                Some(RTCDataChannelInit {
                    ordered: Some(self.config.ordered()),
                    max_retransmits: self.config.max_retransmits(),
                    ..Default::default()
                }),
            )
            .await
            .map_err(|e| TransportError::StartFailed(e.to_string()))?;

        wire_data_channel(
            self,
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
            protocol: WEBRTC_PROTOCOL.to_string(),
            version: WEBRTC_SIGNAL_VERSION,
            session_id,
            kind: WebRtcSignalKind::Offer,
            sender: self.local_pubkey_hex.clone(),
            recipient: remote_pubkey_hex,
            sdp: Some(sdp),
            candidates: None,
            created_at_ms: now,
            expires_at_ms: now.saturating_add(SIGNAL_TTL_MS),
        };
        self.signaling
            .send_signal(&self.signal_relays, remote_xonly, &signal)
            .await?;
        debug!(
            transport_id = %self.transport_id,
            remote_addr = %remote_addr,
            session = %signal.session_id,
            sdp_bytes = signal.sdp.as_ref().map(|s| s.len()).unwrap_or(0),
            "WebRTC offer sent"
        );
        Ok(())
    }

    async fn handle_incoming_signal(&self, incoming: IncomingSignal) -> Result<(), TransportError> {
        let signal = incoming.signal;
        debug!(
            transport_id = %self.transport_id,
            kind = ?signal.kind,
            session = %signal.session_id,
            sender = %signal.sender,
            "WebRTC signal received"
        );
        self.validate_signal(&signal, incoming.sender)?;
        match signal.kind {
            WebRtcSignalKind::Offer => self.handle_offer(signal, incoming.sender).await,
            WebRtcSignalKind::Answer => self.handle_answer(signal).await,
            WebRtcSignalKind::Reject => {
                let addr = TransportAddr::from_string(&signal.sender);
                self.mark_session_failed(
                    addr,
                    &signal.session_id,
                    "peer rejected WebRTC session".to_string(),
                )
                .await;
                Ok(())
            }
            WebRtcSignalKind::Candidate => Ok(()),
        }
    }

    async fn handle_offer(
        &self,
        signal: WebRtcSignal,
        sender_xonly: PublicKey,
    ) -> Result<(), TransportError> {
        if !self.config.accept_connections() {
            return Ok(());
        }
        let remote_addr = TransportAddr::from_string(&signal.sender);
        let pending = self.pending.lock().await.get(&remote_addr).map(|pending| {
            (
                pending.session_id.clone(),
                pending.created_at_ms,
                pending.origin,
            )
        });
        if let Some((pending_session, pending_created_at_ms, pending_origin)) = pending {
            if pending_session == signal.session_id {
                return Ok(());
            }
            if !incoming_offer_replaces_pending(
                &self.local_pubkey_hex,
                &signal.sender,
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
                    .send_reject(&signal.sender, sender_xonly, signal.session_id)
                    .await;
                return Err(TransportError::ConnectionRefused);
            }
        }
        if !accept_webrtc_offer_once(
            &self.seen_sessions,
            &remote_addr,
            &signal.session_id,
            signal.expires_at_ms,
            now_ms(),
        )
        .await
        {
            debug!(
                transport_id = %self.transport_id,
                remote_addr = %remote_addr,
                session = %signal.session_id,
                "duplicate WebRTC offer ignored"
            );
            return Ok(());
        }
        let offer_sdp = signal.sdp.clone().unwrap_or_default();
        let offer = RTCSessionDescription::offer(offer_sdp.clone())
            .map_err(|e| TransportError::StartFailed(e.to_string()))?;
        match prepare_pooled_webrtc_session_for_offer(
            &self.pool,
            &self.pending,
            &self.failed,
            &self.ready,
            &remote_addr,
            &signal.session_id,
            &self.local_pubkey_hex,
        )
        .await
        {
            PooledOfferDisposition::Accept => {}
            PooledOfferDisposition::IgnoreReplay => return Ok(()),
            PooledOfferDisposition::Redial => {
                let _ = self
                    .send_reject(&signal.sender, sender_xonly, signal.session_id)
                    .await;
                return self.start_outbound(remote_addr).await;
            }
        }
        if self.pool.lock().await.len() + self.pending.lock().await.len()
            >= self.config.max_connections()
        {
            let _ = self
                .send_reject(&signal.sender, sender_xonly, signal.session_id)
                .await;
            return Err(TransportError::ConnectionRefused);
        }

        let session_id = signal.session_id.clone();
        let pc = Arc::new(self.new_incoming_peer_connection(&offer_sdp).await?);
        let runtime = self.clone();
        let pc_for_data_channel = Arc::downgrade(&pc);
        let session_for_data_channel = session_id.clone();
        let addr_for_data_channel = remote_addr.clone();
        pc.on_data_channel(Box::new(move |data_channel: Arc<RTCDataChannel>| {
            let runtime = runtime.clone();
            let remote_addr = addr_for_data_channel.clone();
            let session_id = session_for_data_channel.clone();
            let pc = pc_for_data_channel.upgrade();
            Box::pin(async move {
                if let Some(pc) = pc {
                    wire_data_channel(&runtime, remote_addr, session_id, pc, data_channel);
                }
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
            let _ = self
                .send_reject(&signal.sender, sender_xonly, session_id)
                .await;
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
                protocol: WEBRTC_PROTOCOL.to_string(),
                version: WEBRTC_SIGNAL_VERSION,
                session_id: session_id.clone(),
                kind: WebRtcSignalKind::Answer,
                sender: self.local_pubkey_hex.clone(),
                recipient: signal.sender.clone(),
                sdp: Some(sdp),
                candidates: None,
                created_at_ms: now,
                expires_at_ms: now.saturating_add(SIGNAL_TTL_MS),
            };
            self.signaling
                .send_signal(&self.signal_relays, sender_xonly, &reply)
                .await?;
            debug!(
                transport_id = %self.transport_id,
                remote_addr = %remote_addr,
                session = %reply.session_id,
                sdp_bytes = reply.sdp.as_ref().map(|s| s.len()).unwrap_or(0),
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
        pc: Arc<RTCPeerConnection>,
        created_at_ms: u64,
        origin: PendingDialOrigin,
    ) -> bool {
        let pool = self.pool.lock().await;
        let mut pending = self.pending.lock().await;
        if pool.contains_key(addr)
            || pending.contains_key(addr)
            || pool.len() + pending.len() >= self.config.max_connections()
        {
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

    async fn handle_answer(&self, signal: WebRtcSignal) -> Result<(), TransportError> {
        let remote_addr = TransportAddr::from_string(&signal.sender);
        let pc = {
            let pending = self.pending.lock().await;
            let Some(pending) = pending.get(&remote_addr) else {
                return Ok(());
            };
            if pending.session_id != signal.session_id {
                return Err(TransportError::StartFailed(
                    "WebRTC answer session mismatch".into(),
                ));
            }
            Arc::clone(&pending.pc)
        };
        let answer = RTCSessionDescription::answer(signal.sdp.unwrap_or_default())
            .map_err(|e| TransportError::StartFailed(e.to_string()))?;
        pc.set_remote_description(answer)
            .await
            .map_err(|e| TransportError::StartFailed(e.to_string()))?;
        debug!(
            transport_id = %self.transport_id,
            remote_addr = %signal.sender,
            session = %signal.session_id,
            "WebRTC answer applied"
        );
        Ok(())
    }

    async fn send_reject(
        &self,
        recipient_full_hex: &str,
        recipient_xonly: PublicKey,
        session_id: String,
    ) -> Result<(), TransportError> {
        let now = now_ms();
        let reject = WebRtcSignal {
            protocol: WEBRTC_PROTOCOL.to_string(),
            version: WEBRTC_SIGNAL_VERSION,
            session_id,
            kind: WebRtcSignalKind::Reject,
            sender: self.local_pubkey_hex.clone(),
            recipient: recipient_full_hex.to_string(),
            sdp: None,
            candidates: None,
            created_at_ms: now,
            expires_at_ms: now.saturating_add(SIGNAL_TTL_MS),
        };
        self.signaling
            .send_signal(&self.signal_relays, recipient_xonly, &reject)
            .await
    }

    async fn new_peer_connection(&self) -> Result<RTCPeerConnection, TransportError> {
        self.new_peer_connection_with_api(&self.api).await
    }

    async fn new_incoming_peer_connection(
        &self,
        remote_sdp: &str,
    ) -> Result<RTCPeerConnection, TransportError> {
        let api = if incoming_webrtc_mdns_mode(remote_sdp) == MulticastDnsMode::QueryOnly {
            &self.api
        } else {
            &self.incoming_native_api
        };
        self.new_peer_connection_with_api(api).await
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

    fn validate_signal(
        &self,
        signal: &WebRtcSignal,
        outer_sender: PublicKey,
    ) -> Result<(), TransportError> {
        if signal.protocol != WEBRTC_PROTOCOL {
            return Err(TransportError::InvalidAddress("bad WebRTC protocol".into()));
        }
        if signal.version != WEBRTC_SIGNAL_VERSION {
            return Err(TransportError::InvalidAddress("bad WebRTC version".into()));
        }
        if signal.recipient != self.local_pubkey_hex {
            return Err(TransportError::InvalidAddress(
                "WebRTC signal recipient is not local identity".into(),
            ));
        }
        validate_compressed_pubkey_hex(&signal.sender)?;
        validate_compressed_pubkey_hex(&signal.recipient)?;
        let sender_xonly = xonly_from_compressed_hex(&signal.sender)?;
        if sender_xonly != outer_sender {
            return Err(TransportError::InvalidAddress(
                "WebRTC signal sender does not match gift-wrap sender".into(),
            ));
        }
        let now = now_ms();
        if signal.expires_at_ms < now || signal.created_at_ms > now.saturating_add(60_000) {
            return Err(TransportError::Timeout);
        }
        if matches!(
            signal.kind,
            WebRtcSignalKind::Offer | WebRtcSignalKind::Answer
        ) && signal.sdp.as_deref().unwrap_or_default().is_empty()
        {
            return Err(TransportError::InvalidAddress(
                "WebRTC offer/answer requires SDP".into(),
            ));
        }
        Ok(())
    }

    async fn mark_failed(&self, addr: TransportAddr, reason: String) {
        let pending = self.pending.lock().await.remove(&addr);
        if let Some(pending) = pending {
            close_peer_connection_bounded(pending.pc).await;
        }
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
        close_peer_connection_bounded(pending.pc).await;
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
    }

    fn spawn_connect_timeout(&self, addr: TransportAddr, session_id: String) {
        let timeout = Duration::from_millis(self.config.connect_timeout_ms());
        let pending = Arc::clone(&self.pending);
        let failed = Arc::clone(&self.failed);
        let transport_id = self.transport_id;
        tokio::spawn(async move {
            tokio::time::sleep(timeout).await;
            let maybe_pending = {
                let mut pending = pending.lock().await;
                match pending.get(&addr) {
                    Some(dial) if dial.session_id == session_id => pending.remove(&addr),
                    _ => None,
                }
            };
            if let Some(dial) = maybe_pending {
                close_peer_connection_bounded(dial.pc).await;
                let reason = "WebRTC connect timed out".to_string();
                failed.lock().await.insert(addr.clone(), reason.clone());
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

    cleanup_webrtc_session(
        pool,
        pending,
        failed,
        ready,
        remote_addr,
        Some(&existing_session),
        None,
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

fn wire_peer_connection_state(
    runtime: &WebRtcRuntime,
    remote_addr: TransportAddr,
    session_id: String,
    pc: Arc<RTCPeerConnection>,
) {
    let transport_id = runtime.transport_id;
    let peer_addr = remote_addr.clone();
    let peer_session = session_id;
    let pool = Arc::clone(&runtime.pool);
    let pending = Arc::clone(&runtime.pending);
    let ready = Arc::clone(&runtime.ready);
    let failed = Arc::clone(&runtime.failed);
    pc.on_peer_connection_state_change(Box::new(move |state: RTCPeerConnectionState| {
        let peer_addr = peer_addr.clone();
        let peer_session = peer_session.clone();
        let pool = Arc::clone(&pool);
        let pending = Arc::clone(&pending);
        let ready = Arc::clone(&ready);
        let failed = Arc::clone(&failed);
        Box::pin(async move {
            debug!(
                transport_id = %transport_id,
                remote_addr = %peer_addr,
                state = %state,
                "WebRTC peer connection state changed"
            );
            if !webrtc_peer_state_is_terminal(state) {
                return;
            }
            spawn_webrtc_session_cleanup(
                pool,
                pending,
                failed,
                ready,
                peer_addr,
                Some(peer_session),
                Some(format!("WebRTC peer connection became {state}")),
            );
        })
    }));
}

fn webrtc_peer_state_is_terminal(state: RTCPeerConnectionState) -> bool {
    matches!(
        state,
        RTCPeerConnectionState::Disconnected
            | RTCPeerConnectionState::Failed
            | RTCPeerConnectionState::Closed
    )
}

fn wire_data_channel(
    runtime: &WebRtcRuntime,
    remote_addr: TransportAddr,
    session_id: String,
    pc: Arc<RTCPeerConnection>,
    data_channel: Arc<RTCDataChannel>,
) {
    let transport_id = runtime.transport_id;
    let recv_addr = remote_addr.clone();
    let recv_tx = runtime.packet_tx.clone();
    let recv_ready = Arc::clone(&runtime.ready);
    data_channel.on_message(Box::new(move |msg: DataChannelMessage| {
        let recv_addr = recv_addr.clone();
        let recv_tx = recv_tx.clone();
        let recv_ready = Arc::clone(&recv_ready);
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
                mark_webrtc_ready(transport_id, recv_addr, recv_ready).await;
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
    let open_pool = Arc::clone(&runtime.pool);
    let open_pending = Arc::clone(&runtime.pending);
    let open_failed = Arc::clone(&runtime.failed);
    let open_ready = Arc::clone(&runtime.ready);
    data_channel.on_open(Box::new(move || {
        let open_addr = open_addr.clone();
        let open_session = open_session.clone();
        let open_pc = open_pc.clone();
        let open_dc = open_dc.clone();
        let open_pool = Arc::clone(&open_pool);
        let open_pending = Arc::clone(&open_pending);
        let open_failed = Arc::clone(&open_failed);
        let open_ready = Arc::clone(&open_ready);
        Box::pin(async move {
            let (Some(open_pc), Some(open_dc)) = (open_pc.upgrade(), open_dc.upgrade()) else {
                return;
            };
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
            if !is_active_session {
                close_data_channel_bounded(open_dc).await;
                close_peer_connection_bounded(open_pc).await;
                return;
            }
            open_failed.lock().await.remove(&open_addr);
            let previous = open_pool.lock().await.insert(
                open_addr.clone(),
                WebRtcConnection {
                    session_id: open_session,
                    pc: open_pc,
                    data_channel: open_dc,
                },
            );
            if let Some(previous) = previous {
                close_data_channel_bounded(previous.data_channel).await;
                close_peer_connection_bounded(previous.pc).await;
            }
            if let Err(err) = ready_dc
                .send(&Bytes::copy_from_slice(WEBRTC_READY_FRAME))
                .await
            {
                debug!(
                    transport_id = %transport_id,
                    remote_addr = %open_addr,
                    error = %err,
                    "Failed to send WebRTC ready marker"
                );
            }
            spawn_webrtc_ready_fallback(
                transport_id,
                open_addr.clone(),
                Arc::clone(&open_pool),
                Arc::clone(&open_ready),
            );
            debug!(remote_addr = %open_addr, "WebRTC data channel open");
        })
    }));

    let close_addr = remote_addr;
    let close_session = session_id;
    let close_pool = Arc::clone(&runtime.pool);
    let close_pending = Arc::clone(&runtime.pending);
    let close_failed = Arc::clone(&runtime.failed);
    let close_ready = Arc::clone(&runtime.ready);
    data_channel.on_close(Box::new(move || {
        let close_addr = close_addr.clone();
        let close_session = close_session.clone();
        let close_pool = Arc::clone(&close_pool);
        let close_pending = Arc::clone(&close_pending);
        let close_failed = Arc::clone(&close_failed);
        let close_ready = Arc::clone(&close_ready);
        Box::pin(async move {
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

async fn mark_webrtc_ready(
    transport_id: TransportId,
    remote_addr: TransportAddr,
    ready: ReadyPool,
) {
    if ready.lock().await.insert(remote_addr.clone()) {
        debug!(
            transport_id = %transport_id,
            remote_addr = %remote_addr,
            "WebRTC data channel remote ready"
        );
    }
}

fn spawn_webrtc_ready_fallback(
    transport_id: TransportId,
    remote_addr: TransportAddr,
    pool: ConnectionPool,
    ready: ReadyPool,
) {
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(WEBRTC_READY_FALLBACK_MS)).await;
        if pool.lock().await.contains_key(&remote_addr) {
            mark_webrtc_ready(transport_id, remote_addr, ready).await;
        }
    });
}

fn validate_compressed_pubkey_addr(addr: &TransportAddr) -> Result<(), TransportError> {
    let Some(s) = addr.as_str() else {
        return Err(TransportError::InvalidAddress(
            "WebRTC address must be UTF-8 compressed pubkey hex".into(),
        ));
    };
    validate_compressed_pubkey_hex(s)
}

fn validate_compressed_pubkey_hex(s: &str) -> Result<(), TransportError> {
    if s.len() != 66 {
        return Err(TransportError::InvalidAddress(
            "WebRTC address must be 33-byte compressed pubkey hex".into(),
        ));
    }
    let bytes = hex::decode(s).map_err(|e| TransportError::InvalidAddress(e.to_string()))?;
    if bytes.len() != 33 || !matches!(bytes[0], 0x02 | 0x03) {
        return Err(TransportError::InvalidAddress(
            "WebRTC address must be compressed secp256k1 pubkey".into(),
        ));
    }
    Ok(())
}

fn xonly_from_compressed_hex(s: &str) -> Result<PublicKey, TransportError> {
    validate_compressed_pubkey_hex(s)?;
    let bytes = hex::decode(s).map_err(|e| TransportError::InvalidAddress(e.to_string()))?;
    PublicKey::from_slice(&bytes[1..]).map_err(|e| TransportError::InvalidAddress(e.to_string()))
}

fn random_session_id() -> String {
    let mut bytes = [0u8; 16];
    rand::Rng::fill_bytes(&mut rand::rng(), &mut bytes);
    hex::encode(bytes)
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

impl Transport for WebRtcTransport {
    fn transport_id(&self) -> TransportId {
        self.transport_id
    }

    fn transport_type(&self) -> &TransportType {
        &TransportType::WEBRTC
    }

    fn state(&self) -> TransportState {
        self.state
    }

    fn mtu(&self) -> u16 {
        self.config.mtu()
    }

    fn start(&mut self) -> Result<(), TransportError> {
        Err(TransportError::NotSupported(
            "use start_async() for WebRTC transport".into(),
        ))
    }

    fn stop(&mut self) -> Result<(), TransportError> {
        Err(TransportError::NotSupported(
            "use stop_async() for WebRTC transport".into(),
        ))
    }

    fn send(&self, _addr: &TransportAddr, _data: &[u8]) -> Result<(), TransportError> {
        Err(TransportError::NotSupported(
            "use send_async() for WebRTC transport".into(),
        ))
    }

    fn discover(&self) -> Result<Vec<DiscoveredPeer>, TransportError> {
        Ok(Vec::new())
    }

    fn auto_connect(&self) -> bool {
        self.config.auto_connect()
    }

    fn accept_connections(&self) -> bool {
        self.config.accept_connections()
    }

    fn close_connection(&self, _addr: &TransportAddr) {}
}

#[cfg(test)]
#[path = "webrtc/tests.rs"]
mod tests;
