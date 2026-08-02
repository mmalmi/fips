use super::*;

impl NostrDiscovery {
    pub(super) async fn should_suppress_responder_for_active_initiator(
        &self,
        sender_npub: &str,
        offer_received_at: u64,
    ) -> bool {
        let Ok(sender) = NostrPeerKey::parse(sender_npub) else {
            return false;
        };
        let Some(started_at_ms) = self.active_initiators.lock().await.get(&sender).copied() else {
            return false;
        };
        if offer_received_at.saturating_sub(started_at_ms)
            >= MESH_SIGNAL_RETRY_INTERVAL.as_millis() as u64
        {
            return false;
        }
        let (Ok(ours), Ok(theirs)) = (
            PeerIdentity::from_npub(&self.npub),
            PeerIdentity::from_npub(sender_npub),
        ) else {
            return false;
        };
        suppress_responder_for_own_initiator(ours.node_addr(), theirs.node_addr(), true)
    }

    pub(super) async fn accept_incoming_offer_session(&self, session_id: &str) -> bool {
        self.mark_session_seen(session_id, TraversalSignalPath::Mesh)
            .await
            .is_ok()
    }

    pub(super) async fn admit_incoming_mesh_offer(
        &self,
        sender_npub: &str,
        session_id: &str,
        offer_received_at: u64,
    ) -> IncomingMeshOfferAdmission {
        if self
            .should_suppress_responder_for_active_initiator(sender_npub, offer_received_at)
            .await
        {
            return IncomingMeshOfferAdmission::SuppressedByActiveInitiator;
        }
        if self.accept_incoming_offer_session(session_id).await {
            IncomingMeshOfferAdmission::Accepted
        } else {
            IncomingMeshOfferAdmission::Duplicate
        }
    }

    pub async fn request_connect(self: &Arc<Self>, peer_config: PeerConfig) {
        let _ = self
            .request_connect_with_mesh_signaling(peer_config, false)
            .await;
    }

    pub(crate) async fn request_connect_with_mesh_signaling(
        self: &Arc<Self>,
        peer_config: PeerConfig,
        mesh_signaling_allowed: bool,
    ) -> bool {
        if !self.traversal_initiator_admission_allowed(mesh_signaling_allowed) {
            debug!(
                peer = %short_npub(&peer_config.npub),
                mesh_signaling_allowed,
                "traversal: request suppressed by admission"
            );
            return false;
        }
        let peer_key = NostrPeerKey::parse(&peer_config.npub).ok();
        if let Some(peer_key) = peer_key {
            let mut active = self.active_initiators.lock().await;
            if active.contains_key(&peer_key) {
                return false;
            }
            active.insert(peer_key, now_ms());
        }

        let runtime = Arc::clone(self);
        if !self
            .spawn_child_task(async move {
                let event = match runtime
                    .connect_peer(peer_config.clone(), mesh_signaling_allowed)
                    .await
                {
                    Ok(traversal) => BootstrapEvent::Established { traversal },
                    Err(err) => BootstrapEvent::Failed {
                        peer_config,
                        reason: err.to_string(),
                    },
                };
                runtime.emit_event(event).await;
                if let Some(peer_key) = peer_key {
                    runtime.active_initiators.lock().await.remove(&peer_key);
                }
            })
            .await
        {
            if let Some(peer_key) = peer_key {
                self.active_initiators.lock().await.remove(&peer_key);
            }
            return false;
        }
        true
    }

    async fn connect_peer(
        &self,
        peer_config: PeerConfig,
        mesh_signaling_allowed: bool,
    ) -> Result<EstablishedTraversal, BootstrapError> {
        let peer_short = short_npub(&peer_config.npub);
        if !self.traversal_initiator_admission_allowed(mesh_signaling_allowed) {
            debug!(
                peer = %peer_short,
                mesh_signaling_allowed,
                "traversal: initiator suppressed, Node at capacity"
            );
            return Err(BootstrapError::Disabled);
        }
        debug!(
            peer = %peer_short,
            mesh_signaling_allowed,
            "traversal: initiator starting"
        );
        if !mesh_signaling_allowed {
            return Err(BootstrapError::Protocol(
                "NAT traversal requires an authenticated FIPS session".to_string(),
            ));
        }
        let target_pubkey =
            PublicKey::parse(&peer_config.npub).map_err(|e| BootstrapError::InvalidPeerNpub {
                npub: peer_config.npub.clone(),
                reason: e.to_string(),
            })?;
        let peer_key = NostrPeerKey::from_public_key_ref(&target_pubkey);

        let bind_interface = self.bind_interface.read().await.clone();
        let base_socket = bind_traversal_udp_socket(bind_interface.as_deref())?;

        let observation = observe_traversal_addresses(
            &base_socket,
            &self.config.stun_servers,
            self.config.share_local_candidates,
            TRAVERSAL_STUN_TIMEOUT,
        )
        .await?;
        debug!(
            peer = %peer_short,
            reflexive = %observation.reflexive_address.as_ref().map(|a| format!("{}:{}", a.ip, a.port)).unwrap_or_else(|| "-".into()),
            local = observation.local_addresses.len(),
            stun = %observation.stun_server.as_deref().unwrap_or("-"),
            "traversal: initiator STUN observed"
        );
        let session_id = nonce();
        let offer = create_traversal_offer(
            session_id.clone(),
            TraversalSignalTiming::new(now_ms(), self.config.signal_ttl_secs * 1000),
            session_id.clone(),
            self.npub.clone(),
            peer_config.npub.clone(),
            observation,
        );

        let (tx, rx) = oneshot::channel();
        self.pending_answers
            .lock()
            .await
            .insert(offer.nonce.clone(), tx);

        if !self
            .emit_mesh_signal(MeshTraversalSignal::Offer {
                peer_npub: peer_config.npub.clone(),
                offer: offer.clone(),
            })
            .await
        {
            let _ = self.pending_answers.lock().await.remove(&offer.nonce);
            return Err(BootstrapError::Protocol(
                "FIPS traversal offer queue closed".to_string(),
            ));
        }
        debug!(
            peer = %peer_short,
            session = %short_id(&offer.session_id),
            "traversal: offer queued on authenticated FIPS session"
        );

        let answer = match self
            .wait_for_mesh_traversal_answer(&peer_config.npub, &offer, rx)
            .await
        {
            Ok(answer) => answer,
            Err(error) => {
                let _ = self.pending_answers.lock().await.remove(&offer.nonce);
                return Err(error);
            }
        };

        let answer_received_at = now_ms();
        debug!(
            peer = %peer_short,
            session = %short_id(&offer.session_id),
            accepted = answer.payload.accepted,
            signal_path = "fips-session",
            reflexive = %answer.payload.reflexive_address.as_ref().map(|a| format!("{}:{}", a.ip, a.port)).unwrap_or_else(|| "-".into()),
            local = answer.payload.local_addresses.len(),
            "traversal: answer received"
        );
        if let Some(observed_skew_ms) =
            estimate_clock_skew(&offer, &answer.payload, answer_received_at)
        {
            self.failure_state
                .note_observed_skew(peer_key, observed_skew_ms, answer_received_at);
            let abs_skew = observed_skew_ms.unsigned_abs();
            // 30s threshold: well below the 60s SKEW_TOLERANCE wall but loud
            // enough to surface a real clock problem on either side.
            if abs_skew >= 30_000 {
                debug!(
                    peer = %peer_short,
                    session = %short_id(&offer.session_id),
                    skew_ms = observed_skew_ms,
                    "traversal: significant peer clock skew observed"
                );
            } else {
                trace!(
                    peer = %peer_short,
                    skew_ms = observed_skew_ms,
                    "traversal: peer clock skew within nominal range"
                );
            }
        }
        let outcome = validate_traversal_answer_for_offer(
            &offer,
            &answer.payload,
            answer_received_at,
            self.config.signal_ttl_secs * 1000,
            &answer.sender_npub,
            &self.npub,
        )?;
        if outcome == FreshnessOutcome::FreshWithinSkewTolerance {
            debug!(
                peer = %peer_short,
                session = %short_id(&offer.session_id),
                "traversal: answer accepted within clock-skew tolerance"
            );
        }
        if !answer.payload.accepted {
            return Err(BootstrapError::Protocol(
                answer
                    .payload
                    .reason
                    .unwrap_or_else(|| "remote rejected traversal".to_string()),
            ));
        }

        let planned_remotes = planned_remote_endpoints(
            &offer.local_addresses,
            offer.reflexive_address.as_ref(),
            &answer.payload.local_addresses,
            answer.payload.reflexive_address.as_ref(),
            true,
        )?;

        let remote_addr = run_punch_attempt(
            &base_socket,
            &session_id,
            &planned_remotes.remotes,
            self.punch_hint(),
            Duration::from_secs(self.config.attempt_timeout_secs),
            planned_remotes.preferred_count,
        )
        .await
        .map_err(|_| BootstrapError::PunchTimeout(peer_config.npub.clone()))?;
        debug!(
            peer = %peer_short,
            session = %short_id(&session_id),
            remote = %remote_addr,
            "traversal: initiator punch succeeded"
        );

        self.failure_state.record_success(peer_key, now_ms());

        Ok(
            EstablishedTraversal::new(session_id, peer_config.npub, remote_addr, base_socket)
                .with_transport_name("fips-session-nat"),
        )
    }

    pub(super) async fn wait_for_mesh_traversal_answer(
        &self,
        peer_npub: &str,
        offer: &TraversalOffer,
        mut rx: oneshot::Receiver<SignalEnvelope<TraversalAnswer>>,
    ) -> Result<SignalEnvelope<TraversalAnswer>, BootstrapError> {
        let deadline = tokio::time::sleep(signal_answer_timeout(&self.config));
        tokio::pin!(deadline);
        let mut retry = tokio::time::interval_at(
            tokio::time::Instant::now() + MESH_SIGNAL_RETRY_INTERVAL,
            MESH_SIGNAL_RETRY_INTERVAL,
        );
        retry.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

        loop {
            tokio::select! {
                answer = &mut rx => {
                    return answer.map_err(|_| {
                        BootstrapError::Protocol("answer channel closed".to_string())
                    });
                }
                () = &mut deadline => {
                    return Err(BootstrapError::SignalTimeout(peer_npub.to_string()));
                }
                _ = retry.tick() => {
                    if !self
                        .emit_mesh_signal(MeshTraversalSignal::Offer {
                            peer_npub: peer_npub.to_string(),
                            offer: offer.clone(),
                        })
                        .await
                    {
                        return Err(BootstrapError::Protocol(
                            "FIPS traversal offer queue closed".to_string(),
                        ));
                    }
                    trace!(
                        peer = %short_npub(peer_npub),
                        session = %short_id(&offer.session_id),
                        "traversal: repeated unanswered offer on authenticated FIPS session"
                    );
                }
            }
        }
    }

    pub(crate) async fn receive_mesh_traversal_answer(
        &self,
        answer: TraversalAnswer,
        sender_npub: String,
    ) {
        if answer.message_type != "answer" || answer.recipient_npub != self.npub {
            debug!(
                peer = %short_npub(&sender_npub),
                session = %short_id(&answer.session_id),
                "traversal: ignoring mesh answer with mismatched type or recipient"
            );
            return;
        }

        if let Some(tx) = self
            .pending_answers
            .lock()
            .await
            .remove(&answer.in_reply_to)
        {
            let _ = tx.send(SignalEnvelope {
                payload: answer,
                sender_npub,
            });
        } else {
            debug!(
                peer = %short_npub(&sender_npub),
                session = %short_id(&answer.session_id),
                "traversal: ignoring mesh answer without pending offer"
            );
        }
    }

    pub(crate) async fn receive_mesh_traversal_offer(
        self: &Arc<Self>,
        offer: TraversalOffer,
        sender_npub: String,
    ) {
        #[cfg(test)]
        self.received_mesh_offer_count
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        if offer.message_type != "offer" || offer.recipient_npub != self.npub {
            debug!(
                peer = %short_npub(&sender_npub),
                session = %short_id(&offer.session_id),
                "traversal: ignoring mesh offer with mismatched type or recipient"
            );
            return;
        }

        if self
            .replay_cached_mesh_traversal_answer(&offer, &sender_npub)
            .await
        {
            debug!(
                peer = %short_npub(&sender_npub),
                session = %short_id(&offer.session_id),
                "traversal: replayed cached answer for duplicate mesh offer"
            );
            return;
        }

        let Ok(permit) = self.offer_slots.clone().try_acquire_owned() else {
            debug!(
                sender_npub = %sender_npub,
                limit = self.config.max_concurrent_incoming_offers,
                "rate-limited inbound mesh traversal offer (max_concurrent_incoming_offers reached); offer dropped"
            );
            return;
        };
        let offer_received_at = now_ms();
        match self
            .admit_incoming_mesh_offer(&sender_npub, &offer.session_id, offer_received_at)
            .await
        {
            IncomingMeshOfferAdmission::Accepted => {}
            IncomingMeshOfferAdmission::Duplicate => {
                debug!(
                    peer = %short_npub(&sender_npub),
                    session = %short_id(&offer.session_id),
                    "duplicate inbound mesh traversal offer"
                );
                return;
            }
            IncomingMeshOfferAdmission::SuppressedByActiveInitiator => {
                debug!(
                    peer = %short_npub(&sender_npub),
                    session = %short_id(&offer.session_id),
                    "traversal: responder deferred because our fresh initiator wins"
                );
                return;
            }
        }

        let runtime = Arc::clone(self);
        self.spawn_child_task(async move {
            let _permit = permit;
            if let Err(err) = runtime
                .handle_incoming_mesh_offer(offer, sender_npub, offer_received_at)
                .await
            {
                debug!(error = %err, "failed to handle mesh traversal offer");
            }
        })
        .await;
    }

    async fn handle_incoming_mesh_offer(
        self: Arc<Self>,
        offer: TraversalOffer,
        sender_npub: String,
        offer_received_at: u64,
    ) -> Result<(), BootstrapError> {
        let peer_short = short_npub(&sender_npub);
        // This offer arrived through an authenticated FIPS session. A peer
        // traversal cooldown throttles our outbound attempts, but must not
        // reject the other side's attempt: after either peer roams, both can
        // otherwise enter cooldown and drop every offer until one endpoint is
        // restarted.
        if !self.direct_refresh_admission_allowed() {
            debug!(
                peer = %peer_short,
                session = %short_id(&offer.session_id),
                "traversal: incoming mesh offer dropped, Node at connection/link capacity"
            );
            return Ok(());
        }
        debug!(
            peer = %peer_short,
            session = %short_id(&offer.session_id),
            reflexive = %offer.reflexive_address.as_ref().map(|a| format!("{}:{}", a.ip, a.port)).unwrap_or_else(|| "-".into()),
            local = offer.local_addresses.len(),
            "traversal: mesh offer received"
        );
        let outcome = validate_offer_freshness(
            &offer,
            offer_received_at,
            self.config.signal_ttl_secs * 1000,
            &sender_npub,
            &self.npub,
        )?;
        if outcome == FreshnessOutcome::FreshWithinSkewTolerance {
            debug!(
                peer = %peer_short,
                session = %short_id(&offer.session_id),
                offer_issued_at = offer.issued_at,
                offer_received_at = offer_received_at,
                "traversal: mesh offer accepted within clock-skew tolerance"
            );
        }
        let bind_interface = self.bind_interface.read().await.clone();
        let base_socket = bind_traversal_udp_socket(bind_interface.as_deref())?;
        let observation = observe_traversal_addresses(
            &base_socket,
            &self.config.stun_servers,
            self.config.share_local_candidates,
            TRAVERSAL_STUN_TIMEOUT,
        )
        .await?;
        let accepted = observation.has_usable_address();
        debug!(
            peer = %peer_short,
            session = %short_id(&offer.session_id),
            accepted = accepted,
            reflexive = %observation.reflexive_address.as_ref().map(|a| format!("{}:{}", a.ip, a.port)).unwrap_or_else(|| "-".into()),
            local = observation.local_addresses.len(),
            "traversal: mesh responder STUN observed"
        );
        let answer = create_traversal_answer(
            &offer,
            TraversalSignalTiming::new(now_ms(), self.config.signal_ttl_secs * 1000),
            nonce(),
            self.npub.clone(),
            observation,
            accepted.then(|| self.punch_hint()),
            Some(offer_received_at),
        );
        self.cache_mesh_traversal_answer(&offer, &sender_npub, &answer)
            .await;
        if !self
            .emit_mesh_signal(MeshTraversalSignal::Answer {
                peer_npub: sender_npub.clone(),
                answer: answer.clone(),
            })
            .await
        {
            return Err(BootstrapError::Protocol(
                "mesh traversal answer queue full".to_string(),
            ));
        }
        debug!(
            peer = %peer_short,
            session = %short_id(&offer.session_id),
            accepted = accepted,
            "traversal: answer queued for FIPS mesh signaling"
        );
        if !accepted {
            return Ok(());
        }

        let planned_remotes = planned_remote_endpoints(
            &answer.local_addresses,
            answer.reflexive_address.as_ref(),
            &offer.local_addresses,
            offer.reflexive_address.as_ref(),
            true,
        )?;

        if let Ok(remote_addr) = run_punch_attempt(
            &base_socket,
            &offer.session_id,
            &planned_remotes.remotes,
            answer
                .punch
                .clone()
                .expect("accepted answers always include a punch hint"),
            Duration::from_secs(self.config.attempt_timeout_secs),
            planned_remotes.preferred_count,
        )
        .await
        {
            debug!(
                peer = %peer_short,
                session = %short_id(&offer.session_id),
                remote = %remote_addr,
                "traversal: mesh responder punch succeeded"
            );
            self.emit_event(BootstrapEvent::Established {
                traversal: EstablishedTraversal::new(
                    offer.session_id,
                    offer.sender_npub,
                    remote_addr,
                    base_socket,
                )
                .with_transport_name("fips-session-nat"),
            })
            .await;
        }

        Ok(())
    }

    pub(super) async fn cache_mesh_traversal_answer(
        &self,
        offer: &TraversalOffer,
        sender_npub: &str,
        answer: &TraversalAnswer,
    ) {
        let cap = self.config.seen_sessions_max_entries;
        if cap == 0 {
            return;
        }
        let now = now_ms();
        let expires_at_ms = offer
            .expires_at
            .min(now.saturating_add(signal_answer_timeout(&self.config).as_millis() as u64));
        let mut cache = self.answered_offers.lock().await;
        cache.retain(|_, cached| cached.expires_at_ms > now);
        if cache.len() >= cap && !cache.contains_key(&offer.session_id) {
            let oldest = cache
                .iter()
                .min_by_key(|(_, cached)| cached.expires_at_ms)
                .map(|(session_id, _)| session_id.clone());
            if let Some(session_id) = oldest {
                cache.remove(&session_id);
            }
        }
        cache.insert(
            offer.session_id.clone(),
            CachedMeshTraversalAnswer {
                offer: offer.clone(),
                sender_npub: sender_npub.to_string(),
                answer: answer.clone(),
                expires_at_ms,
            },
        );
    }

    async fn replay_cached_mesh_traversal_answer(
        &self,
        offer: &TraversalOffer,
        sender_npub: &str,
    ) -> bool {
        let now = now_ms();
        let answer = {
            let mut cache = self.answered_offers.lock().await;
            cache.retain(|_, cached| cached.expires_at_ms > now);
            cache.get(&offer.session_id).and_then(|cached| {
                (cached.sender_npub == sender_npub && cached.offer == *offer)
                    .then(|| cached.answer.clone())
            })
        };
        let Some(answer) = answer else {
            return false;
        };
        self.emit_mesh_signal(MeshTraversalSignal::Answer {
            peer_npub: sender_npub.to_string(),
            answer,
        })
        .await
    }
}
