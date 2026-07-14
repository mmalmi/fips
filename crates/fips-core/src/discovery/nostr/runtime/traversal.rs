use super::*;

impl NostrDiscovery {
    const INCOMING_OFFER_MIN_INTERVAL_MS: u64 = 60_000;

    pub(super) async fn accept_incoming_offer_at(&self, sender_npub: &str, now_ms: u64) -> bool {
        let Ok(peer) = NostrPeerKey::parse(sender_npub) else {
            return false;
        };
        let mut last = self.last_incoming_offer_ms.lock().await;
        if last
            .get(&peer)
            .is_some_and(|seen| now_ms.saturating_sub(*seen) < Self::INCOMING_OFFER_MIN_INTERVAL_MS)
        {
            return false;
        }
        if last.len() >= self.config.failure_state_max_entries && !last.contains_key(&peer) {
            let oldest = last
                .iter()
                .min_by_key(|(_, seen)| **seen)
                .map(|(peer, _)| *peer);
            if let Some(oldest) = oldest {
                last.remove(&oldest);
            }
        }
        last.insert(peer, now_ms);
        true
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
        let peer_key = NostrPeerKey::parse(&peer_config.npub).ok();
        if let Some(peer_key) = peer_key {
            let mut active = self.active_initiators.lock().await;
            if !active.insert(peer_key) {
                return false;
            }
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

        let configured_nat = peer_config
            .addresses
            .iter()
            .any(|address| address.transport == "udp" && address.addr.eq_ignore_ascii_case("nat"));
        match self.fetch_advert(&peer_config.npub, target_pubkey).await {
            Ok(advert) => {
                if !advert.has_udp_nat_endpoint() && !configured_nat {
                    return Err(BootstrapError::MissingNatEndpoint(peer_config.npub.clone()));
                }
            }
            Err(err) => return Err(err),
        }

        let base_socket = bind_traversal_udp_socket()?;

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

        let answer = match tokio::time::timeout(signal_answer_timeout(&self.config), rx).await {
            Ok(Ok(answer)) => answer,
            Ok(Err(_)) => {
                let _ = self.pending_answers.lock().await.remove(&offer.nonce);
                return Err(BootstrapError::Protocol(
                    "answer channel closed".to_string(),
                ));
            }
            Err(_) => {
                let _ = self.pending_answers.lock().await.remove(&offer.nonce);
                return Err(BootstrapError::SignalTimeout(peer_config.npub));
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
        if offer.message_type != "offer" || offer.recipient_npub != self.npub {
            debug!(
                peer = %short_npub(&sender_npub),
                session = %short_id(&offer.session_id),
                "traversal: ignoring mesh offer with mismatched type or recipient"
            );
            return;
        }

        if !self.accept_incoming_offer_at(&sender_npub, now_ms()).await {
            debug!(
                peer = %short_npub(&sender_npub),
                "rate-limited repeated inbound mesh traversal offer"
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

        let runtime = Arc::clone(self);
        self.spawn_child_task(async move {
            let _permit = permit;
            if let Err(err) = runtime.handle_incoming_mesh_offer(offer, sender_npub).await {
                debug!(error = %err, "failed to handle mesh traversal offer");
            }
        })
        .await;
    }

    async fn handle_incoming_mesh_offer(
        self: Arc<Self>,
        offer: TraversalOffer,
        sender_npub: String,
    ) -> Result<(), BootstrapError> {
        let peer_short = short_npub(&sender_npub);
        let offer_received_at = now_ms();
        if self
            .cooldown_until(&sender_npub, offer_received_at)
            .is_some()
        {
            debug!(
                peer = %peer_short,
                session = %short_id(&offer.session_id),
                "traversal: incoming mesh offer dropped during peer cooldown"
            );
            return Ok(());
        }
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
        let have_active_initiator = if let Ok(sender) = NostrPeerKey::parse(&sender_npub) {
            self.active_initiators.lock().await.contains(&sender)
        } else {
            false
        };
        if have_active_initiator
            && let (Ok(ours), Ok(theirs)) = (
                PeerIdentity::from_npub(&self.npub),
                PeerIdentity::from_npub(&sender_npub),
            )
            && suppress_responder_for_own_initiator(ours.node_addr(), theirs.node_addr(), true)
        {
            debug!(
                peer = %peer_short,
                session = %short_id(&offer.session_id),
                "traversal: responder suppressed because our initiator wins"
            );
            return Ok(());
        }
        self.mark_session_seen(&offer.session_id, TraversalSignalPath::Mesh)
            .await?;

        let base_socket = bind_traversal_udp_socket()?;
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
}
