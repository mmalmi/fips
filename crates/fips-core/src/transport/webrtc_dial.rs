// Outbound setup and connection-state reporting across physical creation.

impl WebRtcTransport {
    /// Initiate a non-blocking WebRTC dial.
    pub async fn connect_async(&self, addr: &TransportAddr) -> Result<(), TransportError> {
        let addr = canonical_webrtc_addr(addr)?;
        if self
            .recovering
            .lock()
            .expect("WebRTC recoveries")
            .contains_key(&addr)
        {
            return Ok(());
        }
        if self.pool.lock().await.contains_key(&addr) {
            return Ok(());
        }
        if self.pending.lock().await.contains_key(&addr) {
            return Ok(());
        }
        let reservation = match self.physical.reserve(&addr) {
            Ok(reservation) => reservation,
            Err(PhysicalReserveError::PeerBusy(
                PhysicalPhase::Creating | PhysicalPhase::Active,
            )) => return Ok(()),
            Err(
                PhysicalReserveError::Stopped
                | PhysicalReserveError::Capacity
                | PhysicalReserveError::PeerBusy(PhysicalPhase::Closing),
            ) => return Err(TransportError::ConnectionRefused),
        };
        self.failed.lock().await.remove(&addr);

        let runtime = self.runtime();
        let remote_addr = addr;
        let deadline =
            tokio::time::Instant::now() + Duration::from_millis(self.config.connect_timeout_ms());
        let task = tokio::spawn(async move {
            let result = runtime
                .start_outbound(remote_addr, reservation, deadline, None, None)
                .await;
            if let Err(error) = &result {
                trace!(error = %error, "WebRTC outbound setup failed");
            }
            result
        });
        let mut tasks = self.dial_tasks.lock().expect("WebRTC dial tasks");
        tasks.retain(|task| !task.is_finished());
        tasks.push(task);
        Ok(())
    }

    /// A verified remote startup epoch invalidates offers sent on the old FSP
    /// session. Retry only an unanswered local offer, retaining its deadline.
    pub(crate) async fn authenticated_session_restarted(&self, peer: secp256k1::PublicKey) {
        if !self.state.is_operational() {
            return;
        }
        let addr = TransportAddr::from_string(&canonical_webrtc_pubkey_hex(peer));
        let stale = {
            let pool = self.pool.lock().await;
            let mut pending = self.pending.lock().await;
            if pool.contains_key(&addr)
                || !pending.get(&addr).is_some_and(|dial| {
                    dial.origin == PendingDialOrigin::Local
                        && dial.awaiting_answer
                        && dial.deadline > tokio::time::Instant::now()
                })
            {
                return;
            }
            // This claim orders atomically with an authenticated answer or
            // promotion. No late callback may remove the replacement owner.
            let stale = pending.remove(&addr).expect("matching pending offer");
            self.recovering
                .lock()
                .expect("WebRTC recoveries")
                .insert(addr.clone(), stale.session_id.clone());
            stale
        };
        let deadline = stale.deadline;
        let guard = WebRtcRecoveryGuard {
            recovering: Arc::clone(&self.recovering),
            addr: addr.clone(),
            session_id: stale.session_id,
        };
        let completion = start_peer_connection_cleanup(stale.pc);
        let runtime = self.runtime();
        let task = tokio::spawn(async move {
            tokio::time::timeout_at(deadline, completion.wait())
                .await
                .map_err(|_| TransportError::Timeout)?;
            if !guard.is_current() {
                return Ok(());
            }
            let reservation = match runtime.physical.reserve(&addr) {
                Ok(reservation) => reservation,
                // A simultaneous incoming negotiation can already own the peer.
                Err(PhysicalReserveError::PeerBusy(
                    PhysicalPhase::Creating | PhysicalPhase::Active,
                )) => return Ok(()),
                Err(_) => return Err(TransportError::ConnectionRefused),
            };
            if !guard.is_current() {
                return Ok(());
            }
            debug!(remote_addr = %addr, "Retrying unanswered WebRTC offer after authenticated FSP restart");
            runtime
                .start_outbound(addr, reservation, deadline, None, Some(guard))
                .await
        });
        let mut tasks = self.dial_tasks.lock().expect("WebRTC dial tasks");
        tasks.retain(|task| !task.is_finished());
        tasks.push(task);
    }

    /// Query connection state synchronously.
    pub fn connection_state_sync(&self, addr: &TransportAddr) -> ConnectionState {
        let addr = match canonical_webrtc_addr(addr) {
            Ok(addr) => addr,
            Err(error) => return ConnectionState::Failed(error.to_string()),
        };
        let pool = match self.pool.try_lock() {
            Ok(pool) => pool,
            Err(_) => return ConnectionState::Connecting,
        };
        if pool.contains_key(&addr) {
            return match self.ready.try_lock() {
                Ok(ready) if ready.contains(&addr) => ConnectionState::Connected,
                _ => ConnectionState::Connecting,
            };
        }
        drop(pool);

        let failed = match self.failed.try_lock() {
            Ok(failed) => failed,
            Err(_) => return ConnectionState::Connecting,
        };
        if let Some(reason) = failed.get(&addr) {
            return ConnectionState::Failed(reason.clone());
        }
        drop(failed);

        match self.pending.try_lock() {
            Ok(pending) if pending.contains_key(&addr) => ConnectionState::Connecting,
            Ok(_)
                if self
                    .recovering
                    .lock()
                    .expect("WebRTC recoveries")
                    .contains_key(&addr) =>
            {
                ConnectionState::Connecting
            }
            // Outbound setup owns capacity before its task publishes a pending
            // dial. Node must retain that preparation through peer creation
            // and data-channel setup instead of retiring it as a missing dial.
            Ok(_)
                if self.physical.is_accepting()
                    && matches!(
                        self.physical.phase(&addr),
                        Some(PhysicalPhase::Creating | PhysicalPhase::Active)
                    ) =>
            {
                ConnectionState::Connecting
            }
            Ok(_) => ConnectionState::None,
            Err(_) => ConnectionState::Connecting,
        }
    }
}
