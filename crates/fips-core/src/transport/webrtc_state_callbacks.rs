fn wire_peer_connection_state(
    runtime: &WebRtcRuntime,
    remote_addr: TransportAddr,
    session_id: String,
    pc: ManagedPeer,
) {
    let transport_id = runtime.transport_id;
    let peer_addr = remote_addr.clone();
    let peer_session = session_id;
    let peer_pc = Arc::downgrade(&pc);
    let pool = Arc::downgrade(&runtime.pool);
    let pending = Arc::downgrade(&runtime.pending);
    let ready = Arc::downgrade(&runtime.ready);
    let failed = Arc::downgrade(&runtime.failed);
    pc.on_peer_connection_state_change(Box::new(move |state: RTCPeerConnectionState| {
        let peer_addr = peer_addr.clone();
        let peer_session = peer_session.clone();
        let peer_pc = peer_pc.clone();
        let pool = pool.clone();
        let pending = pending.clone();
        let ready = ready.clone();
        let failed = failed.clone();
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
            let Some(peer_pc) = peer_pc.upgrade() else {
                return;
            };
            let (Some(pool), Some(pending), Some(failed), Some(ready)) = (
                pool.upgrade(),
                pending.upgrade(),
                failed.upgrade(),
                ready.upgrade(),
            ) else {
                drop(start_peer_connection_cleanup(peer_pc));
                return;
            };
            let owners = WebRtcSessionOwners {
                pool,
                pending,
                failed,
                ready,
            };
            cleanup_terminal_webrtc_session(
                &owners,
                &peer_addr,
                &peer_session,
                Some(format!("WebRTC peer connection became {state}")),
                peer_pc,
            )
            .await;
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

async fn promote_pending_webrtc_session(
    physical: &PhysicalResources,
    pool: &ConnectionPool,
    pending: &PendingPool,
    failed: &FailedPool,
    remote_addr: &TransportAddr,
    candidate: WebRtcConnection,
) -> Result<Option<WebRtcConnection>, WebRtcConnection> {
    // All code that can remove a session locks pool before pending. Holding
    // both through this handoff means close/stop observes the session in one
    // owner map or the other, never in a resurrection gap between them.
    let mut pool = pool.lock().await;
    let mut pending = pending.lock().await;
    let active = pending.get(remote_addr).is_some_and(|dial| {
        dial.session_id == candidate.session_id
            && Arc::ptr_eq(&dial.pc, &candidate.pc)
            && !candidate.pc.is_closing()
            && physical.is_accepting()
            && physical.phase(remote_addr) == Some(PhysicalPhase::Active)
    });
    if !active {
        return Err(candidate);
    }
    pending.remove(remote_addr);
    let previous = pool.insert(remote_addr.clone(), candidate);
    failed.lock().await.remove(remote_addr);
    Ok(previous)
}

async fn while_pooled_webrtc_session_is_active<F, T>(
    physical: &PhysicalResources,
    pool: &ConnectionPool,
    remote_addr: &TransportAddr,
    session_id: &str,
    pc: &ManagedPeer,
    operation: F,
) -> Option<T>
where
    F: std::future::Future<Output = T>,
{
    let pool = pool.lock().await;
    let active = pool.get(remote_addr).is_some_and(|connection| {
        connection.session_id == session_id
            && Arc::ptr_eq(&connection.pc, pc)
            && !pc.is_closing()
            && physical.is_accepting()
            && physical.phase(remote_addr) == Some(PhysicalPhase::Active)
    });
    if !active {
        return None;
    }
    // The bounded operation is the lifecycle linearization point. Cleanup
    // also locks pool first, so it cannot remove this exact owner while the
    // operation is in flight.
    Some(operation.await)
}

async fn mark_webrtc_ready_if_pooled(
    transport_id: TransportId,
    remote_addr: &TransportAddr,
    expected_owner: &WebRtcSessionOwner,
    physical: &PhysicalResources,
    pool: &ConnectionPool,
    ready: &ReadyPool,
) -> bool {
    // Cleanup locks pool before clearing ready. Hold the same pool owner while
    // inserting readiness so close/stop cannot remove the session between the
    // exact-session check and the ready-set mutation.
    let pool = pool.lock().await;
    let mut ready = ready.lock().await;
    if !physical.is_accepting()
        || physical.phase(remote_addr) != Some(PhysicalPhase::Active)
        || !pool.get(remote_addr).is_some_and(|connection| {
            expected_owner.matches(&connection.session_id, &connection.pc)
                && !connection.pc.is_closing()
        })
    {
        return false;
    }
    if ready.insert(remote_addr.clone()) {
        debug!(
            transport_id = %transport_id,
            remote_addr = %remote_addr,
            "WebRTC data channel remote ready"
        );
    }
    true
}

fn spawn_webrtc_ready_fallback(
    transport_id: TransportId,
    remote_addr: TransportAddr,
    expected_owner: WebRtcSessionOwner,
    physical: WeakPhysicalResources,
    pool: ConnectionPool,
    ready: ReadyPool,
) {
    let pool = Arc::downgrade(&pool);
    let ready = Arc::downgrade(&ready);
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(WEBRTC_READY_FALLBACK_MS)).await;
        let (Some(physical), Some(pool), Some(ready)) =
            (physical.upgrade(), pool.upgrade(), ready.upgrade())
        else {
            return;
        };
        mark_webrtc_ready_if_pooled(
            transport_id,
            &remote_addr,
            &expected_owner,
            &physical,
            &pool,
            &ready,
        )
        .await;
    });
}
