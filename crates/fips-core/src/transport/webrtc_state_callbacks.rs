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
            if !spawn_managed_peer_cleanup(&peer_pc) {
                return;
            }
            let (Some(pool), Some(pending), Some(failed), Some(ready)) = (
                pool.upgrade(),
                pending.upgrade(),
                failed.upgrade(),
                ready.upgrade(),
            ) else {
                return;
            };
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
    session_id: String,
    pool: ConnectionPool,
    ready: ReadyPool,
) {
    let pool = Arc::downgrade(&pool);
    let ready = Arc::downgrade(&ready);
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(WEBRTC_READY_FALLBACK_MS)).await;
        let (Some(pool), Some(ready)) = (pool.upgrade(), ready.upgrade()) else {
            return;
        };
        if pool
            .lock()
            .await
            .get(&remote_addr)
            .is_some_and(|connection| connection.session_id == session_id)
        {
            mark_webrtc_ready(transport_id, remote_addr, ready).await;
        }
    });
}
