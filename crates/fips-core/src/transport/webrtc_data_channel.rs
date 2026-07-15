struct WebRtcDataChannelContext {
    transport_id: TransportId,
    packet_tx: PacketTx,
    physical: PhysicalResources,
    owners: WebRtcSessionOwners,
}

fn wire_data_channel(
    context: WebRtcDataChannelContext,
    remote_addr: TransportAddr,
    session_id: String,
    pc: ManagedPeer,
    data_channel: Arc<RTCDataChannel>,
) {
    let WebRtcDataChannelContext {
        transport_id,
        packet_tx,
        physical,
        owners,
    } = context;
    let WebRtcSessionOwners {
        pool,
        pending,
        failed,
        ready,
    } = owners;
    let recv_addr = remote_addr.clone();
    let recv_owner = WebRtcSessionOwner::new(&session_id, &pc);
    let recv_tx = packet_tx;
    let recv_ready = Arc::downgrade(&ready);
    let recv_pool = Arc::downgrade(&pool);
    let recv_physical = physical.clone();
    data_channel.on_message(Box::new(move |msg: DataChannelMessage| {
        let recv_addr = recv_addr.clone();
        let recv_owner = recv_owner.clone();
        let recv_tx = recv_tx.clone();
        let recv_ready = recv_ready.clone();
        let recv_pool = recv_pool.clone();
        let recv_physical = recv_physical.clone();
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
                mark_webrtc_ready_if_pooled(
                    transport_id,
                    &recv_addr,
                    &recv_owner,
                    &recv_physical,
                    &recv_pool,
                    &recv_ready,
                )
                .await;
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
    let open_physical = physical;
    data_channel.on_open(Box::new(move || {
        let open_addr = open_addr.clone();
        let open_session = open_session.clone();
        let open_pc = open_pc.clone();
        let open_dc = open_dc.clone();
        let open_pool = open_pool.clone();
        let open_pending = open_pending.clone();
        let open_failed = open_failed.clone();
        let open_ready = open_ready.clone();
        let open_physical = open_physical.clone();
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
            let previous = match promote_pending_webrtc_session(
                &open_physical,
                &open_pool,
                &open_pending,
                &open_failed,
                &open_addr,
                WebRtcConnection {
                    session_id: open_session.clone(),
                    pc: Arc::clone(&open_pc),
                    data_channel: open_dc,
                },
            )
            .await
            {
                Ok(previous) => previous,
                Err(rejected) => {
                    close_data_channel_bounded(rejected.data_channel).await;
                    close_peer_connection_bounded(rejected.pc).await;
                    return;
                }
            };
            if let Some(previous) = previous {
                close_data_channel_bounded(previous.data_channel).await;
                close_peer_connection_bounded(previous.pc).await;
            }
            let ready_sent = while_pooled_webrtc_session_is_active(
                &open_physical,
                &open_pool,
                &open_addr,
                &open_session,
                &open_pc,
                tokio::time::timeout(
                    WEBRTC_IO_TIMEOUT,
                    ready_dc.send(&Bytes::copy_from_slice(WEBRTC_READY_FRAME)),
                ),
            )
            .await;
            let Some(ready_sent) = ready_sent else {
                close_peer_connection_bounded(open_pc).await;
                return;
            };
            if !matches!(ready_sent, Ok(Ok(_))) {
                debug!(
                    transport_id = %transport_id,
                    remote_addr = %open_addr,
                    result = ?ready_sent,
                    "Failed to send bounded WebRTC ready marker"
                );
                let expected_owner = WebRtcSessionOwner::new(&open_session, &open_pc);
                drop(spawn_webrtc_session_cleanup(
                    open_pool,
                    open_pending,
                    open_failed,
                    open_ready,
                    open_addr,
                    Some(expected_owner),
                    Some("WebRTC ready marker failed".into()),
                ));
                return;
            }
            spawn_webrtc_ready_fallback(
                transport_id,
                open_addr.clone(),
                WebRtcSessionOwner::new(&open_session, &open_pc),
                open_physical.downgrade(),
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
            let (Some(close_pool), Some(close_pending), Some(close_failed), Some(close_ready)) = (
                close_pool.upgrade(),
                close_pending.upgrade(),
                close_failed.upgrade(),
                close_ready.upgrade(),
            ) else {
                drop(start_peer_connection_cleanup(close_pc));
                return;
            };
            let owners = WebRtcSessionOwners {
                pool: close_pool,
                pending: close_pending,
                failed: close_failed,
                ready: close_ready,
            };
            cleanup_terminal_webrtc_session(
                &owners,
                &close_addr,
                &close_session,
                None,
                close_pc,
            )
            .await;
        })
    }));
}
