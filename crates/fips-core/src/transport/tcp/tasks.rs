use super::stream::{DEFAULT_FRAME_COMPLETION_TIMEOUT, read_fmp_packet_with_timeout};
use super::*;
use crate::transport::{PacketBuffer, ReceivedPacket};
use tokio::time::timeout;

// ============================================================================
// Accept Loop
// ============================================================================

/// Socket configuration parameters passed to the accept loop.
pub(super) struct AcceptConfig {
    pub(super) max_inbound: usize,
    pub(super) nodelay: bool,
    pub(super) keepalive_secs: u64,
    pub(super) recv_buf: usize,
    pub(super) send_buf: usize,
    pub(super) first_frame_timeout_ms: u64,
}

/// TCP accept loop — runs as a spawned task when bind_addr is configured.
pub(super) async fn accept_loop(
    listener: TcpListener,
    transport_id: TransportId,
    packet_tx: PacketTx,
    pool: ConnectionPool,
    cfg: AcceptConfig,
    stats: Arc<TcpStats>,
) {
    let AcceptConfig {
        max_inbound,
        nodelay,
        keepalive_secs,
        recv_buf,
        send_buf,
        first_frame_timeout_ms,
    } = cfg;
    debug!(transport_id = %transport_id, "TCP accept loop starting");

    loop {
        match listener.accept().await {
            Ok((stream, peer_addr)) => {
                // Check inbound connection limit. Outbound connect-on-send
                // entries share the pool but do not consume inbound budget.
                if stats.pool_inbound_count() >= max_inbound as u64 {
                    stats.record_connection_rejected();
                    warn!(
                        transport_id = %transport_id,
                        peer_addr = %peer_addr,
                        max = max_inbound,
                        "Rejecting inbound TCP connection (max_inbound_connections reached)"
                    );
                    continue;
                }

                // Configure socket options
                let std_stream = match stream.into_std() {
                    Ok(s) => s,
                    Err(e) => {
                        warn!(
                            transport_id = %transport_id,
                            error = %e,
                            "Failed to convert accepted stream to std"
                        );
                        continue;
                    }
                };

                if let Err(e) = configure_accepted_socket(
                    &std_stream,
                    nodelay,
                    keepalive_secs,
                    recv_buf,
                    send_buf,
                ) {
                    warn!(
                        transport_id = %transport_id,
                        peer_addr = %peer_addr,
                        error = %e,
                        "Failed to configure accepted socket"
                    );
                    continue;
                }

                let stream = match TcpStream::from_std(std_stream) {
                    Ok(s) => s,
                    Err(e) => {
                        warn!(
                            transport_id = %transport_id,
                            error = %e,
                            "Failed to convert accepted stream back to tokio"
                        );
                        continue;
                    }
                };

                let remote_addr = TransportAddr::from_string(&peer_addr.to_string());

                // Resolve the pool slot before spawning so fast EOF cannot
                // clean up before this generation owns the slot and gauge.
                let mut pool_guard = pool.lock().await;
                if let Some(existing) = pool_guard.get(&remote_addr)
                    && !existing.io.is_closed()
                {
                    debug!(
                        transport_id = %transport_id,
                        remote_addr = %remote_addr,
                        "Discarding duplicate inbound TCP connection"
                    );
                    continue;
                }
                if let Some(closed) = pool_guard.remove(&remote_addr) {
                    closed.recv_task.abort();
                    record_pool_removed(&stats, &closed);
                }

                let (read_half, write_half) = stream.into_split();
                let io = Arc::new(StreamConnectionIo::new(write_half));

                let recv_pool = pool.clone();
                let recv_packet_tx = packet_tx.clone();
                let recv_stats = stats.clone();
                let recv_addr = remote_addr.clone();
                let recv_io = io.clone();

                let recv_task = tokio::spawn(async move {
                    tcp_receive_loop(
                        read_half,
                        TcpReceiveContext {
                            transport_id,
                            remote_addr: recv_addr,
                            packet_tx: recv_packet_tx,
                            pool: recv_pool,
                            stats: recv_stats,
                            first_frame_timeout: first_frame_timeout(first_frame_timeout_ms),
                            frame_completion_timeout: DEFAULT_FRAME_COMPLETION_TIMEOUT,
                            direction: Direction::Inbound,
                            io: recv_io,
                        },
                    )
                    .await;
                });

                let conn = TcpConnection {
                    io,
                    recv_task,
                    direction: Direction::Inbound,
                };

                pool_guard.insert(remote_addr.clone(), conn);
                stats.record_pool_inbound_added();
                drop(pool_guard);
                stats.record_connection_accepted();

                debug!(
                    transport_id = %transport_id,
                    remote_addr = %remote_addr,
                    "Accepted inbound TCP connection"
                );
            }
            Err(e) => {
                warn!(
                    transport_id = %transport_id,
                    error = %e,
                    "TCP accept error"
                );
            }
        }
    }
}

// ============================================================================
// Receive Loop (per-connection)
// ============================================================================

/// Per-connection TCP receive loop.
///
/// Reads complete FMP or direct-FSP packets using the stream reader, delivers
/// them to the node via the packet channel. On error or EOF, removes the
/// connection from the pool and exits.
pub(super) struct TcpReceiveContext {
    pub(super) transport_id: TransportId,
    pub(super) remote_addr: TransportAddr,
    pub(super) packet_tx: PacketTx,
    pub(super) pool: ConnectionPool,
    pub(super) stats: Arc<TcpStats>,
    pub(super) first_frame_timeout: Option<Duration>,
    pub(super) frame_completion_timeout: Duration,
    pub(super) direction: Direction,
    pub(super) io: Arc<StreamConnectionIo<tokio::net::tcp::OwnedWriteHalf>>,
}

pub(super) async fn tcp_receive_loop(
    mut reader: tokio::net::tcp::OwnedReadHalf,
    ctx: TcpReceiveContext,
) {
    let TcpReceiveContext {
        transport_id,
        remote_addr,
        packet_tx,
        pool,
        stats,
        first_frame_timeout,
        frame_completion_timeout,
        direction,
        io,
    } = ctx;

    debug!(
        transport_id = %transport_id,
        remote_addr = %remote_addr,
        "TCP receive loop starting"
    );

    let mut first_frame = true;
    loop {
        let is_first_frame = first_frame;
        let read = async {
            if is_first_frame {
                match first_frame_timeout {
                    Some(limit) => match timeout(
                        limit,
                        read_fmp_packet_with_timeout(&mut reader, frame_completion_timeout),
                    )
                    .await
                    {
                        Ok(result) => Some(result),
                        Err(_) => {
                            stats.record_first_frame_timeout();
                            debug!(
                                transport_id = %transport_id,
                                remote_addr = %remote_addr,
                                timeout_ms = limit.as_millis(),
                                "TCP inbound connection timed out before first complete FMP frame"
                            );
                            None
                        }
                    },
                    None => Some(
                        read_fmp_packet_with_timeout(&mut reader, frame_completion_timeout).await,
                    ),
                }
            } else {
                Some(read_fmp_packet_with_timeout(&mut reader, frame_completion_timeout).await)
            }
        };
        tokio::pin!(read);
        let read_result = tokio::select! {
            result = &mut read => result,
            () = io.closed() => None,
        };
        let Some(read_result) = read_result else {
            break;
        };

        match read_result {
            Ok(data) => {
                first_frame = false;
                stats.record_recv(data.len());

                trace!(
                    transport_id = %transport_id,
                    remote_addr = %remote_addr,
                    bytes = data.len(),
                    "TCP packet received"
                );

                let packet = ReceivedPacket::with_timestamp(
                    transport_id,
                    remote_addr.clone(),
                    PacketBuffer::new(data),
                    crate::time::now_ms(),
                );

                if packet_tx.send(packet).is_err() {
                    debug!(
                        transport_id = %transport_id,
                        "Packet channel closed, stopping TCP receive loop"
                    );
                    break;
                }
            }
            Err(e) => {
                stats.record_recv_error();
                // EOF or protocol error — remove connection from pool
                debug!(
                    transport_id = %transport_id,
                    remote_addr = %remote_addr,
                    error = %e,
                    "TCP receive error, removing connection"
                );
                break;
            }
        }
    }

    io.mark_closed();
    let mut pool_guard = pool.lock().await;
    let removed = remove_if_current(&mut pool_guard, &remote_addr, &io);
    drop(pool_guard);
    if let Some(connection) = removed {
        record_pool_removed(&stats, &connection);
    }

    debug!(
        transport_id = %transport_id,
        remote_addr = %remote_addr,
        direction = ?direction,
        "TCP receive loop stopped"
    );
}

pub(super) fn first_frame_timeout(timeout_ms: u64) -> Option<Duration> {
    (timeout_ms > 0).then(|| Duration::from_millis(timeout_ms))
}
