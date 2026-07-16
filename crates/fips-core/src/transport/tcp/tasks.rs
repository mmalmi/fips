use super::stream::read_fmp_packet;
use super::*;
use crate::transport::{PacketBuffer, ReceivedPacket};
use tokio::time::timeout;

// ============================================================================
// Accept Loop
// ============================================================================

/// Socket configuration parameters passed to the accept loop.
pub(super) struct AcceptConfig {
    pub(super) mtu: u16,
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
        mtu,
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

                // Read MSS for per-connection MTU
                let conn_mtu = read_mss_mtu(&std_stream, mtu);

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

                // Split and spawn receive task
                let (read_half, write_half) = stream.into_split();
                let writer = Arc::new(Mutex::new(write_half));

                let recv_pool = pool.clone();
                let recv_packet_tx = packet_tx.clone();
                let recv_stats = stats.clone();
                let recv_addr = remote_addr.clone();

                let recv_task = tokio::spawn(async move {
                    tcp_receive_loop(
                        read_half,
                        TcpReceiveContext {
                            transport_id,
                            remote_addr: recv_addr,
                            packet_tx: recv_packet_tx,
                            pool: recv_pool,
                            mtu: conn_mtu,
                            stats: recv_stats,
                            first_frame_timeout: first_frame_timeout(first_frame_timeout_ms),
                            direction: Direction::Inbound,
                        },
                    )
                    .await;
                });

                let conn = TcpConnection {
                    writer,
                    recv_task,
                    direction: Direction::Inbound,
                };

                let mut pool_guard = pool.lock().await;
                pool_guard.insert(remote_addr.clone(), conn);

                stats.record_connection_accepted();
                stats.record_pool_inbound_added();

                debug!(
                    transport_id = %transport_id,
                    remote_addr = %remote_addr,
                    mtu = conn_mtu,
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
    pub(super) mtu: u16,
    pub(super) stats: Arc<TcpStats>,
    pub(super) first_frame_timeout: Option<Duration>,
    pub(super) direction: Direction,
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
        mtu,
        stats,
        first_frame_timeout,
        direction,
    } = ctx;

    debug!(
        transport_id = %transport_id,
        remote_addr = %remote_addr,
        "TCP receive loop starting"
    );

    let mut first_frame = true;
    loop {
        let read_result = if first_frame {
            match first_frame_timeout {
                Some(limit) => match timeout(limit, read_fmp_packet(&mut reader, mtu)).await {
                    Ok(result) => result,
                    Err(_) => {
                        stats.record_first_frame_timeout();
                        debug!(
                            transport_id = %transport_id,
                            remote_addr = %remote_addr,
                            timeout_ms = limit.as_millis(),
                            "TCP inbound connection timed out before first complete FMP frame"
                        );
                        break;
                    }
                },
                None => read_fmp_packet(&mut reader, mtu).await,
            }
        } else {
            read_fmp_packet(&mut reader, mtu).await
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

    // Clean up: remove ourselves from the pool and decrement the matching
    // direction counter only if this task owned the removed entry.
    let mut pool_guard = pool.lock().await;
    let removed = pool_guard.remove(&remote_addr).is_some();
    drop(pool_guard);
    if removed {
        match direction {
            Direction::Inbound => stats.record_pool_inbound_removed(),
            Direction::Outbound => stats.record_pool_outbound_removed(),
        }
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
