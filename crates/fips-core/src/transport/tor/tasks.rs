use super::{
    ConnectionPool, Direction, StreamConnectionIo, TorConnection, record_pool_removed,
    remove_if_current,
};
use crate::config::TorConfig;
use crate::transport::tcp::stream::{
    DEFAULT_FRAME_COMPLETION_TIMEOUT, read_fmp_packet_with_timeout,
};
use crate::transport::{
    PacketBuffer, PacketTx, ReceivedPacket, TransportAddr, TransportError, TransportId,
};

use super::stats::TorStats;
use socket2::TcpKeepalive;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::{TcpListener, TcpStream};
use tracing::{debug, trace, warn};

// ============================================================================
// Receive Loop (per-connection)
// ============================================================================

/// Per-connection Tor receive loop.
///
/// Reads complete FMP packets using the stream reader, delivers them to
/// the node via the packet channel. On error or EOF, removes the
/// connection from the pool and exits.
pub(super) struct TorReceiveContext {
    pub(super) transport_id: TransportId,
    pub(super) remote_addr: TransportAddr,
    pub(super) packet_tx: PacketTx,
    pub(super) pool: ConnectionPool,
    pub(super) stats: Arc<TorStats>,
    pub(super) first_frame_timeout: Option<Duration>,
    pub(super) direction: Direction,
    pub(super) io: Arc<StreamConnectionIo<tokio::net::tcp::OwnedWriteHalf>>,
}

pub(super) async fn tor_receive_loop(
    mut reader: tokio::net::tcp::OwnedReadHalf,
    ctx: TorReceiveContext,
) {
    let TorReceiveContext {
        transport_id,
        remote_addr,
        packet_tx,
        pool,
        stats,
        first_frame_timeout,
        direction,
        io,
    } = ctx;

    debug!(
        transport_id = %transport_id,
        remote_addr = %remote_addr,
        "Tor receive loop starting"
    );

    let mut first_frame = true;
    loop {
        let is_first_frame = first_frame;
        let read = async {
            let frame = read_fmp_packet_with_timeout(&mut reader, DEFAULT_FRAME_COMPLETION_TIMEOUT);
            if is_first_frame {
                match first_frame_timeout {
                    Some(limit) => match tokio::time::timeout(limit, frame).await {
                        Ok(result) => Some(result),
                        Err(_) => {
                            stats.record_recv_error();
                            debug!(
                                transport_id = %transport_id,
                                remote_addr = %remote_addr,
                                timeout_ms = limit.as_millis(),
                                "Tor inbound connection timed out before its first frame"
                            );
                            None
                        }
                    },
                    None => Some(frame.await),
                }
            } else {
                Some(frame.await)
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
                    "Tor packet received"
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
                        "Packet channel closed, stopping Tor receive loop"
                    );
                    break;
                }
            }
            Err(e) => {
                stats.record_recv_error();
                debug!(
                    transport_id = %transport_id,
                    remote_addr = %remote_addr,
                    error = %e,
                    "Tor receive error, removing connection"
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
        "Tor receive loop stopped"
    );
}

// ============================================================================
// Socket Configuration
// ============================================================================

/// Configure socket options on a SOCKS5-connected stream.
///
/// Sets TCP_NODELAY and keepalive on the underlying TCP connection.
pub(super) fn configure_socket(
    stream: &std::net::TcpStream,
    _config: &TorConfig,
) -> Result<(), TransportError> {
    let socket = socket2::SockRef::from(stream);

    // TCP_NODELAY — always enable for FIPS (latency-sensitive protocol messages)
    socket
        .set_tcp_nodelay(true)
        .map_err(|e| TransportError::StartFailed(format!("set nodelay: {}", e)))?;

    // TCP keepalive (30s default, matching TCP transport)
    let keepalive_secs = 30u64;
    if keepalive_secs > 0 {
        let keepalive = TcpKeepalive::new().with_time(Duration::from_secs(keepalive_secs));
        socket
            .set_tcp_keepalive(&keepalive)
            .map_err(|e| TransportError::StartFailed(format!("set keepalive: {}", e)))?;
    }

    Ok(())
}

// ============================================================================
// Accept Loop (onion service inbound)
// ============================================================================

/// Accept loop for inbound onion service connections.
///
/// Mirrors the TCP transport's accept loop. Tor forwards inbound
/// connections to a local TCP listener; we accept them, configure
/// socket options, split the stream, and spawn a per-connection
/// receive task.
pub(super) async fn tor_accept_loop(
    listener: TcpListener,
    transport_id: TransportId,
    packet_tx: PacketTx,
    pool: ConnectionPool,
    max_inbound: usize,
    stats: Arc<TorStats>,
) {
    debug!(
        transport_id = %transport_id,
        "Onion service accept loop starting"
    );

    loop {
        let (stream, peer_addr) = match listener.accept().await {
            Ok(result) => result,
            Err(e) => {
                warn!(
                    transport_id = %transport_id,
                    error = %e,
                    "Onion service accept error"
                );
                continue;
            }
        };

        // Check inbound connection limit. Outbound SOCKS5-connect entries
        // share the pool but do not consume onion-service inbound budget.
        if stats.pool_inbound_count() >= max_inbound as u64 {
            stats.record_connection_rejected();
            debug!(
                transport_id = %transport_id,
                peer_addr = %peer_addr,
                max_inbound,
                "Rejecting inbound onion connection (limit reached)"
            );
            drop(stream);
            continue;
        }

        // Configure socket options on the accepted stream
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

        let socket = socket2::SockRef::from(&std_stream);
        let _ = socket.set_tcp_nodelay(true);
        let keepalive = TcpKeepalive::new().with_time(Duration::from_secs(30));
        let _ = socket.set_tcp_keepalive(&keepalive);

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

        // Resolve ownership before spawning so a fast EOF cannot beat pool
        // registration or leave a dead generation installed afterward.
        let mut pool_guard = pool.lock().await;
        if let Some(existing) = pool_guard.get(&remote_addr)
            && !existing.io.is_closed()
        {
            debug!(
                transport_id = %transport_id,
                remote_addr = %remote_addr,
                "Discarding duplicate inbound Tor connection"
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
        let recv_stats = stats.clone();
        let recv_addr = remote_addr.clone();
        let recv_tx = packet_tx.clone();
        let recv_io = io.clone();

        let recv_task = tokio::spawn(async move {
            tor_receive_loop(
                read_half,
                TorReceiveContext {
                    transport_id,
                    remote_addr: recv_addr,
                    packet_tx: recv_tx,
                    pool: recv_pool,
                    stats: recv_stats,
                    first_frame_timeout: Some(DEFAULT_FRAME_COMPLETION_TIMEOUT),
                    direction: Direction::Inbound,
                    io: recv_io,
                },
            )
            .await;
        });

        let conn = TorConnection {
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
            peer_addr = %peer_addr,
            "Accepted inbound onion connection"
        );
    }
}
