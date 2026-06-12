use super::{ConnectionPool, Direction, TorConnection};
use crate::config::TorConfig;
use crate::transport::tcp::stream::read_fmp_packet;
use crate::transport::{PacketTx, ReceivedPacket, TransportAddr, TransportError, TransportId};

use super::stats::TorStats;
use socket2::TcpKeepalive;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;
use tokio::time::Instant;
use tracing::{debug, trace, warn};

// ============================================================================
// Receive Loop (per-connection)
// ============================================================================

/// Per-connection Tor receive loop.
///
/// Reads complete FMP packets using the stream reader, delivers them to
/// the node via the packet channel. On error or EOF, removes the
/// connection from the pool and exits.
#[allow(clippy::too_many_arguments)]
pub(super) async fn tor_receive_loop(
    mut reader: tokio::net::tcp::OwnedReadHalf,
    transport_id: TransportId,
    remote_addr: TransportAddr,
    packet_tx: PacketTx,
    pool: ConnectionPool,
    mtu: u16,
    stats: Arc<TorStats>,
    direction: Direction,
) {
    debug!(
        transport_id = %transport_id,
        remote_addr = %remote_addr,
        "Tor receive loop starting"
    );

    loop {
        match read_fmp_packet(&mut reader, mtu).await {
            Ok(data) => {
                stats.record_recv(data.len());

                trace!(
                    transport_id = %transport_id,
                    remote_addr = %remote_addr,
                    bytes = data.len(),
                    "Tor packet received"
                );

                let packet = ReceivedPacket::new(transport_id, remote_addr.clone(), data);

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
    mtu: u16,
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

        // Split stream and spawn receive task
        let (read_half, write_half) = stream.into_split();
        let writer = Arc::new(Mutex::new(write_half));

        let recv_pool = pool.clone();
        let recv_stats = stats.clone();
        let recv_addr = remote_addr.clone();
        let recv_tx = packet_tx.clone();

        let recv_task = tokio::spawn(async move {
            tor_receive_loop(
                read_half,
                transport_id,
                recv_addr,
                recv_tx,
                recv_pool,
                mtu,
                recv_stats,
                Direction::Inbound,
            )
            .await;
        });

        let conn = TorConnection {
            writer,
            recv_task,
            mtu,
            established_at: Instant::now(),
            direction: Direction::Inbound,
        };

        {
            let mut pool_guard = pool.lock().await;
            pool_guard.insert(remote_addr.clone(), conn);
        }

        stats.record_connection_accepted();
        stats.record_pool_inbound_added();

        debug!(
            transport_id = %transport_id,
            peer_addr = %peer_addr,
            "Accepted inbound onion connection"
        );
    }
}
