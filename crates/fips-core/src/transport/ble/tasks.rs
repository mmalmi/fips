// ============================================================================
// Background Tasks
// ============================================================================

use super::{
    SharedBlePool,
    addr::BleAddr,
    discovery::DiscoveryBuffer,
    framing::FramedBleStream,
    io::{self, BleScanner, BleStream},
    pool::{BleConnection, ConnectionPool},
    stats::BleStats,
};
use crate::identity::NodeAddr;
use crate::transport::{
    PacketBuffer, PacketTx, ReceivedPacket, TransportAddr, TransportError, TransportId,
};
use secp256k1::XOnlyPublicKey;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;
use tracing::{debug, info, trace, warn};

/// Pre-handshake pubkey exchange prefix byte.
///
/// Distinguishes the identity exchange from FMP packets (version ≥ 0x01).
/// Temporary — removed when FMP switches from IK to XX handshake.
const PUBKEY_EXCHANGE_PREFIX: u8 = 0x00;

/// Pre-handshake pubkey exchange message size: `[0x00][pubkey:32]`.
const PUBKEY_EXCHANGE_SIZE: usize = 33;

/// Timeout for pubkey exchange recv (seconds).
///
/// The peer should respond in milliseconds; 5s is generous. Without this,
/// a peer that connects but never sends its pubkey blocks the calling task
/// forever — killing scan_probe_loop, accept_loop, or the event loop.
const PUBKEY_EXCHANGE_TIMEOUT_SECS: u64 = 5;

/// Exchange public keys over a newly established L2CAP connection.
///
/// Both sides send `[0x00][our_pubkey:32]` and receive the peer's.
/// Returns the peer's XOnlyPublicKey on success.
pub(super) async fn pubkey_exchange<S: BleStream>(
    stream: &S,
    local_pubkey: &[u8; 32],
) -> Result<XOnlyPublicKey, TransportError> {
    // Send our pubkey
    let mut msg = [0u8; PUBKEY_EXCHANGE_SIZE];
    msg[0] = PUBKEY_EXCHANGE_PREFIX;
    msg[1..].copy_from_slice(local_pubkey);
    stream.send(&msg).await?;

    // Receive peer's pubkey (with timeout to prevent indefinite blocking)
    let mut buf = [0u8; PUBKEY_EXCHANGE_SIZE];
    let timeout = std::time::Duration::from_secs(PUBKEY_EXCHANGE_TIMEOUT_SECS);
    let n = match tokio::time::timeout(timeout, stream.recv(&mut buf)).await {
        Ok(result) => result?,
        Err(_) => return Err(TransportError::Timeout),
    };
    if n != PUBKEY_EXCHANGE_SIZE {
        return Err(TransportError::RecvFailed(format!(
            "pubkey exchange: expected {} bytes, got {}",
            PUBKEY_EXCHANGE_SIZE, n
        )));
    }
    if buf[0] != PUBKEY_EXCHANGE_PREFIX {
        return Err(TransportError::RecvFailed(format!(
            "pubkey exchange: bad prefix 0x{:02X}",
            buf[0]
        )));
    }

    XOnlyPublicKey::from_slice(&buf[1..])
        .map_err(|e| TransportError::RecvFailed(format!("pubkey exchange: invalid key: {}", e)))
}

// Beacon loop removed — advertising is now continuous (started once
// in start_async, stopped in stop_async). BLE advertising overhead
// is negligible (~0.15% duty cycle on advertising channels).

/// Accept loop: accepts inbound L2CAP connections, exchanges pubkeys,
/// and adds to pool.
pub(super) struct AcceptLoopContext<S> {
    pub(super) pool: SharedBlePool<S>,
    pub(super) packet_tx: PacketTx,
    pub(super) transport_id: TransportId,
    pub(super) stats: Arc<BleStats>,
    pub(super) local_pubkey: Option<[u8; 32]>,
    pub(super) discovery_buffer: Arc<DiscoveryBuffer>,
    pub(super) local_node_addr: Option<NodeAddr>,
    pub(super) max_packet: u16,
}

pub(super) async fn accept_loop<A>(mut acceptor: A, ctx: AcceptLoopContext<A::Stream>)
where
    A: io::BleAcceptor,
    A::Stream: 'static,
{
    let AcceptLoopContext {
        pool,
        packet_tx,
        transport_id,
        stats,
        local_pubkey,
        discovery_buffer,
        local_node_addr,
        max_packet,
    } = ctx;

    loop {
        match acceptor.accept().await {
            Ok(stream) => {
                let addr = stream.remote_addr().clone();
                let ta = addr.to_transport_addr();
                let stream = FramedBleStream::new(stream, max_packet);

                // Skip if already connected (outbound won the race)
                {
                    let pool_guard = pool.lock().await;
                    if pool_guard.contains(&ta) {
                        debug!(addr = %ta, "BLE inbound: already connected, skipping");
                        continue;
                    }
                }

                let send_mtu = stream.send_mtu();
                let recv_mtu = stream.recv_mtu();

                // Pre-handshake pubkey exchange (temporary, pre-XX)
                if let Some(ref our_pubkey) = local_pubkey {
                    match pubkey_exchange(&stream, our_pubkey).await {
                        Ok(peer_pubkey) => {
                            debug!(addr = %ta, "BLE inbound pubkey exchange complete");
                            discovery_buffer.add_peer_with_pubkey(&addr, peer_pubkey);

                            // Cross-probe tie-breaker: smaller NodeAddr's
                            // outbound wins. If we're smaller, our outbound
                            // should win — drop this inbound.
                            if let Some(ref our_addr) = local_node_addr {
                                let peer_addr = NodeAddr::from_pubkey(&peer_pubkey);
                                if our_addr < &peer_addr {
                                    debug!(
                                        addr = %ta,
                                        "BLE inbound tie-breaker: dropping (our addr < peer, outbound wins)"
                                    );
                                    continue;
                                }
                            }
                        }
                        Err(e) => {
                            debug!(addr = %ta, error = %e, "BLE inbound pubkey exchange failed");
                            continue;
                        }
                    }
                }

                let stream = Arc::new(stream);

                // Spawn receive loop
                let recv_task = tokio::spawn(receive_loop(
                    Arc::clone(&stream),
                    ta.clone(),
                    Arc::clone(&pool),
                    packet_tx.clone(),
                    transport_id,
                    Arc::clone(&stats),
                    recv_mtu,
                ));

                let conn = BleConnection {
                    stream,
                    recv_task: Some(recv_task),
                    send_mtu,
                    recv_mtu,
                    established_at: tokio::time::Instant::now(),
                    is_static: false,
                    addr,
                };

                let mut pool_guard = pool.lock().await;
                match pool_guard.insert(ta.clone(), conn) {
                    Ok(Some(evicted)) => {
                        stats.record_pool_eviction();
                        info!(addr = %ta, evicted = %evicted, "BLE inbound accepted (evicted peer)");
                    }
                    Ok(None) => {
                        info!(addr = %ta, send_mtu, recv_mtu, "BLE inbound connection accepted");
                    }
                    Err(e) => {
                        warn!(addr = %ta, error = %e, "BLE pool full, inbound connection rejected");
                        stats.record_connection_rejected();
                        continue;
                    }
                }
                stats.record_connection_accepted();
            }
            Err(e) => {
                warn!(error = %e, "BLE accept error");
                break;
            }
        }
    }
}

/// Receive loop: reads packets from a BLE stream and delivers to node.
pub(super) async fn receive_loop<S: BleStream>(
    stream: Arc<S>,
    addr: TransportAddr,
    pool: Arc<Mutex<ConnectionPool<Arc<S>>>>,
    packet_tx: PacketTx,
    transport_id: TransportId,
    stats: Arc<BleStats>,
    recv_mtu: u16,
) {
    let mut buf = vec![0u8; recv_mtu as usize];
    loop {
        match stream.recv(&mut buf).await {
            Ok(0) => {
                debug!(addr = %addr, "BLE connection closed by peer");
                break;
            }
            Ok(n) => {
                stats.record_recv(n);
                let packet = ReceivedPacket::with_timestamp(
                    transport_id,
                    addr.clone(),
                    PacketBuffer::new(buf[..n].to_vec()),
                    crate::time::now_ms(),
                );
                if packet_tx.send(packet).is_err() {
                    trace!("BLE packet_tx closed, stopping receive loop");
                    break;
                }
            }
            Err(e) => {
                debug!(addr = %addr, error = %e, "BLE receive error");
                stats.record_recv_error();
                break;
            }
        }
    }

    // Remove from pool
    let mut pool = pool.lock().await;
    pool.remove(&addr);
}

/// Combined scan + probe loop.
///
/// Scanner events arrive continuously (both sides advertise continuously).
/// Each scan result is probed immediately unless the address is in cooldown
/// (recently probed) or already connected. On successful probe, the
/// connection is promoted directly into the pool (no second L2CAP connect
/// needed) and the peer is reported to the discovery buffer for the node
/// layer to auto-connect.
///
/// Cooldown prevents rapid re-probing of the same address: after any probe
/// attempt (success or failure), the address is suppressed for
/// `cooldown_secs`. Connected peers are filtered by pool membership.
pub(super) struct ScanProbeContext<I: io::BleIo> {
    pub(super) io: Arc<I>,
    pub(super) pool: SharedBlePool<I::Stream>,
    pub(super) buffer: Arc<DiscoveryBuffer>,
    pub(super) stats: Arc<BleStats>,
    pub(super) local_pubkey: Option<[u8; 32]>,
    pub(super) connect_timeout_ms: u64,
    pub(super) cooldown_secs: u64,
    pub(super) local_node_addr: Option<NodeAddr>,
    pub(super) packet_tx: PacketTx,
    pub(super) transport_id: TransportId,
    pub(super) max_packet: u16,
}

pub(super) async fn scan_probe_loop<I: io::BleIo>(
    mut scanner: I::Scanner,
    ctx: ScanProbeContext<I>,
) {
    let ScanProbeContext {
        io,
        pool,
        buffer,
        stats,
        local_pubkey,
        connect_timeout_ms,
        cooldown_secs,
        local_node_addr,
        packet_tx,
        transport_id,
        max_packet,
    } = ctx;

    // Track last probe time per address for cooldown
    let mut last_probed: HashMap<BleAddr, tokio::time::Instant> = HashMap::new();
    // Addresses discovered but not yet connected — retried after cooldown
    // even if the scanner doesn't fire again (BlueZ deduplicates).
    let mut pending_candidates: Vec<io::BleCandidate> = Vec::new();
    let cooldown = std::time::Duration::from_secs(cooldown_secs);
    let retry_interval = tokio::time::interval(std::time::Duration::from_secs(cooldown_secs));
    tokio::pin!(retry_interval);
    retry_interval.tick().await; // consume initial tick

    loop {
        // Either a scanner event or the retry timer fires
        let candidate = tokio::select! {
            result = scanner.next() => {
                match result {
                    Some(a) => a,
                    None => {
                        debug!("BLE scanner ended");
                        break;
                    }
                }
            }
            _ = retry_interval.tick() => {
                // Re-probe pending addresses that aren't connected
                let pool_guard = pool.lock().await;
                pending_candidates.retain(|candidate| {
                    !pool_guard.contains(&candidate.addr.to_transport_addr())
                });
                drop(pool_guard);
                if let Some(candidate) = pending_candidates.first().cloned() {
                    candidate
                } else {
                    continue;
                }
            }
        };
        let addr = candidate.addr.clone();
        let psm = candidate.bootstrap.psm;

        trace!(addr = %addr, psm, "BLE scan result");
        stats.record_scan_result();

        // Skip if already connected
        {
            let pool_guard = pool.lock().await;
            if pool_guard.contains(&addr.to_transport_addr()) {
                pending_candidates.retain(|candidate| candidate.addr != addr);
                continue;
            }
        }

        // Track for retry in case probe fails and scanner doesn't re-fire
        if !pending_candidates
            .iter()
            .any(|pending| pending.addr == addr)
        {
            pending_candidates.push(candidate.clone());
        }

        // Skip if in cooldown
        if last_probed
            .get(&addr)
            .is_some_and(|last| last.elapsed() < cooldown)
        {
            continue;
        }

        // Record probe time (before attempt, so cooldown applies on failure too)
        last_probed.insert(addr.clone(), tokio::time::Instant::now());

        // Need pubkey for probe
        let our_pubkey = match local_pubkey {
            Some(pk) => pk,
            None => {
                buffer.add_peer(&addr);
                continue;
            }
        };

        // L2CAP connect
        let stream = match tokio::time::timeout(
            std::time::Duration::from_millis(connect_timeout_ms),
            io.connect(&addr, psm),
        )
        .await
        {
            Ok(Ok(s)) => s,
            Ok(Err(e)) => {
                debug!(addr = %addr, error = %e, "BLE probe connect failed");
                continue;
            }
            Err(_) => {
                debug!(addr = %addr, "BLE probe connect timeout");
                stats.record_connect_timeout();
                continue;
            }
        };
        let stream = FramedBleStream::new(stream, max_packet.min(candidate.bootstrap.max_packet));

        // Pubkey exchange, then promote connection to pool
        let ta = addr.to_transport_addr();
        match pubkey_exchange(&stream, &our_pubkey).await {
            Ok(peer_pubkey) => {
                debug!(addr = %addr, "BLE probe complete");

                // Cross-probe tie-breaker: smaller NodeAddr's outbound wins.
                // If we lose, drop connection — accept_loop handles inbound.
                if let Some(ref our_addr) = local_node_addr {
                    let peer_addr = NodeAddr::from_pubkey(&peer_pubkey);
                    if our_addr >= &peer_addr {
                        debug!(
                            addr = %addr,
                            "BLE probe tie-breaker: yielding to peer's outbound"
                        );
                        buffer.add_peer_with_pubkey(&addr, peer_pubkey);
                        continue;
                    }
                }

                // Promote connection to pool — no second L2CAP connect needed
                let send_mtu = stream.send_mtu();
                let recv_mtu = stream.recv_mtu();
                let stream = Arc::new(stream);

                let recv_task = tokio::spawn(receive_loop(
                    Arc::clone(&stream),
                    ta.clone(),
                    Arc::clone(&pool),
                    packet_tx.clone(),
                    transport_id,
                    Arc::clone(&stats),
                    recv_mtu,
                ));

                let conn = BleConnection {
                    stream,
                    recv_task: Some(recv_task),
                    send_mtu,
                    recv_mtu,
                    established_at: tokio::time::Instant::now(),
                    is_static: false,
                    addr: addr.clone(),
                };

                let mut pool_guard = pool.lock().await;
                match pool_guard.insert(ta.clone(), conn) {
                    Ok(Some(evicted)) => {
                        stats.record_pool_eviction();
                        debug!(addr = %ta, evicted = %evicted, "BLE probe promoted (evicted peer)");
                    }
                    Ok(None) => {
                        debug!(addr = %ta, "BLE probe promoted to pool");
                    }
                    Err(e) => {
                        warn!(addr = %ta, error = %e, "BLE pool full, probe connection dropped");
                        stats.record_connection_rejected();
                    }
                }
                drop(pool_guard);
                stats.record_connection_established();
                pending_candidates.retain(|candidate| candidate.addr != addr);

                // Report to node layer for auto-connect / handshake
                buffer.add_peer_with_pubkey(&addr, peer_pubkey);
            }
            Err(e) => {
                debug!(addr = %addr, error = %e, "BLE probe pubkey exchange failed");
            }
        }
    }
}
