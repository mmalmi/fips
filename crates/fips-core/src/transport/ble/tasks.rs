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
use tokio::sync::{Mutex, Semaphore};
use tokio::task::JoinSet;
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

/// Time to let the preferred cross-probe direction reach the pool before a
/// non-preferred connection becomes the fallback for a one-way scanner.
const CROSS_PROBE_GRACE_MS: u64 = 100;

const MAX_PENDING_PROBES: usize = 64;
const MAX_PROBE_BACKOFF_SHIFT: u32 = 5;

#[derive(Clone, Debug)]
struct PendingProbe {
    candidate: io::BleCandidate,
    failures: u32,
    next_attempt: tokio::time::Instant,
}

/// Bounded, rotating retry book for scanner results that have not connected.
/// Consecutive failures back off exponentially; taking a due entry rotates it
/// behind its peers so one dead address cannot monopolize the retry timer.
#[derive(Debug)]
struct PendingProbes {
    entries: Vec<PendingProbe>,
    cooldown: std::time::Duration,
}

impl PendingProbes {
    fn new(cooldown: std::time::Duration) -> Self {
        Self {
            entries: Vec::new(),
            cooldown,
        }
    }

    fn position(&self, addr: &BleAddr) -> Option<usize> {
        self.entries
            .iter()
            .position(|entry| &entry.candidate.addr == addr)
    }

    fn observe(&mut self, candidate: io::BleCandidate, now: tokio::time::Instant) {
        if let Some(index) = self.position(&candidate.addr) {
            // Refresh the advertised PSM/packet ceiling without erasing retry
            // history; repeated advertisements must not defeat backoff.
            self.entries[index].candidate = candidate;
            return;
        }
        if self.entries.len() >= MAX_PENDING_PROBES
            && let Some(index) = self
                .entries
                .iter()
                .enumerate()
                .max_by_key(|(_, entry)| (entry.failures, entry.next_attempt))
                .map(|(index, _)| index)
        {
            self.entries.remove(index);
        }
        self.entries.push(PendingProbe {
            candidate,
            failures: 0,
            next_attempt: now,
        });
    }

    fn is_due(&self, addr: &BleAddr, now: tokio::time::Instant) -> bool {
        match self.position(addr) {
            Some(index) => self.entries[index].next_attempt <= now,
            None => true,
        }
    }

    fn mark_attempt(&mut self, addr: &BleAddr, now: tokio::time::Instant) {
        if let Some(index) = self.position(addr) {
            self.entries[index].next_attempt = now + self.cooldown;
        }
    }

    fn record_failure(&mut self, addr: &BleAddr, now: tokio::time::Instant) -> u32 {
        let Some(index) = self.position(addr) else {
            return 0;
        };
        let entry = &mut self.entries[index];
        entry.failures = entry.failures.saturating_add(1);
        let shift = entry
            .failures
            .saturating_sub(1)
            .min(MAX_PROBE_BACKOFF_SHIFT);
        entry.next_attempt = now + self.cooldown * 2u32.pow(shift);
        entry.failures
    }

    fn resolve(&mut self, addr: &BleAddr) {
        self.entries.retain(|entry| &entry.candidate.addr != addr);
    }

    fn drop_connected(&mut self, connected: impl Fn(&BleAddr) -> bool) {
        self.entries
            .retain(|entry| !connected(&entry.candidate.addr));
    }

    fn next_due(&mut self, now: tokio::time::Instant) -> Option<io::BleCandidate> {
        let index = self
            .entries
            .iter()
            .position(|entry| entry.next_attempt <= now)?;
        let entry = self.entries.remove(index);
        let candidate = entry.candidate.clone();
        self.entries.push(entry);
        Some(candidate)
    }
}

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

pub(super) fn local_node_wins_outbound(local: &NodeAddr, peer: &NodeAddr) -> bool {
    local < peer
}

async fn preferred_connection_arrived<S: BleStream>(
    pool: &SharedBlePool<S>,
    addr: &TransportAddr,
) -> bool {
    tokio::time::sleep(std::time::Duration::from_millis(CROSS_PROBE_GRACE_MS)).await;
    pool.lock().await.contains(addr)
}

async fn admit_inbound<S: BleStream + 'static>(stream: S, ctx: AcceptLoopContext<S>) {
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
    let addr = stream.remote_addr().clone();
    let ta = addr.to_transport_addr();
    let stream = FramedBleStream::new(stream, max_packet);

    if pool.lock().await.contains(&ta) {
        debug!(addr = %ta, "BLE inbound: already connected, skipping");
        return;
    }

    let send_mtu = stream.send_mtu();
    let recv_mtu = stream.recv_mtu();
    let mut peer_node_addr = None;
    if let Some(ref our_pubkey) = local_pubkey {
        let peer_pubkey = match pubkey_exchange(&stream, our_pubkey).await {
            Ok(peer_pubkey) => peer_pubkey,
            Err(error) => {
                stats.record_pubkey_exchange_failure();
                debug!(addr = %ta, %error, "BLE inbound pubkey exchange failed");
                return;
            }
        };
        debug!(addr = %ta, "BLE inbound pubkey exchange complete");
        let peer_addr = NodeAddr::from_pubkey(&peer_pubkey);
        peer_node_addr = Some(peer_addr);
        let incumbent = pool.lock().await.live_addr_of_node(&peer_addr);

        if let Some(existing) = incumbent
            && existing != addr
        {
            // The logical peering already exists; re-announce it under the
            // address that actually owns a stream, never the rotated alias.
            discovery_buffer.add_peer_with_pubkey(&existing, peer_pubkey);
            stats.record_duplicate_node_decline();
            debug!(
                addr = %ta,
                node_addr = %peer_addr,
                "BLE inbound peer already connected on a rotating address alias"
            );
            return;
        }

        if let Some(ref our_addr) = local_node_addr
            && local_node_wins_outbound(our_addr, &peer_addr)
            && preferred_connection_arrived(&pool, &ta).await
        {
            debug!(addr = %ta, "BLE inbound tie-breaker: outbound won");
            return;
        }
        // The physical outbound initiator starts the logical handshake.
    }

    let stream = Arc::new(stream);
    let conn = BleConnection {
        stream: Arc::clone(&stream),
        recv_task: None,
        send_mtu,
        recv_mtu,
        established_at: tokio::time::Instant::now(),
        is_static: false,
        addr,
        node_addr: peer_node_addr,
    };

    match pool.lock().await.insert(ta.clone(), conn) {
        Ok(Some(evicted)) => {
            stats.record_pool_eviction();
            info!(addr = %ta, %evicted, "BLE inbound accepted with eviction");
        }
        Ok(None) => {
            info!(addr = %ta, send_mtu, recv_mtu, "BLE inbound connection accepted");
        }
        Err(error) => {
            warn!(addr = %ta, %error, "BLE pool full, inbound connection rejected");
            stats.record_connection_rejected();
            return;
        }
    }
    if !attach_receive_loop(
        stream,
        ta,
        pool,
        packet_tx,
        transport_id,
        Arc::clone(&stats),
        recv_mtu,
    )
    .await
    {
        return;
    }
    stats.record_connection_accepted();
}

pub(super) async fn accept_loop<A>(mut acceptor: A, ctx: AcceptLoopContext<A::Stream>)
where
    A: io::BleAcceptor,
    A::Stream: 'static,
{
    let inbound_limit = ctx.pool.lock().await.max_connections().max(1);
    let permits = Arc::new(Semaphore::new(inbound_limit));
    let mut handlers = JoinSet::new();

    loop {
        while let Some(result) = handlers.try_join_next() {
            if let Err(error) = result {
                debug!(%error, "BLE inbound admission task failed");
            }
        }
        match acceptor.accept().await {
            Ok(stream) => {
                let Ok(permit) = Arc::clone(&permits).try_acquire_owned() else {
                    ctx.stats.record_connection_rejected();
                    debug!("BLE inbound admission limit reached");
                    continue;
                };
                let handler_ctx = AcceptLoopContext {
                    pool: Arc::clone(&ctx.pool),
                    packet_tx: ctx.packet_tx.clone(),
                    transport_id: ctx.transport_id,
                    stats: Arc::clone(&ctx.stats),
                    local_pubkey: ctx.local_pubkey,
                    discovery_buffer: Arc::clone(&ctx.discovery_buffer),
                    local_node_addr: ctx.local_node_addr,
                    max_packet: ctx.max_packet,
                };
                handlers.spawn(async move {
                    let _permit = permit;
                    admit_inbound(stream, handler_ctx).await;
                });
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

    // A retired receive task must not remove a newer connection that reused
    // the same transport address.
    let mut pool = pool.lock().await;
    if pool
        .get(&addr)
        .is_some_and(|connection| Arc::ptr_eq(&connection.stream, &stream))
    {
        pool.remove(&addr);
    }
}

pub(super) async fn attach_receive_loop<S: BleStream + 'static>(
    stream: Arc<FramedBleStream<S>>,
    addr: TransportAddr,
    pool: SharedBlePool<S>,
    packet_tx: PacketTx,
    transport_id: TransportId,
    stats: Arc<BleStats>,
    recv_mtu: u16,
) -> bool {
    let recv_task = tokio::spawn(receive_loop(
        Arc::clone(&stream),
        addr.clone(),
        Arc::clone(&pool),
        packet_tx,
        transport_id,
        stats,
        recv_mtu,
    ));
    let mut pool = pool.lock().await;
    if let Some(connection) = pool.get_mut(&addr)
        && Arc::ptr_eq(&connection.stream, &stream)
    {
        connection.recv_task = Some(recv_task);
        true
    } else {
        recv_task.abort();
        false
    }
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

    // Addresses discovered but not yet connected — retried after cooldown
    // even if the scanner doesn't fire again (BlueZ deduplicates). The book
    // also owns cooldown, exponential backoff, and fair retry rotation.
    // Rotating link aliases already resolved to a stable node identity. An
    // alias stays suppressed only while that node still has a live pool entry.
    let mut known_node_of: HashMap<BleAddr, NodeAddr> = HashMap::new();
    let cooldown = std::time::Duration::from_secs(cooldown_secs.max(1));
    let mut pending = PendingProbes::new(cooldown);
    let retry_interval = tokio::time::interval(cooldown);
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
                pending.drop_connected(|addr| pool_guard.contains(&addr.to_transport_addr()));
                drop(pool_guard);
                match pending.next_due(tokio::time::Instant::now()) {
                    Some(candidate) => candidate,
                    None => continue,
                }
            }
        };
        let addr = candidate.addr.clone();
        let psm = candidate.bootstrap.psm;
        buffer.remember_bootstrap(&addr, candidate.bootstrap);

        trace!(addr = %addr, psm, "BLE scan result");
        stats.record_scan_result();

        // Skip if already connected
        {
            let pool_guard = pool.lock().await;
            if pool_guard.contains(&addr.to_transport_addr()) {
                pending.resolve(&addr);
                continue;
            }
        }

        if let Some(node_addr) = known_node_of.get(&addr).copied() {
            let still_connected = pool.lock().await.find_by_node(&node_addr).is_some();
            if still_connected {
                pending.resolve(&addr);
                continue;
            }
            known_node_of.remove(&addr);
        }

        let now = tokio::time::Instant::now();
        pending.observe(candidate.clone(), now);
        if !pending.is_due(&addr, now) {
            continue;
        }
        pending.mark_attempt(&addr, now);

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
                stats.record_connect_error();
                let failures = pending.record_failure(&addr, tokio::time::Instant::now());
                debug!(addr = %addr, failures, error = %e, "BLE probe connect failed");
                continue;
            }
            Err(_) => {
                debug!(addr = %addr, "BLE probe connect timeout");
                stats.record_connect_timeout();
                pending.record_failure(&addr, tokio::time::Instant::now());
                continue;
            }
        };
        let stream = FramedBleStream::new(stream, max_packet.min(candidate.bootstrap.max_packet));

        // Pubkey exchange, then promote connection to pool
        let ta = addr.to_transport_addr();
        match pubkey_exchange(&stream, &our_pubkey).await {
            Ok(peer_pubkey) => {
                debug!(addr = %addr, "BLE probe complete");
                let peer_addr = NodeAddr::from_pubkey(&peer_pubkey);

                if let Some(existing) = pool.lock().await.live_addr_of_node(&peer_addr)
                    && existing != addr
                {
                    known_node_of.insert(addr.clone(), peer_addr);
                    pending.resolve(&addr);
                    buffer.add_peer_with_pubkey(&existing, peer_pubkey);
                    stats.record_duplicate_node_decline();
                    debug!(
                        addr = %addr,
                        existing = %existing,
                        node_addr = %peer_addr,
                        "BLE probe resolved a rotating alias of a connected peer"
                    );
                    continue;
                }

                // Cross-probe tie-breaker: smaller NodeAddr's outbound wins
                // when both directions arrive. Keep this outbound as a
                // fallback when the peer is not scanning.
                if let Some(ref our_addr) = local_node_addr
                    && !local_node_wins_outbound(our_addr, &peer_addr)
                    && preferred_connection_arrived(&pool, &ta).await
                {
                    known_node_of.insert(addr.clone(), peer_addr);
                    if let Some(existing) = pool.lock().await.live_addr_of_node(&peer_addr) {
                        buffer.add_peer_with_pubkey(&existing, peer_pubkey);
                    }
                    pending.resolve(&addr);
                    debug!(
                        addr = %addr,
                        "BLE probe tie-breaker: yielding to peer's outbound"
                    );
                    continue;
                }

                // Promote connection to pool — no second L2CAP connect needed
                let send_mtu = stream.send_mtu();
                let recv_mtu = stream.recv_mtu();
                let stream = Arc::new(stream);
                let conn = BleConnection {
                    stream: Arc::clone(&stream),
                    recv_task: None,
                    send_mtu,
                    recv_mtu,
                    established_at: tokio::time::Instant::now(),
                    is_static: false,
                    addr: addr.clone(),
                    node_addr: Some(peer_addr),
                };

                match pool.lock().await.insert(ta.clone(), conn) {
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
                        pending.record_failure(&addr, tokio::time::Instant::now());
                        continue;
                    }
                }
                if !attach_receive_loop(
                    stream,
                    ta,
                    Arc::clone(&pool),
                    packet_tx.clone(),
                    transport_id,
                    Arc::clone(&stats),
                    recv_mtu,
                )
                .await
                {
                    continue;
                }
                stats.record_connection_established();
                pending.resolve(&addr);

                // Report to node layer for auto-connect / handshake
                buffer.add_peer_with_pubkey(&addr, peer_pubkey);
            }
            Err(e) => {
                stats.record_pubkey_exchange_failure();
                let failures = pending.record_failure(&addr, tokio::time::Instant::now());
                debug!(addr = %addr, failures, error = %e, "BLE probe pubkey exchange failed");
            }
        }
    }
}

#[cfg(test)]
mod pending_probe_tests {
    use super::*;
    use crate::transport::ble::bootstrap::BleBootstrap;

    fn candidate(device: u8) -> io::BleCandidate {
        io::BleCandidate {
            addr: BleAddr::from_mac("hci0", [device; 6]),
            bootstrap: BleBootstrap::new(0x0080, 512).unwrap(),
        }
    }

    #[test]
    fn failed_probe_backoff_grows_and_caps() {
        let cooldown = std::time::Duration::from_secs(10);
        let start = tokio::time::Instant::now();
        let mut probes = PendingProbes::new(cooldown);
        let item = candidate(1);
        probes.observe(item.clone(), start);

        for failure in 1..=10 {
            probes.record_failure(&item.addr, start);
            let shift = (failure - 1).min(MAX_PROBE_BACKOFF_SHIFT);
            let expected = start + cooldown * 2u32.pow(shift);
            assert_eq!(probes.entries[0].next_attempt, expected);
        }
    }

    #[test]
    fn due_probes_rotate_fairly() {
        let start = tokio::time::Instant::now();
        let mut probes = PendingProbes::new(std::time::Duration::from_secs(1));
        for device in 1..=3 {
            probes.observe(candidate(device), start);
        }

        let order = (0..6)
            .map(|_| probes.next_due(start).unwrap().addr)
            .collect::<Vec<_>>();
        assert_eq!(order[0], order[3]);
        assert_eq!(order[1], order[4]);
        assert_eq!(order[2], order[5]);
        assert_ne!(order[0], order[1]);
        assert_ne!(order[1], order[2]);
    }

    #[test]
    fn repeated_advertisements_do_not_reset_backoff() {
        let cooldown = std::time::Duration::from_secs(10);
        let start = tokio::time::Instant::now();
        let mut probes = PendingProbes::new(cooldown);
        let mut item = candidate(1);
        probes.observe(item.clone(), start);
        probes.record_failure(&item.addr, start);
        let next_attempt = probes.entries[0].next_attempt;

        item.bootstrap.psm = 0x0081;
        probes.observe(item, start + std::time::Duration::from_secs(1));

        assert_eq!(probes.entries[0].next_attempt, next_attempt);
        assert_eq!(probes.entries[0].failures, 1);
        assert_eq!(probes.entries[0].candidate.bootstrap.psm, 0x0081);
    }
}
