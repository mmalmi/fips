use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use tokio::net::UdpSocket;
use tracing::debug;

use super::types::{
    BootstrapError, PUNCH_ACK_MAGIC, PUNCH_MAGIC, PunchHint, PunchPacket, PunchPacketKind,
    TraversalAddress,
};

/// True if the address string parses to an RFC1918 / unique-local / CGNAT /
/// link-local / loopback IP that's only reachable from inside the
/// publisher's own LAN. Used to gate cross-LAN "mixed" punch targets:
/// pairing our public reflexive against the remote peer's private host
/// candidate cannot succeed when we are not on the same LAN, and trying it
/// stalls traversal and risks latching the slow overlay-relay path as
/// `runtime_endpoint`.
const MAX_PUNCH_TARGETS: usize = 8;
const MAX_OFFERED_CANDIDATES: usize = 32;
const PUNCH_SETTLE_MS: u64 = 250;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(super) enum SourceRank {
    Unplanned,
    RemappedPort,
    Planned,
}

pub(super) fn rank_punch_source(remote: SocketAddr, targets: &[SocketAddr]) -> SourceRank {
    let remote = canonical_socket_addr(remote);
    if targets
        .iter()
        .copied()
        .map(canonical_socket_addr)
        .any(|target| target == remote)
    {
        SourceRank::Planned
    } else if targets
        .iter()
        .copied()
        .map(canonical_socket_addr)
        .any(|target| target.ip() == remote.ip())
    {
        SourceRank::RemappedPort
    } else {
        SourceRank::Unplanned
    }
}

fn canonical_socket_addr(addr: SocketAddr) -> SocketAddr {
    match addr {
        SocketAddr::V6(v6) => v6
            .ip()
            .to_ipv4_mapped()
            .map(|ip| SocketAddr::new(IpAddr::V4(ip), v6.port()))
            .unwrap_or(SocketAddr::V6(v6)),
        addr => addr,
    }
}

fn canonical_ip(ip: &str) -> Option<IpAddr> {
    match ip.parse::<IpAddr>().ok()? {
        IpAddr::V6(v6) => Some(v6.to_ipv4_mapped().map_or(IpAddr::V6(v6), IpAddr::V4)),
        ip => Some(ip),
    }
}

fn is_private_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_private(),
        IpAddr::V6(v6) => v6.is_unique_local(),
    }
}

fn is_never_punchable_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            v4.is_loopback()
                || v4.is_link_local()
                || v4.is_unspecified()
                || v4.is_multicast()
                || v4.is_broadcast()
                || (v4.octets()[0] == 100 && (v4.octets()[1] & 0xc0) == 64)
        }
        IpAddr::V6(v6) => {
            v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_multicast()
                || (v6.segments()[0] & 0xffc0) == 0xfe80
        }
    }
}

fn canonical_candidate(candidate: &TraversalAddress) -> Option<TraversalAddress> {
    let ip = canonical_ip(&candidate.ip)?;
    if candidate.port == 0 || is_never_punchable_ip(ip) {
        return None;
    }
    Some(TraversalAddress {
        protocol: candidate.protocol.clone(),
        ip: ip.to_string(),
        port: candidate.port,
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum AddressSource {
    Local,
    Reflexive,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum PunchStrategy {
    Lan,
    Reflexive,
    Mixed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct PlannedPunchTarget {
    pub(super) strategy: PunchStrategy,
    pub(super) local_source: AddressSource,
    pub(super) remote_source: AddressSource,
    pub(super) local: TraversalAddress,
    pub(super) remote: TraversalAddress,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct PlannedRemoteEndpoints {
    pub(super) remotes: Vec<SocketAddr>,
    pub(super) preferred_count: usize,
}

fn same_subnet_24(left: &TraversalAddress, right: &TraversalAddress) -> bool {
    let (Some(IpAddr::V4(left)), Some(IpAddr::V4(right))) =
        (canonical_ip(&left.ip), canonical_ip(&right.ip))
    else {
        return false;
    };
    left.octets()[..3] == right.octets()[..3]
}

fn admit_private_candidate(
    candidate: TraversalAddress,
    local_addresses: &[TraversalAddress],
    apply_private_gate: bool,
) -> Option<TraversalAddress> {
    let ip = canonical_ip(&candidate.ip)?;
    if apply_private_gate
        && is_private_ip(ip)
        && !local_addresses
            .iter()
            .any(|local| same_subnet_24(local, &candidate))
    {
        return None;
    }
    Some(candidate)
}

pub(super) fn plan_punch_targets(
    local_addresses: &[TraversalAddress],
    local_reflexive_address: Option<&TraversalAddress>,
    remote_addresses: &[TraversalAddress],
    remote_reflexive_address: Option<&TraversalAddress>,
    prefer_same_lan: bool,
) -> Vec<PlannedPunchTarget> {
    let mut planned = Vec::new();

    let mut lan_refs = local_addresses.to_vec();
    let local_reflexive_on_lan = local_reflexive_address
        .and_then(|candidate| canonical_ip(&candidate.ip))
        .map(is_private_ip)
        .unwrap_or(true);
    if let Some(candidate) = local_reflexive_address
        .and_then(canonical_candidate)
        .filter(|candidate| canonical_ip(&candidate.ip).is_some_and(is_private_ip))
    {
        lan_refs.push(candidate);
    }

    let remote_reflexive = remote_reflexive_address
        .and_then(canonical_candidate)
        .and_then(|candidate| {
            admit_private_candidate(candidate, &lan_refs, !local_reflexive_on_lan)
        });
    let remote_candidates = remote_addresses
        .iter()
        .take(MAX_OFFERED_CANDIDATES)
        .filter_map(canonical_candidate)
        .filter_map(|candidate| admit_private_candidate(candidate, &lan_refs, true))
        .collect::<Vec<_>>();

    let mut push_unique = |target: PlannedPunchTarget| {
        if planned.len() < MAX_PUNCH_TARGETS && !planned.iter().any(|existing| existing == &target)
        {
            planned.push(target);
        }
    };

    if prefer_same_lan {
        push_same_lan_targets(local_addresses, &remote_candidates, &mut push_unique);
        push_reflexive_target(
            local_reflexive_address,
            remote_reflexive.as_ref(),
            &mut push_unique,
        );
    } else {
        // Reflexive ↔ Reflexive first: the only path that's reliable across
        // arbitrary network topologies. Try this before any host-candidate path
        // so we don't latch onto a misleading asymmetric route (e.g. an offer's
        // private host candidate that we can reach one-way via a routed VPN).
        push_reflexive_target(
            local_reflexive_address,
            remote_reflexive.as_ref(),
            &mut push_unique,
        );
        // Same-LAN paths (matching /24 between local and remote host candidates).
        // Only fires when both sides exposed local candidates AND they share a
        // /24 prefix.
        push_same_lan_targets(local_addresses, &remote_candidates, &mut push_unique);
    }

    push_mixed_targets(
        local_addresses,
        local_reflexive_address,
        &remote_candidates,
        remote_reflexive.as_ref(),
        &mut push_unique,
    );

    planned
}

fn push_reflexive_target(
    local_reflexive_address: Option<&TraversalAddress>,
    remote_reflexive_address: Option<&TraversalAddress>,
    push_unique: &mut impl FnMut(PlannedPunchTarget),
) {
    if let (Some(local), Some(remote)) = (local_reflexive_address, remote_reflexive_address) {
        push_unique(PlannedPunchTarget {
            strategy: PunchStrategy::Reflexive,
            local_source: AddressSource::Reflexive,
            remote_source: AddressSource::Reflexive,
            local: local.clone(),
            remote: remote.clone(),
        });
    }
}

fn push_same_lan_targets(
    local_addresses: &[TraversalAddress],
    remote_addresses: &[TraversalAddress],
    push_unique: &mut impl FnMut(PlannedPunchTarget),
) {
    for local in local_addresses {
        for remote in remote_addresses {
            if same_subnet_24(local, remote) {
                push_unique(PlannedPunchTarget {
                    strategy: PunchStrategy::Lan,
                    local_source: AddressSource::Local,
                    remote_source: AddressSource::Local,
                    local: local.clone(),
                    remote: remote.clone(),
                });
            }
        }
    }
}

fn push_mixed_targets(
    local_addresses: &[TraversalAddress],
    local_reflexive_address: Option<&TraversalAddress>,
    remote_addresses: &[TraversalAddress],
    remote_reflexive_address: Option<&TraversalAddress>,
    push_unique: &mut impl FnMut(PlannedPunchTarget),
) {
    if let Some(remote) = remote_reflexive_address {
        for local in local_addresses {
            push_unique(PlannedPunchTarget {
                strategy: PunchStrategy::Mixed,
                local_source: AddressSource::Local,
                remote_source: AddressSource::Reflexive,
                local: local.clone(),
                remote: remote.clone(),
            });
        }
    }

    if let Some(local) = local_reflexive_address {
        for remote in remote_addresses {
            push_unique(PlannedPunchTarget {
                strategy: PunchStrategy::Mixed,
                local_source: AddressSource::Reflexive,
                remote_source: AddressSource::Local,
                local: local.clone(),
                remote: remote.clone(),
            });
        }
    }
}

pub(super) fn planned_remote_endpoints(
    local_addresses: &[TraversalAddress],
    local_reflexive_address: Option<&TraversalAddress>,
    remote_addresses: &[TraversalAddress],
    remote_reflexive_address: Option<&TraversalAddress>,
    prefer_same_lan: bool,
) -> Result<PlannedRemoteEndpoints, BootstrapError> {
    let mut remotes = Vec::new();
    let mut preferred_count = 0usize;
    for target in plan_punch_targets(
        local_addresses,
        local_reflexive_address,
        remote_addresses,
        remote_reflexive_address,
        prefer_same_lan,
    ) {
        let remote = SocketAddr::new(
            target
                .remote
                .ip
                .parse()
                .map_err(|_| BootstrapError::Protocol("invalid-remote-ip".to_string()))?,
            target.remote.port,
        );
        if !remotes.contains(&remote) {
            if prefer_same_lan && target.strategy == PunchStrategy::Lan {
                preferred_count += 1;
            }
            remotes.push(remote);
        }
    }
    Ok(PlannedRemoteEndpoints {
        remotes,
        preferred_count,
    })
}

pub(super) async fn run_punch_attempt(
    socket: &std::net::UdpSocket,
    session_id: &str,
    targets: &[SocketAddr],
    punch: PunchHint,
    timeout: Duration,
    preferred_count: usize,
) -> Result<SocketAddr, BootstrapError> {
    if targets.is_empty() {
        return Err(BootstrapError::Protocol("no-punch-targets".to_string()));
    }

    if preferred_count > 0 && preferred_count < targets.len() {
        let preferred_timeout = preferred_probe_timeout(timeout);
        if let Ok(remote) = run_punch_attempt_once(
            socket,
            session_id,
            &targets[..preferred_count],
            punch.clone(),
            preferred_timeout,
        )
        .await
        {
            return Ok(remote);
        }

        let fallback_timeout = timeout
            .checked_sub(preferred_timeout)
            .filter(|remaining| *remaining >= Duration::from_millis(250))
            .unwrap_or(timeout);
        return run_punch_attempt_once(socket, session_id, targets, punch, fallback_timeout).await;
    }

    run_punch_attempt_once(socket, session_id, targets, punch, timeout).await
}

fn preferred_probe_timeout(timeout: Duration) -> Duration {
    let timeout_ms = timeout.as_millis();
    if timeout_ms <= 250 {
        timeout
    } else {
        Duration::from_millis(timeout_ms.min(900) as u64)
    }
}

async fn run_punch_attempt_once(
    socket: &std::net::UdpSocket,
    session_id: &str,
    targets: &[SocketAddr],
    punch: PunchHint,
    timeout: Duration,
) -> Result<SocketAddr, BootstrapError> {
    if targets.is_empty() {
        return Err(BootstrapError::Protocol("no-punch-targets".to_string()));
    }

    let udp = UdpSocket::from_std(socket.try_clone()?)?;
    let started_at = tokio::time::Instant::now();
    let finish_at = started_at + timeout;
    let delay = Duration::from_millis(punch.start_at_ms.saturating_sub(now_ms()));
    let send = async {
        tokio::time::sleep(delay).await;
        let end = Instant::now() + Duration::from_millis(punch.duration_ms.max(1));
        let mut sequence = 0u32;
        while Instant::now() < end {
            let packet = build_punch_packet(PunchPacketKind::Probe, sequence, session_id);
            for target in targets {
                let _ = udp.send_to(&packet, target).await;
            }
            sequence = sequence.wrapping_add(1);
            tokio::time::sleep(Duration::from_millis(punch.interval_ms.max(20))).await;
        }
    };

    let expected_hash = session_hash(session_id);
    let receive = async {
        let mut buf = [0u8; 2048];
        let mut candidate = None;
        let mut settle_at: Option<tokio::time::Instant> = None;
        let mut unplanned = 0usize;
        loop {
            let deadline = settle_at.map_or(finish_at, |settle| settle.min(finish_at));
            let recv = tokio::time::timeout_at(deadline, udp.recv_from(&mut buf)).await;
            let Ok(Ok((len, remote))) = recv else {
                if unplanned > 0 {
                    debug!(session = %session_id, unplanned, "traversal: refused punch packets from unplanned sources");
                }
                break candidate
                    .ok_or_else(|| BootstrapError::PunchTimeout(session_id.to_string()));
            };
            let rank = rank_punch_source(remote, targets);
            if rank == SourceRank::Unplanned {
                unplanned += 1;
                continue;
            }
            let Ok(packet) = parse_punch_packet(&buf[..len]) else {
                continue;
            };
            if packet.session_hash != expected_hash {
                continue;
            }
            if packet.kind == PunchPacketKind::Probe {
                let ack = build_punch_packet(PunchPacketKind::Ack, packet.sequence, session_id);
                let _ = udp.send_to(&ack, remote).await;
            }
            if rank == SourceRank::Planned {
                break Ok(remote);
            }
            candidate = Some(remote);
            settle_at.get_or_insert_with(|| {
                tokio::time::Instant::now() + Duration::from_millis(PUNCH_SETTLE_MS)
            });
        }
    };

    tokio::pin!(send, receive);
    tokio::select! {
        result = &mut receive => result,
        () = &mut send => receive.await,
    }
}

pub(super) fn nonce() -> String {
    format!("{}-{:016x}", now_ms(), rand::random::<u64>())
}

pub(super) fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis() as u64)
        .unwrap_or(0)
}

pub(super) fn session_hash(session_id: &str) -> [u8; 16] {
    use sha2::{Digest, Sha256};

    let digest = Sha256::digest(session_id.as_bytes());
    let mut output = [0u8; 16];
    output.copy_from_slice(&digest[..16]);
    output
}

pub(super) fn build_punch_packet(
    kind: PunchPacketKind,
    sequence: u32,
    session_id: &str,
) -> [u8; 24] {
    let magic = match kind {
        PunchPacketKind::Probe => PUNCH_MAGIC,
        PunchPacketKind::Ack => PUNCH_ACK_MAGIC,
    };
    let mut packet = [0u8; 24];
    packet[..4].copy_from_slice(&magic.to_be_bytes());
    packet[4..8].copy_from_slice(&sequence.to_be_bytes());
    packet[8..24].copy_from_slice(&session_hash(session_id));
    packet
}

pub(super) fn parse_punch_packet(bytes: &[u8]) -> Result<PunchPacket, BootstrapError> {
    if bytes.len() < 24 {
        return Err(BootstrapError::Protocol(
            "invalid-punch-packet-length".to_string(),
        ));
    }
    let magic = u32::from_be_bytes(
        bytes[..4]
            .try_into()
            .map_err(|_| BootstrapError::Protocol("invalid-punch-magic".to_string()))?,
    );
    let kind = match magic {
        PUNCH_MAGIC => PunchPacketKind::Probe,
        PUNCH_ACK_MAGIC => PunchPacketKind::Ack,
        _ => {
            return Err(BootstrapError::Protocol("invalid-punch-magic".to_string()));
        }
    };
    let sequence = u32::from_be_bytes(
        bytes[4..8]
            .try_into()
            .map_err(|_| BootstrapError::Protocol("invalid-punch-seq".to_string()))?,
    );
    let mut hash = [0u8; 16];
    hash.copy_from_slice(&bytes[8..24]);
    Ok(PunchPacket {
        kind,
        sequence,
        session_hash: hash,
    })
}
