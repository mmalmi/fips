//! Virtual IP pool manager.
//!
//! Manages allocation, TTL, and reclamation of virtual IPv6 addresses
//! from a configured CIDR range. Tracks mapping state and integrates
//! with conntrack to determine active sessions.

use crate::NodeAddr;
use std::collections::{HashMap, HashSet, VecDeque};
use std::net::Ipv6Addr;
use std::time::Instant;
use tracing::{debug, info};

/// Most live mappings the pool holds before it refuses new names.
///
/// Every mapping adds rules to the NAT table, which is rebuilt whole on each
/// change, and work to every tick and to shutdown, so this bounds all three.
pub const MAPPING_CEILING: usize = 1000;

/// New mappings the pool admits in a burst, when idle long enough to refill.
pub const MAPPING_BURST: u32 = 50;

/// New mappings per second the pool admits once a burst is spent.
pub const MAPPING_RATE: u32 = 10;

/// Errors from pool operations.
#[derive(Debug, thiserror::Error)]
pub enum PoolError {
    #[error("invalid CIDR: {0}")]
    InvalidCidr(String),
    #[error("pool exhausted ({0} addresses in use)")]
    Exhausted(usize),
    #[error("prefix length must be between 1 and 128")]
    InvalidPrefix,
    #[error("live-mapping ceiling reached ({0} mappings)")]
    AtCeiling(usize),
    #[error("new-mapping rate limit reached")]
    RateLimited,
}

/// State of a virtual IP mapping.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MappingState {
    /// Allocated via DNS query, no NAT sessions yet.
    Allocated,
    /// Active NAT sessions exist.
    Active,
    /// Idle TTL expired; waiting for the grace period before reclamation.
    Draining,
}

/// A single virtual IP ↔ FIPS mesh address mapping.
#[derive(Debug, Clone)]
pub struct VirtualIpMapping {
    /// The FIPS node address this mapping is for.
    pub node_addr: NodeAddr,
    /// The virtual IP allocated from the pool.
    pub virtual_ip: Ipv6Addr,
    /// The FIPS mesh address (fd00::/8).
    pub mesh_addr: Ipv6Addr,
    /// The DNS name that was queried (e.g. "npub1abc...xyz.fips").
    pub dns_name: String,
    /// Current state.
    pub state: MappingState,
    /// When this mapping was created.
    pub created: Instant,
    /// When this mapping was last referenced (DNS query or session).
    pub last_referenced: Instant,
    /// When draining started (for grace period tracking).
    pub drain_start: Option<Instant>,
    /// Number of active conntrack sessions.
    pub session_count: u32,
}

/// Events emitted by the pool on state transitions.
#[derive(Debug)]
pub enum PoolEvent {
    /// A new mapping was allocated — NAT rules should be created.
    MappingCreated {
        virtual_ip: Ipv6Addr,
        mesh_addr: Ipv6Addr,
    },
    /// A mapping was reclaimed — NAT rules should be removed.
    MappingRemoved {
        virtual_ip: Ipv6Addr,
        mesh_addr: Ipv6Addr,
    },
}

/// Pool utilization summary.
#[derive(Debug, Clone)]
pub struct PoolStatus {
    pub total: usize,
    pub allocated: usize,
    pub active: usize,
    pub draining: usize,
    pub free: usize,
}

/// Summary of a single mapping for display.
#[derive(Debug, Clone)]
pub struct MappingInfo {
    pub virtual_ip: Ipv6Addr,
    pub mesh_addr: Ipv6Addr,
    pub node_addr: NodeAddr,
    pub dns_name: String,
    pub state: MappingState,
    pub session_count: u32,
    pub age_secs: u64,
    pub last_ref_secs: u64,
}

/// Path the conntrack table is read from when the kernel provides it.
///
/// A kernel built without `CONFIG_NF_CONNTRACK_PROCFS` has no such file;
/// `SystemConntrack` then dumps the table over netlink instead.
const CONNTRACK_PROC_PATH: &str = "/proc/net/nf_conntrack";

/// Active conntrack sessions counted by destination address.
///
/// Taken once per tick, so the pool does a map lookup per mapping instead of
/// reading and scanning the whole conntrack table per mapping under its lock.
#[derive(Debug, Clone, Default)]
pub struct ConntrackSnapshot {
    sessions: HashMap<Ipv6Addr, u32>,
}

impl ConntrackSnapshot {
    /// Build a snapshot from counts already keyed by destination address.
    pub fn from_counts(sessions: HashMap<Ipv6Addr, u32>) -> Self {
        Self { sessions }
    }

    /// Sessions whose destination is `virtual_ip`, or zero if there are none.
    pub fn sessions_for(&self, virtual_ip: Ipv6Addr) -> u32 {
        self.sessions.get(&virtual_ip).copied().unwrap_or(0)
    }

    /// Number of distinct destination addresses the snapshot saw.
    pub fn len(&self) -> usize {
        self.sessions.len()
    }

    /// Whether the snapshot saw no sessions at all.
    pub fn is_empty(&self) -> bool {
        self.sessions.is_empty()
    }
}

/// Trait for taking a conntrack session snapshot.
pub trait ConntrackQuerier: Send + Sync {
    /// Read the conntrack table once and count sessions by destination.
    fn snapshot(&self) -> Result<ConntrackSnapshot, std::io::Error>;
}

/// Conntrack querier that parses /proc/net/nf_conntrack.
pub struct ProcConntrack;

impl ConntrackQuerier for ProcConntrack {
    fn snapshot(&self) -> Result<ConntrackSnapshot, std::io::Error> {
        let content = std::fs::read_to_string(CONNTRACK_PROC_PATH)?;
        Ok(ConntrackSnapshot::from_counts(parse_conntrack(&content)))
    }
}

/// Where a conntrack snapshot was read from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConntrackSource {
    /// `/proc/net/nf_conntrack`.
    Proc,
    /// A conntrack table dump over `NETLINK_NETFILTER`.
    Netlink,
}

impl ConntrackSource {
    /// Short name of the source.
    pub fn name(self) -> &'static str {
        match self {
            Self::Proc => "proc",
            Self::Netlink => "netlink",
        }
    }
}

/// Why no conntrack source could be read.
#[derive(Debug)]
pub struct ConntrackUnreadable {
    /// The error reading `/proc/net/nf_conntrack`.
    pub proc: std::io::Error,
    /// The error from the netlink dump, when the proc file was absent and the
    /// dump was tried.
    pub netlink: Option<std::io::Error>,
}

impl ConntrackUnreadable {
    /// The error that stands for the whole failed read.
    ///
    /// When the dump was tried, its error is the one that decided the read, so
    /// it sets the kind; the absent proc file is kept in the message. Only a
    /// proc error that stopped the read before the dump stands alone.
    fn into_error(self) -> std::io::Error {
        match self.netlink {
            Some(netlink) => std::io::Error::new(
                netlink.kind(),
                format!("proc: {}; netlink: {netlink}", self.proc),
            ),
            None => self.proc,
        }
    }
}

/// The conntrack reader the gateway uses, which also says which source
/// answered.
///
/// The per-tick read reports its source with the snapshot. The queriers are type
/// parameters so tests can substitute fakes.
///
/// The proc file is read first. Only when it is absent is the table dumped
/// over netlink, and that is decided on every read: the file appears once
/// `nf_conntrack` is loaded in the namespace, so a choice fixed at startup
/// could keep using netlink on a kernel that has the file.
pub struct SystemConntrack<P = ProcConntrack, N = super::conntrack::NetlinkConntrack> {
    proc: P,
    netlink: N,
}

impl<P: ConntrackQuerier, N: ConntrackQuerier> SystemConntrack<P, N> {
    /// A reader over the given proc and netlink queriers.
    pub fn new(proc: P, netlink: N) -> Self {
        Self { proc, netlink }
    }

    /// Read conntrack once and say which source the snapshot came from.
    ///
    /// A proc error other than an absent file, such as a permission error, is
    /// returned without trying netlink.
    pub fn read(&self) -> Result<(ConntrackSource, ConntrackSnapshot), ConntrackUnreadable> {
        match self.proc.snapshot() {
            Ok(snapshot) => Ok((ConntrackSource::Proc, snapshot)),
            Err(proc) if proc.kind() == std::io::ErrorKind::NotFound => {
                match self.netlink.snapshot() {
                    Ok(snapshot) => Ok((ConntrackSource::Netlink, snapshot)),
                    Err(netlink) => Err(ConntrackUnreadable {
                        proc,
                        netlink: Some(netlink),
                    }),
                }
            }
            Err(proc) => Err(ConntrackUnreadable {
                proc,
                netlink: None,
            }),
        }
    }
}

impl Default for SystemConntrack {
    fn default() -> Self {
        Self::new(ProcConntrack, super::conntrack::NetlinkConntrack)
    }
}

impl<P: ConntrackQuerier, N: ConntrackQuerier> ConntrackQuerier for SystemConntrack<P, N> {
    fn snapshot(&self) -> Result<ConntrackSnapshot, std::io::Error> {
        self.read()
            .map(|(_, snapshot)| snapshot)
            .map_err(ConntrackUnreadable::into_error)
    }
}

/// Count conntrack lines by the destination addresses they name.
///
/// Every `dst=` value is parsed as an address and compared as an address. The
/// kernel prints tuples as `src=%pI6 dst=%pI6`, the full uncompressed form with
/// leading zeros, so a session to `fd01::1` is written
/// `dst=fd01:0000:0000:0000:0000:0000:0000:0001`; the previous code searched
/// each line for the address's compressed `Display` form, which cannot occur in
/// a fixed-width field, so it counted nothing on any kernel.
///
/// A conntrack line carries the original and the reply tuple, each with its own
/// `dst=`, and the line is counted once per distinct address among them. That
/// keeps the meaning the count had before, which was "this line mentions the
/// address". A value that does not parse as an IPv6 address is skipped, which
/// is how IPv4 lines and any future field are ignored.
fn parse_conntrack(content: &str) -> HashMap<Ipv6Addr, u32> {
    let mut counts: HashMap<Ipv6Addr, u32> = HashMap::new();
    let mut seen: HashSet<Ipv6Addr> = HashSet::new();

    for line in content.lines() {
        seen.clear();
        for token in line.split_whitespace() {
            let Some(value) = token.strip_prefix("dst=") else {
                continue;
            };
            let Ok(addr) = value.parse::<Ipv6Addr>() else {
                continue;
            };
            seen.insert(addr);
        }
        for addr in &seen {
            *counts.entry(*addr).or_insert(0) += 1;
        }
    }

    counts
}

/// Whether a conntrack read outcome is new or a repeat of the last one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReadReport {
    /// The outcome differs from the previous read, or is the first.
    Changed,
    /// The same outcome as the previous read.
    Repeated,
}

/// Remembers the last conntrack read outcome.
///
/// When no source is readable, for example a kernel with no
/// `/proc/net/nf_conntrack` whose netlink dump is refused, every read fails
/// the same way and a per-tick warning would repeat for the life of the
/// process. Warning on a change of outcome still separates "the source is
/// unreadable" from "there are no sessions", which the pool could not
/// distinguish before, without filling the log.
#[derive(Debug, Default)]
pub struct ConntrackReadLog {
    last: Option<Option<std::io::ErrorKind>>,
}

impl ConntrackReadLog {
    /// Record a read outcome and say whether it is new.
    ///
    /// `None` is a successful read; `Some(kind)` is a failure of that kind.
    pub fn observe(&mut self, outcome: Option<std::io::ErrorKind>) -> ReadReport {
        let report = if self.last == Some(outcome) {
            ReadReport::Repeated
        } else {
            ReadReport::Changed
        };
        self.last = Some(outcome);
        report
    }
}

/// Token bucket for new mappings.
///
/// The level is kept in token-nanoseconds so refill is exact integer
/// arithmetic: one token is `NANOS` units, and each elapsed nanosecond adds
/// `rate` units.
#[derive(Debug)]
struct Bucket {
    /// Current level, in units of `1 / NANOS` token.
    level: u128,
    /// Level when full.
    capacity: u128,
    /// Tokens added per second.
    rate: u128,
    /// When the level was last brought up to date; unset until first use.
    last: Option<Instant>,
}

impl Bucket {
    const NANOS: u128 = 1_000_000_000;

    /// A full bucket of `capacity` tokens refilling at `rate` per second.
    fn new(capacity: u32, rate: u32) -> Self {
        let capacity = u128::from(capacity) * Self::NANOS;
        Self {
            level: capacity,
            capacity,
            rate: u128::from(rate),
            last: None,
        }
    }

    /// Add what has accrued since the last refill, up to capacity.
    fn refill(&mut self, now: Instant) {
        if let Some(last) = self.last {
            let elapsed = now.saturating_duration_since(last).as_nanos();
            self.level = self
                .level
                .saturating_add(elapsed.saturating_mul(self.rate))
                .min(self.capacity);
        }
        // Never move backwards, so a stale `now` cannot credit time twice.
        self.last = Some(self.last.map_or(now, |last| last.max(now)));
    }

    /// Whether at least one whole token is available.
    fn has_token(&self) -> bool {
        self.level >= Self::NANOS
    }

    /// Spend one token; the caller has checked `has_token`.
    fn take(&mut self) {
        self.level = self.level.saturating_sub(Self::NANOS);
    }

    /// Whole tokens available.
    #[cfg(test)]
    fn tokens(&self) -> u128 {
        self.level / Self::NANOS
    }
}

/// Virtual IP pool manager.
pub struct VirtualIpPool {
    /// Available addresses (free pool).
    available: VecDeque<Ipv6Addr>,
    /// Active mappings keyed by NodeAddr.
    mappings: HashMap<NodeAddr, VirtualIpMapping>,
    /// Reverse map: virtual IP → NodeAddr.
    reverse: HashMap<Ipv6Addr, NodeAddr>,
    /// DNS TTL / mapping TTL in seconds.
    ttl_secs: u64,
    /// Grace period after last session before reclamation.
    grace_secs: u64,
    /// Total pool size.
    total: usize,
    /// Most live mappings admitted before new names are refused.
    ceiling: usize,
    /// Rate limit on new mappings.
    bucket: Bucket,
}

impl VirtualIpPool {
    /// Create a new pool from a CIDR string (e.g., `fd01::/112`), with the
    /// compiled-in admission limits.
    pub fn new(cidr: &str, ttl_secs: u64, grace_secs: u64) -> Result<Self, PoolError> {
        Self::with_limits(
            cidr,
            ttl_secs,
            grace_secs,
            MAPPING_CEILING,
            MAPPING_BURST,
            MAPPING_RATE,
        )
    }

    /// Create a pool with explicit admission limits.
    ///
    /// Production uses `new`; this exists so tests can set limits small
    /// enough to reach without allocating the compiled-in counts.
    fn with_limits(
        cidr: &str,
        ttl_secs: u64,
        grace_secs: u64,
        ceiling: usize,
        burst: u32,
        rate: u32,
    ) -> Result<Self, PoolError> {
        let (base, prefix_len) = parse_ipv6_cidr(cidr)?;
        if prefix_len == 0 || prefix_len > 128 {
            return Err(PoolError::InvalidPrefix);
        }

        let mut available = VecDeque::new();
        let host_bits = 128 - prefix_len;

        // Cap at 2^16 addresses to avoid massive allocations
        let max_addrs: u128 = if host_bits > 16 {
            1u128 << 16
        } else {
            1u128 << host_bits
        };

        let base_int = u128::from(base);
        // Skip address 0 (network equivalent)
        for i in 1..max_addrs {
            available.push_back(Ipv6Addr::from(base_int + i));
        }

        let total = available.len();
        info!(cidr = %cidr, addresses = total, "Virtual IP pool initialized");

        Ok(Self {
            available,
            mappings: HashMap::new(),
            reverse: HashMap::new(),
            ttl_secs,
            grace_secs,
            total,
            ceiling,
            bucket: Bucket::new(burst, rate),
        })
    }

    /// Refresh an existing mapping's TTL clock, never creating one.
    ///
    /// Returns whether a mapping for `node_addr` existed. A query the gateway
    /// answers without an address still says the client is using the name, so
    /// it must keep the mapping alive without minting one.
    pub fn refresh_if_present(&mut self, node_addr: NodeAddr) -> bool {
        self.refresh_at(node_addr, Instant::now())
    }

    fn refresh_at(&mut self, node_addr: NodeAddr, now: Instant) -> bool {
        match self.mappings.get_mut(&node_addr) {
            Some(mapping) => {
                mapping.last_referenced = now;
                if mapping.state == MappingState::Draining {
                    mapping.state = MappingState::Allocated;
                    mapping.drain_start = None;
                }
                true
            }
            None => false,
        }
    }

    /// Allocate a virtual IP for the given node. Idempotent: returns
    /// existing mapping if one exists.
    pub fn allocate(
        &mut self,
        node_addr: NodeAddr,
        mesh_addr: Ipv6Addr,
        dns_name: &str,
    ) -> Result<(Ipv6Addr, bool), PoolError> {
        self.allocate_at(node_addr, mesh_addr, dns_name, Instant::now())
    }

    /// `allocate` at a given instant, which drives the rate limit's refill
    /// and stamps a new mapping.
    ///
    /// An existing mapping is returned before either limit is consulted, so a
    /// name already in use keeps resolving when new names are refused.
    fn allocate_at(
        &mut self,
        node_addr: NodeAddr,
        mesh_addr: Ipv6Addr,
        dns_name: &str,
        now: Instant,
    ) -> Result<(Ipv6Addr, bool), PoolError> {
        // Idempotent: return existing mapping, refreshed.
        if self.refresh_at(node_addr, now)
            && let Some(mapping) = self.mappings.get(&node_addr)
        {
            return Ok((mapping.virtual_ip, false));
        }

        // Ceiling first, so a refusal there costs no token and names the
        // ceiling whatever the bucket holds.
        if self.mappings.len() >= self.ceiling {
            return Err(PoolError::AtCeiling(self.mappings.len()));
        }
        self.bucket.refill(now);
        if !self.bucket.has_token() {
            return Err(PoolError::RateLimited);
        }
        let virtual_ip = self
            .available
            .pop_front()
            .ok_or(PoolError::Exhausted(self.mappings.len()))?;
        self.bucket.take();

        let mapping = VirtualIpMapping {
            node_addr,
            virtual_ip,
            mesh_addr,
            dns_name: dns_name.to_string(),
            state: MappingState::Allocated,
            created: now,
            last_referenced: now,
            drain_start: None,
            session_count: 0,
        };

        self.mappings.insert(node_addr, mapping);
        self.reverse.insert(virtual_ip, node_addr);

        info!(
            virtual_ip = %virtual_ip,
            mesh_addr = %mesh_addr,
            dns_name = %dns_name,
            "Allocated virtual IP"
        );

        Ok((virtual_ip, true))
    }

    /// Periodic tick — drives state transitions. Returns events for
    /// the NAT and network modules.
    pub fn tick(&mut self, now: Instant, conntrack: Option<&ConntrackSnapshot>) -> Vec<PoolEvent> {
        // An unreadable or interrupted scan is not proof that connections ended.
        let Some(conntrack) = conntrack else {
            return Vec::new();
        };
        let mut events = Vec::new();
        let mut to_free = Vec::new();
        let ttl = std::time::Duration::from_secs(self.ttl_secs);
        let grace = std::time::Duration::from_secs(self.grace_secs);

        for (node_addr, mapping) in &mut self.mappings {
            // One map lookup: the conntrack table was read once, before the
            // pool lock was taken.
            let sessions = conntrack.sessions_for(mapping.virtual_ip);
            mapping.session_count = sessions;

            // Live data-plane traffic pins the mapping: refresh the TTL
            // clock whenever conntrack reports active sessions, so an
            // in-use mapping never ages out from under the client.
            if sessions > 0 {
                mapping.last_referenced = now;
            }

            match mapping.state {
                MappingState::Allocated => {
                    if sessions > 0 {
                        mapping.state = MappingState::Active;
                        debug!(
                            virtual_ip = %mapping.virtual_ip,
                            sessions,
                            "Mapping activated"
                        );
                    } else if now.duration_since(mapping.last_referenced) > ttl {
                        // TTL expired — enter draining with grace period so
                        // the mapping survives browser DNS cache, even if no
                        // conntrack sessions were observed (short HTTP requests
                        // may complete between ticks).
                        mapping.state = MappingState::Draining;
                        mapping.drain_start = Some(now);
                        debug!(
                            virtual_ip = %mapping.virtual_ip,
                            "Allocated mapping TTL expired, draining"
                        );
                    }
                }
                MappingState::Active => {
                    // The traffic refresh above keeps last_referenced == now
                    // while sessions > 0, so the TTL can only trip once the
                    // mapping is idle (no conntrack sessions). An actively used
                    // mapping never drains; an idle one enters the grace period.
                    if now.duration_since(mapping.last_referenced) > ttl {
                        mapping.state = MappingState::Draining;
                        mapping.drain_start = Some(now);
                    }
                }
                MappingState::Draining => {
                    if sessions > 0 {
                        // Traffic resumed before reclamation: recover to
                        // Active and clear drain_start so the next drain
                        // gets a fresh grace window rather than reusing a
                        // stale one.
                        mapping.state = MappingState::Active;
                        mapping.drain_start = None;
                        debug!(
                            virtual_ip = %mapping.virtual_ip,
                            sessions,
                            "Draining mapping recovered to active (traffic resumed)"
                        );
                    } else if let Some(drain_start) = mapping.drain_start
                        && now.duration_since(drain_start) > grace
                    {
                        to_free.push(*node_addr);
                    }
                }
            }
        }

        // Free expired mappings
        for node_addr in to_free {
            if let Some(mapping) = self.mappings.remove(&node_addr) {
                self.reverse.remove(&mapping.virtual_ip);
                self.available.push_back(mapping.virtual_ip);
                info!(
                    virtual_ip = %mapping.virtual_ip,
                    mesh_addr = %mapping.mesh_addr,
                    "Reclaimed virtual IP"
                );
                events.push(PoolEvent::MappingRemoved {
                    virtual_ip: mapping.virtual_ip,
                    mesh_addr: mapping.mesh_addr,
                });
            }
        }

        events
    }

    /// Pool utilization summary.
    pub fn status(&self) -> PoolStatus {
        let mut allocated = 0;
        let mut active = 0;
        let mut draining = 0;
        for mapping in self.mappings.values() {
            match mapping.state {
                MappingState::Allocated => allocated += 1,
                MappingState::Active => active += 1,
                MappingState::Draining => draining += 1,
            }
        }
        PoolStatus {
            total: self.total,
            allocated,
            active,
            draining,
            free: self.available.len(),
        }
    }

    /// Summary of all active mappings.
    pub fn mapping_info(&self, now: Instant) -> Vec<MappingInfo> {
        self.mappings
            .values()
            .map(|m| MappingInfo {
                virtual_ip: m.virtual_ip,
                mesh_addr: m.mesh_addr,
                node_addr: m.node_addr,
                dns_name: m.dns_name.clone(),
                state: m.state,
                session_count: m.session_count,
                age_secs: now.duration_since(m.created).as_secs(),
                last_ref_secs: now.duration_since(m.last_referenced).as_secs(),
            })
            .collect()
    }

    /// Look up which node a virtual IP maps to.
    pub fn lookup_virtual_ip(&self, virtual_ip: &Ipv6Addr) -> Option<&VirtualIpMapping> {
        self.reverse
            .get(virtual_ip)
            .and_then(|addr| self.mappings.get(addr))
    }
}

/// Parse an IPv6 CIDR string into base address and prefix length.
fn parse_ipv6_cidr(cidr: &str) -> Result<(Ipv6Addr, u32), PoolError> {
    let parts: Vec<&str> = cidr.split('/').collect();
    if parts.len() != 2 {
        return Err(PoolError::InvalidCidr(cidr.to_string()));
    }
    let addr: Ipv6Addr = parts[0]
        .parse()
        .map_err(|_| PoolError::InvalidCidr(cidr.to_string()))?;
    let prefix: u32 = parts[1]
        .parse()
        .map_err(|_| PoolError::InvalidCidr(cidr.to_string()))?;
    Ok((addr, prefix))
}

#[cfg(test)]
mod tests;
