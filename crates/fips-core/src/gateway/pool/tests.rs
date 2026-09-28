use super::*;

#[test]
fn new_mapping_burst_is_bounded_and_existing_names_still_resolve() {
    let mut pool = VirtualIpPool::new("fd01::/112", 60, 60).unwrap();
    let now = Instant::now();
    for n in 1..=50u8 {
        pool.allocate_at(make_node_addr(n), make_mesh_addr(n), "peer.fips", now)
            .unwrap();
    }
    assert!(matches!(
        pool.allocate_at(make_node_addr(51), make_mesh_addr(51), "next.fips", now),
        Err(PoolError::RateLimited)
    ));
    assert!(
        !pool
            .allocate_at(make_node_addr(1), make_mesh_addr(1), "peer.fips", now)
            .unwrap()
            .1
    );
}

#[test]
fn unreadable_conntrack_keeps_draining_mapping_until_a_complete_scan() {
    let mut pool = VirtualIpPool::new("fd01::/120", 60, 60).unwrap();
    let now = Instant::now();
    let node = make_node_addr(1);
    pool.allocate_at(node, make_mesh_addr(1), "peer.fips", now)
        .unwrap();
    let empty = ConntrackSnapshot::default();
    assert!(
        pool.tick(now + std::time::Duration::from_secs(61), Some(&empty))
            .is_empty()
    );
    assert!(
        pool.tick(now + std::time::Duration::from_secs(200), None)
            .is_empty()
    );
    assert_eq!(pool.status().draining, 1);
    assert_eq!(
        pool.tick(now + std::time::Duration::from_secs(201), Some(&empty))
            .len(),
        1
    );
}

#[test]
fn dns_renewal_cancels_draining_and_preserves_the_advertised_ttl() {
    let mut pool = VirtualIpPool::new("fd01::/120", 60, 60).unwrap();
    let now = Instant::now();
    let node = make_node_addr(1);
    let mesh = make_mesh_addr(1);
    pool.allocate_at(node, mesh, "peer.fips", now).unwrap();
    let empty = ConntrackSnapshot::default();
    pool.tick(now + std::time::Duration::from_secs(61), Some(&empty));
    assert_eq!(pool.status().draining, 1);
    let renewed = now + std::time::Duration::from_secs(119);
    pool.allocate_at(node, mesh, "peer.fips", renewed).unwrap();
    assert!(
        pool.tick(renewed + std::time::Duration::from_secs(59), Some(&empty))
            .is_empty()
    );
    assert_eq!(pool.status().allocated, 1);
}
use std::time::Duration;

/// Session counts a test sets directly, handed to `tick` as the snapshot
/// the tick task would have read from conntrack.
#[derive(Default)]
struct Sessions {
    counts: HashMap<Ipv6Addr, u32>,
}

impl Sessions {
    fn new() -> Self {
        Self::default()
    }

    fn set(&mut self, addr: Ipv6Addr, count: u32) {
        self.counts.insert(addr, count);
    }

    fn snapshot(&self) -> ConntrackSnapshot {
        ConntrackSnapshot::from_counts(self.counts.clone())
    }
}

fn make_node_addr(byte: u8) -> NodeAddr {
    let mut bytes = [0u8; 16];
    bytes[0] = byte;
    NodeAddr::from_bytes(bytes)
}

fn make_mesh_addr(byte: u8) -> Ipv6Addr {
    let mut bytes = [0u8; 16];
    bytes[0] = 0xfd;
    bytes[15] = byte;
    Ipv6Addr::from(bytes)
}

#[test]
fn test_parse_cidr() {
    let (addr, prefix) = parse_ipv6_cidr("fd01::/112").unwrap();
    assert_eq!(addr, "fd01::".parse::<Ipv6Addr>().unwrap());
    assert_eq!(prefix, 112);
}

#[test]
fn test_parse_cidr_invalid() {
    assert!(parse_ipv6_cidr("not-a-cidr").is_err());
    assert!(parse_ipv6_cidr("fd01::").is_err());
    assert!(parse_ipv6_cidr("fd01::/abc").is_err());
}

#[test]
fn test_pool_creation() {
    let pool = VirtualIpPool::new("fd01::/120", 60, 60).unwrap();
    // /120 = 8 host bits = 256 addresses, minus 1 (network) = 255
    assert_eq!(pool.total, 255);
    assert_eq!(pool.available.len(), 255);
}

#[test]
fn test_pool_allocation() {
    let mut pool = VirtualIpPool::new("fd01::/120", 60, 60).unwrap();
    let node = make_node_addr(1);
    let mesh = make_mesh_addr(1);

    let (vip, is_new) = pool.allocate(node, mesh, "test.fips").unwrap();
    assert!(is_new);
    assert_eq!(vip, "fd01::1".parse::<Ipv6Addr>().unwrap());
    assert_eq!(pool.available.len(), 254);
}

#[test]
fn test_pool_idempotent() {
    let mut pool = VirtualIpPool::new("fd01::/120", 60, 60).unwrap();
    let node = make_node_addr(1);
    let mesh = make_mesh_addr(1);

    let (vip1, new1) = pool.allocate(node, mesh, "test.fips").unwrap();
    let (vip2, new2) = pool.allocate(node, mesh, "test.fips").unwrap();
    assert!(new1);
    assert!(!new2);
    assert_eq!(vip1, vip2);
    assert_eq!(pool.available.len(), 254);
}

#[test]
fn test_pool_exhaustion() {
    // /126 = 2 host bits = 4 addresses, minus 1 = 3
    let mut pool = VirtualIpPool::new("fd01::/126", 60, 60).unwrap();
    assert_eq!(pool.total, 3);

    for i in 1..=3u8 {
        pool.allocate(make_node_addr(i), make_mesh_addr(i), "test.fips")
            .unwrap();
    }
    assert!(
        pool.allocate(make_node_addr(4), make_mesh_addr(4), "test.fips")
            .is_err()
    );
}

/// A `/120` pool with the given limits, TTL and grace of 60 s.
fn limited_pool(ceiling: usize, burst: u32, rate: u32) -> VirtualIpPool {
    VirtualIpPool::with_limits("fd01::/120", 60, 60, ceiling, burst, rate).unwrap()
}

/// Allocate node `i` at `now`.
fn alloc(pool: &mut VirtualIpPool, i: u8, now: Instant) -> Result<(Ipv6Addr, bool), PoolError> {
    pool.allocate_at(make_node_addr(i), make_mesh_addr(i), "test.fips", now)
}

#[test]
fn ceiling_refuses_a_new_name_without_a_token_and_keeps_existing_names() {
    let t0 = Instant::now();
    let mut pool = limited_pool(3, 10, 1);
    let mut vips = Vec::new();
    for i in 1..=3u8 {
        vips.push(alloc(&mut pool, i, t0).unwrap().0);
    }
    assert_eq!(pool.bucket.tokens(), 7);

    assert!(
        matches!(alloc(&mut pool, 4, t0), Err(PoolError::AtCeiling(3))),
        "a fourth new name must be refused at a ceiling of 3"
    );
    assert_eq!(
        pool.bucket.tokens(),
        7,
        "a ceiling refusal must not take a token"
    );
    assert_eq!(
        alloc(&mut pool, 2, t0).unwrap(),
        (vips[1], false),
        "a name that already has a mapping must still resolve at the ceiling"
    );
}

#[test]
fn ceiling_is_checked_before_the_rate_limit() {
    let t0 = Instant::now();
    // The bucket empties exactly as the ceiling is reached.
    let mut pool = limited_pool(3, 3, 1);
    for i in 1..=3u8 {
        alloc(&mut pool, i, t0).unwrap();
    }
    assert_eq!(pool.bucket.tokens(), 0);
    assert!(
        matches!(alloc(&mut pool, 4, t0), Err(PoolError::AtCeiling(3))),
        "a name refused at the ceiling must report the ceiling, not the rate"
    );
}

#[test]
fn rate_limit_refuses_a_burst_keeps_existing_names_and_refills() {
    let t0 = Instant::now();
    let mut pool = limited_pool(100, 2, 1);
    let (vip1, _) = alloc(&mut pool, 1, t0).unwrap();
    alloc(&mut pool, 2, t0).unwrap();
    assert!(
        matches!(alloc(&mut pool, 3, t0), Err(PoolError::RateLimited)),
        "a third new name at the same instant must be refused by a burst of 2"
    );

    assert_eq!(
        alloc(&mut pool, 1, t0).unwrap(),
        (vip1, false),
        "an existing name must resolve with the bucket empty"
    );
    assert_eq!(pool.bucket.tokens(), 0);
    assert!(
        matches!(alloc(&mut pool, 3, t0), Err(PoolError::RateLimited)),
        "resolving an existing name must not have freed a token"
    );

    let (_, is_new) = alloc(&mut pool, 3, t0 + Duration::from_secs(1)).unwrap();
    assert!(is_new, "one refill interval later a new name must allocate");
}

#[test]
fn exhausted_pool_takes_no_token() {
    let t0 = Instant::now();
    // /126 = 3 usable addresses.
    let mut pool = VirtualIpPool::with_limits("fd01::/126", 60, 60, 100, 10, 1).unwrap();
    for i in 1..=3u8 {
        alloc(&mut pool, i, t0).unwrap();
    }
    assert!(matches!(
        alloc(&mut pool, 4, t0),
        Err(PoolError::Exhausted(3))
    ));
    assert_eq!(
        pool.bucket.tokens(),
        7,
        "a refusal for an exhausted pool must not take a token"
    );
}

#[test]
fn test_mapping_lifecycle_allocated_to_free() {
    let mut pool = VirtualIpPool::new("fd01::/120", 1, 1).unwrap();
    let ct = Sessions::new();
    let node = make_node_addr(1);
    let mesh = make_mesh_addr(1);

    pool.allocate(node, mesh, "test.fips").unwrap();

    // Tick before TTL — no change
    let now = Instant::now();
    let events = pool.tick(now, Some(&ct.snapshot()));
    assert!(events.is_empty());
    assert_eq!(pool.mappings.len(), 1);

    // Tick after TTL with no sessions — enters draining
    let later = now + std::time::Duration::from_secs(2);
    let events = pool.tick(later, Some(&ct.snapshot()));
    assert!(events.is_empty());
    assert_eq!(pool.mappings.len(), 1);
    assert_eq!(
        pool.mappings.values().next().unwrap().state,
        MappingState::Draining
    );

    // Tick after grace period — freed
    let after_grace = later + std::time::Duration::from_secs(2);
    let events = pool.tick(after_grace, Some(&ct.snapshot()));
    assert_eq!(events.len(), 1);
    assert!(matches!(events[0], PoolEvent::MappingRemoved { .. }));
    assert_eq!(pool.mappings.len(), 0);
    assert_eq!(pool.available.len(), 255); // returned to pool
}

#[test]
fn test_mapping_lifecycle_active_draining_free() {
    let mut pool = VirtualIpPool::new("fd01::/120", 1, 1).unwrap();
    let mut ct = Sessions::new();
    let node = make_node_addr(1);
    let mesh = make_mesh_addr(1);

    let (vip, _) = pool.allocate(node, mesh, "test.fips").unwrap();

    // Simulate active sessions
    ct.set(vip, 3);
    let now = Instant::now();
    let events = pool.tick(now, Some(&ct.snapshot()));
    assert!(events.is_empty());
    assert_eq!(pool.mappings[&node].state, MappingState::Active);

    // TTL expires after sessions drop to 0 → Draining
    let later = now + std::time::Duration::from_secs(2);
    ct.set(vip, 0);
    let events = pool.tick(later, Some(&ct.snapshot()));
    assert!(events.is_empty());
    assert_eq!(pool.mappings[&node].state, MappingState::Draining);

    // Still draining, grace period not elapsed
    let events = pool.tick(later, Some(&ct.snapshot()));
    assert!(events.is_empty());
    assert_eq!(pool.mappings[&node].state, MappingState::Draining);

    // Grace period elapsed → Free
    let much_later = later + std::time::Duration::from_secs(2);
    let events = pool.tick(much_later, Some(&ct.snapshot()));
    assert_eq!(events.len(), 1);
    assert!(matches!(events[0], PoolEvent::MappingRemoved { .. }));
    assert_eq!(pool.mappings.len(), 0);
}

#[test]
fn test_active_traffic_never_reclaimed() {
    // A mapping with continuous sessions > 0 across many ticks
    // spanning well past the TTL must never be reclaimed and must
    // stay Active: live traffic refreshes last_referenced each tick.
    let mut pool = VirtualIpPool::new("fd01::/120", 1, 1).unwrap();
    let mut ct = Sessions::new();
    let node = make_node_addr(1);
    let mesh = make_mesh_addr(1);

    let (vip, _) = pool.allocate(node, mesh, "test.fips").unwrap();
    ct.set(vip, 2);

    let mut t = Instant::now();
    // First tick activates the mapping.
    let events = pool.tick(t, Some(&ct.snapshot()));
    assert!(events.is_empty());
    assert_eq!(pool.mappings[&node].state, MappingState::Active);

    // Advance many TTL-spans with continuous traffic.
    for _ in 0..10 {
        t += std::time::Duration::from_secs(5); // 5x the 1s TTL
        let events = pool.tick(t, Some(&ct.snapshot()));
        assert!(events.is_empty(), "mapping must not be reclaimed");
        assert_eq!(
            pool.mappings[&node].state,
            MappingState::Active,
            "mapping must stay Active while traffic flows"
        );
    }
    assert_eq!(pool.mappings.len(), 1);
}

#[test]
fn test_bursty_draining_recovers_to_active() {
    // Active -> drains when sessions hit 0 -> regains sessions before
    // grace elapses -> recovers to Active and is not freed.
    let mut pool = VirtualIpPool::new("fd01::/120", 1, 5).unwrap();
    let mut ct = Sessions::new();
    let node = make_node_addr(1);
    let mesh = make_mesh_addr(1);

    let (vip, _) = pool.allocate(node, mesh, "test.fips").unwrap();

    // Activate with traffic.
    ct.set(vip, 1);
    let now = Instant::now();
    let events = pool.tick(now, Some(&ct.snapshot()));
    assert!(events.is_empty());
    assert_eq!(pool.mappings[&node].state, MappingState::Active);

    // TTL passes with sessions dropping to 0 -> Draining.
    let drained = now + std::time::Duration::from_secs(2);
    ct.set(vip, 0);
    let events = pool.tick(drained, Some(&ct.snapshot()));
    assert!(events.is_empty());
    assert_eq!(pool.mappings[&node].state, MappingState::Draining);

    // Traffic resumes before grace (5s) elapses -> recover to Active.
    let resumed = drained + std::time::Duration::from_secs(2);
    ct.set(vip, 3);
    let events = pool.tick(resumed, Some(&ct.snapshot()));
    assert!(events.is_empty());
    assert_eq!(pool.mappings[&node].state, MappingState::Active);
    assert!(pool.mappings[&node].drain_start.is_none());
    assert_eq!(pool.mappings.len(), 1);
}

#[test]
fn test_redrain_honors_fresh_grace_window() {
    // After recovering from Draining, a subsequent drain must get a
    // fresh drain_start so the full grace window is honored again,
    // not reclaimed immediately off a stale drain_start.
    let mut pool = VirtualIpPool::new("fd01::/120", 1, 5).unwrap();
    let mut ct = Sessions::new();
    let node = make_node_addr(1);
    let mesh = make_mesh_addr(1);

    let (vip, _) = pool.allocate(node, mesh, "test.fips").unwrap();

    // Activate.
    ct.set(vip, 1);
    let now = Instant::now();
    pool.tick(now, Some(&ct.snapshot()));
    assert_eq!(pool.mappings[&node].state, MappingState::Active);

    // First drain.
    let first_drain = now + std::time::Duration::from_secs(2);
    ct.set(vip, 0);
    pool.tick(first_drain, Some(&ct.snapshot()));
    assert_eq!(pool.mappings[&node].state, MappingState::Draining);

    // Recover.
    let recover = first_drain + std::time::Duration::from_secs(2);
    ct.set(vip, 2);
    pool.tick(recover, Some(&ct.snapshot()));
    assert_eq!(pool.mappings[&node].state, MappingState::Active);

    // Second drain begins; drain_start must be re-stamped fresh.
    let second_drain = recover + std::time::Duration::from_secs(2);
    ct.set(vip, 0);
    pool.tick(second_drain, Some(&ct.snapshot()));
    assert_eq!(pool.mappings[&node].state, MappingState::Draining);

    // Just before the fresh grace window expires (5s): not reclaimed.
    let before_grace = second_drain + std::time::Duration::from_secs(4);
    let events = pool.tick(before_grace, Some(&ct.snapshot()));
    assert!(events.is_empty(), "fresh grace window must be honored");
    assert_eq!(pool.mappings.len(), 1);

    // After the fresh grace window: reclaimed.
    let after_grace = second_drain + std::time::Duration::from_secs(6);
    let events = pool.tick(after_grace, Some(&ct.snapshot()));
    assert_eq!(events.len(), 1);
    assert!(matches!(events[0], PoolEvent::MappingRemoved { .. }));
    assert_eq!(pool.mappings.len(), 0);
}

#[test]
fn test_pool_status() {
    let mut pool = VirtualIpPool::new("fd01::/120", 60, 60).unwrap();
    let status = pool.status();
    assert_eq!(status.total, 255);
    assert_eq!(status.free, 255);
    assert_eq!(status.allocated, 0);

    pool.allocate(make_node_addr(1), make_mesh_addr(1), "test.fips")
        .unwrap();
    let status = pool.status();
    assert_eq!(status.allocated, 1);
    assert_eq!(status.free, 254);
}

#[test]
fn test_lookup_virtual_ip() {
    let mut pool = VirtualIpPool::new("fd01::/120", 60, 60).unwrap();
    let node = make_node_addr(1);
    let mesh = make_mesh_addr(1);

    let (vip, _) = pool.allocate(node, mesh, "test.fips").unwrap();
    let mapping = pool.lookup_virtual_ip(&vip).unwrap();
    assert_eq!(mapping.node_addr, node);
    assert_eq!(mapping.mesh_addr, mesh);

    let unknown: Ipv6Addr = "fd01::ff".parse().unwrap();
    assert!(pool.lookup_virtual_ip(&unknown).is_none());
}

#[test]
fn test_large_prefix_capped() {
    // /96 = 32 host bits, but pool caps at 2^16
    let pool = VirtualIpPool::new("fd01::/96", 60, 60).unwrap();
    assert_eq!(pool.total, 65535); // 2^16 - 1 (skip addr 0)
}

/// A conntrack line in the form the kernel prints.
///
/// Built from the kernel's own format string, not captured from a running
/// kernel: `net/netfilter/nf_conntrack_standalone.c` prints each tuple with
/// `"src=%pI6 dst=%pI6 "`, and `%pI6` is the full uncompressed form with
/// leading zeros (`Documentation/core-api/printk-formats.rst`). Both were
/// read at v6.8. The host this was written on has no
/// `/proc/net/nf_conntrack` to capture from, because its kernel is built
/// without `CONFIG_NF_CONNTRACK_PROCFS`; OpenWrt's generic kernel config
/// sets it, which is the kernel this parser exists for.
const KERNEL_LINE: &str = "ipv6     10 tcp      6 431999 ESTABLISHED \
     src=fd02:0000:0000:0000:0000:0000:0000:0020 \
     dst=fd01:0000:0000:0000:0000:0000:0000:0001 sport=45678 dport=8000 \
     src=fd01:0000:0000:0000:0000:0000:0000:0001 \
     dst=fd02:0000:0000:0000:0000:0000:0000:0020 sport=8000 dport=45678 \
     [ASSURED] mark=0 use=1";

#[test]
fn conntrack_parse_counts_a_kernel_format_line_for_its_virtual_ip() {
    let counts = parse_conntrack(KERNEL_LINE);
    let virtual_ip: Ipv6Addr = "fd01::1".parse().unwrap();

    assert_eq!(
        counts.get(&virtual_ip).copied().unwrap_or(0),
        1,
        "the kernel writes the uncompressed form, so matching on the \
         address's compressed Display form counts nothing"
    );

    // Healthy path: a different address in the same pool is not counted.
    let other: Ipv6Addr = "fd01::10".parse().unwrap();
    assert_eq!(counts.get(&other).copied().unwrap_or(0), 0);
}

#[test]
fn conntrack_parse_counts_a_line_once_however_many_tuples_name_the_address() {
    // A hairpin flow: the address is the destination of both tuples.
    let line = "ipv6     10 udp      17 29 \
         src=fd01:0000:0000:0000:0000:0000:0000:0001 \
         dst=fd01:0000:0000:0000:0000:0000:0000:0001 sport=1 dport=2 \
         src=fd01:0000:0000:0000:0000:0000:0000:0001 \
         dst=fd01:0000:0000:0000:0000:0000:0000:0001 sport=2 dport=1 \
         mark=0 use=1";
    let counts = parse_conntrack(line);
    let virtual_ip: Ipv6Addr = "fd01::1".parse().unwrap();

    assert_eq!(counts.get(&virtual_ip).copied().unwrap_or(0), 1);
}

#[test]
fn conntrack_parse_counts_each_line_that_names_the_address() {
    let content = format!("{KERNEL_LINE}\n{KERNEL_LINE}\n");
    let counts = parse_conntrack(&content);
    let virtual_ip: Ipv6Addr = "fd01::1".parse().unwrap();

    assert_eq!(counts.get(&virtual_ip).copied().unwrap_or(0), 2);
}

#[test]
fn conntrack_parse_skips_a_value_that_is_not_an_ipv6_address() {
    let content = "ipv4     2 tcp      6 431999 ESTABLISHED src=192.0.2.1 \
         dst=192.0.2.2 sport=1 dport=2 mark=0 use=1\n";

    assert!(parse_conntrack(content).is_empty());
}

#[test]
fn conntrack_snapshot_reads_zero_for_an_address_it_did_not_see() {
    let snapshot = ConntrackSnapshot::from_counts(parse_conntrack(KERNEL_LINE));

    assert_eq!(snapshot.sessions_for("fd01::1".parse().unwrap()), 1);
    assert_eq!(snapshot.sessions_for("fd01::99".parse().unwrap()), 0);
    assert!(ConntrackSnapshot::default().is_empty());
}

#[test]
fn conntrack_read_log_warns_on_a_new_outcome_and_not_on_a_repeat() {
    use std::io::ErrorKind;

    let mut log = ConntrackReadLog::default();

    // The sequence a kernel without the proc file produces, then a source
    // that comes back, then fails again.
    assert_eq!(log.observe(Some(ErrorKind::NotFound)), ReadReport::Changed);
    assert_eq!(log.observe(Some(ErrorKind::NotFound)), ReadReport::Repeated);
    assert_eq!(log.observe(None), ReadReport::Changed);
    assert_eq!(log.observe(None), ReadReport::Repeated);
    assert_eq!(log.observe(Some(ErrorKind::NotFound)), ReadReport::Changed);
    assert_eq!(
        log.observe(Some(ErrorKind::PermissionDenied)),
        ReadReport::Changed,
        "a different failure is a different outcome and is worth a line"
    );
}

/// A conntrack querier that succeeds with an empty snapshot, or fails with
/// a fixed error kind.
struct FixedRead(Option<std::io::ErrorKind>);

impl ConntrackQuerier for FixedRead {
    fn snapshot(&self) -> Result<ConntrackSnapshot, std::io::Error> {
        match self.0 {
            None => Ok(ConntrackSnapshot::default()),
            Some(kind) => Err(kind.into()),
        }
    }
}

#[test]
fn conntrack_read_names_the_proc_source_when_the_proc_read_succeeds() {
    let reader = SystemConntrack::new(FixedRead(None), NOT_CALLED);

    match reader.read() {
        Ok((source, _)) => {
            assert_eq!(source, ConntrackSource::Proc);
            assert_eq!(source.name(), "proc");
        }
        Err(e) => panic!("expected the proc source, got {e:?}"),
    }
}

#[test]
fn conntrack_read_reports_missing_with_the_error_when_the_proc_read_fails() {
    let reader = SystemConntrack::new(
        FixedRead(Some(std::io::ErrorKind::PermissionDenied)),
        NOT_CALLED,
    );

    match reader.read() {
        Err(e) => {
            assert_eq!(e.proc.kind(), std::io::ErrorKind::PermissionDenied);
        }
        Ok((source, _)) => panic!("expected no source, got {source:?}"),
    }
}

/// A netlink stand-in for tests where the dump must not be reached. It
/// fails with a kind no test expects, so reaching it shows in the result.
const NOT_CALLED: FixedRead = FixedRead(Some(std::io::ErrorKind::Unsupported));

/// A conntrack querier that reports one session to a fixed address.
struct OneSession(Ipv6Addr);

impl ConntrackQuerier for OneSession {
    fn snapshot(&self) -> Result<ConntrackSnapshot, std::io::Error> {
        Ok(ConntrackSnapshot::from_counts(HashMap::from([(self.0, 1)])))
    }
}

#[test]
fn system_conntrack_falls_back_to_netlink_when_the_proc_file_is_absent() {
    let addr: Ipv6Addr = "fd01::1".parse().unwrap();
    let reader = SystemConntrack::new(
        FixedRead(Some(std::io::ErrorKind::NotFound)),
        OneSession(addr),
    );

    let (source, snapshot) = reader.read().expect("the netlink dump answered");

    assert_eq!(source, ConntrackSource::Netlink);
    assert_eq!(source.name(), "netlink");
    assert_eq!(snapshot.sessions_for(addr), 1);
}

#[test]
fn system_conntrack_does_not_fall_back_on_a_proc_error_other_than_not_found() {
    let addr: Ipv6Addr = "fd01::1".parse().unwrap();
    let reader = SystemConntrack::new(
        FixedRead(Some(std::io::ErrorKind::PermissionDenied)),
        OneSession(addr),
    );

    let e = reader
        .read()
        .expect_err("a denied proc read is not a missing file");

    assert_eq!(e.proc.kind(), std::io::ErrorKind::PermissionDenied);
    assert!(e.netlink.is_none(), "netlink was not tried");
    assert_eq!(
        reader.snapshot().unwrap_err().kind(),
        std::io::ErrorKind::PermissionDenied
    );
}

#[test]
fn system_conntrack_prefers_proc_when_it_reads() {
    let proc_addr: Ipv6Addr = "fd01::1".parse().unwrap();
    let netlink_addr: Ipv6Addr = "fd01::2".parse().unwrap();
    let reader = SystemConntrack::new(OneSession(proc_addr), OneSession(netlink_addr));

    let (source, snapshot) = reader.read().expect("the proc file answered");

    assert_eq!(source, ConntrackSource::Proc);
    assert_eq!(snapshot.sessions_for(proc_addr), 1);
    assert_eq!(snapshot.sessions_for(netlink_addr), 0);
}

#[test]
fn conntrack_read_reports_both_errors_when_neither_source_reads() {
    let reader = SystemConntrack::new(
        FixedRead(Some(std::io::ErrorKind::NotFound)),
        FixedRead(Some(std::io::ErrorKind::PermissionDenied)),
    );

    match reader.read() {
        Err(e) => {
            assert_eq!(e.proc.kind(), std::io::ErrorKind::NotFound);
            assert_eq!(
                e.netlink.as_ref().map(std::io::Error::kind),
                Some(std::io::ErrorKind::PermissionDenied)
            );
        }
        Ok((source, _)) => panic!("expected no source, got {source:?}"),
    }
    // The per-tick read reports the error that decided it: the dump's.
    assert_eq!(
        reader.snapshot().unwrap_err().kind(),
        std::io::ErrorKind::PermissionDenied
    );
}
