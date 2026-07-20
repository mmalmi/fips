// MAX_BACKOFF_MS is now derived from config: node.retry.max_backoff_secs * 1000
const MAX_RETRY_CONNECTIONS_PER_TICK: usize = 16;
const MAX_ACTIVE_DIRECT_REFRESH_RETRIES_PER_TICK: usize = 2;
const LOCAL_ROUTE_RETRY_DELAY_MS: u64 = 2_000;
const LINK_DEAD_DIRECT_REPROBE_DELAY_MS: u64 = 500;
const LINK_DEAD_DIRECT_REPROBE_JITTER_MS: u64 = 1_000;
const QUIET_TRAVERSAL_DIRECT_REFRESH_JITTER_MS: u64 = 10_000;
const ACTIVE_DIRECT_REFRESH_RETRY_DELAY_MS: u64 = 10_000;
const ACTIVE_DIRECT_REFRESH_RETRY_JITTER_MS: u64 = 10_000;
const ACTIVE_DIRECT_REFRESH_NO_TRANSPORT_COOLDOWN_MS: u64 = 30_000;

fn node_addr_jitter_ms(node_addr: &NodeAddr, max_ms: u64) -> u64 {
    let bytes = node_addr.as_bytes();
    let seed = u16::from(bytes[0]) << 8 | u16::from(bytes[1]);
    u64::from(seed) % (max_ms + 1)
}

fn link_dead_reprobe_jitter_ms(node_addr: &NodeAddr) -> u64 {
    node_addr_jitter_ms(node_addr, LINK_DEAD_DIRECT_REPROBE_JITTER_MS)
}

fn quiet_traversal_refresh_jitter_ms(node_addr: &NodeAddr) -> u64 {
    node_addr_jitter_ms(node_addr, QUIET_TRAVERSAL_DIRECT_REFRESH_JITTER_MS)
}

fn active_direct_refresh_retry_delay_ms(node_addr: &NodeAddr) -> u64 {
    ACTIVE_DIRECT_REFRESH_RETRY_DELAY_MS.saturating_add(node_addr_jitter_ms(
        node_addr,
        ACTIVE_DIRECT_REFRESH_RETRY_JITTER_MS,
    ))
}
