mod tests {
    use super::*;
    use crate::config::PeerConfig;
    use std::collections::HashSet;

    const TEST_MAX_BACKOFF_MS: u64 = 300_000;

    fn test_addr(byte: u8) -> NodeAddr {
        NodeAddr::from_bytes([byte; 16])
    }

    fn test_retry_state(npub: &str, retry_after_ms: u64, expires_at_ms: Option<u64>) -> RetryState {
        RetryState {
            peer_config: PeerConfig::new(npub.to_string(), "udp", "127.0.0.1:9"),
            retry_count: 0,
            retry_after_ms,
            reconnect: true,
            expires_at_ms,
        }
    }

    #[test]
    fn quiet_traversal_refresh_jitter_spreads_across_heartbeat_window() {
        let samples = (0u8..=32)
            .map(|byte| quiet_traversal_refresh_jitter_ms(&test_addr(byte)))
            .collect::<Vec<_>>();

        assert!(
            samples.iter().all(|jitter| *jitter <= 10_000),
            "quiet traversal refresh jitter must stay within the heartbeat-sized spread window"
        );
        assert!(
            samples.iter().any(|jitter| *jitter > 1_000),
            "quiet traversal refreshes should not collapse roster probes into the old one-second window"
        );
    }

    #[test]
    fn pending_route_retries_own_expiry_due_order_and_budgets() {
        let expired = test_addr(1);
        let reconnect_early = test_addr(2);
        let reconnect_late = test_addr(3);
        let active_early = test_addr(4);
        let active_late = test_addr(5);
        let future = test_addr(6);

        let mut pending = PendingRouteRetries::default();
        pending.insert(expired, test_retry_state("expired", 0, Some(100)));
        pending.insert(reconnect_late, test_retry_state("reconnect-late", 80, None));
        pending.insert(
            reconnect_early,
            test_retry_state("reconnect-early", 20, None),
        );
        pending.insert(active_late, test_retry_state("active-late", 70, None));
        pending.insert(active_early, test_retry_state("active-early", 10, None));
        pending.insert(future, test_retry_state("future", 150, None));

        assert_eq!(pending.purge_expired(100), vec![expired]);
        assert!(!pending.contains_key(&expired));
        assert!(pending.contains_key(&future));

        let active_peers: HashSet<NodeAddr> = [active_early, active_late].into_iter().collect();
        let due = pending.due_for_tick(100, |addr| active_peers.contains(addr), 1, 1);

        assert_eq!(due.reconnect_total(), 2);
        assert_eq!(due.reconnect_deferred(), 1);
        assert_eq!(due.active_total(), 2);
        assert_eq!(due.active_deferred(), 1);
        assert_eq!(due.into_due_order(), vec![reconnect_early, active_early]);
    }

    #[test]
    fn test_backoff_exponential() {
        let state = RetryState {
            peer_config: PeerConfig::default(),
            retry_count: 0,
            retry_after_ms: 0,
            reconnect: false,
            expires_at_ms: None,
        };
        // base = 5000ms
        assert_eq!(state.backoff_ms(5000, TEST_MAX_BACKOFF_MS), 5000); // 5s * 2^0

        let state = RetryState {
            retry_count: 1,
            ..state
        };
        assert_eq!(state.backoff_ms(5000, TEST_MAX_BACKOFF_MS), 10_000); // 5s * 2^1

        let state = RetryState {
            retry_count: 2,
            ..state
        };
        assert_eq!(state.backoff_ms(5000, TEST_MAX_BACKOFF_MS), 20_000); // 5s * 2^2

        let state = RetryState {
            retry_count: 3,
            ..state
        };
        assert_eq!(state.backoff_ms(5000, TEST_MAX_BACKOFF_MS), 40_000); // 5s * 2^3

        let state = RetryState {
            retry_count: 4,
            ..state
        };
        assert_eq!(state.backoff_ms(5000, TEST_MAX_BACKOFF_MS), 80_000); // 5s * 2^4
    }

    #[test]
    fn test_backoff_cap() {
        let state = RetryState {
            peer_config: PeerConfig::default(),
            retry_count: 20, // 2^20 * 5000 would be huge
            retry_after_ms: 0,
            reconnect: false,
            expires_at_ms: None,
        };
        assert_eq!(
            state.backoff_ms(5000, TEST_MAX_BACKOFF_MS),
            TEST_MAX_BACKOFF_MS
        );
    }

    #[test]
    fn test_backoff_zero_base() {
        let state = RetryState {
            peer_config: PeerConfig::default(),
            retry_count: 3,
            retry_after_ms: 0,
            reconnect: false,
            expires_at_ms: None,
        };
        assert_eq!(state.backoff_ms(0, TEST_MAX_BACKOFF_MS), 0);
    }
}
