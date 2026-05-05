//! Daemon routing helpers.
//!
//! The default daemon router is still bloom-assisted greedy tree routing.
//! This module adds an opt-in learned-route table that can bias next-hop
//! selection using local evidence from reverse traffic and verified discovery
//! responses.

use crate::NodeAddr;
use serde::Serialize;
use std::collections::HashMap;

/// Locally learned reverse-path route table.
#[derive(Debug, Default)]
pub(crate) struct LearnedRouteTable {
    routes: HashMap<NodeAddr, Vec<LearnedRoute>>,
}

impl LearnedRouteTable {
    pub(crate) fn learn(
        &mut self,
        destination: NodeAddr,
        next_hop: NodeAddr,
        now_ms: u64,
        ttl_secs: u64,
        max_routes_per_dest: usize,
    ) {
        if destination == next_hop || max_routes_per_dest == 0 {
            return;
        }

        let expires_at_ms = now_ms.saturating_add(ttl_secs.saturating_mul(1_000));
        let routes = self.routes.entry(destination).or_default();

        if let Some(route) = routes.iter_mut().find(|route| route.next_hop == next_hop) {
            route.successes = route.successes.saturating_add(1);
            route.last_seen_ms = now_ms;
            route.expires_at_ms = expires_at_ms;
            route.score = (route.score + 1.0).clamp(0.1, 64.0);
        } else {
            routes.push(LearnedRoute {
                next_hop,
                last_seen_ms: now_ms,
                expires_at_ms,
                successes: 1,
                failures: 0,
                score: 1.0,
            });
        }

        Self::sort_and_truncate(routes, max_routes_per_dest);
    }

    pub(crate) fn record_failure(&mut self, destination: &NodeAddr, next_hop: &NodeAddr) {
        let Some(routes) = self.routes.get_mut(destination) else {
            return;
        };

        if let Some(route) = routes.iter_mut().find(|route| &route.next_hop == next_hop) {
            route.failures = route.failures.saturating_add(1);
            route.score = (route.score * 0.5).max(0.01);
        }
    }

    pub(crate) fn best_next_hop<F>(
        &mut self,
        destination: &NodeAddr,
        now_ms: u64,
        mut can_send: F,
    ) -> Option<NodeAddr>
    where
        F: FnMut(&NodeAddr) -> bool,
    {
        let routes = self.routes.get_mut(destination)?;
        routes.retain(|route| route.expires_at_ms > now_ms);
        routes.sort_by(compare_routes);

        routes
            .iter()
            .find(|route| can_send(&route.next_hop))
            .map(|route| route.next_hop)
    }

    pub(crate) fn purge_expired(&mut self, now_ms: u64) {
        self.routes.retain(|_, routes| {
            routes.retain(|route| route.expires_at_ms > now_ms);
            !routes.is_empty()
        });
    }

    pub(crate) fn snapshot(&self, now_ms: u64) -> LearnedRouteTableSnapshot {
        let mut destinations = Vec::new();
        let mut destination_count = 0usize;
        let mut route_count = 0usize;

        for (destination, routes) in &self.routes {
            let active_routes = routes
                .iter()
                .filter(|route| route.expires_at_ms > now_ms)
                .map(|route| {
                    route_count += 1;
                    LearnedRouteSnapshot {
                        next_hop: route.next_hop.to_string(),
                        last_seen_ms: route.last_seen_ms,
                        expires_in_ms: route.expires_at_ms.saturating_sub(now_ms),
                        successes: route.successes,
                        failures: route.failures,
                        score: route.score,
                    }
                })
                .collect::<Vec<_>>();

            if !active_routes.is_empty() {
                destination_count += 1;
                destinations.push(LearnedDestinationSnapshot {
                    destination: destination.to_string(),
                    routes: active_routes,
                });
            }
        }

        LearnedRouteTableSnapshot {
            destinations,
            destination_count,
            route_count,
        }
    }

    fn sort_and_truncate(routes: &mut Vec<LearnedRoute>, max_routes_per_dest: usize) {
        routes.sort_by(compare_routes);
        routes.truncate(max_routes_per_dest);
    }
}

#[derive(Debug, Clone)]
struct LearnedRoute {
    next_hop: NodeAddr,
    last_seen_ms: u64,
    expires_at_ms: u64,
    successes: u64,
    failures: u64,
    score: f64,
}

fn compare_routes(left: &LearnedRoute, right: &LearnedRoute) -> std::cmp::Ordering {
    right
        .score
        .total_cmp(&left.score)
        .then_with(|| right.last_seen_ms.cmp(&left.last_seen_ms))
        .then_with(|| left.next_hop.cmp(&right.next_hop))
}

/// Control-socket snapshot of the learned route table.
#[derive(Debug, Clone, Serialize)]
pub(crate) struct LearnedRouteTableSnapshot {
    pub destination_count: usize,
    pub route_count: usize,
    pub destinations: Vec<LearnedDestinationSnapshot>,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct LearnedDestinationSnapshot {
    pub destination: String,
    pub routes: Vec<LearnedRouteSnapshot>,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct LearnedRouteSnapshot {
    pub next_hop: String,
    pub last_seen_ms: u64,
    pub expires_in_ms: u64,
    pub successes: u64,
    pub failures: u64,
    pub score: f64,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(n: u128) -> NodeAddr {
        NodeAddr::from_bytes(n.to_be_bytes())
    }

    #[test]
    fn learned_routes_prefer_successful_recent_candidates() {
        let dest = addr(100);
        let slow = addr(1);
        let fast = addr(2);
        let mut table = LearnedRouteTable::default();

        table.learn(dest, slow, 1_000, 60, 4);
        table.learn(dest, fast, 1_100, 60, 4);
        table.learn(dest, fast, 1_200, 60, 4);

        assert_eq!(
            table.best_next_hop(&dest, 1_300, |_| true),
            Some(fast),
            "route with stronger local evidence should win"
        );

        table.record_failure(&dest, &fast);
        table.record_failure(&dest, &fast);
        table.record_failure(&dest, &fast);

        assert_eq!(
            table.best_next_hop(&dest, 1_400, |_| true),
            Some(slow),
            "failures should demote a learned route"
        );
    }

    #[test]
    fn learned_routes_expire() {
        let dest = addr(100);
        let hop = addr(1);
        let mut table = LearnedRouteTable::default();

        table.learn(dest, hop, 1_000, 1, 4);
        assert_eq!(table.best_next_hop(&dest, 1_999, |_| true), Some(hop));
        assert_eq!(table.best_next_hop(&dest, 2_001, |_| true), None);
    }
}
