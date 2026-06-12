//! Daemon routing helpers.
//!
//! The default daemon router is still bloom-assisted greedy tree routing.
//! This module adds an opt-in learned-route table that selects among locally
//! observed next hops with smooth weighted round-robin. Return traffic and
//! verified discovery responses reinforce routes; failures decay them; lower
//! score candidates remain in exploratory rotation while they are live.

use crate::NodeAddr;
use serde::Serialize;
use std::collections::HashMap;

const MIN_ROUTE_SCORE: f64 = 0.05;
const MAX_ROUTE_SCORE: f64 = 64.0;
const MAX_ROUTE_WEIGHT: f64 = 512.0;

/// Locally learned reverse-path route table.
#[derive(Debug, Default)]
pub(crate) struct LearnedRouteTable {
    routes: HashMap<NodeAddr, Vec<LearnedRoute>>,
    fallback_exploration: LearnedRouteFallbackExploration,
}

/// Pacing state for periodically exploring non-learned fallback routes.
#[derive(Debug, Default)]
pub(crate) struct LearnedRouteFallbackExploration {
    explored_at_selected: HashMap<NodeAddr, u64>,
}

impl LearnedRouteFallbackExploration {
    pub(crate) fn should_explore(
        &mut self,
        destination: &NodeAddr,
        selected_count: u64,
        interval: u64,
    ) -> bool {
        if interval == 0 || selected_count == 0 || !selected_count.is_multiple_of(interval) {
            return false;
        }

        if self
            .explored_at_selected
            .get(destination)
            .is_some_and(|last_selected| *last_selected == selected_count)
        {
            return false;
        }

        self.explored_at_selected
            .insert(*destination, selected_count);
        true
    }

    pub(crate) fn retain_destinations<F>(&mut self, mut keep: F)
    where
        F: FnMut(&NodeAddr) -> bool,
    {
        self.explored_at_selected
            .retain(|destination, _| keep(destination));
    }

    #[cfg(test)]
    pub(crate) fn contains_destination(&self, destination: &NodeAddr) -> bool {
        self.explored_at_selected.contains_key(destination)
    }
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
            route.score = (route.score + 1.0).clamp(MIN_ROUTE_SCORE, MAX_ROUTE_SCORE);
        } else {
            routes.push(LearnedRoute {
                next_hop,
                last_seen_ms: now_ms,
                expires_at_ms,
                successes: 1,
                failures: 0,
                score: 1.0,
                current_weight: 0.0,
                selected: 0,
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
            route.score = (route.score * 0.5).max(MIN_ROUTE_SCORE);
            route.current_weight = route.current_weight.min(0.0);
        }
    }

    pub(crate) fn select_next_hop<F>(
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

        let sendable = routes
            .iter()
            .enumerate()
            .filter(|(_, route)| can_send(&route.next_hop))
            .map(|(index, route)| (index, route.weight()))
            .collect::<Vec<_>>();
        if sendable.is_empty() {
            return None;
        }

        let total_weight = sendable.iter().map(|(_, weight)| *weight).sum::<f64>();
        let mut selected = sendable[0].0;

        for (index, weight) in sendable {
            routes[index].current_weight += weight;
            let selected_route = &routes[selected];
            let candidate = &routes[index];
            let better = candidate.current_weight > selected_route.current_weight
                || (candidate.current_weight == selected_route.current_weight
                    && compare_routes(candidate, selected_route).is_lt());
            if better {
                selected = index;
            }
        }

        routes[selected].current_weight -= total_weight;
        routes[selected].selected = routes[selected].selected.saturating_add(1);
        let next_hop = routes[selected].next_hop;
        Self::sort_and_truncate(routes, routes.len());
        Some(next_hop)
    }

    pub(crate) fn should_explore_fallback<F>(
        &mut self,
        destination: &NodeAddr,
        now_ms: u64,
        interval: u64,
        mut can_send: F,
    ) -> bool
    where
        F: FnMut(&NodeAddr) -> bool,
    {
        if interval == 0 {
            return false;
        }

        let Some(routes) = self.routes.get_mut(destination) else {
            return false;
        };
        routes.retain(|route| route.expires_at_ms > now_ms);

        if !routes.iter().any(|route| can_send(&route.next_hop)) {
            return false;
        }

        let selected = routes.iter().map(|route| route.selected).sum::<u64>();
        self.fallback_exploration
            .should_explore(destination, selected, interval)
    }

    pub(crate) fn purge_expired(&mut self, now_ms: u64) {
        self.routes.retain(|_, routes| {
            routes.retain(|route| route.expires_at_ms > now_ms);
            !routes.is_empty()
        });
        let live_destinations = self.routes.keys().copied().collect::<Vec<_>>();
        self.fallback_exploration
            .retain_destinations(|destination| live_destinations.contains(destination));
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
                        selected: route.selected,
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
    current_weight: f64,
    selected: u64,
}

impl LearnedRoute {
    fn weight(&self) -> f64 {
        self.score
            .clamp(MIN_ROUTE_SCORE, MAX_ROUTE_SCORE)
            .powf(1.5)
            .clamp(MIN_ROUTE_SCORE, MAX_ROUTE_WEIGHT)
    }
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
    pub selected: u64,
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
            table.select_next_hop(&dest, 1_300, |_| true),
            Some(fast),
            "route with stronger local evidence should win"
        );

        table.record_failure(&dest, &fast);
        table.record_failure(&dest, &fast);
        table.record_failure(&dest, &fast);

        assert_eq!(
            table.select_next_hop(&dest, 1_400, |_| true),
            Some(slow),
            "failures should demote a learned route"
        );
    }

    #[test]
    fn learned_routes_keep_lower_score_candidates_in_rotation() {
        let dest = addr(100);
        let slower = addr(1);
        let faster = addr(2);
        let mut table = LearnedRouteTable::default();

        table.learn(dest, slower, 1_000, 60, 4);
        for now in 1_001..1_005 {
            table.learn(dest, faster, now, 60, 4);
        }

        let mut selected = Vec::new();
        for now in 2_000..2_020 {
            selected.push(table.select_next_hop(&dest, now, |_| true));
        }

        let slower_count = selected.iter().filter(|hop| **hop == Some(slower)).count();
        let faster_count = selected.iter().filter(|hop| **hop == Some(faster)).count();

        assert!(
            slower_count > 0,
            "lower-score route should still receive exploratory traffic"
        );
        assert!(
            faster_count > slower_count,
            "higher-score route should carry most traffic"
        );
    }

    #[test]
    fn learned_route_fallback_exploration_owns_interval_dedup_and_expiry() {
        let dest = addr(100);
        let other = addr(200);
        let mut exploration = LearnedRouteFallbackExploration::default();

        assert!(!exploration.should_explore(&dest, 0, 2));
        assert!(!exploration.should_explore(&dest, 1, 2));
        assert!(exploration.should_explore(&dest, 2, 2));
        assert!(
            !exploration.should_explore(&dest, 2, 2),
            "one selected-count boundary should trigger fallback exploration at most once"
        );
        assert!(exploration.should_explore(&dest, 4, 2));
        assert!(
            !exploration.should_explore(&other, 4, 0),
            "disabled exploration interval should never mark a destination explored"
        );

        exploration.retain_destinations(|destination| *destination == other);
        assert!(
            !exploration.contains_destination(&dest),
            "exploration state for expired learned routes must be purged"
        );
        assert!(
            exploration.should_explore(&dest, 4, 2),
            "a relearned destination should not inherit stale exploration pacing"
        );
    }

    #[test]
    fn learned_routes_expire() {
        let dest = addr(100);
        let hop = addr(1);
        let mut table = LearnedRouteTable::default();

        table.learn(dest, hop, 1_000, 1, 4);
        assert_eq!(table.select_next_hop(&dest, 1_999, |_| true), Some(hop));
        assert_eq!(table.select_next_hop(&dest, 2_001, |_| true), None);
    }
}
