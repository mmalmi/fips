//! Bounded waiting for the next existing per-target discovery forwarding slot.
use super::{LookupForwardOutcome, LookupRequest, Node, NodeAddr};
use crate::time::{Instant, instant_now};
use crate::transport::LinkId;
use std::collections::HashMap;
use std::time::Duration;

const MAX_WAITERS: usize = 256;
const MAX_BYTES: usize = 64 * 1024;
const MAX_PEER_WAITERS: usize = 64;
const MAX_PEER_BYTES: usize = 16 * 1024;
const MAX_DISPATCH_PER_TURN: usize = 16;

struct DeferredForward {
    from: NodeAddr,
    link_id: LinkId,
    authenticated_at: u64,
    received_ms: u64,
    admission_generation: u64,
    request_id: u64,
    // Store exactly the encoded bytes, not spare coordinate Vec capacity.
    encoded: Box<[u8]>,
    due: Instant,
    expires: Instant,
}

#[derive(Default)]
pub(in crate::node) struct DeferredDiscoveryForwards {
    entries: HashMap<NodeAddr, DeferredForward>,
    bytes: usize,
    next_due: Option<Instant>,
}

impl DeferredDiscoveryForwards {
    fn insert(&mut self, target: NodeAddr, entry: DeferredForward) -> bool {
        if self.entries.contains_key(&target)
            || self.entries.len() >= MAX_WAITERS
            || entry.encoded.len() > MAX_BYTES.saturating_sub(self.bytes)
        {
            return false;
        }
        let (count, bytes) = self
            .entries
            .values()
            .filter(|old| old.from == entry.from)
            .fold((0, 0), |(count, bytes), old| {
                (count + 1, bytes + old.encoded.len())
            });
        if count >= MAX_PEER_WAITERS || entry.encoded.len() > MAX_PEER_BYTES.saturating_sub(bytes) {
            return false;
        }
        self.next_due = Some(self.next_due.map_or(entry.due, |old| old.min(entry.due)));
        self.bytes += entry.encoded.len();
        self.entries.insert(target, entry);
        true
    }

    fn take_due(&mut self, target: &NodeAddr, now: Instant) -> Option<DeferredForward> {
        if self.entries.get(target).is_none_or(|entry| entry.due > now) {
            return None;
        }
        let entry = self.entries.remove(target)?;
        self.bytes -= entry.encoded.len();
        self.next_due = self.entries.values().map(|entry| entry.due).min();
        Some(entry)
    }
}

impl Node {
    pub(in crate::node) fn discovery_work_deadline_ms(&self) -> Option<u64> {
        let deferred = self.deferred_discovery_forwards.next_due.map(|due| {
            let remaining = due.saturating_duration_since(instant_now());
            // Round upward so a sub-millisecond remainder cannot busy-wake.
            let millis = remaining
                .as_nanos()
                .div_ceil(1_000_000)
                .min(u128::from(u64::MAX)) as u64;
            Self::now_ms().saturating_add(millis)
        });
        self.pending_lookup_deadline_ms()
            .into_iter()
            .chain(deferred)
            .min()
    }

    pub(in crate::node) async fn check_discovery_work(&mut self, now_ms: u64) {
        // Keep local retries ahead of externally admitted sends under the
        // shared RX-loop timebox. A slow transit must not steal their turn.
        self.check_pending_lookups(now_ms).await;
        let now = instant_now();
        let due: Vec<_> = self
            .deferred_discovery_forwards
            .entries
            .iter()
            .filter_map(|(target, entry)| (entry.due <= now).then_some(*target))
            .take(MAX_DISPATCH_PER_TURN)
            .collect();
        for target in due {
            self.forward_due_lookup_for_target(&target).await;
        }
    }

    pub(super) fn defer_lookup_forward(&mut self, from: &NodeAddr, request: &LookupRequest) {
        if self
            .deferred_discovery_forwards
            .entries
            .contains_key(&request.target)
        {
            return;
        }
        let Some(due) = self
            .discovery_forward_limiter
            .deferred_deadline(from, &request.target)
        else {
            return;
        };
        let Some(peer) = self
            .get_peer(from)
            .filter(|peer| peer.is_healthy() && peer.can_send())
        else {
            return;
        };
        let Some(recent) = self.recent_requests.get(&request.request_id) else {
            return;
        };
        let now_ms = Self::now_ms();
        let expiry_ms = self
            .config
            .node
            .discovery
            .recent_expiry_secs
            .saturating_mul(1000);
        if recent.from_peer != *from
            || recent.target != request.target
            || recent.response_forwarded
            || recent.is_expired(now_ms, expiry_ms)
        {
            return;
        }
        let expires_in = recent
            .timestamp_ms
            .saturating_add(expiry_ms)
            .saturating_sub(now_ms);
        let Some(expiry) = instant_now().checked_add(Duration::from_millis(expires_in)) else {
            return;
        };
        let entry = DeferredForward {
            from: *from,
            link_id: peer.link_id(),
            authenticated_at: peer.authenticated_at(),
            received_ms: recent.timestamp_ms,
            admission_generation: recent.admission_generation,
            request_id: request.request_id,
            encoded: request.encode().into_boxed_slice(),
            due: due.min(expiry),
            expires: expiry,
        };
        if self
            .deferred_discovery_forwards
            .insert(request.target, entry)
        {
            self.recent_requests.protect(request.request_id);
        }
    }

    pub(super) async fn forward_due_lookup_for_target(&mut self, target: &NodeAddr) {
        let Some(entry) = self
            .deferred_discovery_forwards
            .take_due(target, instant_now())
        else {
            return;
        };
        let expiry_ms = self
            .config
            .node
            .discovery
            .recent_expiry_secs
            .saturating_mul(1000);
        let owned = self
            .recent_requests
            .get(&entry.request_id)
            .is_some_and(|recent| {
                recent.from_peer == entry.from
                    && recent.target == *target
                    && recent.timestamp_ms == entry.received_ms
                    && recent.admission_generation == entry.admission_generation
                    && !recent.response_forwarded
                    && Self::now_ms().saturating_sub(recent.timestamp_ms) < expiry_ms
            });
        let live = self.get_peer(&entry.from).is_some_and(|peer| {
            peer.link_id() == entry.link_id
                && peer.authenticated_at() == entry.authenticated_at
                && peer.is_healthy()
                && peer.can_send()
        });
        if !owned || !live || instant_now() >= entry.expires {
            return;
        }
        let Ok(request) = LookupRequest::decode(&entry.encoded[1..]) else {
            return;
        };
        // Remove before awaiting. Dispatch reserves the normal target slot and
        // ingress token before its first transport await; cancellation cannot
        // retry this reservation or remove any untouched waiting request.
        match self
            .forward_ready_lookup_request(&entry.from, request, false)
            .await
        {
            LookupForwardOutcome::Forwarded => self.stats_mut().discovery.req_forwarded += 1,
            LookupForwardOutcome::RateLimited => {
                self.stats_mut().discovery.req_forward_rate_limited += 1
            }
            LookupForwardOutcome::NoPeer => {
                self.recent_requests.remove(entry.request_id);
            }
            LookupForwardOutcome::SendFailed => {}
        }
    }
}

#[cfg(test)]
mod tests;
