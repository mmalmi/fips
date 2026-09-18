//! Volatile, bounded forwarding permissions for explicitly quoted zero-price paths.
//! No payment channel, wallet, mint, financial credit or durable debt is created.
use crate::route_quotes::RouteOffer;
use fips_core::{NodeAddr, node::ForwardingRequest};
use serde::Serialize;
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::{Arc, Mutex},
    time::{SystemTime, UNIX_EPOCH},
};

const MAX_LEASES: usize = 128;
const MAX_PER_PEER: usize = 16;
mod bandwidth;
pub use bandwidth::FreeBandwidthPolicy;
#[cfg(test)]
mod tests;
type Key = (NodeAddr, NodeAddr);

#[derive(Debug)]
struct Lease {
    offer: RouteOffer,
    used: u64,
    quota_blocked: bool,
}
impl Lease {
    fn reserve<T>(
        &mut self,
        bytes: u64,
        now: u64,
        source_admission: bool,
        admit: impl FnOnce() -> Option<T>,
    ) -> Option<T> {
        if bytes == 0 || self.offer.expires_unix <= now {
            return None;
        }
        if !self.fits(bytes, now) {
            self.quota_blocked |= source_admission;
            return None;
        }
        let admitted = admit()?;
        self.used += bytes;
        Some(admitted)
    }
    fn fits(&self, bytes: u64, now: u64) -> bool {
        self.offer.expires_unix > now
            && self
                .used
                .checked_add(bytes)
                .is_some_and(|n| n <= self.offer.max_units)
    }
}

/// Superseded identities retain their original expiry, sharing the same limits
/// as active grants. Packet admission only looks up the active route.
#[derive(Debug, Default)]
struct LeaseBook {
    active: BTreeMap<Key, Lease>,
    retired: BTreeMap<(Key, String), u64>,
}

impl LeaseBook {
    fn get(&self, key: &Key) -> Option<&Lease> {
        self.active.get(key)
    }

    fn get_mut(&mut self, key: &Key) -> Option<&mut Lease> {
        self.active.get_mut(key)
    }

    fn len(&self) -> usize {
        self.active.len() + self.retired.len()
    }

    fn retire(&mut self, key: Key) {
        if let Some(old) = self.active.remove(&key) {
            self.retired
                .insert((key, old.offer.id), old.offer.expires_unix);
        }
    }

    fn install(&mut self, key: Key, offer: &RouteOffer, now: u64) -> Result<(), String> {
        self.active.retain(|_, l| l.offer.expires_unix > now);
        self.retired.retain(|_, expires| *expires > now);
        if self.retired.contains_key(&(key, offer.id.clone())) {
            return Err("free offer was superseded".into());
        }
        if let Some(old) = self.active.get(&key)
            && old.offer.id == offer.id
        {
            return if old.offer == *offer {
                Ok(())
            } else {
                Err("free offer identity changed".into())
            };
        }
        if offer.price.msat != 0 {
            self.retire(key);
            return Ok(());
        }
        if !offer.billing.has_free_handshakes() || offer.expires_unix <= now || offer.max_units == 0
        {
            return Err("invalid free route permission".into());
        }
        let retained_for_peer = self.active.keys().filter(|k| k.0 == key.0).count()
            + self.retired.keys().filter(|(k, _)| k.0 == key.0).count();
        if self.len() >= MAX_LEASES || retained_for_peer >= MAX_PER_PEER {
            return Err("free route capacity".into());
        }
        // Check capacity before replacing the current grant. A rejected offer
        // must not close the route or reset its remaining allowance.
        self.retire(key);
        self.active.insert(
            key,
            Lease {
                offer: offer.clone(),
                used: 0,
                quota_blocked: false,
            },
        );
        Ok(())
    }
}

#[derive(Debug, Default)]
struct State {
    incoming: LeaseBook,
    outgoing: LeaseBook,
    free_packets: u64,
    free_bytes: u64,
    activating_paid: BTreeSet<Key>,
    bandwidth: Option<crate::unpaid_budget::UnpaidBudget>,
}

#[derive(Debug, Default)]
pub struct FreeRoutes {
    state: Mutex<State>,
    accounts: Option<(
        Arc<crate::durable::DurableRelay>,
        Arc<crate::buyer::BuyerAuthorizer>,
    )>,
}

pub(crate) struct PaidRouteGuard<'a> {
    routes: &'a FreeRoutes,
    key: Key,
}
impl Drop for PaidRouteGuard<'_> {
    fn drop(&mut self) {
        self.routes
            .state
            .lock()
            .unwrap()
            .activating_paid
            .remove(&self.key);
    }
}

#[derive(Debug, Serialize)]
pub struct FreeRouteStats {
    /// Active and superseded incoming offers retained until expiry.
    pub incoming_leases: usize,
    /// Active and superseded outgoing offers retained until expiry.
    pub outgoing_leases: usize,
    pub admitted_packets: u64,
    pub admitted_session_bytes: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bandwidth: Option<crate::unpaid_budget::UnpaidStats>,
}

fn now() -> Option<u64> {
    Some(SystemTime::now().duration_since(UNIX_EPOCH).ok()?.as_secs())
}

impl FreeRoutes {
    /// Set runtime limits before publishing the shared free-route book.
    pub fn with_bandwidth(mut self, policy: FreeBandwidthPolicy) -> Result<Self, String> {
        policy.validate()?;
        self.state
            .get_mut()
            .map_err(|_| "free routes poisoned")?
            .bandwidth = Some(crate::unpaid_budget::UnpaidBudget::for_free(&policy));
        Ok(self)
    }

    pub(crate) fn for_accounts(
        seller: Arc<crate::durable::DurableRelay>,
        buyer: Arc<crate::buyer::BuyerAuthorizer>,
    ) -> Self {
        Self {
            accounts: Some((seller, buyer)),
            ..Self::default()
        }
    }

    pub(crate) fn paid_guard(&self, offer: &RouteOffer) -> Result<PaidRouteGuard<'_>, String> {
        let key = (offer.buyer, *offer.destination.node_addr());
        let mut state = self.state.lock().map_err(|_| "free routes poisoned")?;
        if state
            .incoming
            .get(&key)
            .is_some_and(|l| l.offer.expires_unix > now().unwrap_or(0))
            || state.activating_paid.len() >= MAX_LEASES
            || !state.activating_paid.insert(key)
        {
            return Err("free permission or paid activation already owns this route".into());
        }
        Ok(PaidRouteGuard { routes: self, key })
    }

    /// Cached zero-price offers may only reuse the current grant. Paid offers
    /// retain their existing quote reuse and financial validation rules.
    pub(crate) fn can_reuse_offer(&self, offer: &RouteOffer) -> bool {
        if offer.price.msat != 0 {
            return true;
        }
        let key = (offer.buyer, *offer.destination.node_addr());
        self.state.lock().is_ok_and(|state| {
            state
                .incoming
                .get(&key)
                .is_some_and(|lease| lease.offer == *offer)
        })
    }

    /// Remaining quota for the exact current outgoing grant. The caller checks
    /// expiry separately; inspecting an expired grant does not remove it.
    pub(crate) fn remaining_units(&self, offer: &RouteOffer) -> Option<u64> {
        let key = (offer.provider, *offer.destination.node_addr());
        let state = self.state.lock().ok()?;
        let lease = state.outgoing.get(&key).filter(|l| l.offer == *offer)?;
        lease.offer.max_units.checked_sub(lease.used)
    }

    /// A failed real reservation, rather than zero remaining bytes: a positive
    /// remainder may still be too small for the source's next packet.
    pub(crate) fn quota_blocked(&self, offer: &RouteOffer) -> Result<Option<bool>, String> {
        let state = self.state.lock().map_err(|_| "free routes poisoned")?;
        Ok(state
            .outgoing
            .get(&(offer.provider, *offer.destination.node_addr()))
            .filter(|lease| lease.offer == *offer)
            .map(|lease| lease.quota_blocked))
    }

    /// Called only for a locally generated offer under explicit operator pricing.
    pub(crate) fn offer(&self, offer: &RouteOffer) -> Result<(), String> {
        let now = now().ok_or("invalid clock")?;
        let key = (offer.buyer, *offer.destination.node_addr());
        let mut state = self.state.lock().map_err(|_| "free routes poisoned")?;
        if offer.price.msat == 0
            && (state.activating_paid.contains(&key)
                || self
                    .accounts
                    .as_ref()
                    .is_some_and(|(seller, _)| seller.has_active_route(key.0, key.1, now)))
        {
            return Err("close the active paid route before offering free service".into());
        }
        state.incoming.install(key, offer, now)
    }

    /// Called only after the common authenticated quote validation succeeds.
    pub(crate) fn accept(&self, offer: &RouteOffer) -> Result<(), String> {
        let now = now().ok_or("invalid clock")?;
        let key = (offer.provider, *offer.destination.node_addr());
        if offer.price.msat == 0
            && self
                .accounts
                .as_ref()
                .is_some_and(|(_, buyer)| buyer.has_active_route(key.0, key.1, now))
        {
            return Err("close the active paid purchase before selecting free service".into());
        }
        self.state
            .lock()
            .map_err(|_| "free routes poisoned")?
            .outgoing
            .install(key, offer, now)
    }

    pub(crate) fn admit(&self, request: &ForwardingRequest<'_>) -> bool {
        self.admit_at(request, now().unwrap_or(u64::MAX))
    }

    fn admit_at(&self, request: &ForwardingRequest<'_>, now: u64) -> bool {
        let Ok(bytes) = u64::try_from(request.session_payload.len()) else {
            return false;
        };
        let Ok(mut state) = self.state.lock() else {
            return false;
        };
        let incoming = (*request.ingress.node_addr(), request.destination);
        let outgoing = (request.next_hop, request.destination);
        if bytes == 0
            || state
                .incoming
                .get(&incoming)
                .is_none_or(|l| l.offer.next_hop != request.next_hop || !l.fits(bytes, now))
        {
            return false;
        }
        if request.next_hop != request.destination
            && state
                .outgoing
                .get(&outgoing)
                .is_none_or(|l| !l.fits(bytes, now))
        {
            return false;
        }
        // Permissions, rate credit and both byte quotas commit under one lock.
        // A missing continuation cannot consume a neighbor's free bandwidth.
        if state
            .bandwidth
            .as_mut()
            .is_some_and(|budget| !budget.admit(incoming.0, request.session_payload.len()))
        {
            return false;
        }
        if request.next_hop != request.destination {
            state.outgoing.get_mut(&outgoing).unwrap().used += bytes;
        }
        state.incoming.get_mut(&incoming).unwrap().used += bytes;
        state.free_packets = state.free_packets.saturating_add(1);
        state.free_bytes = state.free_bytes.saturating_add(bytes);
        true
    }

    /// Reserve the free continuation together with upstream paid admission.
    /// Rejected upstream traffic cannot burn another customer's free allowance.
    pub(crate) fn onward<T>(
        &self,
        next: NodeAddr,
        destination: NodeAddr,
        bytes: usize,
        admit: impl FnOnce() -> Option<T>,
    ) -> Option<T> {
        let bytes = u64::try_from(bytes).ok().filter(|n| *n > 0)?;
        let now = now()?;
        let mut state = self.state.lock().ok()?;
        let lease = state.outgoing.get_mut(&(next, destination))?;
        lease.reserve(bytes, now, false, admit)
    }

    /// None means no free permission; Some(false) is a known local denial and
    /// must not fall through to untracked sending or a paid accounting record.
    pub(crate) fn prepare_onward(
        &self,
        next: NodeAddr,
        destination: NodeAddr,
        bytes: usize,
    ) -> Option<bool> {
        let Ok(bytes) = u64::try_from(bytes) else {
            return Some(false);
        };
        let Some(now) = now() else {
            return Some(false);
        };
        let Ok(mut state) = self.state.lock() else {
            return Some(false);
        };
        state
            .outgoing
            .get_mut(&(next, destination))
            .map(|lease| lease.reserve(bytes, now, true, || Some(())).is_some())
    }

    pub fn stats(&self) -> FreeRouteStats {
        let state = self.state.lock().unwrap();
        FreeRouteStats {
            incoming_leases: state.incoming.len(),
            outgoing_leases: state.outgoing.len(),
            admitted_packets: state.free_packets,
            admitted_session_bytes: state.free_bytes,
            bandwidth: state.bandwidth.as_ref().map(|budget| budget.stats()),
        }
    }
}
