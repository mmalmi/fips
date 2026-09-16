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
#[cfg(test)]
mod tests;
type Key = (NodeAddr, NodeAddr);

#[derive(Debug)]
struct Lease {
    offer: RouteOffer,
    used: u64,
}
impl Lease {
    fn fits(&self, bytes: u64, now: u64) -> bool {
        self.offer.expires_unix > now
            && self
                .used
                .checked_add(bytes)
                .is_some_and(|n| n <= self.offer.max_units)
    }
}

#[derive(Debug, Default)]
struct State {
    incoming: BTreeMap<Key, Lease>,
    outgoing: BTreeMap<Key, Lease>,
    free_packets: u64,
    free_bytes: u64,
    activating_paid: BTreeSet<Key>,
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
    pub incoming_leases: usize,
    pub outgoing_leases: usize,
    pub admitted_packets: u64,
    pub admitted_session_bytes: u64,
}

fn now() -> Option<u64> {
    Some(SystemTime::now().duration_since(UNIX_EPOCH).ok()?.as_secs())
}

impl FreeRoutes {
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
    fn install(
        leases: &mut BTreeMap<Key, Lease>,
        key: Key,
        offer: &RouteOffer,
        now: u64,
    ) -> Result<(), String> {
        leases.retain(|_, l| l.offer.expires_unix > now);
        if offer.price.msat != 0 {
            leases.remove(&key);
            return Ok(());
        }
        if !offer.billing.has_free_handshakes() || offer.expires_unix <= now || offer.max_units == 0
        {
            return Err("invalid free route permission".into());
        }
        if let Some(old) = leases.get(&key)
            && old.offer.id == offer.id
        {
            return if old.offer == *offer {
                Ok(())
            } else {
                Err("free offer identity changed".into())
            };
        }
        if !leases.contains_key(&key)
            && (leases.len() >= MAX_LEASES
                || leases.keys().filter(|(peer, _)| peer == &key.0).count() >= MAX_PER_PEER)
        {
            return Err("free route capacity".into());
        }
        leases.insert(
            key,
            Lease {
                offer: offer.clone(),
                used: 0,
            },
        );
        Ok(())
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
        Self::install(&mut state.incoming, key, offer, now)
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
        Self::install(
            &mut self
                .state
                .lock()
                .map_err(|_| "free routes poisoned")?
                .outgoing,
            key,
            offer,
            now,
        )
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
        if request.next_hop != request.destination {
            let Some(next) = state
                .outgoing
                .get_mut(&outgoing)
                .filter(|l| l.fits(bytes, now))
            else {
                return false;
            };
            next.used += bytes;
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
        let lease = state
            .outgoing
            .get_mut(&(next, destination))
            .filter(|l| l.fits(bytes, now))?;
        let admitted = admit()?;
        lease.used += bytes;
        Some(admitted)
    }

    pub fn stats(&self) -> FreeRouteStats {
        let state = self.state.lock().unwrap();
        FreeRouteStats {
            incoming_leases: state.incoming.len(),
            outgoing_leases: state.outgoing.len(),
            admitted_packets: state.free_packets,
            admitted_session_bytes: state.free_bytes,
        }
    }
}
