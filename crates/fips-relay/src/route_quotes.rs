//! Bounded adjacent price discovery following the native FIPS route planner.
//!
//! Quotes do not fund channels or authorize traffic. A controller must recheck
//! the route, verify funding, arrange its onward purchase and persist accepted
//! bindings before enabling forwarding. Pending offers may expire on restart;
//! accepted accounting belongs in the durable seller/buyer journals.

mod cache;
mod messages;
mod selection;
pub use messages::{QuoteRequest, QuoteResponse, RouteOffer};
pub use selection::PriceSelectionPolicy;
mod validation;
pub(crate) use validation::contract_from_offer;
#[cfg(test)]
use validation::validate_offer;

use crate::{
    control_transport::{ControlTransport, IncomingRequest, MAX_RECORD_BYTES},
    ledger::{BillingBasis, BytePrice, ChannelTerms, Contract},
};
use fips_core::{FipsEndpoint, Identity, NodeAddr, PeerIdentity};
use std::{
    collections::{BTreeMap, HashSet},
    sync::{Arc, Mutex},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::{
    sync::{Semaphore, mpsc},
    task::{JoinHandle, JoinSet},
};

pub const PRICE_BYTES: u64 = 1_024;
pub const MAX_PAID_HOPS: usize = 8;
const MAX_OFFERS: usize = 128;
const MAX_OFFERS_PER_BUYER: usize = 16;
const MAX_REQUEST_SECONDS: u64 = 30;

#[derive(Debug, Clone)]
pub struct QuotePolicy {
    pub destination_fees: BTreeMap<NodeAddr, u64>,
    pub billing: BillingBasis,
    pub mint_url: String,
    pub receiver_pubkey_hex: String,
    pub fee_msat_per_kib: u64,
    /// Also caps a source's requested route and a relay's total resale price.
    pub max_rate_msat_per_kib: u64,
    pub lifetime_secs: u64,
    pub max_units: u64,
    pub capacity_sat: u64,
    /// Fixed relationship allowance; quoting another destination cannot change it.
    pub grace_msat: u64,
}

#[derive(Debug, Clone)]
struct StoredOffer {
    offer: RouteOffer,
    downstream: Option<RouteOffer>,
    reusable: bool,
}

struct Offers {
    epoch: String,
    next_id: u64,
    pending: BTreeMap<String, StoredOffer>,
}

pub struct RouteQuotes {
    endpoint: Arc<FipsEndpoint>,
    client: Arc<cache::QuoteClient>,
    policy: Arc<QuotePolicy>,
    offers: Mutex<Offers>,
    pub(crate) free: Arc<crate::free_routes::FreeRoutes>,
    selection: Option<selection::PriceSelection>,
}

fn unix_now() -> Result<u64, String> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|t| t.as_secs())
        .map_err(|_| "invalid clock".into())
}

fn is_false(value: &bool) -> bool {
    !value
}

fn valid_key(key: &str) -> bool {
    key.len() == 66
        && (key.starts_with("02") || key.starts_with("03"))
        && key.bytes().all(|c| c.is_ascii_hexdigit())
}

impl RouteQuotes {
    pub fn new(
        endpoint: Arc<FipsEndpoint>,
        control: Arc<ControlTransport>,
        policy: QuotePolicy,
    ) -> Result<Self, String> {
        Self::with_free_routes(endpoint, control, policy, Arc::default())
    }

    pub fn with_free_routes(
        endpoint: Arc<FipsEndpoint>,
        control: Arc<ControlTransport>,
        policy: QuotePolicy,
        free: Arc<crate::free_routes::FreeRoutes>,
    ) -> Result<Self, String> {
        let cap = policy
            .capacity_sat
            .checked_mul(1_000)
            .ok_or("capacity overflow")?;
        if policy.destination_fees.len() > 64
            || policy.destination_fees.values().any(|p| {
                *p > policy.max_rate_msat_per_kib
                    || (*p == 0 && !policy.billing.has_free_handshakes())
            })
            || cap == 0
            || policy.grace_msat > cap
            || (policy.fee_msat_per_kib == 0 && !policy.billing.has_free_handshakes())
            || policy.fee_msat_per_kib > policy.max_rate_msat_per_kib
            || policy.lifetime_secs == 0
            || policy.lifetime_secs > 3_600
            || policy.max_units == 0
            || policy.mint_url.is_empty()
            || policy.mint_url.len() > 512
            || policy.mint_url.ends_with('/')
            || !valid_key(&policy.receiver_pubkey_hex)
            || (BytePrice {
                msat: policy.max_rate_msat_per_kib,
                per_bytes: PRICE_BYTES,
            })
            .amount_due_msat(policy.max_units)
            .is_none()
        {
            return Err("invalid local quote policy".into());
        }
        let policy = Arc::new(policy);
        let client = Arc::new(cache::QuoteClient::new(
            control,
            policy.clone(),
            *endpoint.node_addr(),
        ));
        Ok(Self {
            endpoint,
            client,
            policy,
            free,
            selection: None,
            offers: Mutex::new(Offers {
                epoch: Identity::generate().node_addr().to_string(),
                next_id: 1,
                pending: BTreeMap::new(),
            }),
        })
    }

    /// Request a fresh quote using native routing or the opted-in source selector.
    /// A direct final destination needs no paid forwarding quote.
    pub async fn request_route(&self, destination: PeerIdentity) -> Result<RouteOffer, String> {
        self.request_route_inner(destination, false).await
    }

    pub(crate) fn billing_basis(&self) -> BillingBasis {
        self.policy.billing
    }

    /// Check current native prices and paths while reusing unchanged offers.
    /// This does not accept a quote, fund a channel or authorize any traffic.
    pub async fn refresh_route(&self, destination: PeerIdentity) -> Result<RouteOffer, String> {
        self.request_route_inner(destination, true).await
    }

    pub(crate) fn max_rate_msat_per_kib(&self) -> u64 {
        self.policy.max_rate_msat_per_kib
    }

    pub(crate) fn invalidate_price(&self, provider: NodeAddr, destination: NodeAddr) {
        self.client.invalidate(provider, destination);
    }

    pub(crate) fn stop_reusing(&self, id: &str) -> Result<(), String> {
        if let Some(offer) = self
            .offers
            .lock()
            .map_err(|_| "quote state poisoned")?
            .pending
            .get_mut(id)
        {
            offer.reusable = false;
        }
        Ok(())
    }

    async fn request_route_inner(
        &self,
        destination: PeerIdentity,
        reuse_unchanged: bool,
    ) -> Result<RouteOffer, String> {
        if let Some(selection) = &self.selection {
            return self
                .select_priced_route(destination, selection, reuse_unchanged)
                .await;
        }
        let deadline_unix = unix_now()?.checked_add(20).ok_or("clock overflow")?;
        let provider = self.resolve(destination, None, deadline_unix).await?;
        if provider.node_addr() == destination.node_addr() {
            return Err("destination is a direct neighbor".into());
        }
        self.request_from(
            provider,
            QuoteRequest {
                destination,
                ancestors: vec![*self.endpoint.node_addr()],
                deadline_unix,
                reuse_unchanged,
                requested_max_units: None,
            },
        )
        .await
    }

    /// Renewal retains its provider and financial service. It must not invoke
    /// source discovery for an onward purchase made on behalf of transit.
    pub(crate) async fn renewal_offer(&self, old: &RouteOffer) -> Result<RouteOffer, String> {
        let provider = self.connected_provider(old.provider).await?;
        self.request_from(
            provider,
            QuoteRequest {
                destination: old.destination,
                ancestors: vec![*self.endpoint.node_addr()],
                deadline_unix: unix_now()?.checked_add(20).ok_or("clock overflow")?,
                reuse_unchanged: false,
                requested_max_units: old.trial.then_some(old.max_units),
            },
        )
        .await
    }

    async fn connected_provider(&self, provider: NodeAddr) -> Result<PeerIdentity, String> {
        let peer = self
            .endpoint
            .peers()
            .await
            .map_err(|e| e.to_string())?
            .into_iter()
            .find(|p| p.connected && p.node_addr == provider)
            .ok_or("selected provider is not connected")?;
        PeerIdentity::from_npub(&peer.npub).map_err(|e| e.to_string())
    }

    async fn resolve(
        &self,
        destination: PeerIdentity,
        previous: Option<NodeAddr>,
        deadline: u64,
    ) -> Result<PeerIdentity, String> {
        loop {
            if unix_now()? >= deadline {
                return Err("native route lookup deadline".into());
            }
            if let Some(next) = self
                .endpoint
                .resolve_next_hop(destination, previous)
                .await
                .map_err(|e| e.to_string())?
            {
                return Ok(next);
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }

    async fn request_from(
        &self,
        peer: PeerIdentity,
        request: QuoteRequest,
    ) -> Result<RouteOffer, String> {
        let offer = self.client.request(peer, &request).await?;
        self.free.accept(&offer)?;
        Ok(offer)
    }

    pub async fn handle(&self, peer: PeerIdentity, body: &[u8]) -> QuoteResponse {
        match self.handle_inner(peer, body).await {
            Ok(offer) => QuoteResponse::Offer {
                offer: Box::new(offer),
            },
            Err(_) => QuoteResponse::Rejected,
        }
    }

    async fn handle_inner(&self, peer: PeerIdentity, body: &[u8]) -> Result<RouteOffer, String> {
        if body.len() > MAX_RECORD_BYTES {
            return Err("oversized quote request".into());
        }
        let request: QuoteRequest =
            serde_json::from_slice(body).map_err(|_| "invalid quote request")?;
        let now = unix_now()?;
        let local = *self.endpoint.node_addr();
        if request.ancestors.is_empty()
            || request.ancestors.len() > MAX_PAID_HOPS
            || request.ancestors.last() != Some(peer.node_addr())
            || request.ancestors.contains(&local)
            || request.ancestors.contains(request.destination.node_addr())
            || request.ancestors.iter().collect::<HashSet<_>>().len() != request.ancestors.len()
            || request.destination.node_addr() == &local
            || request.deadline_unix <= now
            || request.deadline_unix > now.saturating_add(MAX_REQUEST_SECONDS)
            || request.requested_max_units == Some(0)
        {
            return Err("invalid quote path or deadline".into());
        }
        {
            let mut offers = self.offers.lock().map_err(|_| "quote state poisoned")?;
            offers
                .pending
                .retain(|_, stored| stored.offer.expires_unix > now);
            if !request.reuse_unchanged
                && (offers.pending.len() >= MAX_OFFERS
                    || offers
                        .pending
                        .values()
                        .filter(|v| v.offer.buyer == *peer.node_addr())
                        .count()
                        >= MAX_OFFERS_PER_BUYER)
            {
                return Err("offer capacity".into());
            }
        }
        let next = self
            .resolve(
                request.destination,
                Some(*peer.node_addr()),
                request.deadline_unix,
            )
            .await?;
        if request.ancestors.contains(next.node_addr()) {
            return Err("quote loop".into());
        }
        let downstream = if next.node_addr() == request.destination.node_addr() {
            None
        } else {
            if request.ancestors.len() == MAX_PAID_HOPS {
                return Err("quote hop limit".into());
            }
            let mut onward = request.clone();
            onward.ancestors.push(local);
            Some(self.request_from(next, onward).await?)
        };
        let rate = self
            .policy
            .destination_fees
            .get(request.destination.node_addr())
            .copied()
            .unwrap_or(self.policy.fee_msat_per_kib)
            .checked_add(downstream.as_ref().map_or(0, |d| d.price.msat))
            .ok_or("quote price overflow")?;
        if rate > self.policy.max_rate_msat_per_kib {
            return Err("route price limit".into());
        }
        let price = BytePrice {
            msat: rate,
            per_bytes: PRICE_BYTES,
        };
        let mut path = vec![local];
        if let Some(downstream) = &downstream {
            path.extend_from_slice(&downstream.path);
        } else {
            path.push(*request.destination.node_addr());
        }
        let expires_unix = now
            .checked_add(self.policy.lifetime_secs)
            .ok_or("expiry overflow")?
            .min(downstream.as_ref().map_or(u64::MAX, |d| d.expires_unix));
        let max_units = self
            .policy
            .max_units
            .min(downstream.as_ref().map_or(u64::MAX, |d| d.max_units))
            .min(request.requested_max_units.unwrap_or(u64::MAX));
        let mut offers = self.offers.lock().map_err(|_| "quote state poisoned")?;
        if request.reuse_unchanged {
            let reuse_until = now.saturating_add((self.policy.lifetime_secs / 4).max(1));
            if let Some(stored) = offers
                .pending
                .values()
                .filter(|s| s.reusable && self.free.can_reuse_offer(&s.offer))
                .find(|s| {
                    let o = &s.offer;
                    o.buyer == *peer.node_addr()
                        && o.destination == request.destination
                        && o.path == path
                        && o.price == price
                        && o.max_units == max_units
                        && o.trial == request.requested_max_units.is_some()
                        && o.expires_unix > reuse_until
                        && o.expires_unix <= expires_unix
                })
            {
                self.free.offer(&stored.offer)?;
                return Ok(stored.offer.clone());
            }
        }
        if offers.pending.len() >= MAX_OFFERS
            || offers
                .pending
                .values()
                .filter(|v| v.offer.buyer == *peer.node_addr())
                .count()
                >= MAX_OFFERS_PER_BUYER
        {
            return Err("offer capacity".into());
        }
        let id = format!("{}-{}", offers.epoch, offers.next_id);
        offers.next_id = offers
            .next_id
            .checked_add(1)
            .ok_or("quote sequence exhausted")?;
        let offer = RouteOffer {
            trial: request.requested_max_units.is_some(),
            billing: self.policy.billing,
            id: id.clone(),
            buyer: *peer.node_addr(),
            provider: local,
            destination: request.destination,
            next_hop: *next.node_addr(),
            path,
            price,
            expires_unix,
            max_units,
            mint_url: self.policy.mint_url.clone(),
            receiver_pubkey_hex: self.policy.receiver_pubkey_hex.clone(),
            capacity_sat: self.policy.capacity_sat,
            grace_msat: self.policy.grace_msat,
        };
        self.free.offer(&offer)?;
        offers.pending.insert(
            id,
            StoredOffer {
                offer: offer.clone(),
                downstream,
                reusable: true,
            },
        );
        Ok(offer)
    }

    pub fn retained_offer(&self, buyer: PeerIdentity, id: &str) -> Result<RouteOffer, String> {
        let now = unix_now()?;
        self.offers
            .lock()
            .map_err(|_| "quote state poisoned")?
            .pending
            .get(id)
            .filter(|s| s.offer.buyer == *buyer.node_addr() && s.offer.expires_unix > now)
            .map(|s| s.offer.clone())
            .ok_or("offer missing, expired or belongs to another buyer".into())
    }

    pub fn downstream_offer(
        &self,
        buyer: PeerIdentity,
        id: &str,
    ) -> Result<Option<RouteOffer>, String> {
        self.retained_offer(buyer, id)?;
        Ok(self
            .offers
            .lock()
            .map_err(|_| "quote state poisoned")?
            .pending
            .get(id)
            .ok_or("offer missing")?
            .downstream
            .clone())
    }

    pub async fn route_still_matches(&self, offer: &RouteOffer) -> Result<bool, String> {
        if !self
            .offers
            .lock()
            .map_err(|_| "quote state poisoned")?
            .pending
            .get(&offer.id)
            .is_some_and(|stored| &stored.offer == offer)
        {
            return Ok(false);
        }
        Ok(offer.provider == *self.endpoint.node_addr()
            && offer.expires_unix > unix_now()?
            && self
                .endpoint
                .resolve_next_hop(offer.destination, Some(offer.buyer))
                .await
                .map_err(|e| e.to_string())?
                .is_some_and(|p| p.node_addr() == &offer.next_hop))
    }

    /// Turn this provider's retained offer into an immutable accounting binding.
    /// This performs no funding, approval or activation. For an existing channel
    /// its original mint, grace, capacity and expiry remain unchanged.
    pub fn bind_offer(
        &self,
        buyer: PeerIdentity,
        id: &str,
        channel: &ChannelTerms,
    ) -> Result<Contract, String> {
        let offer = self.retained_offer(buyer, id)?;
        contract_from_offer(&offer, channel)
    }
}

pub struct QuoteServer {
    task: JoinHandle<()>,
}

impl QuoteServer {
    pub fn start(quotes: Arc<RouteQuotes>, mut incoming: mpsc::Receiver<IncomingRequest>) -> Self {
        let task = tokio::spawn(async move {
            let permits = Arc::new(Semaphore::new(8));
            let mut budget =
                crate::control_transport::AdmissionBudget::new(std::time::Instant::now());
            let mut jobs = JoinSet::new();
            loop {
                tokio::select! {
                    request = incoming.recv() => {
                        let Some(request) = request else { break; };
                        if !budget.allow(std::time::Instant::now()) {
                            let _ = request.respond.send(serde_json::to_vec(&QuoteResponse::Rejected).expect("serializable"));
                            continue;
                        }
                        let Ok(permit) = permits.clone().try_acquire_owned() else {
                            let _ = request.respond.send(serde_json::to_vec(&QuoteResponse::Rejected).expect("serializable"));
                            continue;
                        };
                        let quotes = quotes.clone();
                        jobs.spawn(async move {
                            let _permit = permit;
                            let response = tokio::time::timeout(Duration::from_secs(MAX_REQUEST_SECONDS), quotes.handle(request.peer, &request.body)).await.unwrap_or(QuoteResponse::Rejected);
                            let _ = request.respond.send(serde_json::to_vec(&response).expect("serializable quote"));
                        });
                    }
                    _ = jobs.join_next(), if !jobs.is_empty() => {}
                }
            }
        });
        Self { task }
    }
    pub async fn stop(mut self) {
        self.task.abort();
        let _ = (&mut self.task).await;
    }
}

impl Drop for QuoteServer {
    fn drop(&mut self) {
        self.task.abort();
    }
}

#[cfg(test)]
mod tests;
