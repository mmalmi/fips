//! Bounded adjacent price discovery following the native FIPS route planner.
//!
//! Quotes do not fund channels or authorize traffic. A controller must recheck
//! the route, verify funding, arrange its onward purchase and persist accepted
//! bindings before enabling forwarding. Pending offers may expire on restart;
//! accepted accounting belongs in the durable seller/buyer journals.

mod validation;
pub(crate) use validation::contract_from_offer;
use validation::validate_offer;

use crate::{
    control_transport::{ControlTransport, IncomingRequest, MAX_RECORD_BYTES},
    ledger::{BillingBasis, BytePrice, ChannelTerms, Contract, node_addr},
};
use fips_core::{FipsEndpoint, Identity, NodeAddr, PeerIdentity};
use serde::{Deserialize, Serialize};
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

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QuoteRequest {
    #[serde(with = "peer_identity")]
    pub destination: PeerIdentity,
    #[serde(with = "node_addrs")]
    pub ancestors: Vec<NodeAddr>,
    /// One deadline for the whole recursive request, not a new timeout per hop.
    pub deadline_unix: u64,
    /// Monitoring can reuse an unchanged unexpired offer without growing history.
    #[serde(default, skip_serializing_if = "is_false")]
    pub reuse_unchanged: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RouteOffer {
    #[serde(default, skip_serializing_if = "BillingBasis::is_legacy")]
    pub billing: BillingBasis,
    pub id: String,
    #[serde(with = "node_addr")]
    pub buyer: NodeAddr,
    #[serde(with = "node_addr")]
    pub provider: NodeAddr,
    #[serde(with = "peer_identity")]
    pub destination: PeerIdentity,
    #[serde(with = "node_addr")]
    pub next_hop: NodeAddr,
    /// Provider through final destination; descriptive, not a delivery proof.
    #[serde(with = "node_addrs")]
    pub path: Vec<NodeAddr>,
    pub price: BytePrice,
    pub expires_unix: u64,
    pub max_units: u64,
    pub mint_url: String,
    pub receiver_pubkey_hex: String,
    pub capacity_sat: u64,
    pub grace_msat: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum QuoteResponse {
    Offer { offer: Box<RouteOffer> },
    Rejected,
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
    control: Arc<ControlTransport>,
    policy: QuotePolicy,
    offers: Mutex<Offers>,
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
        let cap = policy
            .capacity_sat
            .checked_mul(1_000)
            .ok_or("capacity overflow")?;
        if cap == 0
            || policy.grace_msat > cap
            || policy.fee_msat_per_kib == 0
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
        Ok(Self {
            endpoint,
            control,
            policy,
            offers: Mutex::new(Offers {
                epoch: Identity::generate().node_addr().to_string(),
                next_id: 1,
                pending: BTreeMap::new(),
            }),
        })
    }

    /// Ask the native source planner, then buy a quote from its next neighbor.
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
            },
        )
        .await
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
        let seconds = request
            .deadline_unix
            .checked_sub(unix_now()?)
            .filter(|n| *n > 0 && *n <= MAX_REQUEST_SECONDS)
            .ok_or("quote deadline")?;
        let bytes = tokio::time::timeout(
            Duration::from_secs(seconds),
            self.control.request(
                peer,
                serde_json::to_vec(&request).map_err(|e| e.to_string())?,
            ),
        )
        .await
        .map_err(|_| "quote deadline")??;
        let reply: QuoteResponse =
            serde_json::from_slice(&bytes).map_err(|_| "invalid quote response")?;
        let QuoteResponse::Offer { offer } = reply else {
            return Err("provider rejected quote request".into());
        };
        validate_offer(
            &self.policy,
            *self.endpoint.node_addr(),
            &offer,
            peer,
            &request,
            unix_now()?,
        )?;
        Ok(*offer)
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
            .fee_msat_per_kib
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
            .min(downstream.as_ref().map_or(u64::MAX, |d| d.max_units));
        let mut offers = self.offers.lock().map_err(|_| "quote state poisoned")?;
        if request.reuse_unchanged {
            let reuse_until = now.saturating_add((self.policy.lifetime_secs / 4).max(1));
            if let Some(stored) = offers.pending.values().filter(|s| s.reusable).find(|s| {
                let o = &s.offer;
                o.buyer == *peer.node_addr()
                    && o.destination == request.destination
                    && o.path == path
                    && o.price == price
                    && o.max_units == max_units
                    && o.expires_unix > reuse_until
                    && o.expires_unix <= expires_unix
            }) {
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
            let mut jobs = JoinSet::new();
            loop {
                tokio::select! {
                    request = incoming.recv() => {
                        let Some(request) = request else { break; };
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

mod node_addrs {
    use super::*;
    pub fn serialize<S: serde::Serializer>(
        addresses: &[NodeAddr],
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        addresses
            .iter()
            .map(|a| *a.as_bytes())
            .collect::<Vec<_>>()
            .serialize(serializer)
    }
    pub fn deserialize<'de, D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Vec<NodeAddr>, D::Error> {
        Vec::<[u8; 16]>::deserialize(deserializer)
            .map(|v| v.into_iter().map(NodeAddr::from_bytes).collect())
    }
}

mod peer_identity {
    use super::*;
    pub fn serialize<S: serde::Serializer>(
        peer: &PeerIdentity,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        peer.npub().serialize(serializer)
    }
    pub fn deserialize<'de, D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> Result<PeerIdentity, D::Error> {
        let value = String::deserialize(deserializer)?;
        PeerIdentity::from_npub(&value).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests;
