//! Bounded adjacent price discovery following the native FIPS route planner.
//!
//! Quotes do not fund channels or authorize traffic. A controller must recheck
//! the route, verify funding, arrange its onward purchase and persist accepted
//! bindings before enabling forwarding. Pending offers may expire on restart;
//! accepted accounting belongs in the durable seller/buyer journals.

use crate::{
    control_transport::{ControlTransport, IncomingRequest, MAX_RECORD_BYTES},
    ledger::{BytePrice, ChannelTerms, Contract, node_addr},
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
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RouteOffer {
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
        crate::ledger::validate_channel(channel).map_err(|e| e.to_string())?;
        if channel.buyer != offer.buyer
            || channel.mint_url != offer.mint_url
            || channel.capacity_sat > offer.capacity_sat
            || channel.grace_msat > offer.grace_msat
            || channel.expires_unix <= unix_now()?
        {
            return Err("channel does not fit the offered terms".into());
        }
        // Same offer and channel produce the same bounded identifier on retries.
        use sha2::{Digest, Sha256};
        let mut digest = Sha256::new();
        digest.update(b"fips-relay/accepted-quote/1");
        digest.update((id.len() as u64).to_be_bytes());
        digest.update(id.as_bytes());
        digest.update(channel.id.as_bytes());
        Ok(Contract {
            id: format!("{:x}", digest.finalize()),
            channel_id: channel.id.clone(),
            destination: *offer.destination.node_addr(),
            next_hop: offer.next_hop,
            expires_unix: channel.expires_unix.min(offer.expires_unix),
            price: offer.price,
            max_units: offer.max_units,
        })
    }
}

fn validate_offer(
    policy: &QuotePolicy,
    local: NodeAddr,
    offer: &RouteOffer,
    peer: PeerIdentity,
    request: &QuoteRequest,
    now: u64,
) -> Result<(), String> {
    if offer.id.is_empty()
        || offer.id.len() > 128
        || offer.buyer != local
        || offer.provider != *peer.node_addr()
        || offer.destination.node_addr() != request.destination.node_addr()
        || offer.path.len() < 2
        || offer.path.len() + request.ancestors.len() > MAX_PAID_HOPS + 2
        || offer.path.first() != Some(&offer.provider)
        || offer.path.last() != Some(offer.destination.node_addr())
        || offer.path.get(1) != Some(&offer.next_hop)
        || offer.path.iter().collect::<HashSet<_>>().len() != offer.path.len()
        || offer.path.iter().any(|p| request.ancestors.contains(p))
        || offer.price.per_bytes != PRICE_BYTES
        || offer.price.msat == 0
        || offer.price.msat > policy.max_rate_msat_per_kib
        || offer.expires_unix <= now
        || offer.expires_unix > now.saturating_add(3_600)
        || offer.mint_url != policy.mint_url
        || !valid_key(&offer.receiver_pubkey_hex)
        || offer.max_units == 0
        || offer.price.amount_due_msat(offer.max_units).is_none()
        || offer.capacity_sat == 0
        || offer
            .capacity_sat
            .checked_mul(1_000)
            .is_none_or(|cap| offer.grace_msat > cap)
    {
        return Err("invalid or unacceptable downstream quote".into());
    }
    Ok(())
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
mod tests {
    use super::*;

    fn peer(n: u8) -> PeerIdentity {
        PeerIdentity::from_pubkey_full(Identity::from_secret_bytes(&[n; 32]).unwrap().pubkey_full())
    }

    #[test]
    fn downstream_quotes_cannot_change_identity_price_mint_or_loop_bounds() {
        let (buyer, provider, destination) = (peer(1), peer(2), peer(3));
        let policy = QuotePolicy {
            mint_url: "http://test.invalid".into(),
            receiver_pubkey_hex: "02".to_owned() + &"11".repeat(32),
            fee_msat_per_kib: 1_024,
            max_rate_msat_per_kib: 8_192,
            lifetime_secs: 120,
            max_units: 20_000,
            capacity_sat: 32,
            grace_msat: 16_384,
        };
        let request = QuoteRequest {
            destination,
            ancestors: vec![*buyer.node_addr()],
            deadline_unix: 110,
        };
        let offer = RouteOffer {
            id: "quote".into(),
            buyer: *buyer.node_addr(),
            provider: *provider.node_addr(),
            destination,
            next_hop: *destination.node_addr(),
            path: vec![*provider.node_addr(), *destination.node_addr()],
            price: BytePrice {
                msat: 1_024,
                per_bytes: PRICE_BYTES,
            },
            expires_unix: 200,
            max_units: 20_000,
            mint_url: policy.mint_url.clone(),
            receiver_pubkey_hex: policy.receiver_pubkey_hex.clone(),
            capacity_sat: 32,
            grace_msat: 16_384,
        };
        let check = |offer: &RouteOffer| {
            validate_offer(&policy, *buyer.node_addr(), offer, provider, &request, 100)
        };
        check(&offer).unwrap();
        let mutations: Vec<fn(&mut RouteOffer)> = vec![
            |o| o.provider = *peer(4).node_addr(),
            |o| o.buyer = *peer(4).node_addr(),
            |o| o.destination = peer(4),
            |o| o.next_hop = *peer(4).node_addr(),
            |o| o.path.clear(),
            |o| o.path.insert(1, o.provider),
            |o| {
                o.path.insert(1, o.buyer);
                o.next_hop = o.buyer;
            },
            |o| o.price.msat = 8_193,
            |o| o.price.msat = 0,
            |o| o.price.per_bytes = 1_025,
            |o| o.expires_unix = 100,
            |o| o.expires_unix = 3_701,
            |o| o.mint_url = "http://another.invalid".into(),
            |o| o.receiver_pubkey_hex = "invalid".into(),
            |o| o.capacity_sat = u64::MAX,
            |o| o.grace_msat = 32_001,
            |o| o.max_units = 0,
            |o| o.id = "x".repeat(129),
            |o| {
                o.path = (2..=11).map(|n| *peer(n).node_addr()).collect();
                o.path.push(*o.destination.node_addr());
                o.next_hop = o.path[1];
            },
        ];
        for (index, mutate) in mutations.into_iter().enumerate() {
            let mut invalid = offer.clone();
            mutate(&mut invalid);
            assert!(check(&invalid).is_err(), "invalid downstream quote {index}");
        }
        // Npub serialization is x-only. The authenticated identity is unchanged
        // when a locally known full key had different parity metadata.
        let mut canonical = offer;
        canonical.destination = PeerIdentity::from_npub(&destination.npub()).unwrap();
        check(&canonical).unwrap();
    }
}
