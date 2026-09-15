//! Automatic adjacent purchases with durable funding/acceptance intent.
//!
//! Configure a test wallet, mint and finite capital policy explicitly. Quotes
//! alone never authorize spending. An application buys a route, or a provider
//! verifies upstream funding before buying the retained onward offer. Network
//! awaits never hold the wallet or journal lock, preventing cross-route deadlock.

use crate::{
    buyer::BuyerAuthorizer,
    control_transport::{ControlTransport, IncomingRequest, MAX_RECORD_BYTES},
    durable::{DurableRelay, MAX_JOURNAL_BYTES, acquire_owner, write_private_journal},
    ledger::{ChannelTerms, Contract, node_addr, validate_channel, validate_contract},
    payment_control::{PaymentControl, PaymentRequest, PaymentResponse},
    route_quotes::{RouteOffer, RouteQuotes, contract_from_offer},
};
use cashu_service::{
    CashuSpilmanPayment, FileSpilmanPaymentReceiver, FileSpilmanPaymentSigner,
    StreamingRouteOpenCashuSpilmanChannelFromWalletRequest,
    open_streaming_route_cashu_spilman_channel_from_wallet,
};
use fips_core::{FipsEndpoint, Identity, NodeAddr, PeerIdentity};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, HashSet},
    fs::File,
    io::Read,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::{
    sync::{Mutex as AsyncMutex, Semaphore, mpsc, watch},
    task::{JoinHandle, JoinSet},
};

const MAX_CHANNELS: usize = 16;
const MAX_ROUTES: usize = 32;

#[path = "controller_settlement.rs"]
mod settlement;
pub use settlement::SettlementReport;
use settlement::{BuyerSettlement, SellerSettlement};

#[path = "controller_renewal.rs"]
mod renewal;
use renewal::Renewal;
pub use renewal::RenewalPolicy;

#[path = "controller_routes.rs"]
mod routes;
use routes::RouteChange;

#[path = "controller_refresh.rs"]
mod refresh;
pub use refresh::WatchedRoute;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ControllerPolicy {
    pub mint_url: String,
    pub channel_capacity_sat: u64,
    /// Includes unresolved funding intents. Only confirmed settlement may release
    /// locked capacity, after the buyer's mint refund recovery completes.
    pub max_locked_sat: u64,
    pub channel_lifetime_secs: u64,
    pub renewal: Option<RenewalPolicy>,
}

#[derive(Clone)]
pub struct ControllerServices {
    pub endpoint: Arc<FipsEndpoint>,
    pub quotes: Arc<RouteQuotes>,
    pub acceptance: Arc<ControlTransport>,
    pub payments: Arc<ControlTransport>,
    pub payment_control: Arc<PaymentControl<FileSpilmanPaymentReceiver>>,
    pub seller: Arc<DurableRelay>,
    pub buyer: Arc<BuyerAuthorizer>,
    pub wallet_directory: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Purchase {
    #[serde(with = "node_addr")]
    pub provider: NodeAddr,
    pub channel: ChannelTerms,
    pub contract: Contract,
}

#[derive(Clone, Serialize, Deserialize)]
struct Funded {
    terms: ChannelTerms,
    opening: CashuSpilmanPayment,
}

#[derive(Clone, Serialize, Deserialize)]
struct FundingIntent {
    id: String,
    #[serde(with = "node_addr")]
    provider: NodeAddr,
    receiver_pubkey_hex: String,
    capacity_sat: u64,
    grace_msat: u64,
    created_unix: u64,
    expires_unix: u64,
    funded: Option<Funded>,
}

#[derive(Clone, Serialize, Deserialize)]
struct Outgoing {
    offer: RouteOffer,
    funding_id: String,
    purchase: Purchase,
    accepted: bool,
    retired: bool,
}

#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
enum Phase {
    Prepared,
    Active,
    Stopped,
}

#[derive(Clone, Serialize, Deserialize)]
struct Incoming {
    offer: RouteOffer,
    downstream: Option<RouteOffer>,
    channel: ChannelTerms,
    contract: Contract,
    verified_paid_msat: u64,
    phase: Phase,
    #[serde(default)]
    replaces: Option<String>,
}

#[derive(Clone, Serialize, Deserialize)]
struct Journal {
    version: u16,
    #[serde(with = "node_addr")]
    local: NodeAddr,
    policy: ControllerPolicy,
    epoch: String,
    next_funding: u64,
    selling_stopped: bool,
    funding: BTreeMap<String, FundingIntent>,
    /// Authorized offers retained before any wallet operation, including a
    /// source crash before a funded channel can be attached to its contract.
    requested: BTreeMap<String, RouteOffer>,
    outgoing: BTreeMap<String, Outgoing>,
    incoming: BTreeMap<String, Incoming>,
    buyer_settlements: BTreeMap<String, BuyerSettlement>,
    seller_settlements: BTreeMap<String, SellerSettlement>,
    renewals: BTreeMap<String, Renewal>,
    renewals_paused: bool,
    #[serde(default)]
    route_changes: BTreeMap<String, RouteChange>,
    #[serde(default)]
    watched_routes: BTreeMap<String, WatchedRoute>,
}

struct Store {
    directory: PathBuf,
    journal: Journal,
    ready: bool,
    _owner: File,
}

impl Store {
    fn change<T>(
        &mut self,
        job: impl FnOnce(&mut Journal) -> Result<T, String>,
    ) -> Result<T, String> {
        if !self.ready {
            return Err("controller journal suspended".into());
        }
        let mut candidate = self.journal.clone();
        let result = job(&mut candidate)?;
        self.journal = candidate;
        self.persist()?;
        Ok(result)
    }

    fn persist(&mut self) -> Result<(), String> {
        self.ready = false;
        let bytes = serde_json::to_vec(&self.journal).map_err(|e| e.to_string())?;
        write_private_journal(&self.directory, "controller.json", &bytes)
            .map_err(|e| e.to_string())?;
        self.ready = true;
        Ok(())
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum ControllerRequest {
    Accept {
        offer_id: String,
        channel: ChannelTerms,
        payment: Box<CashuSpilmanPayment>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        replaces: Option<String>,
    },
    StopRoute {
        contract_id: String,
    },
    Seal {
        channel_id: String,
    },
    Settle {
        channel_id: String,
        payment: Box<CashuSpilmanPayment>,
    },
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum ControllerResponse {
    Accepted {
        purchase: Box<Purchase>,
    },
    Sealed {
        channel_id: String,
        usage: crate::ledger::ChannelUsage,
    },
    Settled {
        report: SettlementReport,
    },
    RouteStopped {
        contract_id: String,
    },
    Pending,
    Rejected,
}

pub struct Controller {
    services: ControllerServices,
    policy: ControllerPolicy,
    store: Arc<Mutex<Store>>,
    wallet: Arc<AsyncMutex<()>>,
    maintenance: AsyncMutex<()>,
    renewal_work: AsyncMutex<()>,
    route_work: AsyncMutex<()>,
    refresh_work: AsyncMutex<()>,
    refresh_checks: Mutex<BTreeMap<String, tokio::time::Instant>>,
    accepting: Mutex<HashSet<String>>,
    last_error: Mutex<Option<String>>,
}

fn now() -> Result<u64, String> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|t| t.as_secs())
        .map_err(|_| "invalid clock".into())
}

async fn blocking<T: Send + 'static>(
    job: impl FnOnce() -> Result<T, String> + Send + 'static,
) -> Result<T, String> {
    tokio::task::spawn_blocking(job)
        .await
        .map_err(|e| e.to_string())?
}

struct AcceptGuard<'a> {
    claims: &'a Mutex<HashSet<String>>,
    id: String,
}
impl Drop for AcceptGuard<'_> {
    fn drop(&mut self) {
        self.claims.lock().unwrap().remove(&self.id);
    }
}

impl Controller {
    /// Creation/loading performs synchronous local I/O; run on a startup worker.
    pub fn create(
        directory: &Path,
        policy: ControllerPolicy,
        services: ControllerServices,
    ) -> Result<Self, String> {
        Self::validate_policy(&policy)?;
        let owner = acquire_owner(directory).map_err(|e| e.to_string())?;
        if directory
            .join("controller.json")
            .try_exists()
            .map_err(|e| e.to_string())?
        {
            return Err("controller already initialized".into());
        }
        let mut store = Store {
            directory: directory.into(),
            journal: Journal {
                version: 1,
                local: *services.endpoint.node_addr(),
                policy: policy.clone(),
                epoch: Identity::generate().node_addr().to_string(),
                next_funding: 1,
                selling_stopped: false,
                funding: BTreeMap::new(),
                requested: BTreeMap::new(),
                outgoing: BTreeMap::new(),
                incoming: BTreeMap::new(),
                buyer_settlements: BTreeMap::new(),
                seller_settlements: BTreeMap::new(),
                renewals: BTreeMap::new(),
                renewals_paused: false,
                route_changes: BTreeMap::new(),
                watched_routes: BTreeMap::new(),
            },
            ready: true,
            _owner: owner,
        };
        store.persist()?;
        Ok(Self::with_store(policy, services, store))
    }

    pub fn load(
        directory: &Path,
        policy: ControllerPolicy,
        services: ControllerServices,
    ) -> Result<Self, String> {
        Self::validate_policy(&policy)?;
        let owner = acquire_owner(directory).map_err(|e| e.to_string())?;
        let file = File::open(directory.join("controller.json")).map_err(|e| e.to_string())?;
        if file.metadata().map_err(|e| e.to_string())?.len() > MAX_JOURNAL_BYTES {
            return Err("controller journal too large".into());
        }
        let mut bytes = Vec::new();
        file.take(MAX_JOURNAL_BYTES + 1)
            .read_to_end(&mut bytes)
            .map_err(|e| e.to_string())?;
        if bytes.len() as u64 > MAX_JOURNAL_BYTES {
            return Err("controller journal too large".into());
        }
        let journal: Journal = serde_json::from_slice(&bytes).map_err(|e| e.to_string())?;
        Self::validate_journal(&journal, &policy, *services.endpoint.node_addr())?;
        Self::reconcile_route_stops(&journal, &services)?;
        Ok(Self::with_store(
            policy,
            services,
            Store {
                directory: directory.into(),
                journal,
                ready: true,
                _owner: owner,
            },
        ))
    }

    fn with_store(policy: ControllerPolicy, services: ControllerServices, store: Store) -> Self {
        Self {
            services,
            policy,
            store: Arc::new(Mutex::new(store)),
            wallet: Arc::new(AsyncMutex::new(())),
            maintenance: AsyncMutex::new(()),
            renewal_work: AsyncMutex::new(()),
            route_work: AsyncMutex::new(()),
            refresh_work: AsyncMutex::new(()),
            refresh_checks: Mutex::new(BTreeMap::new()),
            accepting: Mutex::new(HashSet::new()),
            last_error: Mutex::new(None),
        }
    }

    pub(crate) fn validate_policy(policy: &ControllerPolicy) -> Result<(), String> {
        if policy.renewal.as_ref().is_some_and(|r| {
            !(1..=100).contains(&r.at_capacity_percent)
                || r.before_expiry_secs == 0
                || r.before_expiry_secs > policy.channel_lifetime_secs / 2
        }) {
            return Err("invalid renewal policy".into());
        }
        if policy.channel_capacity_sat == 0
            || policy.channel_capacity_sat.checked_mul(1_000).is_none()
            || policy.max_locked_sat < policy.channel_capacity_sat
            || !(60..=86_400).contains(&policy.channel_lifetime_secs)
            || policy.mint_url.is_empty()
            || policy.mint_url.len() > 512
            || policy.mint_url.ends_with('/')
        {
            return Err("invalid controller capital policy".into());
        }
        Ok(())
    }

    fn validate_journal(
        j: &Journal,
        policy: &ControllerPolicy,
        local: NodeAddr,
    ) -> Result<(), String> {
        if j.version != 1
            || &j.policy != policy
            || j.local != local
            || j.epoch.is_empty()
            || j.epoch.len() > 64
            || j.next_funding == 0
            || j.funding.len() > MAX_CHANNELS
            || j.requested.len() > MAX_ROUTES
            || j.outgoing.len() > MAX_ROUTES
            || j.incoming.len() > MAX_ROUTES
        {
            return Err("invalid controller journal bindings".into());
        }
        Self::validate_settlements(j)?;
        Self::validate_renewals(j)?;
        let mut providers = HashSet::new();
        let mut locked = 0u64;
        for (id, f) in &j.funding {
            let sequence = id
                .strip_prefix(&format!("{}-", j.epoch))
                .and_then(|s| s.parse::<u64>().ok())
                .filter(|n| *n > 0 && *n < j.next_funding);
            if id != &f.id
                || sequence.is_none_or(|n| id != &format!("{}-{n}", j.epoch))
                || id.len() > 128
                || f.provider == local
                || (!Self::funding_released(j, f) && !providers.insert(f.provider))
                || f.capacity_sat == 0
                || f.capacity_sat > policy.channel_capacity_sat
                || f.expires_unix <= f.created_unix
                || f.expires_unix - f.created_unix != policy.channel_lifetime_secs
                || f.receiver_pubkey_hex.len() != 66
                || f.grace_msat > f.capacity_sat * 1_000
            {
                return Err("invalid funding intent".into());
            }
            if !f.funded.as_ref().is_some_and(|funded| {
                j.buyer_settlements
                    .get(&funded.terms.id)
                    .is_some_and(|s| s.refunded)
            }) {
                locked = locked
                    .checked_add(f.capacity_sat)
                    .ok_or("capital overflow")?;
            }
            if let Some(funded) = &f.funded {
                validate_channel(&funded.terms).map_err(|e| e.to_string())?;
                if funded.terms.buyer != local
                    || funded.terms.mint_url != policy.mint_url
                    || funded.terms.expires_unix != f.expires_unix
                    || funded.terms.capacity_sat != f.capacity_sat
                    || funded.terms.grace_msat != f.grace_msat
                    || funded.opening.channel_id != funded.terms.id
                    || funded.opening.balance != 0
                {
                    return Err("funded channel mismatches durable intent".into());
                }
            }
        }
        if locked > policy.max_locked_sat {
            return Err("capital budget exceeded".into());
        }
        Self::validate_route_changes(j)?;
        Self::validate_watched_routes(j)?;
        let mut requested = HashSet::new();
        for (id, offer) in &j.requested {
            if id != &offer.id
                || id.is_empty()
                || id.len() > 128
                || offer.buyer != local
                || offer.provider == local
                || offer.mint_url != policy.mint_url
                || !requested.insert((offer.provider, *offer.destination.node_addr()))
            {
                return Err("invalid requested route".into());
            }
        }
        let mut outgoing = HashSet::new();
        for (id, o) in &j.outgoing {
            let intent = j
                .funding
                .get(&o.funding_id)
                .ok_or("outgoing funding missing")?;
            let f = intent
                .funded
                .as_ref()
                .ok_or("outgoing channel not funded")?;
            if id != &o.purchase.contract.id
                || o.purchase.provider != o.offer.provider
                || intent.provider != o.purchase.provider
                || o.offer.buyer != local
                || o.purchase.channel != f.terms
                || (!o.retired && j.requested.get(&o.offer.id) != Some(&o.offer))
                || (o.retired
                    && !Self::changed_route_retires(j, &o.purchase)
                    && !j
                        .buyer_settlements
                        .get(&o.purchase.channel.id)
                        .is_some_and(|s| s.refunded))
                || (!o.retired
                    && !outgoing.insert((o.purchase.provider, o.purchase.contract.destination)))
            {
                return Err("invalid outgoing agreement".into());
            }
            validate_contract(&o.purchase.contract, &o.purchase.channel)
                .map_err(|e| e.to_string())?;
            if o.purchase.contract.price != o.offer.price
                || o.purchase.contract.billing != o.offer.billing
                || o.purchase.contract.destination != *o.offer.destination.node_addr()
                || o.purchase.contract.next_hop != o.offer.next_hop
            {
                return Err("outgoing price or route changed".into());
            }
        }
        for (id, i) in &j.incoming {
            validate_channel(&i.channel).map_err(|e| e.to_string())?;
            validate_contract(&i.contract, &i.channel).map_err(|e| e.to_string())?;
            if (j.selling_stopped && i.phase != Phase::Stopped)
                || id != &i.contract.id
                || i.offer.provider != local
                || i.channel.buyer != i.offer.buyer
                || i.channel.mint_url != policy.mint_url
                || i.verified_paid_msat > i.channel.capacity_sat * 1_000
                || i.contract.price != i.offer.price
                || i.contract.billing != i.offer.billing
                || i.contract.destination != *i.offer.destination.node_addr()
                || i.contract.next_hop != i.offer.next_hop
                || i.replaces.as_ref().is_some_and(|previous| {
                    previous == id
                        || j.incoming.get(previous).is_none_or(|old| {
                            old.channel.buyer != i.channel.buyer
                                || old.contract.destination != i.contract.destination
                                || old.phase != Phase::Stopped
                        })
                })
            {
                return Err("invalid accepted upstream agreement".into());
            }
            if let Some(d) = &i.downstream {
                if d.buyer != local
                    || d.provider != i.offer.next_hop
                    || d.destination.node_addr() != i.offer.destination.node_addr()
                    || d.price.per_bytes != i.offer.price.per_bytes
                    || d.price.msat >= i.offer.price.msat
                    || d.billing != i.offer.billing
                    || d.mint_url != policy.mint_url
                {
                    return Err("invalid onward quote".into());
                }
            } else if i.offer.next_hop != *i.offer.destination.node_addr() {
                return Err("missing onward quote".into());
            }
        }
        Ok(())
    }

    async fn change<T: Send + 'static>(
        &self,
        job: impl FnOnce(&mut Journal) -> Result<T, String> + Send + 'static,
    ) -> Result<T, String> {
        let store = self.store.clone();
        blocking(move || {
            let mut store = store.lock().map_err(|_| "controller state poisoned")?;
            store.change(job)
        })
        .await
    }

    async fn snapshot(&self) -> Result<Journal, String> {
        let store = self.store.clone();
        blocking(move || {
            let store = store.lock().map_err(|_| "controller state poisoned")?;
            if !store.ready {
                return Err("controller journal suspended".into());
            }
            Ok(store.journal.clone())
        })
        .await
    }

    async fn neighbor(&self, address: NodeAddr) -> Result<PeerIdentity, String> {
        let peers = self
            .services
            .endpoint
            .peers()
            .await
            .map_err(|e| e.to_string())?;
        let peer = peers
            .iter()
            .find(|p| p.connected && p.node_addr == address)
            .ok_or("provider is not a connected native neighbor")?;
        PeerIdentity::from_npub(&peer.npub).map_err(|e| e.to_string())
    }

    /// Explicit application authorization for this destination under local price
    /// and lifetime spending caps. Merely receiving data never calls this method.
    pub async fn buy_route(&self, destination: PeerIdentity) -> Result<Purchase, String> {
        let offer = self.services.quotes.request_route(destination).await?;
        self.purchase_offer(offer).await
    }

    async fn fund(&self, offer: &RouteOffer) -> Result<(String, Funded), String> {
        if Self::offer_paused(&self.snapshot().await?, &offer.id) {
            return Err("route change paused".into());
        }
        if offer.buyer != *self.services.endpoint.node_addr()
            || offer.mint_url != self.policy.mint_url
            || offer.expires_unix <= now()?
        {
            return Err("unapproved funding destination or mint".into());
        }
        let wallet_guard = self.wallet.clone().lock_owned().await;
        let provider = offer.provider;
        let receiver = offer.receiver_pubkey_hex.clone();
        let capacity = self.policy.channel_capacity_sat.min(offer.capacity_sat);
        let grace = offer
            .grace_msat
            .min(capacity.checked_mul(1_000).ok_or("capacity overflow")?);
        let created = now()?;
        let f = self
            .change(move |j| {
                if let Some(f) = j
                    .funding
                    .values()
                    .find(|f| f.provider == provider && !Self::funding_released(j, f))
                {
                    if f.receiver_pubkey_hex != receiver
                        || f.capacity_sat > capacity
                        || f.grace_msat > grace
                        || f.expires_unix <= created
                    {
                        return Err(
                            "existing channel needs explicit renewal or reconciliation".into()
                        );
                    }
                    return Ok(f.clone());
                }
                let locked = j
                    .funding
                    .values()
                    .filter(|f| {
                        !f.funded.as_ref().is_some_and(|f| {
                            j.buyer_settlements
                                .get(&f.terms.id)
                                .is_some_and(|s| s.refunded)
                        })
                    })
                    .try_fold(0u64, |sum, f| sum.checked_add(f.capacity_sat))
                    .ok_or("capital overflow")?;
                if j.funding.len() >= MAX_CHANNELS
                    || locked
                        .checked_add(capacity)
                        .is_none_or(|total| total > j.policy.max_locked_sat)
                {
                    return Err("working capital exhausted".into());
                }
                let id = format!("{}-{}", j.epoch, j.next_funding);
                j.next_funding = j
                    .next_funding
                    .checked_add(1)
                    .ok_or("funding sequence exhausted")?;
                let f = FundingIntent {
                    id: id.clone(),
                    provider,
                    receiver_pubkey_hex: receiver,
                    capacity_sat: capacity,
                    grace_msat: grace,
                    created_unix: created,
                    expires_unix: created
                        .checked_add(j.policy.channel_lifetime_secs)
                        .ok_or("expiry overflow")?,
                    funded: None,
                };
                j.funding.insert(id, f.clone());
                Ok(f)
            })
            .await?;
        let funded = if let Some(funded) = f.funded.clone() {
            funded
        } else {
            let request = StreamingRouteOpenCashuSpilmanChannelFromWalletRequest {
                mint_url: self.policy.mint_url.clone(),
                receiver_pubkey_hex: f.receiver_pubkey_hex.clone(),
                capacity_sat: f.capacity_sat,
                expiry_unix: f.expires_unix.checked_add(60).ok_or("expiry overflow")?,
                max_amount_per_output: 0,
                unit: "sat".into(),
                opening_paid_msat: 0,
                keyset_id: None,
                keyset_info_json: None,
                client_request_id: Some(f.id.clone()),
                route_created_at_unix: Some(f.created_unix),
            };
            let directory = self.services.wallet_directory.clone();
            let runtime = tokio::runtime::Handle::current();
            // The upstream wallet's file-store future is intentionally !Send.
            // Drive it entirely on one blocking worker, keeping the native node
            // loop free and retaining the idempotent intent if its reply is lost.
            let (opened, _wallet) = blocking(move || {
                let opened = runtime.block_on(async move {
                    open_streaming_route_cashu_spilman_channel_from_wallet(&directory, request)
                        .await
                        .map_err(|e| e.to_string())
                });
                // A cancelled async caller must not release wallet ownership
                // while this blocking operation is still running.
                Ok((opened, wallet_guard))
            })
            .await?;
            let opened = opened?;
            let funded = Funded {
                terms: ChannelTerms {
                    id: opened.channel.channel_id,
                    buyer: *self.services.endpoint.node_addr(),
                    mint_url: self.policy.mint_url.clone(),
                    expires_unix: f.expires_unix,
                    capacity_sat: f.capacity_sat,
                    grace_msat: f.grace_msat,
                },
                opening: opened.channel.payment,
            };
            let saved = funded.clone();
            let id = f.id.clone();
            self.change(move |j| {
                j.funding
                    .get_mut(&id)
                    .ok_or("funding intent missing")?
                    .funded = Some(saved);
                Ok(())
            })
            .await?;
            funded
        };
        let buyer = self.services.buyer.clone();
        let terms = funded.terms.clone();
        blocking(move || {
            buyer
                .accept_channel(provider, terms, 0)
                .map_err(|e| e.to_string())
        })
        .await?;
        Ok((f.id, funded))
    }

    async fn purchase_offer(&self, offer: RouteOffer) -> Result<Purchase, String> {
        let peer = self.neighbor(offer.provider).await?;
        self.prepare_changed_route(&offer).await?;
        let existing = self
            .snapshot()
            .await?
            .outgoing
            .values()
            .find(|o| {
                !o.retired
                    && o.purchase.provider == offer.provider
                    && o.purchase.contract.destination == *offer.destination.node_addr()
            })
            .cloned();
        if let Some(existing) = existing {
            if self
                .snapshot()
                .await?
                .buyer_settlements
                .contains_key(&existing.purchase.channel.id)
            {
                let fresh = offer.clone();
                self.change(move |j| Self::reopen_refunded_route(j, &existing, fresh))
                    .await?;
            } else {
                if existing.purchase.contract.expires_unix <= now()?
                    || existing.offer.price != offer.price
                    || existing.offer.billing != offer.billing
                    || existing.offer.next_hop != offer.next_hop
                {
                    return Err("existing route needs explicit replacement".into());
                }
                if existing.accepted {
                    return Ok(existing.purchase);
                }
                self.ensure_buyer_purchase(&existing.purchase).await?;
                return self.send_accept(peer, existing).await;
            }
        }
        let offer = self
            .change(move |j| {
                if let Some(old) = j.requested.values().find(|old| {
                    old.provider == offer.provider
                        && old.destination.node_addr() == offer.destination.node_addr()
                }) {
                    if old.price != offer.price
                        || old.next_hop != offer.next_hop
                        || old.billing != offer.billing
                    {
                        return Err("pending route needs explicit replacement".into());
                    }
                    return Ok(old.clone());
                }
                if j.requested.len() >= MAX_ROUTES {
                    return Err("requested route capacity".into());
                }
                if j.requested.contains_key(&offer.id) {
                    return Err("conflicting requested offer identity".into());
                }
                j.requested.insert(offer.id.clone(), offer.clone());
                Ok(offer)
            })
            .await?;
        let (funding_id, funded) = self.fund(&offer).await?;
        let contract = contract_from_offer(&offer, &funded.terms)?;
        let record = Outgoing {
            offer,
            funding_id,
            purchase: Purchase {
                provider: *peer.node_addr(),
                channel: funded.terms,
                contract,
            },
            accepted: false,
            retired: false,
        };
        let saved = record.clone();
        let record = self
            .change(move |j| {
                if let Some(old) = j.outgoing.values().find(|o| {
                    !o.retired
                        && o.purchase.provider == saved.purchase.provider
                        && o.purchase.contract.destination == saved.purchase.contract.destination
                }) {
                    if old.offer.price != saved.offer.price
                        || old.offer.billing != saved.offer.billing
                        || old.offer.next_hop != saved.offer.next_hop
                    {
                        return Err("conflicting concurrent route purchase".into());
                    }
                    return Ok(old.clone());
                }
                if j.outgoing.len() >= MAX_ROUTES {
                    return Err("outgoing route capacity".into());
                }
                j.outgoing
                    .insert(saved.purchase.contract.id.clone(), saved.clone());
                Ok(saved)
            })
            .await?;
        self.ensure_buyer_purchase(&record.purchase).await?;
        self.send_accept(peer, record).await
    }

    /// A fresh purchase can replace a fully refunded, explicitly closed route.
    /// Keep the old account evidence, and persist the new authorization in the
    /// same mutation that retires its predecessor, before touching the wallet.
    fn reopen_refunded_route(
        j: &mut Journal,
        previous: &Outgoing,
        fresh: RouteOffer,
    ) -> Result<(), String> {
        let old = j
            .outgoing
            .get(&previous.purchase.contract.id)
            .ok_or("closed purchase missing")?;
        if old.purchase != previous.purchase || old.offer != previous.offer {
            return Err("closed purchase changed".into());
        }
        if fresh.id == old.offer.id
            || fresh.expires_unix <= now()?
            || !renewal::same_service(&old.offer, &fresh)
        {
            return Err("repurchase requires a fresh offer for the same service".into());
        }
        if old.retired {
            // Another purchase already advanced this route. The common
            // requested-offer path below reconciles the winning authorization.
            return Ok(());
        }
        if !old.accepted
            || !j
                .buyer_settlements
                .get(&old.purchase.channel.id)
                .is_some_and(|s| s.refunded)
        {
            return Err("previous channel refund incomplete".into());
        }
        if j.renewals
            .get(&old.purchase.channel.id)
            .is_some_and(|r| !r.is_completed())
        {
            return Err("channel replacement already in progress".into());
        }
        if j.requested.contains_key(&fresh.id)
            || j.requested.values().any(|o| {
                o.id != old.offer.id
                    && o.provider == fresh.provider
                    && o.destination.node_addr() == fresh.destination.node_addr()
            })
        {
            return Err("repurchase authorization conflict".into());
        }
        let old_offer = old.offer.id.clone();
        j.outgoing
            .get_mut(&previous.purchase.contract.id)
            .unwrap()
            .retired = true;
        j.requested.remove(&old_offer);
        j.requested.insert(fresh.id.clone(), fresh);
        Ok(())
    }

    async fn ensure_buyer_purchase(&self, purchase: &Purchase) -> Result<(), String> {
        let buyer = self.services.buyer.clone();
        let purchase = purchase.clone();
        blocking(move || {
            buyer
                .accept_channel(purchase.provider, purchase.channel, 0)
                .map_err(|e| e.to_string())?;
            buyer
                .accept_quote(purchase.contract)
                .map_err(|e| e.to_string())
        })
        .await
    }

    async fn opening_payment(
        &self,
        channel: &ChannelTerms,
        provider: NodeAddr,
    ) -> Result<CashuSpilmanPayment, String> {
        let wallet_guard = self.wallet.clone().lock_owned().await;
        let buyer = self.services.buyer.clone();
        let directory = self.services.wallet_directory.clone();
        let id = channel.id.clone();
        blocking(move || {
            let _wallet = wallet_guard;
            let signer = FileSpilmanPaymentSigner::load(&directory)?;
            buyer
                .reproduce_payment(&signer, provider, &id, now()?)
                .map_err(|e| e.to_string())
        })
        .await
    }

    async fn send_accept(&self, peer: PeerIdentity, record: Outgoing) -> Result<Purchase, String> {
        if Self::offer_paused(&self.snapshot().await?, &record.offer.id) {
            return Err("route change paused".into());
        }
        let payment = self
            .opening_payment(&record.purchase.channel, record.purchase.provider)
            .await?;
        let body = serde_json::to_vec(&ControllerRequest::Accept {
            offer_id: record.offer.id.clone(),
            channel: record.purchase.channel.clone(),
            payment: Box::new(payment),
            replaces: self.replaces_for(&record.offer).await?,
        })
        .map_err(|e| e.to_string())?;
        let deadline = tokio::time::Instant::now() + Duration::from_secs(60);
        loop {
            if tokio::time::Instant::now() >= deadline {
                return Err("acceptance deadline; durable request retained".into());
            }
            let bytes = self.services.acceptance.request(peer, body.clone()).await?;
            match serde_json::from_slice::<ControllerResponse>(&bytes)
                .map_err(|_| "invalid acceptance response")?
            {
                ControllerResponse::Accepted { purchase } => {
                    if *purchase != record.purchase {
                        return Err("provider changed accepted terms".into());
                    }
                    let id = record.purchase.contract.id.clone();
                    self.change(move |j| {
                        j.outgoing
                            .get_mut(&id)
                            .ok_or("purchase intent missing")?
                            .accepted = true;
                        Ok(())
                    })
                    .await?;
                    return Ok(*purchase);
                }
                ControllerResponse::Pending => tokio::time::sleep(Duration::from_millis(250)).await,
                ControllerResponse::Rejected => {
                    return Err("provider rejected purchase; intent retained".into());
                }
                _ => return Err("unexpected acceptance response".into()),
            }
        }
    }

    pub async fn handle(&self, peer: PeerIdentity, body: &[u8]) -> ControllerResponse {
        match self.handle_inner(peer, body).await {
            Ok(response) => response,
            Err(error) => {
                *self.last_error.lock().unwrap() = Some(error);
                ControllerResponse::Rejected
            }
        }
    }

    async fn handle_inner(
        &self,
        peer: PeerIdentity,
        body: &[u8],
    ) -> Result<ControllerResponse, String> {
        if body.len() > MAX_RECORD_BYTES {
            return Err("oversized acceptance".into());
        }
        let (offer_id, channel, payment, replaces) =
            match serde_json::from_slice(body).map_err(|_| "invalid acceptance")? {
                ControllerRequest::Accept {
                    offer_id,
                    channel,
                    payment,
                    replaces,
                } => (offer_id, channel, payment, replaces),
                ControllerRequest::StopRoute { contract_id } => {
                    return self.handle_stop_route(peer, &contract_id).await;
                }
                ControllerRequest::Seal { channel_id } => {
                    return self.handle_seal(peer, &channel_id).await;
                }
                ControllerRequest::Settle {
                    channel_id,
                    payment,
                } => return self.handle_settle(peer, &channel_id, *payment).await,
            };
        if channel.buyer != *peer.node_addr() || channel.mint_url != self.policy.mint_url {
            return Err("wrong upstream payer or mint".into());
        }
        let state = self.snapshot().await?;
        if state.selling_stopped {
            return Err("controller stopped selling".into());
        }
        if state.seller_settlements.contains_key(&channel.id) {
            return Err("channel already sealed for settlement".into());
        }
        let old = state
            .incoming
            .values()
            .find(|i| i.offer.id == offer_id && i.channel.id == channel.id)
            .cloned();
        let (offer, downstream, contract) = if let Some(old) = &old {
            if old.channel != channel || old.phase == Phase::Stopped || old.replaces != replaces {
                return Err("closed or changed upstream agreement".into());
            }
            (
                old.offer.clone(),
                old.downstream.clone(),
                old.contract.clone(),
            )
        } else {
            let offer = self.services.quotes.retained_offer(peer, &offer_id)?;
            let contract = self.services.quotes.bind_offer(peer, &offer_id, &channel)?;
            let downstream = self.services.quotes.downstream_offer(peer, &offer_id)?;
            (offer, downstream, contract)
        };
        let _claim = {
            let mut claims = self.accepting.lock().unwrap();
            if !claims.insert(contract.id.clone()) {
                return Ok(ControllerResponse::Pending);
            }
            AcceptGuard {
                claims: &self.accepting,
                id: contract.id.clone(),
            }
        };
        if contract.expires_unix <= now()?
            || self
                .services
                .endpoint
                .resolve_next_hop(offer.destination, Some(channel.buyer))
                .await
                .map_err(|e| e.to_string())?
                .is_none_or(|p| p.node_addr() != &offer.next_hop)
        {
            return Err("accepted route expired or changed".into());
        }
        if old.as_ref().is_some_and(|i| i.phase == Phase::Active) {
            return Ok(ControllerResponse::Accepted {
                purchase: Box::new(Purchase {
                    provider: *self.services.endpoint.node_addr(),
                    channel,
                    contract,
                }),
            });
        }
        let payments = self.services.payment_control.clone();
        let terms = channel.clone();
        let credit = blocking(move || payments.verify_funding(&terms, peer, &payment)).await?;
        let incoming = Incoming {
            offer,
            downstream,
            channel: channel.clone(),
            contract: contract.clone(),
            verified_paid_msat: credit.paid_msat,
            phase: Phase::Prepared,
            replaces,
        };
        let saved = incoming.clone();
        self.change(move |j| {
            if j.selling_stopped {
                return Err("controller stopped selling".into());
            }
            if j.seller_settlements.contains_key(&saved.channel.id) {
                return Err("channel already sealed for settlement".into());
            }
            if let Some(old) = j.incoming.get(&saved.contract.id) {
                if old.channel != saved.channel
                    || old.contract != saved.contract
                    || old.replaces != saved.replaces
                    || old.phase == Phase::Stopped
                {
                    return Err("upstream binding conflict".into());
                }
                return Ok(());
            }
            if j.incoming.len() >= MAX_ROUTES
                || j.incoming.values().any(|i| {
                    i.phase != Phase::Stopped
                        && saved.replaces.as_ref() != Some(&i.contract.id)
                        && i.channel.buyer == saved.channel.buyer
                        && i.contract.destination == saved.contract.destination
                })
            {
                return Err("upstream route capacity or conflict".into());
            }
            if let Some(previous) = &saved.replaces {
                let old = j
                    .incoming
                    .get_mut(previous)
                    .ok_or("replacement route missing")?;
                if previous == &saved.contract.id
                    || old.channel.buyer != saved.channel.buyer
                    || old.contract.destination != saved.contract.destination
                {
                    return Err("replacement route ownership conflict".into());
                }
                old.phase = Phase::Stopped;
            }
            j.incoming.insert(saved.contract.id.clone(), saved);
            Ok(())
        })
        .await?;
        self.activate(incoming).await?;
        Ok(ControllerResponse::Accepted {
            purchase: Box::new(Purchase {
                provider: *self.services.endpoint.node_addr(),
                channel,
                contract,
            }),
        })
    }

    async fn activate(&self, incoming: Incoming) -> Result<(), String> {
        self.check_prepared_route(&incoming).await?;
        let seller = self.services.seller.clone();
        let terms = incoming.channel.clone();
        let paid = incoming.verified_paid_msat;
        let replaces = incoming.replaces.clone();
        blocking(move || {
            if let Some(previous) = replaces
                && seller.usage(&previous).is_some()
            {
                seller
                    .close_contract(&previous)
                    .map_err(|e| e.to_string())?;
            }
            if let Some(old) = seller.channel_terms(&terms.id) {
                if old != terms {
                    return Err("retained channel terms differ".into());
                }
                let previous = seller
                    .channel_usage(&terms.id)
                    .ok_or("channel disappeared")?
                    .paid_msat;
                seller
                    .apply_verified_balance(&terms.id, paid.max(previous))
                    .map_err(|e| e.to_string())
            } else {
                seller
                    .open_channel_verified(terms, paid)
                    .map_err(|e| e.to_string())
            }
        })
        .await?;
        if let Some(downstream) = incoming.downstream.clone() {
            self.check_prepared_route(&incoming).await?;
            self.purchase_offer(downstream).await?;
        }
        // Onward service is accepted before any upstream data receives credit.
        self.check_prepared_route(&incoming).await?;
        let seller = self.services.seller.clone();
        let contract = incoming.contract.clone();
        blocking(move || seller.add_contract(contract).map_err(|e| e.to_string())).await?;
        let id = incoming.contract.id;
        self.change(move |j| {
            let entry = j.incoming.get_mut(&id).ok_or("acceptance intent missing")?;
            if entry.phase == Phase::Stopped {
                return Err("acceptance was stopped".into());
            }
            entry.phase = Phase::Active;
            Ok(())
        })
        .await
    }

    async fn check_prepared_route(&self, incoming: &Incoming) -> Result<(), String> {
        if incoming.contract.expires_unix <= now()?
            || self
                .snapshot()
                .await?
                .incoming
                .get(&incoming.contract.id)
                .is_none_or(|i| i.phase != Phase::Prepared)
        {
            return Err("prepared route expired or stopped".into());
        }
        if self
            .services
            .endpoint
            .resolve_next_hop(incoming.offer.destination, Some(incoming.channel.buyer))
            .await
            .map_err(|e| e.to_string())?
            .is_none_or(|p| p.node_addr() != &incoming.contract.next_hop)
        {
            return Err("prepared native route changed".into());
        }
        Ok(())
    }

    /// Resume durable incomplete requests. A missing reply is not permission to
    /// allocate a new funding identity or another channel. Expired/changed routes
    /// remain stopped until a separate replacement agreement is authorized.
    pub async fn resume_pending(&self) -> Result<(), String> {
        let mut first_error = self.resume_route_changes().await.err();
        let snapshot = self.snapshot().await?;
        let paused_offers: HashSet<_> = snapshot
            .requested
            .values()
            .filter(|o| Self::offer_paused(&snapshot, &o.id))
            .map(|o| o.id.clone())
            .collect();
        // Native destination identities/coordinates are memory state. A router
        // restart does not necessarily restart the endpoints' FSP sessions, so
        // established traffic cannot rely on another handshake to restore them.
        // Prime bounded native discovery from retained agreements. This neither
        // authorizes a changed next hop nor creates a new financial agreement.
        let timestamp = now()?;
        let mut routes = Vec::new();
        for outgoing in snapshot.outgoing.values().filter(|o| {
            o.accepted
                && !o.retired
                && o.purchase.contract.expires_unix > timestamp
                && !snapshot
                    .buyer_settlements
                    .contains_key(&o.purchase.channel.id)
        }) {
            routes.push((outgoing.offer.destination, None));
        }
        for incoming in snapshot
            .incoming
            .values()
            .filter(|i| i.phase == Phase::Active && i.contract.expires_unix > timestamp)
        {
            routes.push((incoming.offer.destination, Some(incoming.channel.buyer)));
        }
        let mut seen = HashSet::new();
        for (destination, previous) in routes {
            if !seen.insert((*destination.node_addr(), previous)) {
                continue;
            }
            if let Err(error) = self
                .services
                .endpoint
                .resolve_next_hop(destination, previous)
                .await
            {
                first_error.get_or_insert(error.to_string());
            }
        }
        for incoming in snapshot
            .incoming
            .into_values()
            .filter(|i| i.phase == Phase::Prepared)
        {
            let claim = {
                let mut claims = self.accepting.lock().unwrap();
                if !claims.insert(incoming.contract.id.clone()) {
                    continue;
                }
                AcceptGuard {
                    claims: &self.accepting,
                    id: incoming.contract.id.clone(),
                }
            };
            if let Err(error) = self.activate(incoming).await {
                first_error.get_or_insert(error);
            }
            drop(claim);
        }
        for offer in snapshot.requested.into_values().filter(|offer| {
            let paused = snapshot.renewals_paused
                && snapshot.renewals.values().any(|r| r.requests(&offer.id))
                || paused_offers.contains(&offer.id);
            let accepted = snapshot
                .outgoing
                .values()
                .any(|o| o.offer.id == offer.id && o.accepted);
            !(paused || accepted)
        }) {
            if let Err(error) = self.purchase_offer(offer).await {
                first_error.get_or_insert(error);
            }
        }
        if let Err(error) = self.resume_settlements().await {
            first_error.get_or_insert(error);
        }
        if let Err(error) = self.maintain_renewals().await {
            first_error.get_or_insert(error);
        }
        first_error.map_or(Ok(()), Err)
    }

    pub async fn purchases(&self) -> Result<Vec<Purchase>, String> {
        let snapshot = self.snapshot().await?;
        Ok(snapshot
            .outgoing
            .into_values()
            .filter(|o| {
                o.accepted
                    && !o.retired
                    && !snapshot
                        .buyer_settlements
                        .contains_key(&o.purchase.channel.id)
            })
            .map(|o| o.purchase)
            .collect())
    }

    /// Quiesce upstream service without erasing the funded accounts. Payment
    /// updates can still settle the final usage; mint close/refund is separate.
    pub async fn stop_selling(&self) -> Result<(), String> {
        let channels = self
            .change(|j| {
                j.selling_stopped = true;
                let mut ids = HashSet::new();
                for i in j.incoming.values_mut() {
                    i.phase = Phase::Stopped;
                    ids.insert(i.channel.id.clone());
                }
                Ok(ids)
            })
            .await?;
        for incoming in self.snapshot().await?.incoming.values() {
            self.services.quotes.stop_reusing(&incoming.offer.id)?;
        }
        let seller = self.services.seller.clone();
        blocking(move || {
            for id in channels {
                if seller.channel_terms(&id).is_some() {
                    seller.close_channel(&id).map_err(|e| e.to_string())?;
                }
            }
            Ok(())
        })
        .await
    }

    pub async fn flush_payments(&self) -> Result<(), String> {
        let _maintenance = self.maintenance.lock().await;
        self.pay_current_usage().await
    }

    async fn pay_current_usage(&self) -> Result<(), String> {
        let mut seen = HashSet::new();
        let mut first_error = None;
        for purchase in self.purchases().await? {
            if !seen.insert(purchase.channel.id.clone()) {
                continue;
            }
            if let Err(error) = self.pay_channel(purchase).await {
                first_error.get_or_insert(error);
            }
        }
        first_error.map_or(Ok(()), Err)
    }

    async fn pay_channel(&self, purchase: Purchase) -> Result<(), String> {
        let peer = self.neighbor(purchase.provider).await?;
        let response = self
            .services
            .payments
            .request(
                peer,
                serde_json::to_vec(&PaymentRequest::Usage {
                    channel_id: purchase.channel.id.clone(),
                })
                .map_err(|e| e.to_string())?,
            )
            .await?;
        let PaymentResponse::Status { channel_id, usage } =
            serde_json::from_slice(&response).map_err(|_| "invalid usage response")?
        else {
            return Err("provider rejected usage".into());
        };
        if channel_id != purchase.channel.id {
            return Err("usage response changed channel".into());
        }
        let prior = self
            .services
            .buyer
            .authorized_sat(&channel_id)
            .ok_or("buyer channel missing")?;
        // A crash can lose a local submission that the provider retained.
        // Pay the supported portion of its cumulative claim; rejecting the
        // entire claim would also prevent payment for every later known send.
        // Controller purchases approve no advance. The strict authorizer still
        // enforces provider identity, evidence, capacity and lifetime limits.
        let supported = usage.submitted_msat.min(
            self.services
                .buyer
                .evidence_msat(&channel_id)
                .ok_or("buyer channel evidence missing")?,
        );
        if usage.paid_msat / 1_000 >= supported.div_ceil(1_000) && usage.paid_msat / 1_000 >= prior
        {
            return Ok(());
        }
        let payment = {
            let wallet_guard = self.wallet.clone().lock_owned().await;
            let buyer = self.services.buyer.clone();
            let directory = self.services.wallet_directory.clone();
            let id = channel_id.clone();
            blocking(move || {
                let _wallet = wallet_guard;
                let signer = FileSpilmanPaymentSigner::load(&directory)?;
                buyer
                    .sign_claim(&signer, purchase.provider, &id, supported, now()?)
                    .map_err(|e| e.to_string())
            })
            .await?
        };
        let expected = payment.balance * 1_000;
        let response = self
            .services
            .payments
            .request(
                peer,
                serde_json::to_vec(&PaymentRequest::Update {
                    channel_id: channel_id.clone(),
                    payment,
                })
                .map_err(|e| e.to_string())?,
            )
            .await?;
        match serde_json::from_slice::<PaymentResponse>(&response)
            .map_err(|_| "invalid payment response")?
        {
            PaymentResponse::Status {
                channel_id: id,
                usage,
            } if id == channel_id && usage.paid_msat >= expected => {}
            _ => return Err("provider did not accept signed balance".into()),
        }
        Ok(())
    }

    pub fn last_error(&self) -> Option<String> {
        self.last_error.lock().unwrap().clone()
    }

    async fn tick(&self) {
        let result = self.flush_payments().await;
        if let Err(error) = result {
            *self.last_error.lock().unwrap() = Some(error);
        }
    }
}

pub struct ControllerTasks {
    requests: JoinHandle<mpsc::Receiver<IncomingRequest>>,
    payments: JoinHandle<()>,
    recovery: JoinHandle<()>,
    refresh: JoinHandle<()>,
    stopping: watch::Sender<bool>,
}
impl ControllerTasks {
    pub fn start(
        controller: Arc<Controller>,
        mut incoming: mpsc::Receiver<IncomingRequest>,
    ) -> Self {
        let (stopping, mut stop_requests) = watch::channel(false);
        let mut stop_payments = stop_requests.clone();
        let mut stop_recovery = stop_requests.clone();
        let mut stop_refresh = stop_requests.clone();
        let handler = controller.clone();
        let requests = tokio::spawn(async move {
            let permits = Arc::new(Semaphore::new(8));
            let mut jobs = JoinSet::new();
            loop {
                tokio::select! {
                    _ = stop_requests.changed() => break,
                    request = incoming.recv() => {
                        let Some(request) = request else { break; };
                        let Ok(permit) = permits.clone().try_acquire_owned() else {
                            let _ = request.respond.send(
                                serde_json::to_vec(&ControllerResponse::Pending).expect("serializable")
                            );
                            continue;
                        };
                        let handler = handler.clone();
                        jobs.spawn(async move {
                            let _permit = permit;
                            let response = handler.handle(request.peer, &request.body).await;
                            let _ = request.respond.send(serde_json::to_vec(&response).expect("serializable"));
                        });
                    }
                    _ = jobs.join_next(), if !jobs.is_empty() => {}
                }
            }
            // Finish wallet/journal operations before returning ownership of
            // the request stream to a replacement controller.
            while jobs.join_next().await.is_some() {}
            incoming
        });
        let payer = controller.clone();
        let payments = tokio::spawn(async move {
            let mut ticker = tokio::time::interval(Duration::from_millis(500));
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                tokio::select! {
                    _ = stop_payments.changed() => break,
                    _ = ticker.tick() => payer.tick().await,
                }
            }
        });
        let watcher = controller.clone();
        let refresh = tokio::spawn(async move {
            let mut ticker = tokio::time::interval(Duration::from_secs(2));
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                tokio::select! {
                    _ = stop_refresh.changed() => break,
                    _ = ticker.tick() => {
                        if let Err(error) = watcher.refresh_watched_routes().await {
                            *watcher.last_error.lock().unwrap() = Some(error);
                        }
                    }
                }
            }
        });
        let recovery = tokio::spawn(async move {
            let mut ticker = tokio::time::interval(Duration::from_secs(2));
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                tokio::select! {
                    _ = stop_recovery.changed() => break,
                    _ = ticker.tick() => {
                        if let Err(error) = controller.resume_pending().await {
                            *controller.last_error.lock().unwrap() = Some(error);
                        }
                    }
                }
            }
        });
        Self {
            requests,
            payments,
            recovery,
            refresh,
            stopping,
        }
    }
    /// Drain in-flight work and return the live transport's request stream for
    /// a controller reload. Dropping tasks instead is an abrupt cancellation.
    pub async fn stop(mut self) -> Option<mpsc::Receiver<IncomingRequest>> {
        let _ = self.stopping.send(true);
        let incoming = (&mut self.requests).await.ok();
        let _ = (&mut self.payments).await;
        let _ = (&mut self.recovery).await;
        let _ = (&mut self.refresh).await;
        incoming
    }
}
impl Drop for ControllerTasks {
    fn drop(&mut self) {
        self.requests.abort();
        self.payments.abort();
        self.recovery.abort();
        self.refresh.abort();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unresolved_journal() -> Journal {
        let local = NodeAddr::from_bytes([1; 16]);
        let policy = ControllerPolicy {
            mint_url: "http://127.0.0.1:1234".into(),
            channel_capacity_sat: 32,
            max_locked_sat: 32,
            channel_lifetime_secs: 600,
            renewal: None,
        };
        let funding = FundingIntent {
            id: "test-1".into(),
            provider: NodeAddr::from_bytes([2; 16]),
            receiver_pubkey_hex: format!("02{}", "11".repeat(32)),
            capacity_sat: 32,
            grace_msat: 8_000,
            created_unix: 100,
            expires_unix: 700,
            funded: None,
        };
        Journal {
            version: 1,
            local,
            policy,
            epoch: "test".into(),
            next_funding: 2,
            selling_stopped: false,
            funding: [(funding.id.clone(), funding)].into(),
            requested: BTreeMap::new(),
            outgoing: BTreeMap::new(),
            incoming: BTreeMap::new(),
            buyer_settlements: BTreeMap::new(),
            seller_settlements: BTreeMap::new(),
            renewals: BTreeMap::new(),
            renewals_paused: false,
            route_changes: BTreeMap::new(),
            watched_routes: BTreeMap::new(),
        }
    }

    #[test]
    fn repurchase_rejects_unfinished_refunds_stale_offers_and_competing_renewal() {
        // Exercise the transition guards directly. The integration suite
        // uses actual funded channels, refunds and a reload of the saved journal.
        let mut journal = unresolved_journal();
        let destination = PeerIdentity::from_pubkey_full(Identity::generate().pubkey_full());
        let terms = ChannelTerms {
            id: "closed".into(),
            buyer: journal.local,
            mint_url: journal.policy.mint_url.clone(),
            capacity_sat: 32,
            grace_msat: 8_000,
            expires_unix: now().unwrap() + 600,
        };
        let offer = RouteOffer {
            billing: Default::default(),
            id: "old-offer".into(),
            buyer: journal.local,
            provider: NodeAddr::from_bytes([2; 16]),
            destination,
            next_hop: *destination.node_addr(),
            path: vec![NodeAddr::from_bytes([2; 16]), *destination.node_addr()],
            price: crate::ledger::BytePrice {
                msat: 1024,
                per_bytes: 1024,
            },
            expires_unix: now().unwrap() + 300,
            max_units: 30_000,
            mint_url: terms.mint_url.clone(),
            receiver_pubkey_hex: format!("02{}", "11".repeat(32)),
            capacity_sat: 32,
            grace_msat: 8_000,
        };
        let old = Outgoing {
            purchase: Purchase {
                provider: offer.provider,
                contract: contract_from_offer(&offer, &terms).unwrap(),
                channel: terms.clone(),
            },
            offer: offer.clone(),
            funding_id: "test-1".into(),
            accepted: true,
            retired: false,
        };
        journal
            .outgoing
            .insert(old.purchase.contract.id.clone(), old.clone());
        journal.requested.insert(offer.id.clone(), offer.clone());
        let mut fresh = offer.clone();
        fresh.id = "fresh-offer".into();
        assert_eq!(
            Controller::reopen_refunded_route(&mut journal, &old, fresh.clone()),
            Err("previous channel refund incomplete".into())
        );
        let provider = serde_json::to_value(&old.purchase).unwrap()["provider"].clone();
        journal.buyer_settlements.insert(
            terms.id.clone(),
            serde_json::from_value(
                serde_json::json!({"provider":provider,"channel":terms,"usage":null,
                "payment":null,"report":null,"refunded":false}),
            )
            .unwrap(),
        );
        assert_eq!(
            Controller::reopen_refunded_route(&mut journal, &old, fresh.clone()),
            Err("previous channel refund incomplete".into())
        );
        journal
            .buyer_settlements
            .get_mut("closed")
            .unwrap()
            .refunded = true;
        for mutation in [0, 1, 2, 3] {
            let mut changed = fresh.clone();
            match mutation {
                0 => changed.id = offer.id.clone(),
                1 => changed.expires_unix = 1,
                2 => changed.price.msat += 1,
                _ => changed.next_hop = NodeAddr::from_bytes([3; 16]),
            }
            assert!(Controller::reopen_refunded_route(&mut journal, &old, changed).is_err());
            assert!(!journal.outgoing[&old.purchase.contract.id].retired);
            assert!(journal.requested.contains_key(&offer.id));
        }
        journal.renewals.insert(
            "closed".into(),
            serde_json::from_value(serde_json::json!({
                "previous":[old], "replacements":null, "completed":false
            }))
            .unwrap(),
        );
        assert_eq!(
            Controller::reopen_refunded_route(&mut journal, &old, fresh),
            Err("channel replacement already in progress".into())
        );
        assert!(!journal.outgoing[&old.purchase.contract.id].retired);
    }

    #[test]
    fn unresolved_funding_survives_storage_and_still_consumes_capital() {
        let root = tempfile::tempdir().unwrap();
        let directory = root.path().join("controller");
        let journal = unresolved_journal();
        let mut store = Store {
            _owner: acquire_owner(&directory).unwrap(),
            directory: directory.clone(),
            journal,
            ready: true,
        };
        store.persist().unwrap();
        let result: Result<(), String> = store.change(|j| {
            j.next_funding += 1;
            Err("rejected transition".into())
        });
        assert!(result.is_err());
        assert_eq!(store.journal.next_funding, 2);
        assert!(
            store.ready,
            "rejected mutation preserves the last committed state"
        );
        assert!(acquire_owner(&directory).is_err());
        drop(store);
        let mut journal: Journal =
            serde_json::from_slice(&std::fs::read(directory.join("controller.json")).unwrap())
                .unwrap();
        Controller::validate_journal(&journal, &journal.policy, journal.local).unwrap();
        assert!(journal.funding["test-1"].funded.is_none());
        let mut second = journal.funding["test-1"].clone();
        second.id = "test-2".into();
        second.provider = NodeAddr::from_bytes([3; 16]);
        journal.next_funding = 3;
        journal.funding.insert(second.id.clone(), second);
        assert_eq!(
            Controller::validate_journal(&journal, &journal.policy, journal.local),
            Err("capital budget exceeded".into()),
            "an unresolved mint operation still locks its whole intended capacity"
        );
    }

    #[test]
    fn reload_rejects_reused_funding_sequence_changed_policy_and_owner() {
        let mut journal = unresolved_journal();
        let mut changed = journal.policy.clone();
        changed.max_locked_sat += 32;
        assert!(Controller::validate_journal(&journal, &changed, journal.local).is_err());
        assert!(
            Controller::validate_journal(&journal, &journal.policy, NodeAddr::from_bytes([4; 16]))
                .is_err()
        );
        journal.next_funding = 1;
        assert_eq!(
            Controller::validate_journal(&journal, &journal.policy, journal.local),
            Err("invalid funding intent".into()),
            "recovery cannot overwrite an earlier idempotent wallet request"
        );
    }
}
