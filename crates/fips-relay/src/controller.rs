//! Automatic adjacent purchases with durable funding/acceptance intent.
//!
//! Configure a test wallet, mint and finite capital policy explicitly. Quotes
//! alone never authorize spending. An application buys a route, or a provider
//! verifies upstream funding before buying the retained onward offer. Peer-control
//! awaits never hold the wallet or journal lock, preventing cross-route deadlock.

use crate::{
    buyer::BuyerAuthorizer,
    control_transport::{ControlTransport, IncomingRequest, MAX_RECORD_BYTES},
    durable::{DurableRelay, MAX_JOURNAL_BYTES, acquire_owner, write_private_journal},
    ledger::{ChannelTerms, Contract, node_addr, validate_channel, validate_contract},
    payment_control::{PaymentControl, PaymentRequest, PaymentResponse},
    route_quotes::{RouteOffer, RouteQuotes, contract_from_offer},
};
use cashu_service::{CashuSpilmanPayment, FileSpilmanPaymentReceiver, FileSpilmanPaymentSigner};
use fips_core::{FipsEndpoint, Identity, NodeAddr, PeerIdentity};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, HashSet},
    fs::File,
    io::Read,
    path::{Path, PathBuf},
    sync::{Arc, Mutex, Weak},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::{
    sync::{Mutex as AsyncMutex, Semaphore, mpsc, watch},
    task::{JoinHandle, JoinSet},
};

mod cadence;
pub use cadence::PaymentCadence;
mod acceptance;
mod capital;
mod channel_history;
mod funding;
pub use capital::FundingBudget;
mod journal;
mod retirement;
use retirement::History;
mod payments;
mod purchase_state;
mod purchases;
mod runtime;
mod source_selection;
pub use runtime::ControllerTasks;

const MAX_CHANNELS: usize = 16;
const MAX_ROUTES: usize = 32;

mod seller_history;
mod settlement;
mod settlement_release;
pub use settlement::SettlementReport;
use settlement::{BuyerSettlement, SellerSettlement};

mod renewal;
use renewal::Renewal;
pub use renewal::RenewalPolicy;

mod routes;
use routes::RouteChange;

mod refresh;
pub use refresh::WatchedRoute;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ControllerPolicy {
    pub mint_url: String,
    pub channel_capacity_sat: u64,
    /// Bounds unresolved reservations and actual wallet debits. Confirmed local
    /// wallet refund recovery releases the channel's locked capital.
    pub max_locked_sat: u64,
    /// Maximum token reserve, rounding and wallet fees above channel capacity.
    pub max_funding_overhead_sat: u64,
    /// Lifetime wallet debits minus verified refunds, including pending reservations.
    pub max_wallet_spend_sat: u64,
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

/// A wholly free path has an expiring permission, never a payment channel.
pub enum RouteAccess {
    Paid(Purchase),
    Free(RouteOffer),
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
struct Funded {
    terms: ChannelTerms,
    opening: CashuSpilmanPayment,
    wallet_operation_id: String,
    wallet_cost: cashu_service::CashuSendCost,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
struct FundingIntent {
    id: String,
    #[serde(with = "node_addr")]
    provider: NodeAddr,
    receiver_pubkey_hex: String,
    capacity_sat: u64,
    max_wallet_debit_sat: u64,
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
    #[serde(default)]
    replacement_retired: bool,
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
    #[serde(default)]
    history: Option<History>,
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
        if !self.ready || self.journal.history.as_ref().is_some_and(History::pending) {
            return Err("controller journal suspended".into());
        }
        let mut candidate = self.journal.clone();
        let result = job(&mut candidate)?;
        Controller::validate_capital(&candidate)?;
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
    ReleaseSettlement {
        channel_id: String,
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
    SettlementReleased {
        channel_id: String,
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
    channel_work: Mutex<BTreeMap<String, Weak<AsyncMutex<()>>>>,
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
                version: 3,
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
                history: Some(History::default()),
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
        let mut store = Store {
            directory: directory.into(),
            journal,
            ready: true,
            _owner: owner,
        };
        store.resume_retirement(&services.buyer, &services.seller)?;
        store.resume_sales(&services.seller)?;
        Self::reconcile_route_stops(&store.journal, &services)?;
        Ok(Self::with_store(policy, services, store))
    }

    fn with_store(policy: ControllerPolicy, services: ControllerServices, store: Store) -> Self {
        Self {
            services,
            policy,
            store: Arc::new(Mutex::new(store)),
            wallet: Arc::new(AsyncMutex::new(())),
            channel_work: Mutex::new(BTreeMap::new()),
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
            || policy
                .channel_capacity_sat
                .checked_add(policy.max_funding_overhead_sat)
                .is_none_or(|max| max > policy.max_locked_sat || max > policy.max_wallet_spend_sat)
            || !(60..=86_400).contains(&policy.channel_lifetime_secs)
            || policy.mint_url.is_empty()
            || policy.mint_url.len() > 512
            || policy.mint_url.ends_with('/')
        {
            return Err("invalid controller capital policy".into());
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
                if let Some(history) = &j.history {
                    ids.extend(history.sellers.keys().cloned());
                }
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

    pub fn last_error(&self) -> Option<String> {
        self.last_error.lock().unwrap().clone()
    }
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod transition_tests;

#[cfg(test)]
mod purchase_state_tests;

#[cfg(test)]
mod retirement_tests;
