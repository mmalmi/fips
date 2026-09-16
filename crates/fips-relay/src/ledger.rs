//! Bounded per-neighbor channels shared by destination-specific route quotes.
//!
//! Restoring evidence never activates credit. The controller must durably reserve
//! its exposure window before activation and reconcile it after a process crash.

mod admission;
mod history;
mod recovery;
mod retirement;
pub use history::RetiredRouteEvidence;

use fips_core::{
    NodeAddr,
    node::{ForwardingOutcome, ForwardingPolicy, ForwardingRequest},
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    sync::Mutex,
    time::{SystemTime, UNIX_EPOCH},
};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChannelTerms {
    pub id: String,
    #[serde(with = "node_addr")]
    pub buyer: NodeAddr,
    pub mint_url: String,
    pub expires_unix: u64,
    pub capacity_sat: u64,
    /// Shared unpaid exposure across every destination using this channel.
    pub grace_msat: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct BytePrice {
    pub msat: u64,
    pub per_bytes: u64,
}

impl BytePrice {
    pub fn amount_due_msat(self, bytes: u64) -> Option<u64> {
        if self.per_bytes == 0 {
            return None;
        }
        u64::try_from(
            (u128::from(bytes) * u128::from(self.msat)).div_ceil(u128::from(self.per_bytes)),
        )
        .ok()
    }
}

/// Immutable unit of service accepted with each route agreement.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BillingBasis {
    /// Original prototype semantics. Retains ciphertext hashes and its limit.
    #[default]
    UniqueSessionEnvelope,
    /// Each native authenticated admission is a new forwarding attempt. Link
    /// replay rejection belongs to FIPS; completion tokens prevent double count.
    ForwardingAttempt,
    /// Per-attempt accounting with strictly shaped, bounded FSP handshakes
    /// excluded from paid evidence. Requires bootstrap-capable forwarding.
    ForwardingData,
}

impl BillingBasis {
    pub fn has_free_handshakes(&self) -> bool {
        *self == Self::ForwardingData
    }
    pub fn is_legacy(&self) -> bool {
        *self == Self::UniqueSessionEnvelope
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Contract {
    pub id: String,
    pub channel_id: String,
    #[serde(with = "node_addr")]
    pub destination: NodeAddr,
    #[serde(with = "node_addr")]
    pub next_hop: NodeAddr,
    pub expires_unix: u64,
    pub price: BytePrice,
    pub max_units: u64,
    #[serde(default, skip_serializing_if = "BillingBasis::is_legacy")]
    pub billing: BillingBasis,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct Limits {
    pub max_channels: usize,
    pub max_contracts: usize,
    pub max_packets_per_contract: usize,
    pub max_pending: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_channels: 16,
            max_contracts: 32,
            max_packets_per_contract: 4_096,
            max_pending: 1_024,
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Usage {
    /// Includes pending and uncertain attempts, preventing credit reuse.
    pub reserved_units: u64,
    pub submitted_units: u64,
    pub unconfirmed_units: u64,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChannelUsage {
    pub reserved_msat: u64,
    pub submitted_msat: u64,
    /// Conservatively consumed crash window with no retained packet evidence.
    /// This amount is never included in a payment claim.
    pub lost_msat: u64,
    /// Verified cumulative signed payment, not total funded capacity.
    pub paid_msat: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
enum AttemptState {
    Pending,
    Submitted,
    Unconfirmed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Attempt {
    token: u64,
    units: u64,
    state: AttemptState,
}

#[derive(Debug)]
struct Account {
    contract: Contract,
    usage: Usage,
    attempts: BTreeMap<[u8; 32], Attempt>,
    completed: Usage,
    active: bool,
}

#[derive(Debug)]
struct Channel {
    terms: ChannelTerms,
    retired: RetiredRouteEvidence,
    usage: ChannelUsage,
    active: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Snapshot {
    version: u16,
    limits: Limits,
    next_token: u64,
    pub(crate) channels: Vec<ChannelSnapshot>,
    pub(crate) accounts: Vec<AccountSnapshot>,
}

impl Snapshot {
    pub(crate) fn reservation_limit(&self, id: &str) -> Option<u64> {
        let channel = self.channels.iter().find(|c| c.terms.id == id)?;
        relationship_reservation_limit(
            &channel.terms,
            channel.usage.paid_msat,
            self.channels.iter().map(|c| (&c.terms, c.usage)),
        )
    }
}

/// Older closed channels keep consuming the relationship's unpaid allowance.
/// Their missing/unconfirmed submissions are never added to a new payment bill.
fn relationship_reservation_limit<'a>(
    terms: &ChannelTerms,
    paid_msat: u64,
    channels: impl Iterator<Item = (&'a ChannelTerms, ChannelUsage)>,
) -> Option<u64> {
    let carried = channels
        .filter(|(old, _)| {
            old.id != terms.id && old.buyer == terms.buyer && old.mint_url == terms.mint_url
        })
        .try_fold(0u64, |sum, (_, usage)| {
            sum.checked_add(usage.reserved_msat.saturating_sub(usage.paid_msat))
        })?;
    Some(
        terms.capacity_sat.checked_mul(1_000)?.min(
            paid_msat
                .saturating_add(terms.grace_msat)
                .saturating_sub(carried),
        ),
    )
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct ChannelSnapshot {
    #[serde(default)]
    pub(crate) retired: Option<RetiredRouteEvidence>,
    pub(crate) terms: ChannelTerms,
    pub(crate) usage: ChannelUsage,
    pub(crate) active: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct AccountSnapshot {
    pub(crate) contract: Contract,
    usage: Usage,
    pub(crate) active: bool,
    // Arrays of tuples keep JSON encoding valid for binary digest keys.
    attempts: Vec<([u8; 32], Attempt)>,
    #[serde(default)]
    completed: Usage,
}

#[derive(Debug, Default)]
struct State {
    seen: std::collections::HashSet<(NodeAddr, [u8; 32])>,
    channels: BTreeMap<String, Channel>,
    accounts: BTreeMap<String, Account>,
    pending: BTreeMap<u64, (String, [u8; 32])>,
    next_token: u64,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum LedgerError {
    #[error("invalid channel or forwarding agreement")]
    InvalidContract,
    #[error("identifier or active buyer/destination already bound")]
    AlreadyBound,
    #[error("previous neighbor channel still has reserved unpaid exposure")]
    UnsettledChannel,
    #[error("accounting capacity exhausted")]
    Capacity,
    #[error("unknown contract or channel")]
    UnknownContract,
    #[error("payment decreased or exceeded channel capacity")]
    InvalidPayment,
    #[error("invalid accounting snapshot")]
    InvalidSnapshot,
}

/// `open_channel_verified` and `apply_verified_balance` accept trusted controller
/// output only. Unverified wire claims must never reach these methods.
#[derive(Debug)]
pub struct RelayLedger {
    limits: Limits,
    state: Mutex<State>,
}

impl RelayLedger {
    pub fn new(limits: Limits) -> Self {
        Self {
            limits,
            state: Mutex::new(State::default()),
        }
    }

    pub fn open_channel_verified(
        &self,
        terms: ChannelTerms,
        paid_msat: u64,
    ) -> Result<(), LedgerError> {
        let capacity = validate_channel(&terms)?;
        if paid_msat > capacity {
            return Err(LedgerError::InvalidPayment);
        }
        let mut state = self.state.lock().unwrap();
        if let Some(existing) = state.channels.get(&terms.id) {
            if existing.terms == terms && paid_msat <= existing.usage.paid_msat {
                return Ok(());
            }
            return Err(LedgerError::AlreadyBound);
        }
        let mut unpaid = false;
        for old in state
            .channels
            .values()
            .filter(|c| c.terms.buyer == terms.buyer && c.terms.mint_url == terms.mint_url)
        {
            if old.active {
                return Err(LedgerError::AlreadyBound);
            }
            unpaid |= old.usage.reserved_msat > old.usage.paid_msat;
        }
        let available = relationship_reservation_limit(
            &terms,
            paid_msat,
            state.channels.values().map(|c| (&c.terms, c.usage)),
        )
        .ok_or(LedgerError::Capacity)?;
        if unpaid && available == 0 {
            return Err(LedgerError::UnsettledChannel);
        }
        if state.channels.len() >= self.limits.max_channels {
            return Err(LedgerError::Capacity);
        }
        state.channels.insert(
            terms.id.clone(),
            Channel {
                terms,
                retired: RetiredRouteEvidence::default(),
                usage: ChannelUsage {
                    paid_msat,
                    ..ChannelUsage::default()
                },
                active: true,
            },
        );
        Ok(())
    }

    /// Quotes share their neighbor channel's credit and grace. Creating or
    /// replacing a quote cannot create a new free or unpaid allowance.
    pub fn add_contract(&self, contract: Contract) -> Result<(), LedgerError> {
        let mut state = self.state.lock().unwrap();
        let channel = state
            .channels
            .get(&contract.channel_id)
            .ok_or(LedgerError::UnknownContract)?;
        validate_contract(&contract, &channel.terms)?;
        if channel.retired.rejects(contract.expires_unix) {
            return Err(LedgerError::InvalidContract);
        }
        if let Some(existing) = state.accounts.get(&contract.id) {
            return if existing.contract == contract {
                Ok(())
            } else {
                Err(LedgerError::AlreadyBound)
            };
        }
        if !channel.active {
            return Err(LedgerError::InvalidContract);
        }
        if state.accounts.values().any(|a| {
            a.active
                && a.contract.destination == contract.destination
                && state.channels[&a.contract.channel_id].terms.buyer == channel.terms.buyer
        }) {
            return Err(LedgerError::AlreadyBound);
        }
        if state.accounts.len() >= self.limits.max_contracts {
            return Err(LedgerError::Capacity);
        }
        state.accounts.insert(
            contract.id.clone(),
            Account {
                contract,
                usage: Usage::default(),
                attempts: BTreeMap::new(),
                completed: Usage::default(),
                active: true,
            },
        );
        Ok(())
    }

    pub fn apply_verified_balance(
        &self,
        channel_id: &str,
        paid_msat: u64,
    ) -> Result<(), LedgerError> {
        let mut state = self.state.lock().unwrap();
        let channel = state
            .channels
            .get_mut(channel_id)
            .ok_or(LedgerError::UnknownContract)?;
        if paid_msat < channel.usage.paid_msat || paid_msat > validate_channel(&channel.terms)? {
            return Err(LedgerError::InvalidPayment);
        }
        channel.usage.paid_msat = paid_msat;
        // Updates cannot reactivate a restored/closed channel.
        Ok(())
    }

    pub fn close_contract(&self, id: &str) -> Result<Usage, LedgerError> {
        let mut state = self.state.lock().unwrap();
        let account = state
            .accounts
            .get_mut(id)
            .ok_or(LedgerError::UnknownContract)?;
        account.active = false;
        Ok(account.usage)
    }

    pub fn close_channel(&self, id: &str) -> Result<ChannelUsage, LedgerError> {
        let mut state = self.state.lock().unwrap();
        let channel = state
            .channels
            .get_mut(id)
            .ok_or(LedgerError::UnknownContract)?;
        channel.active = false;
        let usage = channel.usage;
        for a in state
            .accounts
            .values_mut()
            .filter(|a| a.contract.channel_id == id)
        {
            a.active = false;
        }
        Ok(usage)
    }

    /// Stop service and freeze its final claim. Anything still awaiting a local
    /// transport outcome stays reserved and unconfirmed, even if it finishes
    /// later. Retained fingerprints continue to prevent replay after renewal.
    pub fn seal_channel(&self, id: &str) -> Result<ChannelUsage, LedgerError> {
        self.close_channel(id)?;
        let mut state = self.state.lock().unwrap();
        let mut sealed_tokens = Vec::new();
        for account in state
            .accounts
            .values_mut()
            .filter(|a| a.contract.channel_id == id)
        {
            for attempt in account.attempts.values_mut() {
                if attempt.state == AttemptState::Pending {
                    attempt.state = AttemptState::Unconfirmed;
                    account.usage.unconfirmed_units += attempt.units;
                    sealed_tokens.push(attempt.token);
                }
            }
            if !account.contract.billing.is_legacy() {
                account.completed = account.usage;
                account.attempts.clear();
            }
        }
        for token in sealed_tokens {
            state.pending.remove(&token);
        }
        Ok(state.channels[id].usage)
    }

    pub fn usage(&self, id: &str) -> Option<Usage> {
        self.state.lock().unwrap().accounts.get(id).map(|a| a.usage)
    }

    pub fn channel_usage(&self, id: &str) -> Option<ChannelUsage> {
        self.state.lock().unwrap().channels.get(id).map(|a| a.usage)
    }

    pub fn channel_terms(&self, id: &str) -> Option<ChannelTerms> {
        self.state
            .lock()
            .unwrap()
            .channels
            .get(id)
            .map(|a| a.terms.clone())
    }

    pub fn contract(&self, id: &str) -> Option<Contract> {
        self.state
            .lock()
            .unwrap()
            .accounts
            .get(id)
            .map(|a| a.contract.clone())
    }

    pub(crate) fn has_active_route(
        &self,
        buyer: NodeAddr,
        destination: NodeAddr,
        now: u64,
    ) -> bool {
        let state = self.state.lock().unwrap();
        state.accounts.values().any(|a| {
            let c = &state.channels[&a.contract.channel_id];
            a.active
                && c.active
                && c.terms.buyer == buyer
                && a.contract.destination == destination
                && a.contract.expires_unix > now
                && c.terms.expires_unix > now
        })
    }

    pub fn amount_due_msat(&self, id: &str) -> Option<u64> {
        self.state
            .lock()
            .unwrap()
            .accounts
            .get(id)
            .and_then(|a| a.contract.price.amount_due_msat(a.usage.submitted_units))
    }
}

fn fingerprint(request: &ForwardingRequest<'_>) -> [u8; 32] {
    session_fingerprint(request.source, request.destination, request.session_payload)
}

fn attempt_key(token: u64) -> [u8; 32] {
    let mut key = [0; 32];
    key[..8].copy_from_slice(&token.to_be_bytes());
    key
}

pub(crate) fn session_fingerprint(
    source: NodeAddr,
    destination: NodeAddr,
    payload: &[u8],
) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(b"fips-relay/session-attempt/1");
    hash.update(source.as_bytes());
    hash.update(destination.as_bytes());
    hash.update(payload);
    hash.finalize().into()
}

pub(crate) fn validate_channel(c: &ChannelTerms) -> Result<u64, LedgerError> {
    let cap = c
        .capacity_sat
        .checked_mul(1_000)
        .ok_or(LedgerError::InvalidContract)?;
    if c.id.is_empty()
        || c.id.len() > 128
        || c.mint_url.is_empty()
        || c.mint_url.len() > 512
        || c.mint_url.ends_with('/')
        || cap == 0
        || c.grace_msat > cap
    {
        return Err(LedgerError::InvalidContract);
    }
    Ok(cap)
}

pub(crate) fn validate_contract(c: &Contract, channel: &ChannelTerms) -> Result<(), LedgerError> {
    if c.id.is_empty()
        || c.id.len() > 128
        || c.max_units == 0
        || c.price.msat == 0
        || c.price.amount_due_msat(c.max_units).is_none()
        || c.next_hop == channel.buyer
        || c.expires_unix > channel.expires_unix
    {
        return Err(LedgerError::InvalidContract);
    }
    Ok(())
}

pub(crate) mod node_addr {
    use super::*;
    pub fn serialize<S: serde::Serializer>(
        address: &NodeAddr,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        address.as_bytes().serialize(serializer)
    }
    pub fn deserialize<'de, D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> Result<NodeAddr, D::Error> {
        <[u8; 16]>::deserialize(deserializer).map(NodeAddr::from_bytes)
    }
}
