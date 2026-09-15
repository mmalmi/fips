//! Bounded per-neighbor channels shared by destination-specific route quotes.
//!
//! Restoring evidence never activates credit. The controller must durably reserve
//! its exposure window before activation and reconcile it after a process crash.

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
    active: bool,
}

#[derive(Debug)]
struct Channel {
    terms: ChannelTerms,
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct ChannelSnapshot {
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
        for old in state
            .channels
            .values()
            .filter(|c| c.terms.buyer == terms.buyer && c.terms.mint_url == terms.mint_url)
        {
            if old.active {
                return Err(LedgerError::AlreadyBound);
            }
            if old.usage.reserved_msat > old.usage.paid_msat {
                return Err(LedgerError::UnsettledChannel);
            }
        }
        if state.channels.len() >= self.limits.max_channels {
            return Err(LedgerError::Capacity);
        }
        state.channels.insert(
            terms.id.clone(),
            Channel {
                terms,
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

    pub fn usage(&self, id: &str) -> Option<Usage> {
        self.state.lock().unwrap().accounts.get(id).map(|a| a.usage)
    }

    pub fn channel_usage(&self, id: &str) -> Option<ChannelUsage> {
        self.state.lock().unwrap().channels.get(id).map(|a| a.usage)
    }

    pub fn amount_due_msat(&self, id: &str) -> Option<u64> {
        self.state
            .lock()
            .unwrap()
            .accounts
            .get(id)
            .and_then(|a| a.contract.price.amount_due_msat(a.usage.submitted_units))
    }

    pub fn snapshot(&self) -> Snapshot {
        let state = self.state.lock().unwrap();
        Snapshot {
            version: 3,
            limits: self.limits,
            next_token: state.next_token,
            channels: state
                .channels
                .values()
                .map(|c| ChannelSnapshot {
                    terms: c.terms.clone(),
                    usage: c.usage,
                    active: c.active,
                })
                .collect(),
            accounts: state
                .accounts
                .values()
                .map(|a| AccountSnapshot {
                    contract: a.contract.clone(),
                    usage: a.usage,
                    active: a.active,
                    attempts: a.attempts.iter().map(|(k, v)| (*k, v.clone())).collect(),
                })
                .collect(),
        }
    }

    /// Retain all evidence but activate no traffic. A snapshot alone does not
    /// establish which sends occurred after its last durable checkpoint.
    pub fn restore(snapshot: Snapshot) -> Result<Self, LedgerError> {
        if snapshot.version != 3
            || snapshot.channels.len() > snapshot.limits.max_channels
            || snapshot.accounts.len() > snapshot.limits.max_contracts
        {
            return Err(LedgerError::InvalidSnapshot);
        }
        let mut state = State {
            next_token: snapshot.next_token,
            ..State::default()
        };
        let mut expected_channels = BTreeMap::new();
        for saved in snapshot.channels {
            let cap = validate_channel(&saved.terms).map_err(|_| LedgerError::InvalidSnapshot)?;
            if saved.usage.paid_msat > cap
                || saved.usage.reserved_msat > cap
                || saved.usage.reserved_msat
                    > saved.usage.paid_msat.saturating_add(saved.terms.grace_msat)
                || saved.usage.lost_msat > saved.usage.reserved_msat
                || state.channels.contains_key(&saved.terms.id)
            {
                return Err(LedgerError::InvalidSnapshot);
            }
            expected_channels.insert(saved.terms.id.clone(), saved.usage);
            state.channels.insert(
                saved.terms.id.clone(),
                Channel {
                    terms: saved.terms,
                    usage: ChannelUsage {
                        paid_msat: saved.usage.paid_msat,
                        reserved_msat: saved.usage.lost_msat,
                        lost_msat: saved.usage.lost_msat,
                        ..ChannelUsage::default()
                    },
                    active: false,
                },
            );
        }
        let mut tokens = std::collections::BTreeSet::new();
        for saved in snapshot.accounts {
            if state.accounts.contains_key(&saved.contract.id)
                || saved.attempts.len() > snapshot.limits.max_packets_per_contract
            {
                return Err(LedgerError::InvalidSnapshot);
            }
            let channel = state
                .channels
                .get_mut(&saved.contract.channel_id)
                .ok_or(LedgerError::InvalidSnapshot)?;
            validate_contract(&saved.contract, &channel.terms)
                .map_err(|_| LedgerError::InvalidSnapshot)?;
            let mut reserved = 0u64;
            let mut submitted = 0u64;
            let mut unconfirmed = 0u64;
            let mut previously_unconfirmed = 0u64;
            let mut attempts = BTreeMap::new();
            for (digest, mut attempt) in saved.attempts {
                if attempt.token == 0
                    || attempt.token > snapshot.next_token
                    || !tokens.insert(attempt.token)
                    || attempt.units == 0
                    || attempts.contains_key(&digest)
                {
                    return Err(LedgerError::InvalidSnapshot);
                }
                reserved = reserved
                    .checked_add(attempt.units)
                    .ok_or(LedgerError::InvalidSnapshot)?;
                if !state.seen.insert((channel.terms.buyer, digest)) {
                    return Err(LedgerError::InvalidSnapshot);
                }
                match attempt.state {
                    AttemptState::Submitted => submitted += attempt.units,
                    AttemptState::Pending => {
                        unconfirmed += attempt.units;
                        attempt.state = AttemptState::Unconfirmed;
                    }
                    AttemptState::Unconfirmed => {
                        unconfirmed += attempt.units;
                        previously_unconfirmed += attempt.units;
                    }
                }
                attempts.insert(digest, attempt);
            }
            if reserved != saved.usage.reserved_units
                || submitted != saved.usage.submitted_units
                || saved.usage.unconfirmed_units != previously_unconfirmed
                || reserved > saved.contract.max_units
            {
                return Err(LedgerError::InvalidSnapshot);
            }
            let reserved_cost = saved
                .contract
                .price
                .amount_due_msat(reserved)
                .ok_or(LedgerError::InvalidSnapshot)?;
            let submitted_cost = saved
                .contract
                .price
                .amount_due_msat(submitted)
                .ok_or(LedgerError::InvalidSnapshot)?;
            channel.usage.reserved_msat = channel
                .usage
                .reserved_msat
                .checked_add(reserved_cost)
                .ok_or(LedgerError::InvalidSnapshot)?;
            channel.usage.submitted_msat = channel
                .usage
                .submitted_msat
                .checked_add(submitted_cost)
                .ok_or(LedgerError::InvalidSnapshot)?;
            state.accounts.insert(
                saved.contract.id.clone(),
                Account {
                    contract: saved.contract,
                    usage: Usage {
                        unconfirmed_units: unconfirmed,
                        ..saved.usage
                    },
                    attempts,
                    active: false,
                },
            );
        }
        for (id, expected) in expected_channels {
            if state.channels[&id].usage != expected {
                return Err(LedgerError::InvalidSnapshot);
            }
        }
        Ok(Self {
            limits: snapshot.limits,
            state: Mutex::new(state),
        })
    }

    pub fn admit_at(&self, request: &ForwardingRequest<'_>, now_unix: u64) -> Option<u64> {
        self.admit_with_windows(request, now_unix, None)
    }

    pub(crate) fn admit_with_windows(
        &self,
        request: &ForwardingRequest<'_>,
        now_unix: u64,
        windows: Option<&BTreeMap<String, u64>>,
    ) -> Option<u64> {
        let units = u64::try_from(request.session_payload.len()).ok()?;
        if units == 0 {
            return None;
        }
        let mut state = self.state.lock().ok()?;
        if state.pending.len() >= self.limits.max_pending {
            return None;
        }
        let id = state
            .accounts
            .iter()
            .find(|(_, a)| {
                a.active
                    && a.contract.destination == request.destination
                    && state.channels[&a.contract.channel_id].terms.buyer
                        == *request.ingress.node_addr()
            })?
            .0
            .clone();
        let token = state.next_token.checked_add(1)?;
        let a = &state.accounts[&id];
        if a.contract.next_hop != request.next_hop
            || now_unix >= a.contract.expires_unix
            || a.attempts.len() >= self.limits.max_packets_per_contract
        {
            return None;
        }
        let digest = fingerprint(request);
        if state.seen.contains(&(*request.ingress.node_addr(), digest)) {
            return None;
        }
        let prospective = a.usage.reserved_units.checked_add(units)?;
        if prospective > a.contract.max_units {
            return None;
        }
        let incremental_cost = a
            .contract
            .price
            .amount_due_msat(prospective)?
            .checked_sub(a.contract.price.amount_due_msat(a.usage.reserved_units)?)?;
        let channel_id = a.contract.channel_id.clone();
        let channel = &state.channels[&channel_id];
        if !channel.active || now_unix >= channel.terms.expires_unix {
            return None;
        }
        let channel_reserved = channel.usage.reserved_msat.checked_add(incremental_cost)?;
        let limit = channel
            .usage
            .paid_msat
            .saturating_add(channel.terms.grace_msat)
            .min(channel.terms.capacity_sat.checked_mul(1_000)?)
            .min(windows.map_or(u64::MAX, |w| w.get(&channel_id).copied().unwrap_or(0)));
        if channel_reserved > limit {
            return None;
        }
        let a = state.accounts.get_mut(&id)?;
        a.usage.reserved_units = prospective;
        a.attempts.insert(
            digest,
            Attempt {
                token,
                units,
                state: AttemptState::Pending,
            },
        );
        state.channels.get_mut(&channel_id)?.usage.reserved_msat = channel_reserved;
        state.next_token = token;
        state.seen.insert((*request.ingress.node_addr(), digest));
        state.pending.insert(token, (id, digest));
        Some(token)
    }

    /// Used only by the durable wrapper, which must commit the recovered
    /// exposure and next windows before publishing this ledger to forwarding.
    pub(crate) fn recover_windows(
        snapshot: Snapshot,
        windows: &BTreeMap<String, u64>,
    ) -> Result<Self, LedgerError> {
        let recovered = Self::restore(snapshot.clone())?;
        let mut state = recovered.state.lock().unwrap();
        let mut buyers = std::collections::HashSet::new();
        let mut destinations = std::collections::HashSet::new();
        for saved in &snapshot.channels {
            let channel = state.channels.get_mut(&saved.terms.id).unwrap();
            if saved.active && !buyers.insert((saved.terms.buyer, saved.terms.mint_url.clone())) {
                return Err(LedgerError::InvalidSnapshot);
            }
            channel.active = saved.active;
        }
        for saved in &snapshot.accounts {
            let channel = &state.channels[&saved.contract.channel_id];
            if saved.active
                && (!channel.active
                    || !destinations.insert((channel.terms.buyer, saved.contract.destination)))
            {
                return Err(LedgerError::InvalidSnapshot);
            }
            state.accounts.get_mut(&saved.contract.id).unwrap().active = saved.active;
        }
        for (id, ceiling) in windows {
            let has_quote = state
                .accounts
                .values()
                .any(|a| a.active && &a.contract.channel_id == id);
            let channel = state
                .channels
                .get_mut(id)
                .ok_or(LedgerError::InvalidSnapshot)?;
            let max = validate_channel(&channel.terms)?.min(
                channel
                    .usage
                    .paid_msat
                    .saturating_add(channel.terms.grace_msat),
            );
            if !channel.active
                || !has_quote
                || *ceiling < channel.usage.reserved_msat
                || *ceiling > max
            {
                return Err(LedgerError::InvalidSnapshot);
            }
            let lost = ceiling - channel.usage.reserved_msat;
            channel.usage.lost_msat += lost;
            channel.usage.reserved_msat = *ceiling;
        }
        // Every active quote must have been bounded by a persisted window.
        if state
            .accounts
            .values()
            .any(|a| a.active && !windows.contains_key(&a.contract.channel_id))
        {
            return Err(LedgerError::InvalidSnapshot);
        }
        drop(state);
        Ok(recovered)
    }
}

impl ForwardingPolicy for RelayLedger {
    fn admit(&self, request: &ForwardingRequest<'_>) -> Option<u64> {
        self.admit_at(
            request,
            SystemTime::now().duration_since(UNIX_EPOCH).ok()?.as_secs(),
        )
    }

    fn complete(&self, token: u64, outcome: ForwardingOutcome) {
        let Ok(mut state) = self.state.lock() else {
            return;
        };
        let Some((id, digest)) = state.pending.remove(&token) else {
            return;
        };
        let a = state
            .accounts
            .get_mut(&id)
            .expect("pending account retained");
        let attempt = a
            .attempts
            .get_mut(&digest)
            .expect("pending digest retained");
        let old_cost = a
            .contract
            .price
            .amount_due_msat(a.usage.submitted_units)
            .expect("validated rate");
        match outcome {
            ForwardingOutcome::Submitted => {
                attempt.state = AttemptState::Submitted;
                a.usage.submitted_units += attempt.units;
            }
            ForwardingOutcome::Unconfirmed => {
                attempt.state = AttemptState::Unconfirmed;
                a.usage.unconfirmed_units += attempt.units;
            }
        }
        let delta = a
            .contract
            .price
            .amount_due_msat(a.usage.submitted_units)
            .expect("validated rate")
            - old_cost;
        let channel_id = a.contract.channel_id.clone();
        state
            .channels
            .get_mut(&channel_id)
            .expect("account channel retained")
            .usage
            .submitted_msat += delta;
    }
}

fn fingerprint(request: &ForwardingRequest<'_>) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(b"fips-relay/session-attempt/1");
    hash.update(request.source.as_bytes());
    hash.update(request.destination.as_bytes());
    hash.update(request.session_payload);
    hash.finalize().into()
}

fn validate_channel(c: &ChannelTerms) -> Result<u64, LedgerError> {
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

fn validate_contract(c: &Contract, channel: &ChannelTerms) -> Result<(), LedgerError> {
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

mod node_addr {
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
