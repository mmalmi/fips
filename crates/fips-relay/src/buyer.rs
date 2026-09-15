//! Local spending evidence and durable authorization for adjacent purchases.
//!
//! Sending to a provider is not proof that it forwarded or delivered anything.
//! These records cap signatures; they do not establish fair exchange. A trusted
//! controller accepts quotes/funded channels and owns a finite lifetime budget.

use crate::{
    durable::{
        DurableError, DurableRelay, MAX_JOURNAL_BYTES, acquire_owner, write_private_journal,
    },
    ledger::{
        ChannelTerms, Contract, Limits, node_addr, session_fingerprint, validate_channel,
        validate_contract,
    },
};
use cashu_service::{CashuSpilmanPayment, CashuSpilmanPaymentSigner};
use fips_core::{
    NodeAddr,
    node::{
        ForwardingOutcome, ForwardingPolicy, ForwardingRequest, OriginatedSessionObserver,
        OriginatedSessionRequest,
    },
};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, HashSet},
    fs::File,
    io::Read,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::{SystemTime, UNIX_EPOCH},
};

#[derive(Debug, thiserror::Error)]
pub enum BuyerError {
    #[error(transparent)]
    Journal(#[from] DurableError),
    #[error("unknown or mismatched purchase agreement")]
    UnknownAgreement,
    #[error("invalid or conflicting purchase agreement")]
    InvalidAgreement,
    #[error("provider claim exceeds locally submitted evidence and approved advance")]
    UnearnedClaim,
    #[error("channel capacity or lifetime spending budget exhausted")]
    Budget,
    #[error("payment agreement expired")]
    Expired,
    #[error("bounded evidence storage exhausted")]
    Capacity,
    #[error("invalid buyer journal")]
    Format,
    #[error("payment signer failed: {0}")]
    Signer(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PurchaseChannel {
    #[serde(with = "node_addr")]
    provider: NodeAddr,
    terms: ChannelTerms,
    advance_msat: u64,
    authorized_sat: u64,
    active: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
enum AttemptOutcome {
    Pending,
    Submitted,
    Unconfirmed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Attempt {
    digest: [u8; 32],
    units: u64,
    outcome: AttemptOutcome,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PurchaseQuote {
    contract: Contract,
    active: bool,
    attempts: Vec<Attempt>,
    observed_units: u64,
    submitted_units: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct State {
    version: u16,
    #[serde(with = "node_addr")]
    local: NodeAddr,
    total_budget_sat: u64,
    limits: Limits,
    next_token: u64,
    channels: BTreeMap<String, PurchaseChannel>,
    quotes: BTreeMap<String, PurchaseQuote>,
    #[serde(skip)]
    seen: HashSet<(NodeAddr, [u8; 32])>,
    #[serde(skip)]
    pending: BTreeMap<u64, (String, usize)>,
}

impl State {
    fn evidence_msat(&self, id: &str) -> Option<u64> {
        self.channels.get(id)?;
        self.quotes
            .values()
            .filter(|q| q.contract.channel_id == id)
            .try_fold(0u64, |sum, q| {
                sum.checked_add(q.contract.price.amount_due_msat(q.submitted_units)?)
            })
    }

    fn validate_and_recover(&mut self) -> Result<(), BuyerError> {
        if self.version != 1
            || self.total_budget_sat == 0
            || self.next_token == 0
            || self.channels.len() > self.limits.max_channels
            || self.quotes.len() > self.limits.max_contracts
        {
            return Err(BuyerError::Format);
        }
        self.seen.clear();
        self.pending.clear();
        let mut active_channels = HashSet::new();
        let mut active_quotes = HashSet::new();
        let mut total = 0u64;
        for (id, c) in &self.channels {
            let capacity = validate_channel(&c.terms).map_err(|_| BuyerError::Format)?;
            if id != &c.terms.id
                || c.terms.buyer != self.local
                || c.provider == self.local
                || c.advance_msat > capacity
                || c.authorized_sat > c.terms.capacity_sat
                || (c.active && !active_channels.insert((c.provider, c.terms.mint_url.clone())))
            {
                return Err(BuyerError::Format);
            }
            total = total
                .checked_add(c.authorized_sat)
                .ok_or(BuyerError::Format)?;
        }
        if total > self.total_budget_sat {
            return Err(BuyerError::Format);
        }
        for (id, q) in &mut self.quotes {
            let c = self
                .channels
                .get(&q.contract.channel_id)
                .ok_or(BuyerError::Format)?;
            validate_contract(&q.contract, &c.terms).map_err(|_| BuyerError::Format)?;
            if id != &q.contract.id
                || q.contract.destination == c.provider
                || q.attempts.len() > self.limits.max_packets_per_contract
                || (q.active
                    && (!c.active || !active_quotes.insert((c.provider, q.contract.destination))))
            {
                return Err(BuyerError::Format);
            }
            let (mut observed, mut submitted) = (0u64, 0u64);
            for a in &mut q.attempts {
                if a.units == 0 || !self.seen.insert((c.provider, a.digest)) {
                    return Err(BuyerError::Format);
                }
                observed = observed.checked_add(a.units).ok_or(BuyerError::Format)?;
                if a.outcome == AttemptOutcome::Submitted {
                    submitted = submitted.checked_add(a.units).ok_or(BuyerError::Format)?;
                } else {
                    a.outcome = AttemptOutcome::Unconfirmed;
                }
            }
            if observed != q.observed_units
                || submitted != q.submitted_units
                || observed > q.contract.max_units
            {
                return Err(BuyerError::Format);
            }
        }
        for (id, c) in &self.channels {
            let maximum = self
                .evidence_msat(id)
                .ok_or(BuyerError::Format)?
                .saturating_add(c.advance_msat)
                .div_ceil(1_000);
            if c.authorized_sat > maximum {
                return Err(BuyerError::Format);
            }
        }
        Ok(())
    }
}

/// All methods except observer callbacks and metric reads belong on a blocking
/// controller worker. No disk/signature work runs while holding the packet-state
/// mutex. A signature is requested only after its maximum obligation is durable.
/// Never bypass this authorizer with the same funded wallet/channel.
#[derive(Debug)]
pub struct BuyerAuthorizer {
    directory: PathBuf,
    state: Mutex<State>,
    writer_ready: Mutex<bool>,
    _owner: File,
}

impl BuyerAuthorizer {
    pub fn create(
        directory: &Path,
        local: NodeAddr,
        total_budget_sat: u64,
        limits: Limits,
    ) -> Result<Self, BuyerError> {
        if total_budget_sat == 0 {
            return Err(BuyerError::Budget);
        }
        let owner = acquire_owner(directory)?;
        if directory
            .join("buyer.json")
            .try_exists()
            .map_err(DurableError::Io)?
        {
            return Err(DurableError::InUse.into());
        }
        let buyer = Self {
            directory: directory.into(),
            state: Mutex::new(State {
                version: 1,
                local,
                total_budget_sat,
                limits,
                next_token: 1,
                channels: BTreeMap::new(),
                quotes: BTreeMap::new(),
                seen: HashSet::new(),
                pending: BTreeMap::new(),
            }),
            writer_ready: Mutex::new(true),
            _owner: owner,
        };
        buyer.checkpoint()?;
        Ok(buyer)
    }

    pub fn load(directory: &Path) -> Result<Self, BuyerError> {
        let owner = acquire_owner(directory)?;
        let file = File::open(directory.join("buyer.json")).map_err(DurableError::Io)?;
        if file.metadata().map_err(DurableError::Io)?.len() > MAX_JOURNAL_BYTES {
            return Err(BuyerError::Format);
        }
        let mut bytes = Vec::new();
        file.take(MAX_JOURNAL_BYTES + 1)
            .read_to_end(&mut bytes)
            .map_err(DurableError::Io)?;
        if bytes.len() as u64 > MAX_JOURNAL_BYTES {
            return Err(BuyerError::Format);
        }
        let mut state: State = serde_json::from_slice(&bytes).map_err(|_| BuyerError::Format)?;
        state.validate_and_recover()?;
        let buyer = Self {
            directory: directory.into(),
            state: Mutex::new(state),
            writer_ready: Mutex::new(true),
            _owner: owner,
        };
        buyer.checkpoint()?;
        Ok(buyer)
    }

    /// Trusted acceptance, separate from an untrusted provider's usage report.
    /// A funded channel starts at zero; any explicit advance is a total allowance
    /// for this channel, never a per-quote/per-update allowance.
    pub fn accept_channel(
        &self,
        provider: NodeAddr,
        terms: ChannelTerms,
        advance_msat: u64,
    ) -> Result<(), BuyerError> {
        let capacity = validate_channel(&terms).map_err(|_| BuyerError::InvalidAgreement)?;
        self.change(|state| {
            if terms.buyer != state.local || provider == state.local || advance_msat > capacity {
                return Err(BuyerError::InvalidAgreement);
            }
            if let Some(c) = state.channels.get(&terms.id) {
                return if c.provider == provider
                    && c.terms == terms
                    && c.advance_msat == advance_msat
                {
                    Ok(())
                } else {
                    Err(BuyerError::InvalidAgreement)
                };
            }
            if state.channels.len() >= state.limits.max_channels {
                return Err(BuyerError::Capacity);
            }
            if state
                .channels
                .values()
                .any(|c| c.active && c.provider == provider && c.terms.mint_url == terms.mint_url)
            {
                return Err(BuyerError::InvalidAgreement);
            }
            state.channels.insert(
                terms.id.clone(),
                PurchaseChannel {
                    provider,
                    terms,
                    advance_msat,
                    authorized_sat: 0,
                    active: true,
                },
            );
            Ok(())
        })
    }

    pub fn accept_quote(&self, contract: Contract) -> Result<(), BuyerError> {
        self.change(|state| {
            let c = state
                .channels
                .get(&contract.channel_id)
                .ok_or(BuyerError::UnknownAgreement)?;
            validate_contract(&contract, &c.terms).map_err(|_| BuyerError::InvalidAgreement)?;
            if let Some(q) = state.quotes.get(&contract.id) {
                return if q.contract == contract {
                    Ok(())
                } else {
                    Err(BuyerError::InvalidAgreement)
                };
            }
            if !c.active || contract.destination == c.provider {
                return Err(BuyerError::InvalidAgreement);
            }
            if state.quotes.len() >= state.limits.max_contracts {
                return Err(BuyerError::Capacity);
            }
            if state.quotes.values().any(|q| {
                q.active
                    && q.contract.destination == contract.destination
                    && state.channels[&q.contract.channel_id].provider == c.provider
            }) {
                return Err(BuyerError::InvalidAgreement);
            }
            state.quotes.insert(
                contract.id.clone(),
                PurchaseQuote {
                    contract,
                    active: true,
                    attempts: Vec::new(),
                    observed_units: 0,
                    submitted_units: 0,
                },
            );
            Ok(())
        })
    }

    pub fn close_quote(&self, id: &str) -> Result<(), BuyerError> {
        self.change(|s| {
            s.quotes
                .get_mut(id)
                .ok_or(BuyerError::UnknownAgreement)?
                .active = false;
            Ok(())
        })
    }

    /// Stop new purchase evidence. Final claims can still be signed until expiry;
    /// mint settlement/refund and channel funding are separate controller work.
    pub fn close_channel(&self, id: &str) -> Result<(), BuyerError> {
        self.change(|s| {
            s.channels
                .get_mut(id)
                .ok_or(BuyerError::UnknownAgreement)?
                .active = false;
            for q in s
                .quotes
                .values_mut()
                .filter(|q| q.contract.channel_id == id)
            {
                q.active = false;
            }
            Ok(())
        })
    }

    pub fn checkpoint(&self) -> Result<(), BuyerError> {
        self.change(|_| Ok(()))
    }

    pub fn evidence_msat(&self, id: &str) -> Option<u64> {
        self.state.lock().ok()?.evidence_msat(id)
    }
    pub fn authorized_sat(&self, id: &str) -> Option<u64> {
        Some(self.state.lock().ok()?.channels.get(id)?.authorized_sat)
    }

    /// `provider` must be the authenticated peer carrying the response. All
    /// claims are cumulative. Rounding is once per channel total; stale claims
    /// can only reproduce an already reserved balance, never lower/reset it.
    /// The sat-denominated channel rounds up by less than one sat. Both capacity
    /// and lifetime budget include that rounding, including any approved advance.
    pub fn sign_claim(
        &self,
        signer: &impl CashuSpilmanPaymentSigner,
        provider: NodeAddr,
        id: &str,
        claimed_msat: u64,
        now: u64,
    ) -> Result<CashuSpilmanPayment, BuyerError> {
        self.sign_claim_inner(signer, provider, id, claimed_msat, now, false)
    }

    /// Reproduce a durable balance with funding attached. Failed persistence
    /// cannot be bypassed by reading an uncommitted in-memory authorization.
    pub fn reproduce_payment(
        &self,
        signer: &impl CashuSpilmanPaymentSigner,
        provider: NodeAddr,
        id: &str,
        now: u64,
    ) -> Result<CashuSpilmanPayment, BuyerError> {
        self.sign_claim_inner(signer, provider, id, 0, now, true)
    }

    fn sign_claim_inner(
        &self,
        signer: &impl CashuSpilmanPaymentSigner,
        provider: NodeAddr,
        id: &str,
        claimed_msat: u64,
        now: u64,
        include_funding: bool,
    ) -> Result<CashuSpilmanPayment, BuyerError> {
        let mut ready = self
            .writer_ready
            .lock()
            .map_err(|_| DurableError::Suspended)?;
        if !*ready {
            return Err(DurableError::Suspended.into());
        }
        let (balance, snapshot) = {
            let mut s = self.state.lock().map_err(|_| DurableError::Suspended)?;
            let c = s
                .channels
                .get(id)
                .filter(|c| c.provider == provider)
                .ok_or(BuyerError::UnknownAgreement)?;
            if now >= c.terms.expires_unix {
                return Err(BuyerError::Expired);
            }
            let evidence = s.evidence_msat(id).ok_or(BuyerError::Format)?;
            if claimed_msat > evidence.saturating_add(c.advance_msat) {
                return Err(BuyerError::UnearnedClaim);
            }
            let balance = claimed_msat.div_ceil(1_000).max(c.authorized_sat);
            let total = s
                .channels
                .values()
                .try_fold(0u64, |sum, c| sum.checked_add(c.authorized_sat))
                .ok_or(BuyerError::Budget)?;
            if balance > c.terms.capacity_sat
                || total
                    .checked_add(balance - c.authorized_sat)
                    .is_none_or(|n| n > s.total_budget_sat)
            {
                return Err(BuyerError::Budget);
            }
            s.channels
                .get_mut(id)
                .expect("known channel")
                .authorized_sat = balance;
            (balance, s.clone())
        };
        self.persist(&snapshot, &mut ready)?;
        let payment = signer
            .sign_cashu_spilman_payment(id, balance, include_funding)
            .map_err(BuyerError::Signer)?;
        if payment.channel_id != id || payment.balance != balance {
            return Err(BuyerError::Signer(
                "signer returned a mismatched payment".into(),
            ));
        }
        Ok(payment)
    }

    fn change(
        &self,
        change: impl FnOnce(&mut State) -> Result<(), BuyerError>,
    ) -> Result<(), BuyerError> {
        let mut ready = self
            .writer_ready
            .lock()
            .map_err(|_| DurableError::Suspended)?;
        if !*ready {
            return Err(DurableError::Suspended.into());
        }
        let snapshot = {
            let mut state = self.state.lock().map_err(|_| DurableError::Suspended)?;
            change(&mut state)?;
            state.clone()
        };
        self.persist(&snapshot, &mut ready)
    }

    fn persist(&self, snapshot: &State, ready: &mut bool) -> Result<(), BuyerError> {
        *ready = false;
        let bytes = serde_json::to_vec(snapshot).map_err(|_| BuyerError::Format)?;
        write_private_journal(&self.directory, "buyer.json", &bytes)?;
        *ready = true;
        Ok(())
    }

    fn begin(&self, request: &OriginatedSessionRequest<'_>, local_only: bool) -> Option<u64> {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).ok()?.as_secs();
        let mut s = self.state.lock().ok()?;
        if (local_only && request.source != s.local)
            || request.next_hop == request.destination
            || request.session_payload.is_empty()
            || s.pending.len() >= s.limits.max_pending
        {
            return None;
        }
        let digest =
            session_fingerprint(request.source, request.destination, request.session_payload);
        if s.seen.contains(&(request.next_hop, digest)) {
            return None;
        }
        let id = s
            .quotes
            .iter()
            .find(|(_, q)| {
                let c = &s.channels[&q.contract.channel_id];
                q.active
                    && c.active
                    && c.provider == request.next_hop
                    && q.contract.destination == request.destination
                    && now < q.contract.expires_unix
                    && now < c.terms.expires_unix
            })?
            .0
            .clone();
        let limit = s.limits.max_packets_per_contract;
        let token = s.next_token;
        let next_token = token.checked_add(1)?;
        let q = s.quotes.get_mut(&id)?;
        let units = u64::try_from(request.session_payload.len()).ok()?;
        let observed = q.observed_units.checked_add(units)?;
        if q.attempts.len() >= limit || observed > q.contract.max_units {
            return None;
        }
        q.observed_units = observed;
        let index = q.attempts.len();
        q.attempts.push(Attempt {
            digest,
            units,
            outcome: AttemptOutcome::Pending,
        });
        s.pending.insert(token, (id, index));
        s.seen.insert((request.next_hop, digest));
        s.next_token = next_token;
        Some(token)
    }
}

impl OriginatedSessionObserver for BuyerAuthorizer {
    fn observe(&self, request: &OriginatedSessionRequest<'_>) -> Option<u64> {
        self.begin(request, true)
    }
    fn complete(&self, token: u64, outcome: ForwardingOutcome) {
        let Ok(mut s) = self.state.lock() else {
            return;
        };
        let Some((id, index)) = s.pending.remove(&token) else {
            return;
        };
        let q = s.quotes.get_mut(&id).expect("retained quote");
        let a = &mut q.attempts[index];
        a.outcome = match outcome {
            ForwardingOutcome::Submitted => {
                q.submitted_units += a.units;
                AttemptOutcome::Submitted
            }
            ForwardingOutcome::Unconfirmed => AttemptOutcome::Unconfirmed,
        };
    }
}

/// Transit evidence can incur a downstream obligation only after the upstream
/// seller policy admits that packet. The received packet's claimed source alone
/// never authorizes a purchase. A direct final endpoint needs no onward channel.
#[derive(Debug)]
pub struct PaidForwarder {
    seller: Arc<DurableRelay>,
    buyer: Arc<BuyerAuthorizer>,
    pending: Mutex<BTreeMap<u64, Option<u64>>>,
}

impl PaidForwarder {
    pub fn new(seller: Arc<DurableRelay>, buyer: Arc<BuyerAuthorizer>) -> Self {
        Self {
            seller,
            buyer,
            pending: Mutex::new(BTreeMap::new()),
        }
    }
}

impl ForwardingPolicy for PaidForwarder {
    fn admit(&self, request: &ForwardingRequest<'_>) -> Option<u64> {
        let seller_token = self.seller.admit(request)?;
        let buyer_token = if request.next_hop == request.destination {
            None
        } else {
            let Some(token) = self.buyer.begin(
                &OriginatedSessionRequest {
                    source: request.source,
                    destination: request.destination,
                    next_hop: request.next_hop,
                    session_payload: request.session_payload,
                },
                false,
            ) else {
                self.seller
                    .complete(seller_token, ForwardingOutcome::Unconfirmed);
                return None;
            };
            Some(token)
        };
        self.pending
            .lock()
            .unwrap()
            .insert(seller_token, buyer_token);
        Some(seller_token)
    }
    fn complete(&self, token: u64, outcome: ForwardingOutcome) {
        if let Some(buyer_token) = self.pending.lock().unwrap().remove(&token) {
            self.seller.complete(token, outcome);
            if let Some(token) = buyer_token {
                self.buyer.complete(token, outcome);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{sync::mpsc, time::Duration};

    #[test]
    fn packet_evidence_does_not_wait_for_the_disk_or_signer_worker() {
        let root = tempfile::tempdir().unwrap();
        let local = NodeAddr::from_bytes([1; 16]);
        let provider = NodeAddr::from_bytes([2; 16]);
        let destination = NodeAddr::from_bytes([3; 16]);
        let buyer = Arc::new(
            BuyerAuthorizer::create(&root.path().join("buyer"), local, 10, Limits::default())
                .unwrap(),
        );
        let expires_unix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 600;
        buyer
            .accept_channel(
                provider,
                ChannelTerms {
                    id: "channel".into(),
                    buyer: local,
                    mint_url: "http://test.invalid".into(),
                    expires_unix,
                    capacity_sat: 10,
                    grace_msat: 100,
                },
                0,
            )
            .unwrap();
        buyer
            .accept_quote(Contract {
                id: "quote".into(),
                channel_id: "channel".into(),
                destination,
                next_hop: destination,
                expires_unix,
                price: crate::ledger::BytePrice {
                    msat: 1,
                    per_bytes: 1,
                },
                max_units: 100,
            })
            .unwrap();
        let guard = buyer.writer_ready.lock().unwrap();
        let worker = buyer.clone();
        let (sent, received) = mpsc::channel();
        let thread = std::thread::spawn(move || {
            let token = worker
                .observe(&OriginatedSessionRequest {
                    source: local,
                    destination,
                    next_hop: provider,
                    session_payload: b"packet",
                })
                .unwrap();
            worker.complete(token, ForwardingOutcome::Submitted);
            sent.send(worker.evidence_msat("channel")).unwrap();
        });
        assert_eq!(
            received.recv_timeout(Duration::from_secs(1)).unwrap(),
            Some(6)
        );
        drop(guard);
        thread.join().unwrap();
    }
}
