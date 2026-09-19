//! Bounded control admission; authenticated adjacency is not spending authority.
use crate::controller::{ControlObligations, MAX_CONTROL_OBLIGATIONS};
use fips_core::{FipsEndpoint, NodeAddr, PeerIdentity};
use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use std::{
    collections::{HashMap, HashSet},
    sync::{Arc, Mutex, RwLock},
    time::{Duration, Instant},
};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

const ADMISSION_BURST: u32 = 16;
const ADMISSION_INTERVAL: Duration = Duration::from_millis(100);
const UNCONFIGURED_CONNECTIONS: usize = 8;
const OBLIGATION_CONNECTIONS: usize = 8;
const UNCONFIGURED_PEER_CONNECTIONS: usize = 4;
const AGGREGATE_BURST: u32 = 80;
const AGGREGATE_INTERVAL: Duration = Duration::from_micros(3125);
const UNCONFIGURED_IDENTITIES: usize = 64;
const OBLIGATION_IDENTITIES: usize = MAX_CONTROL_OBLIGATIONS;
const MEMBERSHIP_TIMEOUT: Duration = Duration::from_secs(1);

/// Whether bounded control also admits current authenticated adjacent peers.
/// Neither mode authorizes route purchases, forwarding or wallet spending.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NeighborAdmission {
    #[default]
    ConfiguredOnly,
    AuthenticatedAdjacent,
}

pub(crate) struct AdmissionBudget {
    updated: Instant,
    tokens: u32,
    burst: u32,
    interval: Duration,
}

impl AdmissionBudget {
    pub(crate) fn new(now: Instant) -> Self {
        Self::with_limits(now, ADMISSION_BURST, ADMISSION_INTERVAL)
    }

    fn with_limits(now: Instant, burst: u32, interval: Duration) -> Self {
        Self {
            updated: now,
            tokens: burst,
            burst,
            interval,
        }
    }

    fn available(&self, now: Instant) -> u32 {
        let intervals =
            now.saturating_duration_since(self.updated).as_nanos() / self.interval.as_nanos();
        self.tokens
            .saturating_add(intervals.min(u128::from(self.burst)) as u32)
            .min(self.burst)
    }

    pub(crate) fn allow(&mut self, now: Instant) -> bool {
        let elapsed = now.saturating_duration_since(self.updated);
        if elapsed >= self.interval {
            self.tokens = self.available(now);
            // Both internal intervals are below one second. Carry fractional
            // periods so regular payment epochs do not slowly lose capacity.
            let remainder = (elapsed.as_nanos() % self.interval.as_nanos()) as u64;
            self.updated = now - Duration::from_nanos(remainder);
        }
        if self.tokens == 0 {
            return false;
        }
        self.tokens -= 1;
        true
    }
}

struct PeerBudget {
    incoming: AdmissionBudget,
    outgoing: AdmissionBudget,
    active: usize,
    // Storage reservation only; current verified financial state selects the
    // request lane. Moving between storage pools never resets this budget.
    reserved: bool,
}

impl PeerBudget {
    fn idle_and_refilled(&self, now: Instant) -> bool {
        self.active == 0
            && self.incoming.available(now) == ADMISSION_BURST
            && self.outgoing.available(now) == ADMISSION_BURST
    }
}

struct AdmissionState {
    configured: HashMap<(NodeAddr, bool), AdmissionBudget>,
    aggregate: AdmissionBudget,
    obligation_aggregate: AdmissionBudget,
    peers: HashMap<NodeAddr, PeerBudget>,
}

impl AdmissionState {
    fn new(now: Instant) -> Self {
        Self {
            configured: HashMap::new(),
            aggregate: AdmissionBudget::with_limits(now, AGGREGATE_BURST, AGGREGATE_INTERVAL),
            obligation_aggregate: AdmissionBudget::with_limits(
                now,
                AGGREGATE_BURST,
                AGGREGATE_INTERVAL,
            ),
            peers: HashMap::new(),
        }
    }

    fn admit_peer(&mut self, peer: NodeAddr, outbound: bool, now: Instant, reserved: bool) -> bool {
        let limit = if reserved {
            OBLIGATION_IDENTITIES
        } else {
            UNCONFIGURED_IDENTITIES
        };
        let occupied = self
            .peers
            .values()
            .filter(|budget| budget.reserved == reserved)
            .count();
        if !self.peers.contains_key(&peer) && occupied >= limit {
            let Some(expired) = self.peers.iter().find_map(|(id, budget)| {
                (budget.reserved == reserved && budget.idle_and_refilled(now)).then_some(*id)
            }) else {
                return false;
            };
            self.peers.remove(&expired);
        }
        let budget = self.peers.entry(peer).or_insert_with(|| PeerBudget {
            incoming: AdmissionBudget::new(now),
            outgoing: AdmissionBudget::new(now),
            active: 0,
            reserved,
        });
        // Preserve a demoted/promoted identity's tokens and active permits even
        // if its destination storage pool is full. Idle, refilled records can
        // later be reclaimed by the same bounded eviction rule.
        if occupied < limit {
            budget.reserved = reserved;
        }
        if budget.active >= UNCONFIGURED_PEER_CONNECTIONS {
            return false;
        }
        let direction = if outbound {
            &mut budget.outgoing
        } else {
            &mut budget.incoming
        };
        if !direction.allow(now) {
            return false;
        }
        budget.active += 1;
        true
    }

    fn release_peer(&mut self, peer: NodeAddr) {
        if let Some(budget) = self.peers.get_mut(&peer) {
            budget.active -= 1;
        }
    }
}

/// One node's shared control budgets, reused across quote, acceptance and payment ports.
/// Dynamic membership is read from authenticated links, never from discovery advertisements.
pub struct ControlAdmission {
    endpoint: Arc<FipsEndpoint>,
    configured: HashSet<NodeAddr>,
    customer_network: Option<IpNet>,
    mode: NeighborAdmission,
    state: Mutex<AdmissionState>,
    unconfigured: Arc<Semaphore>,
    obligations: RwLock<Option<ControlObligations>>,
    obligation_slots: Arc<Semaphore>,
}

impl ControlAdmission {
    pub fn new(
        endpoint: Arc<FipsEndpoint>,
        neighbors: Vec<PeerIdentity>,
        customer_network: Option<IpNet>,
        mode: NeighborAdmission,
    ) -> Result<Arc<Self>, String> {
        if neighbors.len() > 64 {
            return Err("too many configured control neighbors".into());
        }
        Ok(Arc::new(Self {
            endpoint,
            configured: neighbors.iter().map(|peer| *peer.node_addr()).collect(),
            customer_network,
            mode,
            state: Mutex::new(AdmissionState::new(Instant::now())),
            unconfigured: Arc::new(Semaphore::new(UNCONFIGURED_CONNECTIONS)),
            obligations: RwLock::new(None),
            obligation_slots: Arc::new(Semaphore::new(OBLIGATION_CONNECTIONS)),
        }))
    }

    pub(crate) fn owns_endpoint(&self, endpoint: &Arc<FipsEndpoint>) -> bool {
        Arc::ptr_eq(&self.endpoint, endpoint)
    }

    pub(crate) fn bind_obligations(&self, obligations: ControlObligations) -> Result<(), String> {
        if obligations.local() != *self.endpoint.node_addr() {
            return Err("control obligations belong to another endpoint".into());
        }
        *self
            .obligations
            .write()
            .map_err(|_| "control obligations poisoned")? = Some(obligations);
        Ok(())
    }

    /// Current shared exchanges for an unconfigured identity, across all ports.
    /// This observation does not reserve capacity or grant control authority.
    pub fn active_unconfigured_exchanges(&self, peer: NodeAddr) -> usize {
        self.state
            .lock()
            .expect("control admission lock")
            .peers
            .get(&peer)
            .map_or(0, |budget| budget.active)
    }

    async fn classify(&self, peer: NodeAddr, outbound: bool) -> Result<PeerKind, String> {
        if self.configured.contains(&peer) {
            return Ok(PeerKind::Configured);
        }
        let peers = tokio::time::timeout(MEMBERSHIP_TIMEOUT, self.endpoint.peers())
            .await
            .map_err(|_| "control adjacency lookup timed out")?
            .map_err(|e| e.to_string())?;
        let connected = peers
            .iter()
            .find(|candidate| candidate.connected && candidate.node_addr == peer)
            .ok_or("not an authenticated adjacent peer")?;
        if self.customer_network.is_some_and(|network| {
            connected
                .authenticated_udp_restart_addr()
                .is_some_and(|address| network.contains(&address.ip()))
        }) {
            return if outbound {
                Err("customer control is inbound only".into())
            } else {
                Ok(PeerKind::Customer)
            };
        }
        if self.mode == NeighborAdmission::AuthenticatedAdjacent {
            Ok(PeerKind::Adjacent)
        } else {
            Err("not an authorized control neighbor".into())
        }
    }

    pub(super) async fn admit(
        self: &Arc<Self>,
        peer: PeerIdentity,
        outbound: bool,
    ) -> Result<AdmissionPermit, String> {
        let peer = *peer.node_addr();
        if self.configured.contains(&peer) {
            let mut state = self
                .state
                .lock()
                .map_err(|_| "control admission poisoned")?;
            if !state
                .configured
                .entry((peer, outbound))
                .or_insert_with(|| AdmissionBudget::new(Instant::now()))
                .allow(Instant::now())
            {
                return Err("control peer request budget exhausted".into());
            }
            return Ok(AdmissionPermit {
                admission: self.clone(),
                peer,
                outbound,
                kind: PeerKind::Configured,
                _slot: None,
            });
        }
        let reserved = self
            .obligations
            .read()
            .map_err(|_| "control obligations poisoned")?
            .as_ref()
            .is_some_and(|obligations| obligations.contains(peer));
        let pool = if reserved {
            &self.obligation_slots
        } else {
            &self.unconfigured
        };
        let slot = pool
            .clone()
            .try_acquire_owned()
            .map_err(|_| "unconfigured control capacity exhausted")?;
        // Charge before the local peer lookup so rotating remote identities also
        // cannot multiply snapshot work. This bucket spans ports and directions.
        {
            let mut state = self
                .state
                .lock()
                .map_err(|_| "control admission poisoned")?;
            let aggregate = if reserved {
                &mut state.obligation_aggregate
            } else {
                &mut state.aggregate
            };
            if !aggregate.allow(Instant::now()) {
                return Err("unconfigured control request budget exhausted".into());
            }
        }
        let kind = self.classify(peer, outbound).await?;
        if !self
            .state
            .lock()
            .map_err(|_| "control admission poisoned")?
            .admit_peer(peer, outbound, Instant::now(), reserved)
        {
            return Err("control peer request budget or identity capacity exhausted".into());
        }
        Ok(AdmissionPermit {
            admission: self.clone(),
            peer,
            outbound,
            kind,
            _slot: Some(slot),
        })
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum PeerKind {
    Configured,
    Customer,
    Adjacent,
}

pub(super) struct AdmissionPermit {
    admission: Arc<ControlAdmission>,
    peer: NodeAddr,
    outbound: bool,
    kind: PeerKind,
    _slot: Option<OwnedSemaphorePermit>,
}

impl AdmissionPermit {
    pub(super) async fn recheck(&self) -> Result<(), String> {
        if self.admission.classify(self.peer, self.outbound).await? != self.kind {
            return Err("control peer admission changed".into());
        }
        Ok(())
    }
}

impl Drop for AdmissionPermit {
    fn drop(&mut self) {
        if self.kind != PeerKind::Configured
            && let Ok(mut state) = self.admission.state.lock()
        {
            state.release_peer(self.peer);
        }
    }
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod membership_tests;
