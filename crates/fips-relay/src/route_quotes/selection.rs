//! Source-side offer selection. Transit continues using the native route planner.
use super::*;
use fips_core::SourceRouteQuality;
use serde::{Deserialize, Serialize};
use tokio::time::Instant;

mod recovery;

const MAX_DESTINATIONS: usize = 32;
const MAX_CANDIDATES: usize = 4;
const MAX_FAILED_PROVIDERS: usize = 16;
const MAX_OBSERVATIONS: usize = 16;
const QUOTE_SECONDS: u64 = 5;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct PriceSelectionPolicy {
    pub feedback_timeout_ms: u64,
    pub retry_after_ms: u64,
    pub trial_max_units: u64,
    pub min_improvement_percent: u8,
    pub max_loss_percent: u8,
    pub max_rtt_ms: u64,
}

impl Default for PriceSelectionPolicy {
    fn default() -> Self {
        Self {
            feedback_timeout_ms: 15_000,
            retry_after_ms: 60_000,
            trial_max_units: 32_768,
            min_improvement_percent: 10,
            max_loss_percent: 25,
            max_rtt_ms: 5_000,
        }
    }
}

impl PriceSelectionPolicy {
    pub fn validate(&self) -> Result<(), String> {
        if !(1_000..=60_000).contains(&self.feedback_timeout_ms)
            || !(self.feedback_timeout_ms..=3_600_000).contains(&self.retry_after_ms)
            || !(4_096..=1_048_576).contains(&self.trial_max_units)
            || self.min_improvement_percent > 50
            || self.max_loss_percent > 90
            || !(1..=60_000).contains(&self.max_rtt_ms)
        {
            return Err("invalid price selection policy".into());
        }
        Ok(())
    }
}

#[derive(Default)]
struct Destination {
    active: Option<RouteOffer>,
    restored: bool,
    observations: BTreeMap<NodeAddr, Observation>,
    failed: BTreeMap<NodeAddr, Instant>,
    cursor: usize,
    blocked_trial: Option<String>,
}

struct Observation {
    path: Vec<NodeAddr>,
    at: Instant,
    loss_ppm: u32,
}

enum SelectionStep {
    Retain(Box<RouteOffer>),
    Accept,
    Request {
        max_units: Option<u64>,
        reuse_unchanged: bool,
    },
}

impl Destination {
    fn selection_step(
        &self,
        selected: &RouteOffer,
        policy: &PriceSelectionPolicy,
        reuse_unchanged: bool,
        remaining: impl Fn(&RouteOffer) -> Option<u64>,
    ) -> Result<SelectionStep, String> {
        let new_trial = self.failed.contains_key(&selected.provider)
            || self.active.as_ref().is_none_or(|a| !same_path(a, selected));
        let working = self
            .working_loss(selected, policy, Instant::now())
            .is_some();
        if reuse_unchanged
            && !new_trial
            && !working
            && let Some(active) = &self.active
            && active.trial
            && active.price == selected.price
        {
            if active.expires_unix > unix_now()? {
                return Ok(SelectionStep::Retain(Box::new(active.clone())));
            }
            if active.price.msat == 0 {
                let units = remaining(active)
                    .filter(|units| *units > 0)
                    .ok_or("unknown free trial has no retained quota")?;
                return Ok(SelectionStep::Request {
                    max_units: Some(units),
                    reuse_unchanged: false,
                });
            }
        }
        let cap = if working {
            None
        } else if new_trial || !reuse_unchanged {
            Some(policy.trial_max_units)
        } else {
            Some(
                self.active
                    .as_ref()
                    .filter(|a| same_path(a, selected))
                    .map_or(policy.trial_max_units, |a| a.max_units),
            )
        };
        // A full offer cached before this trial may already be retired. Fresh
        // promotion avoids pinning a watch to that obsolete agreement.
        let promotion = working && self.active.as_ref().is_some_and(|active| active.trial);
        // Free quotas are ephemeral and may also have been replaced at either peer.
        let fresh_free = selected.price.msat == 0 && remaining(selected).is_none();
        if !reuse_unchanged
            || promotion
            || fresh_free
            || cap.is_some_and(|limit| selected.max_units > limit || new_trial)
        {
            Ok(SelectionStep::Request {
                max_units: cap,
                reuse_unchanged: reuse_unchanged && !new_trial && !promotion && !fresh_free,
            })
        } else {
            Ok(SelectionStep::Accept)
        }
    }

    fn observe(
        &mut self,
        quality: &SourceRouteQuality,
        policy: &PriceSelectionPolicy,
        now: Instant,
    ) -> Result<(), String> {
        if self.restored {
            // A restored accounting hint has not bound an accepted carrier.
            self.observations.clear();
            return Ok(());
        }
        let Some(active) = &self.active else {
            return Ok(());
        };
        if quality.next_hop != Some(active.provider) {
            self.observations.remove(&active.provider);
            return Ok(());
        }
        let loss = quality
            .loss_rate
            .filter(|v| v.is_finite() && (0.0..=1.0).contains(v));
        let rtt = quality.rtt_ms.filter(|v| v.is_finite() && *v >= 0.0);
        if quality.delivery_feedback_timed_out
            || (quality.has_recent_delivery_feedback
                && (loss.is_some_and(|v| v * 100.0 > f64::from(policy.max_loss_percent))
                    || rtt.is_some_and(|v| v > policy.max_rtt_ms as f64)))
        {
            self.fail(active.provider, policy, now)?;
        } else if quality.has_recent_delivery_feedback
            && let (Some(loss), Some(_rtt)) = (loss, rtt)
        {
            self.failed.remove(&active.provider);
            if self.observations.len() >= MAX_OBSERVATIONS
                && !self.observations.contains_key(&active.provider)
                && let Some(oldest) = self
                    .observations
                    .iter()
                    .min_by_key(|(_, sample)| sample.at)
                    .map(|(peer, _)| *peer)
            {
                self.observations.remove(&oldest);
            }
            self.observations.insert(
                active.provider,
                Observation {
                    path: active.path.clone(),
                    at: now,
                    loss_ppm: (loss * 1_000_000.0).round() as u32,
                },
            );
        } else {
            self.observations.remove(&active.provider);
        }
        Ok(())
    }

    fn fail(
        &mut self,
        provider: NodeAddr,
        policy: &PriceSelectionPolicy,
        now: Instant,
    ) -> Result<(), String> {
        if self.failed.len() >= MAX_FAILED_PROVIDERS && !self.failed.contains_key(&provider) {
            if let Some(old) = self
                .failed
                .iter()
                .find(|(_, until)| **until <= now)
                .map(|(p, _)| *p)
            {
                self.failed.remove(&old);
            } else {
                return Err("failed-provider state capacity".into());
            }
        }
        // Polling must not extend the retry delay. These are source-selection
        // exclusions, never native carrier penalties or assumed loss samples.
        self.failed
            .entry(provider)
            .or_insert(now + Duration::from_millis(policy.retry_after_ms));
        self.observations.remove(&provider);
        Ok(())
    }

    fn observe_admission(
        &mut self,
        blocked: bool,
        policy: &PriceSelectionPolicy,
        now: Instant,
    ) -> Result<(), String> {
        let Some(active) = &self.active else {
            self.blocked_trial = None;
            return Ok(());
        };
        if !active.trial || self.working_loss(active, policy, now).is_some() {
            self.blocked_trial = None;
        } else {
            if blocked {
                self.blocked_trial = Some(active.id.clone());
            }
            // Expired or missing admission evidence cannot erase a proven
            // denial and grant the same unknown trial a fresh allowance.
            if self.blocked_trial.as_ref() == Some(&active.id) {
                self.fail(active.provider, policy, now)?;
            }
        }
        Ok(())
    }

    fn working_loss(
        &self,
        offer: &RouteOffer,
        policy: &PriceSelectionPolicy,
        now: Instant,
    ) -> Option<u32> {
        self.active
            .as_ref()
            .filter(|a| same_path(a, offer))
            .and_then(|_| self.measured_loss(offer, policy, now))
    }

    fn measured_loss(
        &self,
        offer: &RouteOffer,
        policy: &PriceSelectionPolicy,
        now: Instant,
    ) -> Option<u32> {
        self.observations
            .get(&offer.provider)
            .filter(|sample| {
                sample.path == offer.path
                    && now.duration_since(sample.at)
                        <= Duration::from_millis(policy.feedback_timeout_ms)
            })
            .map(|sample| sample.loss_ppm)
    }

    fn delivery_ppm(
        &self,
        offer: &RouteOffer,
        policy: &PriceSelectionPolicy,
        now: Instant,
    ) -> u128 {
        // Unknown loss gives an optimistic cost for a quota-limited trial,
        // never an assumed zero-loss measurement qualifying a full allowance.
        let loss = self.measured_loss(offer, policy, now).unwrap_or(0);
        u128::from(1_000_000 - loss.min(999_999))
    }

    fn provider_eligible(&self, provider: NodeAddr, now: Instant) -> bool {
        // An exhausted unknown trial cannot refill itself merely by
        // outliving cooldown when no alternative has been activated.
        !self.active.as_ref().is_some_and(|active| {
            self.blocked_trial.as_ref() == Some(&active.id) && active.provider == provider
        }) && self.failed.get(&provider).is_none_or(|until| *until <= now)
    }

    fn candidate_indices(&mut self, peers: &[NodeAddr], now: Instant) -> Vec<usize> {
        // Excluded providers cannot win this round; do not await their quotes.
        let active = self.active.as_ref().map(|a| a.provider);
        let mut selected = Vec::new();
        if let Some(index) = peers
            .iter()
            .position(|peer| Some(*peer) == active && self.provider_eligible(*peer, now))
        {
            selected.push(index);
        }
        if !peers.is_empty() {
            for offset in 0..peers.len() {
                let index = (self.cursor + offset) % peers.len();
                if selected.len() == MAX_CANDIDATES {
                    break;
                }
                if Some(peers[index]) != active && self.provider_eligible(peers[index], now) {
                    selected.push(index);
                }
            }
            // Keep rotation over the original peer list as exclusions change.
            self.cursor = (self.cursor + MAX_CANDIDATES - 1) % peers.len();
        }
        selected
    }

    fn choose(
        &self,
        offers: Vec<RouteOffer>,
        policy: &PriceSelectionPolicy,
        now: Instant,
    ) -> Result<RouteOffer, String> {
        let mut eligible: Vec<_> = offers
            .into_iter()
            .filter(|o| self.provider_eligible(o.provider, now))
            .collect();
        // Cross-products preserve cost ties and the exact switching margin;
        // division before comparison can make equal savings look sufficient.
        let costs = |a: &RouteOffer, b: &RouteOffer| {
            (
                u128::from(a.price.msat) * self.delivery_ppm(b, policy, now),
                u128::from(b.price.msat) * self.delivery_ppm(a, policy, now),
            )
        };
        eligible.sort_by(|a, b| {
            let (left, right) = costs(a, b);
            (left, a.provider).cmp(&(right, b.provider))
        });
        let best = eligible.first().ok_or("no eligible priced route")?;
        if let Some(current) = eligible
            .iter()
            .find(|o| self.active.as_ref().is_some_and(|a| same_path(a, o)))
        {
            let (candidate, retained) = costs(best, current);
            if candidate * 100 >= retained * u128::from(100 - policy.min_improvement_percent) {
                return Ok(current.clone());
            }
        }
        Ok(best.clone())
    }
}

pub(super) struct PriceSelection {
    policy: PriceSelectionPolicy,
    buyer: Arc<crate::buyer::BuyerAuthorizer>,
    /// Bounds fanout across concurrent source calls, and serializes activation
    /// with sampling so a report cannot be paired with an uncommitted choice.
    work: tokio::sync::Mutex<()>,
    destinations: Mutex<BTreeMap<NodeAddr, Destination>>,
}

fn same_path(a: &RouteOffer, b: &RouteOffer) -> bool {
    a.provider == b.provider
        && a.path == b.path
        && a.destination.node_addr() == b.destination.node_addr()
}

impl RouteQuotes {
    pub(crate) fn price_selection_enabled(&self) -> bool {
        self.selection.is_some()
    }

    pub fn with_price_selection(
        mut self,
        policy: PriceSelectionPolicy,
        buyer: Arc<crate::buyer::BuyerAuthorizer>,
    ) -> Result<Self, String> {
        policy.validate()?;
        if !buyer.is_local(*self.endpoint.node_addr())? {
            return Err("source selection buyer identity mismatch".into());
        }
        if !self.policy.billing.has_free_handshakes() {
            return Err("price selection requires forwarding-data billing".into());
        }
        self.selection = Some(PriceSelection {
            policy,
            buyer,
            work: Default::default(),
            destinations: Default::default(),
        });
        Ok(self)
    }

    /// Called only after explicit free-route authorization or durable paid
    /// acceptance. Discovering/comparing a quote never changes the source path.
    pub(crate) async fn activate_source_route(&self, offer: &RouteOffer) -> Result<(), String> {
        let Some(selection) = &self.selection else {
            return Ok(());
        };
        let _work = selection.work.lock().await;
        let dest = *offer.destination.node_addr();
        let changed = {
            let mut states = selection
                .destinations
                .lock()
                .map_err(|_| "price selection poisoned")?;
            if states.len() >= MAX_DESTINATIONS && !states.contains_key(&dest) {
                return Err("source selection capacity".into());
            }
            let state = states.entry(dest).or_default();
            state.restored
                || state.active.as_ref().is_none_or(|a| {
                    !same_path(a, offer)
                        || (a.id != offer.id && state.failed.contains_key(&offer.provider))
                })
        };
        if changed {
            let peer = self.connected_provider(offer.provider).await?;
            self.endpoint
                .set_source_route(offer.destination, Some(peer))
                .await
                .map_err(|e| e.to_string())?;
        }
        let mut states = selection
            .destinations
            .lock()
            .map_err(|_| "price selection poisoned")?;
        let state = states.get_mut(&dest).ok_or("selection state missing")?;
        if changed {
            state.observations.remove(&offer.provider);
            state.failed.remove(&offer.provider);
        }
        if state
            .active
            .as_ref()
            .is_none_or(|active| active.id != offer.id)
        {
            state.blocked_trial = None;
        }
        state.active = Some(offer.clone());
        state.restored = false;
        Ok(())
    }

    pub(super) async fn select_priced_route(
        &self,
        destination: PeerIdentity,
        selection: &PriceSelection,
        reuse_unchanged: bool,
    ) -> Result<RouteOffer, String> {
        let _work = selection.work.lock().await;
        let quality = self
            .endpoint
            .source_route_quality(
                destination,
                Duration::from_millis(selection.policy.feedback_timeout_ms),
            )
            .await
            .map_err(|e| e.to_string())?;
        self.select_with_quality(destination, selection, reuse_unchanged, &quality)
            .await
    }

    async fn select_with_quality(
        &self,
        destination: PeerIdentity,
        selection: &PriceSelection,
        reuse_unchanged: bool,
        quality: &SourceRouteQuality,
    ) -> Result<RouteOffer, String> {
        let dest = *destination.node_addr();
        let mut peers: Vec<_> = self
            .endpoint
            .peers()
            .await
            .map_err(|e| e.to_string())?
            .into_iter()
            .filter(|p| p.connected)
            .collect();
        if peers.iter().any(|p| p.node_addr == dest) {
            return Err("destination is a direct neighbor".into());
        }
        peers.sort_by_key(|p| p.node_addr);
        let candidates = {
            let mut states = selection
                .destinations
                .lock()
                .map_err(|_| "price selection poisoned")?;
            if states.len() >= MAX_DESTINATIONS && !states.contains_key(&dest) {
                return Err("source selection capacity".into());
            }
            let state = states.entry(dest).or_default();
            let now = Instant::now();
            state.observe(quality, &selection.policy, now)?;
            let blocked = if let Some(active) = &state.active {
                if active.price.msat == 0 {
                    self.free.quota_blocked(active)?
                } else {
                    state.paid_trial_admission(selection.buyer.quota_blocked(active)?, || {
                        selection.buyer.retained_quota(active)
                    })?
                }
            } else {
                None
            };
            state.observe_admission(blocked == Some(true), &selection.policy, now)?;
            let active = state.active.as_ref().map(|a| a.provider);
            if let Some(provider) = active.filter(|p| state.failed.contains_key(p)) {
                self.client.invalidate(provider, dest);
            }
            state.candidate_indices(&peers.iter().map(|p| p.node_addr).collect::<Vec<_>>(), now)
        };
        let request = QuoteRequest {
            destination,
            ancestors: vec![*self.endpoint.node_addr()],
            deadline_unix: unix_now()?
                .checked_add(QUOTE_SECONDS)
                .ok_or("clock overflow")?,
            reuse_unchanged: true,
            requested_max_units: None,
        };
        let mut pending = JoinSet::new();
        for index in candidates {
            let peer = &peers[index];
            let identity = PeerIdentity::from_npub(&peer.npub).map_err(|e| e.to_string())?;
            let client = self.client.clone();
            let request = request.clone();
            pending.spawn(async move { client.request(identity, &request).await });
        }
        let mut offers = Vec::new();
        while let Some(result) = pending.join_next().await {
            if let Ok(Ok(offer)) = result {
                offers.push(offer);
            }
        }
        let (mut selected, step) = {
            let states = selection
                .destinations
                .lock()
                .map_err(|_| "price selection poisoned")?;
            let state = states.get(&dest).ok_or("selection state missing")?;
            let selected = state.choose(offers, &selection.policy, Instant::now())?;
            let step =
                match state.interrupted_trial_step(&selected, &selection.policy, |offer| {
                    selection.buyer.retained_quota(offer)
                })? {
                    Some(step) => step,
                    None => state.selection_step(
                        &selected,
                        &selection.policy,
                        reuse_unchanged,
                        |offer| self.free.remaining_units(offer),
                    )?,
                };
            (selected, step)
        };
        match step {
            SelectionStep::Retain(offer) => return Ok(*offer),
            SelectionStep::Accept => {}
            SelectionStep::Request {
                max_units,
                reuse_unchanged,
            } => {
                let provider = self.connected_provider(selected.provider).await?;
                let mut trial = request;
                trial.deadline_unix = unix_now()?
                    .checked_add(QUOTE_SECONDS)
                    .ok_or("clock overflow")?;
                trial.requested_max_units = max_units;
                trial.reuse_unchanged = reuse_unchanged;
                let offered = self.request_from(provider, trial).await?;
                if !same_path(&selected, &offered) || selected.price != offered.price {
                    return Err("path or price changed while negotiating trial".into());
                }
                selected = offered;
            }
        }
        self.free.accept(&selected)?;
        Ok(selected)
    }
}

#[cfg(test)]
mod free_tests;
#[cfg(test)]
mod tests;

#[cfg(test)]
mod admission_tests;

#[cfg(test)]
mod candidate_tests;
