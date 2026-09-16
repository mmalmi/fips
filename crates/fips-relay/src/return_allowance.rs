//! Bounded small replies earned by locally admitted forward traffic.
//! Payloads remain opaque: this is not a claim to recognize encrypted reports.
use crate::unpaid_budget::{MIN_CHARGE, UnpaidBudget, UnpaidStats};
use fips_core::{NodeAddr, node::ForwardingRequest};
use serde::Serialize;
use std::{collections::BTreeMap, time::Duration};
use tokio::time::Instant;

const MAX_FLOWS: usize = 128;
const MAX_PER_NEIGHBOR: usize = 16;
const MAX_PACKET: usize = 2_048;
const MAX_CREDIT: usize = 4_096;
const LIFETIME: Duration = Duration::from_secs(30);

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct Path {
    ingress: NodeAddr,
    next: NodeAddr,
    source: NodeAddr,
    destination: NodeAddr,
}
impl Path {
    fn from_request(r: &ForwardingRequest<'_>) -> Self {
        Self {
            ingress: *r.ingress.node_addr(),
            next: r.next_hop,
            source: r.source,
            destination: r.destination,
        }
    }
    fn reverse(self) -> Self {
        Self {
            ingress: self.next,
            next: self.ingress,
            source: self.destination,
            destination: self.source,
        }
    }
}

#[derive(Debug)]
struct Credit {
    remaining: usize,
    expires: Instant,
}

#[derive(Debug)]
pub(crate) struct ReturnAllowance {
    flows: BTreeMap<Path, Credit>,
    budget: UnpaidBudget,
}

#[derive(Debug, Serialize)]
pub struct ReturnStats {
    pub tracked_paths: usize,
    pub traffic: UnpaidStats,
}

impl ReturnAllowance {
    pub(crate) fn new() -> Self {
        Self {
            flows: BTreeMap::new(),
            budget: UnpaidBudget::for_returns(),
        }
    }
    pub(crate) fn earn(&mut self, request: &ForwardingRequest<'_>) {
        self.earn_at(request, Instant::now());
    }
    fn earn_at(&mut self, request: &ForwardingRequest<'_>, now: Instant) {
        // This must only follow paid or explicitly free forward admission.
        // Handshakes and replies admitted by this allowance never earn credit.
        self.flows.retain(|_, c| c.expires > now);
        let key = Path::from_request(request).reverse();
        if request.session_payload.is_empty()
            || request.source == request.destination
            || (!self.flows.contains_key(&key)
                && (self.flows.len() >= MAX_FLOWS
                    || self
                        .flows
                        .keys()
                        .filter(|p| p.ingress == key.ingress)
                        .count()
                        >= MAX_PER_NEIGHBOR))
        {
            return;
        }
        let credit = self.flows.entry(key).or_insert(Credit {
            remaining: 0,
            expires: now,
        });
        credit.remaining = credit
            .remaining
            .saturating_add(request.session_payload.len().clamp(512, MAX_PACKET))
            .min(MAX_CREDIT);
        credit.expires = now + LIFETIME;
    }
    pub(crate) fn admit(&mut self, request: &ForwardingRequest<'_>) -> bool {
        self.admit_at(request, Instant::now())
    }
    fn admit_at(&mut self, request: &ForwardingRequest<'_>, now: Instant) -> bool {
        let bytes = request.session_payload.len();
        if !(1..=MAX_PACKET).contains(&bytes) {
            return false;
        }
        let charge = bytes.max(MIN_CHARGE as usize);
        let Some(credit) = self
            .flows
            .get_mut(&Path::from_request(request))
            .filter(|c| c.expires > now && c.remaining >= charge)
        else {
            return false;
        };
        if !self
            .budget
            .admit_at(*request.ingress.node_addr(), bytes, now)
        {
            return false;
        }
        credit.remaining -= charge;
        // Neither the expiry nor any other path's credit is extended by replies.
        true
    }
    pub(crate) fn stats(&self) -> ReturnStats {
        ReturnStats {
            tracked_paths: self.flows.len(),
            traffic: self.budget.stats(),
        }
    }
}

#[cfg(test)]
mod tests;
