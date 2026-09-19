//! Volatile admission eligibility from retained, verified financial records.
use super::*;
use std::{collections::BTreeSet, sync::RwLock};

pub(crate) const MAX_CONTROL_OBLIGATIONS: usize = MAX_CHANNELS * 2 + MAX_ROUTES;

/// Control capacity only; this handle grants no route or spending authority.
/// Its publisher is the owning controller's durable journal, never a peer.
#[derive(Clone)]
pub(crate) struct ControlObligations {
    local: NodeAddr,
    peers: Arc<RwLock<BTreeSet<NodeAddr>>>,
}

impl ControlObligations {
    pub(super) fn new(local: NodeAddr) -> Self {
        Self {
            local,
            peers: Arc::default(),
        }
    }

    /// Rebuild only from the validated journal during local recovery.
    pub(super) fn from_journal(journal: &Journal) -> Result<Self, String> {
        let handle = Self::new(journal.local);
        handle.publish(handle.prepare(journal)?)?;
        Ok(handle)
    }

    pub(crate) fn local(&self) -> NodeAddr {
        self.local
    }

    pub(crate) fn contains(&self, peer: NodeAddr) -> bool {
        self.peers.read().is_ok_and(|peers| peers.contains(&peer))
    }

    pub(super) fn prepare(&self, journal: &Journal) -> Result<BTreeSet<NodeAddr>, String> {
        if journal.local != self.local
            || journal.funding.len() > MAX_CHANNELS
            || journal.incoming.len() > MAX_ROUTES
            || journal
                .history
                .as_ref()
                .is_some_and(|h| h.sellers.len() > MAX_CHANNELS)
        {
            return Err("invalid control obligation projection".into());
        }
        let mut peers: BTreeSet<_> = journal
            .funding
            .values()
            .filter(|funding| funding.funded.is_some())
            .map(|funding| funding.provider)
            .collect();
        // Prepared acceptance follows funding verification. Stopped routes and
        // released reports remain eligible until financial history retirement:
        // the last settlement acknowledgment can still have been lost.
        peers.extend(journal.incoming.values().map(|sale| sale.channel.buyer));
        if let Some(history) = &journal.history {
            peers.extend(history.sellers.values().map(|terms| terms.buyer));
        }
        if peers.len() > MAX_CONTROL_OBLIGATIONS || peers.contains(&self.local) {
            return Err("invalid control obligation identities".into());
        }
        Ok(peers)
    }

    pub(super) fn publish(&self, peers: BTreeSet<NodeAddr>) -> Result<(), String> {
        *self
            .peers
            .write()
            .map_err(|_| "control obligation projection poisoned")? = peers;
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn for_test(local: NodeAddr, peers: impl IntoIterator<Item = NodeAddr>) -> Self {
        let handle = Self::new(local);
        let mut bounded = BTreeSet::new();
        for peer in peers {
            assert_ne!(peer, local);
            bounded.insert(peer);
            assert!(bounded.len() <= MAX_CONTROL_OBLIGATIONS);
        }
        handle.publish(bounded).unwrap();
        handle
    }

    #[cfg(test)]
    pub(crate) fn snapshot(&self) -> Vec<NodeAddr> {
        self.peers
            .read()
            .map(|peers| peers.iter().copied().collect())
            .unwrap_or_default()
    }
}

fn bind_services(
    services: &ControllerServices,
    obligations: &ControlObligations,
) -> Result<(), String> {
    let admissions = [
        services.quotes.control_admission(),
        services.acceptance.control_admission(),
        services.payments.control_admission(),
    ];
    if obligations.local() != *services.endpoint.node_addr()
        || admissions
            .iter()
            .any(|admission| !admission.owns_endpoint(&services.endpoint))
    {
        return Err("controller control admission belongs to another endpoint".into());
    }
    // Reload replaces the projection without replacing any transport, active
    // permit or request budget. Validate every endpoint before binding any one.
    for admission in admissions {
        admission.bind_obligations(obligations.clone())?;
    }
    Ok(())
}

impl Controller {
    pub(crate) fn control_obligations(&self) -> ControlObligations {
        self.control_obligations.clone()
    }

    pub(super) fn bind_control_obligations(&self) -> Result<(), String> {
        bind_services(&self.services, &self.control_obligations())
    }
}

#[cfg(test)]
mod tests;
