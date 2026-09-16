//! Bounded control admission; network location is not spending authorization.
use super::*;

const ADMISSION_BURST: u32 = 16;
const ADMISSION_INTERVAL: Duration = Duration::from_millis(100);
const CUSTOMER_CONNECTIONS: usize = 8;
const CUSTOMER_IDENTITIES: usize = 64;

pub(crate) struct AdmissionBudget {
    updated: Instant,
    tokens: u32,
}

impl AdmissionBudget {
    pub(crate) fn new(now: Instant) -> Self {
        Self {
            updated: now,
            tokens: ADMISSION_BURST,
        }
    }

    pub(crate) fn allow(&mut self, now: Instant) -> bool {
        let intervals =
            now.duration_since(self.updated).as_millis() / ADMISSION_INTERVAL.as_millis();
        if intervals > 0 {
            self.tokens = self
                .tokens
                .saturating_add(intervals.min(u128::from(ADMISSION_BURST)) as u32)
                .min(ADMISSION_BURST);
            self.updated = now;
        }
        if self.tokens == 0 {
            return false;
        }
        self.tokens -= 1;
        true
    }
}

pub(super) fn allow_request(
    budgets: &mut HashMap<(NodeAddr, bool), AdmissionBudget>,
    peer: NodeAddr,
    outbound: bool,
) -> bool {
    let now = Instant::now();
    budgets
        .entry((peer, outbound))
        .or_insert_with(|| AdmissionBudget::new(now))
        .allow(now)
}

pub(super) struct CustomerAdmission {
    endpoint: Arc<FipsEndpoint>,
    network: IpNet,
    aggregate: AdmissionBudget,
    peers: HashMap<NodeAddr, AdmissionBudget>,
}

impl CustomerAdmission {
    pub(super) fn new(endpoint: Arc<FipsEndpoint>, network: IpNet) -> Self {
        Self {
            endpoint,
            network,
            aggregate: AdmissionBudget::new(Instant::now()),
            peers: HashMap::new(),
        }
    }

    pub(super) async fn allow(&mut self, peer: PeerIdentity, active: usize) -> bool {
        let now = Instant::now();
        if active >= CUSTOMER_CONNECTIONS || !self.aggregate.allow(now) {
            return false;
        }
        let Ok(peers) = self.endpoint.peers().await else {
            return false;
        };
        if !peers.iter().any(|p| {
            p.node_addr == *peer.node_addr()
                && p.authenticated_udp_restart_addr()
                    .is_some_and(|a| self.network.contains(&a.ip()))
        }) {
            return false;
        }
        admit_customer(&mut self.peers, *peer.node_addr(), now)
    }
}

fn admit_customer(
    peers: &mut HashMap<NodeAddr, AdmissionBudget>,
    peer: NodeAddr,
    now: Instant,
) -> bool {
    if !peers.contains_key(&peer) && peers.len() >= CUSTOMER_IDENTITIES {
        // Identity churn must not grow memory. The shared bucket remains in
        // force even when an inactive identity's individual bucket is evicted.
        if let Some(oldest) = peers
            .iter()
            .min_by_key(|(_, b)| b.updated)
            .map(|(id, _)| *id)
        {
            peers.remove(&oldest);
        }
    }
    peers
        .entry(peer)
        .or_insert_with(|| AdmissionBudget::new(now))
        .allow(now)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn admission_burst_refills_to_its_fixed_cap() {
        let now = Instant::now();
        let mut budget = AdmissionBudget::new(now);
        for _ in 0..ADMISSION_BURST {
            assert!(budget.allow(now));
        }
        assert!(!budget.allow(now));
        assert!(budget.allow(now + ADMISSION_INTERVAL));
        assert!(!budget.allow(now + ADMISSION_INTERVAL));
        assert!(budget.allow(now + Duration::from_secs(10)));
        assert_eq!(budget.tokens, ADMISSION_BURST - 1);
    }

    #[test]
    fn changing_customer_identities_does_not_expand_memory_or_the_shared_budget() {
        let now = Instant::now();
        let mut peers = HashMap::new();
        let mut aggregate = AdmissionBudget::new(now);
        for i in 0..CUSTOMER_IDENTITIES * 3 {
            let id = *fips_core::Identity::generate().node_addr();
            assert!(admit_customer(&mut peers, id, now));
            assert!(peers.len() <= CUSTOMER_IDENTITIES);
            assert_eq!(aggregate.allow(now), i < ADMISSION_BURST as usize);
        }
    }
}
