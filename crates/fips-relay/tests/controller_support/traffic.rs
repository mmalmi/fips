//! Shared paid traffic fixture; application workloads keep the same financial bounds.
use super::*;
use fips_core::FipsEndpointServiceReceiver;
use std::path::Path;

#[derive(Clone, Copy)]
pub(crate) enum TrafficKind {
    Datagrams,
    #[cfg(feature = "measurements")]
    Stream,
}

impl TrafficKind {
    #[cfg(unix)]
    pub(crate) async fn rekey(
        self,
        root: &Path,
        peers: &[PeerIdentity],
        enabled: bool,
        trace: &Arc<DeliveryTrace>,
    ) -> Option<RekeyObservation> {
        match self {
            Self::Datagrams => RekeyObservation::start(root, peers, enabled, trace).await,
            #[cfg(feature = "measurements")]
            Self::Stream => Some(RekeyObservation::start_unfaulted(root, peers).await),
        }
    }
}

pub(crate) struct Traffic<'a> {
    pub root: &'a Path,
    pub nodes: &'a [Arc<FipsEndpoint>],
    pub peers: &'a [PeerIdentity],
    pub data: &'a mut [FipsEndpointServiceReceiver],
    pub controllers: &'a [Arc<Controller>],
    pub ledgers: &'a [Arc<DurableRelay>],
    pub buyers: &'a [Arc<BuyerAuthorizer>],
    pub forwarding: &'a [Arc<DeliveryTrace>],
    pub links: &'a [(usize, usize, Purchase)],
    pub capacity: u64,
    pub automatic_renewal: bool,
    #[cfg(unix)]
    pub rekey: &'a mut Option<RekeyObservation>,
}

impl Traffic<'_> {
    pub(crate) async fn run(&mut self, kind: TrafficKind) {
        match kind {
            TrafficKind::Datagrams => self.datagrams().await,
            #[cfg(feature = "measurements")]
            TrafficKind::Stream => super::reliable::exercise(self).await,
        }
    }

    async fn datagrams(&mut self) {
        let root = self.root;
        let nodes = self.nodes;
        let peers = self.peers;
        let data = &mut *self.data;
        let controllers = self.controllers;
        let ledgers = self.ledgers;
        let buyers = self.buyers;
        let forwarding = self.forwarding;
        let links = self.links;
        let capacity = self.capacity;
        let automatic_renewal = self.automatic_renewal;
        #[cfg(unix)]
        let rekey = &mut *self.rekey;
        // A final handshake retry can outlive the original 18 traffic rounds.
        // Keep driving delivery until recovery is observed, with a finite cap
        // and the existing overall scenario deadline and spending bounds.
        for round in 0..if automatic_renewal { 36 } else { 8 } {
            for (source, destination) in [(0, 4), (4, 0)] {
                let mut payload = vec![round; 1_000];
                payload[0] = source as u8;
                let delivery = tokio::time::timeout(Duration::from_secs(30), async {
                    loop {
                        nodes[source].send_datagram(peers[destination], 44_740, 44_740, payload.clone()).await.unwrap();
                        let mut received = Vec::new();
                        if let Ok(result) = tokio::time::timeout(
                            Duration::from_millis(if automatic_renewal { 750 } else { 10_000 }),
                            data[destination].recv_batch_into(&mut received, 8),
                        ).await {
                            result.unwrap();
                            if received.iter().any(|m| m.data.as_slice() == payload) { break; }
                        }
                        if !automatic_renewal {
                            super::delivery_evidence(
                                root, peers, forwarding, ledgers, buyers,
                            ).await;
                        }
                        assert!(automatic_renewal,
                            "ordinary delivery needed a retry: round={round} direction={source}->{destination}; received={:?}; errors={:?}; usage={:?}",
                            received.iter().map(|m| (m.source_port, m.destination_port, m.data.len(), m.data.as_slice().iter().copied().take(2).collect::<Vec<_>>())).collect::<Vec<_>>(),
                            errors(controllers), links.iter().map(|(b,s,p)|(*b,*s,ledgers[*s].channel_usage(&p.channel.id))).collect::<Vec<_>>());
                    }
                })
                .await;
                if delivery.is_err() {
                    super::delivery_evidence(root, peers, forwarding, ledgers, buyers).await;
                }
                delivery.unwrap_or_else(|_| panic!("autonomously paid delivery round={round} direction={source}->{destination}; errors={:?}; usage={:?}; evidence={:?}; stages={:?}", errors(controllers), links.iter().map(|(b,s,p)|(*b,*s,ledgers[*s].channel_usage(&p.channel.id))).collect::<Vec<_>>(), links.iter().map(|(b,s,p)|(*b,*s,buyers[*b].evidence_msat(&p.channel.id))).collect::<Vec<_>>(), recovery_stages(root)));
            }
            for controller in controllers {
                assert!(controller.locked_capital_sat().await.unwrap() <= capacity * 2);
            }
            // Payments are driven only by each controller's periodic task.
            tokio::time::sleep(Duration::from_millis(600)).await;
            #[cfg(unix)]
            if let Some(rekey) = rekey.as_mut() {
                rekey.observe(root, peers).await;
            }
            #[cfg(unix)]
            if round >= 17 && rekey.as_ref().is_some_and(|rekey| rekey.recovered()) {
                break;
            }
        }
    }
}
