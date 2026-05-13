//! Process-local discovery backend used by tests and as the simplest
//! reference implementation.
//!
//! Every [`InMemoryDiscovery`] sharing the same [`InMemoryHub`] sees every
//! other instance's advertisement. Useful for exercising the trait surface,
//! the [`DiscoverySet`](crate::DiscoverySet) wiring, and consumer logic
//! without bringing up real transports.

use crate::{
    Discovery, DiscoveryError, DiscoveryHandle, DiscoveredPeer, LocalPeer, PeerEvent, ServiceTag,
};
use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::SystemTime;
use tokio::sync::{broadcast, mpsc};

const SOURCE: &str = "in-memory";

#[derive(Clone)]
pub struct InMemoryHub {
    inner: Arc<HubInner>,
}

struct HubInner {
    peers: Mutex<HashMap<crate::PeerId, LocalPeer>>,
    tx: broadcast::Sender<HubEvent>,
}

#[derive(Clone, Debug)]
enum HubEvent {
    Up(LocalPeer),
    Down(crate::PeerId),
}

impl InMemoryHub {
    pub fn new() -> Self {
        let (tx, _) = broadcast::channel(256);
        Self {
            inner: Arc::new(HubInner {
                peers: Mutex::new(HashMap::new()),
                tx,
            }),
        }
    }

    pub fn discovery(&self) -> Arc<InMemoryDiscovery> {
        Arc::new(InMemoryDiscovery { hub: self.clone() })
    }

    fn announce(&self, peer: LocalPeer) {
        self.inner
            .peers
            .lock()
            .unwrap()
            .insert(peer.id, peer.clone());
        let _ = self.inner.tx.send(HubEvent::Up(peer));
    }

    fn withdraw(&self, id: crate::PeerId) {
        self.inner.peers.lock().unwrap().remove(&id);
        let _ = self.inner.tx.send(HubEvent::Down(id));
    }

    fn snapshot(&self) -> Vec<LocalPeer> {
        self.inner.peers.lock().unwrap().values().cloned().collect()
    }

    fn subscribe(&self) -> broadcast::Receiver<HubEvent> {
        self.inner.tx.subscribe()
    }
}

impl Default for InMemoryHub {
    fn default() -> Self {
        Self::new()
    }
}

pub struct InMemoryDiscovery {
    hub: InMemoryHub,
}

#[async_trait]
impl Discovery for InMemoryDiscovery {
    fn name(&self) -> &'static str {
        SOURCE
    }

    async fn start(
        self: Arc<Self>,
        local: LocalPeer,
        watch: Vec<ServiceTag>,
        events: mpsc::Sender<PeerEvent>,
    ) -> Result<DiscoveryHandle, DiscoveryError> {
        let local_id = local.id;
        self.hub.announce(local.clone());

        for peer in self.hub.snapshot() {
            if peer.id == local_id {
                continue;
            }
            if let Some(ev) = matched_event(&peer, &watch) {
                let _ = events.send(ev).await;
            }
        }

        let mut sub = self.hub.subscribe();
        let watch_clone = watch.clone();
        let task = tokio::spawn(async move {
            loop {
                match sub.recv().await {
                    Ok(HubEvent::Up(peer)) => {
                        if peer.id == local_id {
                            continue;
                        }
                        if let Some(ev) = matched_event(&peer, &watch_clone) {
                            if events.send(ev).await.is_err() {
                                break;
                            }
                        }
                    }
                    Ok(HubEvent::Down(id)) => {
                        if id == local_id {
                            continue;
                        }
                        if events
                            .send(PeerEvent::Down { id, source: SOURCE })
                            .await
                            .is_err()
                        {
                            break;
                        }
                    }
                    Err(broadcast::error::RecvError::Lagged(_)) => continue,
                    Err(broadcast::error::RecvError::Closed) => break,
                }
            }
        });

        let hub = self.hub.clone();
        Ok(DiscoveryHandle::new(move || {
            hub.withdraw(local_id);
            task.abort();
        }))
    }
}

fn matched_event(peer: &LocalPeer, watch: &[ServiceTag]) -> Option<PeerEvent> {
    let services: Vec<_> = peer
        .services
        .iter()
        .filter(|ad| watch.is_empty() || watch.iter().any(|w| w == &ad.tag))
        .cloned()
        .collect();
    if services.is_empty() && !watch.is_empty() {
        return None;
    }
    Some(PeerEvent::Up(DiscoveredPeer {
        id: peer.id,
        services,
        source: SOURCE,
        seen_at: SystemTime::now(),
        display_name: peer.display_name.clone(),
    }))
}
