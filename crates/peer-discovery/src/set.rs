//! Compose multiple [`Discovery`] backends behind one event stream.
//!
//! `DiscoverySet` is the typical entry point for callers: register the
//! backends you want, call [`DiscoverySet::start`] once with the local peer
//! description and the service tags you care about, and consume one merged
//! [`PeerEvent`] stream.

use crate::{Discovery, DiscoveryError, DiscoveryHandle, LocalPeer, PeerEvent, ServiceTag};
use std::sync::Arc;
use tokio::sync::mpsc;

/// Buffer size for the merged event channel. Tuned for low contention; if a
/// consumer falls this far behind, oldest events are dropped at the per-
/// backend boundary, not here.
const DEFAULT_CHANNEL_CAPACITY: usize = 256;

pub struct DiscoverySet {
    backends: Vec<Arc<dyn Discovery>>,
    channel_capacity: usize,
}

impl DiscoverySet {
    pub fn new() -> Self {
        Self {
            backends: Vec::new(),
            channel_capacity: DEFAULT_CHANNEL_CAPACITY,
        }
    }

    pub fn with_channel_capacity(mut self, capacity: usize) -> Self {
        self.channel_capacity = capacity.max(1);
        self
    }

    pub fn register(mut self, backend: Arc<dyn Discovery>) -> Self {
        self.backends.push(backend);
        self
    }

    /// Start every registered backend and return a merged event receiver.
    /// The returned [`DiscoverySetHandle`] keeps every backend alive; drop
    /// it (or call [`DiscoverySetHandle::shutdown`]) to stop them all.
    pub async fn start(
        self,
        local: LocalPeer,
        watch: Vec<ServiceTag>,
    ) -> Result<(mpsc::Receiver<PeerEvent>, DiscoverySetHandle), DiscoveryError> {
        let (tx, rx) = mpsc::channel(self.channel_capacity);
        let mut handles = Vec::with_capacity(self.backends.len());
        for backend in self.backends {
            let h = backend
                .clone()
                .start(local.clone(), watch.clone(), tx.clone())
                .await?;
            handles.push(h);
        }
        Ok((rx, DiscoverySetHandle { _handles: handles }))
    }
}

impl Default for DiscoverySet {
    fn default() -> Self {
        Self::new()
    }
}

pub struct DiscoverySetHandle {
    _handles: Vec<DiscoveryHandle>,
}

impl DiscoverySetHandle {
    pub fn shutdown(self) {
        drop(self);
    }
}
