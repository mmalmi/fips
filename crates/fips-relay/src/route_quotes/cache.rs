//! Short-lived complete offers; no cached result can extend financial authority.
use super::*;
use std::future::Future;
use tokio::{sync::Mutex as AsyncMutex, time::Instant};

const FRESH_FOR: Duration = Duration::from_secs(30);
const REJECT_FOR: Duration = Duration::from_millis(500);
const MAX_ENTRIES: usize = 128;
const MAX_PER_PROVIDER: usize = 16;

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
struct Key {
    provider: NodeAddr,
    destination: NodeAddr,
    ancestors: Vec<NodeAddr>,
    max_units: Option<u64>,
}

struct Cached {
    checked: Instant,
    result: Result<RouteOffer, String>,
}

struct Entry {
    used: Instant,
    value: Arc<AsyncMutex<Option<Cached>>>,
}

#[derive(Default)]
struct Cache {
    entries: Mutex<BTreeMap<Key, Entry>>,
}

impl Cache {
    fn entry(&self, key: &Key) -> Result<Arc<AsyncMutex<Option<Cached>>>, String> {
        let mut entries = self.entries.lock().map_err(|_| "quote cache poisoned")?;
        if !entries.contains_key(key) {
            let provider_full = entries
                .keys()
                .filter(|k| k.provider == key.provider)
                .count()
                >= MAX_PER_PROVIDER;
            if provider_full || entries.len() >= MAX_ENTRIES {
                // Never evict a live request: followers must share its outcome.
                let oldest = entries
                    .iter()
                    .filter(|(k, e)| {
                        (!provider_full || k.provider == key.provider)
                            && Arc::strong_count(&e.value) == 1
                    })
                    .min_by_key(|(_, e)| e.used)
                    .map(|(k, _)| k.clone())
                    .ok_or("quote cache request capacity")?;
                entries.remove(&oldest);
            }
        }
        let entry = entries.entry(key.clone()).or_insert_with(|| Entry {
            used: Instant::now(),
            value: Arc::new(AsyncMutex::new(None)),
        });
        entry.used = Instant::now();
        Ok(entry.value.clone())
    }

    async fn get_or_fetch<F, Fut>(
        &self,
        key: Key,
        request: &QuoteRequest,
        fetch: F,
    ) -> Result<RouteOffer, String>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = Result<RouteOffer, String>>,
    {
        // The wait behind another request shares this caller's own deadline.
        let seconds = request
            .deadline_unix
            .checked_sub(unix_now()?)
            .filter(|s| *s > 0 && *s <= MAX_REQUEST_SECONDS)
            .ok_or("quote deadline")?;
        let entry = self.entry(&key)?;
        tokio::time::timeout(Duration::from_secs(seconds), async {
            let mut cached = entry.lock().await;
            if request.deadline_unix <= unix_now()? {
                return Err("quote deadline".into());
            }
            if request.reuse_unchanged
                && let Some(old) = cached.as_ref()
            {
                let fresh = match &old.result {
                    Ok(offer) => {
                        old.checked.elapsed() < FRESH_FOR && offer.expires_unix > unix_now()?
                    }
                    Err(_) => old.checked.elapsed() < REJECT_FOR,
                };
                if fresh {
                    return old.result.clone();
                }
            }
            // Cancellation leaves an empty slot, never an abandoned busy flag.
            // Fresh requests deliberately ignore prior offers and negative cache.
            *cached = None;
            let result = fetch().await;
            *cached = Some(Cached {
                checked: Instant::now(),
                result: result.clone(),
            });
            result
        })
        .await
        .map_err(|_| "quote deadline".to_string())?
    }

    fn invalidate(&self, provider: NodeAddr, destination: NodeAddr) {
        if let Ok(mut entries) = self.entries.lock() {
            // In-flight callers retain their slot, but their result cannot
            // repopulate the map after invalidation. Admission still revalidates.
            entries.retain(|k, _| k.provider != provider || k.destination != destination);
        }
    }
}

pub(super) struct QuoteClient {
    control: Arc<ControlTransport>,
    policy: Arc<QuotePolicy>,
    local: NodeAddr,
    cache: Cache,
}

impl QuoteClient {
    pub(super) fn new(
        control: Arc<ControlTransport>,
        policy: Arc<QuotePolicy>,
        local: NodeAddr,
    ) -> Self {
        Self {
            control,
            policy,
            local,
            cache: Cache::default(),
        }
    }

    pub(super) async fn request(
        &self,
        peer: PeerIdentity,
        request: &QuoteRequest,
    ) -> Result<RouteOffer, String> {
        let key = Key {
            provider: *peer.node_addr(),
            destination: *request.destination.node_addr(),
            ancestors: request.ancestors.clone(),
            max_units: request.requested_max_units,
        };
        let offer = self
            .cache
            .get_or_fetch(key, request, || {
                validation::fetch_offer(&self.control, &self.policy, self.local, peer, request)
            })
            .await?;
        // Recheck the complete terms, including loop context and wall-clock expiry.
        validation::validate_offer(&self.policy, self.local, &offer, peer, request, unix_now()?)?;
        Ok(offer)
    }

    pub(super) fn invalidate(&self, provider: NodeAddr, destination: NodeAddr) {
        self.cache.invalidate(provider, destination);
    }
}

#[cfg(test)]
mod tests;
