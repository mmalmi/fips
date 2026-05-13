//! Transport-neutral peer discovery.
//!
//! A [`Discovery`] backend learns about peers (other nodes) and advertises the
//! local node's services. Backends are pluggable: a same-host registry, an
//! mDNS responder for the LAN, a nostr-relay-backed announcer for the open
//! internet, and so on. The core types deliberately know nothing about the
//! transports they describe — a peer might be reachable via UDP, TCP, a Unix
//! socket, an iroh `NodeAddr`, or a URL.
//!
//! Each application opts in to the [`ServiceTag`]s it cares about (e.g.
//! `"fips-fmp"`, `"hashtree"`, `"iris-chat"`) and composes the backends it
//! wants. A [`DiscoverySet`] is the typical entry point: it fans events out
//! from many backends into one stream and lets the caller advertise once.

pub mod backends;
mod set;

pub use set::{DiscoverySet, DiscoverySetHandle};

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::borrow::Cow;
use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::SystemTime;
use tokio::sync::mpsc;

/// 32-byte peer identity. Conventionally an Ed25519/X25519 public key, but
/// backends should treat this as opaque bytes.
pub type PeerId = [u8; 32];

/// Short, stable name for a service exposed by a peer. Examples:
/// `"fips-fmp"`, `"hashtree"`, `"iris-chat"`, `"git-htree"`.
///
/// Kept as a `Cow<'static, str>` so consumers can use compile-time constants
/// without allocating, while still allowing dynamic tags for backends like
/// mDNS that surface arbitrary service types.
pub type ServiceTag = Cow<'static, str>;

/// One endpoint at which a service is reachable. The variants are open:
/// [`ServiceAddr::Other`] carries an arbitrary scheme/value pair so backends
/// can describe transports the core doesn't know about (e.g. an iroh
/// `NodeAddr` blob or an `htree://` URL) without forcing this crate to depend
/// on those types.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ServiceAddr {
    Udp(SocketAddr),
    Tcp(SocketAddr),
    Unix(PathBuf),
    Url(String),
    Other { scheme: String, value: String },
}

/// One advertised service: a tag, the addresses it's reachable at, and a
/// small bag of TXT-style key/value attributes for backend-specific metadata.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ServiceAd {
    pub tag: ServiceTag,
    #[serde(default)]
    pub addrs: Vec<ServiceAddr>,
    #[serde(default)]
    pub txt: BTreeMap<String, String>,
}

impl ServiceAd {
    pub fn new(tag: impl Into<ServiceTag>) -> Self {
        Self {
            tag: tag.into(),
            addrs: Vec::new(),
            txt: BTreeMap::new(),
        }
    }

    pub fn with_addr(mut self, addr: ServiceAddr) -> Self {
        self.addrs.push(addr);
        self
    }

    pub fn with_txt(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.txt.insert(key.into(), value.into());
        self
    }
}

/// Description of the local node, handed to every backend at start.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LocalPeer {
    pub id: PeerId,
    #[serde(default)]
    pub services: Vec<ServiceAd>,
    #[serde(default)]
    pub display_name: Option<String>,
}

/// A peer learned about from one (or more) backends.
#[derive(Clone, Debug)]
pub struct DiscoveredPeer {
    pub id: PeerId,
    pub services: Vec<ServiceAd>,
    /// Backend that produced this observation (e.g. `"mdns"`, `"nostr"`).
    pub source: &'static str,
    pub seen_at: SystemTime,
    pub display_name: Option<String>,
}

/// Stream of changes a backend reports about peers it observes.
#[derive(Clone, Debug)]
pub enum PeerEvent {
    /// First sighting from this source, or a sighting after a `Down`.
    Up(DiscoveredPeer),
    /// Re-observation with possibly changed services/addresses.
    Updated(DiscoveredPeer),
    /// Backend believes the peer is no longer reachable from its vantage
    /// point. Other backends may still see it.
    Down {
        id: PeerId,
        source: &'static str,
    },
}

/// Boxed source error used by [`DiscoveryError`]. Backends construct one of
/// these from whatever native error type they have.
pub type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// Errors a backend can return at start/stop time. Per-event errors are
/// logged by the backend and not surfaced through the trait.
#[derive(Debug, thiserror::Error)]
pub enum DiscoveryError {
    #[error("backend `{backend}` failed to start: {source}")]
    Start {
        backend: &'static str,
        #[source]
        source: BoxError,
    },
    #[error("backend `{backend}` is not configured")]
    NotConfigured { backend: &'static str },
    #[error(transparent)]
    Other(#[from] BoxError),
}

/// Handle returned by [`Discovery::start`]. Dropping the handle requests
/// shutdown; backends should treat that as the canonical stop signal.
pub struct DiscoveryHandle {
    shutdown: Option<Box<dyn FnOnce() + Send>>,
}

impl DiscoveryHandle {
    pub fn new<F: FnOnce() + Send + 'static>(shutdown: F) -> Self {
        Self {
            shutdown: Some(Box::new(shutdown)),
        }
    }

    /// Request shutdown explicitly. Equivalent to dropping the handle, but
    /// available for callers that want to surface ordering.
    pub fn shutdown(mut self) {
        if let Some(s) = self.shutdown.take() {
            s();
        }
    }
}

impl Drop for DiscoveryHandle {
    fn drop(&mut self) {
        if let Some(s) = self.shutdown.take() {
            s();
        }
    }
}

/// A pluggable peer-discovery backend.
///
/// Backends learn about remote peers and advertise the local node's
/// services. Implementations are expected to:
///
/// * Spawn whatever background tasks they need on `start` and return a
///   [`DiscoveryHandle`] that tears them down.
/// * Send [`PeerEvent`]s on the supplied channel as peers come and go.
///   Backends MUST NOT block on a full channel — they should drop the event
///   or coalesce.
/// * Filter their own observations to the requested `watch` tags when
///   feasible. (Backends like mDNS that already filter at the protocol level
///   should pass `watch` through; backends like a shared registry may
///   filter in software.)
#[async_trait]
pub trait Discovery: Send + Sync + 'static {
    /// Stable identifier for this backend (e.g. `"mdns"`, `"nostr"`,
    /// `"local-registry"`). Goes into [`DiscoveredPeer::source`] and into
    /// log lines.
    fn name(&self) -> &'static str;

    async fn start(
        self: Arc<Self>,
        local: LocalPeer,
        watch: Vec<ServiceTag>,
        events: mpsc::Sender<PeerEvent>,
    ) -> Result<DiscoveryHandle, DiscoveryError>;
}
