//! Same-host FIPS rendezvous and authenticated capability directory.
//!
//! One process holds a well-known loopback UDP socket as the sticky local
//! rendezvous anchor. A tiny nonce exchange returns its untrusted public-key
//! hint; the client then uses the ordinary Noise IK discovered-peer path to
//! prove ownership. Capabilities are exchanged only through encrypted FSP and
//! kept in memory; authenticated announcements refresh short leases so forced
//! process death expires without filesystem state. Loopback grants no trust
//! exception.

use std::collections::BTreeMap;
use std::io;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::path::PathBuf;
use std::sync::{Arc, RwLock};

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Legacy filesystem-discovery error retained for endpoint API compatibility.
/// In-memory loopback capability snapshots are infallible and return none of
/// these variants.
#[derive(Debug, Error)]
pub enum LocalInstanceRegistryError {
    #[error("same-host FIPS discovery disabled")]
    Disabled,
    #[error("could not resolve FIPS local instance registry directory")]
    NoRegistryDir,
    #[error("local instance registry IO failed at {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("local instance registry serialization failed: {0}")]
    Json(#[from] serde_json::Error),
}

/// Host-global loopback UDP address used by the local rendezvous anchor.
pub const DEFAULT_LOCAL_RENDEZVOUS_ADDR: SocketAddrV4 =
    SocketAddrV4::new(Ipv4Addr::LOCALHOST, 21_211);

/// Runtime configuration for same-host rendezvous over loopback UDP.
///
/// `LocalInstanceDiscoveryConfig` is retained as the public configuration
/// name for compatibility. It no longer describes filesystem discovery.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct LocalInstanceDiscoveryConfig {
    /// Participate in same-host rendezvous. Disabled generic nodes neither
    /// bind the fixed anchor address nor connect to it.
    #[serde(default)]
    pub enabled: bool,
    /// Fixed IPv4 loopback address. This is configurable so isolated tests can
    /// use distinct ports; production callers should keep the default.
    #[serde(default = "default_rendezvous_addr")]
    pub rendezvous_addr: SocketAddrV4,
    /// Delay between attempts to contact or bind the sticky anchor.
    #[serde(default = "default_retry_interval_ms")]
    pub retry_interval_ms: u64,
}

impl Default for LocalInstanceDiscoveryConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            rendezvous_addr: DEFAULT_LOCAL_RENDEZVOUS_ADDR,
            retry_interval_ms: default_retry_interval_ms(),
        }
    }
}

impl LocalInstanceDiscoveryConfig {
    pub(crate) fn has_valid_rendezvous_addr(&self) -> bool {
        self.rendezvous_addr.ip().is_loopback() && self.rendezvous_addr.port() != 0
    }
}

const fn default_rendezvous_addr() -> SocketAddrV4 {
    DEFAULT_LOCAL_RENDEZVOUS_ADDR
}

const fn default_retry_interval_ms() -> u64 {
    1_000
}

pub(crate) fn lan_discovery_scope(config: &crate::Config) -> Option<String> {
    normalized_scope(config.node.discovery.lan.scope.as_deref()).or_else(|| {
        let app = config.node.discovery.nostr.app.trim();
        normalized_scope(Some(app.strip_prefix("fips-overlay-v1:").unwrap_or(app)))
    })
}

fn normalized_scope(scope: Option<&str>) -> Option<String> {
    scope
        .map(str::trim)
        .filter(|scope| !scope.is_empty())
        .map(str::to_string)
}

/// One reusable capability advertised by an authenticated same-host peer.
///
/// Priority ranks providers of this capability only. It has no bearing on
/// which process owns the loopback rendezvous anchor or on outbound links.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LocalInstanceCapability {
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fsp_port: Option<u16>,
    #[serde(default, skip_serializing_if = "is_zero_priority")]
    pub priority: i16,
}

impl LocalInstanceCapability {
    pub fn service(name: impl Into<String>, fsp_port: u16) -> Self {
        Self {
            name: name.into(),
            fsp_port: Some(fsp_port),
            priority: 0,
        }
    }

    pub fn role(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            fsp_port: None,
            priority: 0,
        }
    }

    pub fn with_priority(mut self, priority: i16) -> Self {
        self.priority = priority;
        self
    }
}

fn is_zero_priority(priority: &i16) -> bool {
    *priority == 0
}

/// Direct in-memory provider record learned over an authenticated local FIPS
/// link. A changed startup epoch denotes a restarted provider even when its
/// long-lived identity is unchanged.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalInstanceAdvertisement {
    pub npub: String,
    pub startup_epoch: [u8; 8],
    pub capabilities: Vec<LocalInstanceCapability>,
}

impl LocalInstanceAdvertisement {
    /// Return this provider's preferred advert for one capability name.
    pub fn capability(&self, name: &str) -> Option<&LocalInstanceCapability> {
        self.capabilities
            .iter()
            .filter(|capability| capability.name == name)
            .min_by(|left, right| {
                right
                    .priority
                    .cmp(&left.priority)
                    .then_with(|| left.fsp_port.cmp(&right.fsp_port))
            })
    }
}

/// Cloneable snapshot handle shared by the node and its endpoint facade.
///
/// The directory keeps at most one process incarnation per authenticated
/// npub. Removal is epoch-checked so a delayed disconnect from an old process
/// cannot erase the record installed after that process restarted.
#[derive(Debug, Clone, Default)]
pub(crate) struct LocalCapabilityDirectory {
    providers: Arc<RwLock<BTreeMap<String, LocalInstanceAdvertisement>>>,
}

impl LocalCapabilityDirectory {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    pub(crate) fn snapshot(&self) -> Vec<LocalInstanceAdvertisement> {
        self.read().values().cloned().collect()
    }

    /// Atomically replace the complete authenticated provider snapshot.
    /// When input repeats an npub, its last record wins.
    pub(crate) fn replace(&self, providers: impl IntoIterator<Item = LocalInstanceAdvertisement>) {
        let mut replacement = BTreeMap::new();
        for provider in providers {
            replacement.insert(provider.npub.clone(), provider);
        }
        *self.write() = replacement;
    }

    /// Insert or replace one authenticated process incarnation.
    pub(crate) fn upsert(
        &self,
        provider: LocalInstanceAdvertisement,
    ) -> Option<LocalInstanceAdvertisement> {
        self.write().insert(provider.npub.clone(), provider)
    }

    fn read(&self) -> std::sync::RwLockReadGuard<'_, BTreeMap<String, LocalInstanceAdvertisement>> {
        self.providers
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn write(
        &self,
    ) -> std::sync::RwLockWriteGuard<'_, BTreeMap<String, LocalInstanceAdvertisement>> {
        self.providers
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

/// Choose one provider deterministically. Higher capability priority wins;
/// ties are ordered by authenticated identity and then process epoch.
pub fn select_capability_provider<'a>(
    adverts: &'a [LocalInstanceAdvertisement],
    capability_name: &str,
) -> Option<&'a LocalInstanceAdvertisement> {
    adverts
        .iter()
        .filter(|advert| advert.capability(capability_name).is_some())
        .min_by(|left, right| capability_provider_order(left, right, capability_name))
}

/// Rank every provider so a consumer can try the next one after a service
/// failure. Highest capability priority sorts first.
pub fn rank_capability_providers<'a>(
    adverts: &'a [LocalInstanceAdvertisement],
    capability_name: &str,
) -> Vec<&'a LocalInstanceAdvertisement> {
    let mut providers = adverts
        .iter()
        .filter(|advert| advert.capability(capability_name).is_some())
        .collect::<Vec<_>>();
    providers.sort_by(|left, right| capability_provider_order(left, right, capability_name));
    providers
}

fn capability_provider_order(
    left: &LocalInstanceAdvertisement,
    right: &LocalInstanceAdvertisement,
    capability_name: &str,
) -> std::cmp::Ordering {
    right
        .capability(capability_name)
        .map(|capability| capability.priority)
        .cmp(
            &left
                .capability(capability_name)
                .map(|capability| capability.priority),
        )
        .then_with(|| left.npub.cmp(&right.npub))
        .then_with(|| left.startup_epoch.cmp(&right.startup_epoch))
}

#[cfg(test)]
#[path = "local_tests.rs"]
mod tests;
