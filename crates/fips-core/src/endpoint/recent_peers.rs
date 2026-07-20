//! Store-agnostic persistence model for recently authenticated FIPS peers.
//!
//! This cache is routing memory, not an authorization or membership source.
//! Cached routes may only augment an application's existing [`PeerConfig`]
//! entries; they must never create configured peers by themselves.

use super::status::{FipsEndpointPeer, is_reusable_udp_socket_addr};
use crate::PeerIdentity;
use crate::config::{PeerAddress, PeerAddressProvenance, PeerConfig};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashSet};
use std::net::SocketAddr;
use thiserror::Error;

/// Current recent-peers JSON schema version.
pub const RECENT_PEERS_VERSION: u32 = 1;
/// Maximum number of remote identities retained in one cache.
pub const RECENT_PEERS_MAX_PEERS: usize = 256;
/// Maximum number of restart endpoints retained for one remote identity.
pub const RECENT_PEERS_MAX_ENDPOINTS_PER_PEER: usize = 4;

/// Store-agnostic version-1 recent-peer document.
///
/// The serialized object contains exactly `version`, `local_npub`, `scope`,
/// and `peers`. Applications choose where and how to persist that JSON.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecentPeers {
    pub version: u32,
    pub local_npub: String,
    pub scope: String,
    pub peers: BTreeMap<String, RecentPeer>,
}

/// Authentication recency and reusable endpoints for one remote identity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecentPeer {
    pub last_authenticated_at_ms: u64,
    pub endpoints: Vec<RecentPeerEndpoint>,
}

/// One previously authenticated, restart-safe transport endpoint.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecentPeerEndpoint {
    pub transport: RecentPeerTransport,
    pub addr: String,
    pub last_authenticated_at_ms: u64,
}

/// Transport kinds allowed in the version-1 recent-peer schema.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RecentPeerTransport {
    Udp,
}

/// Validation or JSON codec error for a recent-peer document.
#[derive(Debug, Error)]
pub enum RecentPeersError {
    #[error("invalid recent-peers JSON: {0}")]
    Json(#[from] serde_json::Error),

    #[error("unsupported recent-peers version {actual}; expected {RECENT_PEERS_VERSION}")]
    UnsupportedVersion { actual: u32 },

    #[error("invalid canonical local npub '{npub}': {reason}")]
    InvalidLocalNpub { npub: String, reason: String },

    #[error("recent-peers local identity mismatch: expected '{expected}', found '{actual}'")]
    LocalIdentityMismatch { expected: String, actual: String },

    #[error("recent-peers scope mismatch: expected '{expected}', found '{actual}'")]
    ScopeMismatch { expected: String, actual: String },

    #[error("invalid canonical peer npub '{npub}': {reason}")]
    InvalidPeerNpub { npub: String, reason: String },

    #[error("recent-peers document contains the local identity as a remote peer")]
    LocalIdentityAsPeer,

    #[error("recent-peers document has {actual} peers; maximum is {max}")]
    TooManyPeers { actual: usize, max: usize },

    #[error("recent peer '{npub}' has {actual} endpoints; maximum is {max}")]
    TooManyEndpoints {
        npub: String,
        actual: usize,
        max: usize,
    },

    #[error("recent peer '{npub}' has unusable UDP endpoint '{addr}'")]
    UnusableUdpEndpoint { npub: String, addr: String },

    #[error("recent peer '{npub}' repeats UDP endpoint '{addr}'")]
    DuplicateUdpEndpoint { npub: String, addr: String },

    #[error(
        "recent peer '{npub}' endpoint timestamp {endpoint_at_ms} is newer than peer timestamp {peer_at_ms}"
    )]
    EndpointNewerThanPeer {
        npub: String,
        endpoint_at_ms: u64,
        peer_at_ms: u64,
    },
}

impl RecentPeers {
    /// Create an empty version-1 cache for one local identity and app scope.
    pub fn new(
        local_npub: impl Into<String>,
        scope: impl Into<String>,
    ) -> Result<Self, RecentPeersError> {
        let local_npub = local_npub.into();
        validate_canonical_npub(&local_npub).map_err(|reason| {
            RecentPeersError::InvalidLocalNpub {
                npub: local_npub.clone(),
                reason,
            }
        })?;
        Ok(Self {
            version: RECENT_PEERS_VERSION,
            local_npub,
            scope: scope.into(),
            peers: BTreeMap::new(),
        })
    }

    /// Strictly decode and validate a cache for the expected identity/scope.
    ///
    /// Unknown fields, unknown transports, wrong versions, invalid identities,
    /// unsafe endpoints, and documents exceeding the schema limits are
    /// rejected. Identity and scope binding prevents one app or local key from
    /// accidentally consuming another's routing memory.
    pub fn from_json(
        json: &str,
        expected_local_npub: &str,
        expected_scope: &str,
    ) -> Result<Self, RecentPeersError> {
        let recent: Self = serde_json::from_str(json)?;
        recent.validate()?;

        validate_canonical_npub(expected_local_npub).map_err(|reason| {
            RecentPeersError::InvalidLocalNpub {
                npub: expected_local_npub.to_string(),
                reason,
            }
        })?;
        if recent.local_npub != expected_local_npub {
            return Err(RecentPeersError::LocalIdentityMismatch {
                expected: expected_local_npub.to_string(),
                actual: recent.local_npub,
            });
        }
        if recent.scope != expected_scope {
            return Err(RecentPeersError::ScopeMismatch {
                expected: expected_scope.to_string(),
                actual: recent.scope,
            });
        }
        Ok(recent)
    }

    /// Validate and encode the canonical compact version-1 JSON document.
    pub fn to_json(&self) -> Result<String, RecentPeersError> {
        self.validate()?;
        Ok(serde_json::to_string(self)?)
    }

    /// Validate and encode an indented version-1 JSON document.
    pub fn to_json_pretty(&self) -> Result<String, RecentPeersError> {
        self.validate()?;
        Ok(serde_json::to_string_pretty(self)?)
    }

    /// Local identity to which this routing cache is bound.
    pub fn local_npub(&self) -> &str {
        &self.local_npub
    }

    /// Application discovery scope to which this routing cache is bound.
    pub fn scope(&self) -> &str {
        &self.scope
    }

    /// Validate all schema invariants without decoding or encoding JSON.
    pub fn validate(&self) -> Result<(), RecentPeersError> {
        if self.version != RECENT_PEERS_VERSION {
            return Err(RecentPeersError::UnsupportedVersion {
                actual: self.version,
            });
        }
        validate_canonical_npub(&self.local_npub).map_err(|reason| {
            RecentPeersError::InvalidLocalNpub {
                npub: self.local_npub.clone(),
                reason,
            }
        })?;
        if self.peers.len() > RECENT_PEERS_MAX_PEERS {
            return Err(RecentPeersError::TooManyPeers {
                actual: self.peers.len(),
                max: RECENT_PEERS_MAX_PEERS,
            });
        }

        for (npub, peer) in &self.peers {
            validate_canonical_npub(npub).map_err(|reason| RecentPeersError::InvalidPeerNpub {
                npub: npub.clone(),
                reason,
            })?;
            if npub == &self.local_npub {
                return Err(RecentPeersError::LocalIdentityAsPeer);
            }
            validate_peer(npub, peer)?;
        }
        Ok(())
    }

    /// Record one currently authenticated endpoint snapshot.
    ///
    /// A connected peer's identity is retained regardless of transport. Only
    /// [`FipsEndpointPeer::authenticated_udp_restart_addr`] can add a restart
    /// endpoint. A disconnected status/retry entry is ignored because it is
    /// not fresh authentication evidence.
    ///
    /// Returns `true` only when the cache contents changed.
    pub fn observe_authenticated_peer(
        &mut self,
        peer: &FipsEndpointPeer,
        authenticated_at_ms: u64,
    ) -> Result<bool, RecentPeersError> {
        if !peer.connected {
            return Ok(false);
        }
        validate_canonical_npub(&peer.npub).map_err(|reason| {
            RecentPeersError::InvalidPeerNpub {
                npub: peer.npub.clone(),
                reason,
            }
        })?;
        if peer.npub == self.local_npub {
            return Err(RecentPeersError::LocalIdentityAsPeer);
        }

        let previous = self.peers.get(&peer.npub).cloned();
        let restart_addr = peer.authenticated_udp_restart_addr();
        let entry = self.peers.entry(peer.npub.clone()).or_insert(RecentPeer {
            last_authenticated_at_ms: authenticated_at_ms,
            endpoints: Vec::new(),
        });
        entry.last_authenticated_at_ms = entry.last_authenticated_at_ms.max(authenticated_at_ms);

        if let Some(addr) = restart_addr {
            observe_udp_endpoint(entry, addr, authenticated_at_ms);
        }
        self.retain_newest_peers();
        Ok(self.peers.get(&peer.npub) != previous.as_ref())
    }

    /// Remove identity and endpoint observations older than `ttl_ms`.
    ///
    /// Identity-only records are intentionally retained for the same TTL as
    /// routed records. Future timestamps survive clock rollback by using
    /// saturating age arithmetic.
    pub fn prune(&mut self, now_ms: u64, ttl_ms: u64) {
        self.peers.retain(|_, peer| {
            peer.endpoints.retain(|endpoint| {
                now_ms.saturating_sub(endpoint.last_authenticated_at_ms) <= ttl_ms
            });
            now_ms.saturating_sub(peer.last_authenticated_at_ms) <= ttl_ms
        });
    }

    /// Merge cached routes into already-authorized peer configurations.
    ///
    /// This method cannot create membership: it only mutates entries in the
    /// supplied slice and never calls [`crate::endpoint::FipsEndpoint::update_peers`].
    /// Applications remain responsible for deciding which peers belong in
    /// that slice. Cached addresses use authenticated provenance and preserve
    /// their observation timestamp for retry ranking.
    ///
    /// Returns the number of addresses added or refreshed.
    pub fn merge_into_peer_configs(&self, peer_configs: &mut [PeerConfig]) -> usize {
        let mut merged = 0;
        for config in peer_configs {
            let Some(canonical_npub) = peer_config_canonical_npub(&config.npub) else {
                continue;
            };
            let Some(recent) = self.peers.get(&canonical_npub) else {
                continue;
            };
            for endpoint in &recent.endpoints {
                merged += merge_endpoint(config, endpoint);
            }
        }
        merged
    }

    fn retain_newest_peers(&mut self) {
        if self.peers.len() <= RECENT_PEERS_MAX_PEERS {
            return;
        }
        let mut newest = self
            .peers
            .iter()
            .map(|(npub, peer)| (peer.last_authenticated_at_ms, npub.clone()))
            .collect::<Vec<_>>();
        newest.sort_by(|left, right| right.cmp(left));
        let keep = newest
            .into_iter()
            .take(RECENT_PEERS_MAX_PEERS)
            .map(|(_, npub)| npub)
            .collect::<HashSet<_>>();
        self.peers.retain(|npub, _| keep.contains(npub));
    }
}

fn validate_canonical_npub(npub: &str) -> Result<(), String> {
    let identity = PeerIdentity::from_npub(npub).map_err(|error| error.to_string())?;
    if identity.npub() != npub {
        return Err("npub is not in canonical lowercase NIP-19 form".to_string());
    }
    Ok(())
}

fn validate_peer(npub: &str, peer: &RecentPeer) -> Result<(), RecentPeersError> {
    if peer.endpoints.len() > RECENT_PEERS_MAX_ENDPOINTS_PER_PEER {
        return Err(RecentPeersError::TooManyEndpoints {
            npub: npub.to_string(),
            actual: peer.endpoints.len(),
            max: RECENT_PEERS_MAX_ENDPOINTS_PER_PEER,
        });
    }
    let mut addresses = HashSet::new();
    for endpoint in &peer.endpoints {
        if endpoint.last_authenticated_at_ms > peer.last_authenticated_at_ms {
            return Err(RecentPeersError::EndpointNewerThanPeer {
                npub: npub.to_string(),
                endpoint_at_ms: endpoint.last_authenticated_at_ms,
                peer_at_ms: peer.last_authenticated_at_ms,
            });
        }
        let addr = endpoint.addr.parse::<SocketAddr>().map_err(|_| {
            RecentPeersError::UnusableUdpEndpoint {
                npub: npub.to_string(),
                addr: endpoint.addr.clone(),
            }
        })?;
        if !is_reusable_udp_socket_addr(&addr) {
            return Err(RecentPeersError::UnusableUdpEndpoint {
                npub: npub.to_string(),
                addr: endpoint.addr.clone(),
            });
        }
        if !addresses.insert(addr) {
            return Err(RecentPeersError::DuplicateUdpEndpoint {
                npub: npub.to_string(),
                addr: endpoint.addr.clone(),
            });
        }
    }
    Ok(())
}

fn peer_config_canonical_npub(value: &str) -> Option<String> {
    if let Ok(identity) = PeerIdentity::from_npub(value) {
        return Some(identity.npub());
    }

    value
        .parse::<secp256k1::XOnlyPublicKey>()
        .ok()
        .map(PeerIdentity::from_pubkey)
        .map(|identity| identity.npub())
}

fn observe_udp_endpoint(peer: &mut RecentPeer, addr: SocketAddr, authenticated_at_ms: u64) {
    if let Some(endpoint) = peer.endpoints.iter_mut().find(|endpoint| {
        endpoint
            .addr
            .parse::<SocketAddr>()
            .is_ok_and(|stored| stored == addr)
    }) {
        endpoint.addr = addr.to_string();
        endpoint.last_authenticated_at_ms =
            endpoint.last_authenticated_at_ms.max(authenticated_at_ms);
    } else {
        peer.endpoints.push(RecentPeerEndpoint {
            transport: RecentPeerTransport::Udp,
            addr: addr.to_string(),
            last_authenticated_at_ms: authenticated_at_ms,
        });
    }
    peer.endpoints.sort_by(|left, right| {
        right
            .last_authenticated_at_ms
            .cmp(&left.last_authenticated_at_ms)
            .then_with(|| left.addr.cmp(&right.addr))
    });
    peer.endpoints.truncate(RECENT_PEERS_MAX_ENDPOINTS_PER_PEER);
}

fn merge_endpoint(config: &mut PeerConfig, endpoint: &RecentPeerEndpoint) -> usize {
    let cached_addr = endpoint.addr.parse::<SocketAddr>().ok();
    let existing = config.addresses.iter_mut().find(|candidate| {
        candidate.transport == "udp"
            && candidate
                .addr
                .parse::<SocketAddr>()
                .ok()
                .zip(cached_addr)
                .is_some_and(|(candidate, cached)| candidate == cached)
    });

    if let Some(existing) = existing {
        if existing.provenance == PeerAddressProvenance::Configured {
            return 0;
        }
        let prior_provenance = existing.provenance;
        let prior_seen_at_ms = existing.seen_at_ms;
        existing.provenance = PeerAddressProvenance::Authenticated;
        existing.seen_at_ms = Some(
            existing
                .seen_at_ms
                .unwrap_or_default()
                .max(endpoint.last_authenticated_at_ms),
        );
        return usize::from(
            existing.provenance != prior_provenance || existing.seen_at_ms != prior_seen_at_ms,
        );
    }

    config.addresses.push(
        PeerAddress::new("udp", &endpoint.addr)
            .authenticated()
            .with_seen_at_ms(endpoint.last_authenticated_at_ms),
    );
    1
}

#[cfg(test)]
mod tests;
