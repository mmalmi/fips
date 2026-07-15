//! Peer access control lists (ACLs) keyed by npub or alias.
//!
//! Evaluation follows TCP Wrappers ordering:
//! 1. If `peers.allow` matches a peer, allow it.
//! 2. Otherwise, if `peers.deny` matches a peer, deny it.
//! 3. Otherwise, allow it.
//!
//! `ALL` acts as a wildcard entry in either file. Because allow rules are
//! evaluated first, an allowlist match overrides a denylist match for the
//! same peer.

use crate::config::NostrDiscoveryPolicy;
use crate::node::{Node, NodeError};
use crate::transport::{TransportAddr, TransportId};
use crate::upper::hosts::{HostMap, HostMapReloader, file_mtime};
use crate::{NodeAddr, PeerIdentity};
use serde::Serialize;
use std::collections::{BTreeSet, HashSet};
use std::fmt;
use std::path::{Path, PathBuf};
use std::time::SystemTime;
use tracing::{debug, info, warn};

/// Default path for the peer allow list.
pub const DEFAULT_PEERS_ALLOW_PATH: &str = "/etc/fips/peers.allow";

/// Default path for the peer deny list.
pub const DEFAULT_PEERS_DENY_PATH: &str = "/etc/fips/peers.deny";

/// Result of evaluating a peer against the ACL.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerAclDecision {
    /// Explicitly permitted by `peers.allow`.
    AllowList,
    /// Explicitly rejected by `peers.deny`.
    DenyList,
    /// No rule matched after evaluating allow and deny rules.
    DefaultAllow,
}

impl PeerAclDecision {
    /// Whether the peer is allowed.
    pub fn allowed(self) -> bool {
        matches!(self, Self::AllowList | Self::DefaultAllow)
    }
}

impl fmt::Display for PeerAclDecision {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AllowList => write!(f, "allowlist match"),
            Self::DenyList => write!(f, "denylist match"),
            Self::DefaultAllow => write!(f, "default allow"),
        }
    }
}

/// Runtime context for ACL enforcement logging.
#[derive(Debug, Clone, Copy)]
pub enum PeerAclContext {
    OutboundConnect,
    InboundHandshake,
    OutboundHandshake,
}

/// Snapshot of the currently loaded ACL state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PeerAclStatus {
    pub allow_file: String,
    pub deny_file: String,
    pub enforcement_active: bool,
    pub effective_mode: String,
    pub default_decision: String,
    pub allow_all: bool,
    pub deny_all: bool,
    pub allow_file_entries: Vec<String>,
    pub deny_file_entries: Vec<String>,
    pub allow_entries: Vec<String>,
    pub deny_entries: Vec<String>,
}

impl fmt::Display for PeerAclContext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::OutboundConnect => write!(f, "outbound_connect"),
            Self::InboundHandshake => write!(f, "inbound_handshake"),
            Self::OutboundHandshake => write!(f, "outbound_handshake"),
        }
    }
}

/// Loaded peer ACL state.
#[derive(Debug, Clone, Default)]
pub struct PeerAcl {
    allow: HashSet<NodeAddr>,
    deny: HashSet<NodeAddr>,
    allow_file_entries: BTreeSet<String>,
    deny_file_entries: BTreeSet<String>,
    allow_npubs: BTreeSet<String>,
    deny_npubs: BTreeSet<String>,
    allow_all: bool,
    deny_all: bool,
}

impl PeerAcl {
    /// Create an empty ACL.
    pub fn new() -> Self {
        Self::default()
    }

    /// Load the allow/deny files into a new ACL.
    #[cfg(test)]
    pub fn load_files(allow_path: &Path, deny_path: &Path) -> Self {
        let hosts = HostMap::new();
        Self::load_files_with_hosts(allow_path, deny_path, &hosts)
    }

    /// Load the allow/deny files into a new ACL using alias resolution.
    pub fn load_files_with_hosts(allow_path: &Path, deny_path: &Path, hosts: &HostMap) -> Self {
        let mut acl = Self::new();
        acl.load_file(allow_path, true, hosts);
        acl.load_file(deny_path, false, hosts);

        if !acl.is_empty() {
            debug!(
                allow_entries = acl.allow.len(),
                deny_entries = acl.deny.len(),
                allow_all = acl.allow_all,
                deny_all = acl.deny_all,
                "Loaded peer ACL files"
            );
        }

        acl
    }

    /// Evaluate whether a peer is allowed.
    pub fn check(&self, peer: &PeerIdentity) -> PeerAclDecision {
        let addr = peer.node_addr();

        if self.allow_all || self.allow.contains(addr) {
            PeerAclDecision::AllowList
        } else if self.deny_all || self.deny.contains(addr) {
            PeerAclDecision::DenyList
        } else {
            PeerAclDecision::DefaultAllow
        }
    }

    /// Whether the ACL has no entries or wildcards.
    pub fn is_empty(&self) -> bool {
        self.allow.is_empty() && self.deny.is_empty() && !self.allow_all && !self.deny_all
    }

    /// Return the effective ACL mode after applying precedence rules.
    pub fn effective_mode(&self) -> &'static str {
        if self.allow_all {
            "allow_all"
        } else if !self.allow.is_empty() && self.deny_all {
            "allow_then_deny_all"
        } else if !self.allow.is_empty() && !self.deny.is_empty() {
            "allow_then_deny"
        } else if !self.allow.is_empty() {
            "allowlist"
        } else if self.deny_all {
            "deny_all"
        } else if !self.deny.is_empty() {
            "denylist"
        } else {
            "default_open"
        }
    }

    /// Return the decision applied to peers that are not named in either file.
    pub fn default_decision(&self) -> &'static str {
        if self.allow_all || (self.deny.is_empty() && !self.deny_all && self.allow.is_empty()) {
            "allow"
        } else if self.deny_all {
            "deny"
        } else {
            "allow"
        }
    }

    /// Return the loaded allowlist entries as npubs.
    pub fn allow_entries(&self) -> Vec<String> {
        self.allow_npubs.iter().cloned().collect()
    }

    /// Return the loaded allowlist tokens exactly as written in the ACL file.
    pub fn allow_file_entries(&self) -> Vec<String> {
        self.allow_file_entries.iter().cloned().collect()
    }

    /// Return the loaded denylist entries as npubs.
    pub fn deny_entries(&self) -> Vec<String> {
        self.deny_npubs.iter().cloned().collect()
    }

    /// Return the loaded denylist tokens exactly as written in the ACL file.
    pub fn deny_file_entries(&self) -> Vec<String> {
        self.deny_file_entries.iter().cloned().collect()
    }

    fn load_file(&mut self, path: &Path, is_allow: bool, hosts: &HostMap) {
        let contents = match std::fs::read_to_string(path) {
            Ok(c) => c,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                debug!(path = %path.display(), "No ACL file found, skipping");
                return;
            }
            Err(e) => {
                warn!(path = %path.display(), error = %e, "Failed to read ACL file");
                return;
            }
        };

        for (line_num, line) in contents.lines().enumerate() {
            let trimmed = line.split('#').next().unwrap_or("").trim();

            if trimmed.is_empty() {
                continue;
            }

            let fields: Vec<&str> = trimmed.split_whitespace().collect();
            if fields.len() != 1 {
                warn!(
                    path = %path.display(),
                    line = line_num + 1,
                    content = %trimmed,
                    "Expected one ACL entry per line, skipping"
                );
                continue;
            }

            let entry = fields[0];
            if entry.eq_ignore_ascii_case("ALL") {
                if is_allow {
                    self.allow_all = true;
                } else {
                    self.deny_all = true;
                }
                continue;
            }

            let (peer, resolved_npub) = match Self::resolve_entry(entry, hosts) {
                Ok(resolved) => resolved,
                Err(e) => {
                    warn!(
                        path = %path.display(),
                        line = line_num + 1,
                        entry = %entry,
                        error = %e,
                        "Skipping invalid ACL entry"
                    );
                    continue;
                }
            };

            if is_allow {
                self.allow.insert(*peer.node_addr());
                self.allow_file_entries.insert(entry.to_string());
                self.allow_npubs.insert(resolved_npub);
            } else {
                self.deny.insert(*peer.node_addr());
                self.deny_file_entries.insert(entry.to_string());
                self.deny_npubs.insert(resolved_npub);
            }
        }
    }

    fn resolve_entry(entry: &str, hosts: &HostMap) -> Result<(PeerIdentity, String), String> {
        if let Ok(peer) = PeerIdentity::from_npub(entry) {
            return Ok((peer, entry.to_string()));
        }

        let mapped = hosts
            .lookup_npub(entry)
            .ok_or_else(|| "unknown alias or invalid npub".to_string())?;
        let peer = PeerIdentity::from_npub(mapped)
            .map_err(|e| format!("alias resolves to invalid npub: {e}"))?;
        Ok((peer, mapped.to_string()))
    }
}

/// Tracks peer ACL files and reloads them on mtime changes.
pub struct PeerAclReloader {
    acl: PeerAcl,
    hosts: HostMapReloader,
    file_backed: bool,
    allow_path: PathBuf,
    deny_path: PathBuf,
    last_allow_mtime: Option<SystemTime>,
    last_deny_mtime: Option<SystemTime>,
}

impl PeerAclReloader {
    /// Create a reloader for explicit ACL file paths.
    #[cfg(test)]
    pub(crate) fn with_paths(allow_path: PathBuf, deny_path: PathBuf) -> Self {
        Self::with_alias_sources(
            allow_path,
            deny_path,
            HostMap::new(),
            PathBuf::from(crate::upper::hosts::DEFAULT_HOSTS_PATH),
        )
    }

    /// Create a reloader with explicit ACL paths and alias sources.
    pub(crate) fn with_alias_sources(
        allow_path: PathBuf,
        deny_path: PathBuf,
        base_hosts: HostMap,
        hosts_path: PathBuf,
    ) -> Self {
        let last_allow_mtime = file_mtime(&allow_path);
        let last_deny_mtime = file_mtime(&deny_path);
        let hosts = HostMapReloader::new(base_hosts, hosts_path);
        let acl = PeerAcl::load_files_with_hosts(&allow_path, &deny_path, hosts.hosts());

        Self {
            acl,
            hosts,
            file_backed: true,
            allow_path,
            deny_path,
            last_allow_mtime,
            last_deny_mtime,
        }
    }

    /// Create a memory-only ACL reloader.
    ///
    /// This preserves configured peer aliases for display and DNS host-map
    /// lookups while avoiding system ACL/hosts file probes.
    pub(crate) fn memory_only(base_hosts: HostMap) -> Self {
        Self {
            acl: PeerAcl::new(),
            hosts: HostMapReloader::memory_only(base_hosts),
            file_backed: false,
            allow_path: PathBuf::new(),
            deny_path: PathBuf::new(),
            last_allow_mtime: None,
            last_deny_mtime: None,
        }
    }

    /// Get the current ACL.
    pub fn acl(&self) -> &PeerAcl {
        &self.acl
    }

    /// Return a human-readable snapshot of the loaded ACL state.
    pub fn status(&self) -> PeerAclStatus {
        PeerAclStatus {
            allow_file: self.allow_path.display().to_string(),
            deny_file: self.deny_path.display().to_string(),
            enforcement_active: !self.acl.is_empty(),
            effective_mode: self.acl.effective_mode().to_string(),
            default_decision: self.acl.default_decision().to_string(),
            allow_all: self.acl.allow_all,
            deny_all: self.acl.deny_all,
            allow_file_entries: self.acl.allow_file_entries(),
            deny_file_entries: self.acl.deny_file_entries(),
            allow_entries: self.acl.allow_entries(),
            deny_entries: self.acl.deny_entries(),
        }
    }

    /// Check whether ACL or hosts alias sources changed and reload if needed.
    pub fn check_reload(&mut self) -> bool {
        if !self.file_backed {
            return false;
        }

        let allow_mtime = file_mtime(&self.allow_path);
        let deny_mtime = file_mtime(&self.deny_path);
        let hosts_changed = self.hosts.check_reload();

        if allow_mtime == self.last_allow_mtime
            && deny_mtime == self.last_deny_mtime
            && !hosts_changed
        {
            return false;
        }

        self.last_allow_mtime = allow_mtime;
        self.last_deny_mtime = deny_mtime;
        self.acl =
            PeerAcl::load_files_with_hosts(&self.allow_path, &self.deny_path, self.hosts.hosts());

        info!(
            allow_file = %self.allow_path.display(),
            deny_file = %self.deny_path.display(),
            allow_entries = self.acl.allow.len(),
            deny_entries = self.acl.deny.len(),
            alias_entries = self.hosts.hosts().len(),
            allow_all = self.acl.allow_all,
            deny_all = self.acl.deny_all,
            "Reloaded peer ACL files"
        );
        true
    }
}

impl Node {
    pub(in crate::node) fn enforces_configured_only_peer_admission(&self) -> bool {
        self.config.node.discovery.nostr.enabled
            && self.config.node.discovery.nostr.policy == NostrDiscoveryPolicy::ConfiguredOnly
    }

    pub(in crate::node) fn is_configured_peer_identity(
        &self,
        peer_identity: &PeerIdentity,
    ) -> bool {
        self.configured_peer(peer_identity.node_addr()).is_some()
    }

    fn open_discovery_active_or_pending_for_peer(&self, peer_identity: &PeerIdentity) -> bool {
        let peer_node_addr = peer_identity.node_addr();
        self.peers.contains_key(peer_node_addr)
            || self.retry_pending.contains_key(peer_node_addr)
            || self.peers.connection_values().any(|conn| {
                conn.expected_identity()
                    .is_some_and(|id| id == peer_identity)
            })
    }

    fn open_discovery_non_configured_occupancy(&self, configured_npubs: &HashSet<String>) -> usize {
        let mut occupied = HashSet::new();
        for (peer_addr, peer) in &self.peers {
            if !configured_npubs.contains(&peer.npub()) {
                occupied.insert(*peer_addr);
            }
        }
        let mut unknown_inbound = 0usize;
        for connection in self
            .peers
            .connection_values()
            .filter(|conn| conn.is_inbound())
        {
            if let Some(identity) = connection.expected_identity() {
                if !configured_npubs.contains(&identity.npub()) {
                    occupied.insert(*identity.node_addr());
                }
            } else {
                unknown_inbound = unknown_inbound.saturating_add(1);
            }
        }

        occupied.len().saturating_add(unknown_inbound)
    }

    fn admits_open_discovery_peer(&self, peer_identity: &PeerIdentity) -> bool {
        let nostr = &self.config.node.discovery.nostr;
        if !nostr.enabled || nostr.policy != NostrDiscoveryPolicy::Open {
            return true;
        }
        if self.is_configured_peer_identity(peer_identity)
            || self.open_discovery_active_or_pending_for_peer(peer_identity)
        {
            return true;
        }

        let configured_npubs = self
            .config
            .peers()
            .iter()
            .map(|peer| peer.npub.clone())
            .collect::<HashSet<_>>();
        self.open_discovery_non_configured_occupancy(&configured_npubs)
            < nostr.open_discovery_max_pending
    }

    /// Reload the peer ACL if the ACL or hosts files changed.
    pub(crate) fn reload_peer_acl(&mut self) -> bool {
        self.peer_acl.check_reload()
    }

    /// Return a control-plane snapshot of the current peer ACL.
    pub(crate) fn peer_acl_status(&self) -> PeerAclStatus {
        self.peer_acl.status()
    }

    /// Reject a peer if the current ACL denies it.
    pub(crate) fn authorize_peer(
        &self,
        peer_identity: &PeerIdentity,
        context: PeerAclContext,
        transport_id: TransportId,
        remote_addr: &TransportAddr,
    ) -> Result<(), NodeError> {
        let local_rendezvous = self.is_local_rendezvous_path(transport_id, remote_addr);
        if self.enforces_configured_only_peer_admission()
            && !self.is_configured_peer_identity(peer_identity)
            && !local_rendezvous
        {
            let peer_node_addr = *peer_identity.node_addr();
            warn!(
                peer = %self.peer_display_name(&peer_node_addr),
                npub = %peer_identity.npub(),
                transport_id = %transport_id,
                remote_addr = %remote_addr,
                context = %context,
                "Rejected non-configured peer by configured-only discovery policy"
            );

            return Err(NodeError::AccessDenied(format!(
                "peer {} rejected by configured-only discovery policy",
                peer_identity.npub()
            )));
        }

        if !local_rendezvous
            && matches!(context, PeerAclContext::InboundHandshake)
            && !self.admits_open_discovery_peer(peer_identity)
        {
            let peer_node_addr = *peer_identity.node_addr();
            warn!(
                peer = %self.peer_display_name(&peer_node_addr),
                npub = %peer_identity.npub(),
                transport_id = %transport_id,
                remote_addr = %remote_addr,
                context = %context,
                open_discovery_max_pending = self.config.node.discovery.nostr.open_discovery_max_pending,
                "Rejected non-configured inbound peer by open-discovery admission cap"
            );

            return Err(NodeError::AccessDenied(format!(
                "peer {} rejected by open-discovery admission cap",
                peer_identity.npub()
            )));
        }

        let decision = self.peer_acl.acl().check(peer_identity);
        if decision.allowed() {
            return Ok(());
        }

        let peer_node_addr = *peer_identity.node_addr();
        warn!(
            peer = %self.peer_display_name(&peer_node_addr),
            npub = %peer_identity.npub(),
            transport_id = %transport_id,
            remote_addr = %remote_addr,
            context = %context,
            decision = %decision,
            "Rejected peer by ACL"
        );

        Err(NodeError::AccessDenied(format!(
            "peer {} rejected by ACL: {}",
            peer_identity.npub(),
            decision
        )))
    }
}

#[cfg(test)]
#[cfg(test)]
mod tests;
