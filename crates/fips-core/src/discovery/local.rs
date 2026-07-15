//! Same-host instance discovery via a small registry under `~/.fips`.
//!
//! This is deliberately lower-tech than mDNS: processes owned by the same
//! user publish a JSON record with loopback-reachable transport contacts.
//! Consumers treat records as routing hints only. The Noise handshake still
//! authenticates the advertised `npub`, so a stale or spoofed file cannot
//! impersonate a peer. Scans ignore stale records but never delete another
//! process's files, avoiding cleanup races with atomic heartbeat replacement.

use std::fs;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use tracing::debug;

pub const LOCAL_INSTANCE_RECORD_VERSION: u16 = 1;
pub const LOCAL_INSTANCE_ADVERTISEMENT_VERSION: u16 = 2;
const LOCAL_INSTANCE_ADVERTISEMENT_EXTENSION: &str = "v2";
const ENV_DIR: &str = "FIPS_LOCAL_INSTANCE_DIR";
const ENV_DISABLE: &str = "FIPS_LOCAL_INSTANCE_DISCOVERY";
static LOCAL_INSTANCE_WRITE_LOCK: Mutex<()> = Mutex::new(());

pub(crate) fn local_discovery_scope(config: &crate::Config) -> Option<String> {
    normalized_scope(config.node.discovery.local.scope.as_deref())
        .or_else(|| lan_discovery_scope(config))
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

/// Runtime configuration for the same-host JSON registry.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct LocalInstanceDiscoveryConfig {
    /// Master switch. Disabled in plain `Config::default()` so generic FIPS
    /// nodes don't cross-feed through the user's home directory by accident.
    /// Embedded endpoints with a discovery scope enable it explicitly.
    #[serde(default)]
    pub enabled: bool,
    /// Same-host composition namespace. This is intentionally independent of
    /// public Nostr application and LAN discovery scopes. When omitted, the
    /// older LAN/Nostr-derived scope remains the compatibility fallback.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    /// Optional registry directory. Defaults to `$FIPS_LOCAL_INSTANCE_DIR`,
    /// then `~/.fips/instances`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dir: Option<String>,
    /// How often to refresh our own JSON record.
    #[serde(default = "LocalInstanceDiscoveryConfig::default_publish_interval_secs")]
    pub publish_interval_secs: u64,
    /// Steady-state scan cadence after the startup sweep window.
    #[serde(default = "LocalInstanceDiscoveryConfig::default_scan_interval_secs")]
    pub scan_interval_secs: u64,
    /// Scan cadence during the short startup sweep window.
    #[serde(default = "LocalInstanceDiscoveryConfig::default_startup_scan_interval_secs")]
    pub startup_scan_interval_secs: u64,
    /// Duration of the startup sweep window.
    #[serde(default = "LocalInstanceDiscoveryConfig::default_startup_scan_duration_secs")]
    pub startup_scan_duration_secs: u64,
    /// Records older than this are ignored.
    #[serde(default = "LocalInstanceDiscoveryConfig::default_stale_after_secs")]
    pub stale_after_secs: u64,
}

impl Default for LocalInstanceDiscoveryConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            scope: None,
            dir: None,
            publish_interval_secs: Self::default_publish_interval_secs(),
            scan_interval_secs: Self::default_scan_interval_secs(),
            startup_scan_interval_secs: Self::default_startup_scan_interval_secs(),
            startup_scan_duration_secs: Self::default_startup_scan_duration_secs(),
            stale_after_secs: Self::default_stale_after_secs(),
        }
    }
}

impl LocalInstanceDiscoveryConfig {
    fn default_publish_interval_secs() -> u64 {
        30
    }
    fn default_scan_interval_secs() -> u64 {
        60
    }
    fn default_startup_scan_interval_secs() -> u64 {
        5
    }
    fn default_startup_scan_duration_secs() -> u64 {
        20
    }
    fn default_stale_after_secs() -> u64 {
        180
    }

    pub(crate) fn publish_interval_ms(&self) -> u64 {
        secs_to_ms_floor(self.publish_interval_secs, 1)
    }

    pub(crate) fn scan_interval_ms(&self) -> u64 {
        secs_to_ms_floor(self.scan_interval_secs, 1)
    }

    pub(crate) fn startup_scan_interval_ms(&self) -> u64 {
        secs_to_ms_floor(self.startup_scan_interval_secs, 1)
    }

    pub(crate) fn startup_scan_duration_ms(&self) -> u64 {
        self.startup_scan_duration_secs.saturating_mul(1000)
    }

    pub(crate) fn stale_after_ms(&self) -> u64 {
        secs_to_ms_floor(self.stale_after_secs, 1)
    }
}

fn secs_to_ms_floor(secs: u64, min_secs: u64) -> u64 {
    secs.max(min_secs).saturating_mul(1000)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LocalInstanceContact {
    pub transport: String,
    pub addr: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LocalInstanceRecord {
    pub version: u16,
    pub npub: String,
    pub discovery_scope: String,
    pub pid: u32,
    pub started_at_ms: u64,
    pub updated_at_ms: u64,
    #[serde(default)]
    pub contacts: Vec<LocalInstanceContact>,
}

/// One reusable same-host capability exposed over the authenticated FIPS
/// endpoint. A capability without an FSP port describes an instance role,
/// such as providing routes to the outer network. Like contacts, capabilities
/// are untrusted hints: consumers must confirm them through the authenticated
/// peer and validate the selected service protocol.
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

/// A live v1 instance record joined with its matching v2 capabilities.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalInstanceAdvertisement {
    pub instance_id: String,
    pub instance: LocalInstanceRecord,
    pub capabilities: Vec<LocalInstanceCapability>,
}

impl LocalInstanceAdvertisement {
    /// Return this instance's preferred advert for one capability name.
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct LocalInstanceCapabilitiesRecord {
    version: u16,
    instance_id: String,
    #[serde(default)]
    capabilities: Vec<LocalInstanceCapability>,
}

/// Choose one live provider deterministically. Higher advertised priority
/// wins; equal-priority candidates are ordered by their stable process-lifetime
/// instance ID so all local consumers converge without a coordinator.
pub fn select_capability_provider<'a>(
    adverts: &'a [LocalInstanceAdvertisement],
    capability_name: &str,
) -> Option<&'a LocalInstanceAdvertisement> {
    adverts
        .iter()
        .filter(|advert| advert.capability(capability_name).is_some())
        .min_by(|left, right| capability_provider_order(left, right, capability_name))
}

/// Rank every live provider so a consumer can fall through when the preferred
/// hint does not answer. Highest priority sorts first, followed by stable ID.
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
        .then_with(|| left.instance_id.cmp(&right.instance_id))
}

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

#[derive(Debug, Clone)]
pub struct LocalInstanceRegistry {
    dir: PathBuf,
    record_path: PathBuf,
    advertisement_path: PathBuf,
    npub: String,
    discovery_scope: String,
    pid: u32,
    started_at_ms: u64,
    stale_after_ms: u64,
}

impl LocalInstanceRegistry {
    pub fn new(
        npub: impl Into<String>,
        discovery_scope: impl Into<String>,
        config: &LocalInstanceDiscoveryConfig,
        started_at_ms: u64,
    ) -> Result<Self, LocalInstanceRegistryError> {
        if !config.enabled || env_disables_discovery() {
            return Err(LocalInstanceRegistryError::Disabled);
        }

        let npub = npub.into();
        let discovery_scope = discovery_scope.into();
        let dir = registry_dir(config.dir.as_deref())?;
        let pid = std::process::id();
        let record_path = dir.join(record_filename(&npub, &discovery_scope, pid));
        let advertisement_path = advertisement_path(&record_path);

        Ok(Self {
            dir,
            record_path,
            advertisement_path,
            npub,
            discovery_scope,
            pid,
            started_at_ms,
            stale_after_ms: config.stale_after_ms(),
        })
    }

    pub fn publish(
        &self,
        contacts: Vec<LocalInstanceContact>,
        now_ms: u64,
    ) -> Result<(), LocalInstanceRegistryError> {
        self.publish_with_capabilities(contacts, Vec::new(), now_ms)
    }

    pub fn publish_with_capabilities(
        &self,
        contacts: Vec<LocalInstanceContact>,
        capabilities: Vec<LocalInstanceCapability>,
        now_ms: u64,
    ) -> Result<(), LocalInstanceRegistryError> {
        let _guard = LOCAL_INSTANCE_WRITE_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if contacts.is_empty() {
            return self.remove_files();
        }

        ensure_private_dir(&self.dir)?;
        let record = LocalInstanceRecord {
            version: LOCAL_INSTANCE_RECORD_VERSION,
            npub: self.npub.clone(),
            discovery_scope: self.discovery_scope.clone(),
            pid: self.pid,
            started_at_ms: self.started_at_ms,
            updated_at_ms: now_ms,
            contacts,
        };
        let capability_record =
            (!capabilities.is_empty()).then(|| LocalInstanceCapabilitiesRecord {
                version: LOCAL_INSTANCE_ADVERTISEMENT_VERSION,
                instance_id: instance_id(
                    &record.npub,
                    &record.discovery_scope,
                    record.pid,
                    record.started_at_ms,
                ),
                capabilities,
            });
        let capabilities_changed = read_capabilities_record(&self.advertisement_path).as_ref()
            != capability_record.as_ref();
        if capabilities_changed {
            // Invalidate the old hint first. If either following write fails,
            // consumers fail closed instead of using withdrawn capabilities.
            remove_file_if_exists(&self.advertisement_path)?;
        }
        write_private_json(&self.record_path, &record, self.pid)?;
        match (capabilities_changed, capability_record) {
            (true, Some(capability_record)) => {
                write_private_json(&self.advertisement_path, &capability_record, self.pid)
            }
            _ => Ok(()),
        }
    }

    pub fn remove(&self) -> Result<(), LocalInstanceRegistryError> {
        let _guard = LOCAL_INSTANCE_WRITE_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        self.remove_files()
    }

    fn remove_files(&self) -> Result<(), LocalInstanceRegistryError> {
        remove_file_if_exists(&self.record_path)?;
        remove_file_if_exists(&self.advertisement_path)
    }

    pub fn scan(
        &self,
        now_ms: u64,
        stale_after_ms: u64,
    ) -> Result<Vec<LocalInstanceRecord>, LocalInstanceRegistryError> {
        self.scan_records(now_ms, stale_after_ms, false)
    }

    fn scan_records(
        &self,
        now_ms: u64,
        stale_after_ms: u64,
        include_self: bool,
    ) -> Result<Vec<LocalInstanceRecord>, LocalInstanceRegistryError> {
        let entries = match fs::read_dir(&self.dir) {
            Ok(entries) => entries,
            Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(source) => {
                return Err(LocalInstanceRegistryError::Io {
                    path: self.dir.clone(),
                    source,
                });
            }
        };

        let mut records = Vec::new();
        for entry in entries {
            let entry = match entry {
                Ok(entry) => entry,
                Err(err) => {
                    debug!(error = %err, "local instance registry: skipping unreadable entry");
                    continue;
                }
            };
            let path = entry.path();
            if path.extension().and_then(|s| s.to_str()) != Some("json") {
                continue;
            }

            let text = match fs::read_to_string(&path) {
                Ok(text) => text,
                Err(err) => {
                    debug!(path = %path.display(), error = %err, "local instance registry: skipping unreadable record");
                    continue;
                }
            };
            let record: LocalInstanceRecord = match serde_json::from_str(&text) {
                Ok(record) => record,
                Err(err) => {
                    debug!(path = %path.display(), error = %err, "local instance registry: skipping malformed record");
                    continue;
                }
            };
            if record.version != LOCAL_INSTANCE_RECORD_VERSION {
                continue;
            }
            if now_ms.saturating_sub(record.updated_at_ms) > stale_after_ms {
                continue;
            }
            if record.contacts.is_empty() {
                continue;
            }
            if record.discovery_scope != self.discovery_scope {
                continue;
            }
            if !include_self && record.npub == self.npub && record.pid == self.pid {
                continue;
            }
            records.push(record);
        }

        records.sort_by(|a, b| b.updated_at_ms.cmp(&a.updated_at_ms));
        Ok(records)
    }

    /// Read all live capability providers, including this process, and attach
    /// a v2 advert only when it matches the accepted v1 record's stable
    /// process-lifetime ID. Including self lets every process run the same
    /// deterministic provider election. Contacts and freshness always come
    /// from v1, so heartbeat updates do not create false withdrawals.
    pub fn scan_advertisements(
        &self,
        now_ms: u64,
        stale_after_ms: u64,
    ) -> Result<Vec<LocalInstanceAdvertisement>, LocalInstanceRegistryError> {
        self.scan_records(now_ms, stale_after_ms, true)
            .map(|records| {
                records
                    .into_iter()
                    .filter_map(|record| read_matching_advertisement(&self.dir, &record))
                    .collect()
            })
    }

    pub fn live_advertisements(
        &self,
    ) -> Result<Vec<LocalInstanceAdvertisement>, LocalInstanceRegistryError> {
        self.scan_advertisements(crate::time::now_ms(), self.stale_after_ms)
    }
}

fn read_matching_advertisement(
    dir: &Path,
    record: &LocalInstanceRecord,
) -> Option<LocalInstanceAdvertisement> {
    let path = advertisement_path(&dir.join(record_filename(
        &record.npub,
        &record.discovery_scope,
        record.pid,
    )));
    let capability_record = read_capabilities_record(&path)?;
    let expected_instance_id = instance_id(
        &record.npub,
        &record.discovery_scope,
        record.pid,
        record.started_at_ms,
    );
    (capability_record.version == LOCAL_INSTANCE_ADVERTISEMENT_VERSION
        && capability_record.instance_id == expected_instance_id)
        .then(|| LocalInstanceAdvertisement {
            instance_id: expected_instance_id,
            instance: record.clone(),
            capabilities: capability_record.capabilities,
        })
}

fn read_capabilities_record(path: &Path) -> Option<LocalInstanceCapabilitiesRecord> {
    let text = fs::read_to_string(path).ok()?;
    serde_json::from_str(&text).ok()
}

fn write_private_json<T: Serialize>(
    path: &Path,
    value: &T,
    pid: u32,
) -> Result<(), LocalInstanceRegistryError> {
    let data = serde_json::to_vec_pretty(value)?;
    let extension = path
        .extension()
        .and_then(|value| value.to_str())
        .unwrap_or("");
    let tmp_path = path.with_extension(format!("{extension}.tmp-{pid}"));
    fs::write(&tmp_path, data).map_err(|source| LocalInstanceRegistryError::Io {
        path: tmp_path.clone(),
        source,
    })?;
    set_private_file_permissions(&tmp_path)?;
    fs::rename(&tmp_path, path).map_err(|source| {
        let _ = fs::remove_file(&tmp_path);
        LocalInstanceRegistryError::Io {
            path: path.to_path_buf(),
            source,
        }
    })
}

fn remove_file_if_exists(path: &Path) -> Result<(), LocalInstanceRegistryError> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(source) => Err(LocalInstanceRegistryError::Io {
            path: path.to_path_buf(),
            source,
        }),
    }
}

pub fn contact_for_transport_addr(
    transport: impl Into<String>,
    local_addr: SocketAddr,
) -> Option<LocalInstanceContact> {
    if local_addr.port() == 0 {
        return None;
    }

    let addr = if local_addr.ip().is_unspecified() {
        match local_addr.ip() {
            IpAddr::V4(_) => SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), local_addr.port()),
            IpAddr::V6(_) => SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), local_addr.port()),
        }
    } else {
        local_addr
    };

    Some(LocalInstanceContact {
        transport: transport.into(),
        addr: addr.to_string(),
    })
}

fn env_disables_discovery() -> bool {
    std::env::var(ENV_DISABLE)
        .ok()
        .map(|value| {
            let value = value.trim().to_ascii_lowercase();
            matches!(value.as_str(), "0" | "false" | "off" | "no" | "disabled")
        })
        .unwrap_or(false)
}

fn registry_dir(configured: Option<&str>) -> Result<PathBuf, LocalInstanceRegistryError> {
    if let Some(path) = configured
        && !path.trim().is_empty()
    {
        return Ok(PathBuf::from(path));
    }
    if let Ok(path) = std::env::var(ENV_DIR)
        && !path.trim().is_empty()
    {
        return Ok(PathBuf::from(path));
    }
    dirs::home_dir()
        .map(|home| home.join(".fips").join("instances"))
        .ok_or(LocalInstanceRegistryError::NoRegistryDir)
}

fn record_filename(npub: &str, discovery_scope: &str, pid: u32) -> String {
    let mut hasher = Sha256::new();
    hasher.update(discovery_scope.as_bytes());
    hasher.update([0]);
    hasher.update(npub.as_bytes());
    hasher.update([0]);
    hasher.update(pid.to_le_bytes());
    format!("{}.json", hex::encode(hasher.finalize()))
}

fn advertisement_path(record_path: &Path) -> PathBuf {
    record_path.with_extension(LOCAL_INSTANCE_ADVERTISEMENT_EXTENSION)
}

fn instance_id(npub: &str, discovery_scope: &str, pid: u32, started_at_ms: u64) -> String {
    let mut hasher = Sha256::new();
    hasher.update(discovery_scope.as_bytes());
    hasher.update([0]);
    hasher.update(npub.as_bytes());
    hasher.update([0]);
    hasher.update(pid.to_le_bytes());
    hasher.update(started_at_ms.to_le_bytes());
    hex::encode(hasher.finalize())
}

fn ensure_private_dir(path: &Path) -> Result<(), LocalInstanceRegistryError> {
    fs::create_dir_all(path).map_err(|source| LocalInstanceRegistryError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    set_private_dir_permissions(path)
}

#[cfg(unix)]
fn set_private_dir_permissions(path: &Path) -> Result<(), LocalInstanceRegistryError> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700)).map_err(|source| {
        LocalInstanceRegistryError::Io {
            path: path.to_path_buf(),
            source,
        }
    })
}

#[cfg(not(unix))]
fn set_private_dir_permissions(_path: &Path) -> Result<(), LocalInstanceRegistryError> {
    Ok(())
}

#[cfg(unix)]
fn set_private_file_permissions(path: &Path) -> Result<(), LocalInstanceRegistryError> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).map_err(|source| {
        LocalInstanceRegistryError::Io {
            path: path.to_path_buf(),
            source,
        }
    })
}

#[cfg(not(unix))]
fn set_private_file_permissions(_path: &Path) -> Result<(), LocalInstanceRegistryError> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::TransportInstances;
    use crate::{Config, FipsEndpoint, UdpConfig};

    fn config_for(dir: &Path) -> LocalInstanceDiscoveryConfig {
        LocalInstanceDiscoveryConfig {
            enabled: true,
            dir: Some(dir.to_string_lossy().to_string()),
            ..LocalInstanceDiscoveryConfig::default()
        }
    }

    #[test]
    fn same_host_scope_does_not_replace_lan_scope() {
        let mut config = Config::new();
        config.node.discovery.local.scope = Some("iris-local-v1".to_string());
        config.node.discovery.lan.scope = Some("nostr-vpn:private-network".to_string());

        assert_eq!(
            local_discovery_scope(&config).as_deref(),
            Some("iris-local-v1")
        );
        assert_eq!(
            lan_discovery_scope(&config).as_deref(),
            Some("nostr-vpn:private-network")
        );
    }

    fn record(npub: &str, scope: &str, pid: u32, updated_at_ms: u64) -> LocalInstanceRecord {
        LocalInstanceRecord {
            version: LOCAL_INSTANCE_RECORD_VERSION,
            npub: npub.to_string(),
            discovery_scope: scope.to_string(),
            pid,
            started_at_ms: 1,
            updated_at_ms,
            contacts: vec![LocalInstanceContact {
                transport: "udp".to_string(),
                addr: "127.0.0.1:22121".to_string(),
            }],
        }
    }

    fn capability(name: &str, fsp_port: Option<u16>) -> LocalInstanceCapability {
        match fsp_port {
            Some(port) => LocalInstanceCapability::service(name, port),
            None => LocalInstanceCapability::role(name),
        }
    }

    #[test]
    fn wildcard_ipv4_contact_uses_loopback() {
        let contact =
            contact_for_transport_addr("udp", "0.0.0.0:22121".parse().unwrap()).expect("contact");

        assert_eq!(contact.transport, "udp");
        assert_eq!(contact.addr, "127.0.0.1:22121");
    }

    #[test]
    fn wildcard_ipv6_contact_uses_loopback() {
        let contact =
            contact_for_transport_addr("udp", "[::]:22121".parse().unwrap()).expect("contact");

        assert_eq!(contact.addr, "[::1]:22121");
    }

    #[test]
    fn publish_and_remove_record() {
        let temp = tempfile::tempdir().unwrap();
        let registry =
            LocalInstanceRegistry::new("npub-self", "scope-a", &config_for(temp.path()), 100)
                .unwrap();

        registry
            .publish(
                vec![LocalInstanceContact {
                    transport: "udp".to_string(),
                    addr: "127.0.0.1:22121".to_string(),
                }],
                200,
            )
            .unwrap();

        let text = fs::read_to_string(&registry.record_path).unwrap();
        let parsed: LocalInstanceRecord = serde_json::from_str(&text).unwrap();
        assert_eq!(parsed.npub, "npub-self");
        assert_eq!(parsed.discovery_scope, "scope-a");
        assert_eq!(parsed.updated_at_ms, 200);

        registry.remove().unwrap();
        assert!(!registry.record_path.exists());
    }

    #[test]
    fn capability_advert_preserves_v1_instance_discovery() {
        let temp = tempfile::tempdir().unwrap();
        let config = config_for(temp.path());
        let provider =
            LocalInstanceRegistry::new("npub-provider", "iris-local-v1", &config, 100).unwrap();
        let contacts = vec![LocalInstanceContact {
            transport: "udp".to_string(),
            addr: "127.0.0.1:49152".to_string(),
        }];

        provider
            .publish_with_capabilities(
                contacts,
                vec![
                    capability("hashtree.blob/1", Some(39_018)),
                    capability("nostr.pubsub/1", Some(7_368)),
                    LocalInstanceCapability::role("fips.egress/1").with_priority(100),
                ],
                200,
            )
            .unwrap();

        // The registry keeps emitting the immutable v1 shape so released
        // FIPS readers with deny_unknown_fields still discover this peer.
        let v1_text = fs::read_to_string(&provider.record_path).unwrap();
        assert!(!v1_text.contains("capabilities"));
        let v1: LocalInstanceRecord = serde_json::from_str(&v1_text).unwrap();
        assert_eq!(v1.version, LOCAL_INSTANCE_RECORD_VERSION);

        let consumer =
            LocalInstanceRegistry::new("npub-consumer", "iris-local-v1", &config, 150).unwrap();
        let legacy_records = consumer.scan(250, 1_000).unwrap();
        assert_eq!(legacy_records.len(), 1);
        assert_eq!(legacy_records[0].npub, "npub-provider");

        let adverts = consumer.scan_advertisements(250, 1_000).unwrap();
        assert_eq!(adverts.len(), 1);
        assert_eq!(adverts[0].instance.npub, "npub-provider");
        assert_eq!(
            provider.scan_advertisements(250, 1_000).unwrap()[0]
                .instance
                .npub,
            "npub-provider",
            "provider election must include the local instance"
        );
        assert_eq!(
            adverts[0].capabilities,
            vec![
                capability("hashtree.blob/1", Some(39_018)),
                capability("nostr.pubsub/1", Some(7_368)),
                LocalInstanceCapability::role("fips.egress/1").with_priority(100),
            ]
        );

        // A v1 heartbeat may be renamed just before the unchanged v2 file.
        // Matching the stable instance ID keeps capabilities continuously
        // visible through that harmless update window.
        let mut refreshed_v1 = v1;
        refreshed_v1.updated_at_ms = 201;
        write_private_json(&provider.record_path, &refreshed_v1, provider.pid).unwrap();
        let adverts = consumer.scan_advertisements(250, 1_000).unwrap();
        assert_eq!(adverts[0].capabilities.len(), 3);

        provider.remove().unwrap();
        assert!(!provider.record_path.exists());
        assert!(!provider.advertisement_path.exists());
        assert!(consumer.scan_advertisements(300, 1_000).unwrap().is_empty());
    }

    #[test]
    fn scan_ignores_orphaned_capability_advert_without_deleting_files() {
        let temp = tempfile::tempdir().unwrap();
        let config = config_for(temp.path());
        let provider =
            LocalInstanceRegistry::new("npub-provider", "iris-local-v1", &config, 100).unwrap();
        provider
            .publish_with_capabilities(
                vec![LocalInstanceContact {
                    transport: "udp".to_string(),
                    addr: "127.0.0.1:49152".to_string(),
                }],
                vec![capability("hashtree.blob/1", Some(39_018))],
                200,
            )
            .unwrap();
        fs::remove_file(&provider.record_path).unwrap();
        assert!(provider.advertisement_path.exists());

        let consumer =
            LocalInstanceRegistry::new("npub-consumer", "iris-local-v1", &config, 150).unwrap();
        assert!(consumer.scan_advertisements(250, 1_000).unwrap().is_empty());
        assert!(
            provider.advertisement_path.exists(),
            "read-only scans must not race and delete a fresh publication"
        );
    }

    #[test]
    fn capability_provider_selection_fails_over_after_withdrawal() {
        let temp = tempfile::tempdir().unwrap();
        let config = config_for(temp.path());
        let contacts = || {
            vec![LocalInstanceContact {
                transport: "udp".to_string(),
                addr: "127.0.0.1:49152".to_string(),
            }]
        };
        let low = LocalInstanceRegistry::new("npub-low", "iris-local-v1", &config, 100).unwrap();
        let high = LocalInstanceRegistry::new("npub-high", "iris-local-v1", &config, 100).unwrap();
        low.publish_with_capabilities(
            contacts(),
            vec![LocalInstanceCapability::role("fips.egress/1").with_priority(10)],
            200,
        )
        .unwrap();
        high.publish_with_capabilities(
            contacts(),
            vec![LocalInstanceCapability::role("fips.egress/1").with_priority(20)],
            200,
        )
        .unwrap();

        let consumer =
            LocalInstanceRegistry::new("npub-consumer", "iris-local-v1", &config, 150).unwrap();
        let adverts = consumer.scan_advertisements(250, 1_000).unwrap();
        assert_eq!(
            rank_capability_providers(&adverts, "fips.egress/1")
                .into_iter()
                .map(|advert| advert.instance.npub.as_str())
                .collect::<Vec<_>>(),
            vec!["npub-high", "npub-low"]
        );
        assert_eq!(
            select_capability_provider(&adverts, "fips.egress/1")
                .unwrap()
                .instance
                .npub,
            "npub-high"
        );

        high.publish_with_capabilities(contacts(), Vec::new(), 300)
            .unwrap();
        let adverts = consumer.scan_advertisements(300, 1_000).unwrap();
        assert_eq!(
            select_capability_provider(&adverts, "fips.egress/1")
                .unwrap()
                .instance
                .npub,
            "npub-low"
        );
        assert_eq!(consumer.scan(300, 1_000).unwrap().len(), 2);
    }

    #[tokio::test]
    async fn endpoint_heartbeat_publishes_runtime_capabilities() {
        let temp = tempfile::tempdir().unwrap();
        let mut config = Config::new();
        config.transports.udp = TransportInstances::Single(UdpConfig {
            bind_addr: Some("127.0.0.1:0".to_string()),
            advertise_on_nostr: Some(false),
            ..UdpConfig::default()
        });
        config.node.discovery.lan.scope = Some("iris-local-v1".to_string());
        config.node.discovery.local = config_for(temp.path());

        let endpoint = FipsEndpoint::builder()
            .config(config.clone())
            .discovery_scope("iris-local-v1")
            .local_role("fips.egress/1", 100)
            .without_system_tun()
            .bind()
            .await
            .expect("provider endpoint should bind");
        let consumer = LocalInstanceRegistry::new(
            "npub-consumer",
            "iris-local-v1",
            &config.node.discovery.local,
            1,
        )
        .unwrap();
        let adverts = consumer
            .scan_advertisements(u64::MAX / 2, u64::MAX)
            .unwrap();

        assert_eq!(adverts.len(), 1);
        assert_eq!(adverts[0].instance.npub, endpoint.npub());
        assert_eq!(
            adverts[0].capabilities,
            vec![LocalInstanceCapability::role("fips.egress/1").with_priority(100)]
        );

        let service = endpoint
            .register_service_receiver_with_capability(LocalInstanceCapability::service(
                "hashtree.blob/1",
                39_018,
            ))
            .await
            .expect("Hashtree service should register");
        let adverts = consumer
            .scan_advertisements(u64::MAX / 2, u64::MAX)
            .unwrap();
        assert_eq!(
            adverts[0].capabilities,
            vec![
                LocalInstanceCapability::role("fips.egress/1").with_priority(100),
                LocalInstanceCapability::service("hashtree.blob/1", 39_018),
            ]
        );

        drop(service);
        tokio::time::timeout(std::time::Duration::from_secs(3), async {
            loop {
                let adverts = consumer
                    .scan_advertisements(u64::MAX / 2, u64::MAX)
                    .unwrap();
                if adverts
                    .first()
                    .and_then(|advert| advert.capability("hashtree.blob/1"))
                    .is_none()
                {
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("dropped service must withdraw its capability");
        let _replacement = endpoint
            .register_service_receiver_with_capability(LocalInstanceCapability::service(
                "hashtree.blob/1",
                39_018,
            ))
            .await
            .expect("withdrawn service port should be reusable");

        endpoint
            .shutdown()
            .await
            .expect("provider should shut down");
        assert!(
            consumer
                .scan_advertisements(u64::MAX / 2, u64::MAX)
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn scan_filters_self_scope_and_stale_records() {
        let temp = tempfile::tempdir().unwrap();
        let registry =
            LocalInstanceRegistry::new("npub-self", "scope-a", &config_for(temp.path()), 100)
                .unwrap();
        ensure_private_dir(temp.path()).unwrap();

        let cases = [
            record("npub-peer", "scope-a", 2, 900),
            record("npub-self", "scope-a", registry.pid, 900),
            record("npub-other-scope", "scope-b", 3, 900),
            record("npub-stale", "scope-a", 4, 100),
        ];
        for (index, record) in cases.iter().enumerate() {
            let path = temp.path().join(format!("{index}.json"));
            fs::write(path, serde_json::to_vec(record).unwrap()).unwrap();
        }

        let records = registry.scan(1000, 500).unwrap();

        assert_eq!(records.len(), 1);
        assert_eq!(records[0].npub, "npub-peer");
    }
}
