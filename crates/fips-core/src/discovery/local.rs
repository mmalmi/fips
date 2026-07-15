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
#[path = "local_tests.rs"]
mod tests;
