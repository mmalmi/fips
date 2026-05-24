//! Same-host instance discovery via a small registry under `~/.fips`.
//!
//! This is deliberately lower-tech than mDNS: processes owned by the same
//! user publish a JSON record with loopback-reachable transport contacts.
//! Consumers treat records as routing hints only. The Noise handshake still
//! authenticates the advertised `npub`, so a stale or spoofed file cannot
//! impersonate a peer.

use std::fs;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use tracing::debug;

pub const LOCAL_INSTANCE_RECORD_VERSION: u16 = 1;
const ENV_DIR: &str = "FIPS_LOCAL_INSTANCE_DIR";
const ENV_DISABLE: &str = "FIPS_LOCAL_INSTANCE_DISCOVERY";

/// Runtime configuration for the same-host JSON registry.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LocalInstanceDiscoveryConfig {
    /// Master switch. Disabled in plain `Config::default()` so generic FIPS
    /// nodes don't cross-feed through the user's home directory by accident.
    /// Embedded endpoints with a discovery scope enable it explicitly.
    #[serde(default)]
    pub enabled: bool,
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
    /// Records older than this are ignored and best-effort removed.
    #[serde(default = "LocalInstanceDiscoveryConfig::default_stale_after_secs")]
    pub stale_after_secs: u64,
}

impl Default for LocalInstanceDiscoveryConfig {
    fn default() -> Self {
        Self {
            enabled: false,
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
    npub: String,
    discovery_scope: String,
    pid: u32,
    started_at_ms: u64,
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

        Ok(Self {
            dir,
            record_path,
            npub,
            discovery_scope,
            pid,
            started_at_ms,
        })
    }

    pub fn publish(
        &self,
        contacts: Vec<LocalInstanceContact>,
        now_ms: u64,
    ) -> Result<(), LocalInstanceRegistryError> {
        if contacts.is_empty() {
            self.remove()?;
            return Ok(());
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
        let data = serde_json::to_vec_pretty(&record)?;
        let tmp_path = self
            .record_path
            .with_extension(format!("json.tmp-{}", self.pid));
        fs::write(&tmp_path, data).map_err(|source| LocalInstanceRegistryError::Io {
            path: tmp_path.clone(),
            source,
        })?;
        set_private_file_permissions(&tmp_path)?;
        fs::rename(&tmp_path, &self.record_path).map_err(|source| {
            let _ = fs::remove_file(&tmp_path);
            LocalInstanceRegistryError::Io {
                path: self.record_path.clone(),
                source,
            }
        })?;
        Ok(())
    }

    pub fn remove(&self) -> Result<(), LocalInstanceRegistryError> {
        match fs::remove_file(&self.record_path) {
            Ok(()) => Ok(()),
            Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(source) => Err(LocalInstanceRegistryError::Io {
                path: self.record_path.clone(),
                source,
            }),
        }
    }

    pub fn scan(
        &self,
        now_ms: u64,
        stale_after_ms: u64,
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
            if record.discovery_scope != self.discovery_scope {
                continue;
            }
            if record.npub == self.npub && record.pid == self.pid {
                continue;
            }
            if now_ms.saturating_sub(record.updated_at_ms) > stale_after_ms {
                let _ = fs::remove_file(&path);
                continue;
            }
            if record.contacts.is_empty() {
                continue;
            }
            records.push(record);
        }

        records.sort_by(|a, b| b.updated_at_ms.cmp(&a.updated_at_ms));
        Ok(records)
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

    fn config_for(dir: &Path) -> LocalInstanceDiscoveryConfig {
        LocalInstanceDiscoveryConfig {
            enabled: true,
            dir: Some(dir.to_string_lossy().to_string()),
            ..LocalInstanceDiscoveryConfig::default()
        }
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
