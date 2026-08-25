//! FIPS Configuration System
//!
//! Loads configuration from YAML files with a cascading priority system:
//! 1. `./fips.yaml` (current directory - highest priority)
//! 2. `~/.config/fips/fips.yaml` (user config directory)
//! 3. `/etc/fips/fips.yaml` (system - lowest priority)
//!
//! Values from higher priority files override those from lower priority files.
//!
//! # YAML Structure
//!
//! The YAML structure mirrors the sysctl-style paths in the architecture docs.
//! For example, `node.identity.nsec` in the docs corresponds to:
//!
//! ```yaml
//! node:
//!   identity:
//!     nsec: "nsec1..."
//! ```

#[cfg(target_os = "linux")]
mod gateway;
mod node;
mod peer;
mod transport;
mod webrtc_budget;

use crate::discovery::nostr::FRESHNESS_SKEW_TOLERANCE_MS;
use crate::upper::config::{DnsConfig, TunConfig};
use crate::{Identity, IdentityError};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use thiserror::Error;
use zeroize::{Zeroize, Zeroizing};

pub use crate::discovery::local::LocalInstanceDiscoveryConfig;
#[cfg(target_os = "linux")]
pub use gateway::{ConntrackConfig, GatewayConfig, GatewayDnsConfig, PortForward, Proto};
pub use node::{
    BloomConfig, BuffersConfig, CacheConfig, ControlConfig, DiscoveryConfig, LimitsConfig,
    NodeConfig, NostrDiscoveryConfig, NostrDiscoveryPolicy, NostrPeerfindingSource,
    RateLimitConfig, RekeyConfig, RetryConfig, RoutingConfig, RoutingMode, SessionConfig,
    SessionMmpConfig, TreeConfig,
};
pub use peer::{ConnectPolicy, PeerAddress, PeerAddressProvenance, PeerConfig};
#[cfg(feature = "sim-transport")]
pub use transport::SimTransportConfig;
pub use transport::{
    BleConfig, DirectoryServiceConfig, EthernetConfig, TcpConfig, TorConfig, TransportInstances,
    TransportsConfig, UdpConfig, WebRtcConfig, WebSocketConfig,
};
pub(crate) use webrtc_budget::{
    MAX_WEBRTC_CONFIG_CANDIDATE_SOCKETS, validate_webrtc_candidate_socket_budget,
};
#[cfg(feature = "webrtc-transport")]
pub(crate) use webrtc_budget::{
    MAX_WEBRTC_HOST_CANDIDATE_SOCKETS, MAX_WEBRTC_LOCAL_CANDIDATE_LINES,
    MAX_WEBRTC_LOCAL_CANDIDATE_ROUTES, MAX_WEBRTC_REMOTE_CANDIDATE_LINES,
    MAX_WEBRTC_REMOTE_CANDIDATE_ROUTES,
};
#[cfg(all(test, feature = "webrtc-transport"))]
pub(crate) use webrtc_budget::{MAX_WEBRTC_SOCKETS_PER_STUN_SERVER, MAX_WEBRTC_STUN_SERVERS};

/// Default config filename.
const CONFIG_FILENAME: &str = "fips.yaml";

/// Default key filename, placed alongside the config file.
const KEY_FILENAME: &str = "fips.key";

/// Default public key filename, placed alongside the key file.
const PUB_FILENAME: &str = "fips.pub";

/// Returns true if the textual `host:port` form refers to a loopback host.
/// Recognizes IPv4 `127.x.x.x`, IPv6 `::1` (with or without brackets), and
/// the literal string `localhost`. Hostnames are conservatively assumed to
/// be non-loopback. Used by `Config::validate()` to reject misconfigured
/// loopback UDP binds combined with non-loopback peer addresses (see
/// ISSUE-2026-0005).
fn is_loopback_addr_str(addr: &str) -> bool {
    // Bracketed IPv6: `[::1]:port`
    if let Some(rest) = addr.strip_prefix('[')
        && let Some(end) = rest.find(']')
    {
        let host = &rest[..end];
        return host == "::1";
    }
    // Plain `host:port` — split on the rightmost ':'.
    let host = match addr.rsplit_once(':') {
        Some((h, _)) => h,
        None => addr,
    };
    host == "localhost" || host == "::1" || host == "0:0:0:0:0:0:0:1" || host.starts_with("127.")
}

/// Derive the key file path from a config file path.
pub fn key_file_path(config_path: &Path) -> PathBuf {
    config_path
        .parent()
        .unwrap_or(Path::new("."))
        .join(KEY_FILENAME)
}

/// Derive the public key file path from a config file path.
pub fn pub_file_path(config_path: &Path) -> PathBuf {
    config_path
        .parent()
        .unwrap_or(Path::new("."))
        .join(PUB_FILENAME)
}

/// Resolve a default Unix-socket path under the canonical order:
/// `/run/fips/<filename>` -> `$XDG_RUNTIME_DIR/fips/<filename>` -> `/tmp/fips-<filename>`.
///
/// `/run/fips` is the packaged convention. The resolver selects it whenever
/// the directory exists so daemon and client defaults stay aligned. The daemon
/// bind path creates missing parent directories; packaged installs create
/// `/run/fips` via tmpfiles before service start.
#[cfg(unix)]
pub(crate) fn resolve_default_socket(filename: &str) -> String {
    if Path::new("/run/fips").is_dir() {
        return format!("/run/fips/{filename}");
    }

    if let Ok(xdg) = std::env::var("XDG_RUNTIME_DIR")
        && Path::new(&xdg).is_dir()
    {
        return format!("{xdg}/fips/{filename}");
    }

    format!("/tmp/fips-{filename}")
}

/// Default control socket path for fipsctl / fipstop.
///
/// On Unix, checks the system-wide path first (used when the daemon runs as
/// a systemd service), then falls back to the user's XDG runtime directory.
/// On Windows, returns the default TCP port ("21210").
pub fn default_control_path() -> PathBuf {
    #[cfg(unix)]
    {
        PathBuf::from(resolve_default_socket("control.sock"))
    }
    #[cfg(windows)]
    {
        PathBuf::from("21210")
    }
}

/// Default gateway control socket path.
///
/// On Unix, follows the same pattern as the main control socket.
/// On Windows, returns a placeholder TCP port ("21211").
pub fn default_gateway_path() -> PathBuf {
    #[cfg(unix)]
    {
        PathBuf::from(resolve_default_socket("gateway.sock"))
    }
    #[cfg(windows)]
    {
        PathBuf::from("21211")
    }
}

/// Read a bare bech32 nsec from a key file.
pub fn read_key_file(path: &Path) -> Result<String, ConfigError> {
    let contents = std::fs::read_to_string(path).map_err(|e| ConfigError::ReadFile {
        path: path.to_path_buf(),
        source: e,
    })?;
    let contents = Zeroizing::new(contents);
    let nsec = contents.trim().to_string();
    if nsec.is_empty() {
        return Err(ConfigError::EmptyKeyFile {
            path: path.to_path_buf(),
        });
    }
    Ok(nsec)
}

fn open_key_output(path: &Path, mode: u32, enforce_mode: bool) -> std::io::Result<std::fs::File> {
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);

    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(mode).custom_flags(libc::O_NOFOLLOW);
    }

    let file = options.open(path)?;

    #[cfg(unix)]
    if enforce_mode {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(std::fs::Permissions::from_mode(mode))?;
    }

    #[cfg(not(unix))]
    let _ = (mode, enforce_mode);

    Ok(file)
}

fn classify_key_open_error(path: &Path, source: std::io::Error) -> ConfigError {
    if path
        .symlink_metadata()
        .is_ok_and(|metadata| metadata.file_type().is_symlink())
    {
        ConfigError::KeyPathIsSymlink {
            path: path.to_path_buf(),
        }
    } else {
        ConfigError::WriteKeyFile {
            path: path.to_path_buf(),
            source,
        }
    }
}

fn warn_unmanaged_key_file(path: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        let Ok(metadata) = path.symlink_metadata() else {
            return;
        };
        if metadata.file_type().is_symlink() {
            tracing::warn!(
                path = %path.display(),
                "Identity key file is a symlink; its target permissions are operator-managed"
            );
        } else if metadata.is_file() && metadata.permissions().mode() & 0o077 != 0 {
            tracing::warn!(
                path = %path.display(),
                mode = format!("{:04o}", metadata.permissions().mode() & 0o7777),
                "Identity key file is accessible beyond its owner; expected mode 0600"
            );
        }
    }

    #[cfg(not(unix))]
    let _ = path;
}

/// Write a bare bech32 nsec to a key file with restricted permissions.
///
/// On Unix, the file is created with mode 0600 (owner read/write only).
/// On Windows, the file inherits default ACLs from the parent directory.
pub fn write_key_file(path: &Path, nsec: &str) -> Result<(), ConfigError> {
    use std::io::Write;

    let mut file =
        open_key_output(path, 0o600, true).map_err(|error| classify_key_open_error(path, error))?;

    file.write_all(nsec.as_bytes())
        .map_err(|e| ConfigError::WriteKeyFile {
            path: path.to_path_buf(),
            source: e,
        })?;
    file.write_all(b"\n")
        .map_err(|e| ConfigError::WriteKeyFile {
            path: path.to_path_buf(),
            source: e,
        })?;
    Ok(())
}

/// Write a bare bech32 npub to a public key file.
///
/// On Unix, the file is created with mode 0644 (owner read/write, others read).
/// On Windows, the file inherits default ACLs from the parent directory.
pub fn write_pub_file(path: &Path, npub: &str) -> Result<(), ConfigError> {
    use std::io::Write;

    let mut file = open_key_output(path, 0o644, false)
        .map_err(|error| classify_key_open_error(path, error))?;

    file.write_all(npub.as_bytes())
        .map_err(|e| ConfigError::WriteKeyFile {
            path: path.to_path_buf(),
            source: e,
        })?;
    file.write_all(b"\n")
        .map_err(|e| ConfigError::WriteKeyFile {
            path: path.to_path_buf(),
            source: e,
        })?;
    Ok(())
}

/// Resolve identity from config and key file.
///
/// Behavior depends on `node.identity.persistent`:
///
/// - **`persistent: false`** (default): generate a fresh ephemeral keypair
///   every start. Key files are written for operator visibility but overwritten
///   on each restart.
///
/// - **`persistent: true`**: use three-tier resolution:
///   1. Explicit nsec in config — highest priority
///   2. Persistent key file (`fips.key`) — reused across restarts
///   3. Generate new — creates keypair, writes `fips.key` and `fips.pub`
///
/// - **`nsec` set explicitly**: always uses that, regardless of `persistent`.
///
/// Returns the nsec string (bech32 or hex) to be used for identity creation.
pub fn resolve_identity(
    config: &Config,
    loaded_paths: &[PathBuf],
) -> Result<ResolvedIdentity, ConfigError> {
    use crate::encode_nsec;

    // Explicit nsec in config always wins
    if let Some(nsec) = &config.node.identity.nsec {
        return Ok(ResolvedIdentity {
            nsec: nsec.clone(),
            source: IdentitySource::Config,
        });
    }

    // Determine key file directory from loaded config paths
    let config_ref = if let Some(path) = loaded_paths.last() {
        path.clone()
    } else {
        Config::search_paths()
            .first()
            .cloned()
            .unwrap_or_else(|| PathBuf::from("./fips.yaml"))
    };
    let key_path = key_file_path(&config_ref);
    let pub_path = pub_file_path(&config_ref);

    if config.node.identity.persistent {
        // Persistent mode: load existing key file or generate-and-persist
        if key_path.symlink_metadata().is_ok() {
            let nsec = Zeroizing::new(read_key_file(&key_path)?);
            let identity = Identity::from_secret_str(&nsec)?;
            warn_unmanaged_key_file(&key_path);
            if let Err(error) = write_pub_file(&pub_path, &identity.npub()) {
                tracing::warn!(path = %pub_path.display(), %error, "Failed to write public identity file");
            }
            return Ok(ResolvedIdentity {
                nsec: nsec.to_string(),
                source: IdentitySource::KeyFile(key_path),
            });
        }

        // No key file yet — generate and persist
        let identity = Identity::generate();
        let mut our_keypair = identity.keypair();
        let mut secret_key = our_keypair.secret_key();
        let nsec = Zeroizing::new(encode_nsec(&secret_key));
        secret_key.non_secure_erase();
        our_keypair.non_secure_erase();
        let npub = identity.npub();

        if let Some(parent) = key_path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }

        match write_key_file(&key_path, &nsec) {
            Ok(()) => {
                if let Err(error) = write_pub_file(&pub_path, &npub) {
                    tracing::warn!(path = %pub_path.display(), %error, "Failed to write public identity file");
                }
                Ok(ResolvedIdentity {
                    nsec: nsec.to_string(),
                    source: IdentitySource::Generated(key_path),
                })
            }
            Err(error) => {
                tracing::warn!(
                    path = %key_path.display(),
                    %error,
                    "Failed to persist generated identity; the npub will change on restart"
                );
                Ok(ResolvedIdentity {
                    nsec: nsec.to_string(),
                    source: IdentitySource::Ephemeral,
                })
            }
        }
    } else {
        // Ephemeral mode (default): fresh keypair every start, write key files
        // for operator visibility
        let identity = Identity::generate();
        let mut our_keypair = identity.keypair();
        let mut secret_key = our_keypair.secret_key();
        let nsec = Zeroizing::new(encode_nsec(&secret_key));
        secret_key.non_secure_erase();
        our_keypair.non_secure_erase();
        let npub = identity.npub();

        if let Some(parent) = key_path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }

        if key_path.symlink_metadata().is_ok() {
            tracing::warn!(
                path = %key_path.display(),
                config_key = "node.identity.persistent",
                "Existing identity key path is being replaced by an ephemeral identity"
            );
        }
        if let Err(error) = write_key_file(&key_path, &nsec) {
            tracing::warn!(path = %key_path.display(), %error, "Failed to write ephemeral identity key file");
        }
        if let Err(error) = write_pub_file(&pub_path, &npub) {
            tracing::warn!(path = %pub_path.display(), %error, "Failed to write public identity file");
        }

        Ok(ResolvedIdentity {
            nsec: nsec.to_string(),
            source: IdentitySource::Ephemeral,
        })
    }
}

/// Result of identity resolution.
///
/// The returned `nsec` is caller-owned secret material. Callers should move it
/// into the long-lived identity configuration promptly and clear it before
/// replacing or discarding it.
pub struct ResolvedIdentity {
    /// The nsec string (bech32 or hex) for creating an Identity.
    pub nsec: String,
    /// Where the identity came from.
    pub source: IdentitySource,
}

/// Where a resolved identity originated.
pub enum IdentitySource {
    /// From explicit nsec in config file.
    Config,
    /// Loaded from a persistent key file.
    KeyFile(PathBuf),
    /// Generated and saved to a new key file.
    Generated(PathBuf),
    /// Generated but could not be persisted.
    Ephemeral,
}

/// Errors that can occur during configuration loading.
#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("failed to read config file {path}: {source}")]
    ReadFile {
        path: PathBuf,
        source: std::io::Error,
    },

    #[error("failed to parse config file {path}: {source}")]
    ParseYaml {
        path: PathBuf,
        source: serde_yaml::Error,
    },

    #[error("key file is empty: {path}")]
    EmptyKeyFile { path: PathBuf },

    #[error("failed to write key file {path}: {source}")]
    WriteKeyFile {
        path: PathBuf,
        source: std::io::Error,
    },

    #[error("refusing to write key file through a symlink: {path}")]
    KeyPathIsSymlink { path: PathBuf },

    #[error("identity error: {0}")]
    Identity(#[from] IdentityError),

    #[error("invalid configuration: {0}")]
    Validation(String),
}

/// Identity configuration (`node.identity.*`).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct IdentityConfig {
    /// Secret key in nsec (bech32) or hex format (`node.identity.nsec`).
    /// If not specified, a new keypair will be generated.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nsec: Option<String>,

    /// Whether to persist the identity across restarts (`node.identity.persistent`).
    /// When false (default), a fresh ephemeral keypair is generated each start.
    /// When true, the key file is reused across restarts.
    #[serde(default)]
    pub persistent: bool,
}

impl IdentityConfig {
    /// Replace the configured private key after clearing the previous value.
    pub fn replace_nsec(&mut self, nsec: Option<String>) {
        self.nsec.zeroize();
        self.nsec = nsec;
    }

    /// Transfer the configured private key out without cloning it.
    ///
    /// `IdentityConfig` clears an nsec that remains in the struct when it is
    /// dropped. Taking the option leaves `None` behind, so callers can retain
    /// the pre-zeroization ability to move the secret into another owner.
    pub fn take_nsec(&mut self) -> Option<String> {
        self.nsec.take()
    }

    /// Consume this configuration and transfer its private key without cloning.
    pub fn into_nsec(mut self) -> Option<String> {
        self.take_nsec()
    }
}

impl Drop for IdentityConfig {
    fn drop(&mut self) {
        self.nsec.zeroize();
    }
}

/// Root configuration structure.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Config {
    /// Node configuration (`node.*`).
    #[serde(default)]
    pub node: NodeConfig,

    /// TUN interface configuration (`tun.*`).
    #[serde(default)]
    pub tun: TunConfig,

    /// DNS responder configuration (`dns.*`).
    #[serde(default)]
    pub dns: DnsConfig,

    /// Transport instances (`transports.*`).
    #[serde(default, skip_serializing_if = "TransportsConfig::is_empty")]
    pub transports: TransportsConfig,

    /// Static peers to connect to (`peers`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub peers: Vec<PeerConfig>,

    /// Gateway configuration (`gateway`).
    #[cfg(target_os = "linux")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gateway: Option<GatewayConfig>,
}

impl Config {
    /// Create a new empty configuration.
    pub fn new() -> Self {
        Self::default()
    }

    /// Load configuration from the standard search paths.
    ///
    /// Files are loaded in reverse priority order and merged:
    /// 1. `/etc/fips/fips.yaml` (loaded first, lowest priority)
    /// 2. `~/.config/fips/fips.yaml` (user config)
    /// 3. `./fips.yaml` (loaded last, highest priority)
    ///
    /// Returns a tuple of (config, paths_loaded) where paths_loaded contains
    /// the paths that were successfully loaded.
    pub fn load() -> Result<(Self, Vec<PathBuf>), ConfigError> {
        let search_paths = Self::search_paths();
        Self::load_from_paths(&search_paths)
    }

    /// Load configuration from specific paths.
    ///
    /// Paths are processed in order, with later paths overriding earlier ones.
    pub fn load_from_paths(paths: &[PathBuf]) -> Result<(Self, Vec<PathBuf>), ConfigError> {
        let mut merged = ZeroizingYamlValue(serde_yaml::Value::Mapping(serde_yaml::Mapping::new()));
        let mut loaded_paths = Vec::new();

        for path in paths {
            if path.exists() {
                let contents = Zeroizing::new(std::fs::read_to_string(path).map_err(|e| {
                    ConfigError::ReadFile {
                        path: path.to_path_buf(),
                        source: e,
                    }
                })?);
                let mut file_config: serde_yaml::Value =
                    serde_yaml::from_str(&contents).map_err(|e| ConfigError::ParseYaml {
                        path: path.to_path_buf(),
                        source: e,
                    })?;
                if file_config.is_null() {
                    file_config = serde_yaml::Value::Mapping(serde_yaml::Mapping::new());
                }
                merge_yaml_value(&mut merged.0, file_config);
                loaded_paths.push(path.clone());
            }
        }

        // Deserialize by reference so `merged` remains reachable and its
        // strings can be cleared on both the success and error paths.
        let config = Config::deserialize(&merged.0).map_err(|e| ConfigError::ParseYaml {
            path: loaded_paths
                .last()
                .cloned()
                .unwrap_or_else(|| PathBuf::from("<merged config>")),
            source: e,
        })?;

        Ok((config, loaded_paths))
    }

    /// Load configuration from a single file.
    pub fn load_file(path: &Path) -> Result<Self, ConfigError> {
        let contents =
            Zeroizing::new(
                std::fs::read_to_string(path).map_err(|e| ConfigError::ReadFile {
                    path: path.to_path_buf(),
                    source: e,
                })?,
            );

        serde_yaml::from_str(&contents).map_err(|e| ConfigError::ParseYaml {
            path: path.to_path_buf(),
            source: e,
        })
    }

    /// Get the standard search paths in priority order (lowest to highest).
    pub fn search_paths() -> Vec<PathBuf> {
        let mut paths = Vec::new();

        // System config (lowest priority)
        paths.push(PathBuf::from("/etc/fips").join(CONFIG_FILENAME));

        // User config directory
        if let Some(config_dir) = dirs::config_dir() {
            paths.push(config_dir.join("fips").join(CONFIG_FILENAME));
        }

        // Home directory (legacy location)
        if let Some(home_dir) = dirs::home_dir() {
            paths.push(home_dir.join(".fips.yaml"));
        }

        // Current directory (highest priority)
        paths.push(PathBuf::from(".").join(CONFIG_FILENAME));

        paths
    }

    /// Merge another configuration into this one.
    ///
    /// Values from `other` override values in `self` when present.
    pub fn merge(&mut self, mut other: Config) {
        // Merge node.identity section
        if other.node.identity.nsec.is_some() {
            self.node
                .identity
                .replace_nsec(other.node.identity.nsec.take());
        }
        if other.node.identity.persistent {
            self.node.identity.persistent = true;
        }
        // Merge node.leaf_only
        if other.node.leaf_only {
            self.node.leaf_only = true;
        }
        // Merge tun section
        if other.tun.enabled {
            self.tun.enabled = true;
        }
        if other.tun.name.is_some() {
            self.tun.name = other.tun.name;
        }
        if other.tun.mtu.is_some() {
            self.tun.mtu = other.tun.mtu;
        }
        // Merge dns section — higher-priority config always wins for enabled
        self.dns.enabled = other.dns.enabled;
        if other.dns.bind_addr.is_some() {
            self.dns.bind_addr = other.dns.bind_addr;
        }
        if other.dns.port.is_some() {
            self.dns.port = other.dns.port;
        }
        if other.dns.ttl.is_some() {
            self.dns.ttl = other.dns.ttl;
        }
        // Merge transports section
        self.transports.merge(other.transports);
        // Merge peers (replace if non-empty)
        if !other.peers.is_empty() {
            self.peers = other.peers;
        }
        // Merge gateway section — higher-priority config replaces entirely
        #[cfg(target_os = "linux")]
        if other.gateway.is_some() {
            self.gateway = other.gateway;
        }
    }

    /// Create an Identity from this configuration.
    ///
    /// If an nsec is configured, uses that to create the identity.
    /// Otherwise, generates a new random identity.
    pub fn create_identity(&self) -> Result<Identity, ConfigError> {
        match &self.node.identity.nsec {
            Some(nsec) => Ok(Identity::from_secret_str(nsec)?),
            None => Ok(Identity::generate()),
        }
    }

    /// Check if an identity is configured (vs. will be generated).
    pub fn has_identity(&self) -> bool {
        self.node.identity.nsec.is_some()
    }

    /// Check if leaf-only mode is configured.
    pub fn is_leaf_only(&self) -> bool {
        self.node.leaf_only
    }

    /// Get the configured peers.
    pub fn peers(&self) -> &[PeerConfig] {
        &self.peers
    }

    /// Get peers that should auto-connect on startup.
    pub fn auto_connect_peers(&self) -> impl Iterator<Item = &PeerConfig> {
        self.peers.iter().filter(|p| p.is_auto_connect())
    }

    /// Validate cross-field configuration invariants.
    pub fn validate(&self) -> Result<(), ConfigError> {
        let nostr = &self.node.discovery.nostr;
        let local = &self.node.discovery.local;

        if local.enabled && !local.has_valid_rendezvous_addr() {
            return Err(ConfigError::Validation(format!(
                "node.discovery.local.rendezvous_addr must be a non-zero IPv4 loopback address, got {}",
                local.rendezvous_addr
            )));
        }

        if local.enabled {
            let fixed = std::net::SocketAddr::V4(local.rendezvous_addr);
            for (name, udp) in self.transports.udp.iter() {
                if udp.outbound_only() {
                    continue;
                }
                let Ok(bind) = udp.bind_addr().parse::<std::net::SocketAddr>() else {
                    continue;
                };
                if bind.port() == fixed.port() && (bind.ip().is_unspecified() || bind == fixed) {
                    let name = name.unwrap_or("default");
                    return Err(ConfigError::Validation(format!(
                        "transports.udp.{name} bind {bind} collides with the local rendezvous at {fixed}"
                    )));
                }
            }
        }

        let any_transport_advertises_on_nostr = self
            .transports
            .udp
            .iter()
            .any(|(_, cfg)| cfg.advertise_on_nostr())
            || self
                .transports
                .tcp
                .iter()
                .any(|(_, cfg)| cfg.advertise_on_nostr())
            || self
                .transports
                .tor
                .iter()
                .any(|(_, cfg)| cfg.advertise_on_nostr())
            || self
                .transports
                .webrtc
                .iter()
                .any(|(_, cfg)| cfg.advertise_on_nostr());

        if any_transport_advertises_on_nostr && !nostr.enabled {
            return Err(ConfigError::Validation(
                "at least one transport has `advertise_on_nostr = true`, but `node.discovery.nostr.enabled` is false".to_string(),
            ));
        }

        let has_nat_udp_advert = self
            .transports
            .udp
            .iter()
            .any(|(_, cfg)| cfg.advertise_on_nostr() && !cfg.is_public());

        if nostr.enabled && has_nat_udp_advert && nostr.stun_servers.is_empty() {
            return Err(ConfigError::Validation(
                "NAT UDP advert publishing requires `node.discovery.nostr.stun_servers` to be non-empty".to_string(),
            ));
        }

        // Reject loopback UDP bind combined with non-loopback peer addresses.
        // Linux pins the source IP to a loopback-bound socket, so packets
        // sent from such a socket to external peers are dropped at the
        // routing layer with no clear error in the daemon log. See
        // ISSUE-2026-0005. Outbound-only mode is exempt because it
        // overrides bind_addr to 0.0.0.0:0 (kernel-picked source).
        for (name, cfg) in self.transports.udp.iter() {
            if cfg.outbound_only() {
                continue;
            }
            if is_loopback_addr_str(cfg.bind_addr()) {
                let any_external_peer = self.peers.iter().any(|peer| {
                    peer.addresses
                        .iter()
                        .any(|a| a.transport == "udp" && !is_loopback_addr_str(&a.addr))
                });
                if any_external_peer {
                    let label = name.unwrap_or("(unnamed)");
                    return Err(ConfigError::Validation(format!(
                        "transports.udp[{label}].bind_addr is loopback ({}) but at least one peer has a non-loopback UDP address; \
                         fips cannot reach external peers from a loopback-bound socket. \
                         Use bind_addr: \"0.0.0.0:2121\" (with kernel-firewall hardening if exposure is a concern), or set outbound_only: true.",
                        cfg.bind_addr()
                    )));
                }
            }
        }

        let mut webrtc_candidate_sockets = 0usize;
        for (name, cfg) in self.transports.webrtc.iter() {
            let stun_servers = cfg.stun_servers(&nostr.stun_servers);
            let reservation =
                validate_webrtc_candidate_socket_budget(cfg.max_connections(), &stun_servers)
                    .map_err(|reason| {
                        let label = name.unwrap_or("(unnamed)");
                        ConfigError::Validation(format!(
                            "transports.webrtc[{label}] candidate socket budget: {reason}"
                        ))
                    })?;
            webrtc_candidate_sockets = webrtc_candidate_sockets
                .checked_add(reservation)
                .ok_or_else(|| {
                    ConfigError::Validation(
                        "transports.webrtc configured candidate socket budget overflowed".into(),
                    )
                })?;
            if webrtc_candidate_sockets > MAX_WEBRTC_CONFIG_CANDIDATE_SOCKETS {
                return Err(ConfigError::Validation(format!(
                    "transports.webrtc configured candidate socket budget reserves {webrtc_candidate_sockets}, exceeding {MAX_WEBRTC_CONFIG_CANDIDATE_SOCKETS}"
                )));
            }
        }

        for (name, cfg) in self.transports.websocket.iter() {
            cfg.validate().map_err(|reason| {
                let label = name.unwrap_or("(unnamed)");
                ConfigError::Validation(format!(
                    "transports.websocket[{label}] configuration: {reason}"
                ))
            })?;
        }

        let rate_limit = &self.node.rate_limit;
        if rate_limit.established_handshake_burst == Some(0) {
            return Err(ConfigError::Validation(
                "`node.rate_limit.established_handshake_burst` must be positive; zero would refuse every rekey and restart msg1 from an established peer"
                    .to_string(),
            ));
        }
        if let Some(rate) = rate_limit.established_handshake_rate
            && !(rate.is_finite() && rate > 0.0)
        {
            return Err(ConfigError::Validation(format!(
                "`node.rate_limit.established_handshake_rate` is {rate}, but must be a finite value greater than zero"
            )));
        }
        if rate_limit.session_setup_burst == 0 {
            return Err(ConfigError::Validation(
                "`node.rate_limit.session_setup_burst` must be positive; zero would refuse every inbound end-to-end session setup"
                    .to_string(),
            ));
        }
        if !(rate_limit.session_setup_rate.is_finite() && rate_limit.session_setup_rate > 0.0) {
            return Err(ConfigError::Validation(format!(
                "`node.rate_limit.session_setup_rate` is {}, but must be a finite value greater than zero",
                rate_limit.session_setup_rate
            )));
        }

        // An offer evicted from the replay cache must already be too old to
        // pass the freshness check, or it can be accepted a second time. The
        // skew allowance applies at each end of the accepted window.
        let skew_secs = FRESHNESS_SKEW_TOLERANCE_MS / 1000;
        let freshness_window_secs = nostr.signal_ttl_secs.saturating_add(2 * skew_secs);
        if freshness_window_secs >= nostr.replay_window_secs {
            return Err(ConfigError::Validation(format!(
                "`node.discovery.nostr.signal_ttl_secs` is {}, which with {skew_secs}s of clock-skew grace on each side makes a traversal signal acceptable over a {freshness_window_secs}s window, \
                 but `node.discovery.nostr.replay_window_secs` is {}. The freshness window must be strictly narrower than the replay window.",
                nostr.signal_ttl_secs, nostr.replay_window_secs
            )));
        }

        if nostr.max_concurrent_offers_per_npub == 0 {
            return Err(ConfigError::Validation(
                "`node.discovery.nostr.max_concurrent_offers_per_npub` must be positive; zero would refuse every inbound traversal offer"
                    .to_string(),
            ));
        }
        if nostr.max_concurrent_offers_per_npub > tokio::sync::Semaphore::MAX_PERMITS {
            return Err(ConfigError::Validation(format!(
                "`node.discovery.nostr.max_concurrent_offers_per_npub` is {}, which exceeds the semaphore maximum of {}",
                nostr.max_concurrent_offers_per_npub,
                tokio::sync::Semaphore::MAX_PERMITS
            )));
        }

        Ok(())
    }

    /// Serialize this configuration to YAML.
    pub fn to_yaml(&self) -> Result<String, serde_yaml::Error> {
        serde_yaml::to_string(self)
    }
}

struct ZeroizingYamlValue(serde_yaml::Value);

impl Drop for ZeroizingYamlValue {
    fn drop(&mut self) {
        zeroize_yaml_value(&mut self.0);
    }
}

fn zeroize_yaml_value(value: &mut serde_yaml::Value) {
    match value {
        serde_yaml::Value::String(string) => string.zeroize(),
        serde_yaml::Value::Sequence(sequence) => {
            for value in sequence {
                zeroize_yaml_value(value);
            }
        }
        serde_yaml::Value::Mapping(mapping) => {
            for value in mapping.values_mut() {
                zeroize_yaml_value(value);
            }
        }
        serde_yaml::Value::Tagged(tagged) => zeroize_yaml_value(&mut tagged.value),
        serde_yaml::Value::Null | serde_yaml::Value::Bool(_) | serde_yaml::Value::Number(_) => {}
    }
}

fn merge_yaml_value(base: &mut serde_yaml::Value, overlay: serde_yaml::Value) {
    match (base, overlay) {
        (serde_yaml::Value::Mapping(base_map), serde_yaml::Value::Mapping(overlay_map)) => {
            for (key, value) in overlay_map {
                match base_map.get_mut(&key) {
                    Some(existing) => merge_yaml_value(existing, value),
                    None => {
                        base_map.insert(key, value);
                    }
                }
            }
        }
        (base_slot, overlay) => {
            zeroize_yaml_value(base_slot);
            *base_slot = overlay;
        }
    }
}

#[cfg(test)]
mod tests;

#[cfg(test)]
#[path = "tests/socket_defaults.rs"]
mod socket_default_tests;

#[cfg(test)]
mod webrtc_budget_tests;
