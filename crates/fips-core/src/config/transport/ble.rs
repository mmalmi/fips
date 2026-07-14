use super::*;

// ============================================================================
// BLE Transport Configuration
// ============================================================================

/// Default BLE L2CAP PSM (dynamic range).
const DEFAULT_BLE_PSM: u16 = 0x0085;

/// Default BLE MTU for L2CAP CoC connections.
const DEFAULT_BLE_MTU: u16 = 2048;

/// Default maximum concurrent BLE connections.
const DEFAULT_BLE_MAX_CONNECTIONS: usize = 7;

/// Default BLE connect timeout in milliseconds.
const DEFAULT_BLE_CONNECT_TIMEOUT_MS: u64 = 10_000;

/// Default BLE probe cooldown in seconds. After probing an address
/// (success or failure), wait this long before probing it again.
const DEFAULT_BLE_PROBE_COOLDOWN_SECS: u64 = 30;

/// BLE transport instance configuration.
///
/// BleConfig is always compiled. The runtime uses BlueZ on Linux or a
/// platform command adapter when `host-ble-transport` is enabled.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BleConfig {
    /// HCI adapter name (e.g., "hci0"). Required.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub adapter: Option<String>,

    /// L2CAP PSM for FIPS connections. Default: 0x0085 (133).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub psm: Option<u16>,

    /// Default MTU for BLE connections. Default: 2048.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mtu: Option<u16>,

    /// Maximum concurrent BLE connections. Default: 7.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_connections: Option<usize>,

    /// Outbound connect timeout in milliseconds. Default: 10000.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub connect_timeout_ms: Option<u64>,

    /// Broadcast BLE advertisements. Default: true.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub advertise: Option<bool>,

    /// Listen for BLE advertisements. Default: true.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scan: Option<bool>,

    /// Auto-connect to discovered BLE peers. Default: false.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auto_connect: Option<bool>,

    /// Accept incoming BLE connections. Default: true.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub accept_connections: Option<bool>,

    /// Probe cooldown in seconds. After probing a BLE address, wait
    /// this long before probing the same address again. Default: 30.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub probe_cooldown_secs: Option<u64>,
}

impl BleConfig {
    /// Get the adapter name. Default: "hci0".
    pub fn adapter(&self) -> &str {
        self.adapter.as_deref().unwrap_or("hci0")
    }

    /// Get the L2CAP PSM. Default: 0x0085.
    pub fn psm(&self) -> u16 {
        self.psm.unwrap_or(DEFAULT_BLE_PSM)
    }

    /// Get the default MTU. Default: 2048.
    pub fn mtu(&self) -> u16 {
        self.mtu.unwrap_or(DEFAULT_BLE_MTU)
    }

    /// Get the maximum concurrent connections. Default: 7.
    pub fn max_connections(&self) -> usize {
        self.max_connections.unwrap_or(DEFAULT_BLE_MAX_CONNECTIONS)
    }

    /// Get the connect timeout in milliseconds. Default: 10000.
    pub fn connect_timeout_ms(&self) -> u64 {
        self.connect_timeout_ms
            .unwrap_or(DEFAULT_BLE_CONNECT_TIMEOUT_MS)
    }

    /// Whether to broadcast advertisements. Default: true.
    pub fn advertise(&self) -> bool {
        self.advertise.unwrap_or(true)
    }

    /// Whether to scan for advertisements. Default: true.
    pub fn scan(&self) -> bool {
        self.scan.unwrap_or(true)
    }

    /// Whether to auto-connect to discovered peers. Default: false.
    pub fn auto_connect(&self) -> bool {
        self.auto_connect.unwrap_or(false)
    }

    /// Whether to accept incoming connections. Default: true.
    pub fn accept_connections(&self) -> bool {
        self.accept_connections.unwrap_or(true)
    }

    /// Get the probe cooldown in seconds. Default: 30.
    pub fn probe_cooldown_secs(&self) -> u64 {
        self.probe_cooldown_secs
            .unwrap_or(DEFAULT_BLE_PROBE_COOLDOWN_SECS)
    }
}
