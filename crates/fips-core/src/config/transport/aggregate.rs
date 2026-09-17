use super::*;

// ============================================================================
// TransportsConfig
// ============================================================================

/// Transports configuration section.
///
/// Each transport type can have either a single instance (config directly
/// under the type name) or multiple named instances.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TransportsConfig {
    /// UDP transport instances.
    #[serde(default, skip_serializing_if = "is_transport_empty")]
    pub udp: TransportInstances<UdpConfig>,

    /// In-memory simulated transport instances.
    #[cfg(feature = "sim-transport")]
    #[serde(default, skip_serializing_if = "is_transport_empty")]
    pub sim: TransportInstances<SimTransportConfig>,

    /// Ethernet transport instances.
    #[serde(default, skip_serializing_if = "is_transport_empty")]
    pub ethernet: TransportInstances<EthernetConfig>,

    /// TCP transport instances.
    #[serde(default, skip_serializing_if = "is_transport_empty")]
    pub tcp: TransportInstances<TcpConfig>,

    /// WebSocket physical transport instances.
    #[serde(default, skip_serializing_if = "is_transport_empty")]
    pub websocket: TransportInstances<WebSocketConfig>,

    /// Tor transport instances.
    #[serde(default, skip_serializing_if = "is_transport_empty")]
    pub tor: TransportInstances<TorConfig>,

    /// WebRTC transport instances.
    #[serde(default, skip_serializing_if = "is_transport_empty")]
    pub webrtc: TransportInstances<WebRtcConfig>,

    /// BLE transport instances.
    #[serde(default, skip_serializing_if = "is_transport_empty")]
    pub ble: TransportInstances<BleConfig>,
}

/// Helper for skip_serializing_if on TransportInstances.
fn is_transport_empty<T>(instances: &TransportInstances<T>) -> bool {
    instances.is_empty()
}

impl TransportsConfig {
    /// Configured transport types and their instance counts, omitting empty sections.
    ///
    /// Names identify adapter types, not individual named instances. A configured
    /// adapter is not necessarily available on the current platform or build.
    pub fn instance_counts(&self) -> impl Iterator<Item = (&'static str, usize)> {
        [
            ("udp", self.udp.len()),
            #[cfg(feature = "sim-transport")]
            ("sim", self.sim.len()),
            ("ethernet", self.ethernet.len()),
            ("tcp", self.tcp.len()),
            ("websocket", self.websocket.len()),
            ("tor", self.tor.len()),
            ("webrtc", self.webrtc.len()),
            ("ble", self.ble.len()),
        ]
        .into_iter()
        .filter(|(_, count)| *count > 0)
    }

    /// Check if any transports are configured.
    pub fn is_empty(&self) -> bool {
        self.instance_counts().next().is_none()
    }

    /// Merge another TransportsConfig into this one.
    ///
    /// Non-empty transport sections from `other` replace those in `self`.
    pub fn merge(&mut self, other: TransportsConfig) {
        if !other.udp.is_empty() {
            self.udp = other.udp;
        }
        #[cfg(feature = "sim-transport")]
        if !other.sim.is_empty() {
            self.sim = other.sim;
        }
        if !other.ethernet.is_empty() {
            self.ethernet = other.ethernet;
        }
        if !other.tcp.is_empty() {
            self.tcp = other.tcp;
        }
        if !other.websocket.is_empty() {
            self.websocket = other.websocket;
        }
        if !other.tor.is_empty() {
            self.tor = other.tor;
        }
        if !other.webrtc.is_empty() {
            self.webrtc = other.webrtc;
        }
        if !other.ble.is_empty() {
            self.ble = other.ble;
        }
    }
}
