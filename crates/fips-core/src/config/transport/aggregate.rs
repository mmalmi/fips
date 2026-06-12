use super::*;

// ============================================================================
// TransportsConfig
// ============================================================================

/// Transports configuration section.
///
/// Each transport type can have either a single instance (config directly
/// under the type name) or multiple named instances.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
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
    /// Check if any transports are configured.
    pub fn is_empty(&self) -> bool {
        self.udp.is_empty()
            && {
                #[cfg(feature = "sim-transport")]
                {
                    self.sim.is_empty()
                }
                #[cfg(not(feature = "sim-transport"))]
                {
                    true
                }
            }
            && self.ethernet.is_empty()
            && self.tcp.is_empty()
            && self.tor.is_empty()
            && self.webrtc.is_empty()
            && self.ble.is_empty()
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
