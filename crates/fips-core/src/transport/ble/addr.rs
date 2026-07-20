//! BLE transport address parsing and formatting.
//!
//! Address format: `"adapter/peer-token"`.
//!
//! BlueZ uses a MAC address as the peer token. Mobile platform adapters use
//! opaque identifiers supplied by the operating system.

use crate::transport::{TransportAddr, TransportError};

/// A parsed BLE device address.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct BleAddr {
    /// HCI adapter name (e.g., "hci0").
    pub adapter: String,
    /// 6-byte Bluetooth device address.
    pub device: [u8; 6],
    /// Opaque platform peer token when no stable Bluetooth address is exposed.
    pub opaque_token: Option<String>,
}

impl BleAddr {
    /// Parse a BLE address from the `"adapter/AA:BB:CC:DD:EE:FF"` format.
    pub fn parse(s: &str) -> Result<Self, TransportError> {
        let (adapter, mac_str) = s.split_once('/').ok_or_else(|| {
            TransportError::InvalidAddress(format!("missing '/' in BLE address: {s}"))
        })?;

        if adapter.is_empty() {
            return Err(TransportError::InvalidAddress("empty adapter name".into()));
        }

        let (device, opaque_token) = if let Some(device) = parse_mac(mac_str) {
            (device, None)
        } else {
            if adapter.starts_with("hci") {
                return Err(TransportError::InvalidAddress(format!(
                    "invalid MAC address: {mac_str}"
                )));
            }
            validate_opaque_token(mac_str)?;
            ([0; 6], Some(mac_str.to_string()))
        };

        Ok(Self {
            adapter: adapter.to_string(),
            device,
            opaque_token,
        })
    }

    /// Construct an address backed by a Bluetooth MAC address.
    pub fn from_mac(adapter: impl Into<String>, device: [u8; 6]) -> Self {
        Self {
            adapter: adapter.into(),
            device,
            opaque_token: None,
        }
    }

    /// Construct an address backed by an opaque platform peer token.
    pub fn from_opaque(
        adapter: impl Into<String>,
        token: impl Into<String>,
    ) -> Result<Self, TransportError> {
        let adapter = adapter.into();
        let token = token.into();
        if adapter.is_empty() {
            return Err(TransportError::InvalidAddress("empty adapter name".into()));
        }
        validate_opaque_token(&token)?;
        Ok(Self {
            adapter,
            device: [0; 6],
            opaque_token: Some(token),
        })
    }

    /// Format as `"adapter/AA:BB:CC:DD:EE:FF"`.
    pub fn to_string_repr(&self) -> String {
        if let Some(token) = &self.opaque_token {
            return format!("{}/{}", self.adapter, token);
        }
        format!(
            "{}/{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
            self.adapter,
            self.device[0],
            self.device[1],
            self.device[2],
            self.device[3],
            self.device[4],
            self.device[5],
        )
    }

    /// Convert to a `TransportAddr` (string representation).
    pub fn to_transport_addr(&self) -> TransportAddr {
        TransportAddr::from_string(&self.to_string_repr())
    }

    /// Platform token without the local adapter prefix.
    pub fn peer_token(&self) -> String {
        self.opaque_token.clone().unwrap_or_else(|| {
            format!(
                "{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
                self.device[0],
                self.device[1],
                self.device[2],
                self.device[3],
                self.device[4],
                self.device[5]
            )
        })
    }
}

// ============================================================================
// bluer type conversions (glibc-linux only; see build.rs bluer_available)
// ============================================================================

#[cfg(bluer_available)]
impl BleAddr {
    /// Construct from a bluer `Address` and adapter name.
    pub fn from_bluer(addr: bluer::Address, adapter: &str) -> Self {
        Self {
            adapter: adapter.to_string(),
            device: addr.0,
            opaque_token: None,
        }
    }

    /// Convert to a bluer `Address`.
    pub fn to_bluer_address(&self) -> Result<bluer::Address, TransportError> {
        if self.opaque_token.is_some() {
            return Err(TransportError::InvalidAddress(
                "opaque mobile BLE peer token cannot be used by BlueZ".into(),
            ));
        }
        Ok(bluer::Address(self.device))
    }

    /// Convert to a bluer L2CAP `SocketAddr` with the given PSM.
    pub fn to_socket_addr(&self, psm: u16) -> Result<bluer::l2cap::SocketAddr, TransportError> {
        Ok(bluer::l2cap::SocketAddr::new(
            self.to_bluer_address()?,
            bluer::AddressType::LePublic,
            psm,
        ))
    }
}

impl std::fmt::Display for BleAddr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_string_repr())
    }
}

/// Parse a colon-delimited MAC address string into 6 bytes.
fn parse_mac(s: &str) -> Option<[u8; 6]> {
    let parts: Vec<&str> = s.split(':').collect();
    if parts.len() != 6 {
        return None;
    }
    let mut mac = [0u8; 6];
    for (i, part) in parts.iter().enumerate() {
        mac[i] = u8::from_str_radix(part, 16).ok()?;
    }
    Some(mac)
}

fn validate_opaque_token(token: &str) -> Result<(), TransportError> {
    if token.is_empty() || token.len() > 128 {
        return Err(TransportError::InvalidAddress(
            "BLE peer token must contain 1 to 128 bytes".into(),
        ));
    }
    if !token
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'))
    {
        return Err(TransportError::InvalidAddress(
            "BLE peer token contains unsupported characters".into(),
        ));
    }
    Ok(())
}

/// Extract the adapter name from a transport address string.
///
/// Returns `None` if the address is not valid UTF-8 or doesn't contain '/'.
pub fn adapter_from_addr(addr: &TransportAddr) -> Option<&str> {
    addr.as_str()?.split_once('/').map(|(adapter, _)| adapter)
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_valid() {
        let addr = BleAddr::parse("hci0/AA:BB:CC:DD:EE:FF").unwrap();
        assert_eq!(addr.adapter, "hci0");
        assert_eq!(addr.device, [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
    }

    #[test]
    fn test_parse_lowercase() {
        let addr = BleAddr::parse("hci1/aa:bb:cc:dd:ee:ff").unwrap();
        assert_eq!(addr.adapter, "hci1");
        assert_eq!(addr.device, [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
    }

    #[test]
    fn test_roundtrip() {
        let original = "hci0/AA:BB:CC:DD:EE:FF";
        let addr = BleAddr::parse(original).unwrap();
        assert_eq!(addr.to_string_repr(), original);
    }

    #[test]
    fn test_roundtrip_opaque_platform_token() {
        let original = "ios/4D36E96E-E325-11CE-BFC1-08002BE10318";
        let addr = BleAddr::parse(original).unwrap();
        assert_eq!(addr.to_string_repr(), original);
    }

    #[test]
    fn test_display() {
        let addr = BleAddr::parse("hci0/01:02:03:04:05:06").unwrap();
        assert_eq!(format!("{addr}"), "hci0/01:02:03:04:05:06");
    }

    #[test]
    fn test_to_transport_addr() {
        let addr = BleAddr::parse("hci0/AA:BB:CC:DD:EE:FF").unwrap();
        let ta = addr.to_transport_addr();
        assert_eq!(ta.as_str(), Some("hci0/AA:BB:CC:DD:EE:FF"));
    }

    #[test]
    fn test_parse_missing_slash() {
        assert!(BleAddr::parse("hci0-AA:BB:CC:DD:EE:FF").is_err());
    }

    #[test]
    fn test_parse_empty_adapter() {
        assert!(BleAddr::parse("/AA:BB:CC:DD:EE:FF").is_err());
    }

    #[test]
    fn test_parse_invalid_mac_short() {
        assert!(BleAddr::parse("hci0/AA:BB:CC").is_err());
    }

    #[test]
    fn test_parse_invalid_mac_hex() {
        assert!(BleAddr::parse("hci0/GG:HH:II:JJ:KK:LL").is_err());
    }

    #[test]
    fn test_adapter_from_addr() {
        let ta = TransportAddr::from_string("hci0/AA:BB:CC:DD:EE:FF");
        assert_eq!(adapter_from_addr(&ta), Some("hci0"));
    }

    #[test]
    fn test_adapter_from_addr_no_slash() {
        let ta = TransportAddr::from_string("invalid");
        assert_eq!(adapter_from_addr(&ta), None);
    }
}
