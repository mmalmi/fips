use super::super::*;

// ========================================================================
// link_mtu tests
// ========================================================================

/// Minimal mock transport for testing the default link_mtu() behavior.
struct MockTransport {
    id: TransportId,
    mtu_value: u16,
}

impl MockTransport {
    fn new(mtu: u16) -> Self {
        Self {
            id: TransportId::new(99),
            mtu_value: mtu,
        }
    }
}

impl Transport for MockTransport {
    fn transport_id(&self) -> TransportId {
        self.id
    }
    fn transport_type(&self) -> &TransportType {
        &TransportType::UDP
    }
    fn state(&self) -> TransportState {
        TransportState::Up
    }
    fn mtu(&self) -> u16 {
        self.mtu_value
    }
    fn start(&mut self) -> Result<(), TransportError> {
        Ok(())
    }
    fn stop(&mut self) -> Result<(), TransportError> {
        Ok(())
    }
    fn send(&self, _addr: &TransportAddr, _data: &[u8]) -> Result<(), TransportError> {
        Ok(())
    }
    fn discover(&self) -> Result<Vec<DiscoveredPeer>, TransportError> {
        Ok(vec![])
    }
}

/// Mock transport that overrides link_mtu() to return per-link values.
struct PerLinkMtuTransport {
    id: TransportId,
    default_mtu: u16,
    /// Address-specific MTU overrides.
    overrides: Vec<(TransportAddr, u16)>,
}

impl PerLinkMtuTransport {
    fn new(default_mtu: u16, overrides: Vec<(TransportAddr, u16)>) -> Self {
        Self {
            id: TransportId::new(100),
            default_mtu,
            overrides,
        }
    }
}

impl Transport for PerLinkMtuTransport {
    fn transport_id(&self) -> TransportId {
        self.id
    }
    fn transport_type(&self) -> &TransportType {
        &TransportType::UDP
    }
    fn state(&self) -> TransportState {
        TransportState::Up
    }
    fn mtu(&self) -> u16 {
        self.default_mtu
    }
    fn link_mtu(&self, addr: &TransportAddr) -> u16 {
        for (a, mtu) in &self.overrides {
            if a == addr {
                return *mtu;
            }
        }
        self.mtu()
    }
    fn start(&mut self) -> Result<(), TransportError> {
        Ok(())
    }
    fn stop(&mut self) -> Result<(), TransportError> {
        Ok(())
    }
    fn send(&self, _addr: &TransportAddr, _data: &[u8]) -> Result<(), TransportError> {
        Ok(())
    }
    fn discover(&self) -> Result<Vec<DiscoveredPeer>, TransportError> {
        Ok(vec![])
    }
}

#[test]
fn test_link_mtu_default_falls_back_to_mtu() {
    let transport = MockTransport::new(1280);
    let addr = TransportAddr::from_string("192.168.1.1:2121");

    // Default link_mtu() should return the transport-wide mtu()
    assert_eq!(transport.link_mtu(&addr), 1280);
    assert_eq!(transport.link_mtu(&addr), transport.mtu());

    // Any address should return the same value
    let other_addr = TransportAddr::from_string("10.0.0.1:5000");
    assert_eq!(transport.link_mtu(&other_addr), 1280);
}

#[test]
fn test_link_mtu_per_link_override() {
    let addr_a = TransportAddr::from_string("192.168.1.1:2121");
    let addr_b = TransportAddr::from_string("10.0.0.1:5000");
    let addr_unknown = TransportAddr::from_string("172.16.0.1:6000");

    let transport =
        PerLinkMtuTransport::new(1280, vec![(addr_a.clone(), 512), (addr_b.clone(), 247)]);

    // Known addresses return their per-link MTU
    assert_eq!(transport.link_mtu(&addr_a), 512);
    assert_eq!(transport.link_mtu(&addr_b), 247);

    // Unknown address falls back to transport-wide default
    assert_eq!(transport.link_mtu(&addr_unknown), 1280);
    assert_eq!(transport.mtu(), 1280);
}

#[test]
fn test_transport_handle_link_mtu_delegation() {
    use crate::config::UdpConfig;
    use crate::transport::packet_channel;
    use crate::transport::udp::UdpTransport;

    let config = UdpConfig::default();
    let expected_mtu = config.mtu();
    let (tx, _rx) = packet_channel(1);
    let transport = UdpTransport::new(TransportId::new(1), None, config, tx);
    let handle = TransportHandle::Udp(transport);

    let addr = TransportAddr::from_string("192.168.1.1:2121");

    // TransportHandle::link_mtu() should delegate and return the same
    // as TransportHandle::mtu() for UDP (no per-link overrides)
    assert_eq!(handle.link_mtu(&addr), expected_mtu);
    assert_eq!(handle.link_mtu(&addr), handle.mtu());
}
