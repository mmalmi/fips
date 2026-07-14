use super::*;

/// Placeholder TUN device for platforms where apps must own packet I/O.
pub struct TunDevice {
    name: String,
    mtu: u16,
    address: FipsAddress,
}

impl TunDevice {
    /// System TUN creation is not available on this platform.
    pub async fn create(config: &TunConfig, address: FipsAddress) -> Result<Self, TunError> {
        let _ = (config, address);
        Err(TunError::UnsupportedPlatform)
    }

    /// Get the configured device name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Get the configured MTU.
    pub fn mtu(&self) -> u16 {
        self.mtu
    }

    /// Get the FIPS address assigned to this device.
    pub fn address(&self) -> &FipsAddress {
        &self.address
    }

    /// Creating a system TUN writer is not available on this platform.
    pub fn create_writer(
        &self,
        max_mss: u16,
        path_mtu_lookup: PathMtuLookup,
    ) -> Result<(TunWriter, TunTx), TunError> {
        let _ = (max_mss, path_mtu_lookup);
        Err(TunError::UnsupportedPlatform)
    }
}

impl std::fmt::Debug for TunDevice {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TunDevice")
            .field("name", &self.name)
            .field("mtu", &self.mtu)
            .field("address", &self.address)
            .finish()
    }
}

/// Placeholder writer for type-checking unreachable system-TUN paths.
pub struct TunWriter;

impl TunWriter {
    /// No-op: system TUN is unavailable on this platform.
    pub fn run(self) {}
}

/// No-op reader placeholder for platforms where apps own packet I/O.
pub(crate) fn run_tun_reader(runtime: super::TunReaderRuntime) {
    let super::TunReaderRuntime {
        device,
        mtu,
        our_addr,
        tun_tx,
        outbound_tx,
        transport_mtu,
        path_mtu_lookup,
    } = runtime;
    let _ = (
        device,
        mtu,
        our_addr,
        tun_tx,
        outbound_tx,
        transport_mtu,
        path_mtu_lookup,
    );
}

/// No-op shutdown for platforms without a FIPS-created system TUN.
pub async fn shutdown_tun_interface(name: &str) -> Result<(), TunError> {
    let _ = name;
    Ok(())
}
