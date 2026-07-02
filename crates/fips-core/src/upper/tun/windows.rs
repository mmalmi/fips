use super::*;
use crate::TunConfig;
use std::sync::Arc;

/// The Windows adapter name visible in network settings and used in netsh commands.
pub(crate) const ADAPTER_NAME: &str = "FIPS";

/// Wintun ring buffer capacity in bytes. Must be a power of 2 between
/// 0x20000 (128 KiB) and 0x4000000 (64 MiB). 2 MiB balances memory
/// usage against burst tolerance.
const WINTUN_RING_CAPACITY: u32 = 0x200000; // 2 MiB

/// FIPS TUN device wrapper (Windows/wintun).
///
/// Uses the wintun driver for userspace packet I/O on Windows. The wintun
/// DLL must be present in the executable's directory or system PATH.
/// Adapter creation requires Administrator privileges.
///
/// Unlike the Linux TUN which uses a file descriptor, wintun uses a
/// session-based API with ring buffers for packet exchange.
pub struct TunDevice {
    session: Arc<wintun::Session>,
    _adapter: Arc<wintun::Adapter>,
    name: String,
    mtu: u16,
    address: FipsAddress,
}

impl TunDevice {
    /// Create a wintun TUN adapter and configure it with an IPv6 address.
    ///
    /// Loads the wintun DLL, creates (or reopens) a named adapter, starts
    /// a session with a 2 MiB ring buffer, and configures the interface
    /// via netsh. Requires Administrator privileges.
    pub async fn create(config: &TunConfig, address: FipsAddress) -> Result<Self, TunError> {
        let name = config.name();
        let mtu = config.mtu();

        // Load the wintun DLL
        let wintun = unsafe { wintun::load() }.map_err(|e| {
            TunError::Create(
                format!(
                    "Failed to load wintun.dll: {}. Download from https://www.wintun.net/",
                    e
                )
                .into(),
            )
        })?;

        // Create or reopen the adapter.
        // First arg: adapter name visible in Windows network settings.
        // Second arg: tunnel type (internal identifier for wintun).
        let adapter = match wintun::Adapter::create(&wintun, ADAPTER_NAME, name, None) {
            Ok(a) => a,
            Err(e) => {
                return Err(TunError::Create(
                    format!(
                        "Failed to create wintun adapter '{}': {}. Run as Administrator.",
                        name, e
                    )
                    .into(),
                ));
            }
        };

        // Start a session with the configured ring buffer capacity
        let session = adapter.start_session(WINTUN_RING_CAPACITY).map_err(|e| {
            TunError::Create(format!("Failed to start wintun session: {}", e).into())
        })?;

        let session = Arc::new(session);

        // Configure the IPv6 address and route via netsh.
        // Use the adapter name (ADAPTER_NAME) not the tunnel type name.
        let ipv6_addr = address.to_ipv6();
        configure_windows_interface(ADAPTER_NAME, ipv6_addr, mtu).await?;

        Ok(Self {
            session,
            _adapter: adapter,
            name: name.to_string(),
            mtu,
            address,
        })
    }

    /// Get the device name.
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

    /// Read a packet from the TUN device.
    ///
    /// Blocks until a packet is available from the wintun session.
    /// Returns the number of bytes copied into `buf`.
    pub fn read_packet(&mut self, buf: &mut [u8]) -> Result<usize, TunError> {
        match self.session.receive_blocking() {
            Ok(packet) => {
                let bytes = packet.bytes();
                let len = bytes.len().min(buf.len());
                buf[..len].copy_from_slice(&bytes[..len]);
                Ok(len)
            }
            Err(e) => Err(TunError::Configure(format!("read failed: {}", e))),
        }
    }

    /// Shutdown the TUN device by removing the fd00::/8 route.
    ///
    /// The wintun adapter and session are cleaned up when dropped.
    pub async fn shutdown(&self) -> Result<(), TunError> {
        debug!(name = %self.name, "Shutting down TUN device");
        let _ = tokio::process::Command::new("netsh")
            .args([
                "interface",
                "ipv6",
                "delete",
                "route",
                "fd00::/8",
                &format!("interface={}", ADAPTER_NAME),
            ])
            .output()
            .await;
        Ok(())
    }

    /// Create a TunWriter for this device.
    ///
    /// Clones the wintun session `Arc` so the writer can allocate and send
    /// packets independently. Returns the writer and a channel sender for
    /// submitting packets to be written.
    ///
    /// `max_mss` is the global TCP MSS ceiling. `path_mtu_lookup` is a
    /// read-only handle to per-destination path MTU learned via
    /// discovery.
    pub fn create_writer(
        &self,
        max_mss: u16,
        path_mtu_lookup: PathMtuLookup,
    ) -> Result<(TunWriter, TunTx), TunError> {
        let (tx, rx) = write_channel();
        Ok((
            TunWriter {
                session: self.session.clone(),
                rx,
                name: self.name.clone(),
                max_mss,
                path_mtu_lookup,
            },
            tx,
        ))
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

/// Writer thread for TUN device (Windows).
///
/// Services a queue of outbound packets and writes them to the wintun
/// session. Uses `allocate_send_packet()` / `send_packet()` instead of
/// file I/O.
///
/// Also performs TCP MSS clamping on inbound SYN-ACK packets.
pub struct TunWriter {
    session: Arc<wintun::Session>,
    rx: TunRx,
    name: String,
    max_mss: u16,
    path_mtu_lookup: PathMtuLookup,
}

impl TunWriter {
    /// Run the writer loop.
    ///
    /// Blocks forever, reading packets from the channel and writing them
    /// to the wintun session. Returns when the channel is closed.
    pub fn run(self) {
        use super::per_flow_max_mss;
        use crate::upper::tcp_mss::clamp_tcp_mss;

        debug!(name = %self.name, max_mss = self.max_mss, "TUN writer starting");

        for mut packet in self.rx {
            // Per-destination clamp (peer source IPv6 = bytes 8..24)
            let effective_max_mss = if packet.len() >= 24 {
                per_flow_max_mss(
                    &self.path_mtu_lookup,
                    &packet.as_slice()[8..24],
                    self.max_mss,
                )
            } else {
                self.max_mss
            };
            // Clamp TCP MSS on inbound SYN-ACK packets
            if clamp_tcp_mss(packet.as_mut_slice(), effective_max_mss) {
                trace!(
                    name = %self.name,
                    max_mss = effective_max_mss,
                    "Clamped TCP MSS in inbound SYN-ACK packet"
                );
            }

            let pkt_len = match u16::try_from(packet.len()) {
                Ok(len) => len,
                Err(_) => {
                    warn!(name = %self.name, len = packet.len(), "Dropping oversized packet for TUN");
                    continue;
                }
            };
            match self.session.allocate_send_packet(pkt_len) {
                Ok(mut send_packet) => {
                    send_packet.bytes_mut().copy_from_slice(packet.as_slice());
                    self.session.send_packet(send_packet);
                    trace!(name = %self.name, len = packet.len(), "TUN packet written");
                }
                Err(e) => {
                    error!(name = %self.name, error = %e, "TUN write error (allocate)");
                }
            }
        }
    }
}

/// TUN packet reader loop (Windows).
///
/// Reads IPv6 packets from the wintun session. Packets destined for FIPS
/// addresses (fd::/8) are forwarded to the Node via the outbound channel
/// for session encapsulation and routing. Non-FIPS packets receive ICMPv6
/// Destination Unreachable responses.
///
/// Also performs TCP MSS clamping on SYN packets to prevent oversized segments.
///
/// This is designed to run in a dedicated thread since wintun reads are blocking.
/// The loop exits when the session is closed or an unrecoverable error occurs.
pub fn run_tun_reader(
    mut device: TunDevice,
    mtu: u16,
    our_addr: FipsAddress,
    tun_tx: TunTx,
    outbound_tx: TunOutboundTx,
    transport_mtu: u16,
    path_mtu_lookup: PathMtuLookup,
) {
    let (name, mut buf, max_mss) = super::tun_reader_setup(device.name(), mtu, transport_mtu);

    loop {
        match device.read_packet(&mut buf) {
            Ok(n) if n > 0 => {
                if !super::handle_tun_packet(
                    &mut buf[..n],
                    max_mss,
                    &name,
                    our_addr,
                    &tun_tx,
                    &outbound_tx,
                    &path_mtu_lookup,
                ) {
                    break;
                }
            }
            Ok(_) => {}
            Err(e) => {
                let err_str = format!("{}", e);
                if !err_str.contains("Bad address") {
                    error!(name = %name, error = %e, "TUN read error");
                }
                break;
            }
        }
    }
}

/// Shutdown and delete a TUN interface by name (Windows).
///
/// Removes the fd00::/8 route via netsh. The wintun adapter itself
/// is cleaned up when the `Adapter` handle is dropped.
pub async fn shutdown_tun_interface(name: &str) -> Result<(), TunError> {
    debug!("Shutting down TUN interface {}", name);
    let _ = tokio::process::Command::new("netsh")
        .args([
            "interface",
            "ipv6",
            "delete",
            "route",
            "fd00::/8",
            &format!("interface={}", ADAPTER_NAME),
        ])
        .output()
        .await;
    let _ = name; // name is the tunnel type, not the adapter name
    debug!("TUN interface {} stopped", name);
    Ok(())
}

/// Configure the Windows network interface with IPv6 address, MTU, and route.
///
/// Uses `netsh` commands to configure the wintun adapter. A brief delay
/// is inserted before configuration to allow Windows to fully register
/// the adapter in its network stack.
///
/// `adapter_name` must be the Windows adapter name (e.g. "FIPS"), not the
/// wintun tunnel type name.
async fn configure_windows_interface(
    adapter_name: &str,
    addr: Ipv6Addr,
    mtu: u16,
) -> Result<(), TunError> {
    // Brief delay to let Windows fully register the adapter
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;

    // Set IPv6 address
    let output = tokio::process::Command::new("netsh")
        .args([
            "interface",
            "ipv6",
            "add",
            "address",
            adapter_name,
            &format!("{}/128", addr),
        ])
        .output()
        .await
        .map_err(|e| TunError::Configure(format!("netsh add address failed: {}", e)))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        if !stderr.contains("already") && !stdout.contains("already") {
            warn!(
                "netsh add address failed: stdout={} stderr={}",
                stdout.trim(),
                stderr.trim()
            );
        }
    }

    // Set MTU
    let output = tokio::process::Command::new("netsh")
        .args([
            "interface",
            "ipv6",
            "set",
            "subinterface",
            adapter_name,
            &format!("mtu={}", mtu),
        ])
        .output()
        .await
        .map_err(|e| TunError::Configure(format!("netsh set mtu failed: {}", e)))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        warn!(
            "netsh set mtu failed: stdout={} stderr={}",
            stdout.trim(),
            stderr.trim()
        );
    }

    // Add route for fd00::/8 (FIPS address space) via this adapter
    let output = tokio::process::Command::new("netsh")
        .args([
            "interface",
            "ipv6",
            "add",
            "route",
            "fd00::/8",
            adapter_name,
        ])
        .output()
        .await
        .map_err(|e| TunError::Configure(format!("netsh add route failed: {}", e)))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        if !stderr.contains("already") && !stdout.contains("already") {
            warn!(
                "netsh add route failed: stdout={} stderr={}",
                stdout.trim(),
                stderr.trim()
            );
        }
    }

    Ok(())
}
