//! FIPS TUN Interface
//!
//! Manages the TUN device for sending and receiving IPv6 packets.
//! The TUN interface presents FIPS addresses to the local system,
//! allowing standard socket applications to communicate over the mesh.
//!
//! Platform-specific implementations:
//! - Linux: Uses the `tun` crate with `rtnetlink` for interface configuration
//! - macOS: Uses the `tun` crate with `ifconfig`/`route` for interface configuration
//! - Windows: Uses the `wintun` crate for TUN device support

use crate::FipsAddress;
#[cfg(any(
    target_os = "linux",
    target_os = "macos",
    not(any(target_os = "linux", target_os = "macos", windows))
))]
use crate::TunConfig;
use std::collections::HashMap;
#[cfg(any(target_os = "linux", target_os = "macos"))]
use std::fs::File;
#[cfg(any(target_os = "linux", target_os = "macos"))]
use std::io::Read;
#[cfg(not(target_os = "macos"))]
#[cfg(any(target_os = "linux", target_os = "macos"))]
use std::io::Write;
use std::net::Ipv6Addr;
#[cfg(any(target_os = "linux", target_os = "macos"))]
use std::os::unix::io::{AsRawFd, FromRawFd};
use std::sync::{Arc, RwLock};
use thiserror::Error;
#[cfg(any(target_os = "linux", target_os = "macos"))]
use tracing::error;
use tracing::{debug, trace};
#[cfg(windows)]
use tracing::{error, warn};
#[cfg(any(target_os = "linux", target_os = "macos"))]
use tun::Layer;

pub(crate) use super::tun_outbound::{TunOutboundAdmission, tun_outbound_channel};
pub use super::tun_outbound::{TunOutboundRx, TunOutboundTx};
pub use super::tun_write::TunTx;
#[cfg(test)]
pub(crate) use super::tun_write::write_channel_with_bulk_capacity;
pub(crate) use super::tun_write::{TunRx, TunWriteErrorKind, TunWriteLane, write_channel};

/// Read-only handle to the per-destination path MTU map. Populated by
/// the discovery handler on `LookupResponse`; read by the TUN reader
/// (outbound clamp) and writer (inbound clamp) at TCP MSS clamp time.
/// Keyed by [`FipsAddress`] (16 bytes, the IPv6 form of a fips peer
/// address).
pub type PathMtuLookup = Arc<RwLock<HashMap<FipsAddress, u16>>>;

/// Compute the effective TCP MSS ceiling for a packet given its peer
/// address bytes (a 16-byte IPv6 destination on outbound, source on
/// inbound). Returns `min(global_max_mss, learned_path_max_mss)` when
/// the per-destination path MTU is known via discovery; otherwise
/// returns `min(global_max_mss, ipv6_minimum_safe_max_mss)`, the
/// conservative IPv6-minimum-derived ceiling.
///
/// The conservative empty-lookup fallback exists because there is a
/// race window between TCP-SYN-out and discovery-completes-with-path-
/// MTU on cold flows. Without the floor, the first SYN exits at the
/// kernel-natural MSS (TUN MTU minus IPv6/TCP headers), which can
/// exceed what some downstream forwarder hop is willing to carry.
/// The drop is silent (no PTB feedback through the userspace TUN to
/// the kernel TCP stack), so TCP retransmits at the same too-large
/// MSS and the application's first connection wedges before discovery
/// completes for a corrected second SYN to fire.
///
/// RFC 8200 mandates every IPv6 path accepts at least 1280-byte
/// packets, so a SYN clamped to the IPv6-minimum-derived MSS fits
/// any compliant path. Subsequent flows pick up the actual learned
/// per-destination value, which can be larger (when path supports
/// it) or smaller (when path is observed-tighter than the IPv6 min).
///
/// Path MTU bytes-on-wire to TCP MSS: subtract 77 bytes of FIPS encap
/// overhead, then 40 bytes IPv6 + 20 bytes TCP headers.
#[cfg(any(test, target_os = "linux", target_os = "macos", windows))]
pub(crate) fn per_flow_max_mss(
    lookup: &PathMtuLookup,
    addr_bytes: &[u8],
    global_max_mss: u16,
) -> u16 {
    use super::icmp::effective_ipv6_mtu;

    // RFC 8200 IPv6-minimum MTU (1280) → effective FIPS-encapsulated
    // payload (1203) → TCP segment after IPv6+TCP headers (1143).
    // Used as the conservative ceiling for empty-lookup destinations.
    const IPV6_MIN_MTU: u16 = 1280;
    let conservative_max_mss = effective_ipv6_mtu(IPV6_MIN_MTU)
        .saturating_sub(40)
        .saturating_sub(20);
    let empty_lookup_ceiling = std::cmp::min(global_max_mss, conservative_max_mss);

    if addr_bytes.len() != 16 {
        trace!(
            len = addr_bytes.len(),
            global_max_mss,
            empty_lookup_ceiling,
            "per_flow_max_mss: addr_bytes wrong length, fall back to conservative ceiling"
        );
        return empty_lookup_ceiling;
    }
    let Ok(fips_addr) = FipsAddress::from_slice(addr_bytes) else {
        trace!(
            global_max_mss,
            empty_lookup_ceiling,
            "per_flow_max_mss: FipsAddress::from_slice rejected (non-fd::/8 prefix), fall back to conservative ceiling"
        );
        return empty_lookup_ceiling;
    };
    let Ok(map) = lookup.read() else {
        trace!(
            fips_addr = %fips_addr,
            global_max_mss,
            empty_lookup_ceiling,
            "per_flow_max_mss: lookup read lock poisoned, fall back to conservative ceiling"
        );
        return empty_lookup_ceiling;
    };
    let Some(&path_mtu) = map.get(&fips_addr) else {
        trace!(
            fips_addr = %fips_addr,
            global_max_mss,
            empty_lookup_ceiling,
            map_len = map.len(),
            "per_flow_max_mss: no path_mtu_lookup entry for destination, fall back to conservative ceiling"
        );
        return empty_lookup_ceiling;
    };
    let path_max_mss = effective_ipv6_mtu(path_mtu)
        .saturating_sub(40)
        .saturating_sub(20);
    let result = std::cmp::min(global_max_mss, path_max_mss);
    trace!(
        fips_addr = %fips_addr,
        path_mtu,
        path_max_mss,
        global_max_mss,
        result,
        "per_flow_max_mss: per-destination clamp applied"
    );
    result
}

/// Errors that can occur with TUN operations.
#[derive(Debug, Error)]
pub enum TunError {
    #[error("failed to create TUN device: {0}")]
    Create(#[source] Box<dyn std::error::Error + Send + Sync>),

    #[error("failed to configure TUN device: {0}")]
    Configure(String),

    #[cfg(target_os = "linux")]
    #[error("netlink error: {0}")]
    Netlink(#[from] rtnetlink::Error),

    #[error("interface not found: {0}")]
    InterfaceNotFound(String),

    #[error("permission denied: {0}")]
    PermissionDenied(String),

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[error("IPv6 is disabled (set net.ipv6.conf.all.disable_ipv6=0)")]
    Ipv6Disabled,

    #[error("system TUN is not supported on this platform")]
    UnsupportedPlatform,
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
impl From<tun::Error> for TunError {
    fn from(e: tun::Error) -> Self {
        TunError::Create(Box::new(e))
    }
}

/// TUN device state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TunState {
    /// TUN is disabled in configuration.
    Disabled,
    /// TUN is configured but not yet created.
    Configured,
    /// TUN device is active and ready.
    Active,
    /// TUN device failed to initialize.
    Failed,
}

impl std::fmt::Display for TunState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TunState::Disabled => write!(f, "disabled"),
            TunState::Configured => write!(f, "configured"),
            TunState::Active => write!(f, "active"),
            TunState::Failed => write!(f, "failed"),
        }
    }
}

// ============================================================================
// Unix (Linux + macOS) TUN implementation
// ============================================================================

/// FIPS TUN device wrapper.
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub struct TunDevice {
    device: tun::Device,
    name: String,
    mtu: u16,
    address: FipsAddress,
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
impl TunDevice {
    /// Create or open a TUN device.
    ///
    /// If the interface already exists, opens it and reconfigures it.
    /// Otherwise, creates a new TUN device.
    ///
    /// This requires CAP_NET_ADMIN capability (run with sudo or setcap).
    pub async fn create(config: &TunConfig, address: FipsAddress) -> Result<Self, TunError> {
        // Check if IPv6 is enabled
        if platform::is_ipv6_disabled() {
            return Err(TunError::Ipv6Disabled);
        }

        let name = config.name();
        let mtu = config.mtu();

        // Delete existing interface if present (TUN devices are exclusive)
        if platform::interface_exists(name).await {
            debug!(name, "Deleting existing TUN interface");
            if let Err(e) = platform::delete_interface(name).await {
                debug!(name, error = %e, "Failed to delete existing interface");
            }
        }

        // Create the TUN device
        let mut tun_config = tun::Configuration::default();

        // On macOS, utun devices get kernel-assigned names (utun0, utun1, ...),
        // so we skip setting the name and read it back after creation.
        #[cfg(target_os = "linux")]
        #[allow(deprecated)]
        tun_config.name(name).layer(Layer::L3).mtu(mtu);

        #[cfg(target_os = "macos")]
        {
            #[allow(deprecated)]
            tun_config.layer(Layer::L3).mtu(mtu);
        }

        let device = tun::create(&tun_config)?;

        // Read the actual device name (on macOS this is the kernel-assigned utun* name)
        let actual_name = {
            use tun::AbstractDevice;
            device
                .tun_name()
                .map_err(|e| TunError::Configure(format!("failed to get device name: {}", e)))?
        };

        // Configure address and bring up via platform-specific method
        platform::configure_interface(&actual_name, address.to_ipv6(), mtu).await?;

        Ok(Self {
            device,
            name: actual_name,
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

    /// Get a reference to the underlying tun::Device.
    pub fn device(&self) -> &tun::Device {
        &self.device
    }

    /// Get a mutable reference to the underlying tun::Device.
    pub fn device_mut(&mut self) -> &mut tun::Device {
        &mut self.device
    }

    /// Read a packet from the TUN device.
    ///
    /// Returns the number of bytes read into the buffer, or an `io::Error`.
    /// The buffer should be at least MTU + header size (typically 1500+ bytes).
    ///
    /// The tun crate's `Read` impl transparently strips the macOS utun
    /// packet information header, so this returns a raw IP packet on all
    /// platforms.
    ///
    /// The raw `io::Error` is returned so callers can inspect `ErrorKind`
    /// (e.g. `WouldBlock`) or `raw_os_error()` without string matching.
    pub fn read_packet(&mut self, buf: &mut [u8]) -> Result<usize, std::io::Error> {
        self.device.read(buf)
    }

    /// Shutdown and delete the TUN device.
    ///
    /// This deletes the interface entirely.
    pub async fn shutdown(&self) -> Result<(), TunError> {
        debug!(name = %self.name, "Deleting TUN device");
        platform::delete_interface(&self.name).await
    }

    /// Create a TunWriter for this device.
    ///
    /// This duplicates the underlying file descriptor so that reads and writes
    /// can happen independently on separate threads. Returns the writer and
    /// a channel sender for submitting packets to be written.
    ///
    /// `max_mss` is the global TCP MSS ceiling derived from the local
    /// `transport_mtu()` floor. `path_mtu_lookup` is a read-only handle to
    /// the per-destination path MTU map populated by discovery; the writer
    /// reads it on each inbound SYN-ACK to compute a per-flow ceiling that
    /// honors learned narrow paths through the mesh.
    pub fn create_writer(
        &self,
        max_mss: u16,
        path_mtu_lookup: PathMtuLookup,
    ) -> Result<(TunWriter, TunTx), TunError> {
        let fd = self.device.as_raw_fd();

        // Duplicate the file descriptor for writing
        let write_fd = unsafe { libc::dup(fd) };
        if write_fd < 0 {
            return Err(TunError::Configure(format!(
                "failed to dup fd: {}",
                std::io::Error::last_os_error()
            )));
        }

        let write_file = unsafe { File::from_raw_fd(write_fd) };
        let (tx, rx) = write_channel();

        Ok((
            TunWriter {
                file: write_file,
                rx,
                name: self.name.clone(),
                max_mss,
                path_mtu_lookup,
            },
            tx,
        ))
    }
}

/// macOS utun protocol family value for IPv6 (matches `<sys/socket.h>`
/// `AF_INET6` on Darwin). Used as the 4-byte big-endian packet-info
/// header prepended to every utun frame.
#[cfg(target_os = "macos")]
const UTUN_AF_INET6: u32 = 30;

/// Build the 4-byte big-endian utun packet-info header for an IPv6 frame.
///
/// utun devices on macOS require a 4-byte address-family prefix on every
/// frame: a single big-endian `u32` carrying the protocol family. For
/// IPv6 traffic (the only family FIPS sends) this is `AF_INET6 = 30`,
/// which serializes as `[0x00, 0x00, 0x00, 0x1e]`.
#[cfg(target_os = "macos")]
#[inline]
fn utun_af_inet6_header() -> [u8; 4] {
    UTUN_AF_INET6.to_be_bytes()
}

/// Parse the 4-byte big-endian utun packet-info header.
///
/// Returns the address-family value (`AF_INET6 = 30` for IPv6 frames),
/// or `None` if the buffer is shorter than the 4-byte header. The `tun`
/// crate's `Read` impl strips this transparently for us in the read
/// path; this helper exists for round-trip testability with
/// [`utun_af_inet6_header`] and for any future code path that reads
/// from the dup'd fd directly.
#[cfg(all(test, target_os = "macos"))]
#[inline]
fn parse_utun_af_prefix(buf: &[u8]) -> Option<u32> {
    if buf.len() < 4 {
        return None;
    }
    Some(u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]))
}

/// Writer thread for TUN device.
///
/// Services a queue of outbound packets and writes them to the TUN device.
/// Multiple producers can send packets via the TunTx channel.
///
/// Also performs TCP MSS clamping on inbound SYN-ACK packets.
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub struct TunWriter {
    file: File,
    rx: TunRx,
    name: String,
    max_mss: u16,
    path_mtu_lookup: PathMtuLookup,
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
impl TunWriter {
    /// Run the writer loop.
    ///
    /// Blocks forever, reading packets from the channel and writing them
    /// to the TUN device. Returns when the channel is closed (all senders dropped).
    #[cfg_attr(target_os = "macos", allow(unused_mut))]
    pub fn run(mut self) {
        use super::tcp_mss::clamp_tcp_mss;

        debug!(name = %self.name, max_mss = self.max_mss, "TUN writer starting");

        for mut packet in self.rx {
            // Per-destination clamp: peer IPv6 source address (bytes 8..24)
            // identifies the flow's remote end. If discovery has learned a
            // smaller path MTU for that peer, tighten the ceiling.
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

            // On macOS, utun devices require a 4-byte packet information header
            // prepended to each packet. The tun crate handles this for its own
            // Read/Write impl, but we use a dup'd fd directly. We use writev
            // to avoid allocating a buffer on every packet.
            #[cfg(target_os = "macos")]
            let write_result = {
                use std::os::unix::io::AsRawFd;
                let af_header = utun_af_inet6_header();
                let iov = [
                    libc::iovec {
                        iov_base: af_header.as_ptr() as *mut libc::c_void,
                        iov_len: 4,
                    },
                    libc::iovec {
                        iov_base: packet.as_slice().as_ptr() as *mut libc::c_void,
                        iov_len: packet.len(),
                    },
                ];
                let ret = unsafe { libc::writev(self.file.as_raw_fd(), iov.as_ptr(), 2) };
                if ret < 0 {
                    Err(std::io::Error::last_os_error())
                } else {
                    let expected = 4 + packet.len();
                    if (ret as usize) < expected {
                        Err(std::io::Error::new(
                            std::io::ErrorKind::WriteZero,
                            format!("short writev: {} of {} bytes", ret, expected),
                        ))
                    } else {
                        Ok(())
                    }
                }
            };
            #[cfg(not(target_os = "macos"))]
            let write_result = self.file.write_all(packet.as_slice());

            if let Err(e) = write_result {
                // "Bad address" is expected during shutdown when interface is deleted
                let err_str = e.to_string();
                if err_str.contains("Bad address") {
                    break;
                }
                error!(name = %self.name, error = %e, "TUN write error");
            } else {
                trace!(name = %self.name, len = packet.len(), "TUN packet written");
            }
        }
    }
}

/// TUN packet reader loop (Linux).
///
/// Reads IPv6 packets from the TUN device. Packets destined for FIPS addresses
/// (fd::/8) are forwarded to the Node via the outbound channel for session
/// encapsulation and routing. Non-FIPS packets receive ICMPv6 Destination
/// Unreachable responses.
///
/// Also performs TCP MSS clamping on SYN packets to prevent oversized segments.
///
/// This is designed to run in a dedicated thread since TUN reads are blocking.
/// The loop exits when the TUN interface is deleted (EFAULT) or an unrecoverable
/// error occurs.
#[cfg(not(target_os = "macos"))]
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub fn run_tun_reader(
    mut device: TunDevice,
    mtu: u16,
    our_addr: FipsAddress,
    tun_tx: TunTx,
    outbound_tx: TunOutboundTx,
    transport_mtu: u16,
    path_mtu_lookup: PathMtuLookup,
) {
    let (name, mut buf, max_mss) = tun_reader_setup(device.name(), mtu, transport_mtu);

    loop {
        match device.read_packet(&mut buf) {
            Ok(n) if n > 0 => {
                if !handle_tun_packet(
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
                // EFAULT ("Bad address") is expected during shutdown when the interface is deleted
                if e.raw_os_error() != Some(libc::EFAULT) {
                    error!(name = %name, error = %e, "TUN read error");
                }
                break;
            }
        }
    }
}

/// RAII wrapper that closes a raw fd on drop.
///
/// Used to ensure the shutdown pipe read-end is always closed when
/// `run_tun_reader` returns, regardless of which exit path is taken.
#[cfg(target_os = "macos")]
struct ShutdownFd(std::os::unix::io::RawFd);

#[cfg(target_os = "macos")]
impl Drop for ShutdownFd {
    fn drop(&mut self) {
        unsafe {
            libc::close(self.0);
        }
    }
}

/// TUN packet reader loop (macOS).
///
/// Uses `select()` to multiplex between the TUN fd and a shutdown pipe,
/// avoiding the need to close the TUN fd externally (which would cause a
/// double-close when `TunDevice` drops).
#[cfg(target_os = "macos")]
#[allow(clippy::too_many_arguments)]
pub fn run_tun_reader(
    mut device: TunDevice,
    mtu: u16,
    our_addr: FipsAddress,
    tun_tx: TunTx,
    outbound_tx: TunOutboundTx,
    transport_mtu: u16,
    path_mtu_lookup: PathMtuLookup,
    shutdown_fd: std::os::unix::io::RawFd,
) {
    let _shutdown_fd = ShutdownFd(shutdown_fd);
    let tun_fd = device.device().as_raw_fd();
    let (name, mut buf, max_mss) = tun_reader_setup(device.name(), mtu, transport_mtu);

    // Set TUN fd to non-blocking so we can use select + read without blocking
    // past the point where select returns readable.
    unsafe {
        let flags = libc::fcntl(tun_fd, libc::F_GETFL);
        if flags >= 0 {
            libc::fcntl(tun_fd, libc::F_SETFL, flags | libc::O_NONBLOCK);
        }
    }

    let nfds = tun_fd.max(shutdown_fd) + 1;

    loop {
        // Wait for either TUN data or shutdown signal
        unsafe {
            let mut read_fds: libc::fd_set = std::mem::zeroed();
            libc::FD_ZERO(&mut read_fds);
            libc::FD_SET(tun_fd, &mut read_fds);
            libc::FD_SET(shutdown_fd, &mut read_fds);

            let ret = libc::select(
                nfds,
                &mut read_fds,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            );
            if ret < 0 {
                let err = std::io::Error::last_os_error();
                if err.kind() == std::io::ErrorKind::Interrupted {
                    continue;
                }
                error!(name = %name, error = %err, "TUN select error");
                break;
            }

            // Shutdown signal received
            if libc::FD_ISSET(shutdown_fd, &read_fds) {
                debug!(name = %name, "TUN reader received shutdown signal");
                break;
            }
        }

        // TUN fd is readable — drain all available packets
        loop {
            match device.read_packet(&mut buf) {
                Ok(n) if n > 0 => {
                    if !handle_tun_packet(
                        &mut buf[..n],
                        max_mss,
                        &name,
                        our_addr,
                        &tun_tx,
                        &outbound_tx,
                        &path_mtu_lookup,
                    ) {
                        return; // _shutdown_fd closes on drop
                    }
                }
                Ok(_) => break, // No more data
                Err(e) => {
                    if e.kind() == std::io::ErrorKind::WouldBlock {
                        break; // Done for this select round
                    }
                    // EBADF is expected during shutdown when the fd is closed
                    if e.raw_os_error() != Some(libc::EBADF) {
                        error!(name = %name, error = %e, "TUN read error");
                    }
                    return; // _shutdown_fd closes on drop
                }
            }
        }
    }
    // _shutdown_fd closes on drop
}

/// Common setup for TUN reader: allocates buffer, computes max MSS.
#[cfg(any(target_os = "linux", target_os = "macos", windows))]
fn tun_reader_setup(device_name: &str, mtu: u16, transport_mtu: u16) -> (String, Vec<u8>, u16) {
    use super::icmp::effective_ipv6_mtu;

    let name = device_name.to_string();
    let buf = vec![0u8; mtu as usize + 100];

    const IPV6_HEADER: u16 = 40;
    const TCP_HEADER: u16 = 20;
    let effective_mtu = effective_ipv6_mtu(transport_mtu);
    let max_mss = effective_mtu
        .saturating_sub(IPV6_HEADER)
        .saturating_sub(TCP_HEADER);

    debug!(
        name = %name,
        tun_mtu = mtu,
        transport_mtu = transport_mtu,
        effective_mtu = effective_mtu,
        max_mss = max_mss,
        "TUN reader starting"
    );

    (name, buf, max_mss)
}

/// Process a single TUN packet. Returns `false` if the reader should exit.
#[cfg(any(target_os = "linux", target_os = "macos", windows))]
fn handle_tun_packet(
    packet: &mut [u8],
    max_mss: u16,
    name: &str,
    our_addr: FipsAddress,
    tun_tx: &TunTx,
    outbound_tx: &TunOutboundTx,
    path_mtu_lookup: &PathMtuLookup,
) -> bool {
    use super::icmp::{DestUnreachableCode, build_dest_unreachable, should_send_icmp_error};
    use super::tcp_mss::clamp_tcp_mss;

    log_ipv6_packet(packet);

    // Must be a valid IPv6 packet
    if packet.len() < 40 || packet[0] >> 4 != 6 {
        return true;
    }

    // Check if destination is a FIPS address (fd::/8 prefix)
    if packet[24] == crate::identity::FIPS_ADDRESS_PREFIX {
        // Per-destination clamp: if discovery has learned a smaller path
        // MTU for this destination, tighten the ceiling for this flow.
        let effective_max_mss = per_flow_max_mss(path_mtu_lookup, &packet[24..40], max_mss);
        if clamp_tcp_mss(packet, effective_max_mss) {
            trace!(name = %name, max_mss = effective_max_mss, "Clamped TCP MSS in SYN packet");
        }
        match outbound_tx.admit_from_tun_reader(packet.to_vec()) {
            Ok(TunOutboundAdmission::Enqueued | TunOutboundAdmission::BulkDropped) => {}
            Err(_) => return false, // Channel closed, shutdown
        }
    } else {
        // Non-FIPS destination: send ICMPv6 Destination Unreachable
        if should_send_icmp_error(packet)
            && let Some(response) =
                build_dest_unreachable(packet, DestUnreachableCode::NoRoute, our_addr.to_ipv6())
        {
            trace!(name = %name, len = response.len(), "Sending ICMPv6 Destination Unreachable (non-FIPS destination)");
            if tun_tx.send(response).is_err() {
                return false;
            }
        }
    }
    true
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
impl std::fmt::Debug for TunDevice {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TunDevice")
            .field("name", &self.name)
            .field("mtu", &self.mtu)
            .field("address", &self.address)
            .finish()
    }
}

/// Log basic information about an IPv6 packet at TRACE level.
pub fn log_ipv6_packet(packet: &[u8]) {
    if packet.len() < 40 {
        debug!(len = packet.len(), "Received undersized packet");
        return;
    }

    let version = packet[0] >> 4;
    if version != 6 {
        debug!(version, len = packet.len(), "Received non-IPv6 packet");
        return;
    }

    let payload_len = u16::from_be_bytes([packet[4], packet[5]]);
    let next_header = packet[6];
    let hop_limit = packet[7];

    let src = Ipv6Addr::from(<[u8; 16]>::try_from(&packet[8..24]).unwrap());
    let dst = Ipv6Addr::from(<[u8; 16]>::try_from(&packet[24..40]).unwrap());

    let protocol = match next_header {
        6 => "TCP",
        17 => "UDP",
        58 => "ICMPv6",
        _ => "other",
    };

    trace!("TUN packet received:");
    trace!("      src: {}", src);
    trace!("      dst: {}", dst);
    trace!(" protocol: {} ({})", protocol, next_header);
    trace!("  payload: {} bytes, hop_limit: {}", payload_len, hop_limit);
}

/// Shutdown and delete a TUN interface by name.
///
/// This deletes the interface, which will cause any blocking reads
/// to return an error. Use this for graceful shutdown when the TUN device
/// has been moved to another thread.
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub async fn shutdown_tun_interface(name: &str) -> Result<(), TunError> {
    debug!("Shutting down TUN interface {}", name);
    platform::delete_interface(name).await?;
    debug!("TUN interface {} stopped", name);
    Ok(())
}

// ============================================================================
// Platform-specific system TUN modules
// ============================================================================

#[cfg(windows)]
mod windows;
#[cfg(windows)]
pub use windows::{TunDevice, TunWriter, run_tun_reader, shutdown_tun_interface};

#[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
mod unsupported;
#[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
pub use unsupported::{TunDevice, TunWriter, run_tun_reader, shutdown_tun_interface};

#[cfg(any(target_os = "linux", target_os = "macos"))]
mod platform;

#[cfg(test)]
mod tests;
