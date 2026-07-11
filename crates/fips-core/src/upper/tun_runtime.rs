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
pub(crate) fn run_tun_reader(runtime: TunReaderRuntime) {
    #[cfg(target_os = "linux")]
    if runtime.device.vnet_hdr() {
        run_linux_vnet_tun_reader(runtime);
        return;
    }

    let TunReaderRuntime {
        mut device,
        mtu,
        our_addr,
        tun_tx,
        outbound_tx,
        transport_mtu,
        path_mtu_lookup,
    } = runtime;
    let read_buffer_len = device.read_buffer_len(mtu);
    let (name, mut buf, max_mss) =
        tun_reader_setup_with_buffer_len(device.name(), mtu, transport_mtu, read_buffer_len);

    loop {
        match device.read_packet(&mut buf) {
            Ok(n) if n > 0 => {
                crate::perf_profile::record_tun_read_packet(n);
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

#[cfg(target_os = "linux")]
fn run_linux_vnet_tun_reader(runtime: TunReaderRuntime) {
    let TunReaderRuntime {
        mut device,
        mtu,
        our_addr,
        tun_tx,
        outbound_tx,
        transport_mtu,
        path_mtu_lookup,
    } = runtime;
    let read_buffer_len = device.read_buffer_len(mtu);
    let (name, mut buf, max_mss) =
        tun_reader_setup_with_buffer_len(device.name(), mtu, transport_mtu, read_buffer_len);
    let mut packets = Vec::with_capacity(64);

    loop {
        packets.clear();
        match device.read_vnet_packets_into(&mut buf, &mut packets) {
            Ok(n) if n > 0 => {
                debug_assert_eq!(n, packets.len());
                for packet in packets.drain(..) {
                    crate::perf_profile::record_tun_read_packet(packet.len());
                    if !handle_tun_packet_owned(
                        packet,
                        max_mss,
                        &name,
                        our_addr,
                        &tun_tx,
                        &outbound_tx,
                        &path_mtu_lookup,
                    ) {
                        return;
                    }
                }
            }
            Ok(_) => {}
            Err(e) => {
                if e.raw_os_error() != Some(libc::EFAULT) {
                    error!(name = %name, error = %e, "Linux vnet TUN read error");
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
pub(crate) fn run_tun_reader(runtime: TunReaderRuntime, shutdown_fd: std::os::unix::io::RawFd) {
    let TunReaderRuntime {
        mut device,
        mtu,
        our_addr,
        tun_tx,
        outbound_tx,
        transport_mtu,
        path_mtu_lookup,
    } = runtime;
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
                    crate::perf_profile::record_tun_read_packet(n);
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
#[cfg(any(target_os = "macos", windows))]
fn tun_reader_setup(device_name: &str, mtu: u16, transport_mtu: u16) -> (String, Vec<u8>, u16) {
    tun_reader_setup_with_buffer_len(
        device_name,
        mtu,
        transport_mtu,
        default_tun_read_buffer_len(mtu),
    )
}

#[cfg(any(target_os = "linux", target_os = "macos", windows))]
fn tun_reader_setup_with_buffer_len(
    device_name: &str,
    mtu: u16,
    transport_mtu: u16,
    read_buffer_len: usize,
) -> (String, Vec<u8>, u16) {
    use super::icmp::effective_ipv6_mtu;

    let name = device_name.to_string();
    let buf = vec![0u8; read_buffer_len];

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

#[cfg(any(target_os = "linux", target_os = "macos", windows))]
fn default_tun_read_buffer_len(mtu: u16) -> usize {
    mtu as usize + 100
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
    match prepare_tun_packet(packet, max_mss, name, our_addr, path_mtu_lookup) {
        TunPacketAction::Forward => {
            if outbound_tx
                .admit_from_tun_reader(tun_outbound_packet(packet))
                .is_err()
            {
                return false; // Channel closed, shutdown
            }
        }
        TunPacketAction::Icmp(response) => {
            if tun_tx.send(response).is_err() {
                return false;
            }
        }
        TunPacketAction::Ignore => {}
    }
    true
}

#[cfg(target_os = "linux")]
fn handle_tun_packet_owned(
    mut packet: Vec<u8>,
    max_mss: u16,
    name: &str,
    our_addr: FipsAddress,
    tun_tx: &TunTx,
    outbound_tx: &TunOutboundTx,
    path_mtu_lookup: &PathMtuLookup,
) -> bool {
    match prepare_tun_packet(&mut packet, max_mss, name, our_addr, path_mtu_lookup) {
        TunPacketAction::Forward => {
            if outbound_tx
                .admit_from_tun_reader(tun_outbound_packet_owned(packet))
                .is_err()
            {
                return false;
            }
        }
        TunPacketAction::Icmp(response) => {
            if tun_tx.send(response).is_err() {
                return false;
            }
        }
        TunPacketAction::Ignore => {}
    }
    true
}

#[cfg(any(target_os = "linux", target_os = "macos", windows))]
enum TunPacketAction {
    Forward,
    Icmp(Vec<u8>),
    Ignore,
}

#[cfg(any(target_os = "linux", target_os = "macos", windows))]
fn prepare_tun_packet(
    packet: &mut [u8],
    max_mss: u16,
    name: &str,
    our_addr: FipsAddress,
    path_mtu_lookup: &PathMtuLookup,
) -> TunPacketAction {
    use super::icmp::{DestUnreachableCode, build_dest_unreachable, should_send_icmp_error};
    use super::tcp_mss::clamp_tcp_mss;

    log_ipv6_packet(packet);

    if packet.len() < 40 || packet[0] >> 4 != 6 {
        return TunPacketAction::Ignore;
    }

    if packet[24] == crate::identity::FIPS_ADDRESS_PREFIX {
        let effective_max_mss = per_flow_max_mss(path_mtu_lookup, &packet[24..40], max_mss);
        if clamp_tcp_mss(packet, effective_max_mss) {
            trace!(name = %name, max_mss = effective_max_mss, "Clamped TCP MSS in SYN packet");
        }
        return TunPacketAction::Forward;
    }

    if should_send_icmp_error(packet)
        && let Some(response) =
            build_dest_unreachable(packet, DestUnreachableCode::NoRoute, our_addr.to_ipv6())
    {
        trace!(name = %name, len = response.len(), "Sending ICMPv6 Destination Unreachable (non-FIPS destination)");
        return TunPacketAction::Icmp(response);
    }

    TunPacketAction::Ignore
}

#[cfg(any(test, target_os = "linux", target_os = "macos", windows))]
fn tun_outbound_packet(packet: &[u8]) -> Vec<u8> {
    let mut outbound = Vec::with_capacity(
        packet
            .len()
            .saturating_add(TUN_OUTBOUND_PACKET_TAIL_RESERVE),
    );
    outbound.extend_from_slice(packet);
    outbound
}

#[cfg(any(test, target_os = "linux"))]
fn tun_outbound_packet_owned(mut packet: Vec<u8>) -> Vec<u8> {
    let needed = packet
        .len()
        .saturating_add(TUN_OUTBOUND_PACKET_TAIL_RESERVE);
    if packet.capacity() < needed {
        packet.reserve(needed - packet.capacity());
    }
    packet
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
pub(crate) use windows::run_tun_reader;
#[cfg(windows)]
pub use windows::{TunDevice, TunWriter, shutdown_tun_interface};

#[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
pub(crate) use unsupported::run_tun_reader;
#[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
pub use unsupported::{TunDevice, TunWriter, shutdown_tun_interface};

pub(crate) struct TunReaderRuntime {
    pub(crate) device: TunDevice,
    pub(crate) mtu: u16,
    pub(crate) our_addr: FipsAddress,
    pub(crate) tun_tx: TunTx,
    pub(crate) outbound_tx: TunOutboundTx,
    pub(crate) transport_mtu: u16,
    pub(crate) path_mtu_lookup: PathMtuLookup,
}
