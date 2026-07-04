//! UDP socket wrapper with platform-specific receive implementations.
//!
//! On Linux, provides `SO_RXQ_OVFL` kernel drop counter support and
//! `UDP_GRO` receive segment-size metadata via `recvmsg()` ancillary
//! data parsing. The async wrapper uses
//! `tokio::io::unix::AsyncFd` for integration with the tokio runtime.
//!
//! On macOS, uses the same `recvmsg()` path but without `SO_RXQ_OVFL`
//! (kernel drop counting is not available; the drops field returns 0).
//!
//! On Windows, uses `tokio::net::UdpSocket` directly (kernel drop
//! counting is not available; the drops field always returns 0).
//!
//! Follows the pattern established by `transport/ethernet/socket.rs`.

use crate::transport::TransportError;
use socket2::{Domain, Protocol, Socket, Type};
use std::net::SocketAddr;
use std::sync::Arc;
#[cfg(unix)]
use tracing::warn;

/// Maximum number of datagrams a single `recvmmsg` syscall pulls from the
/// kernel queue. Shared with the higher-level UDP receive loops so all Linux
/// packet ingress paths use the same batch width.
#[cfg(target_os = "linux")]
const RECV_BATCH_SIZE: usize = super::UDP_RECV_BATCH_SIZE;

// ============================================================================
// Unix implementation
// ============================================================================

#[cfg(unix)]
mod platform {
    use super::*;
    use std::os::unix::io::{AsRawFd, RawFd};
    use tokio::io::unix::AsyncFd;

    /// Maximum number of datagrams a single send batch pushes to the kernel.
    ///
    /// Linux uses sendmmsg/GSO and keeps this at 256 because the rx_loop can
    /// drain up to 256 outbound commands per scheduler tick. macOS uses
    /// Darwin sendmsg_x; 64 matches the macOS TUN read burst so a full tunnel
    /// burst can leave in one syscall without growing the stack frame as much
    /// as the Linux path.
    #[cfg(target_os = "linux")]
    const SEND_BATCH_SIZE: usize = 256;
    #[cfg(target_os = "macos")]
    const SEND_BATCH_SIZE: usize = 64;
    #[cfg(target_os = "linux")]
    const UDP_GSO_MAX_SEGMENTS: usize = 64;
    #[cfg(target_os = "linux")]
    const UDP_GSO_MAX_IOV: usize =
        UDP_GSO_MAX_SEGMENTS * crate::transport::udp::UDP_PAYLOAD_MAX_SLICES;
    #[cfg(target_os = "linux")]
    const UDP_GSO_MAX_PAYLOAD: usize = u16::MAX as usize - 8;
    #[cfg(target_os = "linux")]
    static UDP_GSO_DISABLED: std::sync::atomic::AtomicBool =
        std::sync::atomic::AtomicBool::new(false);

    // Adapted from Apple's xnu bsd/sys/socket_private.h layout, also used by
    // quinn-udp's `fast-apple-datapath` implementation. libc exposes the
    // syscall number but not this private convenience ABI.
    #[cfg(target_os = "macos")]
    #[repr(C)]
    #[allow(non_camel_case_types)]
    struct msghdr_x {
        msg_name: *mut libc::c_void,
        msg_namelen: libc::socklen_t,
        msg_iov: *mut libc::iovec,
        msg_iovlen: libc::c_int,
        msg_control: *mut libc::c_void,
        msg_controllen: libc::socklen_t,
        msg_flags: libc::c_int,
        msg_datalen: usize,
    }

    #[cfg(target_os = "macos")]
    unsafe extern "C" {
        fn sendmsg_x(
            s: libc::c_int,
            msgp: *const msghdr_x,
            cnt: libc::c_uint,
            flags: libc::c_int,
        ) -> isize;
    }

    /// Wrapper around a `socket2::Socket` providing sync send/recv with
    /// `SO_RXQ_OVFL` ancillary data parsing.
    pub struct UdpRawSocket {
        inner: Socket,
        local_addr: SocketAddr,
        #[cfg(target_os = "linux")]
        udp_gro_enabled: bool,
    }

    #[cfg(target_os = "linux")]
    const RECV_CMSG_BUF_SIZE: usize = unsafe { libc::CMSG_SPACE(std::mem::size_of::<u32>() as u32) }
        as usize
        + unsafe { libc::CMSG_SPACE(std::mem::size_of::<u16>() as u32) } as usize;

    #[cfg(target_os = "linux")]
    #[derive(Default)]
    struct LinuxRecvCmsgs {
        drops: Option<u32>,
        gro_segment_size: usize,
    }

    #[cfg(target_os = "linux")]
    fn configure_linux_recv_sockopts(fd: RawFd) -> bool {
        let enable: libc::c_int = 1;

        let rxq_ret = unsafe {
            libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_RXQ_OVFL,
                &enable as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            )
        };
        if rxq_ret < 0 {
            warn!(
                "setsockopt(SO_RXQ_OVFL) failed: {}",
                std::io::Error::last_os_error()
            );
        }

        let gro_ret = unsafe {
            libc::setsockopt(
                fd,
                libc::IPPROTO_UDP,
                libc::UDP_GRO,
                &enable as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            )
        };
        if gro_ret < 0 {
            tracing::debug!(
                error = %std::io::Error::last_os_error(),
                "setsockopt(UDP_GRO) failed; receiving UDP datagrams without GRO metadata"
            );
            false
        } else {
            tracing::debug!("UDP_GRO receive offload enabled");
            true
        }
    }

    #[cfg(target_os = "linux")]
    unsafe fn parse_linux_recv_cmsgs(msg: &libc::msghdr) -> LinuxRecvCmsgs {
        let mut parsed = LinuxRecvCmsgs::default();
        let mut cmsg = unsafe { libc::CMSG_FIRSTHDR(msg) };
        while !cmsg.is_null() {
            let level = unsafe { (*cmsg).cmsg_level };
            let cmsg_type = unsafe { (*cmsg).cmsg_type };
            if level == libc::SOL_SOCKET && cmsg_type == libc::SO_RXQ_OVFL {
                let data = unsafe { libc::CMSG_DATA(cmsg) };
                parsed.drops = Some(unsafe { std::ptr::read_unaligned(data as *const u32) });
            } else if level == libc::IPPROTO_UDP && cmsg_type == libc::UDP_GRO {
                let data = unsafe { libc::CMSG_DATA(cmsg) };
                let segment_size = unsafe { std::ptr::read_unaligned(data as *const u16) };
                if segment_size > 0 {
                    parsed.gro_segment_size = segment_size as usize;
                }
            }
            cmsg = unsafe { libc::CMSG_NXTHDR(msg, cmsg) };
        }
        parsed
    }

    impl UdpRawSocket {
        /// Create, bind, and configure a UDP socket.
        ///
        /// Enables `SO_RXQ_OVFL` for kernel drop counting (non-fatal if
        /// unsupported). Sets non-blocking mode for async integration.
        #[cfg_attr(target_os = "macos", allow(dead_code))]
        pub fn open(
            bind_addr: SocketAddr,
            recv_buf_size: usize,
            send_buf_size: usize,
        ) -> Result<Self, TransportError> {
            Self::open_inner(bind_addr, recv_buf_size, send_buf_size)
        }

        fn open_inner(
            bind_addr: SocketAddr,
            recv_buf_size: usize,
            send_buf_size: usize,
        ) -> Result<Self, TransportError> {
            let domain = if bind_addr.is_ipv4() {
                Domain::IPV4
            } else {
                Domain::IPV6
            };
            let sock = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))
                .map_err(|e| TransportError::StartFailed(format!("socket create failed: {}", e)))?;

            sock.set_nonblocking(true).map_err(|e| {
                TransportError::StartFailed(format!("set nonblocking failed: {}", e))
            })?;

            // SO_REUSEPORT/SO_REUSEADDR keeps restart/adopt behavior friendly
            // on platforms that support it.
            #[cfg(not(target_os = "macos"))]
            {
                let _ = sock.set_reuse_port(true);
                let _ = sock.set_reuse_address(true);
            }
            #[cfg(target_os = "macos")]
            {
                let _ = sock.set_reuse_port(true);
                let _ = sock.set_reuse_address(true);
            }

            #[cfg(target_os = "macos")]
            crate::transport::udp::darwin_sockopts::apply_udp_socket_tuning(
                sock.as_raw_fd(),
                "udp-listen",
            );

            sock.bind(&bind_addr.into())
                .map_err(|e| TransportError::StartFailed(format!("bind failed: {}", e)))?;

            // Set socket buffer sizes via the standard SO_RCVBUF /
            // SO_SNDBUF path first. These are clamped to
            // `net.core.{rmem,wmem}_max`, which on a default Linux
            // container is ~213 KiB — way too small to absorb a multi-
            // Gbps inbound burst, leading to UDP RcvbufErrors at line
            // rate. If clamped and we hold CAP_NET_ADMIN, the
            // SO_RCVBUFFORCE / SO_SNDBUFFORCE variants bypass the
            // sysctl ceiling entirely.
            sock.set_recv_buffer_size(recv_buf_size)
                .map_err(|e| TransportError::StartFailed(format!("set recv buffer: {}", e)))?;
            sock.set_send_buffer_size(send_buf_size)
                .map_err(|e| TransportError::StartFailed(format!("set send buffer: {}", e)))?;

            // The SO_RCVBUFFORCE / SO_SNDBUFFORCE fallback below is
            // Linux-only and may reassign these; non-Linux builds
            // leave them at the initial reading.
            #[allow(unused_mut)]
            let mut actual_recv = sock
                .recv_buffer_size()
                .map_err(|e| TransportError::StartFailed(format!("get recv buffer: {}", e)))?;
            #[allow(unused_mut)]
            let mut actual_send = sock
                .send_buffer_size()
                .map_err(|e| TransportError::StartFailed(format!("get send buffer: {}", e)))?;

            #[cfg(target_os = "linux")]
            if actual_recv < recv_buf_size {
                let val: libc::c_int = recv_buf_size as libc::c_int;
                let ret = unsafe {
                    libc::setsockopt(
                        sock.as_raw_fd(),
                        libc::SOL_SOCKET,
                        libc::SO_RCVBUFFORCE,
                        &val as *const _ as *const libc::c_void,
                        std::mem::size_of::<libc::c_int>() as libc::socklen_t,
                    )
                };
                if ret == 0
                    && let Ok(after) = sock.recv_buffer_size()
                {
                    actual_recv = after;
                }
            }
            #[cfg(target_os = "linux")]
            if actual_send < send_buf_size {
                let val: libc::c_int = send_buf_size as libc::c_int;
                let ret = unsafe {
                    libc::setsockopt(
                        sock.as_raw_fd(),
                        libc::SOL_SOCKET,
                        libc::SO_SNDBUFFORCE,
                        &val as *const _ as *const libc::c_void,
                        std::mem::size_of::<libc::c_int>() as libc::socklen_t,
                    )
                };
                if ret == 0
                    && let Ok(after) = sock.send_buffer_size()
                {
                    actual_send = after;
                }
            }

            if actual_recv < recv_buf_size {
                warn!(
                    requested = recv_buf_size,
                    actual = actual_recv,
                    "UDP recv buffer clamped by kernel even with SO_RCVBUFFORCE \
                     (increase net.core.rmem_max or grant CAP_NET_ADMIN)"
                );
            }
            if actual_send < send_buf_size {
                warn!(
                    requested = send_buf_size,
                    actual = actual_send,
                    "UDP send buffer clamped by kernel even with SO_SNDBUFFORCE \
                     (increase net.core.wmem_max or grant CAP_NET_ADMIN)"
                );
            }

            #[cfg(target_os = "linux")]
            let udp_gro_enabled = configure_linux_recv_sockopts(sock.as_raw_fd());

            let local_addr = sock
                .local_addr()
                .map_err(|e| TransportError::StartFailed(format!("get local addr: {}", e)))?
                .as_socket()
                .ok_or_else(|| {
                    TransportError::StartFailed("local address is not an IP socket".into())
                })?;

            Ok(Self {
                inner: sock,
                local_addr,
                #[cfg(target_os = "linux")]
                udp_gro_enabled,
            })
        }

        /// Adopt an existing bound UDP socket.
        ///
        /// This preserves socket identity/NAT mapping created by bootstrap code.
        #[cfg_attr(target_os = "macos", allow(dead_code))]
        pub fn adopt(
            socket: std::net::UdpSocket,
            recv_buf_size: usize,
            send_buf_size: usize,
        ) -> Result<Self, TransportError> {
            Self::adopt_inner(socket, recv_buf_size, send_buf_size)
        }

        fn adopt_inner(
            socket: std::net::UdpSocket,
            recv_buf_size: usize,
            send_buf_size: usize,
        ) -> Result<Self, TransportError> {
            let sock = Socket::from(socket);

            sock.set_nonblocking(true).map_err(|e| {
                TransportError::StartFailed(format!("set nonblocking failed: {}", e))
            })?;

            // Adopted NAT-traversal sockets become normal FIPS UDP transports.
            // Keep their reuse flags aligned with `open()`.
            #[cfg(not(target_os = "macos"))]
            {
                let _ = sock.set_reuse_port(true);
                let _ = sock.set_reuse_address(true);
            }
            #[cfg(target_os = "macos")]
            {
                let _ = sock.set_reuse_port(true);
                let _ = sock.set_reuse_address(true);
            }

            #[cfg(target_os = "macos")]
            crate::transport::udp::darwin_sockopts::apply_udp_socket_tuning(
                sock.as_raw_fd(),
                "udp-adopted",
            );

            sock.set_recv_buffer_size(recv_buf_size)
                .map_err(|e| TransportError::StartFailed(format!("set recv buffer: {}", e)))?;
            sock.set_send_buffer_size(send_buf_size)
                .map_err(|e| TransportError::StartFailed(format!("set send buffer: {}", e)))?;

            // The SO_RCVBUFFORCE / SO_SNDBUFFORCE fallback below is
            // Linux-only and may reassign these; non-Linux builds
            // leave them at the initial reading.
            #[allow(unused_mut)]
            let mut actual_recv = sock
                .recv_buffer_size()
                .map_err(|e| TransportError::StartFailed(format!("get recv buffer: {}", e)))?;
            #[allow(unused_mut)]
            let mut actual_send = sock
                .send_buffer_size()
                .map_err(|e| TransportError::StartFailed(format!("get send buffer: {}", e)))?;

            // CAP_NET_ADMIN holders can bypass rmem_max via
            // SO_RCVBUFFORCE; see `open()` for the rationale.
            #[cfg(target_os = "linux")]
            if actual_recv < recv_buf_size {
                let val: libc::c_int = recv_buf_size as libc::c_int;
                let ret = unsafe {
                    libc::setsockopt(
                        sock.as_raw_fd(),
                        libc::SOL_SOCKET,
                        libc::SO_RCVBUFFORCE,
                        &val as *const _ as *const libc::c_void,
                        std::mem::size_of::<libc::c_int>() as libc::socklen_t,
                    )
                };
                if ret == 0
                    && let Ok(after) = sock.recv_buffer_size()
                {
                    actual_recv = after;
                }
            }
            #[cfg(target_os = "linux")]
            if actual_send < send_buf_size {
                let val: libc::c_int = send_buf_size as libc::c_int;
                let ret = unsafe {
                    libc::setsockopt(
                        sock.as_raw_fd(),
                        libc::SOL_SOCKET,
                        libc::SO_SNDBUFFORCE,
                        &val as *const _ as *const libc::c_void,
                        std::mem::size_of::<libc::c_int>() as libc::socklen_t,
                    )
                };
                if ret == 0
                    && let Ok(after) = sock.send_buffer_size()
                {
                    actual_send = after;
                }
            }

            if actual_recv < recv_buf_size {
                warn!(
                    requested = recv_buf_size,
                    actual = actual_recv,
                    "UDP recv buffer clamped by kernel even with SO_RCVBUFFORCE \
                     (increase net.core.rmem_max or grant CAP_NET_ADMIN)"
                );
            }
            if actual_send < send_buf_size {
                warn!(
                    requested = send_buf_size,
                    actual = actual_send,
                    "UDP send buffer clamped by kernel even with SO_SNDBUFFORCE \
                     (increase net.core.wmem_max or grant CAP_NET_ADMIN)"
                );
            }

            #[cfg(target_os = "linux")]
            let udp_gro_enabled = configure_linux_recv_sockopts(sock.as_raw_fd());

            let local_addr = sock
                .local_addr()
                .map_err(|e| TransportError::StartFailed(format!("get local addr: {}", e)))?
                .as_socket()
                .ok_or_else(|| {
                    TransportError::StartFailed("local address is not an IP socket".into())
                })?;

            Ok(Self {
                inner: sock,
                local_addr,
                #[cfg(target_os = "linux")]
                udp_gro_enabled,
            })
        }

        /// Get the local bound address.
        pub fn local_addr(&self) -> SocketAddr {
            self.local_addr
        }

        /// Get the actual receive buffer size granted by the kernel.
        pub fn recv_buffer_size(&self) -> Result<usize, TransportError> {
            self.inner
                .recv_buffer_size()
                .map_err(|e| TransportError::StartFailed(format!("get recv buffer: {}", e)))
        }

        /// Get the actual send buffer size granted by the kernel.
        pub fn send_buffer_size(&self) -> Result<usize, TransportError> {
            self.inner
                .send_buffer_size()
                .map_err(|e| TransportError::StartFailed(format!("get send buffer: {}", e)))
        }

        /// Synchronous send to a destination address.
        ///
        /// Returns the number of bytes sent, or an `io::Error`.
        ///
        /// On Linux the production send path uses `send_batch` (sendmmsg);
        /// this single-packet variant remains for non-Linux unix targets
        /// and for the local `tests` module.
        #[cfg_attr(target_os = "linux", allow(dead_code))]
        pub fn send_to(&self, data: &[u8], dest: &SocketAddr) -> std::io::Result<usize> {
            let dest: socket2::SockAddr = (*dest).into();
            self.inner.send_to(data, &dest)
        }

        /// Synchronous receive with `SO_RXQ_OVFL` ancillary data parsing.
        ///
        /// Returns `(bytes_read, source_addr, kernel_drops, gro_segment_size)`.
        /// The `kernel_drops` value is a cumulative counter since socket
        /// creation; it is 0 if `SO_RXQ_OVFL` is not supported.
        /// `gro_segment_size` is 0 unless Linux `UDP_GRO` reported the
        /// original UDP payload size for a coalesced receive.
        ///
        /// On Linux the production receive path uses `recv_batch` (recvmmsg);
        /// this single-packet variant remains for non-Linux unix targets and
        /// for the local `tests` module.
        #[cfg_attr(target_os = "linux", allow(dead_code))]
        pub fn recv_from(
            &self,
            buf: &mut [u8],
        ) -> std::io::Result<(usize, SocketAddr, u32, usize)> {
            let fd = self.inner.as_raw_fd();

            let mut iov = libc::iovec {
                iov_base: buf.as_mut_ptr() as *mut libc::c_void,
                iov_len: buf.len(),
            };

            #[cfg(target_os = "linux")]
            const CMSG_BUF_SIZE: usize = RECV_CMSG_BUF_SIZE;
            #[cfg(not(target_os = "linux"))]
            const CMSG_BUF_SIZE: usize = 64;
            let mut cmsg_buf = [0u8; CMSG_BUF_SIZE];

            let mut src_addr: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
            let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
            msg.msg_name = &mut src_addr as *mut _ as *mut libc::c_void;
            msg.msg_namelen = std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
            msg.msg_iov = &mut iov;
            msg.msg_iovlen = 1 as _;
            msg.msg_control = cmsg_buf.as_mut_ptr() as *mut libc::c_void;
            msg.msg_controllen = cmsg_buf.len() as _;

            let n = unsafe { libc::recvmsg(fd, &mut msg, 0) };
            if n < 0 {
                return Err(std::io::Error::last_os_error());
            }

            // Parse source address from sockaddr_storage
            let addr = sockaddr_to_socket_addr(&src_addr)?;

            #[cfg(target_os = "linux")]
            let cmsgs = unsafe { parse_linux_recv_cmsgs(&msg) };
            #[cfg(target_os = "linux")]
            let (drops, gro_segment_size) = (cmsgs.drops.unwrap_or(0), cmsgs.gro_segment_size);
            #[cfg(not(target_os = "linux"))]
            let (drops, gro_segment_size) = (0, 0);

            Ok((n as usize, addr, drops, gro_segment_size))
        }

        /// Receive up to `RECV_BATCH_SIZE` datagrams in a single recvmmsg syscall
        /// (Linux only — macOS falls through to per-packet recvmsg).
        ///
        /// Returns `(count, kernel_drops)`. Caller provides receive buffers
        /// with enough spare capacity for one datagram, plus matching
        /// `addrs` and `gro_segment_sizes` slices; on return,
        /// `bufs[0..count]` have their lengths set to the initialized bytes
        /// received from the kernel. `gro_segment_sizes[i]` is 0 unless Linux
        /// `UDP_GRO` reported the original UDP payload size for that slot.
        ///
        /// `kernel_drops` is the `SO_RXQ_OVFL` cumulative counter sampled
        /// from the cmsg chain of the FIRST datagram in the batch. The
        /// counter is monotonic per-socket since `SO_RXQ_OVFL` was enabled,
        /// so a single sample per batch is sufficient to feed the 1Hz
        /// congestion detector in `sample_transport_congestion()`. Returns
        /// `(0, 0)` on a spurious wakeup with no datagrams ready.
        #[cfg(target_os = "linux")]
        pub fn recv_batch(
            &self,
            bufs: &mut [Vec<u8>],
            addrs: &mut [Option<SocketAddr>],
            gro_segment_sizes: &mut [usize],
        ) -> std::io::Result<(usize, u32)> {
            let n = bufs
                .len()
                .min(addrs.len())
                .min(gro_segment_sizes.len())
                .min(RECV_BATCH_SIZE);
            if n == 0 {
                return Ok((0, 0));
            }
            let fd = self.inner.as_raw_fd();

            // CMSG buffers for every batch slot. SO_RXQ_OVFL and UDP_GRO are
            // attached to individual datagrams, not guaranteed to the first
            // datagram in a recvmmsg batch.
            const CMSG_BUF_SIZE: usize = RECV_CMSG_BUF_SIZE;
            let mut cmsg_bufs = [[0u8; CMSG_BUF_SIZE]; RECV_BATCH_SIZE];

            // Stack-allocated parallel arrays; lifetime tied to this call.
            let mut iovs: [libc::iovec; RECV_BATCH_SIZE] = unsafe { std::mem::zeroed() };
            let mut storages: [libc::sockaddr_storage; RECV_BATCH_SIZE] =
                unsafe { std::mem::zeroed() };
            let mut msgs: [libc::mmsghdr; RECV_BATCH_SIZE] = unsafe { std::mem::zeroed() };

            for i in 0..n {
                bufs[i].clear();
                gro_segment_sizes[i] = 0;
                let spare = bufs[i].spare_capacity_mut();
                if spare.is_empty() {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        "UDP receive buffer has no spare capacity",
                    ));
                }
                iovs[i].iov_base = spare.as_mut_ptr() as *mut libc::c_void;
                iovs[i].iov_len = spare.len();
                msgs[i].msg_hdr.msg_name = &mut storages[i] as *mut _ as *mut libc::c_void;
                msgs[i].msg_hdr.msg_namelen =
                    std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
                msgs[i].msg_hdr.msg_iov = &mut iovs[i];
                msgs[i].msg_hdr.msg_iovlen = 1;
                msgs[i].msg_hdr.msg_control = cmsg_bufs[i].as_mut_ptr() as *mut libc::c_void;
                msgs[i].msg_hdr.msg_controllen = cmsg_bufs[i].len() as _;
                msgs[i].msg_len = 0;
            }

            let r = unsafe {
                libc::recvmmsg(
                    fd,
                    msgs.as_mut_ptr(),
                    n as libc::c_uint,
                    0,
                    std::ptr::null_mut(),
                )
            };
            if r < 0 {
                return Err(std::io::Error::last_os_error());
            }
            let count = r as usize;
            for i in 0..count {
                let len = msgs[i].msg_len as usize;
                if len > bufs[i].capacity() {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "recvmmsg reported a datagram larger than the receive buffer",
                    ));
                }
                // SAFETY: `recvmmsg` wrote `len` initialized bytes into
                // `bufs[i]`'s spare capacity through the iovec above, and
                // `len <= capacity` was checked before extending the Vec.
                unsafe {
                    bufs[i].set_len(len);
                }
                addrs[i] = sockaddr_to_socket_addr(&storages[i]).ok();
            }

            // Walk every cmsg chain. Skip when no datagram landed (cmsg
            // buffers are undefined in that case).
            let mut drops: u32 = 0;
            if count > 0 {
                for (i, msg) in msgs.iter().take(count).enumerate() {
                    let cmsgs = unsafe { parse_linux_recv_cmsgs(&msg.msg_hdr) };
                    if let Some(sample) = cmsgs.drops {
                        drops = sample;
                    }
                    gro_segment_sizes[i] = cmsgs.gro_segment_size;
                }
            }

            Ok((count, drops))
        }

        /// Send same-destination payloads without first materializing
        /// `(payload, addr)` tuples for every packet.
        #[cfg(target_os = "linux")]
        pub fn send_batch_to<B>(
            &self,
            payloads: &B,
            offset: usize,
            dest: SocketAddr,
        ) -> std::io::Result<usize>
        where
            B: crate::transport::udp::UdpPayloadBatch + ?Sized,
        {
            let n = payloads.len().saturating_sub(offset).min(SEND_BATCH_SIZE);
            if n == 0 {
                return Ok(0);
            }

            if !UDP_GSO_DISABLED.load(std::sync::atomic::Ordering::Relaxed) {
                let gso_n = udp_gso_prefix_len(payloads, offset, n);
                if gso_n > 1 {
                    match self.send_gso_batch_to(payloads, offset, dest, gso_n) {
                        Ok(()) => {
                            crate::perf_profile::record_udp_send_gso_batch(gso_n);
                            return Ok(gso_n);
                        }
                        Err(error) if is_udp_gso_capability_error(&error) => {
                            UDP_GSO_DISABLED.store(true, std::sync::atomic::Ordering::Relaxed);
                            tracing::warn!(
                                error = %error,
                                "UDP_GSO refused by kernel; falling back to sendmmsg"
                            );
                        }
                        Err(error) => return Err(error),
                    }
                }
            }

            let fd = self.inner.as_raw_fd();
            let sa: socket2::SockAddr = dest.into();
            let sa_len = sa.len();
            debug_assert!(sa_len as usize <= std::mem::size_of::<libc::sockaddr_storage>());

            let mut storage: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
            unsafe {
                std::ptr::copy_nonoverlapping(
                    sa.as_ptr() as *const u8,
                    &mut storage as *mut _ as *mut u8,
                    sa_len as usize,
                );
            }

            let mut iovs: [[libc::iovec; crate::transport::udp::UDP_PAYLOAD_MAX_SLICES];
                SEND_BATCH_SIZE] = unsafe { std::mem::zeroed() };
            let mut msgs: [libc::mmsghdr; SEND_BATCH_SIZE] = unsafe { std::mem::zeroed() };

            for i in 0..n {
                let mut slices = [None; crate::transport::udp::UDP_PAYLOAD_MAX_SLICES];
                let payload_index = offset + i;
                let expected_len = payloads.payload_len(payload_index);
                let slice_count = payloads.payload_slices(payload_index, &mut slices);
                if slice_count == 0 || slice_count > crate::transport::udp::UDP_PAYLOAD_MAX_SLICES {
                    return Err(std::io::Error::other("invalid UDP payload slices"));
                }

                let mut slice_total = 0usize;
                for (slice_idx, data) in slices.iter().take(slice_count).flatten().enumerate() {
                    slice_total = slice_total.saturating_add(data.len());
                    iovs[i][slice_idx].iov_base = data.as_ptr() as *mut libc::c_void;
                    iovs[i][slice_idx].iov_len = data.len();
                }
                if slice_total != expected_len {
                    return Err(std::io::Error::other(
                        "UDP payload slices do not match payload length",
                    ));
                }
                msgs[i].msg_hdr.msg_name = &mut storage as *mut _ as *mut libc::c_void;
                msgs[i].msg_hdr.msg_namelen = sa_len;
                msgs[i].msg_hdr.msg_iov = iovs[i].as_mut_ptr();
                msgs[i].msg_hdr.msg_iovlen = slice_count as _;
            }

            let r = unsafe { libc::sendmmsg(fd, msgs.as_mut_ptr(), n as libc::c_uint, 0) };
            if r < 0 {
                return Err(std::io::Error::last_os_error());
            }
            let sent = r as usize;
            crate::perf_profile::record_udp_send_sendmmsg_batch(sent);
            Ok(sent)
        }

        /// Send same-destination payloads through Darwin's UDP batch syscall.
        #[cfg(target_os = "macos")]
        pub fn send_batch_to<B>(
            &self,
            payloads: &B,
            offset: usize,
            dest: SocketAddr,
        ) -> std::io::Result<usize>
        where
            B: crate::transport::udp::UdpPayloadBatch + ?Sized,
        {
            let n = payloads.len().saturating_sub(offset).min(SEND_BATCH_SIZE);
            if n == 0 {
                return Ok(0);
            }

            let fd = self.inner.as_raw_fd();
            let sa: socket2::SockAddr = dest.into();
            let sa_len = sa.len();

            let mut iovs: [[libc::iovec; crate::transport::udp::UDP_PAYLOAD_MAX_SLICES];
                SEND_BATCH_SIZE] = unsafe { std::mem::zeroed() };
            let mut msgs: [msghdr_x; SEND_BATCH_SIZE] = unsafe { std::mem::zeroed() };

            for i in 0..n {
                let mut slices = [None; crate::transport::udp::UDP_PAYLOAD_MAX_SLICES];
                let payload_index = offset + i;
                let expected_len = payloads.payload_len(payload_index);
                let slice_count = payloads.payload_slices(payload_index, &mut slices);
                if slice_count == 0 || slice_count > crate::transport::udp::UDP_PAYLOAD_MAX_SLICES {
                    return Err(std::io::Error::other("invalid UDP payload slices"));
                }

                let mut slice_total = 0usize;
                for (slice_idx, data) in slices.iter().take(slice_count).flatten().enumerate() {
                    slice_total = slice_total.saturating_add(data.len());
                    iovs[i][slice_idx].iov_base = data.as_ptr() as *mut libc::c_void;
                    iovs[i][slice_idx].iov_len = data.len();
                }
                if slice_total != expected_len {
                    return Err(std::io::Error::other(
                        "UDP payload slices do not match payload length",
                    ));
                }

                msgs[i].msg_name = sa.as_ptr() as *mut libc::c_void;
                msgs[i].msg_namelen = sa_len;
                msgs[i].msg_iov = iovs[i].as_mut_ptr();
                msgs[i].msg_iovlen = slice_count as libc::c_int;
                msgs[i].msg_control = std::ptr::null_mut();
                msgs[i].msg_controllen = 0;
                msgs[i].msg_flags = 0;
                msgs[i].msg_datalen = expected_len;
            }

            loop {
                let sent = unsafe { sendmsg_x(fd, msgs.as_ptr(), n as libc::c_uint, 0) };
                if sent >= 0 {
                    let sent = sent as usize;
                    if sent > n {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            "sendmsg_x reported more sent messages than requested",
                        ));
                    }
                    crate::perf_profile::record_udp_send_sendmsgx_batch(sent);
                    return Ok(sent);
                }

                let error = std::io::Error::last_os_error();
                if error.kind() != std::io::ErrorKind::Interrupted {
                    return Err(error);
                }
            }
        }

        #[cfg(target_os = "linux")]
        fn send_gso_batch_to<B>(
            &self,
            payloads: &B,
            offset: usize,
            dest: SocketAddr,
            count: usize,
        ) -> std::io::Result<()>
        where
            B: crate::transport::udp::UdpPayloadBatch + ?Sized,
        {
            debug_assert!(count > 1);
            let n = count.min(UDP_GSO_MAX_SEGMENTS);
            let segment_size = payloads.payload_len(offset);
            debug_assert!(segment_size > 0);
            debug_assert!(segment_size <= u16::MAX as usize);

            let fd = self.inner.as_raw_fd();
            let sa: socket2::SockAddr = dest.into();
            let sa_len = sa.len();
            let mut storage: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
            unsafe {
                std::ptr::copy_nonoverlapping(
                    sa.as_ptr() as *const u8,
                    &mut storage as *mut _ as *mut u8,
                    sa_len as usize,
                );
            }

            let mut iovs: [libc::iovec; UDP_GSO_MAX_IOV] = unsafe { std::mem::zeroed() };
            let mut iov_count = 0usize;
            for i in 0..n {
                let payload_index = offset + i;
                let payload_len = payloads.payload_len(payload_index);
                if payload_len == 0 || payload_len > segment_size {
                    return Err(std::io::Error::other(
                        "UDP GSO payload length changed after prefix selection",
                    ));
                }
                let mut slices = [None; crate::transport::udp::UDP_PAYLOAD_MAX_SLICES];
                let slice_count = payloads.payload_slices(payload_index, &mut slices);
                if slice_count == 0
                    || slice_count > crate::transport::udp::UDP_PAYLOAD_MAX_SLICES
                    || iov_count.saturating_add(slice_count) > iovs.len()
                {
                    return Err(std::io::Error::other("invalid UDP GSO payload slices"));
                }

                let mut slice_total = 0usize;
                for data in slices.iter().take(slice_count).flatten() {
                    slice_total = slice_total.saturating_add(data.len());
                    iovs[iov_count].iov_base = data.as_ptr() as *mut libc::c_void;
                    iovs[iov_count].iov_len = data.len();
                    iov_count += 1;
                }
                if slice_total != payload_len {
                    return Err(std::io::Error::other(
                        "UDP GSO payload slices do not match payload length",
                    ));
                }
            }

            let cmsg_space =
                unsafe { libc::CMSG_SPACE(std::mem::size_of::<u16>() as u32) as usize };
            let mut cmsg_buf = [0u8; 64];
            debug_assert!(cmsg_space <= cmsg_buf.len());

            let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
            msg.msg_name = &mut storage as *mut _ as *mut libc::c_void;
            msg.msg_namelen = sa_len;
            msg.msg_iov = iovs.as_mut_ptr();
            msg.msg_iovlen = iov_count as _;
            msg.msg_control = cmsg_buf.as_mut_ptr() as *mut libc::c_void;
            msg.msg_controllen = cmsg_space as _;

            unsafe {
                let cmsg = libc::CMSG_FIRSTHDR(&msg);
                if cmsg.is_null() {
                    return Err(std::io::Error::other("CMSG_FIRSTHDR returned null"));
                }
                (*cmsg).cmsg_level = libc::IPPROTO_UDP as _;
                (*cmsg).cmsg_type = libc::UDP_SEGMENT as _;
                (*cmsg).cmsg_len = libc::CMSG_LEN(std::mem::size_of::<u16>() as u32) as _;
                let data = libc::CMSG_DATA(cmsg) as *mut u16;
                *data = segment_size as u16;
            }

            let result = unsafe { libc::sendmsg(fd, &msg, 0) };
            if result < 0 {
                Err(std::io::Error::last_os_error())
            } else {
                Ok(())
            }
        }

        /// Wrap this socket in a tokio `AsyncFd` for async I/O.
        pub fn into_async(self) -> Result<AsyncUdpSocket, TransportError> {
            let async_fd = AsyncFd::new(self)
                .map_err(|e| TransportError::StartFailed(format!("AsyncFd::new failed: {}", e)))?;
            Ok(AsyncUdpSocket {
                inner: Arc::new(async_fd),
            })
        }
    }

    #[cfg(target_os = "linux")]
    pub(super) fn udp_gso_prefix_len<B>(payloads: &B, offset: usize, candidate: usize) -> usize
    where
        B: crate::transport::udp::UdpPayloadBatch + ?Sized,
    {
        let max = payloads
            .len()
            .saturating_sub(offset)
            .min(candidate)
            .min(SEND_BATCH_SIZE)
            .min(UDP_GSO_MAX_SEGMENTS);
        if max < 2 {
            return 0;
        }

        let segment_size = payloads.payload_len(offset);
        if segment_size == 0 || segment_size > u16::MAX as usize {
            return 0;
        }
        let mut total_payload = 0usize;
        let mut count = 0usize;

        for i in 0..max {
            let len = payloads.payload_len(offset + i);
            if len == 0 || len > segment_size {
                break;
            }
            if count > 0 && total_payload.saturating_add(len) > UDP_GSO_MAX_PAYLOAD {
                break;
            }
            total_payload = total_payload.saturating_add(len);
            count += 1;
            if len < segment_size {
                break;
            }
        }

        if count > 1 { count } else { 0 }
    }

    #[cfg(target_os = "linux")]
    fn is_udp_gso_capability_error(error: &std::io::Error) -> bool {
        error.kind() == std::io::ErrorKind::InvalidInput
            || matches!(error.raw_os_error(), Some(code)
                if code == libc::EOPNOTSUPP || code == libc::ENOPROTOOPT || code == libc::EIO)
    }

    impl AsRawFd for UdpRawSocket {
        fn as_raw_fd(&self) -> RawFd {
            self.inner.as_raw_fd()
        }
    }

    /// Async wrapper around `UdpRawSocket` using tokio's `AsyncFd`.
    ///
    /// `Arc`-shareable between send and receive tasks. `AsyncFd<T>` is
    /// `Sync` when `T: Send`, which `socket2::Socket` satisfies.
    #[derive(Clone)]
    pub struct AsyncUdpSocket {
        inner: Arc<AsyncFd<UdpRawSocket>>,
    }

    impl AsRawFd for AsyncUdpSocket {
        fn as_raw_fd(&self) -> RawFd {
            self.inner.get_ref().as_raw_fd()
        }
    }

    impl AsyncUdpSocket {
        /// Whether Linux UDP_GRO receive offload was accepted by the kernel.
        #[cfg(target_os = "linux")]
        pub(crate) fn udp_gro_enabled(&self) -> bool {
            self.inner.get_ref().udp_gro_enabled
        }

        /// Send a payload to a destination address.
        ///
        /// Used by `UdpTransport::send_async` for the low-rate control
        /// plane (handshakes, MMP reports, rekeys). The high-throughput
        /// dataplane data path goes through `send_batch`.
        pub async fn send_to(
            &self,
            data: &[u8],
            dest: &SocketAddr,
        ) -> Result<usize, TransportError> {
            loop {
                let mut guard = self
                    .inner
                    .writable()
                    .await
                    .map_err(|e| TransportError::SendFailed(format!("writable wait: {}", e)))?;

                match guard.try_io(|inner| inner.get_ref().send_to(data, dest)) {
                    Ok(Ok(n)) => return Ok(n),
                    Ok(Err(e)) => return Err(TransportError::SendFailed(format!("{}", e))),
                    Err(_would_block) => continue,
                }
            }
        }

        /// Receive a payload, source address, kernel drop counter, and
        /// Linux UDP_GRO segment size.
        ///
        /// Returns `(bytes_read, source_addr, kernel_drops, gro_segment_size)`.
        /// On Linux the production receive path uses `recv_batch`; this
        /// single-packet variant remains for non-Linux unix targets and for
        /// the local `tests` module.
        #[cfg_attr(target_os = "linux", allow(dead_code))]
        pub async fn recv_from(
            &self,
            buf: &mut [u8],
        ) -> Result<(usize, SocketAddr, u32, usize), TransportError> {
            loop {
                let mut guard = self
                    .inner
                    .readable()
                    .await
                    .map_err(|e| TransportError::RecvFailed(format!("readable wait: {}", e)))?;

                match guard.try_io(|inner| inner.get_ref().recv_from(buf)) {
                    Ok(Ok(result)) => return Ok(result),
                    Ok(Err(e)) => return Err(TransportError::RecvFailed(format!("{}", e))),
                    Err(_would_block) => continue,
                }
            }
        }

        /// Drain up to `RECV_BATCH_SIZE` datagrams from the kernel via
        /// `recvmmsg` (Linux). Returns `(count, kernel_drops)`; same
        /// buffer / addr / GRO segment-size contract as
        /// `UdpRawSocket::recv_batch`.
        #[cfg(target_os = "linux")]
        pub async fn recv_batch(
            &self,
            bufs: &mut [Vec<u8>],
            addrs: &mut [Option<SocketAddr>],
            gro_segment_sizes: &mut [usize],
        ) -> Result<(usize, u32), TransportError> {
            loop {
                let mut guard = self
                    .inner
                    .readable()
                    .await
                    .map_err(|e| TransportError::RecvFailed(format!("readable wait: {}", e)))?;

                match guard
                    .try_io(|inner| inner.get_ref().recv_batch(bufs, addrs, gro_segment_sizes))
                {
                    Ok(Ok((0, _))) => {
                        // Spurious wakeup or no datagrams ready — yield
                        // back to the reactor instead of busy-looping.
                        guard.clear_ready();
                        continue;
                    }
                    Ok(Ok(result)) => return Ok(result),
                    Ok(Err(e)) => return Err(TransportError::RecvFailed(format!("{}", e))),
                    Err(_would_block) => continue,
                }
            }
        }

        /// Push same-destination datagrams to the kernel in batches without
        /// building a per-packet address tuple batch first.
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        pub async fn send_batch_to<B>(
            &self,
            payloads: &B,
            offset: usize,
            dest: SocketAddr,
        ) -> Result<usize, TransportError>
        where
            B: crate::transport::udp::UdpPayloadBatch + ?Sized,
        {
            loop {
                let mut guard = self
                    .inner
                    .writable()
                    .await
                    .map_err(|e| TransportError::SendFailed(format!("writable wait: {}", e)))?;

                match guard.try_io(|inner| inner.get_ref().send_batch_to(payloads, offset, dest)) {
                    Ok(Ok(n)) => return Ok(n),
                    Ok(Err(e)) => return Err(TransportError::SendFailed(format!("{}", e))),
                    Err(_would_block) => continue,
                }
            }
        }
    }

    /// Convert a `libc::sockaddr_storage` to `std::net::SocketAddr`.
    fn sockaddr_to_socket_addr(storage: &libc::sockaddr_storage) -> std::io::Result<SocketAddr> {
        match storage.ss_family as libc::c_int {
            libc::AF_INET => {
                let addr: &libc::sockaddr_in =
                    unsafe { &*(storage as *const _ as *const libc::sockaddr_in) };
                let ip = std::net::Ipv4Addr::from(u32::from_be(addr.sin_addr.s_addr));
                let port = u16::from_be(addr.sin_port);
                Ok(SocketAddr::from((ip, port)))
            }
            libc::AF_INET6 => {
                let addr: &libc::sockaddr_in6 =
                    unsafe { &*(storage as *const _ as *const libc::sockaddr_in6) };
                let ip = std::net::Ipv6Addr::from(addr.sin6_addr.s6_addr);
                let port = u16::from_be(addr.sin6_port);
                Ok(SocketAddr::from((ip, port)))
            }
            family => Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("unsupported address family: {}", family),
            )),
        }
    }
}

// ============================================================================
// Windows implementation
// ============================================================================

#[cfg(windows)]
mod platform {
    use super::*;

    /// UDP socket wrapper (Windows).
    ///
    /// Uses `socket2::Socket` for configuration and `tokio::net::UdpSocket`
    /// for async I/O. Kernel drop counting is not available on Windows;
    /// the drops field always returns 0.
    pub struct UdpRawSocket {
        inner: Socket,
        local_addr: SocketAddr,
    }

    impl UdpRawSocket {
        /// Create, bind, and configure a UDP socket.
        ///
        /// Sets non-blocking mode and configures buffer sizes. The socket
        /// is bound immediately so `local_addr()` returns the actual
        /// assigned address (important when binding to port 0).
        pub fn open(
            bind_addr: SocketAddr,
            recv_buf_size: usize,
            send_buf_size: usize,
        ) -> Result<Self, TransportError> {
            let domain = if bind_addr.is_ipv4() {
                Domain::IPV4
            } else {
                Domain::IPV6
            };
            let sock = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))
                .map_err(|e| TransportError::StartFailed(format!("socket create failed: {}", e)))?;

            sock.set_nonblocking(true).map_err(|e| {
                TransportError::StartFailed(format!("set nonblocking failed: {}", e))
            })?;

            // Windows: `socket2::Socket::set_reuse_port` doesn't exist.
            // SO_REUSEADDR is available and harmless to set.
            let _ = sock.set_reuse_address(true);

            sock.bind(&bind_addr.into())
                .map_err(|e| TransportError::StartFailed(format!("bind failed: {}", e)))?;

            // Set socket buffer sizes
            sock.set_recv_buffer_size(recv_buf_size)
                .map_err(|e| TransportError::StartFailed(format!("set recv buffer: {}", e)))?;
            sock.set_send_buffer_size(send_buf_size)
                .map_err(|e| TransportError::StartFailed(format!("set send buffer: {}", e)))?;

            let local_addr = sock
                .local_addr()
                .map_err(|e| TransportError::StartFailed(format!("get local addr: {}", e)))?
                .as_socket()
                .ok_or_else(|| {
                    TransportError::StartFailed("local address is not an IP socket".into())
                })?;

            Ok(Self {
                inner: sock,
                local_addr,
            })
        }

        /// Adopt an existing bound UDP socket.
        pub fn adopt(
            socket: std::net::UdpSocket,
            recv_buf_size: usize,
            send_buf_size: usize,
        ) -> Result<Self, TransportError> {
            let sock = Socket::from(socket);

            sock.set_nonblocking(true).map_err(|e| {
                TransportError::StartFailed(format!("set nonblocking failed: {}", e))
            })?;

            sock.set_recv_buffer_size(recv_buf_size)
                .map_err(|e| TransportError::StartFailed(format!("set recv buffer: {}", e)))?;
            sock.set_send_buffer_size(send_buf_size)
                .map_err(|e| TransportError::StartFailed(format!("set send buffer: {}", e)))?;

            let local_addr = sock
                .local_addr()
                .map_err(|e| TransportError::StartFailed(format!("get local addr: {}", e)))?
                .as_socket()
                .ok_or_else(|| {
                    TransportError::StartFailed("local address is not an IP socket".into())
                })?;

            Ok(Self {
                inner: sock,
                local_addr,
            })
        }

        /// Get the local bound address.
        pub fn local_addr(&self) -> SocketAddr {
            self.local_addr
        }

        /// Get the actual receive buffer size.
        pub fn recv_buffer_size(&self) -> Result<usize, TransportError> {
            self.inner
                .recv_buffer_size()
                .map_err(|e| TransportError::StartFailed(format!("get recv buffer: {}", e)))
        }

        /// Get the actual send buffer size.
        pub fn send_buffer_size(&self) -> Result<usize, TransportError> {
            self.inner
                .send_buffer_size()
                .map_err(|e| TransportError::StartFailed(format!("get send buffer: {}", e)))
        }

        /// Wrap this socket in an async wrapper for tokio I/O.
        pub fn into_async(self) -> Result<AsyncUdpSocket, TransportError> {
            let std_socket: std::net::UdpSocket = self.inner.into();
            let tokio_socket = tokio::net::UdpSocket::from_std(std_socket)
                .map_err(|e| TransportError::StartFailed(format!("tokio socket failed: {}", e)))?;

            Ok(AsyncUdpSocket {
                inner: Arc::new(tokio_socket),
            })
        }
    }

    /// Async UDP socket wrapper (Windows).
    ///
    /// Uses `tokio::net::UdpSocket` directly. Kernel drop counting
    /// is not available; the drops field always returns 0.
    #[derive(Clone)]
    pub struct AsyncUdpSocket {
        inner: Arc<tokio::net::UdpSocket>,
    }

    impl AsyncUdpSocket {
        /// Send a payload to a destination address.
        pub async fn send_to(
            &self,
            data: &[u8],
            dest: &SocketAddr,
        ) -> Result<usize, TransportError> {
            self.inner
                .send_to(data, dest)
                .await
                .map_err(|e| TransportError::SendFailed(format!("{}", e)))
        }

        /// Receive a payload, source address, kernel drop counter, and
        /// Linux UDP_GRO segment size.
        ///
        /// Returns `(bytes_read, source_addr, 0, 0)`. The drops and GRO fields
        /// are always 0 on Windows since kernel receive ancillary metadata is
        /// not available here.
        pub async fn recv_from(
            &self,
            buf: &mut [u8],
        ) -> Result<(usize, SocketAddr, u32, usize), TransportError> {
            let (n, addr) = self
                .inner
                .recv_from(buf)
                .await
                .map_err(|e| TransportError::RecvFailed(format!("{}", e)))?;
            Ok((n, addr, 0, 0))
        }
    }
}

pub use platform::{AsyncUdpSocket, UdpRawSocket};

#[cfg(test)]
mod tests;
