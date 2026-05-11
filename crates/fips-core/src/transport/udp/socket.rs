//! UDP socket wrapper with platform-specific receive implementations.
//!
//! On Linux, provides `SO_RXQ_OVFL` kernel drop counter support via
//! `recvmsg()` ancillary data parsing. The async wrapper uses
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

// ============================================================================
// Unix implementation
// ============================================================================

#[cfg(unix)]
mod platform {
    use super::*;
    use std::os::unix::io::{AsRawFd, RawFd};
    use tokio::io::unix::AsyncFd;

    /// Maximum number of datagrams a single `recvmmsg` syscall pulls
    /// from the kernel queue. Tuned to amortise syscall + per-task-wakeup
    /// overhead across a useful burst without blowing the stack (each
    /// slot owns an mmsghdr + sockaddr_storage + iovec) and without
    /// inflating tail latency on a quiet line.
    #[cfg(target_os = "linux")]
    const RECV_BATCH_SIZE: usize = 32;

    /// Maximum number of datagrams a single `sendmmsg` syscall pushes to
    /// the kernel. Larger than `RECV_BATCH_SIZE` because the rx_loop can
    /// drain up to 256 outbound commands per scheduler tick and we want
    /// the trailing-burst flush at the end of that drain to land in one
    /// syscall instead of `ceil(N/32)` of them. The kernel sendmmsg
    /// hard cap is 1024; 256 fits the stack budget (each slot is
    /// `mmsghdr + sockaddr_storage + iovec` ≈ 200 bytes ≈ 50 KiB total).
    ///
    /// The per-packet `sendmmsg` amortised cost was ~2.1 µs at
    /// SEND_BATCH=32 in FIPS_PERF profiles (≈37% of one core at
    /// 164 kpps); growing the batch should drop that toward the
    /// per-call kernel fixed cost / N.
    #[cfg(target_os = "linux")]
    const SEND_BATCH_SIZE: usize = 256;

    /// Back-compat alias used by call sites that don't distinguish.
    /// `recv_batch` uses `RECV_BATCH_SIZE`; `send_batch` uses
    /// `SEND_BATCH_SIZE`.
    #[cfg(target_os = "linux")]
    const BATCH_SIZE: usize = RECV_BATCH_SIZE;

    /// Wrapper around a `socket2::Socket` providing sync send/recv with
    /// `SO_RXQ_OVFL` ancillary data parsing.
    pub struct UdpRawSocket {
        inner: Socket,
        local_addr: SocketAddr,
    }

    impl UdpRawSocket {
        /// Create, bind, and configure a UDP socket.
        ///
        /// Enables `SO_RXQ_OVFL` for kernel drop counting (non-fatal if
        /// unsupported). Sets non-blocking mode for async integration.
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

            // SO_REUSEPORT lets the Linux UDP demux load-balance
            // across sockets bound to the same address — and lets
            // per-peer `ConnectedPeerSocket`s bind to the same
            // wildcard port the listen socket holds (most-specific
            // 5-tuple match preferentially routes a connected peer's
            // traffic to its dedicated socket; the listen socket then
            // only handles new / unknown peers). On non-Linux this
            // setsockopt has no effect for UDP, so we ignore failures.
            let _ = sock.set_reuse_port(true);
            let _ = sock.set_reuse_address(true);

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
                if ret == 0 {
                    if let Ok(after) = sock.recv_buffer_size() {
                        actual_recv = after;
                    }
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
                if ret == 0 {
                    if let Ok(after) = sock.send_buffer_size() {
                        actual_send = after;
                    }
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

            // Enable SO_RXQ_OVFL for kernel drop counter in recvmsg ancillary data.
            // Non-fatal: older kernels or non-Linux platforms may not support it.
            #[cfg(target_os = "linux")]
            {
                let enable: libc::c_int = 1;
                let ret = unsafe {
                    libc::setsockopt(
                        sock.as_raw_fd(),
                        libc::SOL_SOCKET,
                        libc::SO_RXQ_OVFL,
                        &enable as *const _ as *const libc::c_void,
                        std::mem::size_of::<libc::c_int>() as libc::socklen_t,
                    )
                };
                if ret < 0 {
                    warn!(
                        "setsockopt(SO_RXQ_OVFL) failed: {}",
                        std::io::Error::last_os_error()
                    );
                }
            }

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
        ///
        /// This preserves socket identity/NAT mapping created by bootstrap code.
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
                if ret == 0 {
                    if let Ok(after) = sock.recv_buffer_size() {
                        actual_recv = after;
                    }
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
                if ret == 0 {
                    if let Ok(after) = sock.send_buffer_size() {
                        actual_send = after;
                    }
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
            {
                let enable: libc::c_int = 1;
                let ret = unsafe {
                    libc::setsockopt(
                        sock.as_raw_fd(),
                        libc::SOL_SOCKET,
                        libc::SO_RXQ_OVFL,
                        &enable as *const _ as *const libc::c_void,
                        std::mem::size_of::<libc::c_int>() as libc::socklen_t,
                    )
                };
                if ret < 0 {
                    warn!(
                        "setsockopt(SO_RXQ_OVFL) failed: {}",
                        std::io::Error::last_os_error()
                    );
                }
            }

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
        /// Returns `(bytes_read, source_addr, kernel_drops)`. The `kernel_drops`
        /// value is a cumulative counter since socket creation; it is 0 if
        /// `SO_RXQ_OVFL` is not supported.
        ///
        /// On Linux the production receive path uses `recv_batch` (recvmmsg);
        /// this single-packet variant remains for non-Linux unix targets and
        /// for the local `tests` module.
        #[cfg_attr(target_os = "linux", allow(dead_code))]
        pub fn recv_from(&self, buf: &mut [u8]) -> std::io::Result<(usize, SocketAddr, u32)> {
            let fd = self.inner.as_raw_fd();

            let mut iov = libc::iovec {
                iov_base: buf.as_mut_ptr() as *mut libc::c_void,
                iov_len: buf.len(),
            };

            // Control message buffer sized for SO_RXQ_OVFL (u32).
            // CMSG_SPACE computes the aligned size including header.
            #[cfg(target_os = "linux")]
            const CMSG_BUF_SIZE: usize = unsafe { libc::CMSG_SPACE(4) } as usize;
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

            // Walk cmsg chain for SO_RXQ_OVFL drop counter
            #[cfg(target_os = "linux")]
            let mut drops: u32 = 0;
            #[cfg(not(target_os = "linux"))]
            let drops: u32 = 0;
            #[cfg(target_os = "linux")]
            unsafe {
                let mut cmsg = libc::CMSG_FIRSTHDR(&msg);
                while !cmsg.is_null() {
                    if (*cmsg).cmsg_level == libc::SOL_SOCKET
                        && (*cmsg).cmsg_type == libc::SO_RXQ_OVFL
                    {
                        let data = libc::CMSG_DATA(cmsg);
                        drops = std::ptr::read_unaligned(data as *const u32);
                    }
                    cmsg = libc::CMSG_NXTHDR(&msg, cmsg);
                }
            }

            Ok((n as usize, addr, drops))
        }

        /// Receive up to `BATCH_SIZE` datagrams in a single recvmmsg syscall
        /// (Linux only — macOS falls through to per-packet recvmsg).
        ///
        /// Returns `(count, kernel_drops)`. Caller pre-sizes `bufs` (each
        /// must be at least the configured MTU) and the matching `addrs` /
        /// `lens` slices; on return, slots `[0..count)` are valid.
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
            bufs: &mut [&mut [u8]],
            addrs: &mut [Option<SocketAddr>],
            lens: &mut [usize],
        ) -> std::io::Result<(usize, u32)> {
            let n = bufs.len().min(addrs.len()).min(lens.len()).min(BATCH_SIZE);
            if n == 0 {
                return Ok((0, 0));
            }
            let fd = self.inner.as_raw_fd();

            // CMSG buffer wired to msgs[0] only. SO_RXQ_OVFL delivers a
            // monotonic u32 drop counter; sampling once per batch gives
            // the 1Hz congestion detector ample fresh values under load
            // (one batch = up to 32 datagrams).
            const CMSG_BUF_SIZE: usize = unsafe { libc::CMSG_SPACE(4) } as usize;
            let mut cmsg_buf = [0u8; CMSG_BUF_SIZE];

            // Stack-allocated parallel arrays; lifetime tied to this call.
            let mut iovs: [libc::iovec; BATCH_SIZE] = unsafe { std::mem::zeroed() };
            let mut storages: [libc::sockaddr_storage; BATCH_SIZE] = unsafe { std::mem::zeroed() };
            let mut msgs: [libc::mmsghdr; BATCH_SIZE] = unsafe { std::mem::zeroed() };

            for i in 0..n {
                iovs[i].iov_base = bufs[i].as_mut_ptr() as *mut libc::c_void;
                iovs[i].iov_len = bufs[i].len();
                msgs[i].msg_hdr.msg_name = &mut storages[i] as *mut _ as *mut libc::c_void;
                msgs[i].msg_hdr.msg_namelen =
                    std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
                msgs[i].msg_hdr.msg_iov = &mut iovs[i];
                msgs[i].msg_hdr.msg_iovlen = 1;
                msgs[i].msg_len = 0;
            }
            // Only msgs[0] carries a cmsg buffer — sampling the OVFL counter
            // there is enough since it is socket-wide and monotonic.
            msgs[0].msg_hdr.msg_control = cmsg_buf.as_mut_ptr() as *mut libc::c_void;
            msgs[0].msg_hdr.msg_controllen = cmsg_buf.len() as _;

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
                lens[i] = msgs[i].msg_len as usize;
                addrs[i] = sockaddr_to_socket_addr(&storages[i]).ok();
            }

            // Walk msgs[0] cmsg chain for SO_RXQ_OVFL. Skip when no
            // datagram landed (cmsg buffer is undefined in that case).
            let mut drops: u32 = 0;
            if count > 0 {
                unsafe {
                    let mut cmsg = libc::CMSG_FIRSTHDR(&msgs[0].msg_hdr);
                    while !cmsg.is_null() {
                        if (*cmsg).cmsg_level == libc::SOL_SOCKET
                            && (*cmsg).cmsg_type == libc::SO_RXQ_OVFL
                        {
                            let data = libc::CMSG_DATA(cmsg);
                            drops = std::ptr::read_unaligned(data as *const u32);
                        }
                        cmsg = libc::CMSG_NXTHDR(&msgs[0].msg_hdr, cmsg);
                    }
                }
            }

            Ok((count, drops))
        }

        /// Send up to `SEND_BATCH_SIZE` datagrams in a single sendmmsg
        /// syscall (Linux only). Returns the count actually sent. Caller
        /// is responsible for retrying remaining packets if
        /// `n < packets.len()`.
        #[cfg(target_os = "linux")]
        pub fn send_batch(&self, packets: &[(&[u8], SocketAddr)]) -> std::io::Result<usize> {
            let n = packets.len().min(SEND_BATCH_SIZE);
            if n == 0 {
                return Ok(0);
            }
            let fd = self.inner.as_raw_fd();

            let mut iovs: [libc::iovec; SEND_BATCH_SIZE] = unsafe { std::mem::zeroed() };
            let mut storages: [libc::sockaddr_storage; SEND_BATCH_SIZE] =
                unsafe { std::mem::zeroed() };
            let mut storage_lens: [libc::socklen_t; SEND_BATCH_SIZE] = [0; SEND_BATCH_SIZE];
            let mut msgs: [libc::mmsghdr; SEND_BATCH_SIZE] = unsafe { std::mem::zeroed() };

            for i in 0..n {
                let (data, dest) = packets[i];
                let sa: socket2::SockAddr = (dest).into();
                let sa_len = sa.len();
                debug_assert!(sa_len as usize <= std::mem::size_of::<libc::sockaddr_storage>());
                unsafe {
                    std::ptr::copy_nonoverlapping(
                        sa.as_ptr() as *const u8,
                        &mut storages[i] as *mut _ as *mut u8,
                        sa_len as usize,
                    );
                }
                storage_lens[i] = sa_len;

                iovs[i].iov_base = data.as_ptr() as *mut libc::c_void;
                iovs[i].iov_len = data.len();
                msgs[i].msg_hdr.msg_name = &mut storages[i] as *mut _ as *mut libc::c_void;
                msgs[i].msg_hdr.msg_namelen = storage_lens[i];
                msgs[i].msg_hdr.msg_iov = &mut iovs[i];
                msgs[i].msg_hdr.msg_iovlen = 1;
            }

            let r = unsafe { libc::sendmmsg(fd, msgs.as_mut_ptr(), n as libc::c_uint, 0) };
            if r < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(r as usize)
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
        /// Send a payload to a destination address.
        ///
        /// On Linux the production send path uses `send_batch`; this
        /// single-packet variant remains for non-Linux unix targets and
        /// for the local `tests` module.
        #[cfg_attr(target_os = "linux", allow(dead_code))]
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

        /// Receive a payload, source address, and kernel drop counter.
        ///
        /// Returns `(bytes_read, source_addr, kernel_drops)`. On Linux the
        /// production receive path uses `recv_batch`; this single-packet
        /// variant remains for non-Linux unix targets and for the local
        /// `tests` module.
        #[cfg_attr(target_os = "linux", allow(dead_code))]
        pub async fn recv_from(
            &self,
            buf: &mut [u8],
        ) -> Result<(usize, SocketAddr, u32), TransportError> {
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

        /// Drain up to `BATCH_SIZE` datagrams from the kernel via
        /// `recvmmsg` (Linux). Returns `(count, kernel_drops)`; same
        /// buffer / addr / len contract as `UdpRawSocket::recv_batch`.
        #[cfg(target_os = "linux")]
        pub async fn recv_batch(
            &self,
            bufs: &mut [&mut [u8]],
            addrs: &mut [Option<SocketAddr>],
            lens: &mut [usize],
        ) -> Result<(usize, u32), TransportError> {
            loop {
                let mut guard = self
                    .inner
                    .readable()
                    .await
                    .map_err(|e| TransportError::RecvFailed(format!("readable wait: {}", e)))?;

                match guard.try_io(|inner| inner.get_ref().recv_batch(bufs, addrs, lens)) {
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

        /// Push up to `BATCH_SIZE` datagrams to the kernel via `sendmmsg`
        /// (Linux). Returns the count actually sent. Caller is responsible
        /// for retrying remaining packets if `n < packets.len()`.
        #[cfg(target_os = "linux")]
        pub async fn send_batch(
            &self,
            packets: &[(&[u8], SocketAddr)],
        ) -> Result<usize, TransportError> {
            loop {
                let mut guard = self
                    .inner
                    .writable()
                    .await
                    .map_err(|e| TransportError::SendFailed(format!("writable wait: {}", e)))?;

                match guard.try_io(|inner| inner.get_ref().send_batch(packets)) {
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

            // SO_REUSEPORT / SO_REUSEADDR — see the sync `UdpRawSocket::open`
            // path above for rationale (per-peer ConnectedPeerSocket
            // must bind to the same port the listen socket holds).
            let _ = sock.set_reuse_port(true);
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

        /// Receive a payload, source address, and kernel drop counter.
        ///
        /// Returns `(bytes_read, source_addr, 0)`. The drops field is always 0
        /// on Windows since kernel drop counting is not available.
        pub async fn recv_from(
            &self,
            buf: &mut [u8],
        ) -> Result<(usize, SocketAddr, u32), TransportError> {
            let (n, addr) = self
                .inner
                .recv_from(buf)
                .await
                .map_err(|e| TransportError::RecvFailed(format!("{}", e)))?;
            Ok((n, addr, 0))
        }
    }
}

pub use platform::{AsyncUdpSocket, UdpRawSocket};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_udp_socket_bind() {
        // Bind to an ephemeral port
        let sock = UdpRawSocket::open("127.0.0.1:0".parse().unwrap(), 65536, 65536)
            .expect("failed to bind UDP socket");

        let addr = sock.local_addr();
        assert!(addr.port() > 0, "should be assigned an ephemeral port");
        assert!(addr.ip().is_loopback());
    }

    #[test]
    fn test_udp_socket_buffer_sizes() {
        let sock = UdpRawSocket::open("127.0.0.1:0".parse().unwrap(), 65536, 65536)
            .expect("failed to bind UDP socket");

        let recv_buf = sock.recv_buffer_size().expect("get recv buffer");
        let send_buf = sock.send_buffer_size().expect("get send buffer");
        assert!(recv_buf > 0, "recv buffer should be non-zero");
        assert!(send_buf > 0, "send buffer should be non-zero");
    }

    #[tokio::test]
    async fn test_async_udp_socket_send_recv() {
        let sock1 = UdpRawSocket::open("127.0.0.1:0".parse().unwrap(), 65536, 65536)
            .expect("failed to bind socket 1");
        let addr1 = sock1.local_addr();
        let async1 = sock1.into_async().expect("into_async 1");

        let sock2 = UdpRawSocket::open("127.0.0.1:0".parse().unwrap(), 65536, 65536)
            .expect("failed to bind socket 2");
        let addr2 = sock2.local_addr();
        let async2 = sock2.into_async().expect("into_async 2");

        // Send from socket 1 to socket 2
        let payload = b"hello fips";
        let sent = async1.send_to(payload, &addr2).await.expect("send_to");
        assert_eq!(sent, payload.len());

        // Receive on socket 2
        let mut buf = [0u8; 1024];
        let (n, src, _drops) = async2.recv_from(&mut buf).await.expect("recv_from");
        assert_eq!(n, payload.len());
        assert_eq!(&buf[..n], payload);
        assert_eq!(src, addr1);
    }
}
