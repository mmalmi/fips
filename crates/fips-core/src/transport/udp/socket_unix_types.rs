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
        fn recvmsg_x(
            s: libc::c_int,
            msgp: *mut msghdr_x,
            cnt: libc::c_uint,
            flags: libc::c_int,
        ) -> isize;

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

    fn configure_socket_buffer_sizes(
        sock: &Socket,
        recv_buf_size: usize,
        send_buf_size: usize,
    ) -> Result<(), TransportError> {
        sock.set_recv_buffer_size(recv_buf_size)
            .map_err(|e| TransportError::StartFailed(format!("set recv buffer: {}", e)))?;
        sock.set_send_buffer_size(send_buf_size)
            .map_err(|e| TransportError::StartFailed(format!("set send buffer: {}", e)))?;

        let actual_recv = sock
            .recv_buffer_size()
            .map_err(|e| TransportError::StartFailed(format!("get recv buffer: {}", e)))?;
        let actual_send = sock
            .send_buffer_size()
            .map_err(|e| TransportError::StartFailed(format!("get send buffer: {}", e)))?;

        #[cfg(target_os = "linux")]
        let (actual_recv, actual_send) = force_linux_socket_buffer_sizes(
            sock,
            recv_buf_size,
            send_buf_size,
            actual_recv,
            actual_send,
        );

        warn_if_socket_buffer_clamped("recv", recv_buf_size, actual_recv);
        warn_if_socket_buffer_clamped("send", send_buf_size, actual_send);

        Ok(())
    }

    #[cfg(target_os = "linux")]
    fn force_linux_socket_buffer_sizes(
        sock: &Socket,
        recv_buf_size: usize,
        send_buf_size: usize,
        mut actual_recv: usize,
        mut actual_send: usize,
    ) -> (usize, usize) {
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
        (actual_recv, actual_send)
    }

    fn warn_if_socket_buffer_clamped(kind: &'static str, requested: usize, actual: usize) {
        if actual >= requested {
            return;
        }
        #[cfg(target_os = "linux")]
        warn!(
            requested,
            actual,
            "UDP {kind} buffer clamped by kernel even with SO_{kind_upper}BUFFORCE \
             (increase net.core.{sysctl}_max or grant CAP_NET_ADMIN)",
            kind_upper = if kind == "recv" { "RCV" } else { "SND" },
            sysctl = if kind == "recv" { "rmem" } else { "wmem" },
        );
        #[cfg(not(target_os = "linux"))]
        warn!(requested, actual, "UDP {kind} buffer clamped by kernel");
    }

    fn configure_socket_nonblocking(sock: &Socket) -> Result<(), TransportError> {
        sock.set_nonblocking(true)
            .map_err(|e| TransportError::StartFailed(format!("set nonblocking failed: {}", e)))
    }

    fn configure_socket_reuse(sock: &Socket) {
        let _ = sock.set_reuse_port(true);
        let _ = sock.set_reuse_address(true);
    }

    #[cfg(target_os = "macos")]
    fn apply_darwin_udp_tuning(sock: &Socket, label: &'static str) {
        crate::transport::udp::darwin_sockopts::apply_udp_socket_tuning(sock.as_raw_fd(), label);
    }

    #[cfg(not(target_os = "macos"))]
    fn apply_darwin_udp_tuning(_sock: &Socket, _label: &'static str) {}

    fn socket_local_addr(sock: &Socket) -> Result<SocketAddr, TransportError> {
        sock.local_addr()
            .map_err(|e| TransportError::StartFailed(format!("get local addr: {}", e)))?
            .as_socket()
            .ok_or_else(|| TransportError::StartFailed("local address is not an IP socket".into()))
    }

    fn finish_configured_socket(sock: Socket) -> Result<UdpRawSocket, TransportError> {
        #[cfg(target_os = "linux")]
        let udp_gro_enabled = configure_linux_recv_sockopts(sock.as_raw_fd());
        let local_addr = socket_local_addr(&sock)?;

        Ok(UdpRawSocket {
            inner: sock,
            local_addr,
            #[cfg(target_os = "linux")]
            udp_gro_enabled,
        })
    }
