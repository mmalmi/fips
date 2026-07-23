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
            Self::open_inner(bind_addr, recv_buf_size, send_buf_size)
        }

        /// Create a UDP socket whose address cannot be shared by another
        /// FIPS instance. Used as the same-host rendezvous ownership lock.
        pub fn open_exclusive(
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

            configure_socket_nonblocking(&sock)?;

            apply_darwin_udp_tuning(&sock, "udp-listen");

            sock.bind(&bind_addr.into())
                .map_err(|error| TransportError::bind_failed(bind_addr, error))?;

            // Set socket buffer sizes via the standard SO_RCVBUF /
            // SO_SNDBUF path first. These are clamped to
            // `net.core.{rmem,wmem}_max`, which on a default Linux
            // container is ~213 KiB — way too small to absorb a multi-
            // Gbps inbound burst, leading to UDP RcvbufErrors at line
            // rate. If clamped and we hold CAP_NET_ADMIN, the
            // SO_RCVBUFFORCE / SO_SNDBUFFORCE variants bypass the
            // sysctl ceiling entirely.
            configure_socket_buffer_sizes(&sock, recv_buf_size, send_buf_size)?;

            finish_configured_socket(sock)
        }

        /// Adopt an existing bound UDP socket.
        ///
        /// This preserves socket identity/NAT mapping created by bootstrap code.
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

            configure_socket_nonblocking(&sock)?;

            apply_darwin_udp_tuning(&sock, "udp-adopted");

            configure_socket_buffer_sizes(&sock, recv_buf_size, send_buf_size)?;

            finish_configured_socket(sock)
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
        /// Linux/macOS use `recv_batch` (recvmmsg/recvmsg_x); this
        /// single-packet variant remains for other unix targets.
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
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
        /// (Linux only — macOS uses `recvmsg_x` below).
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

        /// Receive up to `RECV_BATCH_SIZE` datagrams in a single Darwin
        /// `recvmsg_x` syscall.
        ///
        /// macOS does not expose kernel drop or UDP GRO metadata here, so
        /// drops and per-slot GRO segment sizes remain zero.
        #[cfg(target_os = "macos")]
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

            let mut iovs: [libc::iovec; RECV_BATCH_SIZE] = unsafe { std::mem::zeroed() };
            let mut storages: [libc::sockaddr_storage; RECV_BATCH_SIZE] =
                unsafe { std::mem::zeroed() };
            let mut msgs: [msghdr_x; RECV_BATCH_SIZE] = unsafe { std::mem::zeroed() };

            for i in 0..n {
                bufs[i].clear();
                addrs[i] = None;
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
                msgs[i].msg_name = &mut storages[i] as *mut _ as *mut libc::c_void;
                msgs[i].msg_namelen =
                    std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
                msgs[i].msg_iov = &mut iovs[i];
                msgs[i].msg_iovlen = 1;
                msgs[i].msg_control = std::ptr::null_mut();
                msgs[i].msg_controllen = 0;
                msgs[i].msg_flags = 0;
                msgs[i].msg_datalen = spare.len();
            }

            let count = loop {
                let r = unsafe { recvmsg_x(fd, msgs.as_mut_ptr(), n as libc::c_uint, 0) };
                if r >= 0 {
                    break r as usize;
                }
                let error = std::io::Error::last_os_error();
                if error.kind() != std::io::ErrorKind::Interrupted {
                    return Err(error);
                }
            };
            crate::perf_profile::record_udp_recv_recvmsgx_batch(count);

            for i in 0..count {
                if (msgs[i].msg_flags & libc::MSG_TRUNC) != 0 {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "recvmsg_x reported a truncated UDP datagram",
                    ));
                }
                let len = msgs[i].msg_datalen;
                if len > bufs[i].capacity() {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "recvmsg_x reported a datagram larger than the receive buffer",
                    ));
                }
                // SAFETY: `recvmsg_x` initialized `len` bytes in `bufs[i]`'s
                // spare capacity through the iovec, and `len <= capacity`
                // was checked above.
                unsafe {
                    bufs[i].set_len(len);
                }
                addrs[i] = sockaddr_to_socket_addr(&storages[i]).ok();
            }

            Ok((count, 0))
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
