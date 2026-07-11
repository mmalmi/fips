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
        /// Linux/macOS use `recv_batch`; this single-packet variant remains
        /// for other unix targets.
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
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
        /// `recvmmsg` (Linux) or `recvmsg_x` (macOS). Returns
        /// `(count, kernel_drops)`; same buffer / addr / GRO segment-size contract as
        /// `UdpRawSocket::recv_batch`.
        #[cfg(any(target_os = "linux", target_os = "macos"))]
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

// ============================================================================
// Windows implementation
// ============================================================================
