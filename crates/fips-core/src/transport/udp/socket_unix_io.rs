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
        #[cfg(all(test, target_os = "macos"))]
        pub(crate) fn bound_device_index_v4(
            &self,
        ) -> std::io::Result<Option<std::num::NonZeroU32>> {
            self.inner.get_ref().bound_device_index_v4()
        }

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
            bounded_control_send(async {
                loop {
                    let mut guard = self.inner.writable().await.map_err(|e| {
                        TransportError::SendFailed(format!("writable wait: {}", e))
                    })?;

                    match guard.try_io(|inner| inner.get_ref().send_to(data, dest)) {
                        Ok(Ok(n)) => return Ok(n),
                        Ok(Err(e)) => {
                            return Err(TransportError::SendFailed(format!("{}", e)));
                        }
                        Err(_would_block) => continue,
                    }
                }
            })
            .await
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

    const UDP_CONTROL_SEND_TIMEOUT: std::time::Duration =
        std::time::Duration::from_millis(100);

    pub(super) async fn bounded_control_send<F>(
        send: F,
    ) -> Result<usize, TransportError>
    where
        F: std::future::Future<Output = Result<usize, TransportError>>,
    {
        match tokio::time::timeout(UDP_CONTROL_SEND_TIMEOUT, send).await {
            Ok(result) => result,
            Err(_) => Err(TransportError::Timeout),
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
                Ok(SocketAddr::V6(std::net::SocketAddrV6::new(
                    ip,
                    port,
                    0,
                    addr.sin6_scope_id,
                )))
            }
            family => Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("unsupported address family: {}", family),
            )),
        }
    }

    #[cfg(test)]
    mod sockaddr_tests {
        use super::sockaddr_to_socket_addr;
        use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};

        fn sockaddr_v6(ip: Ipv6Addr, port: u16, scope_id: u32) -> libc::sockaddr_storage {
            let mut storage: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
            let addr = unsafe { &mut *(&mut storage as *mut _ as *mut libc::sockaddr_in6) };
            addr.sin6_family = libc::AF_INET6 as libc::sa_family_t;
            addr.sin6_port = port.to_be();
            addr.sin6_addr = libc::in6_addr {
                s6_addr: ip.octets(),
            };
            addr.sin6_scope_id = scope_id;
            storage
        }

        fn sockaddr_v4(ip: Ipv4Addr, port: u16) -> libc::sockaddr_storage {
            let mut storage: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
            let addr = unsafe { &mut *(&mut storage as *mut _ as *mut libc::sockaddr_in) };
            addr.sin_family = libc::AF_INET as libc::sa_family_t;
            addr.sin_port = port.to_be();
            addr.sin_addr = libc::in_addr {
                s_addr: u32::from(ip).to_be(),
            };
            storage
        }

        #[test]
        fn link_local_source_keeps_scope_id() {
            let ip: Ipv6Addr = "fe80::1".parse().unwrap();
            let addr = sockaddr_to_socket_addr(&sockaddr_v6(ip, 4871, 42)).unwrap();
            assert_eq!(addr, SocketAddr::V6(std::net::SocketAddrV6::new(ip, 4871, 0, 42)));
        }

        #[test]
        fn scoped_and_unscoped_addresses_are_distinct() {
            let ip: Ipv6Addr = "fe80::1".parse().unwrap();
            let scoped = sockaddr_to_socket_addr(&sockaddr_v6(ip, 4871, 42)).unwrap();
            let unscoped = sockaddr_to_socket_addr(&sockaddr_v6(ip, 4871, 0)).unwrap();
            assert_ne!(scoped, unscoped);
        }

        #[test]
        fn global_v6_and_v4_sources_are_unchanged() {
            let v6: Ipv6Addr = "2001:db8::1".parse().unwrap();
            assert_eq!(
                sockaddr_to_socket_addr(&sockaddr_v6(v6, 4871, 0)).unwrap(),
                SocketAddr::from((v6, 4871))
            );
            let v4 = Ipv4Addr::new(192, 168, 8, 238);
            assert_eq!(
                sockaddr_to_socket_addr(&sockaddr_v4(v4, 2121)).unwrap(),
                SocketAddr::from((v4, 2121))
            );
        }
    }

// ============================================================================
// Windows implementation
// ============================================================================
