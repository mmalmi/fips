// Public socket APIs for mobile platforms, shared with real UDP tests.
impl UdpRawSocket {
    #[cfg(target_os = "ios")]
    pub fn send_batch_to<B>(
        &self,
        payloads: &B,
        offset: usize,
        dest: SocketAddr,
    ) -> std::io::Result<usize>
    where
        B: crate::transport::udp::UdpPayloadBatch + ?Sized,
    {
        self.send_batch_portable(payloads, offset, dest)
    }

    /// Send the already-collected prefix without waiting to fill a batch.
    /// Public sendmsg preserves each datagram and avoids copying split payloads.
    #[cfg(any(test, target_os = "ios"))]
    fn send_batch_portable<B>(
        &self,
        payloads: &B,
        offset: usize,
        dest: SocketAddr,
    ) -> std::io::Result<usize>
    where
        B: crate::transport::udp::UdpPayloadBatch + ?Sized,
    {
        let limit = payloads.len().saturating_sub(offset).min(SEND_BATCH_SIZE);
        let address = socket2::SockAddr::from(dest);
        for sent in 0..limit {
            let index = offset + sent;
            let mut slices = [None; crate::transport::udp::UDP_PAYLOAD_MAX_SLICES];
            let count = payloads.payload_slices(index, &mut slices);
            let mut vectors =
                [std::io::IoSlice::new(&[]); crate::transport::udp::UDP_PAYLOAD_MAX_SLICES];
            let mut length = 0usize;
            let valid =
                count > 0 && count <= slices.len() && slices[..count].iter().all(Option::is_some);
            if valid {
                for (vector, data) in vectors.iter_mut().zip(slices[..count].iter().flatten()) {
                    *vector = std::io::IoSlice::new(data);
                    length = length.saturating_add(data.len());
                }
            }
            let result = if valid && length == payloads.payload_len(index) {
                loop {
                    match self.inner.send_to_vectored(&vectors[..count], &address) {
                        Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                        result => break result,
                    }
                }
            } else {
                Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "invalid UDP payload slices",
                ))
            };
            match result {
                Ok(bytes) if bytes == length => {}
                Ok(_) if sent > 0 => return Ok(sent),
                Ok(_) => return Err(std::io::Error::other("partial UDP datagram send")),
                // Account for the completed prefix before the caller retries
                // only the unsent suffix, including after WouldBlock.
                Err(_) if sent > 0 => return Ok(sent),
                Err(error) => return Err(error),
            }
        }
        Ok(limit)
    }

    /// Drain only datagrams already ready on the nonblocking socket. Mobile
    /// targets share one readiness turn and the pooled receive buffers,
    /// using public recvmsg calls without waiting to fill a batch.
    #[cfg(any(test, target_os = "ios", target_os = "android"))]
    fn recv_batch_portable(
        &self,
        bufs: &mut [Vec<u8>],
        addrs: &mut [Option<SocketAddr>],
        gro_segment_sizes: &mut [usize],
    ) -> std::io::Result<(usize, u32)> {
        let limit = bufs
            .len()
            .min(addrs.len())
            .min(gro_segment_sizes.len())
            .min(RECV_BATCH_SIZE);
        for i in 0..limit {
            bufs[i].clear();
            addrs[i] = None;
            gro_segment_sizes[i] = 0;
            if bufs[i].capacity() == 0 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "UDP receive buffer has no spare capacity",
                ));
            }
        }
        let mut count = 0;
        while count < limit {
            let received = self
                .inner
                .recv_from_vectored(&mut [socket2::MaybeUninitSlice::new(
                    bufs[count].spare_capacity_mut(),
                )]);
            let (len, flags, source) = match received {
                Ok(received) => received,
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock && count > 0 => {
                    break;
                }
                Err(error) => return Err(error),
            };
            if flags.is_truncated() || len > bufs[count].capacity() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "recvmsg reported a truncated UDP datagram",
                ));
            }
            let source = source.as_socket().ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "UDP source is not an IP address",
                )
            })?;
            // SAFETY: recvmsg initialized exactly len bytes in the Vec's
            // spare capacity; truncation and capacity were checked above.
            unsafe {
                bufs[count].set_len(len);
            }
            addrs[count] = Some(source);
            count += 1;
        }
        Ok((count, 0))
    }
}

#[cfg(test)]
mod portable_io_tests {
    use super::*;

    struct Payloads(Vec<[Vec<u8>; 2]>);

    impl crate::transport::udp::UdpPayloadBatch for Payloads {
        fn len(&self) -> usize {
            self.0.len()
        }
        fn payload_len(&self, index: usize) -> usize {
            self.0[index].iter().map(Vec::len).sum()
        }
        fn contiguous_payload(&self, _: usize) -> Option<&[u8]> {
            None
        }
        fn payload_slices<'a>(&'a self, index: usize, out: &mut [Option<&'a [u8]>; 2]) -> usize {
            *out = [Some(&self.0[index][0]), Some(&self.0[index][1])];
            2
        }
    }

    #[test]
    fn portable_send_preserves_datagram_boundaries_order_and_ready_batch_tail() {
        for bind in ["127.0.0.1:0", "[::1]:0"] {
            let sender = UdpRawSocket::open(bind.parse().unwrap(), 65536, 65536).unwrap();
            let receiver = UdpRawSocket::open(bind.parse().unwrap(), 65536, 1024 * 1024).unwrap();
            let payloads = Payloads(
                (0..SEND_BATCH_SIZE + 2)
                    .map(|n| {
                        if n == 0 {
                            [vec![], vec![]]
                        } else {
                            [vec![0xf1], (n as u16).to_be_bytes().to_vec()]
                        }
                    })
                    .collect(),
            );
            assert_eq!(
                sender
                    .send_batch_portable(&payloads, 0, receiver.local_addr())
                    .unwrap(),
                SEND_BATCH_SIZE
            );
            assert_eq!(
                sender
                    .send_batch_portable(&payloads, SEND_BATCH_SIZE, receiver.local_addr())
                    .unwrap(),
                2
            );
            assert_eq!(
                sender
                    .send_batch_portable(&payloads, payloads.0.len(), receiver.local_addr())
                    .unwrap(),
                0
            );
            for expected in &payloads.0 {
                wait_readable(&receiver);
                let mut bufs = [Vec::with_capacity(32)];
                let mut addrs = [None];
                assert_eq!(
                    receiver
                        .recv_batch_portable(&mut bufs, &mut addrs, &mut [0])
                        .unwrap()
                        .0,
                    1
                );
                assert_eq!(bufs[0], expected.concat());
                assert_eq!(addrs[0], Some(sender.local_addr()));
            }
        }
    }

    #[test]
    fn portable_send_accounts_for_successful_prefix_before_a_datagram_error() {
        let sender = UdpRawSocket::open("127.0.0.1:0".parse().unwrap(), 65536, 65536).unwrap();
        let receiver = UdpRawSocket::open("127.0.0.1:0".parse().unwrap(), 65536, 65536).unwrap();
        let payloads = Payloads(vec![
            [b"first".to_vec(), vec![]],
            [vec![7; u16::MAX as usize + 1], vec![]],
            [b"must remain unsent".to_vec(), vec![]],
        ]);
        assert_eq!(
            sender
                .send_batch_portable(&payloads, 0, receiver.local_addr())
                .unwrap(),
            1
        );
        assert!(
            sender
                .send_batch_portable(&payloads, 1, receiver.local_addr())
                .is_err()
        );
        wait_readable(&receiver);
        let mut bufs = [Vec::with_capacity(32), Vec::with_capacity(32)];
        let mut addrs = [None; 2];
        assert_eq!(
            receiver
                .recv_batch_portable(&mut bufs, &mut addrs, &mut [0; 2])
                .unwrap()
                .0,
            1
        );
        assert_eq!(bufs[0], b"first");
        assert_eq!(
            receiver
                .recv_batch_portable(&mut bufs, &mut addrs, &mut [0; 2])
                .unwrap_err()
                .kind(),
            std::io::ErrorKind::WouldBlock
        );
    }

    fn wait_readable(socket: &UdpRawSocket) {
        let mut descriptor = libc::pollfd {
            fd: socket.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: descriptor is one initialized pollfd valid for this call.
        let ready = unsafe { libc::poll(&mut descriptor, 1, 2_000) };
        assert_eq!(ready, 1, "loopback datagram did not become readable");
        assert_ne!(descriptor.revents & libc::POLLIN, 0);
    }

    #[test]
    fn portable_receive_drains_ready_datagrams_in_order_without_a_batching_delay() {
        for bind in ["127.0.0.1:0", "[::1]:0"] {
            let sender = UdpRawSocket::open(bind.parse().unwrap(), 65536, 65536).unwrap();
            let receiver = UdpRawSocket::open(bind.parse().unwrap(), 65536, 65536).unwrap();
            for data in [b"first".as_slice(), b"", b"third"] {
                sender.send_to(data, &receiver.local_addr()).unwrap();
            }
            wait_readable(&receiver);
            let mut bufs = vec![Vec::with_capacity(32), Vec::with_capacity(32)];
            let mut addrs = [None; 2];
            let mut gro = [usize::MAX; 2];
            let (count, drops) = receiver
                .recv_batch_portable(&mut bufs, &mut addrs, &mut gro)
                .unwrap();
            assert_eq!((count, drops), (2, 0));
            assert_eq!(bufs[0], b"first");
            assert!(bufs[1].is_empty(), "empty UDP payload is still a datagram");
            assert_eq!(addrs, [Some(sender.local_addr()); 2]);
            assert_eq!(gro, [0; 2]);

            let (count, drops) = receiver
                .recv_batch_portable(&mut bufs, &mut addrs, &mut gro)
                .unwrap();
            assert_eq!(
                (count, drops),
                (1, 0),
                "return the ready tail without waiting for a full batch"
            );
            assert_eq!(bufs[0], b"third");
            assert!(bufs[1].is_empty());
            assert_eq!(addrs, [Some(sender.local_addr()), None]);
            assert_eq!(gro, [0; 2]);
            assert_eq!(
                receiver
                    .recv_batch_portable(&mut bufs, &mut addrs, &mut gro)
                    .unwrap_err()
                    .kind(),
                std::io::ErrorKind::WouldBlock
            );
            assert!(bufs.iter().all(Vec::is_empty));
            assert_eq!(addrs, [None; 2]);

            sender.send_to(b"new", &receiver.local_addr()).unwrap();
            wait_readable(&receiver);
            assert_eq!(
                receiver
                    .recv_batch_portable(&mut bufs, &mut addrs, &mut gro)
                    .unwrap()
                    .0,
                1
            );
            assert_eq!(
                bufs[0], b"new",
                "a reused slot contains no prior packet tail"
            );
        }
    }

    #[test]
    fn portable_receive_rejects_invalid_capacity_and_truncated_packets() {
        let sender = UdpRawSocket::open("127.0.0.1:0".parse().unwrap(), 65536, 65536).unwrap();
        let receiver = UdpRawSocket::open("127.0.0.1:0".parse().unwrap(), 65536, 65536).unwrap();
        let mut addrs = [None];
        let mut gro = [usize::MAX];
        sender
            .send_to(b"oversized", &receiver.local_addr())
            .unwrap();
        assert_eq!(
            receiver
                .recv_batch_portable(&mut [], &mut addrs, &mut gro)
                .unwrap(),
            (0, 0)
        );
        assert_eq!(
            receiver
                .recv_batch_portable(&mut [Vec::new()], &mut addrs, &mut gro)
                .unwrap_err()
                .kind(),
            std::io::ErrorKind::InvalidInput
        );
        wait_readable(&receiver);
        let mut bufs = [Vec::with_capacity(4)];
        assert_eq!(
            receiver
                .recv_batch_portable(&mut bufs, &mut addrs, &mut gro)
                .unwrap_err()
                .kind(),
            std::io::ErrorKind::InvalidData
        );
        assert!(
            bufs[0].is_empty(),
            "a truncated frame must not expose a partial datagram"
        );
        assert_eq!(addrs, [None]);
        sender.send_to(b"ok", &receiver.local_addr()).unwrap();
        wait_readable(&receiver);
        assert_eq!(
            receiver
                .recv_batch_portable(&mut bufs, &mut addrs, &mut gro)
                .unwrap(),
            (1, 0)
        );
        assert_eq!(bufs[0], b"ok");
        assert_eq!(addrs, [Some(sender.local_addr())]);
    }
}
