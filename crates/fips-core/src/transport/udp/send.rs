#[derive(Clone)]
pub(crate) struct UdpSendSnapshot {
    socket: AsyncUdpSocket,
    local_addr: SocketAddr,
    mtu: u16,
    stats: Arc<UdpStats>,
}

pub(crate) const UDP_PAYLOAD_MAX_SLICES: usize = 2;

pub(crate) trait UdpPayloadBatch {
    fn len(&self) -> usize;
    fn payload_len(&self, index: usize) -> usize;
    #[cfg(any(test, not(any(target_os = "linux", target_os = "macos"))))]
    fn contiguous_payload(&self, index: usize) -> Option<&[u8]>;
    fn payload_slices<'a>(
        &'a self,
        index: usize,
        out: &mut [Option<&'a [u8]>; UDP_PAYLOAD_MAX_SLICES],
    ) -> usize;

    #[cfg(any(
        test,
        not(any(
            target_os = "linux",
            target_os = "macos",
            target_os = "ios",
            target_os = "android"
        ))
    ))]
    fn copy_payload_into(&self, index: usize, out: &mut Vec<u8>) {
        out.clear();
        let mut slices = [None; UDP_PAYLOAD_MAX_SLICES];
        let slice_count = self.payload_slices(index, &mut slices);
        for slice in slices.iter().take(slice_count).flatten() {
            out.extend_from_slice(slice);
        }
    }
}

impl std::fmt::Debug for UdpSendSnapshot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UdpSendSnapshot")
            .field("local_addr", &self.local_addr)
            .field("mtu", &self.mtu)
            .finish_non_exhaustive()
    }
}

impl UdpSendSnapshot {
    pub(crate) fn validate_packet(
        &self,
        data_len: usize,
        remote_addr: SocketAddr,
    ) -> Result<(), TransportError> {
        if data_len > self.mtu as usize {
            self.stats.record_mtu_exceeded();
            return Err(TransportError::MtuExceeded {
                packet_size: data_len,
                mtu: self.mtu,
            });
        }
        if !socket_addr_families_compatible(self.local_addr, remote_addr) {
            return Err(TransportError::InvalidAddress(format!(
                "remote address family {remote_addr} is incompatible with local UDP socket {}",
                self.local_addr
            )));
        }
        Ok(())
    }

    #[cfg(any(
        target_os = "linux",
        target_os = "macos",
        target_os = "ios",
        target_os = "android"
    ))]
    pub(crate) async fn send_payload_batch_to<B>(
        &self,
        payloads: &B,
        remote_addr: SocketAddr,
    ) -> usize
    where
        B: UdpPayloadBatch + ?Sized,
    {
        let packet_count = payloads.len();
        if packet_count == 0 {
            return 0;
        }

        let mut failed = 0usize;
        let mut offset = 0usize;
        while offset < packet_count {
            let _t = crate::perf_profile::Timer::start(crate::perf_profile::Stage::UdpSend);
            match self
                .socket
                .send_batch_to(payloads, offset, remote_addr)
                .await
            {
                Ok(0) => {
                    self.stats.record_send_error();
                    failed = failed.saturating_add(packet_count.saturating_sub(offset));
                    break;
                }
                Ok(sent) => {
                    let end = offset.saturating_add(sent).min(packet_count);
                    let bytes = (offset..end)
                        .map(|batch_index| payloads.payload_len(batch_index))
                        .sum();
                    self.stats.record_send_batch(end - offset, bytes);
                    offset = end;
                }
                Err(_) => {
                    self.stats.record_send_error();
                    failed = failed.saturating_add(packet_count.saturating_sub(offset));
                    break;
                }
            }
        }
        failed
    }

    #[cfg(not(any(
        target_os = "linux",
        target_os = "macos",
        target_os = "ios",
        target_os = "android"
    )))]
    pub(crate) async fn send_payload_batch_to<B>(
        &self,
        payloads: &B,
        remote_addr: SocketAddr,
    ) -> usize
    where
        B: UdpPayloadBatch + ?Sized,
    {
        self.send_payload_batch_scalar_to(payloads, remote_addr)
            .await
    }

    #[cfg(any(
        test,
        not(any(
            target_os = "linux",
            target_os = "macos",
            target_os = "ios",
            target_os = "android"
        ))
    ))]
    async fn send_payload_batch_scalar_to<B>(&self, payloads: &B, remote_addr: SocketAddr) -> usize
    where
        B: UdpPayloadBatch + ?Sized,
    {
        let mut scratch = Vec::new();
        for index in 0..payloads.len() {
            let expected_len = payloads.payload_len(index);
            let data = match payloads.contiguous_payload(index) {
                Some(data) => data,
                None => {
                    payloads.copy_payload_into(index, &mut scratch);
                    scratch.as_slice()
                }
            };
            let result = self.socket.send_to(data, &remote_addr).await;
            if let Ok(bytes_sent) = result {
                debug_assert_eq!(bytes_sent, expected_len);
                self.stats.record_send(bytes_sent);
            } else {
                self.stats.record_send_error();
                // Completion accounting treats successful sends as a prefix.
                return payloads.len() - index;
            }
        }
        0
    }
}
