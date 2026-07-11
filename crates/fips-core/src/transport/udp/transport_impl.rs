impl Transport for UdpTransport {
    fn transport_id(&self) -> TransportId {
        self.transport_id
    }

    fn transport_type(&self) -> &TransportType {
        &TransportType::UDP
    }

    fn state(&self) -> TransportState {
        self.state
    }

    fn mtu(&self) -> u16 {
        self.config.mtu()
    }

    fn start(&mut self) -> Result<(), TransportError> {
        // Synchronous start not supported - use start_async()
        Err(TransportError::NotSupported(
            "use start_async() for UDP transport".into(),
        ))
    }

    fn stop(&mut self) -> Result<(), TransportError> {
        // Synchronous stop not supported - use stop_async()
        Err(TransportError::NotSupported(
            "use stop_async() for UDP transport".into(),
        ))
    }

    fn send(&self, _addr: &TransportAddr, _data: &[u8]) -> Result<(), TransportError> {
        // Synchronous send not supported - use send_async()
        Err(TransportError::NotSupported(
            "use send_async() for UDP transport".into(),
        ))
    }

    fn discover(&self) -> Result<Vec<DiscoveredPeer>, TransportError> {
        // UDP discovery not yet implemented (would use multicast/DNS-SD)
        // Peer configuration is handled at the node level, not transport level
        Ok(Vec::new())
    }

    /// Whether the transport accepts inbound handshake initiations.
    /// `outbound_only` mode forces this to false; otherwise reflects the
    /// `accept_connections` config field (default: true). Note that the
    /// hard gate is at the Node level (see ISSUE-2026-0004 fix in
    /// `src/node/handlers/handshake.rs`); this method is what that gate
    /// consults for transports that lack runtime-state-based filtering.
    fn accept_connections(&self) -> bool {
        if self.config.outbound_only() {
            false
        } else {
            self.config.accept_connections()
        }
    }
}

impl Drop for UdpTransport {
    fn drop(&mut self) {
        let had_task = self.recv_task.is_some();
        let had_socket = self.socket.is_some();
        if had_task || had_socket {
            debug!(
                transport_id = %self.transport_id,
                state = ?self.state,
                had_recv_task = had_task,
                had_socket = had_socket,
                "UdpTransport dropped without stop_async(); cleaning up",
            );
        }
        if let Some(task) = self.recv_task.take() {
            task.abort();
        }
        self.socket.take();
        self.local_addr = None;
    }
}

/// UDP receive loop - runs as a spawned task.
///
/// On Linux, drains the kernel UDP queue in `UDP_RECV_BATCH_SIZE` bursts via
/// `recvmmsg` to amortise the per-syscall + per-task-wakeup overhead. macOS
/// uses Darwin `recvmsg_x` for the same batching shape. Windows falls through
/// to single-packet `recv_from`. Either way every
/// datagram is forwarded to `packet_tx` in arrival order.
async fn udp_receive_loop(
    socket: AsyncUdpSocket,
    transport_id: TransportId,
    packet_tx: PacketTx,
    mtu: u16,
    stats: Arc<UdpStats>,
) {
    debug!(transport_id = %transport_id, "UDP receive loop starting");

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn cached_transport_addr(
        cache: &mut Vec<(SocketAddr, TransportAddr)>,
        remote_addr: SocketAddr,
    ) -> TransportAddr {
        if let Some((_, addr)) = cache
            .iter()
            .find(|(socket_addr, _)| *socket_addr == remote_addr)
        {
            return addr.clone();
        }

        const UDP_ADDR_CACHE_CAP: usize = 16;
        let addr = TransportAddr::from_socket_addr(remote_addr);
        if cache.len() >= UDP_ADDR_CACHE_CAP {
            cache.remove(0);
        }
        cache.push((remote_addr, addr.clone()));
        addr
    }

    #[cfg(target_os = "linux")]
    {
        const BATCH: usize = UDP_RECV_BATCH_SIZE;
        let packet_buf_size = mtu as usize + 100;
        let udp_gro_enabled = socket.udp_gro_enabled();
        let recv_buf_size = if udp_gro_enabled {
            UDP_GRO_RECV_BUFFER_SIZE
        } else {
            packet_buf_size
        };
        // Backing pool: one Vec<u8> per recvmmsg slot. Without UDP_GRO,
        // when a packet lands we `mem::replace` the filled Vec out
        // (handing the buffer directly to rx_loop via mpsc) and drop in
        // a fresh capacity-only Vec to refill that slot on the next call.
        //
        // Previous code did `let data = buf.to_vec();` per packet,
        // which was 1 alloc + 1 memcpy of the entire packet (~1.5 KB)
        // for every received UDP datagram. At 100 kpps that's
        // ~150 MB/sec of avoidable memory bandwidth on the RX hot path.
        // With UDP_GRO enabled, the backing slot is large enough for a
        // coalesced kernel receive and is split back into ordinary FIPS
        // datagrams before dataplane fast ingress or packet-channel delivery.
        let mut backing: Vec<Vec<u8>> = (0..BATCH)
            .map(|_| packet_tx.recv_buffer(recv_buf_size))
            .collect();
        let mut addrs: [Option<std::net::SocketAddr>; BATCH] = std::array::from_fn(|_| None);
        let mut gro_segment_sizes = [0usize; BATCH];
        let mut addr_cache: Vec<(SocketAddr, TransportAddr)> = Vec::new();

        loop {
            let recv_result = {
                let _t = crate::perf_profile::Timer::start(crate::perf_profile::Stage::UdpRecv);
                socket
                    .recv_batch(&mut backing, &mut addrs, &mut gro_segment_sizes)
                    .await
            };
            match recv_result {
                Ok((count, kernel_drops)) => {
                    stats.set_kernel_drops(kernel_drops as u64);
                    let timestamp_ms = crate::time::now_ms();
                    let trace_enqueued_at = crate::perf_profile::stamp();
                    let mut packets = packet_tx.packet_batch(count);
                    for i in 0..count {
                        let len = backing[i].len();
                        let gro_segment_size = gro_segment_sizes[i];
                        gro_segment_sizes[i] = 0;
                        let Some(remote_addr) = addrs[i].take() else {
                            reset_recv_buffer(&mut backing[i]);
                            continue;
                        };
                        stats.record_recv(len);

                        // Peek before swap: punch probes / acks are
                        // discarded without consuming a buffer move.
                        if is_punch_packet(&backing[i][..len]) {
                            trace!(
                                transport_id = %transport_id,
                                remote_addr = %remote_addr,
                                bytes = len,
                                "Dropping stray punch probe/ack on UDP transport"
                            );
                            reset_recv_buffer(&mut backing[i]);
                            continue;
                        }

                        if gro_segment_size == 0 && len > packet_buf_size {
                            stats.record_recv_error();
                            debug!(
                                transport_id = %transport_id,
                                remote_addr = %remote_addr,
                                bytes = len,
                                packet_buf_size = packet_buf_size,
                                "Dropping oversized UDP receive without GRO segment metadata"
                            );
                            reset_recv_buffer(&mut backing[i]);
                            continue;
                        }
                        if gro_segment_size > packet_buf_size {
                            stats.record_recv_error();
                            debug!(
                                transport_id = %transport_id,
                                remote_addr = %remote_addr,
                                bytes = len,
                                gro_segment_size = gro_segment_size,
                                packet_buf_size = packet_buf_size,
                                "Dropping UDP GRO receive with oversized segment"
                            );
                            reset_recv_buffer(&mut backing[i]);
                            continue;
                        }

                        let addr = cached_transport_addr(&mut addr_cache, remote_addr);
                        let gro_segment_count = udp_gro_segment_count(len, gro_segment_size);
                        if gro_segment_count > 1 {
                            crate::perf_profile::record_udp_recv_gro_split(gro_segment_count, len);
                            let source = &backing[i][..len];
                            let mut start = 0usize;
                            while start < source.len() {
                                let end = start.saturating_add(gro_segment_size).min(source.len());
                                let mut data = packet_tx.recv_buffer(end - start);
                                data.extend_from_slice(&source[start..end]);
                                packets.push(ReceivedPacket::with_trace_timestamp(
                                    transport_id,
                                    addr.clone(),
                                    packet_tx.packet_buffer(data),
                                    timestamp_ms,
                                    trace_enqueued_at,
                                ));
                                start = end;
                            }
                            reset_recv_buffer(&mut backing[i]);
                            trace!(
                                transport_id = %transport_id,
                                remote_addr = %remote_addr,
                                bytes = len,
                                gro_segment_size = gro_segment_size,
                                gro_segments = gro_segment_count,
                                "UDP GRO packet split"
                            );
                            continue;
                        }

                        crate::perf_profile::record_udp_recv_plain_packet();
                        let data = if recv_buf_size == packet_buf_size {
                            // Move the filled buffer out of the slot and
                            // refill with a fresh one. `mem::replace`
                            // returns the OLD value and writes the new one
                            // — single pointer swap, no copy.
                            std::mem::replace(&mut backing[i], packet_tx.recv_buffer(recv_buf_size))
                        } else {
                            let mut data = packet_tx.recv_buffer(len);
                            data.extend_from_slice(&backing[i][..len]);
                            reset_recv_buffer(&mut backing[i]);
                            data
                        };
                        let packet = ReceivedPacket::with_trace_timestamp(
                            transport_id,
                            addr,
                            packet_tx.packet_buffer(data),
                            timestamp_ms,
                            trace_enqueued_at,
                        );

                        trace!(
                            transport_id = %transport_id,
                            remote_addr = %remote_addr,
                            bytes = len,
                            gro_segment_size = gro_segment_size,
                            "UDP packet received"
                        );

                        packets.push(packet);
                    }

                    debug_udp_fmp_batch("pre-fast-ingress", transport_id, packets.as_slice(), None);
                    let accepted_fast_ingress =
                        packet_tx.try_fast_ingress_packet_batch(&mut packets);
                    debug_udp_fmp_batch(
                        "post-fast-ingress",
                        transport_id,
                        packets.as_slice(),
                        Some(accepted_fast_ingress),
                    );
                    if !packets.is_empty() && packet_tx.send_packet_batch(packets).is_err() {
                        debug!(
                            transport_id = %transport_id,
                            "Packet channel closed, stopping receive loop"
                        );
                        return;
                    }
                }
                Err(e) => {
                    stats.record_recv_error();
                    warn!(
                        transport_id = %transport_id,
                        error = %e,
                        "UDP receive error"
                    );
                }
            }
        }
    }

    #[cfg(target_os = "macos")]
    {
        const BATCH: usize = UDP_RECV_BATCH_SIZE;
        let buf_size = mtu as usize + 100;
        let mut backing: Vec<Vec<u8>> = (0..BATCH)
            .map(|_| packet_tx.recv_buffer(buf_size))
            .collect();
        let mut addrs: [Option<std::net::SocketAddr>; BATCH] = std::array::from_fn(|_| None);
        let mut gro_segment_sizes = [0usize; BATCH];
        let mut addr_cache: Vec<(SocketAddr, TransportAddr)> = Vec::new();

        loop {
            match socket
                .recv_batch(&mut backing, &mut addrs, &mut gro_segment_sizes)
                .await
            {
                Ok((count, kernel_drops)) => {
                    stats.set_kernel_drops(kernel_drops as u64);
                    let timestamp_ms = crate::time::now_ms();
                    let trace_enqueued_at = crate::perf_profile::stamp();
                    let mut packets = packet_tx.packet_batch(count);
                    for i in 0..count {
                        let len = backing[i].len();
                        gro_segment_sizes[i] = 0;
                        let Some(remote_addr) = addrs[i].take() else {
                            backing[i].clear();
                            continue;
                        };
                        stats.record_recv(len);

                        if is_punch_packet(&backing[i][..len]) {
                            trace!(
                                transport_id = %transport_id,
                                remote_addr = %remote_addr,
                                bytes = len,
                                "Dropping stray punch probe/ack on UDP transport"
                            );
                            backing[i].clear();
                            continue;
                        }

                        let data =
                            std::mem::replace(&mut backing[i], packet_tx.recv_buffer(buf_size));
                        let addr = cached_transport_addr(&mut addr_cache, remote_addr);
                        let packet = ReceivedPacket::with_trace_timestamp(
                            transport_id,
                            addr,
                            packet_tx.packet_buffer(data),
                            timestamp_ms,
                            trace_enqueued_at,
                        );

                        trace!(
                            transport_id = %transport_id,
                            remote_addr = %remote_addr,
                            bytes = len,
                            "UDP packet received"
                        );

                        packets.push(packet);
                    }
                    if packets.is_empty() {
                        continue;
                    }
                    debug_udp_fmp_batch("pre-fast-ingress", transport_id, packets.as_slice(), None);
                    let accepted_fast_ingress =
                        packet_tx.try_fast_ingress_packet_batch(&mut packets);
                    debug_udp_fmp_batch(
                        "post-fast-ingress",
                        transport_id,
                        packets.as_slice(),
                        Some(accepted_fast_ingress),
                    );
                    if packets.is_empty() {
                        continue;
                    }
                    if packet_tx.send_packet_batch(packets).is_err() {
                        debug!(
                            transport_id = %transport_id,
                            "Packet channel closed, stopping receive loop"
                        );
                        break;
                    }
                }
                Err(e) => {
                    stats.record_recv_error();
                    warn!(
                        transport_id = %transport_id,
                        error = %e,
                        "UDP receive error"
                    );
                }
            }
        }
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let mut buf = vec![0u8; mtu as usize + 100];

        loop {
            match socket.recv_from(&mut buf).await {
                Ok((len, remote_addr, kernel_drops, _gro_segment_size)) => {
                    stats.record_recv(len);
                    stats.set_kernel_drops(kernel_drops as u64);

                    if is_punch_packet(&buf[..len]) {
                        trace!(
                            transport_id = %transport_id,
                            remote_addr = %remote_addr,
                            bytes = len,
                            "Dropping stray punch probe/ack on UDP transport"
                        );
                        continue;
                    }

                    let data = buf[..len].to_vec();
                    let addr = TransportAddr::from_socket_addr(remote_addr);
                    let packet = ReceivedPacket::with_timestamp(
                        transport_id,
                        addr,
                        super::PacketBuffer::new(data),
                        crate::time::now_ms(),
                    );

                    trace!(
                        transport_id = %transport_id,
                        remote_addr = %remote_addr,
                        bytes = len,
                        "UDP packet received"
                    );

                    let mut packets = packet_tx.packet_batch(1);
                    packets.push(packet);
                    packet_tx.try_fast_ingress_packet_batch(&mut packets);
                    if packets.is_empty() {
                        continue;
                    }
                    if packet_tx.send_packet_batch(packets).is_err() {
                        debug!(
                            transport_id = %transport_id,
                            "Packet channel closed, stopping receive loop"
                        );
                        break;
                    }
                }
                Err(e) => {
                    stats.record_recv_error();
                    warn!(
                        transport_id = %transport_id,
                        error = %e,
                        "UDP receive error"
                    );
                }
            }
        }
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests;
