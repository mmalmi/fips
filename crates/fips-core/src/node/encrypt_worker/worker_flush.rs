struct EncryptWorkerShard {
    idx: usize,
    batch: Vec<QueuedFmpSendJob>,
    max_batch: usize,
}

impl EncryptWorkerShard {
    fn new(idx: usize, max_batch: usize) -> Self {
        Self {
            idx,
            batch: Vec::with_capacity(max_batch),
            max_batch,
        }
    }

    fn drain_and_flush_once<R, F>(&mut self, recv_batch: R, flush_batch: F) -> bool
    where
        R: FnOnce(&mut Vec<QueuedFmpSendJob>, usize) -> Option<FmpWorkerBatchStats>,
        F: FnOnce(
            &mut Vec<QueuedFmpSendJob>,
        ) -> Result<(), Box<dyn std::error::Error + Send + Sync>>,
    {
        debug_assert!(self.batch.is_empty());
        let Some(stats) = recv_batch(&mut self.batch, self.max_batch) else {
            return false;
        };
        debug_assert_eq!(stats.packet_count(), self.batch.len());
        // Preserve dequeue order once the worker owns a local batch. Priority
        // queues act before dequeue; sorting here can move small endpoint-data
        // packets ahead of earlier bulk packets for the same TCP-shaped flow.
        crate::perf_profile::record_fmp_worker_batch(
            self.batch.len(),
            stats.priority_packets,
            stats.bulk_packets,
            self.max_batch,
        );
        if let Err(err) = flush_batch(&mut self.batch) {
            debug!(
                worker = self.idx,
                error = %err,
                "FMP encrypt worker batch flush failed"
            );
            self.batch.clear();
        }
        true
    }

    #[cfg(test)]
    fn batch_len(&self) -> usize {
        self.batch.len()
    }
}

struct SealedSendPacket {
    send_target: SelectedSendTarget,
    #[cfg(unix)]
    target_key: SendTargetKey,
    wire_packet: Vec<u8>,
    bulk_endpoint_data: bool,
    drop_on_backpressure: bool,
}

impl SealedSendPacket {
    #[cfg(any(test, not(unix)))]
    fn from_job(job: FmpSendJob) -> Result<Self, SealPacketError> {
        #[cfg(unix)]
        let target_key = job.send_target_key();
        #[cfg(unix)]
        return Self::from_job_with_target_key(job, target_key);

        #[cfg(not(unix))]
        return Self::from_job_without_target_key(job);
    }

    #[cfg(all(
        unix,
        any(test, not(any(target_os = "macos", target_os = "linux")))
    ))]
    fn from_queued(queued: QueuedFmpSendJob) -> Result<Self, SealPacketError> {
        let QueuedFmpSendJob {
            job, target_key, ..
        } = queued;
        Self::from_job_with_target_key(job, target_key)
    }

    #[cfg(unix)]
    fn from_job_with_target_key(
        job: FmpSendJob,
        target_key: SendTargetKey,
    ) -> Result<Self, SealPacketError> {
        Self::from_job_inner(job, target_key)
    }

    #[cfg(not(unix))]
    fn from_job_without_target_key(job: FmpSendJob) -> Result<Self, SealPacketError> {
        Self::from_job_inner(job)
    }

    #[cfg(unix)]
    fn from_job_inner(job: FmpSendJob, target_key: SendTargetKey) -> Result<Self, SealPacketError> {
        let FmpSendJob {
            cipher,
            counter,
            mut wire_buf,
            fsp_seal,
            send_target,
            endpoint_flow_dispatch_key: _,
            bulk_endpoint_data,
            drop_on_backpressure,
            scheduling_weight: _,
            queued_at,
        } = job;
        debug_assert_eq!(
            send_target.key(),
            target_key,
            "sealed packet must keep the queued target key"
        );
        record_fmp_worker_queue_wait(
            encrypt_worker_lane_for_endpoint_data(bulk_endpoint_data),
            queued_at,
        );

        Self::seal_wire_packet(cipher, counter, &mut wire_buf, fsp_seal)?;

        Ok(Self {
            send_target,
            #[cfg(unix)]
            target_key,
            wire_packet: wire_buf,
            bulk_endpoint_data,
            drop_on_backpressure,
        })
    }

    #[cfg(not(unix))]
    fn from_job_inner(job: FmpSendJob) -> Result<Self, SealPacketError> {
        let FmpSendJob {
            cipher,
            counter,
            mut wire_buf,
            fsp_seal,
            send_target,
            endpoint_flow_dispatch_key: _,
            bulk_endpoint_data,
            drop_on_backpressure,
            scheduling_weight: _,
            queued_at,
        } = job;
        record_fmp_worker_queue_wait(
            encrypt_worker_lane_for_endpoint_data(bulk_endpoint_data),
            queued_at,
        );

        Self::seal_wire_packet(cipher, counter, &mut wire_buf, fsp_seal)?;

        Ok(Self {
            send_target,
            wire_packet: wire_buf,
            bulk_endpoint_data,
            drop_on_backpressure,
        })
    }

    fn seal_wire_packet(
        cipher: Arc<LessSafeKey>,
        counter: u64,
        wire_buf: &mut Vec<u8>,
        fsp_seal: Option<FspSealJob>,
    ) -> Result<(), SealPacketError> {
        if let Some(fsp) = fsp_seal {
            if fsp.aad_offset + FSP_HEADER_SIZE > fsp.plaintext_offset
                || fsp.plaintext_offset > wire_buf.len()
            {
                return Err(SealPacketError::InvalidFspLayout);
            }

            let _t =
                crate::perf_profile::Timer::start(crate::perf_profile::Stage::FmpWorkerFspSeal);
            let mut nonce_bytes = [0u8; 12];
            nonce_bytes[4..12].copy_from_slice(&fsp.counter.to_le_bytes());
            let nonce = Nonce::assume_unique_for_key(nonce_bytes);
            let (prefix, plaintext_slice) = wire_buf.split_at_mut(fsp.plaintext_offset);
            let aad = &prefix[fsp.aad_offset..fsp.aad_offset + FSP_HEADER_SIZE];
            let tag = fsp
                .cipher
                .seal_in_place_separate_tag(nonce, Aad::from(aad), plaintext_slice)
                .map_err(|_| SealPacketError::FspSeal)?;
            wire_buf.extend_from_slice(tag.as_ref());
        }

        let _t = crate::perf_profile::Timer::start(crate::perf_profile::Stage::FmpWorkerFmpSeal);
        let mut nonce_bytes = [0u8; 12];
        nonce_bytes[4..12].copy_from_slice(&counter.to_le_bytes());
        let nonce = Nonce::assume_unique_for_key(nonce_bytes);
        // Split-borrow: AAD reads from header bytes [0..16], seal writes into
        // the plaintext slice [16..].
        let (header_slice, plaintext_slice) = wire_buf.split_at_mut(ESTABLISHED_HEADER_SIZE);
        let tag = cipher
            .seal_in_place_separate_tag(nonce, Aad::from(&*header_slice), plaintext_slice)
            .map_err(|_| SealPacketError::FmpSeal)?;
        // wire_buf already has `+16` capacity reserved -> no realloc.
        wire_buf.extend_from_slice(tag.as_ref());
        Ok(())
    }

    #[cfg(unix)]
    fn into_parts(self) -> (SelectedSendTarget, SendTargetKey, Vec<u8>, bool, bool) {
        (
            self.send_target,
            self.target_key,
            self.wire_packet,
            self.bulk_endpoint_data,
            self.drop_on_backpressure,
        )
    }

    #[cfg(not(unix))]
    fn into_parts(self) -> (SelectedSendTarget, Vec<u8>, bool, bool) {
        (
            self.send_target,
            self.wire_packet,
            self.bulk_endpoint_data,
            self.drop_on_backpressure,
        )
    }

    #[cfg(all(test, unix))]
    fn target_key(&self) -> SendTargetKey {
        self.target_key
    }

    #[cfg(test)]
    fn wire_packet(&self) -> &[u8] {
        &self.wire_packet
    }

    #[cfg(test)]
    fn drop_on_backpressure(&self) -> bool {
        self.drop_on_backpressure
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SealPacketError {
    InvalidFspLayout,
    FspSeal,
    FmpSeal,
}

/// Sync OS-thread worker loop. Blocks on the bounded fair queue,
/// drains follow-on packets into a fixed-size local batch, then issues
/// one `sendmmsg(2)` per drain cycle.
#[cfg(not(target_os = "macos"))]
fn run_worker(idx: usize, mut rx: FairWorkerReceiver) {
    trace!(worker = idx, "FMP encrypt worker thread starting");

    let mut shard = EncryptWorkerShard::new(idx, worker_batch_size());

    while shard.drain_and_flush_once(|batch, max| rx.recv_batch(batch, max), flush_batch_sync) {}
    trace!(worker = idx, "FMP encrypt worker thread exiting");
}

#[cfg(target_os = "macos")]
fn run_worker_macos(idx: usize, rx: MacWorkerReceiver) {
    trace!(worker = idx, "FMP encrypt worker thread starting");

    let batch_size = macos_worker_batch_size();
    let mut shard = EncryptWorkerShard::new(idx, batch_size);

    while shard.drain_and_flush_once(|batch, max| rx.recv_batch(batch, max), flush_batch_sync) {}
    trace!(worker = idx, "FMP encrypt worker thread exiting");
}

/// Encrypt every job in `batch` in place, then issue one or more
/// bulk-send syscalls grouped **by exact send target**. Clears
/// `batch` on return. Sync version — operates directly on the raw
/// nonblocking UDP fd with a retry-on-EAGAIN loop; no tokio reactor.
///
/// **Why grouping is required:** `EncryptWorkerPool::dispatch` hashes
/// the exact send target modulo the worker count to pick a worker — this
/// pins one peer's flow to one worker (FIFO order preserved for TCP), but
/// it does NOT mean every job in a worker's drained batch shares a target.
/// Two different peers can hash to the same worker. The previous
/// implementation cloned `batch[0].socket` /
/// `batch[0].connected_socket` and used them for the entire batch,
/// silently misdirecting packets:
///
/// - **Connected-socket path:** `sendmsg(.., msg_name=NULL)` delivers
///   to the peer cached at `connect(2)` time. Mixing jobs across
///   peers sent all of them to the first peer's connected socket.
/// - **UDP_GSO path:** the super-skb has one `msg_name` + one
///   `UDP_SEGMENT` cmsg. Mixing destinations sent the segmented
///   payload to `packets[0].dest_addr` regardless of each job's
///   intended target.
/// - **Plain `sendmmsg` path:** the kernel honours per-message
///   `msg_name`, so the non-connected fallback was actually safe —
///   but we group anyway for code symmetry and to keep GSO
///   eligibility checks simple.
///
/// **Order preservation:** adjacent packets for the same target keep
/// channel-drain order inside one group, and interleaved targets stay
/// as separate groups in that same drain order. TCP-shaped flows need
/// FIFO within a target, while control/liveness packets for another
/// target must not be pushed behind a later same-target bulk packet.
fn flush_batch_sync(
    batch: &mut Vec<QueuedFmpSendJob>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    if batch.is_empty() {
        return Ok(());
    }

    // FIPS_PERF: one AEAD timer span over the whole worker batch, recorded as
    // per-packet samples so the pipeline readout stays comparable with
    // per-packet queue waits and send counters.
    let packet_count = batch.len();
    let _t = crate::perf_profile::BatchTimer::start(
        crate::perf_profile::Stage::FmpEncrypt,
        packet_count,
    );

    // Per-target encrypted-packet group. Vec layout (not HashMap)
    // because the typical batch has 1 target (hash-by-dest dispatch),
    // 2-3 worst-case under hash collisions. Merge only adjacent packets:
    // reaching backward across an intervening group would turn dequeue
    // order A,B,A into send order A,A,B and can delay a control/liveness
    // packet that arrived between bulk packets.
    #[cfg(unix)]
    let group_packet_capacity = batch.len();
    #[cfg(unix)]
    let mut groups: Vec<SelectedSendBatch> = Vec::with_capacity(1);
    #[cfg(target_os = "macos")]
    let mut macos_completions: Vec<MacCompletionGroup> = Vec::with_capacity(1);

    for queued in batch.drain(..) {
        #[cfg(target_os = "macos")]
        let QueuedFmpSendJob {
            job,
            target_key,
            macos_flow,
            macos_seq,
            ..
        } = queued;

        #[cfg(target_os = "macos")]
        let sealed_result = SealedSendPacket::from_job_with_target_key(job, target_key);
        #[cfg(target_os = "linux")]
        let QueuedFmpSendJob {
            job,
            target_key,
            linux_container,
            linux_container_slot,
            ..
        } = queued;

        #[cfg(target_os = "linux")]
        let sealed_result = SealedSendPacket::from_job_with_target_key(job, target_key);
        #[cfg(all(unix, not(any(target_os = "macos", target_os = "linux"))))]
        let sealed_result = SealedSendPacket::from_queued(queued);
        #[cfg(not(unix))]
        let sealed_result = {
            let QueuedFmpSendJob { job, .. } = queued;
            SealedSendPacket::from_job(job)
        };

        let sealed = match sealed_result {
            Ok(sealed) => sealed,
            Err(_) => {
                #[cfg(target_os = "macos")]
                if let Some(flow) = macos_flow.as_ref() {
                    push_mac_completion(
                        &mut macos_completions,
                        Arc::clone(flow),
                        macos_seq,
                        MacSendItem::Skip,
                    );
                }
                #[cfg(target_os = "linux")]
                if let Some(container) = linux_container.as_ref() {
                    container.skip(linux_container_slot);
                }
                continue;
            }
        };

        #[cfg(target_os = "macos")]
        if let Some(flow) = macos_flow {
            let (_send_target, _target_key, wire_packet, bulk_endpoint_data, drop_on_backpressure) =
                sealed.into_parts();
            push_mac_completion(
                &mut macos_completions,
                flow,
                macos_seq,
                MacSendItem::Packet {
                    packet: wire_packet,
                    bulk_endpoint_data,
                    drop_on_backpressure,
                },
            );
            continue;
        }

        #[cfg(target_os = "linux")]
        if let Some(container) = linux_container {
            let (_send_target, _target_key, wire_packet, _bulk_endpoint_data, drop_on_backpressure) =
                sealed.into_parts();
            container.complete_packet(linux_container_slot, wire_packet, drop_on_backpressure);
            continue;
        }

        #[cfg(unix)]
        {
            let (send_target, target_key, wire_packet, bulk_endpoint_data, drop_on_backpressure) =
                sealed.into_parts();
            push_selected_send_batch_with_capacity(
                &mut groups,
                send_target,
                target_key,
                wire_packet,
                bulk_endpoint_data,
                drop_on_backpressure,
                group_packet_capacity,
            );
        }
        #[cfg(not(unix))]
        {
            // Windows: encrypt worker pool isn't spawned (see
            // lifecycle.rs); this function is unreachable. Drop
            // values explicitly so the compiler sees them as used.
            let _ = sealed;
        }
    }

    #[cfg(target_os = "macos")]
    for group in macos_completions {
        group.complete();
    }

    #[cfg(unix)]
    record_selected_send_groups(&groups);
    #[cfg(unix)]
    let udp_send_packet_count = groups
        .iter()
        .map(SelectedSendBatch::packet_count)
        .sum::<usize>();

    drop(_t); // close the encrypt timer before we open the send timer

    // 2) Bulk send each group via its own raw FD.
    //
    // **Preferred (Linux only): UDP_GSO** — when every wire packet in
    // a group is the same size (last may be shorter, which the kernel
    // handles), one `sendmsg(2)` with the `UDP_SEGMENT` cmsg lets the
    // kernel split one "super-skb" into N on-the-wire UDP datagrams
    // in a single skb-walk. Profiling on AMD VM showed `sendmmsg(2)`
    // taking ~4.5 µs per packet at single-flow TCP rates — the kernel
    // TX path was the actual bottleneck, not the AEAD. UDP_GSO
    // collapses that to ~one walk per group. Same primitive WireGuard
    // kernel + boringtun use to hit 2.5-3.2 Gbps.
    //
    // **Fallback: sendmmsg(2)** — used when sizes differ in the
    // group (FIPS control frames + EndpointData mixed), and after a
    // one-shot EINVAL/EOPNOTSUPP from UDP_GSO sticks the
    // GSO_DISABLED flag. Same retry-on-EAGAIN loop as before.
    //
    // On EAGAIN we `yield_now()` — the kernel UDP socket is in
    // nonblocking mode (`UdpRawSocket::open`), and at line rate the
    // kernel send buffer (8 MiB by `DEFAULT_UDP_SEND_BUF`) is rarely
    // full so this is the cold path.
    #[cfg(unix)]
    let _t2 = crate::perf_profile::BatchTimer::start(
        crate::perf_profile::Stage::UdpSend,
        udp_send_packet_count,
    );

    #[cfg(target_os = "linux")]
    flush_linux_send_batches_sync(groups)?;
    #[cfg(all(unix, not(target_os = "linux")))]
    for group in groups {
        let send_attempt = DirectSendBatchAttempt::from_batch(group);
        if let Err(err) = flush_direct_send_attempt(send_attempt) {
            return Err(format!("sendto failed: {err}").into());
        }
    }
    // Windows: encrypt worker pool isn't spawned at all (see
    // lifecycle.rs), so this function is never reached. The
    // tokio-backed `AsyncUdpSocket::send_to` path on the rx_loop
    // remains the only outbound path on that platform.
    Ok(())
}

#[cfg(target_os = "linux")]
fn flush_linux_send_batches_sync(
    groups: Vec<SelectedSendBatch>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    for group in groups {
        let mut send_attempt = LinuxSendBatchAttempt::from_batch(group);
        let (fd, connected, dest_addr) = send_attempt.target_parts();

        // Within a group, destination is uniform by construction —
        // GSO needs only the size check now. Chunk by payload bytes too:
        // UDP_SEGMENT still hands the kernel one logical UDP payload, so
        // a wide worker/container batch must not exceed the UDP payload
        // length limit even when it contains fewer than 64 segments.
        if !GSO_DISABLED.load(std::sync::atomic::Ordering::Relaxed)
            && send_attempt.gso_eligible_sizes()
        {
            while !send_attempt.is_complete() {
                let chunk_len = linux_gso_safe_chunk_len(send_attempt.remaining_packets());
                match send_batch_gso(
                    fd,
                    &send_attempt.remaining_packets()[..chunk_len],
                    dest_addr,
                    connected,
                ) {
                    Ok(()) => {
                        crate::perf_profile::record_udp_send_gso_batch(chunk_len);
                        send_attempt.mark_sent(chunk_len);
                    }
                    Err(err) if is_gso_capability_error(&err) => {
                        GSO_DISABLED.store(true, std::sync::atomic::Ordering::Relaxed);
                        warn!(
                            error = %err,
                            "UDP_GSO refused by kernel; falling back to sendmmsg for life of process"
                        );
                        // Fall through to sendmmsg for the remaining packets.
                        break;
                    }
                    Err(err) if is_send_backpressure(&err) => {
                        // Send buffer full mid-GSO — fall through to
                        // sendmmsg retry loop for the remaining packets. No
                        // GSO_DISABLED toggle.
                        break;
                    }
                    Err(err) => {
                        return Err(format!("sendmsg+UDP_GSO failed: {err}").into());
                    }
                }
            }
            if send_attempt.is_complete() {
                continue;
            }
        }

        while !send_attempt.is_complete() {
            let n = match send_batch_raw(fd, send_attempt.remaining_packets(), dest_addr, connected)
            {
                Ok(n) => n,
                Err(err) if is_send_backpressure(&err) => {
                    send_attempt.handle_backpressure(&err);
                    continue;
                }
                Err(err) => {
                    return Err(format!("sendmmsg(2) failed: {err}").into());
                }
            };
            if n == 0 {
                break;
            }
            crate::perf_profile::record_udp_send_sendmmsg_batch(n);
            send_attempt.mark_sent(n);
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn linux_gso_safe_chunk_len(packets: &[Vec<u8>]) -> usize {
    debug_assert!(!packets.is_empty());
    let mut total_payload = 0usize;
    let mut count = 0usize;
    for packet in packets.iter().take(LINUX_UDP_SEND_BATCH_MAX) {
        if count > 0
            && total_payload.saturating_add(packet.len()) > LINUX_UDP_GSO_MAX_PAYLOAD
        {
            break;
        }
        total_payload = total_payload.saturating_add(packet.len());
        count += 1;
    }
    count.max(1)
}

#[cfg(all(unix, not(target_os = "linux")))]
fn flush_direct_send_attempt(mut send_attempt: DirectSendBatchAttempt) -> std::io::Result<()> {
    #[cfg(target_os = "macos")]
    {
        MAC_DIRECT_SEND_RATE_PACER.with(|pacer| {
            let mut rate_pacer = pacer.borrow_mut();
            while !send_attempt.is_complete() {
                if let Some(len) = send_attempt.current_bulk_packet_len_for_pacing() {
                    rate_pacer.pace(len);
                }
                send_attempt.send_current()?;
            }
            Ok(())
        })
    }

    #[cfg(not(target_os = "macos"))]
    {
        while !send_attempt.is_complete() {
            send_attempt.send_current()?;
        }
        Ok(())
    }
}

#[cfg(all(test, unix))]
fn flush_direct_batch_sync(
    batch: &mut Vec<FmpSendJob>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut queued: Vec<QueuedFmpSendJob> = batch.drain(..).map(QueuedFmpSendJob::direct).collect();
    flush_batch_sync(&mut queued)
}
