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
    #[cfg(unix)]
    lane: SelectedSendLane,
    wire_packet: Vec<u8>,
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

    #[cfg(unix)]
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
        let lane = SelectedSendLane::for_endpoint_data(bulk_endpoint_data);
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
            #[cfg(unix)]
            lane,
            wire_packet: wire_buf,
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
            drop_on_backpressure,
        })
    }

    fn seal_wire_packet(
        cipher: LessSafeKey,
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
    fn into_parts(
        self,
    ) -> (
        SelectedSendTarget,
        SendTargetKey,
        SelectedSendLane,
        Vec<u8>,
        bool,
    ) {
        (
            self.send_target,
            self.target_key,
            self.lane,
            self.wire_packet,
            self.drop_on_backpressure,
        )
    }

    #[cfg(not(unix))]
    fn into_parts(self) -> (SelectedSendTarget, Vec<u8>, bool) {
        (
            self.send_target,
            self.wire_packet,
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

#[cfg(target_os = "linux")]
fn run_linux_wg_batch_worker(idx: usize, rx: Receiver<LinuxWgEncryptBatch>, max_batch: usize) {
    trace!(worker = idx, "FMP Linux WG-batch encrypt worker starting");

    for mut batch in rx {
        let packet_count = batch.jobs.len();
        if packet_count == 0 {
            batch.ready.complete(Vec::new());
            continue;
        }

        let stats = FmpWorkerBatchStats::from_batch(&batch.jobs);
        crate::perf_profile::record_fmp_worker_batch(
            packet_count,
            stats.priority_packets,
            stats.bulk_packets,
            max_batch,
        );

        let _t = crate::perf_profile::Timer::start(crate::perf_profile::Stage::FmpEncrypt);
        let groups = seal_linux_queued_batch_to_send_groups(&mut batch.jobs);
        drop(_t);
        batch.ready.complete(groups);
    }

    trace!(worker = idx, "FMP Linux WG-batch encrypt worker exiting");
}

#[cfg(target_os = "linux")]
const DEFAULT_LINUX_DEFERRED_SENDER_CAP: usize = 8;
#[cfg(target_os = "linux")]
fn parse_linux_deferred_sender_enabled(raw: Option<&str>) -> bool {
    !matches!(
        raw.map(str::trim),
        Some("0" | "false" | "FALSE" | "False" | "no" | "NO" | "No" | "off" | "OFF" | "Off")
    )
}

#[cfg(target_os = "linux")]
fn linux_deferred_sender_enabled() -> bool {
    static VALUE: OnceLock<bool> = OnceLock::new();
    *VALUE.get_or_init(|| {
        parse_linux_deferred_sender_enabled(std::env::var("FIPS_LINUX_DEFER_UDP_SEND").ok().as_deref())
    })
}

#[cfg(target_os = "linux")]
fn parse_linux_deferred_sender_cap(raw: Option<&str>) -> usize {
    raw.and_then(|raw| raw.trim().parse::<usize>().ok())
        .unwrap_or(DEFAULT_LINUX_DEFERRED_SENDER_CAP)
        .clamp(1, 1024)
}

#[cfg(target_os = "linux")]
fn linux_deferred_sender_cap() -> usize {
    static VALUE: OnceLock<usize> = OnceLock::new();
    *VALUE.get_or_init(|| {
        parse_linux_deferred_sender_cap(
            std::env::var("FIPS_LINUX_DEFERRED_SENDER_CAP")
                .ok()
                .as_deref(),
        )
    })
}

#[cfg(target_os = "linux")]
struct LinuxDeferredSender {
    priority_tx: Sender<Vec<SelectedSendBatch>>,
    bulk_tx: Sender<Vec<SelectedSendBatch>>,
}

#[cfg(target_os = "linux")]
impl LinuxDeferredSender {
    fn send(&self, groups: Vec<SelectedSendBatch>) -> Result<(), LinuxDeferredSendError> {
        let (priority_groups, bulk_groups) = split_linux_deferred_send_groups(groups);
        let mut returned_groups = Vec::new();

        if let Err(err) = try_send_linux_deferred_groups(&self.priority_tx, priority_groups) {
            let closed = err.is_closed();
            returned_groups.extend(err.into_groups());
            returned_groups.extend(bulk_groups);
            return if closed {
                Err(LinuxDeferredSendError::Closed(returned_groups))
            } else {
                Err(LinuxDeferredSendError::Full(returned_groups))
            };
        }
        if let Err(err) = try_send_linux_deferred_groups(&self.bulk_tx, bulk_groups) {
            return Err(err);
        }

        Ok(())
    }
}

#[cfg(target_os = "linux")]
enum LinuxDeferredSendError {
    Full(Vec<SelectedSendBatch>),
    Closed(Vec<SelectedSendBatch>),
}

#[cfg(target_os = "linux")]
impl LinuxDeferredSendError {
    fn is_closed(&self) -> bool {
        matches!(self, Self::Closed(_))
    }

    fn into_groups(self) -> Vec<SelectedSendBatch> {
        match self {
            Self::Full(groups) | Self::Closed(groups) => groups,
        }
    }
}

#[cfg(target_os = "linux")]
fn try_send_linux_deferred_groups(
    tx: &Sender<Vec<SelectedSendBatch>>,
    groups: Vec<SelectedSendBatch>,
) -> Result<(), LinuxDeferredSendError> {
    if groups.is_empty() {
        return Ok(());
    }
    match tx.try_send(groups) {
        Ok(()) => Ok(()),
        Err(TrySendError::Full(groups)) => Err(LinuxDeferredSendError::Full(groups)),
        Err(TrySendError::Disconnected(groups)) => Err(LinuxDeferredSendError::Closed(groups)),
    }
}

#[cfg(target_os = "linux")]
fn split_linux_deferred_send_groups(
    groups: Vec<SelectedSendBatch>,
) -> (Vec<SelectedSendBatch>, Vec<SelectedSendBatch>) {
    let mut priority_groups = Vec::new();
    let mut bulk_groups = Vec::new();
    for group in groups {
        match group.lane() {
            SelectedSendLane::Priority => priority_groups.push(group),
            SelectedSendLane::Bulk => bulk_groups.push(group),
        }
    }
    (priority_groups, bulk_groups)
}

#[cfg(target_os = "linux")]
fn linux_deferred_sender() -> Option<&'static LinuxDeferredSender> {
    static VALUE: OnceLock<Option<LinuxDeferredSender>> = OnceLock::new();
    VALUE
        .get_or_init(|| {
            if !linux_deferred_sender_enabled() {
                return None;
            }
            let cap = linux_deferred_sender_cap();
            let (priority_tx, priority_rx) = bounded(cap);
            let (bulk_tx, bulk_rx) = bounded(cap);
            match std::thread::Builder::new()
                .name("fips-linux-udp-sender".to_string())
                .spawn(move || run_linux_deferred_sender(priority_rx, bulk_rx))
            {
                Ok(_) => Some(LinuxDeferredSender {
                    priority_tx,
                    bulk_tx,
                }),
                Err(err) => {
                    warn!(
                        error = %err,
                        "failed to spawn deferred Linux UDP sender; using synchronous sends"
                    );
                    None
                }
            }
        })
        .as_ref()
}

#[cfg(target_os = "linux")]
fn run_linux_deferred_sender(
    priority_rx: Receiver<Vec<SelectedSendBatch>>,
    bulk_rx: Receiver<Vec<SelectedSendBatch>>,
) {
    loop {
        while let Ok(groups) = priority_rx.try_recv() {
            flush_linux_deferred_send_groups(groups);
        }

        crossbeam_channel::select_biased! {
            recv(priority_rx) -> msg => match msg {
                Ok(groups) => flush_linux_deferred_send_groups(groups),
                Err(_) => break,
            },
            recv(bulk_rx) -> msg => match msg {
                Ok(groups) => flush_linux_deferred_send_groups(groups),
                Err(_) => break,
            },
        }
    }
}

#[cfg(target_os = "linux")]
fn flush_linux_deferred_send_groups(groups: Vec<SelectedSendBatch>) {
    if !groups.is_empty() {
        let _t = crate::perf_profile::Timer::start(crate::perf_profile::Stage::UdpSend);
        if let Err(err) = flush_linux_send_groups_sync(groups) {
            debug!(error = %err, "deferred Linux UDP send failed");
        }
    }
}

#[cfg(target_os = "linux")]
fn seal_linux_queued_batch_to_send_groups(
    batch: &mut Vec<QueuedFmpSendJob>,
) -> Vec<SelectedSendBatch> {
    let group_packet_capacity = batch.len();
    let mut groups = Vec::with_capacity(1);

    for queued in batch.drain(..) {
        let Ok(sealed) = SealedSendPacket::from_queued(queued) else {
            continue;
        };
        let (send_target, target_key, lane, wire_packet, drop_on_backpressure) =
            sealed.into_parts();
        push_selected_send_batch_with_lane_and_capacity(
            &mut groups,
            send_target,
            target_key,
            lane,
            wire_packet,
            drop_on_backpressure,
            group_packet_capacity,
        );
    }

    record_selected_send_groups(&groups);
    groups
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

    // FIPS_PERF: one AEAD timer span over the whole batch — average
    // per-packet falls out of the COUNT increment once per flush.
    let _t = crate::perf_profile::Timer::start(crate::perf_profile::Stage::FmpEncrypt);

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

    for queued in batch.drain(..) {
        #[cfg(unix)]
        let sealed_result = SealedSendPacket::from_queued(queued);
        #[cfg(not(unix))]
        let sealed_result = {
            let QueuedFmpSendJob { job, .. } = queued;
            SealedSendPacket::from_job(job)
        };

        let sealed = match sealed_result {
            Ok(sealed) => sealed,
            Err(_) => continue,
        };

        #[cfg(unix)]
        {
            let (send_target, target_key, lane, wire_packet, drop_on_backpressure) =
                sealed.into_parts();
            push_selected_send_batch_with_lane_and_capacity(
                &mut groups,
                send_target,
                target_key,
                lane,
                wire_packet,
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

    #[cfg(unix)]
    record_selected_send_groups(&groups);

    drop(_t); // close the encrypt timer before we open the send timer

    #[cfg(target_os = "linux")]
    if let Some(sender) = linux_deferred_sender() {
        match sender.send(groups) {
            Ok(()) => return Ok(()),
            Err(err) => {
                if err.is_closed() {
                    warn!("deferred Linux UDP sender closed; falling back to synchronous send");
                }
                groups = err.into_groups();
            }
        }
    }

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
    let _t2 = crate::perf_profile::Timer::start(crate::perf_profile::Stage::UdpSend);

    #[cfg(target_os = "linux")]
    flush_linux_send_groups_sync(groups)?;
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
fn flush_linux_send_groups_sync(
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
            while let Some(len) = send_attempt.current_packet_len() {
                rate_pacer.pace(len);
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
