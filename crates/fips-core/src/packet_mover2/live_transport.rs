const TRANSPORT_SEND_WORKER_COALESCE_PACKETS: usize = 64;
const TRANSPORT_SEND_WORKER_DEFAULT_MAX_PACKETS: usize = 4096;
const TRANSPORT_SEND_WORKER_PRIORITY_RESERVE_PACKETS: usize = 64;

#[derive(Debug)]
struct PacketMover2TransportSendJob {
    lane: Lane,
    snapshot: crate::transport::udp::UdpSendSnapshot,
    transport_id: TransportId,
    remote_addr: std::net::SocketAddr,
    packets: Vec<PacketOutput>,
}

#[derive(Debug)]
pub(crate) struct PacketMover2TransportSendWorkerPool {
    senders: Vec<tokio::sync::mpsc::Sender<PacketMover2TransportSendJob>>,
    handles: Vec<tokio::task::JoinHandle<()>>,
    queued_packets: Arc<std::sync::atomic::AtomicUsize>,
    queued_priority_packets: Arc<std::sync::atomic::AtomicUsize>,
    max_queued_packets: usize,
    max_priority_queued_packets: usize,
    worker_count: usize,
}

impl PacketMover2TransportSendWorkerPool {
    pub(crate) fn new(max_queued_packets: usize) -> Self {
        let worker_count = packet_mover2_transport_send_worker_count();
        Self {
            senders: Vec::new(),
            handles: Vec::new(),
            queued_packets: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            queued_priority_packets: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            max_queued_packets: max_queued_packets.max(1),
            max_priority_queued_packets: max_queued_packets
                .max(1)
                .min(TRANSPORT_SEND_WORKER_PRIORITY_RESERVE_PACKETS),
            worker_count,
        }
    }

    pub(crate) fn default_live() -> Self {
        Self::new(TRANSPORT_SEND_WORKER_DEFAULT_MAX_PACKETS)
    }

    fn max_job_packets_for_lane(&self, lane: Lane) -> usize {
        match lane {
            Lane::Priority => self.max_priority_queued_packets,
            Lane::Bulk => self.max_queued_packets,
        }
    }

    fn enqueue(
        &mut self,
        job: PacketMover2TransportSendJob,
    ) -> Result<usize, PacketMover2TransportSendJob> {
        let packet_count = job.packets.len();
        if packet_count == 0 {
            return Ok(0);
        }
        self.ensure_started();
        if !self.try_reserve(job.lane, packet_count) {
            crate::perf_profile::record_event_count(
                crate::perf_profile::Event::PacketMover2TransportSendWorkerBackpressure,
                packet_count as u64,
            );
            return Err(job);
        }
        let shard = packet_mover2_transport_send_worker_shard(
            job.transport_id,
            job.remote_addr,
            self.senders.len(),
        );
        let sender = &self.senders[shard];
        if sender.capacity() == 0 {
            crate::perf_profile::record_event_count(
                crate::perf_profile::Event::PacketMover2TransportSendWorkerBackpressure,
                packet_count as u64,
            );
        }
        match sender.try_send(job) {
            Ok(()) => Ok(packet_count),
            Err(error) => {
                let job = match error {
                    tokio::sync::mpsc::error::TrySendError::Full(job)
                    | tokio::sync::mpsc::error::TrySendError::Closed(job) => job,
                };
                self.release(job.lane, packet_count);
                Err(job)
            }
        }
    }

    fn ensure_started(&mut self) {
        if !self.senders.is_empty() {
            return;
        }
        let worker_count = self.worker_count.max(1);
        let channel_jobs = self
            .max_queued_packets
            .saturating_add(self.max_priority_queued_packets)
            .max(1);
        self.senders.reserve(worker_count);
        self.handles.reserve(worker_count);
        for worker_idx in 0..worker_count {
            let (tx, rx) = tokio::sync::mpsc::channel(channel_jobs);
            let queued_packets = Arc::clone(&self.queued_packets);
            let queued_priority_packets = Arc::clone(&self.queued_priority_packets);
            self.senders.push(tx);
            self.handles.push(tokio::spawn(async move {
                packet_mover2_transport_send_worker_loop(
                    worker_idx,
                    rx,
                    queued_packets,
                    queued_priority_packets,
                )
                .await;
            }));
        }
    }

    fn try_reserve(&self, lane: Lane, packet_count: usize) -> bool {
        if packet_count > self.max_job_packets_for_lane(lane) {
            return false;
        }
        if lane == Lane::Priority
            && !try_reserve_transport_send_packets(
                &self.queued_priority_packets,
                packet_count,
                self.max_priority_queued_packets,
            )
        {
            return false;
        }
        let total_limit = match lane {
            Lane::Priority => self
                .max_queued_packets
                .saturating_add(self.max_priority_queued_packets),
            Lane::Bulk => self.max_queued_packets,
        };
        if !try_reserve_transport_send_packets(&self.queued_packets, packet_count, total_limit) {
            if lane == Lane::Priority {
                self.queued_priority_packets
                    .fetch_sub(packet_count, std::sync::atomic::Ordering::AcqRel);
            }
            return false;
        }
        true
    }

    fn release(&self, lane: Lane, packet_count: usize) {
        self.queued_packets
            .fetch_sub(packet_count, std::sync::atomic::Ordering::AcqRel);
        if lane == Lane::Priority {
            self.queued_priority_packets
                .fetch_sub(packet_count, std::sync::atomic::Ordering::AcqRel);
        }
    }
}

fn try_reserve_transport_send_packets(
    queued_packets: &std::sync::atomic::AtomicUsize,
    packet_count: usize,
    max_queued_packets: usize,
) -> bool {
    let mut queued = queued_packets.load(std::sync::atomic::Ordering::Acquire);
    loop {
        let Some(next) = queued.checked_add(packet_count) else {
            return false;
        };
        if next > max_queued_packets {
            return false;
        }
        match queued_packets.compare_exchange_weak(
            queued,
            next,
            std::sync::atomic::Ordering::AcqRel,
            std::sync::atomic::Ordering::Acquire,
        ) {
            Ok(_) => return true,
            Err(current) => queued = current,
        }
    }
}

impl Default for PacketMover2TransportSendWorkerPool {
    fn default() -> Self {
        Self::default_live()
    }
}

impl Drop for PacketMover2TransportSendWorkerPool {
    fn drop(&mut self) {
        self.senders.clear();
        for handle in self.handles.drain(..) {
            handle.abort();
        }
    }
}

async fn packet_mover2_transport_send_worker_loop(
    _worker_idx: usize,
    mut rx: tokio::sync::mpsc::Receiver<PacketMover2TransportSendJob>,
    queued_packets: Arc<std::sync::atomic::AtomicUsize>,
    queued_priority_packets: Arc<std::sync::atomic::AtomicUsize>,
) {
    let mut pending = None;
    loop {
        let mut job = if let Some(job) = pending.take() {
            job
        } else {
            match rx.recv().await {
                Some(job) => job,
                None => break,
            }
        };
        while job.packets.len() < TRANSPORT_SEND_WORKER_COALESCE_PACKETS {
            let Ok(next) = rx.try_recv() else {
                break;
            };
            if next.lane == job.lane
                && next.transport_id == job.transport_id
                && next.remote_addr == job.remote_addr
            {
                job.packets.extend(next.packets);
            } else {
                pending = Some(next);
                break;
            }
        }
        send_packet_mover2_transport_worker_job(
            job,
            &queued_packets,
            &queued_priority_packets,
        )
        .await;
    }
}

async fn send_packet_mover2_transport_worker_job(
    job: PacketMover2TransportSendJob,
    queued_packets: &std::sync::atomic::AtomicUsize,
    queued_priority_packets: &std::sync::atomic::AtomicUsize,
) {
    let lane = job.lane;
    let packet_count = job.packets.len();
    let _timer = crate::perf_profile::Timer::start(
        crate::perf_profile::Stage::PacketMover2TransportSendWorker,
    );
    let remote_addr = job.remote_addr;
    let owned_packets = job
        .packets
        .into_iter()
        .enumerate()
        .map(|(index, output)| (index, output.into_payload(), remote_addr))
        .collect::<Vec<_>>();
    let failed = job
        .snapshot
        .send_owned_batch(&owned_packets)
        .await
        .into_iter()
        .filter(|(_, result)| result.is_err())
        .count();
    if failed > 0 {
        crate::perf_profile::record_event_count(
            crate::perf_profile::Event::PacketMover2TransportSendWorkerSendFailed,
            failed as u64,
        );
    }
    queued_packets.fetch_sub(packet_count, std::sync::atomic::Ordering::AcqRel);
    if lane == Lane::Priority {
        queued_priority_packets.fetch_sub(packet_count, std::sync::atomic::Ordering::AcqRel);
    }
}

fn packet_mover2_transport_send_worker_count() -> usize {
    std::thread::available_parallelism()
        .map(|count| count.get())
        .unwrap_or(1)
        .max(1)
}

fn packet_mover2_transport_send_worker_shard(
    transport_id: TransportId,
    remote_addr: std::net::SocketAddr,
    shards: usize,
) -> usize {
    use std::hash::{Hash, Hasher};

    let shards = shards.max(1);
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    transport_id.hash(&mut hasher);
    remote_addr.hash(&mut hasher);
    (hasher.finish() as usize) % shards
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct PacketMover2TransportPlanGroup {
    lane: Lane,
    transport_id: TransportId,
    remote_addr: TransportAddr,
    outputs: Vec<PacketOutput>,
}

impl PacketMover2TransportPlanGroup {
    fn new(
        transport_id: TransportId,
        remote_addr: TransportAddr,
        output: PacketOutput,
    ) -> Self {
        let lane = output.lane();
        Self {
            lane,
            transport_id,
            remote_addr,
            outputs: vec![output],
        }
    }

    fn matches(&self, lane: Lane, transport_id: TransportId, remote_addr: &TransportAddr) -> bool {
        self.lane == lane && self.transport_id == transport_id && &self.remote_addr == remote_addr
    }

    fn push(&mut self, output: PacketOutput) {
        debug_assert_eq!(self.lane, output.lane());
        self.outputs.push(output);
    }

    fn len(&self) -> usize {
        self.outputs.len()
    }
}

#[derive(Debug, Default)]
struct PacketMover2TransportSendGroups {
    groups: Vec<PacketMover2TransportPlanGroup>,
}

impl PacketMover2TransportSendGroups {
    fn new() -> Self {
        Self::default()
    }

    fn clear(&mut self) {
        self.groups.clear();
    }

    fn planned_packets(&self) -> usize {
        self.groups.iter().map(PacketMover2TransportPlanGroup::len).sum()
    }

    fn take_groups_preserving_capacity(&mut self) -> Vec<PacketMover2TransportPlanGroup> {
        let capacity = self.groups.capacity();
        std::mem::replace(&mut self.groups, Vec::with_capacity(capacity))
    }

    fn send_transport(
        &mut self,
        transport_id: TransportId,
        remote_addr: TransportAddr,
        output: PacketOutput,
    ) -> Result<(), PacketMover2OutputError> {
        let lane = output.lane();
        if let Some(group) = self.groups.last_mut()
            && group.matches(lane, transport_id, &remote_addr)
        {
            group.push(output);
            return Ok(());
        }
        self.groups
            .push(PacketMover2TransportPlanGroup::new(transport_id, remote_addr, output));
        Ok(())
    }
}

pub(crate) trait PacketMover2TransportResolver {
    fn resolve_packet_mover2_transport(
        &self,
        transport_id: TransportId,
    ) -> Option<&TransportHandle>;
}

impl PacketMover2TransportResolver for HashMap<TransportId, TransportHandle> {
    fn resolve_packet_mover2_transport(
        &self,
        transport_id: TransportId,
    ) -> Option<&TransportHandle> {
        self.get(&transport_id)
    }
}

impl<T: PacketMover2TransportResolver + ?Sized> PacketMover2TransportResolver for &T {
    fn resolve_packet_mover2_transport(
        &self,
        transport_id: TransportId,
    ) -> Option<&TransportHandle> {
        (**self).resolve_packet_mover2_transport(transport_id)
    }
}

async fn send_packet_mover2_transport_groups_with_worker<R>(
    transports: &R,
    groups: Vec<PacketMover2TransportPlanGroup>,
    drops: &mut Vec<PacketMover2OutputDrop>,
    worker: &mut PacketMover2TransportSendWorkerPool,
    mut sent_outputs: Option<&mut Vec<PacketOutput>>,
) -> usize
where
    R: PacketMover2TransportResolver + ?Sized,
{
    if groups.is_empty() {
        return 0;
    }

    let mut sent = 0usize;
    for group in groups {
        let Some(transport) = transports.resolve_packet_mover2_transport(group.transport_id)
        else {
            drop_transport_plan_group(group, drops, PacketMover2OutputError::NoRoute);
            continue;
        };

        let TransportHandle::Udp(udp) = transport else {
            send_non_udp_transport_plan_group(transport, group, drops, &mut sent_outputs, &mut sent)
                .await;
            continue;
        };

        send_udp_transport_plan_group(
            udp,
            group,
            drops,
            worker,
            &mut sent_outputs,
            &mut sent,
        )
        .await;
    }
    sent
}

async fn send_non_udp_transport_plan_group(
    transport: &TransportHandle,
    group: PacketMover2TransportPlanGroup,
    drops: &mut Vec<PacketMover2OutputDrop>,
    sent_outputs: &mut Option<&mut Vec<PacketOutput>>,
    sent: &mut usize,
) {
    for output in group.outputs {
        send_non_udp_transport_output(
            transport,
            &group.remote_addr,
            output,
            drops,
            sent_outputs,
            sent,
        )
        .await;
    }
}

async fn send_non_udp_transport_output(
    transport: &TransportHandle,
    remote_addr: &TransportAddr,
    output: PacketOutput,
    drops: &mut Vec<PacketMover2OutputDrop>,
    sent_outputs: &mut Option<&mut Vec<PacketOutput>>,
    sent: &mut usize,
) {
    match transport.send(remote_addr, output.payload()).await {
        Ok(_) => {
            *sent += 1;
            if let Some(sent_outputs) = sent_outputs.as_deref_mut() {
                sent_outputs.push(output);
            }
        }
        Err(error) => drops.push(PacketMover2OutputDrop::from_output(
            &output,
            packet_mover2_output_error_for_transport(&error),
        )),
    }
}

async fn send_udp_transport_plan_group(
    udp: &crate::transport::udp::UdpTransport,
    group: PacketMover2TransportPlanGroup,
    drops: &mut Vec<PacketMover2OutputDrop>,
    worker: &mut PacketMover2TransportSendWorkerPool,
    sent_outputs: &mut Option<&mut Vec<PacketOutput>>,
    sent: &mut usize,
) {
    let snapshot = match udp.send_snapshot() {
        Ok(snapshot) => snapshot,
        Err(error) => {
            drop_transport_plan_group(
                group,
                drops,
                packet_mover2_output_error_for_transport(&error),
            );
            return;
        }
    };
    let socket_addr = match udp.resolve_for_off_task(&group.remote_addr).await {
        Ok(socket_addr) => socket_addr,
        Err(error) => {
            drop_transport_plan_group(
                group,
                drops,
                packet_mover2_output_error_for_transport(&error),
            );
            return;
        }
    };

    let lane = group.lane;
    let transport_id = group.transport_id;
    let max_job_packets = worker.max_job_packets_for_lane(group.lane);
    let mut packets = Vec::new();
    for output in group.outputs {
        if let Err(error) = snapshot.validate_packet(output.payload_len(), socket_addr) {
            drops.push(PacketMover2OutputDrop::from_output(
                &output,
                packet_mover2_output_error_for_transport(&error),
            ));
            continue;
        }
        packets.push(output);
        if packets.len() >= max_job_packets {
            flush_packet_mover2_udp_send_job(
                PacketMover2TransportSendJob {
                    lane,
                    snapshot: snapshot.clone(),
                    transport_id,
                    remote_addr: socket_addr,
                    packets: std::mem::take(&mut packets),
                },
                drops,
                worker,
                sent_outputs,
                sent,
            );
        }
    }
    flush_packet_mover2_udp_send_job(
        PacketMover2TransportSendJob {
            lane,
            snapshot,
            transport_id,
            remote_addr: socket_addr,
            packets,
        },
        drops,
        worker,
        sent_outputs,
        sent,
    );
}

fn flush_packet_mover2_udp_send_job(
    job: PacketMover2TransportSendJob,
    drops: &mut Vec<PacketMover2OutputDrop>,
    worker: &mut PacketMover2TransportSendWorkerPool,
    sent_outputs: &mut Option<&mut Vec<PacketOutput>>,
    sent: &mut usize,
) {
    if job.packets.is_empty() {
        return;
    }
    let sent_receipts = if sent_outputs.is_some() {
        Some(
            job.packets
                .iter()
                .map(PacketOutput::clone)
                .collect::<Vec<_>>(),
        )
    } else {
        None
    };
    match worker.enqueue(job) {
        Ok(count) => {
            *sent += count;
            if let (Some(sent_outputs), Some(sent_receipts)) =
                (sent_outputs.as_deref_mut(), sent_receipts)
            {
                sent_outputs.extend(sent_receipts);
            }
        }
        Err(mut job) => {
            let dropped = job.packets.len();
            crate::perf_profile::record_event_count(
                crate::perf_profile::Event::PacketMover2TransportSendWorkerDropped,
                dropped as u64,
            );
            for output in job.packets.drain(..) {
                drops.push(PacketMover2OutputDrop::from_output(
                    &output,
                    PacketMover2OutputError::Unavailable,
                ));
            }
        }
    }
}

fn drop_transport_plan_group(
    mut group: PacketMover2TransportPlanGroup,
    drops: &mut Vec<PacketMover2OutputDrop>,
    reason: PacketMover2OutputError,
) {
    for output in group.outputs.drain(..) {
        drops.push(PacketMover2OutputDrop::from_output(&output, reason));
    }
}

fn packet_mover2_output_error_for_transport(error: &TransportError) -> PacketMover2OutputError {
    match error {
        TransportError::MtuExceeded { .. } => PacketMover2OutputError::MtuExceeded,
        error if error.is_local_route_unavailable() => PacketMover2OutputError::NoRoute,
        TransportError::NotStarted | TransportError::NotSupported(_) => {
            PacketMover2OutputError::Unavailable
        }
        _ => PacketMover2OutputError::TransportFailed,
    }
}
