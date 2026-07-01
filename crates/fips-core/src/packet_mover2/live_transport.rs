const TRANSPORT_SEND_WORKER_COALESCE_PACKETS: usize = 64;
const TRANSPORT_SEND_WORKER_DEFAULT_MAX_PACKETS: usize = 4096;
const TRANSPORT_SEND_WORKER_PRIORITY_RESERVE_PACKETS: usize = 64;

#[derive(Debug)]
struct PacketMover2TransportSendJob {
    lane: Lane,
    snapshot: crate::transport::udp::UdpSendSnapshot,
    transport_id: TransportId,
    remote_addr: std::net::SocketAddr,
    packets: Vec<(PacketOutput, std::net::SocketAddr)>,
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
    let owned_packets = job
        .packets
        .into_iter()
        .enumerate()
        .map(|(index, (output, addr))| (index, output.into_payload(), addr))
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
struct PacketMover2TransportSendPlan {
    transport_id: TransportId,
    remote_addr: TransportAddr,
    output: PacketOutput,
}

impl PacketMover2TransportSendPlan {
    fn new(
        transport_id: TransportId,
        remote_addr: TransportAddr,
        output: PacketOutput,
    ) -> Self {
        Self {
            transport_id,
            remote_addr,
            output,
        }
    }

    fn transport_id(&self) -> TransportId {
        self.transport_id
    }

    fn remote_addr(&self) -> &TransportAddr {
        &self.remote_addr
    }

    fn output(&self) -> &PacketOutput {
        &self.output
    }
}

#[derive(Debug, Default)]
struct PacketMover2TransportSendPlanOutput {
    plans: Vec<PacketMover2TransportSendPlan>,
}

impl PacketMover2TransportSendPlanOutput {
    fn new() -> Self {
        Self::default()
    }

    fn clear(&mut self) {
        self.plans.clear();
    }

    fn plans(&self) -> &[PacketMover2TransportSendPlan] {
        &self.plans
    }

    fn take_plans_preserving_capacity(&mut self) -> Vec<PacketMover2TransportSendPlan> {
        let capacity = self.plans.capacity();
        std::mem::replace(&mut self.plans, Vec::with_capacity(capacity))
    }

    fn send_transport(
        &mut self,
        transport_id: TransportId,
        remote_addr: TransportAddr,
        output: PacketOutput,
    ) -> Result<(), PacketMover2OutputError> {
        self.plans.push(PacketMover2TransportSendPlan::new(
            transport_id,
            remote_addr,
            output,
        ));
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

async fn send_packet_mover2_transport_plans_with_worker<R>(
    transports: &R,
    plans: Vec<PacketMover2TransportSendPlan>,
    drops: &mut Vec<PacketMover2OutputDrop>,
    worker: &mut PacketMover2TransportSendWorkerPool,
    mut sent_outputs: Option<&mut Vec<PacketOutput>>,
) -> usize
where
    R: PacketMover2TransportResolver + ?Sized,
{
    if plans.is_empty() {
        return 0;
    }

    let mut sent = 0usize;
    let mut pending_udp = PendingPacketMover2UdpSendJob::default();
    for plan in plans {
        let lane = plan.output().lane();
        let Some(transport) = transports.resolve_packet_mover2_transport(plan.transport_id())
        else {
            drops.push(PacketMover2OutputDrop::from_output(
                plan.output(),
                PacketMover2OutputError::NoRoute,
            ));
            continue;
        };

        let TransportHandle::Udp(udp) = transport else {
            flush_pending_packet_mover2_udp_send_job(
                &mut pending_udp,
                drops,
                worker,
                &mut sent_outputs,
                &mut sent,
            );
            send_non_udp_transport_plan(transport, plan, drops, &mut sent_outputs, &mut sent).await;
            continue;
        };

        if !pending_udp.matches(lane, plan.transport_id(), plan.remote_addr()) {
            flush_pending_packet_mover2_udp_send_job(
                &mut pending_udp,
                drops,
                worker,
                &mut sent_outputs,
                &mut sent,
            );
            let Some((snapshot, socket_addr)) =
                prepare_packet_mover2_udp_worker_target(udp, &plan, drops).await
            else {
                continue;
            };
            pending_udp.reset(
                snapshot,
                lane,
                plan.transport_id(),
                plan.remote_addr().clone(),
                socket_addr,
            );
        }
        pending_udp.validate_and_push(plan, drops);
        if pending_udp.len() >= worker.max_job_packets_for_lane(lane) {
            flush_pending_packet_mover2_udp_send_job(
                &mut pending_udp,
                drops,
                worker,
                &mut sent_outputs,
                &mut sent,
            );
        }
    }
    flush_pending_packet_mover2_udp_send_job(
        &mut pending_udp,
        drops,
        worker,
        &mut sent_outputs,
        &mut sent,
    );
    sent
}

async fn send_non_udp_transport_plan(
    transport: &TransportHandle,
    plan: PacketMover2TransportSendPlan,
    drops: &mut Vec<PacketMover2OutputDrop>,
    sent_outputs: &mut Option<&mut Vec<PacketOutput>>,
    sent: &mut usize,
) {
    match transport
        .send(plan.remote_addr(), plan.output().payload())
        .await
    {
        Ok(_) => {
            *sent += 1;
            if let Some(sent_outputs) = sent_outputs.as_deref_mut() {
                sent_outputs.push(plan.output().clone());
            }
        }
        Err(error) => drops.push(PacketMover2OutputDrop::from_output(
            plan.output(),
            packet_mover2_output_error_for_transport(&error),
        )),
    }
}

async fn prepare_packet_mover2_udp_worker_target(
    udp: &crate::transport::udp::UdpTransport,
    plan: &PacketMover2TransportSendPlan,
    drops: &mut Vec<PacketMover2OutputDrop>,
) -> Option<(crate::transport::udp::UdpSendSnapshot, std::net::SocketAddr)> {
    let snapshot = match udp.send_snapshot() {
        Ok(snapshot) => snapshot,
        Err(error) => {
            drops.push(PacketMover2OutputDrop::from_output(
                plan.output(),
                packet_mover2_output_error_for_transport(&error),
            ));
            return None;
        }
    };
    let socket_addr = match udp.resolve_for_off_task(plan.remote_addr()).await {
        Ok(socket_addr) => socket_addr,
        Err(error) => {
            drops.push(PacketMover2OutputDrop::from_output(
                plan.output(),
                packet_mover2_output_error_for_transport(&error),
            ));
            return None;
        }
    };
    Some((snapshot, socket_addr))
}

#[derive(Default)]
struct PendingPacketMover2UdpSendJob {
    lane: Option<Lane>,
    snapshot: Option<crate::transport::udp::UdpSendSnapshot>,
    transport_id: Option<TransportId>,
    remote_transport_addr: Option<TransportAddr>,
    socket_addr: Option<std::net::SocketAddr>,
    packets: Vec<(PacketOutput, std::net::SocketAddr)>,
}

impl PendingPacketMover2UdpSendJob {
    fn matches(&self, lane: Lane, transport_id: TransportId, remote_addr: &TransportAddr) -> bool {
        self.lane == Some(lane)
            && self.transport_id == Some(transport_id)
            && self.remote_transport_addr.as_ref() == Some(remote_addr)
    }

    fn reset(
        &mut self,
        snapshot: crate::transport::udp::UdpSendSnapshot,
        lane: Lane,
        transport_id: TransportId,
        remote_transport_addr: TransportAddr,
        socket_addr: std::net::SocketAddr,
    ) {
        debug_assert!(self.packets.is_empty());
        self.lane = Some(lane);
        self.snapshot = Some(snapshot);
        self.transport_id = Some(transport_id);
        self.remote_transport_addr = Some(remote_transport_addr);
        self.socket_addr = Some(socket_addr);
    }

    fn validate_and_push(
        &mut self,
        plan: PacketMover2TransportSendPlan,
        drops: &mut Vec<PacketMover2OutputDrop>,
    ) {
        let Some(snapshot) = self.snapshot.as_ref() else {
            drops.push(PacketMover2OutputDrop::from_output(
                plan.output(),
                PacketMover2OutputError::Unavailable,
            ));
            return;
        };
        let Some(socket_addr) = self.socket_addr else {
            drops.push(PacketMover2OutputDrop::from_output(
                plan.output(),
                PacketMover2OutputError::Unavailable,
            ));
            return;
        };
        if let Err(error) = snapshot.validate_packet(plan.output().payload_len(), socket_addr) {
            drops.push(PacketMover2OutputDrop::from_output(
                plan.output(),
                packet_mover2_output_error_for_transport(&error),
            ));
            return;
        }
        self.packets.push((plan.output, socket_addr));
    }

    fn len(&self) -> usize {
        self.packets.len()
    }

    fn take_job(&mut self) -> Option<PacketMover2TransportSendJob> {
        if self.packets.is_empty() {
            return None;
        }
        let lane = self.lane.take()?;
        let snapshot = self.snapshot.take()?;
        let transport_id = self.transport_id.take()?;
        self.remote_transport_addr.take()?;
        let remote_addr = self.socket_addr.take()?;
        Some(PacketMover2TransportSendJob {
            lane,
            snapshot,
            transport_id,
            remote_addr,
            packets: std::mem::take(&mut self.packets),
        })
    }
}

fn flush_pending_packet_mover2_udp_send_job(
    pending: &mut PendingPacketMover2UdpSendJob,
    drops: &mut Vec<PacketMover2OutputDrop>,
    worker: &mut PacketMover2TransportSendWorkerPool,
    sent_outputs: &mut Option<&mut Vec<PacketOutput>>,
    sent: &mut usize,
) {
    let Some(job) = pending.take_job() else {
        return;
    };
    let sent_receipts = if sent_outputs.is_some() {
        Some(
            job.packets
                .iter()
                .map(|(output, _)| output.clone())
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
            for (output, _) in job.packets.drain(..) {
                drops.push(PacketMover2OutputDrop::from_output(
                    &output,
                    PacketMover2OutputError::Unavailable,
                ));
            }
        }
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
