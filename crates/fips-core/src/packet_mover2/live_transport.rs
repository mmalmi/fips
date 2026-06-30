trait PacketMover2TransportOutput {
    fn send_transport(
        &mut self,
        transport_id: TransportId,
        remote_addr: TransportAddr,
        output: PacketOutput,
    ) -> Result<(), PacketMover2OutputError>;
}

impl<T: PacketMover2TransportOutput + ?Sized> PacketMover2TransportOutput for &mut T {
    fn send_transport(
        &mut self,
        transport_id: TransportId,
        remote_addr: TransportAddr,
        output: PacketOutput,
    ) -> Result<(), PacketMover2OutputError> {
        (**self).send_transport(transport_id, remote_addr, output)
    }
}

const TRANSPORT_PRIORITY_CUT_IN_PACKETS: usize = 32;
const TRANSPORT_SEND_WORKER_COALESCE_PACKETS: usize = 64;
const TRANSPORT_SEND_WORKER_DEFAULT_MAX_PACKETS: usize = 4096;

#[derive(Debug)]
struct PacketMover2TransportSendJob {
    snapshot: crate::transport::udp::UdpSendSnapshot,
    transport_id: TransportId,
    remote_addr: std::net::SocketAddr,
    packets: Vec<(usize, PacketOutput, std::net::SocketAddr)>,
}

#[derive(Debug)]
pub(crate) struct PacketMover2TransportSendWorkerPool {
    senders: Vec<tokio::sync::mpsc::Sender<PacketMover2TransportSendJob>>,
    handles: Vec<tokio::task::JoinHandle<()>>,
    queued_packets: Arc<std::sync::atomic::AtomicUsize>,
    max_queued_packets: usize,
    worker_count: usize,
}

impl PacketMover2TransportSendWorkerPool {
    pub(crate) fn new(max_queued_packets: usize) -> Self {
        let worker_count = packet_mover2_transport_send_worker_count();
        Self {
            senders: Vec::new(),
            handles: Vec::new(),
            queued_packets: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            max_queued_packets: max_queued_packets.max(1),
            worker_count,
        }
    }

    pub(crate) fn default_live() -> Self {
        Self::new(TRANSPORT_SEND_WORKER_DEFAULT_MAX_PACKETS)
    }

    fn try_enqueue(
        &mut self,
        job: PacketMover2TransportSendJob,
    ) -> Result<usize, PacketMover2TransportSendJob> {
        let packet_count = job.packets.len();
        if packet_count == 0 {
            return Ok(0);
        }
        self.ensure_started();
        if !self.try_reserve(packet_count) {
            return Err(job);
        }
        let shard = packet_mover2_transport_send_worker_shard(
            job.transport_id,
            job.remote_addr,
            self.senders.len(),
        );
        match self.senders[shard].try_send(job) {
            Ok(()) => Ok(packet_count),
            Err(error) => {
                self.queued_packets
                    .fetch_sub(packet_count, std::sync::atomic::Ordering::AcqRel);
                Err(error.into_inner())
            }
        }
    }

    fn ensure_started(&mut self) {
        if !self.senders.is_empty() {
            return;
        }
        let worker_count = self.worker_count.max(1);
        self.senders.reserve(worker_count);
        self.handles.reserve(worker_count);
        for worker_idx in 0..worker_count {
            let (tx, rx) = tokio::sync::mpsc::channel(self.max_queued_packets);
            let queued_packets = Arc::clone(&self.queued_packets);
            self.senders.push(tx);
            self.handles.push(tokio::spawn(async move {
                packet_mover2_transport_send_worker_loop(worker_idx, rx, queued_packets).await;
            }));
        }
    }

    fn try_reserve(&self, packet_count: usize) -> bool {
        let mut queued = self
            .queued_packets
            .load(std::sync::atomic::Ordering::Acquire);
        loop {
            let Some(next) = queued.checked_add(packet_count) else {
                return false;
            };
            if next > self.max_queued_packets {
                return false;
            }
            match self.queued_packets.compare_exchange_weak(
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
            if next.transport_id == job.transport_id && next.remote_addr == job.remote_addr {
                job.packets.extend(next.packets);
            } else {
                pending = Some(next);
                break;
            }
        }
        send_packet_mover2_transport_worker_job(job, &queued_packets).await;
    }
}

async fn send_packet_mover2_transport_worker_job(
    job: PacketMover2TransportSendJob,
    queued_packets: &std::sync::atomic::AtomicUsize,
) {
    let packet_count = job.packets.len();
    let _timer = crate::perf_profile::Timer::start(
        crate::perf_profile::Stage::PacketMover2TransportSendWorker,
    );
    let owned_packets = job
        .packets
        .into_iter()
        .map(|(index, output, addr)| (index, output.into_payload(), addr))
        .collect::<Vec<_>>();
    let _ = job.snapshot.send_owned_batch(&owned_packets).await;
    queued_packets.fetch_sub(packet_count, std::sync::atomic::Ordering::AcqRel);
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
}

impl PacketMover2TransportOutput for PacketMover2TransportSendPlanOutput {
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

impl PacketMover2OutputSink for PacketMover2TransportSendPlanOutput {
    fn send(&mut self, output: PacketOutput) -> Result<(), PacketMover2OutputError> {
        let Some((transport_id, remote_addr)) = output.path.as_ref().and_then(|path| match path {
            TransportPath::Live {
                transport_id,
                remote_addr,
            } => Some((*transport_id, remote_addr.clone())),
        }) else {
            return Err(PacketMover2OutputError::NoRoute);
        };
        self.send_transport(transport_id, remote_addr, output)
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

async fn send_packet_mover2_transport_plans_with_bulk_worker<R>(
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
    let mut batch = Vec::new();
    let priority_cut_in_end = send_transport_priority_cut_in(
        transports,
        &plans,
        drops,
        &mut sent_outputs,
        &mut sent,
        &mut batch,
    )
    .await;
    send_remaining_transport_priority_plans(
        transports,
        &plans,
        priority_cut_in_end,
        drops,
        &mut sent,
        &mut batch,
        &mut sent_outputs,
    )
    .await;
    send_bulk_transport_plans_with_worker(
        transports,
        plans,
        drops,
        worker,
        &mut sent_outputs,
        &mut sent,
    )
    .await;
    sent
}

async fn send_remaining_transport_priority_plans<'a, R>(
    transports: &R,
    plans: &'a [PacketMover2TransportSendPlan],
    priority_cut_in_end: usize,
    drops: &mut Vec<PacketMover2OutputDrop>,
    sent: &mut usize,
    batch: &mut Vec<(usize, &'a TransportAddr, &'a [u8])>,
    sent_outputs: &mut Option<&mut Vec<PacketOutput>>,
) where
    R: PacketMover2TransportResolver + ?Sized,
{
    let mut start = 0usize;
    while let Some((range_start, range_end, transport_id)) =
        next_transport_batch_range(plans, start)
    {
        batch.clear();
        append_transport_batch_plans_skipping_priority_before(
            plans,
            range_start,
            range_end,
            Lane::Priority,
            priority_cut_in_end,
            batch,
        );
        send_transport_plan_batch(
            transports,
            plans,
            transport_id,
            batch,
            sent,
            drops,
            sent_outputs,
        )
        .await;
        start = range_end;
    }
}

async fn send_bulk_transport_plans_with_worker<R>(
    transports: &R,
    plans: Vec<PacketMover2TransportSendPlan>,
    drops: &mut Vec<PacketMover2OutputDrop>,
    worker: &mut PacketMover2TransportSendWorkerPool,
    sent_outputs: &mut Option<&mut Vec<PacketOutput>>,
    sent: &mut usize,
) where
    R: PacketMover2TransportResolver + ?Sized,
{
    let mut pending_udp = PendingPacketMover2UdpSendJob::default();
    for (plan_index, plan) in plans.into_iter().enumerate() {
        if plan.output().lane() != Lane::Bulk {
            continue;
        }
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
                sent_outputs,
                sent,
            );
            let result = transport
                .send(plan.remote_addr(), plan.output().payload())
                .await;
            let plans = [plan];
            record_transport_send_result(&plans, 0, result, sent, drops, sent_outputs);
            continue;
        };

        if !pending_udp.matches(plan.transport_id(), plan.remote_addr()) {
            flush_pending_packet_mover2_udp_send_job(
                &mut pending_udp,
                drops,
                worker,
                sent_outputs,
                sent,
            );
            let Some((snapshot, socket_addr)) =
                prepare_packet_mover2_udp_worker_batch(udp, &plan, drops).await
            else {
                continue;
            };
            pending_udp.reset(
                snapshot,
                plan.transport_id(),
                plan.remote_addr().clone(),
                socket_addr,
            );
        }
        let Some(socket_addr) = pending_udp.validate_packet(&plan, drops) else {
            continue;
        };
        pending_udp.push(plan_index, plan, socket_addr);
    }
    flush_pending_packet_mover2_udp_send_job(&mut pending_udp, drops, worker, sent_outputs, sent);
}

async fn prepare_packet_mover2_udp_worker_batch(
    udp: &crate::transport::udp::UdpTransport,
    plan: &PacketMover2TransportSendPlan,
    drops: &mut Vec<PacketMover2OutputDrop>,
) -> Option<(crate::transport::udp::UdpSendSnapshot, std::net::SocketAddr)> {
    let _timer =
        crate::perf_profile::Timer::start(crate::perf_profile::Stage::PacketMover2TransportPrepare);
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
    snapshot: Option<crate::transport::udp::UdpSendSnapshot>,
    transport_id: Option<TransportId>,
    transport_addr: Option<TransportAddr>,
    socket_addr: Option<std::net::SocketAddr>,
    packets: Vec<(usize, PacketOutput, std::net::SocketAddr)>,
}

impl PendingPacketMover2UdpSendJob {
    fn matches(&self, transport_id: TransportId, remote_addr: &TransportAddr) -> bool {
        self.transport_id == Some(transport_id)
            && self.transport_addr.as_ref() == Some(remote_addr)
            && self.snapshot.is_some()
            && self.socket_addr.is_some()
    }

    fn reset(
        &mut self,
        snapshot: crate::transport::udp::UdpSendSnapshot,
        transport_id: TransportId,
        transport_addr: TransportAddr,
        socket_addr: std::net::SocketAddr,
    ) {
        debug_assert!(self.packets.is_empty());
        self.snapshot = Some(snapshot);
        self.transport_id = Some(transport_id);
        self.transport_addr = Some(transport_addr);
        self.socket_addr = Some(socket_addr);
    }

    fn validate_packet(
        &self,
        plan: &PacketMover2TransportSendPlan,
        drops: &mut Vec<PacketMover2OutputDrop>,
    ) -> Option<std::net::SocketAddr> {
        let _timer = crate::perf_profile::Timer::start(
            crate::perf_profile::Stage::PacketMover2TransportPrepare,
        );
        let snapshot = self.snapshot.as_ref()?;
        let socket_addr = self.socket_addr?;
        if let Err(error) = snapshot.validate_packet(plan.output().payload_len(), socket_addr) {
            drops.push(PacketMover2OutputDrop::from_output(
                plan.output(),
                packet_mover2_output_error_for_transport(&error),
            ));
            return None;
        }
        Some(socket_addr)
    }

    fn push(
        &mut self,
        plan_index: usize,
        plan: PacketMover2TransportSendPlan,
        remote_addr: std::net::SocketAddr,
    ) {
        self.packets.push((plan_index, plan.output, remote_addr));
    }

    fn take_job(&mut self) -> Option<PacketMover2TransportSendJob> {
        if self.packets.is_empty() {
            return None;
        }
        let snapshot = self.snapshot.take()?;
        let transport_id = self.transport_id.take()?;
        let remote_addr = self.socket_addr.take()?;
        let _ = self.transport_addr.take();
        Some(PacketMover2TransportSendJob {
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
                .map(|(_, output, _)| output.clone())
                .collect::<Vec<_>>(),
        )
    } else {
        None
    };
    match worker.try_enqueue(job) {
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
                crate::perf_profile::Event::TransportBulkDropped,
                dropped as u64,
            );
            for (_, output, _) in job.packets.drain(..) {
                drops.push(PacketMover2OutputDrop::from_output(
                    &output,
                    PacketMover2OutputError::Unavailable,
                ));
            }
        }
    }
}

async fn send_transport_priority_cut_in<'a, R>(
    transports: &R,
    plans: &'a [PacketMover2TransportSendPlan],
    drops: &mut Vec<PacketMover2OutputDrop>,
    sent_outputs: &mut Option<&mut Vec<PacketOutput>>,
    sent: &mut usize,
    batch: &mut Vec<(usize, &'a TransportAddr, &'a [u8])>,
) -> usize
where
    R: PacketMover2TransportResolver + ?Sized,
{
    let mut start = 0usize;
    let mut remaining = TRANSPORT_PRIORITY_CUT_IN_PACKETS;
    let mut priority_cut_in_end = 0usize;
    while remaining > 0 {
        let Some((range_start, range_end, transport_id)) =
            next_transport_priority_cut_in_batch_range(plans, start, remaining)
        else {
            break;
        };
        batch.clear();
        append_transport_batch_plans(plans, range_start, range_end, Lane::Priority, batch);
        let priority_packets = batch.len();
        send_transport_plan_batch(
            transports,
            plans,
            transport_id,
            batch,
            sent,
            drops,
            sent_outputs,
        )
        .await;
        remaining = remaining.saturating_sub(priority_packets);
        priority_cut_in_end = range_end;
        start = range_end;
    }
    priority_cut_in_end
}

async fn send_transport_plan_batch<'a, R>(
    transports: &R,
    plans: &'a [PacketMover2TransportSendPlan],
    transport_id: TransportId,
    batch: &[(usize, &'a TransportAddr, &'a [u8])],
    sent: &mut usize,
    drops: &mut Vec<PacketMover2OutputDrop>,
    sent_outputs: &mut Option<&mut Vec<PacketOutput>>,
) where
    R: PacketMover2TransportResolver + ?Sized,
{
    if batch.is_empty() {
        return;
    }
    let Some(transport) = transports.resolve_packet_mover2_transport(transport_id) else {
        for (plan_index, _, _) in batch.iter().copied() {
            drops.push(PacketMover2OutputDrop::from_output(
                plans[plan_index].output(),
                PacketMover2OutputError::NoRoute,
            ));
        }
        return;
    };

    if batch.len() == 1 {
        let plan_index = batch[0].0;
        let plan = &plans[plan_index];
        let result = transport
            .send(plan.remote_addr(), plan.output().payload())
            .await;
        record_transport_send_result(plans, plan_index, result, sent, drops, sent_outputs);
        return;
    }

    transport
        .send_batch(batch, |plan_index, result| {
            record_transport_send_result(plans, plan_index, result, sent, drops, sent_outputs);
        })
        .await;
}

fn next_transport_batch_range(
    plans: &[PacketMover2TransportSendPlan],
    start: usize,
) -> Option<(usize, usize, TransportId)> {
    let range_start = start;
    if range_start == plans.len() {
        return None;
    }

    let transport_id = plans[range_start].transport_id;
    let mut range_end = range_start + 1;
    while range_end < plans.len() && plans[range_end].transport_id == transport_id {
        range_end += 1;
    }
    Some((range_start, range_end, transport_id))
}

fn next_transport_priority_cut_in_batch_range(
    plans: &[PacketMover2TransportSendPlan],
    start: usize,
    max_packets: usize,
) -> Option<(usize, usize, TransportId)> {
    if max_packets == 0 {
        return None;
    }
    let mut range_start = start;
    while range_start < plans.len() && plans[range_start].output().lane() != Lane::Priority {
        range_start += 1;
    }
    if range_start == plans.len() {
        return None;
    }

    let transport_id = plans[range_start].transport_id;
    let mut priority_packets = 1usize;
    let mut range_end = range_start + 1;
    while range_end < plans.len() {
        let plan = &plans[range_end];
        if plan.output().lane() == Lane::Priority {
            if plan.transport_id != transport_id || priority_packets == max_packets {
                break;
            }
            priority_packets += 1;
        }
        range_end += 1;
    }
    Some((range_start, range_end, transport_id))
}

fn record_transport_send_result(
    plans: &[PacketMover2TransportSendPlan],
    plan_index: usize,
    result: Result<usize, TransportError>,
    sent: &mut usize,
    drops: &mut Vec<PacketMover2OutputDrop>,
    sent_outputs: &mut Option<&mut Vec<PacketOutput>>,
) {
    let plan = &plans[plan_index];
    match result {
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

fn append_transport_batch_plans<'a>(
    plans: &'a [PacketMover2TransportSendPlan],
    start: usize,
    end: usize,
    lane: Lane,
    batch: &mut Vec<(usize, &'a TransportAddr, &'a [u8])>,
) {
    append_transport_batch_plans_skipping_priority_before(plans, start, end, lane, 0, batch);
}

fn append_transport_batch_plans_skipping_priority_before<'a>(
    plans: &'a [PacketMover2TransportSendPlan],
    start: usize,
    end: usize,
    lane: Lane,
    skip_priority_before: usize,
    batch: &mut Vec<(usize, &'a TransportAddr, &'a [u8])>,
) {
    batch.extend(
        plans[start..end]
            .iter()
            .enumerate()
            .filter_map(|(relative_index, plan)| {
                let plan_index = start + relative_index;
                if plan.output().lane() != lane {
                    return None;
                }
                if lane == Lane::Priority && plan_index < skip_priority_before {
                    return None;
                }
                Some((plan_index, plan.remote_addr(), plan.output().payload()))
            }),
    );
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
