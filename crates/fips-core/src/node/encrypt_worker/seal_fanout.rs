#[cfg(target_os = "linux")]
struct LinuxBatchSealFanoutPool {
    tx: Sender<LinuxBatchSealFanoutJob>,
    helper_count: usize,
}

#[cfg(target_os = "linux")]
struct LinuxBatchSealFanoutJob {
    base: usize,
    jobs: Vec<QueuedFmpSendJob>,
    result_tx: Sender<LinuxBatchSealFanoutResult>,
}

#[cfg(target_os = "linux")]
struct LinuxBatchSealFanoutResult {
    sealed: Vec<(usize, SealedSendPacket)>,
}

#[cfg(target_os = "linux")]
impl LinuxBatchSealFanoutPool {
    fn spawn(helper_count: usize) -> Arc<Self> {
        let queue_cap = linux_batch_seal_queue_cap(helper_count);
        let (tx, rx) = bounded(queue_cap);
        for idx in 0..helper_count {
            let rx: Receiver<LinuxBatchSealFanoutJob> = rx.clone();
            std::thread::Builder::new()
                .name(format!("fips-linux-seal-{idx}"))
                .spawn(move || linux_batch_seal_helper_loop(rx))
                .expect("failed to spawn fips Linux batch seal helper");
        }
        Arc::new(Self { tx, helper_count })
    }
}

#[cfg(target_os = "linux")]
fn linux_batch_seal_helper_loop(rx: Receiver<LinuxBatchSealFanoutJob>) {
    while let Ok(job) = rx.recv() {
        let result = linux_batch_seal_chunk(job.base, job.jobs);
        let _ = job.result_tx.send(result);
    }
}

#[cfg(target_os = "linux")]
fn try_seal_batch_with_linux_fanout(
    batch: &mut Vec<QueuedFmpSendJob>,
) -> Option<Vec<SealedSendPacket>> {
    let pool = linux_batch_seal_fanout_pool()?;
    let batch_len = batch.len();
    if batch_len < linux_batch_seal_min_packets()
        || batch
            .iter()
            .any(|job| job.queue_lane() != EncryptWorkerLane::Bulk)
    {
        return None;
    }

    let chunk_size = linux_batch_seal_chunk_packets();
    let chunk_count = batch_len.div_ceil(chunk_size);
    if chunk_count < 2 {
        return None;
    }

    let helper_budget = pool.helper_count.min(chunk_count.saturating_sub(1));
    if helper_budget == 0 {
        return None;
    }

    let jobs: Vec<QueuedFmpSendJob> = batch.drain(..).collect();
    let (result_tx, result_rx) = bounded(chunk_count);
    let mut pending_helpers = 0usize;
    let mut local_chunks = Vec::new();

    let mut base = 0usize;
    let mut chunk_index = 0usize;
    let mut iter = jobs.into_iter();
    loop {
        let mut chunk = Vec::with_capacity(chunk_size);
        for _ in 0..chunk_size {
            if let Some(job) = iter.next() {
                chunk.push(job);
            } else {
                break;
            }
        }
        if chunk.is_empty() {
            break;
        }

        let chunk_base = base;
        base += chunk.len();
        if chunk_index < helper_budget {
            let job = LinuxBatchSealFanoutJob {
                base: chunk_base,
                jobs: chunk,
                result_tx: result_tx.clone(),
            };
            match pool.tx.try_send(job) {
                Ok(()) => {
                    pending_helpers += 1;
                }
                Err(TrySendError::Full(job)) | Err(TrySendError::Disconnected(job)) => {
                    local_chunks.push((job.base, job.jobs));
                }
            }
        } else {
            local_chunks.push((chunk_base, chunk));
        }
        chunk_index += 1;
    }
    drop(result_tx);

    let mut sealed = Vec::with_capacity(batch_len);
    for (base, chunk) in local_chunks {
        sealed.extend(linux_batch_seal_chunk(base, chunk).sealed);
    }
    for _ in 0..pending_helpers {
        match result_rx.recv() {
            Ok(result) => sealed.extend(result.sealed),
            Err(_) => break,
        }
    }

    sealed.sort_unstable_by_key(|(index, _)| *index);
    Some(sealed.into_iter().map(|(_, packet)| packet).collect())
}

#[cfg(target_os = "linux")]
fn linux_batch_seal_chunk(
    base: usize,
    jobs: Vec<QueuedFmpSendJob>,
) -> LinuxBatchSealFanoutResult {
    let mut sealed = Vec::with_capacity(jobs.len());
    for (offset, queued) in jobs.into_iter().enumerate() {
        if let Ok(packet) = SealedSendPacket::from_queued(queued) {
            sealed.push((base + offset, packet));
        }
    }
    LinuxBatchSealFanoutResult { sealed }
}

#[cfg(target_os = "linux")]
fn linux_batch_seal_fanout_pool() -> Option<Arc<LinuxBatchSealFanoutPool>> {
    static POOL: OnceLock<Option<Arc<LinuxBatchSealFanoutPool>>> = OnceLock::new();
    POOL.get_or_init(|| {
        let helpers = linux_batch_seal_helper_count();
        (helpers > 0).then(|| LinuxBatchSealFanoutPool::spawn(helpers))
    })
    .as_ref()
    .map(Arc::clone)
}

#[cfg(target_os = "linux")]
fn linux_batch_seal_helper_count() -> usize {
    std::env::var("FIPS_LINUX_BATCH_SEAL_HELPERS")
        .ok()
        .and_then(|raw| raw.trim().parse::<usize>().ok())
        .unwrap_or(0)
        .min(16)
}

#[cfg(target_os = "linux")]
fn linux_batch_seal_min_packets() -> usize {
    static VALUE: OnceLock<usize> = OnceLock::new();
    *VALUE.get_or_init(|| {
        std::env::var("FIPS_LINUX_BATCH_SEAL_MIN_PACKETS")
            .ok()
            .and_then(|raw| raw.trim().parse::<usize>().ok())
            .unwrap_or(16)
            .clamp(2, 256)
    })
}

#[cfg(target_os = "linux")]
fn linux_batch_seal_chunk_packets() -> usize {
    static VALUE: OnceLock<usize> = OnceLock::new();
    *VALUE.get_or_init(|| {
        std::env::var("FIPS_LINUX_BATCH_SEAL_CHUNK_PACKETS")
            .ok()
            .and_then(|raw| raw.trim().parse::<usize>().ok())
            .unwrap_or(8)
            .clamp(1, LINUX_UDP_SEND_BATCH_MAX)
    })
}

#[cfg(target_os = "linux")]
fn linux_batch_seal_queue_cap(helper_count: usize) -> usize {
    std::env::var("FIPS_LINUX_BATCH_SEAL_QUEUE_CAP")
        .ok()
        .and_then(|raw| raw.trim().parse::<usize>().ok())
        .unwrap_or_else(|| helper_count.saturating_mul(4).max(1))
        .clamp(1, 4096)
}
