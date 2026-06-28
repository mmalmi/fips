enum PacketMover2AeadJob {
    Open { work: CryptoWork, cipher: AeadKey },
    Seal {
        work: OutboundCryptoWork,
        cipher: AeadKey,
    },
}

impl PacketMover2AeadJob {
    fn lane(&self) -> Lane {
        match self {
            Self::Open { work, .. } => work.reservation.lane,
            Self::Seal { work, .. } => work.reservation.lane,
        }
    }
}

struct PacketMover2QueuedAeadJob {
    job: PacketMover2AeadJob,
    completion_tx: crossbeam_channel::Sender<CryptoCompletion>,
}

struct PacketMover2AeadWorkerPool {
    priority_tx: crossbeam_channel::Sender<PacketMover2QueuedAeadJob>,
    bulk_tx: crossbeam_channel::Sender<PacketMover2QueuedAeadJob>,
}

impl PacketMover2AeadWorkerPool {
    fn spawn() -> Self {
        let workers = packet_mover2_aead_worker_count();
        let (priority_tx, priority_rx) =
            crossbeam_channel::bounded(packet_mover2_aead_priority_queue_cap());
        let (bulk_tx, bulk_rx) = crossbeam_channel::bounded(packet_mover2_aead_bulk_queue_cap());
        for idx in 0..workers {
            let priority_rx = priority_rx.clone();
            let bulk_rx = bulk_rx.clone();
            std::thread::Builder::new()
                .name(format!("pm2-aead-{idx}"))
                .spawn(move || run_packet_mover2_aead_worker(priority_rx, bulk_rx))
                .expect("failed to spawn packet_mover2 AEAD worker");
        }

        Self {
            priority_tx,
            bulk_tx,
        }
    }

    fn execute_jobs_into(
        &self,
        jobs: &mut Vec<PacketMover2AeadJob>,
        completions: &mut Vec<CryptoCompletion>,
    ) {
        let count = jobs.len();
        if count == 0 {
            return;
        }

        let (completion_tx, completion_rx) = crossbeam_channel::bounded(count);
        for job in jobs.drain(..) {
            self.dispatch(PacketMover2QueuedAeadJob {
                job,
                completion_tx: completion_tx.clone(),
            });
        }
        drop(completion_tx);

        for completion in completion_rx.iter().take(count) {
            completions.push(completion);
        }
    }

    fn dispatch(&self, queued: PacketMover2QueuedAeadJob) {
        let lane = queued.job.lane();
        let result = match lane {
            Lane::Priority => self.priority_tx.send(queued),
            Lane::Bulk => self.bulk_tx.send(queued),
        };
        if let Err(error) = result {
            let queued = error.into_inner();
            let completion = packet_mover2_aead_failed_completion(queued.job);
            let _ = queued.completion_tx.send(completion);
        }
    }
}

fn packet_mover2_aead_pool() -> &'static PacketMover2AeadWorkerPool {
    static POOL: std::sync::OnceLock<PacketMover2AeadWorkerPool> = std::sync::OnceLock::new();
    POOL.get_or_init(PacketMover2AeadWorkerPool::spawn)
}

fn packet_mover2_aead_worker_count() -> usize {
    std::thread::available_parallelism()
        .map(std::num::NonZeroUsize::get)
        .unwrap_or(1)
        .clamp(1, 8)
}

fn packet_mover2_aead_priority_queue_cap() -> usize {
    1024
}

fn packet_mover2_aead_bulk_queue_cap() -> usize {
    4096
}

fn run_packet_mover2_aead_worker(
    priority_rx: crossbeam_channel::Receiver<PacketMover2QueuedAeadJob>,
    bulk_rx: crossbeam_channel::Receiver<PacketMover2QueuedAeadJob>,
) {
    loop {
        let queued = match priority_rx.try_recv() {
            Ok(queued) => queued,
            Err(crossbeam_channel::TryRecvError::Disconnected) => break,
            Err(crossbeam_channel::TryRecvError::Empty) => {
                crossbeam_channel::select_biased! {
                    recv(priority_rx) -> msg => match msg {
                        Ok(queued) => queued,
                        Err(_) => break,
                    },
                    recv(bulk_rx) -> msg => match msg {
                        Ok(queued) => queued,
                        Err(_) => break,
                    },
                }
            }
        };

        let completion = execute_packet_mover2_aead_job(queued.job);
        let _ = queued.completion_tx.send(completion);
    }
}

fn execute_packet_mover2_aead_job(job: PacketMover2AeadJob) -> CryptoCompletion {
    match job {
        PacketMover2AeadJob::Open { work, cipher } => {
            let reservation = work.reservation.clone();
            let _timer =
                crate::perf_profile::Timer::start(crate::perf_profile::Stage::PacketMover2AeadOpen);
            match AeadOpenWork::from_crypto_work(work, cipher) {
                Ok(work) => StatelessAeadOpenWorker.execute(work),
                Err(_) => CryptoCompletion {
                    reservation,
                    result: CryptoResult::Failed(CryptoFailureKind::Open),
                },
            }
        }
        PacketMover2AeadJob::Seal { work, cipher } => {
            let reservation = work.reservation.clone();
            let _timer =
                crate::perf_profile::Timer::start(crate::perf_profile::Stage::PacketMover2AeadSeal);
            match AeadSealWork::from_outbound_work(work, cipher) {
                Ok(work) => StatelessAeadSealWorker.execute(work),
                Err(_) => CryptoCompletion {
                    reservation,
                    result: CryptoResult::Failed(CryptoFailureKind::Seal),
                },
            }
        }
    }
}

fn packet_mover2_aead_failed_completion(job: PacketMover2AeadJob) -> CryptoCompletion {
    match job {
        PacketMover2AeadJob::Open { work, .. } => CryptoCompletion {
            reservation: work.reservation,
            result: CryptoResult::Failed(CryptoFailureKind::Open),
        },
        PacketMover2AeadJob::Seal { work, .. } => CryptoCompletion {
            reservation: work.reservation,
            result: CryptoResult::Failed(CryptoFailureKind::Seal),
        },
    }
}
