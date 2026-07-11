use std::cell::UnsafeCell;
use std::sync::{Condvar, LazyLock, Mutex, Weak};
use std::sync::atomic::{
    AtomicBool, AtomicUsize, Ordering::Acquire, Ordering::Relaxed, Ordering::Release,
};

const DATAPLANE_AEAD_WORKER_FAIRNESS_PACKETS: usize = 8;
const DATAPLANE_AEAD_JOB_PACKETS: usize =
    crate::node::FIPS_ENDPOINT_DIRECT_PACKET_RUN_MAX_PACKETS;

pub(crate) struct PreparedCryptoRun {
    run: CryptoOwnerRun,
    cipher: AeadKey,
}

impl PreparedCryptoRun {
    fn open(work: CryptoWork, cipher: AeadKey) -> Self {
        Self {
            run: CryptoOwnerRun::new(
                CryptoOwnerRunItem::open(work),
                DATAPLANE_AEAD_JOB_PACKETS,
            ),
            cipher,
        }
    }

    fn seal(work: OutboundCryptoWork, cipher: AeadKey) -> Self {
        Self {
            run: CryptoOwnerRun::new(
                CryptoOwnerRunItem::seal(work),
                DATAPLANE_AEAD_JOB_PACKETS,
            ),
            cipher,
        }
    }

    fn try_push_open(&mut self, work: CryptoWork) -> Result<(), CryptoWork> {
        if self.run.len() >= DATAPLANE_AEAD_JOB_PACKETS
            || !self.run.matches(
                &work.reservation,
                true,
                work.is_open_fsp_session_payload(),
            )
        {
            return Err(work);
        }
        self.run.push(CryptoOwnerRunItem::open(work));
        Ok(())
    }

    fn try_push_seal(&mut self, work: OutboundCryptoWork) -> Result<(), OutboundCryptoWork> {
        if self.run.len() >= DATAPLANE_AEAD_JOB_PACKETS
            || !self.run.matches(&work.reservation, false, false)
        {
            return Err(work);
        }
        self.run.push(CryptoOwnerRunItem::seal(work));
        Ok(())
    }

    fn lane(&self) -> Lane {
        self.run
            .first_reservation()
            .expect("prepared crypto owner run contains work")
            .lane
    }

    fn into_parts(self) -> (CryptoOwnerRun, AeadKey) {
        (self.run, self.cipher)
    }
}

#[derive(Clone, Debug)]
struct DataplaneAeadWorkerCounters {
    in_flight: Arc<AtomicUsize>,
    bulk_in_flight: Arc<AtomicUsize>,
    ready: Arc<AtomicUsize>,
}

impl DataplaneAeadWorkerCounters {
    fn new() -> Self {
        Self {
            in_flight: Arc::new(AtomicUsize::new(0)),
            bulk_in_flight: Arc::new(AtomicUsize::new(0)),
            ready: Arc::new(AtomicUsize::new(0)),
        }
    }

    fn add(&self, count: usize, bulk_count: usize) {
        self.in_flight.fetch_add(count, Relaxed);
        if bulk_count > 0 {
            self.bulk_in_flight.fetch_add(bulk_count, Relaxed);
        }
    }

    fn mark_ready(&self, count: usize) {
        self.ready.fetch_add(count, Relaxed);
    }

    fn retire(&self, count: usize, bulk_count: usize) {
        self.in_flight.fetch_sub(count, Relaxed);
        self.ready.fetch_sub(count, Relaxed);
        if bulk_count > 0 {
            self.bulk_in_flight.fetch_sub(bulk_count, Relaxed);
        }
    }
}

#[derive(Debug)]
pub(crate) struct CryptoReadySlot {
    owner_shard: usize,
    owner: OwnerId,
    generation: u64,
    lane: Lane,
    first_order: OrderToken,
    len: usize,
    open_fsp_session_payload: AtomicBool,
    ready: AtomicBool,
    items: CryptoReadyItems,
    counters: Option<DataplaneAeadWorkerCounters>,
}

#[derive(Debug)]
struct CryptoReadyItems(UnsafeCell<Option<Vec<CryptoOwnerRunItem>>>);

// One crypto worker owns the whole item vector until it publishes the ready flag.
unsafe impl Sync for CryptoReadyItems {}

impl CryptoReadyItems {
    fn new(items: Vec<CryptoOwnerRunItem>) -> Self {
        Self(UnsafeCell::new(Some(items)))
    }

    /// # Safety
    /// This may run once, and `take` must not run until it publishes readiness.
    unsafe fn execute(&self, cipher: &AeadKey, is_open: bool) -> bool {
        let items = unsafe {
            (*self.0.get())
                .as_ref()
                .expect("AEAD owner run items already retired")
        };
        execute_crypto_owner_run(items, cipher, is_open)
    }

    /// # Safety
    /// All subruns must be finished, and this method may be called only once.
    unsafe fn take(&self) -> Vec<CryptoOwnerRunItem> {
        unsafe {
            (*self.0.get())
                .take()
                .expect("ready AEAD results already taken")
        }
    }
}

impl CryptoReadySlot {
    fn new(run: CryptoOwnerRun, counters: DataplaneAeadWorkerCounters) -> Self {
        let reservation = run
            .first_reservation()
            .expect("crypto owner run contains work");
        let owner_shard = reservation.owner_shard();
        let owner = reservation.owner;
        let generation = reservation.generation;
        let lane = reservation.lane;
        let first_order = reservation.order;
        let len = run.len();
        let open_fsp_session_payload = run.is_open_fsp_session_payload_run();
        Self {
            owner_shard,
            owner,
            generation,
            lane,
            first_order,
            len,
            open_fsp_session_payload: AtomicBool::new(open_fsp_session_payload),
            ready: AtomicBool::new(false),
            items: CryptoReadyItems::new(run.items),
            counters: Some(counters),
        }
    }

    pub(crate) fn completed(completion: CryptoCompletion) -> Arc<Self> {
        Self::from_completed_items(vec![CryptoOwnerRunItem::completed(completion)])
    }

    #[cfg(test)]
    fn completed_run(completions: Vec<CryptoCompletion>) -> Arc<Self> {
        Self::from_completed_items(
            completions
                .into_iter()
                .map(CryptoOwnerRunItem::completed)
                .collect(),
        )
    }

    fn from_completed_items(items: Vec<CryptoOwnerRunItem>) -> Arc<Self> {
        let reservation = &items
            .first()
            .expect("completed owner slot contains a result")
            .reservation;
        debug_assert!(items.iter().enumerate().all(|(index, item)| {
            item.reservation.owner_shard() == reservation.owner_shard()
                && item.reservation.owner == reservation.owner
                && item.reservation.generation == reservation.generation
                && item.reservation.lane == reservation.lane
                && item.reservation.order.0
                    == reservation.order.0.wrapping_add(index as u64)
        }));
        Arc::new(Self {
            owner_shard: reservation.owner_shard(),
            owner: reservation.owner,
            generation: reservation.generation,
            lane: reservation.lane,
            first_order: reservation.order,
            len: items.len(),
            open_fsp_session_payload: AtomicBool::new(false),
            ready: AtomicBool::new(true),
            items: CryptoReadyItems::new(items),
            counters: None,
        })
    }

    fn complete(&self) {
        if let Some(counters) = &self.counters {
            counters.mark_ready(self.len());
        }
        crate::perf_profile::record_dataplane_aead_ready_slot(self.len());
        self.ready.store(true, Release);
    }

    pub(crate) fn is_ready(&self) -> bool {
        self.ready.load(Acquire)
    }

    pub(crate) fn len(&self) -> usize {
        self.len
    }

    fn take_results(&self) -> Vec<CryptoOwnerRunItem> {
        assert!(self.is_ready(), "owner retired an unready AEAD slot");
        // Ready is published only after every subrun finishes; owner retirement is single-threaded.
        unsafe { self.items.take() }
    }

    fn retire(&self, count: usize) {
        if let Some(counters) = &self.counters {
            let bulk_count = if self.lane == Lane::Bulk { count } else { 0 };
            counters.retire(count, bulk_count);
        }
    }

    fn may_be_open_fsp_session_payload_run(&self) -> bool {
        self.open_fsp_session_payload.load(Relaxed)
    }

    pub(crate) fn owner_shard(&self) -> usize {
        self.owner_shard
    }

    pub(crate) fn owner(&self) -> OwnerId {
        self.owner
    }

    pub(crate) fn generation(&self) -> u64 {
        self.generation
    }

    pub(crate) fn lane(&self) -> Lane {
        self.lane
    }

    pub(crate) fn first_order(&self) -> OrderToken {
        self.first_order
    }
}

#[derive(Debug)]
struct PreparedCryptoOwnerRun {
    slot: Arc<CryptoReadySlot>,
    cipher: AeadKey,
    is_open: bool,
    readiness_notify: Arc<tokio::sync::Notify>,
    queued_at: Option<crate::perf_profile::TraceStamp>,
}

#[derive(Debug, Default)]
struct CryptoOwnerRunQueue {
    priority: VecDeque<PreparedCryptoOwnerRun>,
    bulk: VecDeque<PreparedCryptoOwnerRun>,
    priority_packets_with_bulk_waiting: usize,
    closed: bool,
}

#[derive(Debug)]
struct CryptoWorkerQueue {
    runs: Mutex<CryptoOwnerRunQueue>,
    available: Condvar,
}

impl CryptoWorkerQueue {
    fn new() -> Self {
        Self {
            runs: Mutex::new(CryptoOwnerRunQueue::default()),
            available: Condvar::new(),
        }
    }

    fn push(&self, run: PreparedCryptoOwnerRun) {
        let lane = run.slot.lane();
        let mut runs = self.runs.lock().expect("AEAD worker queue poisoned");
        assert!(!runs.closed, "AEAD worker queue closed");
        match lane {
            Lane::Priority => runs.priority.push_back(run),
            Lane::Bulk => runs.bulk.push_back(run),
        }
        drop(runs);
        self.available.notify_one();
    }

    fn pop(&self) -> Option<PreparedCryptoOwnerRun> {
        let mut runs = self.runs.lock().expect("AEAD worker queue poisoned");
        loop {
            let run = if runs.bulk.is_empty() {
                runs.priority_packets_with_bulk_waiting = 0;
                runs.priority.pop_front()
            } else if runs.priority.is_empty()
                || runs.priority_packets_with_bulk_waiting
                    >= DATAPLANE_AEAD_WORKER_FAIRNESS_PACKETS
            {
                runs.priority_packets_with_bulk_waiting = 0;
                runs.bulk.pop_front()
            } else {
                let run = runs.priority.pop_front();
                if let Some(run) = &run {
                    runs.priority_packets_with_bulk_waiting = runs
                        .priority_packets_with_bulk_waiting
                        .saturating_add(run.slot.len());
                }
                run
            };
            if let Some(run) = run {
                return Some(run);
            }
            if runs.closed {
                return None;
            }
            runs = self
                .available
                .wait(runs)
                .expect("AEAD worker queue poisoned");
        }
    }

    fn close(&self) {
        let mut runs = self.runs.lock().expect("AEAD worker queue poisoned");
        runs.closed = true;
        drop(runs);
        self.available.notify_all();
    }
}

#[derive(Debug)]
struct NativeExecutor {
    worker_queue: Arc<CryptoWorkerQueue>,
    workers: Vec<std::thread::JoinHandle<()>>,
}

impl NativeExecutor {
    fn try_new() -> std::io::Result<Self> {
        let worker_queue = Arc::new(CryptoWorkerQueue::new());
        let worker_count = dataplane_aead_worker_count();
        let mut workers = Vec::with_capacity(worker_count);
        for index in 0..worker_count {
            let queue = Arc::clone(&worker_queue);
            let worker = std::thread::Builder::new()
                .name(format!("fips-aead-{index}"))
                .spawn(move || {
                    // A popped ordered run cannot be reconstructed after a panic.
                    if std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                        run_crypto_worker(queue)
                    }))
                    .is_err()
                    {
                        std::process::abort();
                    }
                });
            match worker {
                Ok(worker) => workers.push(worker),
                Err(error) => {
                    worker_queue.close();
                    for worker in workers {
                        let _ = worker.join();
                    }
                    return Err(error);
                }
            }
        }

        Ok(Self {
            worker_queue,
            workers,
        })
    }
}

static NATIVE_EXECUTOR: LazyLock<(Mutex<Option<Weak<NativeExecutor>>>, Condvar)> =
    LazyLock::new(|| (Mutex::new(None), Condvar::new()));

fn acquire_native_executor() -> Arc<NativeExecutor> {
    let (registry, released) = &*NATIVE_EXECUTOR;
    let mut registered = registry.lock().expect("native AEAD registry poisoned");
    loop {
        match registered.as_ref() {
            Some(executor) => match executor.upgrade() {
                Some(executor) => return executor,
                None => {
                    registered = released
                        .wait(registered)
                        .expect("native AEAD registry poisoned");
                }
            },
            None => {
                let executor = match NativeExecutor::try_new() {
                    Ok(executor) => Arc::new(executor),
                    Err(error) => {
                        drop(registered);
                        panic!("failed to spawn dataplane AEAD workers: {error}");
                    }
                };
                *registered = Some(Arc::downgrade(&executor));
                return executor;
            }
        }
    }
}

impl Drop for NativeExecutor {
    fn drop(&mut self) {
        let (registry, released) = &*NATIVE_EXECUTOR;
        let mut registered = registry.lock().expect("native AEAD registry poisoned");
        debug_assert!(registered
            .as_ref()
            .is_some_and(|executor| std::ptr::eq(executor.as_ptr(), self)));
        self.worker_queue.close();
        let worker_failed = self
            .workers
            .drain(..)
            .fold(false, |failed, worker| worker.join().is_err() || failed);
        *registered = None;
        released.notify_all();
        drop(registered);
        if worker_failed && !std::thread::panicking() {
            panic!("dataplane AEAD worker failed");
        }
    }
}

#[derive(Debug)]
pub(crate) struct DataplaneAeadWorkerPool {
    readiness_notify: Arc<tokio::sync::Notify>,
    native_executor: Option<Arc<NativeExecutor>>,
    counters: DataplaneAeadWorkerCounters,
    max_in_flight: usize,
}

impl DataplaneAeadWorkerPool {
    pub(crate) fn new(max_in_flight: usize) -> Self {
        Self {
            readiness_notify: Arc::new(tokio::sync::Notify::new()),
            native_executor: None,
            counters: DataplaneAeadWorkerCounters::new(),
            max_in_flight: max_in_flight.max(1),
        }
    }

    pub(crate) fn readiness_notify(&self) -> Arc<tokio::sync::Notify> {
        Arc::clone(&self.readiness_notify)
    }

    pub(crate) fn record_perf_depths(&self) {
        if !crate::perf_profile::enabled() {
            return;
        }
        crate::perf_profile::record_event_count(
            crate::perf_profile::Event::DataplaneAeadInFlight,
            self.counters.in_flight.load(Relaxed) as u64,
        );
        let completion_depth = self.counters.ready.load(Relaxed);
        crate::perf_profile::record_event_count(
            crate::perf_profile::Event::DataplaneAeadReadyPackets,
            completion_depth as u64,
        );
    }

    fn available_capacity(&self) -> usize {
        self.max_in_flight.saturating_sub(
            self.counters.in_flight.load(Relaxed),
        )
    }

    fn available_capacity_for_lane(&self, lane: Lane) -> usize {
        let total_available = self.available_capacity();
        if lane == Lane::Priority {
            return total_available;
        }
        let bulk_limit =
            self.max_in_flight
                .saturating_sub(dataplane_aead_worker_priority_reserve(
                    self.max_in_flight,
                ));
        let bulk_in_flight = self
            .counters
            .bulk_in_flight
            .load(Relaxed);
        bulk_limit.saturating_sub(bulk_in_flight).min(total_available)
    }

    fn prepare_owner_run(
        &self,
        run: CryptoOwnerRun,
        cipher: AeadKey,
    ) -> PreparedCryptoOwnerRun {
        let len = run.len();
        let bulk_count = run.bulk_count();
        let is_open = run.is_open();
        self.counters.add(len, bulk_count);
        let slot = Arc::new(CryptoReadySlot::new(run, self.counters.clone()));
        PreparedCryptoOwnerRun {
            slot,
            cipher,
            is_open,
            readiness_notify: Arc::clone(&self.readiness_notify),
            queued_at: crate::perf_profile::stamp(),
        }
    }

    fn submit_owner_run(&mut self, run: PreparedCryptoOwnerRun) {
        let run_len = run.slot.len();
        self.native_executor
            .get_or_insert_with(acquire_native_executor)
            .worker_queue
            .push(run);
        crate::perf_profile::record_dataplane_aead_prepared_job(run_len);
    }

    fn submit_prepared_chunk(
        &mut self,
        prepared: &mut Vec<PreparedCryptoRun>,
        mut stage: impl FnMut(Arc<CryptoReadySlot>),
    ) {
        for prepared in prepared.drain(..) {
            let (run, cipher) = prepared.into_parts();
            let run = self.prepare_owner_run(run, cipher);
            stage(Arc::clone(&run.slot));
            self.submit_owner_run(run);
        }
    }
}

fn run_crypto_worker(queue: Arc<CryptoWorkerQueue>) {
    while let Some(prepared) = queue.pop() {
        crate::perf_profile::record_since(
            crate::perf_profile::Stage::DataplaneAeadWorkerQueueWait,
            prepared.queued_at,
        );
        // The queue gives one worker exclusive ownership until the run is ready.
        let crypto_succeeded = unsafe {
            prepared
                .slot
                .items
                .execute(&prepared.cipher, prepared.is_open)
        };
        if !crypto_succeeded {
            prepared.slot.open_fsp_session_payload.store(false, Relaxed);
        }
        prepared.slot.complete();
        prepared.readiness_notify.notify_one();
    }
}

fn execute_crypto_owner_run(
    items: &[CryptoOwnerRunItem],
    cipher: &AeadKey,
    is_open: bool,
) -> bool {
    let _open_timer = is_open.then(|| {
        crate::perf_profile::Timer::start(crate::perf_profile::Stage::DataplaneAeadOpen)
    });
    let failed = if is_open {
        CryptoFailureKind::Open
    } else {
        CryptoFailureKind::Seal
    };
    let mut succeeded = true;
    for item in items {
        // The caller owns a unique subrun range, so this worker is the item's sole writer.
        let state = unsafe { item.begin_crypto(failed) };
        let result = match state {
            CryptoOwnerRunItemState::Open(packet) => {
                execute_open_crypto_work(packet, &item.reservation, cipher)
            }
            CryptoOwnerRunItemState::Seal(packet) => {
                execute_seal_crypto_work(packet, &item.reservation, cipher)
            }
            CryptoOwnerRunItemState::Completed(_) => panic!("crypto owner run executed twice"),
        };
        succeeded &= !matches!(&result, CryptoResult::Failed(_));
        // Paired with begin_crypto by the same sole writer.
        unsafe { item.complete_crypto(result) };
    }
    succeeded
}

fn dataplane_aead_worker_count() -> usize {
    let parallelism = std::thread::available_parallelism()
        .map_or(1, std::num::NonZeroUsize::get);
    parallelism.saturating_sub(1).max(1)
}

fn dataplane_aead_worker_priority_reserve(max_in_flight: usize) -> usize {
    max_in_flight
        .saturating_sub(DATAPLANE_AEAD_WORKER_FAIRNESS_PACKETS)
        .min(DATAPLANE_AEAD_WORKER_FAIRNESS_PACKETS)
}

impl std::fmt::Debug for PreparedCryptoRun {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PreparedCryptoRun")
            .field("len", &self.run.len())
            .finish_non_exhaustive()
    }
}

fn failed_crypto_completion(
    reservation: OwnerReservation,
    kind: CryptoFailureKind,
) -> CryptoCompletion {
    CryptoCompletion {
        reservation,
        result: CryptoResult::Failed(kind),
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum AeadHeader {
    Fmp([u8; FMP_ESTABLISHED_HEADER_SIZE]),
    Fsp([u8; FSP_HEADER_SIZE]),
}

impl AeadHeader {
    fn as_aad(&self) -> &[u8] {
        match self {
            Self::Fmp(header) => header,
            Self::Fsp(header) => header,
        }
    }
}

fn execute_open_crypto_work(
    mut packet: SocketPacket,
    reservation: &OwnerReservation,
    cipher: &LessSafeKey,
) -> CryptoResult {
    let aad_len = match packet.owner.protocol {
        PacketProtocol::Fmp => FMP_ESTABLISHED_HEADER_SIZE,
        PacketProtocol::Fsp => FSP_HEADER_SIZE,
    };
    let ciphertext_offset = usize::from(packet.ciphertext_offset);
    let wire_flags = packet.wire_flags;

    let target = packet.output;
    let source_wire_len = packet.payload.len();
    let plaintext_len = {
        if aad_len > ciphertext_offset || ciphertext_offset > packet.payload.len() {
            return CryptoResult::Failed(CryptoFailureKind::Open);
        }
        let (prefix, ciphertext) = packet.payload.as_mut_slice().split_at_mut(ciphertext_offset);
        let Some(aad) = prefix.get(..aad_len) else {
            return CryptoResult::Failed(CryptoFailureKind::Open);
        };
        let nonce = aead_nonce(reservation.counter);
        let Ok(plaintext) = cipher.open_in_place(nonce, Aad::from(aad), ciphertext) else {
            return CryptoResult::Failed(CryptoFailureKind::Open);
        };
        plaintext.len()
    };
    packet.payload.truncate(ciphertext_offset + plaintext_len);
    CryptoResult::Opened(PacketOutput {
        owner: reservation.owner,
        counter: reservation.counter,
        ingress_seq: reservation.ingress_seq,
        lane: reservation.lane,
        target,
        source_path: reservation.source_path.clone(),
        previous_hop: reservation.previous_hop,
        ce_flag: reservation.ce_flag,
        path_mtu: reservation.path_mtu,
        wire_flags,
        opened_payload_offset: packet.ciphertext_offset,
        source_peer: reservation.source_peer,
        path: reservation.output_path.clone(),
        activity_tick: reservation.activity_tick,
        fmp_timestamp_ms: reservation.fmp_timestamp_ms,
        source_wire_len: Some(source_wire_len),
        fsp_send_receipt: None,
        send_token: reservation.send_token,
        payload: packet.payload,
    })
}

fn execute_seal_crypto_work(
    mut packet: OutboundPacket,
    reservation: &OwnerReservation,
    cipher: &LessSafeKey,
) -> CryptoResult {
    let _timer = crate::perf_profile::Timer::start(crate::perf_profile::Stage::DataplaneAeadSeal);
    let inner_prefix = match packet.crypto_plaintext_prefix(
        reservation.fmp_timestamp_ms,
        reservation.fsp_timestamp_ms,
    ) {
        Ok(prefix) => prefix,
        Err(_) => return CryptoResult::Failed(CryptoFailureKind::Seal),
    };
    let Ok(payload_len) = u16::try_from(inner_prefix.len().saturating_add(packet.payload.len()))
    else {
        return CryptoResult::Failed(CryptoFailureKind::Seal);
    };
    let (header, coord_prefix, ciphertext_offset) = match (packet.owner.protocol, packet.wire) {
            (
                PacketProtocol::Fmp,
                OutboundWire::Fmp {
                    receiver_idx,
                    flags,
                },
            ) => (
                AeadHeader::Fmp(build_fmp_established_header(
                    receiver_idx,
                    reservation.counter,
                    flags,
                    payload_len,
                )),
                Vec::new(),
                FMP_ESTABLISHED_HEADER_SIZE,
            ),
            (PacketProtocol::Fsp, OutboundWire::Fsp { flags }) => {
                let coord_prefix = std::mem::take(&mut packet.fsp_cleartext_prefix);
                if validate_fsp_cleartext_prefix(flags, &coord_prefix).is_err() {
                    return CryptoResult::Failed(CryptoFailureKind::Seal);
                }
                let ciphertext_offset = FSP_HEADER_SIZE + coord_prefix.len();
                let Ok(header) = build_fsp_established_header(
                    reservation.counter,
                    flags,
                    payload_len,
                ) else {
                    return CryptoResult::Failed(CryptoFailureKind::Seal);
                };
                (
                    AeadHeader::Fsp(header),
                    coord_prefix,
                    ciphertext_offset,
                )
            }
            _ => return CryptoResult::Failed(CryptoFailureKind::Seal),
        };

    let aad = header.as_aad();
    let aad_len = aad.len();
    let prefix_len = aad
        .len()
        .saturating_add(coord_prefix.len())
        .saturating_add(inner_prefix.len());
    if packet.payload.try_prepend_slices(
        &[aad, coord_prefix.as_slice(), inner_prefix.as_slice()],
        AEAD_TAG_SIZE,
    ) {
        crate::perf_profile::record_event(crate::perf_profile::Event::DataplaneSealInPlace);
    } else {
        crate::perf_profile::record_event(crate::perf_profile::Event::DataplaneSealAllocated);
        let plaintext = std::mem::take(&mut packet.payload);
        let mut payload = Vec::with_capacity(
            prefix_len
                .saturating_add(plaintext.len())
                .saturating_add(AEAD_TAG_SIZE),
        );
        payload.extend_from_slice(aad);
        payload.extend_from_slice(&coord_prefix);
        payload.extend_from_slice(&inner_prefix);
        payload.extend_from_slice(plaintext.as_slice());
        packet.payload = PacketBuffer::new(payload);
    }

    if aad_len > ciphertext_offset || ciphertext_offset > packet.payload.len() {
        return CryptoResult::Failed(CryptoFailureKind::Seal);
    }
    let nonce = aead_nonce(reservation.counter);
    let (prefix, plaintext) = packet
        .payload
        .as_mut_slice()
        .split_at_mut(ciphertext_offset);
    let Some(aad) = prefix.get(..aad_len) else {
        return CryptoResult::Failed(CryptoFailureKind::Seal);
    };
    let Ok(tag) = cipher.seal_in_place_separate_tag(nonce, Aad::from(aad), plaintext) else {
        return CryptoResult::Failed(CryptoFailureKind::Seal);
    };
    packet.payload.extend_from_slice(tag.as_ref());

    match packet.post_seal {
        OutboundPostSeal::Transport => CryptoResult::Sealed(PacketOutput {
            owner: reservation.owner,
            counter: reservation.counter,
            ingress_seq: reservation.ingress_seq,
            lane: reservation.lane,
            target: OutputTarget::Transport,
            source_path: reservation.source_path.clone(),
            previous_hop: reservation.previous_hop,
            ce_flag: reservation.ce_flag,
            path_mtu: reservation.path_mtu,
            wire_flags: reservation.wire_flags,
            opened_payload_offset: 0,
            source_peer: reservation.source_peer,
            path: reservation.output_path.clone(),
            activity_tick: reservation.activity_tick,
            fmp_timestamp_ms: reservation.fmp_timestamp_ms,
            source_wire_len: None,
            fsp_send_receipt: packet.fsp_send_receipt,
            send_token: reservation.send_token,
            payload: packet.payload,
        }),
        OutboundPostSeal::FmpWrap(route) => {
            let mut output = route
                .into_fmp_outbound(packet.class, packet.payload)
                .with_fsp_send_receipt(DataplaneFspSendReceipt {
                    owner: reservation.owner,
                    counter: reservation.counter,
                });
            if let Some(send_token) = packet.send_token {
                output = output.with_send_token(send_token);
            }
            if let Some(tick) = reservation.activity_tick {
                output = output.with_activity_tick(tick);
            }
            CryptoResult::Outbound(output)
        }
    }
}

fn validate_fsp_cleartext_prefix(flags: u8, prefix: &[u8]) -> Result<(), WireBuildError> {
    if flags & crate::node::session_wire::FSP_FLAG_CP == 0 {
        return if prefix.is_empty() {
            Ok(())
        } else {
            Err(WireBuildError::BadFspCoords)
        };
    }

    crate::node::session_wire::parse_encrypted_coords(prefix)
        .map(|_| ())
        .map_err(|_| WireBuildError::BadFspCoords)
}

fn aead_nonce(counter: u64) -> Nonce {
    let mut nonce_bytes = [0u8; 12];
    nonce_bytes[4..12].copy_from_slice(&counter.to_le_bytes());
    Nonce::assume_unique_for_key(nonce_bytes)
}
