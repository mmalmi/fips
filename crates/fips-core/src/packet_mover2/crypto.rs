pub(crate) enum PreparedCryptoWork {
    Open { work: CryptoWork, cipher: AeadKey },
    Seal {
        work: OutboundCryptoWork,
        cipher: AeadKey,
        wrap_cipher: Option<AeadKey>,
    },
    Completed(CryptoCompletion),
}

const PACKET_MOVER2_AEAD_WORKER_CHUNK_TARGET: usize = 32;

impl PreparedCryptoWork {
    pub(crate) fn open(work: CryptoWork, cipher: AeadKey) -> Self {
        Self::Open { work, cipher }
    }

    pub(crate) fn seal(work: OutboundCryptoWork, cipher: AeadKey) -> Self {
        Self::Seal {
            work,
            cipher,
            wrap_cipher: None,
        }
    }

    pub(crate) fn seal_wrapped(
        work: OutboundCryptoWork,
        cipher: AeadKey,
        wrap_cipher: AeadKey,
    ) -> Self {
        Self::Seal {
            work,
            cipher,
            wrap_cipher: Some(wrap_cipher),
        }
    }

    pub(crate) fn failed(reservation: OwnerReservation, kind: CryptoFailureKind) -> Self {
        Self::Completed(failed_crypto_completion(reservation, kind))
    }

    pub(crate) fn failed_wrapped(
        reservation: OwnerReservation,
        wrap_reservation: OwnerReservation,
        kind: CryptoFailureKind,
    ) -> Self {
        Self::Completed(failed_wrapped_crypto_completion(
            reservation,
            wrap_reservation,
            kind,
        ))
    }

    pub(crate) fn execute(
        self,
        opened: &StatelessAeadOpenWorker,
        sealed: &StatelessAeadSealWorker,
    ) -> CryptoCompletion {
        match self {
            Self::Open { work, cipher } => {
                let reservation = work.reservation.clone();
                let _timer = crate::perf_profile::Timer::start(
                    crate::perf_profile::Stage::PacketMover2AeadOpen,
                );
                match AeadOpenWork::from_crypto_work(work, cipher) {
                    Ok(work) => opened.execute(work),
                    Err(_) => failed_crypto_completion(reservation, CryptoFailureKind::Open),
                }
            }
            Self::Seal {
                work,
                cipher,
                wrap_cipher,
            } => {
                let reservation = work.reservation.clone();
                let wrap_reservation = work.wrap.as_ref().map(|wrap| wrap.reservation.clone());
                let _timer = crate::perf_profile::Timer::start(
                    crate::perf_profile::Stage::PacketMover2AeadSeal,
                );
                match AeadSealWork::from_outbound_work(work, cipher) {
                    Ok(work) => match wrap_cipher {
                        Some(wrap_cipher) => sealed.execute_reserved_wrap(work, wrap_cipher),
                        None => sealed.execute(work),
                    },
                    Err(_) => match wrap_reservation {
                        Some(wrap_reservation) => failed_wrapped_crypto_completion(
                            reservation,
                            wrap_reservation,
                            CryptoFailureKind::Seal,
                        ),
                        None => failed_crypto_completion(reservation, CryptoFailureKind::Seal),
                    },
                }
            }
            Self::Completed(completion) => completion,
        }
    }

    fn push_executor_failed_completions(self, completions: &mut Vec<CryptoCompletion>) {
        match self {
            Self::Open { work, .. } => completions.push(failed_crypto_completion(
                work.reservation,
                CryptoFailureKind::Open,
            )),
            Self::Seal { work, .. } => {
                let reservation = work.reservation;
                match work.wrap {
                    Some(wrap) => completions.push(failed_wrapped_crypto_completion(
                        reservation,
                        wrap.reservation,
                        CryptoFailureKind::Seal,
                    )),
                    None => completions.push(failed_crypto_completion(
                        reservation,
                        CryptoFailureKind::Seal,
                    )),
                }
            }
            Self::Completed(completion) => completions.push(completion),
        }
    }
}

pub(crate) trait PacketMover2CryptoExecutor {
    fn available_capacity(&self) -> usize {
        usize::MAX
    }

    fn execute_prepared_chunk(
        &mut self,
        prepared: &mut Vec<PreparedCryptoWork>,
        completions: &mut Vec<CryptoCompletion>,
    ) -> usize;
}

#[derive(Debug, Default)]
pub(crate) struct InlinePacketMover2CryptoExecutor {
    opened: StatelessAeadOpenWorker,
    sealed: StatelessAeadSealWorker,
}

impl PacketMover2CryptoExecutor for InlinePacketMover2CryptoExecutor {
    fn execute_prepared_chunk(
        &mut self,
        prepared: &mut Vec<PreparedCryptoWork>,
        completions: &mut Vec<CryptoCompletion>,
    ) -> usize {
        completions.clear();
        let count = prepared.len();
        for work in prepared.drain(..) {
            completions.push(work.execute(&self.opened, &self.sealed));
        }
        count
    }
}

#[derive(Debug)]
pub(crate) struct PacketMover2AeadWorkerPool {
    work_tx: Option<crossbeam_channel::Sender<Vec<PreparedCryptoWork>>>,
    completion_rx: Option<crossbeam_channel::Receiver<Vec<CryptoCompletion>>>,
    completion_notify: Arc<tokio::sync::Notify>,
    pending_completions: VecDeque<CryptoCompletion>,
    in_flight: Arc<std::sync::atomic::AtomicUsize>,
    max_in_flight: usize,
    workers: Vec<std::thread::JoinHandle<()>>,
}

impl PacketMover2AeadWorkerPool {
    pub(crate) fn new(worker_count: usize, max_in_flight: usize) -> Self {
        let worker_count = worker_count.max(1);
        let max_in_flight = max_in_flight.max(1);
        let (work_tx, work_rx): (
            crossbeam_channel::Sender<Vec<PreparedCryptoWork>>,
            crossbeam_channel::Receiver<Vec<PreparedCryptoWork>>,
        ) = crossbeam_channel::bounded(max_in_flight);
        let (completion_tx, completion_rx): (
            crossbeam_channel::Sender<Vec<CryptoCompletion>>,
            crossbeam_channel::Receiver<Vec<CryptoCompletion>>,
        ) = crossbeam_channel::bounded(max_in_flight);
        let in_flight = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let completion_notify = Arc::new(tokio::sync::Notify::new());
        let mut workers = Vec::with_capacity(worker_count);
        for worker_idx in 0..worker_count {
            let work_rx = work_rx.clone();
            let completion_tx = completion_tx.clone();
            let in_flight = Arc::clone(&in_flight);
            let completion_notify = Arc::clone(&completion_notify);
            workers.push(
                std::thread::Builder::new()
                    .name(format!("pm2-aeadw-{worker_idx}"))
                    .spawn(move || {
                        let opened = StatelessAeadOpenWorker;
                        let sealed = StatelessAeadSealWorker;
                        while let Ok(mut prepared) = work_rx.recv() {
                            let count = prepared.len();
                            let mut completions = Vec::with_capacity(count);
                            for work in prepared.drain(..) {
                                completions.push(work.execute(&opened, &sealed));
                            }
                            if completion_tx.send(completions).is_err() {
                                in_flight
                                    .fetch_sub(count, std::sync::atomic::Ordering::AcqRel);
                                break;
                            }
                            completion_notify.notify_one();
                        }
                    })
                    .expect("spawn packet_mover2 AEAD worker"),
            );
        }

        Self {
            work_tx: Some(work_tx),
            completion_rx: Some(completion_rx),
            completion_notify,
            pending_completions: VecDeque::new(),
            in_flight,
            max_in_flight,
            workers,
        }
    }

    pub(crate) fn completion_notify(&self) -> Arc<tokio::sync::Notify> {
        Arc::clone(&self.completion_notify)
    }
}

impl PacketMover2CryptoExecutor for PacketMover2AeadWorkerPool {
    fn available_capacity(&self) -> usize {
        if self.work_tx.is_none() {
            return 0;
        }
        self.max_in_flight.saturating_sub(
            self.in_flight
                .load(std::sync::atomic::Ordering::Acquire),
        )
    }

    fn execute_prepared_chunk(
        &mut self,
        prepared: &mut Vec<PreparedCryptoWork>,
        completions: &mut Vec<CryptoCompletion>,
    ) -> usize {
        completions.clear();
        let count = prepared.len();
        if count == 0 {
            return 0;
        }

        let mut chunk = Vec::new();
        std::mem::swap(prepared, &mut chunk);
        let Some(work_tx) = &self.work_tx else {
            for work in chunk.drain(..) {
                work.push_executor_failed_completions(completions);
            }
            return count;
        };

        if chunk.len() <= PACKET_MOVER2_AEAD_WORKER_CHUNK_TARGET {
            let chunk_len = chunk.len();
            match work_tx.try_send(chunk) {
                Ok(()) => {
                    self.in_flight
                        .fetch_add(chunk_len, std::sync::atomic::Ordering::AcqRel);
                }
                Err(crossbeam_channel::TrySendError::Full(mut chunk))
                | Err(crossbeam_channel::TrySendError::Disconnected(mut chunk)) => {
                    for work in chunk.drain(..) {
                        work.push_executor_failed_completions(completions);
                    }
                }
            }
            return count;
        }

        let mut remaining = chunk.into_iter();
        loop {
            let work_chunk: Vec<_> = remaining
                .by_ref()
                .take(PACKET_MOVER2_AEAD_WORKER_CHUNK_TARGET)
                .collect();
            if work_chunk.is_empty() {
                break;
            }
            let chunk_len = work_chunk.len();
            match work_tx.try_send(work_chunk) {
                Ok(()) => {
                    self.in_flight
                        .fetch_add(chunk_len, std::sync::atomic::Ordering::AcqRel);
                }
                Err(crossbeam_channel::TrySendError::Full(mut work_chunk))
                | Err(crossbeam_channel::TrySendError::Disconnected(mut work_chunk)) => {
                    for work in work_chunk.drain(..) {
                        work.push_executor_failed_completions(completions);
                    }
                    for work in remaining {
                        work.push_executor_failed_completions(completions);
                    }
                    break;
                }
            }
        }
        count
    }
}

impl PacketMover2CompletionSource for PacketMover2AeadWorkerPool {
    fn drain_completions<F>(&mut self, limit: usize, mut push: F) -> usize
    where
        F: FnMut(CryptoCompletion),
    {
        let mut drained = 0usize;
        while drained < limit {
            if let Some(completion) = self.pending_completions.pop_front() {
                push(completion);
                self.in_flight
                    .fetch_sub(1, std::sync::atomic::Ordering::AcqRel);
                drained += 1;
                continue;
            }

            let Some(completion_rx) = &self.completion_rx else {
                break;
            };
            match completion_rx.try_recv() {
                Ok(completions) => {
                    self.pending_completions.extend(completions);
                }
                Err(crossbeam_channel::TryRecvError::Empty)
                | Err(crossbeam_channel::TryRecvError::Disconnected) => break,
            }
        }
        drained
    }
}

impl Drop for PacketMover2AeadWorkerPool {
    fn drop(&mut self) {
        self.work_tx.take();
        self.completion_rx.take();
        for worker in self.workers.drain(..) {
            let _ = worker.join();
        }
    }
}

impl std::fmt::Debug for PreparedCryptoWork {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Open { work, .. } => f
                .debug_struct("PreparedCryptoWork::Open")
                .field("reservation", &work.reservation)
                .finish_non_exhaustive(),
            Self::Seal { work, .. } => f
                .debug_struct("PreparedCryptoWork::Seal")
                .field("reservation", &work.reservation)
                .finish_non_exhaustive(),
            Self::Completed(completion) => f
                .debug_tuple("PreparedCryptoWork::Completed")
                .field(completion)
                .finish(),
        }
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

fn failed_wrapped_crypto_completion(
    reservation: OwnerReservation,
    wrap_reservation: OwnerReservation,
    kind: CryptoFailureKind,
) -> CryptoCompletion {
    CryptoCompletion {
        reservation,
        result: CryptoResult::WrappedFailed {
            failure: kind,
            completion: Box::new(failed_crypto_completion(wrap_reservation, kind)),
        },
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

pub(crate) struct AeadOpenWork {
    work: CryptoWork,
    cipher: AeadKey,
    header: AeadHeader,
    ciphertext_offset: usize,
}

impl AeadOpenWork {
    pub(crate) fn from_crypto_work(
        work: CryptoWork,
        cipher: AeadKey,
    ) -> Result<Self, WirePreflightError> {
        let (header, ciphertext_offset, counter) = match work.packet.owner.protocol {
            PacketProtocol::Fmp => {
                let header = FmpWireHeader::parse(&work.packet.payload)?;
                (
                    AeadHeader::Fmp(header.header_bytes()),
                    header.ciphertext_offset(),
                    header.counter(),
                )
            }
            PacketProtocol::Fsp => {
                let header = FspWireHeader::parse(&work.packet.payload)?;
                (
                    AeadHeader::Fsp(header.header_bytes()),
                    header.ciphertext_offset(),
                    header.counter(),
                )
            }
        };
        if counter != work.packet.counter {
            return Err(WirePreflightError::CounterMismatch);
        }

        Ok(Self {
            work,
            cipher,
            header,
            ciphertext_offset,
        })
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct StatelessAeadOpenWorker;

impl StatelessAeadOpenWorker {
    pub(crate) fn execute(&self, mut work: AeadOpenWork) -> CryptoCompletion {
        let reservation = work.work.reservation;
        let target = work.work.packet.output;
        let header = work.header;
        let source_wire_len = work.work.packet.payload.len();
        let opened_len = match work.work.packet.payload.get_mut(work.ciphertext_offset..) {
            Some(ciphertext) => {
                let nonce = aead_nonce(reservation.counter);
                work.cipher
                    .open_in_place(nonce, Aad::from(header.as_aad()), ciphertext)
                    .map(|plaintext| plaintext.len())
                    .ok()
            }
            None => None,
        };

        let result = match opened_len {
            Some(plaintext_len) => {
                work.work
                    .packet
                    .payload
                    .truncate(work.ciphertext_offset + plaintext_len);
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
                    path: reservation.output_path.clone(),
                    activity_tick: reservation.activity_tick,
                    fmp_timestamp_ms: reservation.fmp_timestamp_ms,
                    source_wire_len: Some(source_wire_len),
                    payload: work.work.packet.payload,
                })
            }
            None => CryptoResult::Failed(CryptoFailureKind::Open),
        };

        CryptoCompletion {
            reservation,
            result,
        }
    }
}

pub(crate) struct AeadSealWork {
    work: OutboundCryptoWork,
    cipher: AeadKey,
    post_seal: OutboundPostSeal,
    wrap: Option<OutboundWrapReservation>,
    aad_len: usize,
    ciphertext_offset: usize,
}

impl AeadSealWork {
    pub(crate) fn from_outbound_work(
        mut work: OutboundCryptoWork,
        cipher: AeadKey,
    ) -> Result<Self, WireBuildError> {
        let inner_prefix = work.packet.crypto_plaintext_prefix(
            work.reservation.fmp_timestamp_ms,
            work.reservation.fsp_timestamp_ms,
        )?;
        let payload_len = u16::try_from(inner_prefix.len().saturating_add(work.packet.payload.len()))
            .map_err(|_| WireBuildError::PayloadTooLarge)?;
        let counter = work.reservation.counter;
        let (header, coord_prefix, ciphertext_offset) =
            match (work.packet.owner.protocol, work.packet.wire) {
            (
                PacketProtocol::Fmp,
                OutboundWire::Fmp {
                    receiver_idx,
                    flags,
                },
            ) => (
                AeadHeader::Fmp(build_fmp_established_header(
                    receiver_idx,
                    counter,
                    flags,
                    payload_len,
                )),
                Vec::new(),
                FMP_ESTABLISHED_HEADER_SIZE,
            ),
            (PacketProtocol::Fsp, OutboundWire::Fsp { flags }) => {
                let coord_prefix = std::mem::take(&mut work.packet.fsp_cleartext_prefix);
                validate_fsp_cleartext_prefix(flags, &coord_prefix)?;
                let ciphertext_offset = FSP_HEADER_SIZE + coord_prefix.len();
                (
                    AeadHeader::Fsp(build_fsp_established_header(counter, flags, payload_len)?),
                    coord_prefix,
                    ciphertext_offset,
                )
            }
            _ => return Err(WireBuildError::ProtocolMismatch),
        };

        let aad = header.as_aad();
        let aad_len = aad.len();
        let prefix_len = aad
            .len()
            .saturating_add(coord_prefix.len())
            .saturating_add(inner_prefix.len());
        let plaintext = std::mem::take(&mut work.packet.payload);
        let mut payload = Vec::with_capacity(
            prefix_len
                .saturating_add(plaintext.len())
                .saturating_add(AEAD_TAG_SIZE),
        );
        payload.extend_from_slice(aad);
        payload.extend_from_slice(&coord_prefix);
        payload.extend_from_slice(&inner_prefix);
        payload.extend_from_slice(&plaintext);
        work.packet.payload = payload.into();

        let wrap = work.wrap.take();
        Ok(Self {
            post_seal: work.packet.post_seal,
            wrap,
            work,
            cipher,
            aad_len,
            ciphertext_offset,
        })
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct StatelessAeadSealWorker;

impl StatelessAeadSealWorker {
    pub(crate) fn execute(&self, work: AeadSealWork) -> CryptoCompletion {
        self.execute_inner(work, None)
    }

    pub(crate) fn execute_reserved_wrap(
        &self,
        work: AeadSealWork,
        wrap_cipher: AeadKey,
    ) -> CryptoCompletion {
        self.execute_inner(work, Some(wrap_cipher))
    }

    fn execute_inner(
        &self,
        mut work: AeadSealWork,
        wrap_cipher: Option<AeadKey>,
    ) -> CryptoCompletion {
        let reservation = work.work.reservation;
        let tag = if work.aad_len <= work.ciphertext_offset
            && work.ciphertext_offset <= work.work.packet.payload.len()
        {
            let nonce = aead_nonce(reservation.counter);
            let (prefix, plaintext) = work
                .work
                .packet
                .payload
                .split_at_mut(work.ciphertext_offset);
            let Some(aad) = prefix.get(..work.aad_len) else {
                return CryptoCompletion {
                    reservation,
                    result: CryptoResult::Failed(CryptoFailureKind::Seal),
                };
            };
            work.cipher
                .seal_in_place_separate_tag(nonce, Aad::from(aad), plaintext)
                .ok()
        } else {
            None
        };

        let result = match tag {
            Some(tag) => {
                work.work.packet.payload.extend_from_slice(tag.as_ref());
                match work.post_seal {
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
                        path: reservation.output_path.clone(),
                        activity_tick: reservation.activity_tick,
                        fmp_timestamp_ms: reservation.fmp_timestamp_ms,
                        source_wire_len: None,
                        payload: work.work.packet.payload,
                    }),
                    OutboundPostSeal::FmpWrap(route) => {
                        if let Some(mut wrap) = work.wrap.take() {
                            route.fill_reserved_fmp_outbound(
                                &mut wrap.packet,
                                work.work.packet.payload,
                            );
                            let wrap_reservation = wrap.reservation.clone();
                            let completion = match wrap_cipher {
                                Some(cipher) => {
                                    let wrap_work = OutboundCryptoWork::new(
                                        wrap.reservation,
                                        wrap.packet,
                                    );
                                    match AeadSealWork::from_outbound_work(wrap_work, cipher) {
                                        Ok(wrap_work) => self.execute(wrap_work),
                                        Err(_) => failed_crypto_completion(
                                            wrap_reservation,
                                            CryptoFailureKind::Seal,
                                        ),
                                    }
                                }
                                None => failed_crypto_completion(
                                    wrap_reservation,
                                    CryptoFailureKind::Seal,
                                ),
                            };
                            CryptoResult::WrappedSealed(WrappedCryptoCompletion::new(
                                reservation.owner,
                                reservation.counter,
                                completion,
                            ))
                        } else {
                        let mut packet =
                            route.into_fmp_outbound(work.work.packet.class, work.work.packet.payload);
                        if let Some(tick) = reservation.activity_tick {
                            packet = packet.with_activity_tick(tick);
                        }
                        CryptoResult::Outbound(WrappedOutboundPacket::new(
                            packet,
                            reservation.owner,
                            reservation.counter,
                        ))
                        }
                    }
                }
            }
            None => match work.wrap.take() {
                Some(wrap) => CryptoResult::WrappedFailed {
                    failure: CryptoFailureKind::Seal,
                    completion: Box::new(failed_crypto_completion(
                        wrap.reservation,
                        CryptoFailureKind::Seal,
                    )),
                },
                None => CryptoResult::Failed(CryptoFailureKind::Seal),
            },
        };

        CryptoCompletion {
            reservation,
            result,
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
