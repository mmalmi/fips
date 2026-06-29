pub(crate) enum PreparedCryptoWork {
    Open { work: CryptoWork, cipher: AeadKey },
    Seal {
        work: OutboundCryptoWork,
        cipher: AeadKey,
    },
    Completed(CryptoCompletion),
}

impl PreparedCryptoWork {
    pub(crate) fn open(work: CryptoWork, cipher: AeadKey) -> Self {
        Self::Open { work, cipher }
    }

    pub(crate) fn seal(work: OutboundCryptoWork, cipher: AeadKey) -> Self {
        Self::Seal { work, cipher }
    }

    pub(crate) fn failed(reservation: OwnerReservation, kind: CryptoFailureKind) -> Self {
        Self::Completed(failed_crypto_completion(reservation, kind))
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
            Self::Seal { work, cipher } => {
                let reservation = work.reservation.clone();
                let _timer = crate::perf_profile::Timer::start(
                    crate::perf_profile::Stage::PacketMover2AeadSeal,
                );
                match AeadSealWork::from_outbound_work(work, cipher) {
                    Ok(work) => sealed.execute(work),
                    Err(_) => failed_crypto_completion(reservation, CryptoFailureKind::Seal),
                }
            }
            Self::Completed(completion) => completion,
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

        Ok(Self {
            post_seal: work.packet.post_seal,
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
    pub(crate) fn execute(&self, mut work: AeadSealWork) -> CryptoCompletion {
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
            None => CryptoResult::Failed(CryptoFailureKind::Seal),
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
