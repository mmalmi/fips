pub(crate) trait StatelessCryptoWorker {
    fn execute(&self, work: CryptoWork) -> CryptoCompletion;
}

#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct CopyCryptoWorker;

impl StatelessCryptoWorker for CopyCryptoWorker {
    fn execute(&self, work: CryptoWork) -> CryptoCompletion {
        let output = PacketOutput {
            owner: work.packet.owner,
            counter: work.packet.counter,
            ingress_seq: work.reservation.ingress_seq,
            target: work.packet.output,
            source_path: work.reservation.source_path.clone(),
            previous_hop: work.reservation.previous_hop,
            ce_flag: work.reservation.ce_flag,
            path: work.reservation.output_path.clone(),
            activity_tick: work.reservation.activity_tick,
            source_wire_len: Some(work.packet.payload.len()),
            payload: work.packet.payload,
        };
        CryptoCompletion {
            reservation: work.reservation,
            result: CryptoResult::Opened(output),
        }
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
                    target,
                    source_path: reservation.source_path.clone(),
                    previous_hop: reservation.previous_hop,
                    ce_flag: reservation.ce_flag,
                    path: reservation.output_path.clone(),
                    activity_tick: reservation.activity_tick,
                    source_wire_len: Some(source_wire_len),
                    payload: work.work.packet.payload,
                })
            }
            None => CryptoResult::Failed,
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
    ciphertext_offset: usize,
}

impl AeadSealWork {
    pub(crate) fn from_outbound_work(
        mut work: OutboundCryptoWork,
        cipher: AeadKey,
    ) -> Result<Self, WireBuildError> {
        work.packet
            .apply_payload_transform(work.reservation.fsp_timestamp_ms)?;
        if work.packet.owner.protocol == PacketProtocol::Fmp
            && let Some(timestamp_ms) = work.reservation.fmp_timestamp_ms
        {
            work.packet.prepend_fmp_inner_timestamp(timestamp_ms);
        }
        let payload_len = u16::try_from(work.packet.payload.len())
            .map_err(|_| WireBuildError::PayloadTooLarge)?;
        let counter = work.reservation.counter;
        let (header, ciphertext_offset) = match (work.packet.owner.protocol, work.packet.wire) {
            (
                PacketProtocol::Fmp,
                OutboundWire::Fmp {
                    receiver_idx,
                    flags,
                },
            ) => (
                build_fmp_established_header(receiver_idx, counter, flags, payload_len).to_vec(),
                FMP_ESTABLISHED_HEADER_SIZE,
            ),
            (PacketProtocol::Fsp, OutboundWire::Fsp { flags }) => (
                build_fsp_established_header(counter, flags, payload_len)?.to_vec(),
                FSP_HEADER_SIZE,
            ),
            _ => return Err(WireBuildError::ProtocolMismatch),
        };

        let mut wire = Vec::with_capacity(header.len() + work.packet.payload.len() + AEAD_TAG_SIZE);
        wire.extend_from_slice(&header);
        wire.extend_from_slice(&work.packet.payload);
        work.packet.payload = wire.into();

        Ok(Self {
            post_seal: work.packet.post_seal,
            work,
            cipher,
            ciphertext_offset,
        })
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct StatelessAeadSealWorker;

impl StatelessAeadSealWorker {
    pub(crate) fn execute(&self, mut work: AeadSealWork) -> CryptoCompletion {
        let reservation = work.work.reservation;
        let tag = if work.ciphertext_offset <= work.work.packet.payload.len() {
            let nonce = aead_nonce(reservation.counter);
            let (aad, plaintext) = work
                .work
                .packet
                .payload
                .split_at_mut(work.ciphertext_offset);
            work.cipher
                .seal_in_place_separate_tag(nonce, Aad::from(&*aad), plaintext)
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
                        target: OutputTarget::Transport,
                        source_path: reservation.source_path.clone(),
                        previous_hop: reservation.previous_hop,
                        ce_flag: reservation.ce_flag,
                        path: reservation.output_path.clone(),
                        activity_tick: reservation.activity_tick,
                        source_wire_len: None,
                        payload: work.work.packet.payload,
                    }),
                    OutboundPostSeal::FmpWrap(route) => {
                        let mut packet =
                            route.into_fmp_outbound(work.work.packet.class, work.work.packet.payload);
                        if let Some(tick) = reservation.activity_tick {
                            packet = packet.with_activity_tick(tick);
                        }
                        CryptoResult::Outbound(packet)
                    }
                }
            }
            None => CryptoResult::Failed,
        };

        CryptoCompletion {
            reservation,
            result,
        }
    }
}

fn aead_nonce(counter: u64) -> Nonce {
    let mut nonce_bytes = [0u8; 12];
    nonce_bytes[4..12].copy_from_slice(&counter.to_le_bytes());
    Nonce::assume_unique_for_key(nonce_bytes)
}
