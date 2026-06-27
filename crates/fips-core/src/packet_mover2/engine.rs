#[derive(Debug)]
pub(crate) struct PacketMover2<W = CopyCryptoWorker> {
    admission: AdmissionQueue,
    outbound_admission: OutboundAdmissionQueue,
    owners: HashMap<OwnerId, OwnerState>,
    worker: W,
    drops: Vec<PacketDrop>,
}

impl<W: StatelessCryptoWorker> PacketMover2<W> {
    pub(crate) fn new(config: AdmissionConfig, worker: W) -> Self {
        Self {
            admission: AdmissionQueue::new(config),
            outbound_admission: OutboundAdmissionQueue::new(config),
            owners: HashMap::new(),
            worker,
            drops: Vec::new(),
        }
    }

    pub(crate) fn register_owner(&mut self, owner: OwnerId, config: OwnerConfig) {
        self.owners.insert(owner, OwnerState::new(owner, config));
    }

    pub(crate) fn unregister_owner(&mut self, owner: OwnerId) -> bool {
        self.owners.remove(&owner).is_some()
    }

    pub(crate) fn owner_mut(&mut self, owner: OwnerId) -> Option<&mut OwnerState> {
        self.owners.get_mut(&owner)
    }

    fn owner_crypto_keys(&self, owner: OwnerId) -> Option<OwnerCryptoKeys> {
        self.owners.get(&owner).and_then(OwnerState::crypto_keys)
    }

    pub(crate) fn submit_socket_packet(
        &mut self,
        packet: SocketPacket,
    ) -> Result<u64, AdmissionDrop> {
        match self.admission.admit(packet) {
            Ok(seq) => Ok(seq),
            Err(drop) => {
                self.drops.push(drop.clone().into());
                Err(drop)
            }
        }
    }

    pub(crate) fn submit_socket_batch<I>(&mut self, packets: I) -> AdmissionBatchSummary
    where
        I: IntoIterator<Item = SocketPacket>,
    {
        let mut summary = AdmissionBatchSummary::default();
        for packet in packets {
            match self.submit_socket_packet(packet) {
                Ok(_) => summary.admitted += 1,
                Err(_) => summary.dropped += 1,
            }
        }
        summary
    }

    pub(crate) fn submit_outbound_packet(
        &mut self,
        packet: OutboundPacket,
    ) -> Result<u64, OutboundAdmissionDrop> {
        match self.outbound_admission.admit(packet) {
            Ok(seq) => Ok(seq),
            Err(drop) => {
                self.drops.push(drop.clone().into());
                Err(drop)
            }
        }
    }

    pub(crate) fn dispatch_available(&mut self, limit: usize) -> Vec<CryptoWork> {
        let mut work = Vec::new();
        self.dispatch_available_into(limit, &mut work);
        work
    }

    pub(crate) fn dispatch_available_into(
        &mut self,
        limit: usize,
        work: &mut Vec<CryptoWork>,
    ) -> usize {
        work.clear();

        while work.len() < limit {
            let Some(queued) = self.admission.pop_next() else {
                break;
            };

            let Some(owner) = self.owners.get_mut(&queued.packet.owner) else {
                self.drops.push(PacketDrop::from_queued(
                    &queued,
                    PacketDropReason::UnknownOwner,
                ));
                continue;
            };

            match owner.reserve(&queued.packet, queued.ingress_seq) {
                Ok(reservation) => work.push(CryptoWork {
                    reservation,
                    packet: queued.packet,
                }),
                Err(error) => self
                    .drops
                    .push(PacketDrop::from_queued(&queued, error.into())),
            }
        }

        work.len()
    }

    pub(crate) fn dispatch_outbound_available(&mut self, limit: usize) -> Vec<OutboundCryptoWork> {
        let mut work = Vec::new();
        self.dispatch_outbound_available_into(limit, &mut work);
        work
    }

    pub(crate) fn dispatch_outbound_available_into(
        &mut self,
        limit: usize,
        work: &mut Vec<OutboundCryptoWork>,
    ) -> usize {
        work.clear();

        while work.len() < limit {
            let Some(queued) = self.outbound_admission.pop_next() else {
                break;
            };

            let Some(owner) = self.owners.get_mut(&queued.packet.owner) else {
                self.drops.push(PacketDrop::from_queued_outbound(
                    &queued,
                    PacketDropReason::UnknownOwner,
                ));
                continue;
            };

            match owner.reserve_outbound(&queued.packet, queued.ingress_seq) {
                Ok(reservation) => work.push(OutboundCryptoWork {
                    reservation,
                    packet: queued.packet,
                }),
                Err(error) => self
                    .drops
                    .push(PacketDrop::from_queued_outbound(&queued, error.into())),
            }
        }

        work.len()
    }

    pub(crate) fn execute_work(&self, work: CryptoWork) -> CryptoCompletion {
        self.worker.execute(work)
    }

    pub(crate) fn retire_completion(&mut self, completion: CryptoCompletion) -> Vec<RetiredPacket> {
        let Some(owner) = self.owners.get_mut(&completion.reservation.owner) else {
            return vec![RetiredPacket::Drop(PacketDrop::from_completion(
                &completion,
                PacketDropReason::UnknownOwner,
            ))];
        };
        let retired = owner.retire(completion);
        self.drops
            .extend(retired.iter().filter_map(|item| match item {
                RetiredPacket::Drop(drop) => Some(drop.clone()),
                RetiredPacket::Output(_) => None,
            }));
        retired
    }

    pub(crate) fn run_available(&mut self, limit: usize) -> PacketMoverTurn {
        let mut work = Vec::new();
        self.run_available_with_scratch(limit, &mut work)
    }

    pub(crate) fn run_available_with_scratch(
        &mut self,
        limit: usize,
        work: &mut Vec<CryptoWork>,
    ) -> PacketMoverTurn {
        let dispatched = self.dispatch_available_into(limit, work);
        let mut retired = Vec::new();
        for work in work.drain(..) {
            let completion = self.worker.execute(work);
            retired.extend(self.retire_completion(completion));
        }
        PacketMoverTurn {
            dispatched,
            retired,
            drops: self.drain_drops(),
        }
    }

    pub(crate) fn run_aead_available(&mut self, limit: usize) -> PacketMoverTurn {
        let mut open_work = Vec::new();
        let mut seal_work = Vec::new();
        self.run_aead_available_with_scratch(limit, &mut open_work, &mut seal_work)
    }

    pub(crate) fn run_aead_available_with_scratch(
        &mut self,
        limit: usize,
        open_work: &mut Vec<CryptoWork>,
        seal_work: &mut Vec<OutboundCryptoWork>,
    ) -> PacketMoverTurn {
        let opened = StatelessAeadOpenWorker;
        let sealed = StatelessAeadSealWorker;
        let outbound_priority_reserve =
            usize::from(limit > 1 && self.outbound_admission.has_priority_pending());
        let inbound_dispatched = self
            .dispatch_available_into(limit.saturating_sub(outbound_priority_reserve), open_work);
        let outbound_dispatched = self
            .dispatch_outbound_available_into(limit.saturating_sub(inbound_dispatched), seal_work);
        let mut retired = Vec::new();

        for work in open_work.drain(..) {
            let reservation = work.reservation.clone();
            let completion = match self.owner_crypto_keys(reservation.owner) {
                Some(keys) => match AeadOpenWork::from_crypto_work(work, keys.open) {
                    Ok(work) => opened.execute(work),
                    Err(_) => CryptoCompletion {
                        reservation,
                        result: CryptoResult::Failed,
                    },
                },
                None => CryptoCompletion {
                    reservation,
                    result: CryptoResult::Failed,
                },
            };
            retired.extend(self.retire_completion(completion));
        }

        for work in seal_work.drain(..) {
            let reservation = work.reservation.clone();
            let completion = match self.owner_crypto_keys(reservation.owner) {
                Some(keys) => match AeadSealWork::from_outbound_work(work, keys.seal) {
                    Ok(work) => sealed.execute(work),
                    Err(_) => CryptoCompletion {
                        reservation,
                        result: CryptoResult::Failed,
                    },
                },
                None => CryptoCompletion {
                    reservation,
                    result: CryptoResult::Failed,
                },
            };
            retired.extend(self.retire_completion(completion));
        }

        PacketMoverTurn {
            dispatched: inbound_dispatched + outbound_dispatched,
            retired,
            drops: self.drain_drops(),
        }
    }

    pub(crate) fn drain_drops(&mut self) -> Vec<PacketDrop> {
        std::mem::take(&mut self.drops)
    }

    #[cfg(test)]
    fn queue_lens(&self) -> (usize, usize) {
        self.admission.lens()
    }

    #[cfg(test)]
    fn outbound_queue_lens(&self) -> (usize, usize) {
        self.outbound_admission.lens()
    }
}
