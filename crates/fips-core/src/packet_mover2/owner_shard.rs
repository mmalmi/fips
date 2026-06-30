#[derive(Debug)]
struct PacketMover2OwnerShard {
    admission: AdmissionQueue,
    outbound_admission: OutboundAdmissionQueue,
    owners: HashMap<OwnerId, OwnerState>,
    drops: Vec<PacketDrop>,
}

enum OutboundDispatchResult {
    Completed,
    Blocked(QueuedOutboundPacket),
}

impl PacketMover2OwnerShard {
    fn new() -> Self {
        Self {
            admission: AdmissionQueue::new(),
            outbound_admission: OutboundAdmissionQueue::new(),
            owners: HashMap::new(),
            drops: Vec::new(),
        }
    }

    fn register_owner(&mut self, owner: OwnerId, config: OwnerConfig) {
        self.owners.insert(owner, OwnerState::new(owner, config));
    }

    fn unregister_owner(&mut self, owner: OwnerId) -> bool {
        self.owners.remove(&owner).is_some()
    }

    fn has_owner(&self, owner: OwnerId) -> bool {
        self.owners.contains_key(&owner)
    }

    fn owner_active_path(&self, owner: OwnerId) -> Option<TransportPath> {
        self.owners
            .get(&owner)
            .and_then(OwnerState::active_path)
    }

    fn owner_mut(&mut self, owner: OwnerId) -> Option<&mut OwnerState> {
        self.owners.get_mut(&owner)
    }

    fn owner(&self, owner: OwnerId) -> Option<&OwnerState> {
        self.owners.get(&owner)
    }

    fn submit_socket_packet_with_seq(
        &mut self,
        packet: SocketPacket,
        ingress_seq: u64,
    ) -> u64 {
        self.admission.admit_with_seq(packet, ingress_seq)
    }

    fn submit_outbound_packet_with_seq(
        &mut self,
        packet: OutboundPacket,
        ingress_seq: u64,
    ) -> u64 {
        self.outbound_admission.admit_with_seq(packet, ingress_seq)
    }

    fn dispatch_ingress_available_into(
        &mut self,
        limit: usize,
        work: &mut Vec<CryptoWork>,
        priority_only: bool,
    ) -> usize {
        let start_len = work.len();
        let target_len = start_len.saturating_add(limit);
        let mut attempts_remaining = self.admission.len();
        while work.len() < target_len && attempts_remaining > 0 {
            let pop = if priority_only {
                self.admission.pop_next_priority()
            } else {
                self.admission.pop_next()
            };
            let Some(pop) = pop else {
                if !priority_only && limit > 0 {
                    crate::perf_profile::record_event(
                        crate::perf_profile::Event::PacketMover2DispatchNoIngress,
                    );
                }
                break;
            };
            attempts_remaining = attempts_remaining.saturating_sub(1);
            let OwnerAdmissionPop {
                item: queued,
                cursor,
            } = pop;

            let Some(owner) = self.owners.get_mut(&queued.packet.owner) else {
                self.drops.push(PacketDrop::from_queued(
                    &queued,
                    PacketDropReason::UnknownOwner,
                ));
                self.admission.continue_owner_run(cursor);
                continue;
            };
            if !owner.can_reserve_class(queued.packet.class) {
                record_owner_blocked(owner.reserve_block_reason(queued.packet.class));
                self.admission.defer_owner_pop(OwnerAdmissionPop {
                    item: queued,
                    cursor,
                });
                continue;
            }

            match owner.reserve(&queued.packet, queued.ingress_seq) {
                Ok(reservation) => {
                    work.push(CryptoWork {
                        reservation,
                        packet: queued.packet,
                    });
                    self.admission.continue_owner_run(cursor);
                    attempts_remaining = self.admission.len();
                }
                Err(error) => {
                    self.drops
                        .push(PacketDrop::from_queued(&queued, error.into()));
                    self.admission.continue_owner_run(cursor);
                }
            }
        }

        let dispatched = work.len().saturating_sub(start_len);
        if !priority_only && limit > 0 && dispatched >= limit {
            crate::perf_profile::record_event(
                crate::perf_profile::Event::PacketMover2DispatchLimitHit,
            );
        }
        dispatched
    }

    fn has_inbound_priority_pending(&self) -> bool {
        self.admission.has_priority_pending()
    }

    fn has_outbound_priority_pending(&self) -> bool {
        self.outbound_admission.has_priority_pending()
    }

    fn admission_len_for_priority(&self, priority_only: bool) -> usize {
        if priority_only {
            self.admission_lane_len(Lane::Priority)
        } else {
            self.admission.len()
        }
    }

    fn peek_ingress_seq(&self, priority_only: bool) -> Option<u64> {
        if priority_only {
            self.admission.peek_next_priority_seq()
        } else {
            self.admission.peek_next_seq()
        }
    }

    fn peek_outbound_seq(&self, priority_only: bool) -> Option<u64> {
        if priority_only {
            self.outbound_admission.peek_next_priority_seq()
        } else {
            self.outbound_admission.peek_next_seq()
        }
    }

    fn admission_lane_len(&self, lane: Lane) -> usize {
        let lens = self.admission.lens();
        match lane {
            Lane::Priority => lens.0,
            Lane::Bulk => lens.1,
        }
    }

    fn outbound_admission_lane_len(&self, lane: Lane) -> usize {
        let lens = self.outbound_admission.lens();
        match lane {
            Lane::Priority => lens.0,
            Lane::Bulk => lens.1,
        }
    }

    fn outbound_len(&self) -> usize {
        self.outbound_admission.len()
    }

    fn pop_outbound(&mut self) -> Option<OwnerAdmissionPop<QueuedOutboundPacket>> {
        self.outbound_admission.pop_next()
    }

    fn pop_outbound_priority(&mut self) -> Option<OwnerAdmissionPop<QueuedOutboundPacket>> {
        self.outbound_admission.pop_next_priority()
    }

    fn continue_outbound_owner_run(&mut self, cursor: OwnerAdmissionCursor) {
        self.outbound_admission.continue_owner_run(cursor);
    }

    fn defer_outbound_owner_pop(&mut self, pop: OwnerAdmissionPop<QueuedOutboundPacket>) {
        self.outbound_admission.defer_owner_pop(pop);
    }

    fn dispatch_outbound_available_into(
        &mut self,
        queued: QueuedOutboundPacket,
        work: &mut Vec<OutboundCryptoWork>,
    ) -> OutboundDispatchResult {
        let owner_id = queued.packet.owner;
        let lane = queued.packet.lane();
        let class = queued.packet.class;
        let ingress_seq = queued.ingress_seq;

        let Some(owner) = self.owners.get(&owner_id) else {
            self.drops.push(PacketDrop::from_queued_outbound(
                &queued,
                PacketDropReason::UnknownOwner,
            ));
            return OutboundDispatchResult::Completed;
        };
        if !owner.can_reserve_class(class) {
            record_owner_blocked(owner.reserve_block_reason(class));
            return OutboundDispatchResult::Blocked(queued);
        }

        let (reservation, packet) = {
            let owner = self
                .owners
                .get_mut(&owner_id)
                .expect("outbound owner checked before reservation");
            match owner.reserve_outbound(queued.packet, ingress_seq) {
                Ok(reserved) => reserved,
                Err(error) => {
                    self.drops.push(PacketDrop {
                        owner: owner_id,
                        counter: None,
                        ingress_seq: Some(ingress_seq),
                        lane,
                        reason: error.into(),
                        crypto_failure: None,
                        wire_flags: None,
                        authenticated_counter_highest: None,
                    });
                    return OutboundDispatchResult::Completed;
                }
            }
        };

        work.push(OutboundCryptoWork::new(reservation, packet));
        OutboundDispatchResult::Completed
    }

    pub(crate) fn retire_completion(&mut self, completion: CryptoCompletion) -> Vec<RetiredPacket> {
        let _timer =
            crate::perf_profile::Timer::start(crate::perf_profile::Stage::PacketMover2Retire);
        let Some(owner) = self.owners.get_mut(&completion.reservation.owner) else {
            return vec![RetiredPacket::Drop(PacketDrop::from_completion(
                &completion,
                PacketDropReason::UnknownOwner,
                None,
            ))];
        };
        let retired = owner.retire(completion);
        self.drops
            .extend(retired.iter().filter_map(|item| match item {
                RetiredPacket::Drop(drop) => Some(drop.clone()),
                RetiredPacket::Output(_) => None,
                RetiredPacket::Outbound(_) => None,
            }));
        retired
    }

    fn drain_drops(&mut self) -> Vec<PacketDrop> {
        std::mem::take(&mut self.drops)
    }

    fn admission_queue_lens(&self) -> (usize, usize) {
        self.admission.lens()
    }

    fn outbound_admission_queue_lens(&self) -> (usize, usize) {
        self.outbound_admission.lens()
    }
}
