#[derive(Debug)]
struct DataplaneOwnerShardRetireWorker {
    owners: HashMap<OwnerId, CryptoOwnerContinuation>,
    ready: VecDeque<OwnerId>,
}

#[derive(Debug, Default)]
struct CryptoOwnerContinuation {
    runs: VecDeque<PendingCryptoOwnerRun>,
    ready_queued: bool,
}

#[derive(Clone, Copy, Debug, Default)]
struct RetiredCrypto {
    packets: usize,
    worker_packets: usize,
    bulk_packets: usize,
}

impl DataplaneOwnerShardRetireWorker {
    fn new() -> Self {
        Self {
            owners: HashMap::new(),
            ready: VecDeque::new(),
        }
    }

    fn queue_run(&mut self, run: Arc<CryptoOwnerRun>) -> bool {
        let owner = run.owner;
        let is_ready = run.is_ready();
        let continuation = self.owners.entry(owner).or_default();
        if let Some(last) = continuation.runs.back() {
            debug_assert_eq!(
                OrderToken(last.next_order.0.wrapping_add(last.remaining as u64)),
                run.first_order,
                "crypto owner runs must be queued in reservation order"
            );
        }
        continuation
            .runs
            .push_back(PendingCryptoOwnerRun::new(run));
        is_ready && self.mark_ready(owner)
    }

    fn mark_ready(&mut self, owner: OwnerId) -> bool {
        let Some(continuation) = self.owners.get_mut(&owner) else {
            return false;
        };
        if continuation.ready_queued {
            return false;
        }
        let was_empty = self.ready.is_empty();
        continuation.ready_queued = true;
        self.ready.push_back(owner);
        was_empty
    }

    fn retire_ready_runs_into(
        &mut self,
        owner_shard: &mut DataplaneOwnerShard,
        limit: usize,
        retired: &mut DataplaneRetiredOutputSink<'_>,
        drops: &mut Vec<PacketDrop>,
        compact_endpoint_data: bool,
    ) -> RetiredCrypto {
        let mut retired_crypto = RetiredCrypto::default();
        while retired_crypto.packets < limit {
            let Some(owner_id) = self.ready.pop_front() else {
                break;
            };
            let Some(continuation) = self.owners.get_mut(&owner_id) else {
                continue;
            };
            continuation.ready_queued = false;
            while retired_crypto.packets < limit {
                let Some(run) = continuation.runs.front_mut() else {
                    break;
                };
                if !run.is_ready() {
                    break;
                }
                let run_limit = limit.saturating_sub(retired_crypto.packets);
                let before_in_flight = owner_shard
                    .owners
                    .get(&owner_id)
                    .map_or(0, |owner| owner.in_flight);
                let got = match owner_shard.owners.get_mut(&owner_id) {
                    Some(owner) => owner.retire_ready_run_prefix_into(
                        run,
                        run_limit,
                        retired,
                        drops,
                        compact_endpoint_data,
                    ),
                    None => {
                        let got = run_limit.min(run.remaining);
                        run.consume_prefix(got, |completion| {
                            drops.push(PacketDrop::from_completion(
                                &completion,
                                PacketDropReason::UnknownOwner,
                                None,
                            ));
                        });
                        got
                    }
                };
                if got == 0 {
                    break;
                }
                retired_crypto.packets = retired_crypto.packets.saturating_add(got);
                if run.worker_counted() {
                    retired_crypto.worker_packets = retired_crypto.worker_packets.saturating_add(got);
                    if run.lane() == Lane::Bulk {
                        retired_crypto.bulk_packets = retired_crypto.bulk_packets.saturating_add(got);
                    }
                }
                if owner_shard
                    .owners
                    .get(&owner_id)
                    .is_some_and(|owner| owner.in_flight < before_in_flight)
                {
                    owner_shard.admission.wake_owner(owner_id);
                    owner_shard.outbound_admission.wake_owner(owner_id);
                }
                if run.is_empty() {
                    continuation.runs.pop_front();
                }
            }
            if continuation
                .runs
                .front()
                .is_some_and(PendingCryptoOwnerRun::is_ready)
                && retired_crypto.packets >= limit
            {
                continuation.ready_queued = true;
                self.ready.push_back(owner_id);
            }
            if continuation.runs.is_empty() {
                self.owners.remove(&owner_id);
            }
            if retired_crypto.packets >= limit {
                break;
            }
        }
        retired_crypto
    }

    fn has_ready_runs(&self) -> bool {
        !self.ready.is_empty()
    }
}

#[derive(Debug)]
struct DataplaneOwnerShard {
    index: usize,
    admission: AdmissionQueue,
    outbound_admission: OutboundAdmissionQueue,
    owners: HashMap<OwnerId, OwnerState>,
}

impl DataplaneOwnerShard {
    fn new(index: usize) -> Self {
        Self {
            index,
            admission: AdmissionQueue::new(),
            outbound_admission: OutboundAdmissionQueue::new(),
            owners: HashMap::new(),
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

    fn fsp_owner_destinations(&self, destinations: &mut Vec<NodeAddr>) {
        destinations.extend(self.owners.keys().filter_map(|owner| {
            (owner.protocol() == PacketProtocol::Fsp).then_some(owner.node_addr())
        }));
    }

    fn owner_active_path(&self, owner: OwnerId) -> Option<TransportPath> {
        self.owners
            .get(&owner)
            .and_then(OwnerState::active_path)
    }

    fn owner_fsp_next_hop(&self, owner: OwnerId) -> Option<NodeAddr> {
        self.owners
            .get(&owner)
            .and_then(OwnerState::fsp_wrap_next_hop)
    }

    fn owner_mut(&mut self, owner: OwnerId) -> Option<&mut OwnerState> {
        self.owners.get_mut(&owner)
    }

    fn owner(&self, owner: OwnerId) -> Option<&OwnerState> {
        self.owners.get(&owner)
    }

    fn owner_fsp_activity(&self, owner: OwnerId) -> Option<DataplaneFspOwnerActivity> {
        self.owner(owner).and_then(OwnerState::fsp_activity)
    }

    fn owner_has_fsp_pending_receive_epoch(
        &self,
        owner: OwnerId,
        received_k_bit: bool,
    ) -> bool {
        self.owner(owner)
            .is_some_and(|owner| owner.has_fsp_pending_receive_epoch(received_k_bit))
    }

    fn owner_has_fmp_pending_receive_epoch(
        &self,
        owner: OwnerId,
        received_k_bit: bool,
    ) -> bool {
        self.owner(owner)
            .is_some_and(|owner| owner.has_fmp_pending_receive_epoch(received_k_bit))
    }

    fn owner_fsp_mmp_snapshot(&self, owner: OwnerId) -> Option<DataplaneFspMmpSnapshot> {
        self.owner(owner).and_then(OwnerState::fsp_mmp_snapshot)
    }

    fn owner_fsp_send_context(&self, owner: OwnerId) -> Option<DataplaneFspSendContext> {
        self.owner(owner).and_then(OwnerState::fsp_send_context)
    }

    fn owner_fmp_send_context(&self, owner: OwnerId) -> Option<DataplaneFmpSendContext> {
        self.owner(owner).and_then(OwnerState::fmp_send_context)
    }

    fn owner_fmp_link_metrics(
        &self,
        owner: OwnerId,
        now: std::time::Instant,
    ) -> Option<DataplaneFmpLinkMetrics> {
        self.owner(owner)
            .and_then(|owner| owner.fmp_link_metrics(now))
    }

    fn owner_fmp_link_cost(&self, owner: OwnerId) -> Option<f64> {
        self.owner(owner).and_then(OwnerState::fmp_link_cost)
    }

    fn owner_fmp_has_srtt(&self, owner: OwnerId) -> bool {
        self.owner(owner).is_some_and(OwnerState::fmp_has_srtt)
    }

    fn collect_fmp_mmp_reports(
        &mut self,
        now: std::time::Instant,
        batch: &mut DataplaneFmpMmpReportBatch,
    ) {
        for owner in self.owners.values_mut() {
            owner.collect_fmp_mmp_reports(now, batch);
        }
    }

    fn collect_fsp_mmp_reports(
        &mut self,
        now: std::time::Instant,
        batch: &mut DataplaneFspMmpReportBatch,
    ) {
        for owner in self.owners.values_mut() {
            owner.collect_fsp_mmp_reports(now, batch);
        }
    }

    fn record_fsp_mmp_send_result(
        &mut self,
        owner: OwnerId,
        success: bool,
    ) -> Option<DataplaneFspMmpReportingResumed> {
        self.owner_mut(owner)
            .and_then(|owner| owner.record_fsp_mmp_send_result(success))
    }

    fn seed_fsp_path_mtu(
        &mut self,
        owner: OwnerId,
        path_mtu: u16,
    ) -> Result<(), DataplaneFspMmpSkip> {
        self.owner_mut(owner)
            .ok_or(DataplaneFspMmpSkip::UnknownOwner)?
            .seed_fsp_path_mtu(path_mtu)
    }

    fn process_fsp_mmp_receiver_report(
        &mut self,
        owner: OwnerId,
        rr: &crate::mmp::report::ReceiverReport,
        last_outbound_next_hop: Option<NodeAddr>,
        now_ms: u64,
        now: std::time::Instant,
        min_loss_sample: u64,
    ) -> Result<DataplaneFspReceiverReportResult, DataplaneFspMmpSkip> {
        self.owner_mut(owner)
            .ok_or(DataplaneFspMmpSkip::UnknownOwner)?
            .process_fsp_mmp_receiver_report(
                rr,
                last_outbound_next_hop,
                now_ms,
                now,
                min_loss_sample,
            )
    }

    fn apply_fsp_path_mtu_signal(
        &mut self,
        owner: OwnerId,
        path_mtu: u16,
        now: std::time::Instant,
    ) -> Result<DataplaneFspPathMtuApplyResult, DataplaneFspMmpSkip> {
        self.owner_mut(owner)
            .ok_or(DataplaneFspMmpSkip::UnknownOwner)?
            .apply_fsp_path_mtu_signal(path_mtu, now)
    }

    fn min_fsp_rx_age_for_next_hop(&self, next_hop: &NodeAddr, now_ms: u64) -> Option<u64> {
        self.owners
            .values()
            .filter_map(OwnerState::fsp_activity)
            .filter(|activity| activity.tracks_next_hop(next_hop))
            .filter_map(|activity| activity.last_rx_age_ms(now_ms))
            .min()
    }

    fn min_fsp_data_rx_age_for_next_hop(&self, next_hop: &NodeAddr, now_ms: u64) -> Option<u64> {
        self.owners
            .values()
            .filter_map(OwnerState::fsp_activity)
            .filter(|activity| activity.tracks_data_next_hop(next_hop))
            .filter_map(|activity| activity.last_rx_data_age_ms(now_ms))
            .min()
    }

    fn any_fsp_recent_outbound_without_inbound_for_next_hop(
        &self,
        next_hop: &NodeAddr,
        now_ms: u64,
        timeout_ms: u64,
    ) -> bool {
        self.owners
            .values()
            .filter_map(OwnerState::fsp_activity)
            .filter(|activity| activity.tracks_next_hop(next_hop))
            .any(|activity| activity.has_recent_outbound_without_inbound(now_ms, timeout_ms))
    }

    fn submit_socket_packet_with_seq(
        &mut self,
        packet: SocketPacket,
        ingress_seq: u64,
    ) -> bool {
        self.admission.admit_with_seq(packet, ingress_seq)
    }

    fn submit_socket_packet_run_with_seq(
        &mut self,
        packets: Vec<SocketPacket>,
        first_seq: u64,
    ) -> bool {
        self.admission.admit_run_with_seq(packets, first_seq)
    }

    fn submit_outbound_packet_with_seq(
        &mut self,
        packet: OutboundPacket,
        ingress_seq: u64,
    ) -> bool {
        self.outbound_admission.admit_with_seq(packet, ingress_seq)
    }

    fn submit_outbound_packet_run_with_seq(
        &mut self,
        packets: Vec<OutboundPacket>,
        first_seq: u64,
    ) -> bool {
        self.outbound_admission
            .admit_run_with_seq(packets, first_seq)
    }

    fn dispatch_ingress_prepared_into(
        &mut self,
        limit: usize,
        prepared: &mut Vec<PreparedCryptoWork>,
        priority_only: bool,
        record_fsp_path_open: bool,
        fsp_path_open: &mut u64,
        fsp_path_open_bulk: &mut u64,
        drops: &mut Vec<PacketDrop>,
    ) -> usize {
        let mut dispatched = 0usize;
        let mut attempts_remaining = self.admission.len();
        while dispatched < limit && attempts_remaining > 0 {
            let run_limit = limit.saturating_sub(dispatched);
            let Some(mut run) = self.admission.pop_next_run(priority_only, run_limit) else {
                if !priority_only && limit > 0 {
                    crate::perf_profile::record_event(
                        crate::perf_profile::Event::DataplaneDispatchNoIngress,
                    );
                }
                break;
            };
            attempts_remaining = attempts_remaining.saturating_sub(run.items.len());
            if run.items.len() > 1 {
                crate::perf_profile::record_event_count(
                    crate::perf_profile::Event::DataplaneIngressOwnerRunContinue,
                    run.items.len().saturating_sub(1) as u64,
                );
            }
            let owner_id = run.cursor.owner;

            let Some(owner) = self.owners.get_mut(&owner_id) else {
                for queued in &run.items {
                    drops.push(PacketDrop::from_queued(
                        queued,
                        PacketDropReason::UnknownOwner,
                    ));
                }
                self.admission.continue_owner_lane(run.cursor);
                continue;
            };

            let mut remaining = Vec::new();
            let mut items = std::mem::take(&mut run.items).into_iter();
            while let Some(queued) = items.next() {
                if !owner.can_reserve_class(queued.packet.class) {
                    record_ingress_owner_blocked(owner.reserve_block_reason(queued.packet.class));
                    remaining.push(queued);
                    remaining.extend(items);
                    break;
                }

                match owner.reserve(&queued.packet, queued.ingress_seq) {
                    Ok((reservation, open_key)) => {
                        let packet_owner = queued.packet.owner;
                        let packet_counter = queued.packet.counter;
                        let packet_lane = queued.packet.lane();
                        let reservation = reservation.with_owner_shard(self.index);
                        if record_fsp_path_open {
                            count_fsp_path_open_dispatch(
                                &reservation,
                                fsp_path_open,
                                fsp_path_open_bulk,
                            );
                        }
                        match open_key {
                            Some(open_key) => prepared.push(PreparedCryptoWork::open(
                                CryptoWork {
                                    reservation,
                                    packet: queued.packet,
                                },
                                open_key,
                            )),
                            None => prepared.push(PreparedCryptoWork::failed(
                                reservation,
                                CryptoFailureKind::Open,
                            )),
                        }
                        tracing::debug!(
                            owner = ?packet_owner,
                            counter = packet_counter,
                            lane = ?packet_lane,
                            "dataplane inbound dispatched"
                        );
                        dispatched = dispatched.saturating_add(1);
                        attempts_remaining = self.admission.len();
                    }
                    Err(error) => {
                        tracing::debug!(
                            owner = ?queued.packet.owner,
                            counter = queued.packet.counter,
                            generation = queued.packet.generation,
                            class = ?queued.packet.class,
                            lane = ?queued.packet.lane(),
                            wire_flags = queued.packet.wire_flags,
                            receive_epoch = ?queued.packet.receive_epoch,
                            ingress_seq = queued.ingress_seq,
                            reason = ?error,
                            "dataplane inbound reservation failed"
                        );
                        drops.push(PacketDrop::from_queued(&queued, error.into()));
                    }
                }
            }

            if remaining.is_empty() {
                self.admission.continue_owner_lane(run.cursor);
            } else {
                run.items = remaining;
                self.admission.defer_owner_run(run);
            }
        }

        if !priority_only && limit > 0 && dispatched >= limit {
            crate::perf_profile::record_event(
                crate::perf_profile::Event::DataplaneDispatchLimitHit,
            );
        }
        dispatched
    }

    fn dispatch_outbound_prepared_into(
        &mut self,
        limit: usize,
        prepared: &mut Vec<PreparedCryptoWork>,
        priority_only: bool,
        drops: &mut Vec<PacketDrop>,
    ) -> usize {
        let mut dispatched = 0usize;
        let mut attempts_remaining = self.outbound_admission.len();
        while dispatched < limit && attempts_remaining > 0 {
            let run_limit = limit.saturating_sub(dispatched);
            let Some(mut run) = self
                .outbound_admission
                .pop_next_run(priority_only, run_limit)
            else {
                break;
            };
            attempts_remaining = attempts_remaining.saturating_sub(run.items.len());
            if run.items.len() > 1 {
                crate::perf_profile::record_event_count(
                    crate::perf_profile::Event::DataplaneOutboundOwnerRunContinue,
                    run.items.len().saturating_sub(1) as u64,
                );
            }
            let owner_id = run.cursor.owner;

            let Some(owner) = self.owners.get_mut(&owner_id) else {
                for queued in &run.items {
                    drops.push(PacketDrop::from_queued_outbound(
                        queued,
                        PacketDropReason::UnknownOwner,
                    ));
                }
                self.outbound_admission.continue_owner_lane(run.cursor);
                continue;
            };

            let mut remaining = Vec::new();
            let mut items = std::mem::take(&mut run.items).into_iter();
            while let Some(queued) = items.next() {
                let class = queued.packet.class;
                let ingress_seq = queued.ingress_seq;
                if !owner.can_reserve_class(class) {
                    record_outbound_owner_blocked(owner.reserve_block_reason(class));
                    remaining.push(queued);
                    remaining.extend(items);
                    break;
                }

                match owner.reserve_outbound(queued.packet, ingress_seq) {
                    Ok((reservation, packet)) => {
                        let reservation = reservation.with_owner_shard(self.index);
                        match owner.seal_key() {
                            Some(seal_key) => prepared.push(PreparedCryptoWork::seal(
                                OutboundCryptoWork {
                                    reservation,
                                    packet,
                                },
                                seal_key,
                            )),
                            None => prepared.push(PreparedCryptoWork::failed(
                                reservation,
                                CryptoFailureKind::Seal,
                            )),
                        }
                        dispatched = dispatched.saturating_add(1);
                    }
                    Err(error) => {
                        drops.push(PacketDrop {
                            owner: owner_id,
                            counter: None,
                            reason: error.into(),
                            crypto_failure: None,
                            wire_flags: None,
                            authenticated_counter_highest: None,
                        });
                    }
                }
                attempts_remaining = self.outbound_admission.len();
            }

            if remaining.is_empty() {
                self.outbound_admission.continue_owner_lane(run.cursor);
            } else {
                run.items = remaining;
                self.outbound_admission.defer_owner_run(run);
            }
        }
        dispatched
    }

    fn admission_queue_lens(&self) -> (usize, usize) {
        self.admission.lens()
    }

    fn admission_ready_lens(&self) -> (usize, usize) {
        self.admission.ready_lens()
    }

    fn outbound_admission_queue_lens(&self) -> (usize, usize) {
        self.outbound_admission.lens()
    }

    fn outbound_admission_ready_lens(&self) -> (usize, usize) {
        self.outbound_admission.ready_lens()
    }

    fn record_authenticated_fsp_session(
        &mut self,
        session: DataplaneAuthenticatedFspSession,
    ) -> Option<bool> {
        self.owner_mut(session.owner)
            .and_then(|owner| owner.record_authenticated_fsp_session(session))
    }

    fn record_fsp_decrypt_failure(&mut self, owner: OwnerId) -> Option<u32> {
        self.owner_mut(owner)
            .and_then(OwnerState::record_fsp_decrypt_failure)
    }

}
