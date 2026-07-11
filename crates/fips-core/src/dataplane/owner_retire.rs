impl OwnerState {
    fn stage_retire_slot(&mut self, slot: Arc<CryptoReadySlot>) -> bool {
        debug_assert_eq!(slot.owner(), self.owner);
        let was_empty = self.pending.is_empty();
        let slot = OwnerRetireSlot::new(slot);
        let order = slot.order();
        if self
            .pending
            .back()
            .is_none_or(|pending| pending.order() < order)
        {
            self.pending.push_back(slot);
        } else {
            let index = self
                .pending
                .partition_point(|pending| pending.order() < order);
            assert_ne!(
                self.pending[index].order(),
                order,
                "owner retire slot order reused"
            );
            self.pending.insert(index, slot);
        }
        was_empty
    }

    fn has_pending_retirements(&self) -> bool {
        !self.pending.is_empty()
    }

    fn has_ready_retirement(&self) -> bool {
        self.pending
            .front()
            .is_some_and(|slot| slot.order() == OrderToken(self.next_retire) && slot.is_ready())
    }

    fn take_pending_retirements(&mut self) -> Vec<OwnerRetireSlot> {
        self.pending.drain(..).collect()
    }

    fn retire_ready_slots_into(
        &mut self,
        limit: usize,
        retired: &mut DataplaneRetiredOutputSink<'_>,
        drops: &mut Vec<PacketDrop>,
        compact_endpoint_data: bool,
    ) -> usize {
        let mut retired_count = 0usize;
        while retired_count < limit {
            let order = OrderToken(self.next_retire);
            let Some(front) = self.pending.front() else {
                break;
            };
            if front.order() != order || !front.is_ready() {
                break;
            }
            let mut slot = self.pending.pop_front().expect("owner retire head exists");

            let slot_limit = limit.saturating_sub(retired_count).min(slot.remaining());
            let stale_generation = slot.generation() != self.generation;
            let compact_fsp_run = !stale_generation
                && slot.is_open_fsp_session_payload_run();
            let drained = if stale_generation {
                slot.drain_results(slot_limit, |completion| {
                    drops.push(PacketDrop::from_completion(
                        &completion,
                        PacketDropReason::StaleCompletionGeneration,
                        None,
                    ));
                })
            } else if compact_fsp_run {
                self.retire_ready_open_fsp_session_payload_slot_into(
                    &mut slot,
                    slot_limit,
                    retired,
                    drops,
                    compact_endpoint_data,
                )
            } else {
                slot.drain_results(slot_limit, |completion| {
                    self.retire_ready_completion_into(
                        completion,
                        retired,
                        drops,
                        compact_endpoint_data,
                    );
                })
            };

            self.next_retire = self.next_retire.wrapping_add(drained as u64);
            self.in_flight = self.in_flight.saturating_sub(drained);
            if slot.lane() == Lane::Bulk {
                self.bulk_in_flight = self.bulk_in_flight.saturating_sub(drained);
            }
            retired_count = retired_count.saturating_add(drained);
            if !slot.is_empty() {
                debug_assert_eq!(slot.order(), OrderToken(self.next_retire));
                self.pending.push_front(slot);
            }
        }
        retired_count
    }

    fn retire_ready_open_fsp_session_payload_slot_into(
        &mut self,
        slot: &mut OwnerRetireSlot,
        limit: usize,
        retired: &mut DataplaneRetiredOutputSink<'_>,
        drops: &mut Vec<PacketDrop>,
        compact_endpoint_data: bool,
    ) -> usize {
        let mut endpoint_data_batch: Option<DataplaneEndpointDataBatch> = None;
        let mut endpoint_packets = 0usize;
        let record_endpoint_packets = crate::perf_profile::enabled();
        let mut direct_enqueued_at_ms = None;
        let received_at = std::time::Instant::now();
        let drained = slot.drain_results(limit, |completion| {
            if !self.complete_replay_reservation(&completion.reservation, true) {
                drops.push(PacketDrop::from_completion(
                    &completion,
                    PacketDropReason::Replay,
                    None,
                ));
                return;
            }
            let CryptoResult::Opened(output) = completion.result else {
                unreachable!("open FSP session payload slot contains only opened outputs");
            };
            self.authenticated_counter_highest = self
                .authenticated_counter_highest
                .max(completion.reservation.counter);
            let mut output = output;
            if compact_endpoint_data {
                let enqueued_at_ms =
                    *direct_enqueued_at_ms.get_or_insert_with(crate::time::now_ms);
                if let Some(ingress) =
                    DataplaneFspEndpointDataIngress::take_from_output(&mut output, enqueued_at_ms)
                {
                    self.record_retired_endpoint_data_ingress(&ingress, received_at);
                    if record_endpoint_packets {
                        endpoint_packets = endpoint_packets.saturating_add(1);
                    }
                    match &mut endpoint_data_batch {
                        Some(batch) => batch.push(ingress),
                        None => {
                            endpoint_data_batch =
                                Some(DataplaneEndpointDataBatch::from_ingress(ingress));
                        }
                    }
                    return;
                }
            }

            flush_retired_endpoint_data_batch(retired, &mut endpoint_data_batch);
            retired.push_output(output);
        });
        flush_retired_endpoint_data_batch(retired, &mut endpoint_data_batch);
        if record_endpoint_packets {
            crate::perf_profile::record_dataplane_established_fsp_data_retire_run(endpoint_packets);
        }
        drained
    }

    fn retire_ready_completion_into(
        &mut self,
        completion: CryptoCompletion,
        retired: &mut DataplaneRetiredOutputSink<'_>,
        drops: &mut Vec<PacketDrop>,
        compact_endpoint_data: bool,
    ) {
        let replay_accepted = self.complete_replay_reservation(
            &completion.reservation,
            matches!(&completion.result, CryptoResult::Opened(_)),
        );
        if matches!(&completion.result, CryptoResult::Opened(_)) && !replay_accepted {
            drops.push(PacketDrop::from_completion(
                &completion,
                PacketDropReason::Replay,
                None,
            ));
            return;
        }
        match completion.result {
            CryptoResult::Opened(output) => {
                self.authenticated_counter_highest = self
                    .authenticated_counter_highest
                    .max(completion.reservation.counter);
                self.retire_opened_output_into(output, retired, compact_endpoint_data);
            }
            CryptoResult::Sealed(output) => retired.push_output(output),
            CryptoResult::Outbound(packet) => retired.push_outbound(packet),
            CryptoResult::Failed(failure) => {
                drops.push(PacketDrop::from_completion_with_authenticated_highest(
                    &completion,
                    PacketDropReason::CryptoFailed,
                    failure,
                    self.authenticated_counter_highest,
                ));
            }
        }
    }

    fn retire_opened_output_into(
        &mut self,
        output: PacketOutput,
        retired: &mut DataplaneRetiredOutputSink<'_>,
        compact_endpoint_data: bool,
    ) {
        if compact_endpoint_data && matches!(output.target(), OutputTarget::SessionPayload { .. }) {
            let mut output = output;
            if let Some(ingress) =
                DataplaneFspEndpointDataIngress::take_from_output(&mut output, crate::time::now_ms())
            {
                self.record_retired_endpoint_data_ingress(&ingress, std::time::Instant::now());
                retired.push_endpoint_data_batch(ingress);
            } else {
                retired.push_output(output);
            }
            return;
        }

        retired.push_output(output);
    }

    fn record_retired_endpoint_data_ingress(
        &mut self,
        ingress: &DataplaneFspEndpointDataIngress,
        received_at: std::time::Instant,
    ) {
        let commit = ingress.commit();
        if self.owner != OwnerId::fsp_node(commit.source_addr()) {
            return;
        }
        let _ = self.record_authenticated_fsp_session(DataplaneAuthenticatedFspSession::new(
            commit.source_addr(),
            commit.previous_hop_addr(),
            crate::protocol::SessionMessageType::EndpointData.to_byte(),
            ingress.body_len,
            ingress.receive_sync,
            ingress.activity_tick,
            received_at,
        ));
    }

    fn reserve_class(&mut self, class: PacketClass) {
        self.in_flight = self.in_flight.saturating_add(1);
        if class.lane() == Lane::Bulk {
            self.bulk_in_flight = self.bulk_in_flight.saturating_add(1);
        }
    }
}

fn note_activity(slot: &mut Option<ActivityTick>, tick: ActivityTick) -> bool {
    match slot {
        Some(current) if *current >= tick => false,
        _ => {
            *slot = Some(tick);
            true
        }
    }
}

fn flush_retired_endpoint_data_batch(
    retired: &mut DataplaneRetiredOutputSink<'_>,
    endpoint_data_batch: &mut Option<DataplaneEndpointDataBatch>,
) {
    if let Some(batch) = endpoint_data_batch.take() {
        retired.append_endpoint_data_batch(batch);
    }
}
