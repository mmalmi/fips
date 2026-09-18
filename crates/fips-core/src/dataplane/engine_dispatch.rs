impl Dataplane {
    fn prepare_aead_available_into(
        &mut self,
        limit: usize,
        prepared_work: &mut Vec<PreparedCryptoRun>,
        ready_slots: &mut Vec<Arc<CryptoReadySlot>>,
        worker_pool: &DataplaneAeadWorkerPool,
    ) -> usize {
        prepared_work.clear();
        ready_slots.clear();
        let _owner_dispatch_timer =
            crate::perf_profile::Timer::start(crate::perf_profile::Stage::DataplaneOwnerDispatch);
        let worker_capacity = worker_pool.available_capacity();
        let total_limit = limit.min(worker_capacity);
        if limit > 0 && worker_capacity == 0 {
            crate::perf_profile::record_event(
                crate::perf_profile::Event::DataplaneDispatchExecutorFull,
            );
        }
        let priority_capacity =
            total_limit.min(worker_pool.available_capacity_for_lane(Lane::Priority));
        let mut priority_inbound_capacity = priority_capacity;
        let mut bulk_capacity =
            total_limit.min(worker_pool.available_capacity_for_lane(Lane::Bulk));
        let inbound_priority_pending = self.has_inbound_priority_pending();
        let outbound_priority_reserve = outbound_priority_dispatch_limit(
            priority_capacity,
            self.has_outbound_priority_pending(),
        );
        let pre_priority_inbound_limit =
            inbound_before_outbound_priority_limit(priority_capacity, outbound_priority_reserve)
                .min(if inbound_priority_pending {
                    priority_inbound_capacity
                } else {
                    bulk_capacity
                });
        let mut fsp_path_open = FspPathOpenDispatch::new(crate::perf_profile::enabled());

        let mut dispatched_total = self.dispatch_prepared_ingress_shards_into(
            pre_priority_inbound_limit,
            prepared_work,
            ready_slots,
            if inbound_priority_pending {
                Lane::Priority
            } else {
                Lane::Bulk
            },
            &mut fsp_path_open,
        );
        priority_inbound_capacity = priority_inbound_capacity.saturating_sub(dispatched_total);
        if !inbound_priority_pending {
            bulk_capacity = bulk_capacity.saturating_sub(dispatched_total);
        }

        let priority_outbound_limit =
            outbound_priority_reserve.min(total_limit.saturating_sub(dispatched_total));
        dispatched_total =
            dispatched_total.saturating_add(self.dispatch_outbound_prepared_shards_into(
                priority_outbound_limit,
                prepared_work,
                ready_slots,
                Lane::Priority,
            ));

        let priority_inbound_limit = if inbound_priority_pending {
            priority_inbound_capacity.min(total_limit.saturating_sub(dispatched_total))
        } else {
            0
        };
        dispatched_total =
            dispatched_total.saturating_add(self.dispatch_prepared_ingress_shards_into(
                priority_inbound_limit,
                prepared_work,
                ready_slots,
                Lane::Priority,
                &mut fsp_path_open,
            ));

        dispatched_total =
            dispatched_total.saturating_add(self.dispatch_outbound_prepared_shards_into(
                total_limit.saturating_sub(dispatched_total),
                prepared_work,
                ready_slots,
                Lane::Priority,
            ));
        let bulk_inbound = self.dispatch_prepared_ingress_shards_into(
            total_limit
                .saturating_sub(dispatched_total)
                .min(bulk_capacity),
            prepared_work,
            ready_slots,
            Lane::Bulk,
            &mut fsp_path_open,
        );
        dispatched_total = dispatched_total.saturating_add(bulk_inbound);
        bulk_capacity = bulk_capacity.saturating_sub(bulk_inbound);
        let bulk_outbound = self.dispatch_outbound_prepared_shards_into(
            total_limit
                .saturating_sub(dispatched_total)
                .min(bulk_capacity),
            prepared_work,
            ready_slots,
            Lane::Bulk,
        );
        dispatched_total = dispatched_total.saturating_add(bulk_outbound);
        bulk_capacity = bulk_capacity.saturating_sub(bulk_outbound);
        // Admission and owner queues retain free backlog until both normal
        // directions have had their dispatch turn. Ordered crypto already in
        // flight cannot be preempted; worker and owner caps bound that delay.
        let background_capacity = worker_pool
            .available_capacity_for_lane(Lane::Background)
            .min(bulk_capacity);
        let background_inbound = self.dispatch_prepared_ingress_shards_into(
            total_limit
                .saturating_sub(dispatched_total)
                .min(background_capacity),
            prepared_work,
            ready_slots,
            Lane::Background,
            &mut fsp_path_open,
        );
        dispatched_total = dispatched_total.saturating_add(background_inbound);
        dispatched_total = dispatched_total.saturating_add(
            self.dispatch_outbound_prepared_shards_into(
                total_limit
                    .saturating_sub(dispatched_total)
                    .min(background_capacity.saturating_sub(background_inbound)),
                prepared_work,
                ready_slots,
                Lane::Background,
            ),
        );
        fsp_path_open.record();
        dispatched_total
    }
}
