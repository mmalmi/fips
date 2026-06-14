impl QueuedFmpSendJob {
    #[cfg(target_os = "linux")]
    fn linux_container(
        job: FmpSendJob,
        linux_container: Arc<LinuxBulkSendContainer>,
        linux_container_slot: usize,
    ) -> Self {
        let lane = encrypt_worker_lane_for_endpoint_data(job.bulk_endpoint_data);
        let target_key = job.send_target_key();
        let dispatch_key = SendDispatchKey::new(target_key, job.endpoint_flow_dispatch_key);
        let scheduling_weight = clamp_send_scheduling_weight(job.scheduling_weight);
        Self {
            job,
            lane,
            target_key,
            dispatch_key,
            scheduling_weight,
            fair_reservation: None,
            linux_container: Some(linux_container),
            linux_container_slot,
        }
    }

    fn complete_worker_drop(self) {
        #[cfg(target_os = "macos")]
        if let Some(flow) = self.macos_flow {
            flow.complete_many(vec![(self.macos_seq, MacSendItem::Skip)]);
            return;
        }

        #[cfg(target_os = "linux")]
        if let Some(container) = self.linux_container {
            container.skip(self.linux_container_slot);
            return;
        }

        drop(self);
    }
}
