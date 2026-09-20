impl DataplaneLiveNode {
    pub(crate) fn fmp_report_deadline(&self) -> Option<std::time::Instant> {
        self.fmp_report_deadline
    }

    // This is a conservative wake hint, not report authority. Touch only the
    // changed owner; collection replaces stale hints after removal or rekey.
    fn note_fmp_report_deadline(&mut self, due: Option<std::time::Instant>) {
        if let Some(due) = due {
            self.fmp_report_deadline =
                Some(self.fmp_report_deadline.map_or(due, |old| old.min(due)));
        }
    }

    pub(crate) fn record_authenticated_fmp_mmp_receive(
        &mut self,
        receive: DataplaneAuthenticatedFmpMmpReceive,
    ) -> Result<Option<std::time::Duration>, DataplaneFmpMmpSkip> {
        let Some(owner_state) = self.driver.owner_mut(receive.owner) else {
            return Err(DataplaneFmpMmpSkip::UnknownOwner);
        };
        let now = receive.now;
        let result = owner_state.record_authenticated_fmp_receive(receive);
        let due = owner_state.next_fmp_mmp_report_at(now);
        self.note_fmp_report_deadline(due);
        result
    }

    pub(crate) fn record_fmp_mmp_send_result(
        &mut self,
        node_addr: &NodeAddr,
        counter: u64,
        timestamp_ms: u32,
        bytes_sent: usize,
    ) {
        let owner = OwnerId::fmp_node(*node_addr);
        let Some(owner_state) = self.driver.owner_mut(owner) else {
            return;
        };
        owner_state.record_fmp_send_result(counter, timestamp_ms, bytes_sent);
        let due = owner_state.next_fmp_mmp_report_at(std::time::Instant::now());
        self.note_fmp_report_deadline(due);
    }

    pub(crate) fn process_fmp_mmp_receiver_report(
        &mut self,
        node_addr: &NodeAddr,
        rr: &crate::mmp::report::ReceiverReport,
        now_ms: u64,
        now: std::time::Instant,
    ) -> Result<DataplaneFmpReceiverReportResult, DataplaneFmpMmpSkip> {
        let owner = OwnerId::fmp_node(*node_addr);
        let Some(owner_state) = self.driver.owner_mut(owner) else {
            return Err(DataplaneFmpMmpSkip::UnknownOwner);
        };
        let result = owner_state.process_fmp_mmp_receiver_report(rr, now_ms, now);
        let due = owner_state.next_fmp_mmp_report_at(now);
        self.note_fmp_report_deadline(due);
        result
    }

    pub(crate) fn collect_fmp_mmp_reports(
        &mut self,
        now: std::time::Instant,
    ) -> DataplaneFmpMmpReportBatch {
        let batch = self.driver.collect_fmp_mmp_reports(now);
        self.fmp_report_deadline = batch.next_report_at;
        batch
    }
}

impl OwnerState {
    fn next_fmp_mmp_report_at(&self, now: std::time::Instant) -> Option<std::time::Instant> {
        if self.owner.protocol() != PacketProtocol::Fmp {
            return None;
        }
        let mmp = self.fmp_mmp.as_ref()?;
        let sender = (mmp.mode() == crate::mmp::MmpMode::Full)
            .then(|| mmp.sender.next_report_at(now))
            .flatten();
        let receiver = (mmp.mode() != crate::mmp::MmpMode::Minimal)
            .then(|| mmp.receiver.next_report_at(now))
            .flatten();
        sender.into_iter().chain(receiver).min()
    }
}
