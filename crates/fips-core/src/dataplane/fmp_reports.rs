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
        elicits_report: bool,
    ) {
        let owner = OwnerId::fmp_node(*node_addr);
        let Some(owner_state) = self.driver.owner_mut(owner) else {
            return;
        };
        owner_state.record_fmp_send_result(counter, timestamp_ms, bytes_sent, elicits_report);
        let due = owner_state.next_fmp_mmp_report_at(std::time::Instant::now());
        self.note_fmp_report_deadline(due);
    }

    /// Transfer the winning pending connection's sender before any active sends.
    /// Refusal returns the state unchanged; this never sends or runs a report.
    pub(crate) fn install_pending_fmp_sender(
        &mut self,
        node: &NodeAddr,
        expected_generation: u64,
        sender: crate::mmp::SenderState,
    ) -> Result<(), crate::mmp::SenderState> {
        let Some(owner) = self.driver.owner_mut(OwnerId::fmp_node(*node)) else {
            return Err(sender);
        };
        if owner.generation != expected_generation {
            return Err(sender);
        }
        let Some(mmp) = owner.fmp_mmp.as_mut() else {
            return Err(sender);
        };
        let pending_data = sender.cumulative_packets_sent() != 0;
        mmp.sender.absorb_pending_sender(sender)?;
        mmp.sender_report_pending |= pending_data;
        let due = owner.next_fmp_mmp_report_at(std::time::Instant::now());
        self.note_fmp_report_deadline(due);
        Ok(())
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
        let sender = (mmp.mode() == crate::mmp::MmpMode::Full && mmp.needs_sender_report())
            .then(|| mmp.sender.next_report_at(now))
            .flatten();
        let receiver = (mmp.mode() != crate::mmp::MmpMode::Minimal && mmp.receiver_report_pending)
            .then(|| mmp.receiver.next_report_at(now))
            .flatten();
        sender.into_iter().chain(receiver).min()
    }
}

#[cfg(test)]
mod pending_sender_tests {
    use super::*;

    #[test]
    fn pending_fmp_sender_install_requires_exact_owner_and_empty_interval() {
        let node = NodeAddr::from_bytes([9; 16]);
        let owner = OwnerId::fmp_node(node);
        let mut live = DataplaneLiveNode::new(AdmissionConfig::new(4, 8));
        let mut sender = crate::mmp::SenderState::new();
        sender.record_sent(0, 0, 37);
        let sender = live
            .install_pending_fmp_sender(&node, 3, sender)
            .err()
            .unwrap();
        assert_eq!(sender.cumulative_packets_sent(), 1);
        live.register_owner(owner, OwnerConfig::new(3, 8));
        let sender = live
            .install_pending_fmp_sender(&node, 3, sender)
            .err()
            .unwrap();
        assert_eq!(live.fmp_report_deadline(), None);
        live.unregister_owner(owner);
        live.register_owner(
            owner,
            OwnerConfig::new(3, 8).with_fmp_mmp(crate::mmp::MmpConfig::default(), true),
        );
        let sender = live
            .install_pending_fmp_sender(&node, 2, sender)
            .err()
            .unwrap();
        assert_eq!(live.fmp_report_deadline(), None);
        assert!(live.install_pending_fmp_sender(&node, 3, sender).is_ok());
        assert!(live.fmp_report_deadline().is_some());
        let mut second = crate::mmp::SenderState::new();
        second.record_sent(10, 9, 80);
        let second = live
            .install_pending_fmp_sender(&node, 3, second)
            .err()
            .unwrap();
        assert_eq!(second.cumulative_bytes_sent(), 80);
        let installed = &live
            .driver
            .owner_mut(owner)
            .unwrap()
            .fmp_mmp
            .as_ref()
            .unwrap()
            .sender;
        assert_eq!(installed.cumulative_packets_sent(), 1);
        assert_eq!(installed.cumulative_bytes_sent(), 37);
        // Subsequent ordinary sends append to, rather than replace, pending history.
        live.record_fmp_mmp_send_result(&node, 1, 20, 45, true);
        let installed = &live
            .driver
            .owner_mut(owner)
            .unwrap()
            .fmp_mmp
            .as_ref()
            .unwrap()
            .sender;
        assert_eq!(installed.cumulative_packets_sent(), 2);
        assert_eq!(installed.cumulative_bytes_sent(), 82);
        // Real owner rekey preserves lifetime totals but empties the old interval.
        live.driver.owner_mut(owner).unwrap().rekey(4);
        let mut replacement = crate::mmp::SenderState::new();
        replacement.record_sent(0, 0, 37);
        assert!(
            live.install_pending_fmp_sender(&node, 4, replacement)
                .is_ok()
        );
        let installed = &live
            .driver
            .owner_mut(owner)
            .unwrap()
            .fmp_mmp
            .as_ref()
            .unwrap()
            .sender;
        assert_eq!(installed.cumulative_packets_sent(), 3);
        assert_eq!(installed.cumulative_bytes_sent(), 119);
    }
    #[test]
    fn pending_fmp_sender_install_respects_report_modes() {
        use crate::mmp::{MmpConfig, MmpMode, SenderState};
        for mode in [MmpMode::Full, MmpMode::Lightweight, MmpMode::Minimal] {
            let node = NodeAddr::from_bytes([9; 16]);
            let owner = OwnerId::fmp_node(node);
            let mut live = DataplaneLiveNode::new(AdmissionConfig::new(4, 8));
            live.register_owner(
                owner,
                OwnerConfig::new(1, 8).with_fmp_mmp(
                    MmpConfig {
                        mode,
                        ..Default::default()
                    },
                    true,
                ),
            );
            let mut sender = SenderState::new();
            sender.record_sent(0, 0, 37);
            assert!(live.install_pending_fmp_sender(&node, 1, sender).is_ok());
            assert_eq!(live.fmp_report_deadline().is_some(), mode == MmpMode::Full);
            let installed = &live
                .driver
                .owner_mut(owner)
                .unwrap()
                .fmp_mmp
                .as_ref()
                .unwrap()
                .sender;
            assert_eq!(installed.cumulative_packets_sent(), 1);
            assert_eq!(installed.cumulative_bytes_sent(), 37);
        }
    }
}
