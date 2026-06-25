#[derive(Clone)]
pub(crate) struct DecryptWorkerReturnSender {
    lanes: PriorityBulkLaneSender<DecryptWorkerEvent>,
}

pub(crate) struct DecryptWorkerReturnReceivers {
    pub(crate) priority: TokioReceiver<DecryptWorkerEvent>,
    pub(crate) authenticated_bulk: TokioReceiver<DecryptWorkerEvent>,
    authenticated_bulk_credits: LaneCreditGate,
}

pub(crate) fn decrypt_worker_return_channels()
-> (DecryptWorkerReturnSender, DecryptWorkerReturnReceivers) {
    decrypt_worker_return_channels_with_caps(
        fallback_priority_channel_cap(),
        fallback_bulk_channel_cap(),
    )
}

fn decrypt_worker_return_channels_with_caps(
    priority_cap: usize,
    bulk_cap: usize,
) -> (DecryptWorkerReturnSender, DecryptWorkerReturnReceivers) {
    let (lanes, receivers) = priority_bulk_lane_channels(priority_cap, bulk_cap);
    let (priority_rx, authenticated_bulk_rx, authenticated_bulk_credits) = receivers.into_parts();
    (
        DecryptWorkerReturnSender { lanes },
        DecryptWorkerReturnReceivers {
            priority: priority_rx,
            authenticated_bulk: authenticated_bulk_rx,
            authenticated_bulk_credits,
        },
    )
}

impl DecryptWorkerReturnSender {
    #[cfg(test)]
    pub(crate) fn send_for_test(&self, event: DecryptWorkerEvent) -> bool {
        self.send(event)
    }

    fn authenticated_bulk_capacity(&self) -> usize {
        self.lanes.bulk_capacity()
    }

    fn send(&self, mut event: DecryptWorkerEvent) -> bool {
        let lane = decrypt_worker_event_lane(&event);
        let packet_lane = decrypt_worker_return_packet_lane(lane);
        let packet_count = event.packet_count();
        let drop_event = decrypt_worker_event_drop_event(&event, lane);
        let backlog_high_event = decrypt_worker_event_backlog_high_event(&event);
        event.set_trace_enqueued_at(crate::perf_profile::stamp());
        match self.lanes.try_send(event, packet_lane, packet_count, 0) {
            PriorityBulkLaneSendResult::Sent {
                previous_bulk_queued: Some(previous),
                ..
            } => {
                let queued = previous.saturating_add(packet_count);
                if previous < DECRYPT_FALLBACK_BACKLOG_HIGH_WATER
                    && queued >= DECRYPT_FALLBACK_BACKLOG_HIGH_WATER
                {
                    crate::perf_profile::record_event(backlog_high_event);
                }
                true
            }
            PriorityBulkLaneSendResult::Sent { .. } => true,
            PriorityBulkLaneSendResult::Dropped(drop) => {
                if matches!(drop.reason, PriorityBulkLaneDropReason::ReceiverClosed) {
                    debug!(?lane, "decrypt return receiver gone; dropping worker event");
                }
                record_decrypt_worker_return_drop_count(drop_event, lane, packet_count);
                false
            }
        }
    }
}

impl DecryptWorkerReturnReceivers {
    pub(crate) fn release_dequeued_event(&self, event: &DecryptWorkerEvent) {
        if matches!(event.lane(), DecryptWorkerLane::Bulk) {
            self.authenticated_bulk_credits
                .release_count(event.packet_count());
        }
    }

    #[cfg(test)]
    pub(crate) fn bulk_queued_packets(&self) -> usize {
        self.authenticated_bulk_queued_packets()
    }

    #[cfg(test)]
    pub(crate) fn bulk_pressure_queued_packets(&self) -> usize {
        self.authenticated_bulk_queued_packets()
    }

    #[cfg(test)]
    pub(crate) fn authenticated_bulk_queued_packets(&self) -> usize {
        self.authenticated_bulk_credits.queued_packets()
    }
}

fn decrypt_worker_return_packet_lane(lane: DecryptWorkerLane) -> PacketLane {
    match lane {
        DecryptWorkerLane::Priority => PacketLane::Priority,
        DecryptWorkerLane::Bulk => PacketLane::Bulk,
    }
}

fn decrypt_worker_event_lane(event: &DecryptWorkerEvent) -> DecryptWorkerLane {
    match event {
        DecryptWorkerEvent::AuthenticatedLink(link) => link.lane(),
        DecryptWorkerEvent::AuthenticatedLinkBatch(_) => DecryptWorkerLane::Bulk,
        DecryptWorkerEvent::AuthenticatedFmpReceive(receive) => receive.lane,
        DecryptWorkerEvent::AuthenticatedSession(session) => session.lane,
        DecryptWorkerEvent::AuthenticatedSessionBatch(_) => DecryptWorkerLane::Bulk,
        DecryptWorkerEvent::DirectSessionCommit(commit) => commit.lane,
        DecryptWorkerEvent::DirectSessionCommitBatch(_) => DecryptWorkerLane::Bulk,
        DecryptWorkerEvent::DirectSessionData(direct) => direct.lane,
        DecryptWorkerEvent::DirectSessionDataBatch(_) => DecryptWorkerLane::Bulk,
        DecryptWorkerEvent::FspDecryptFailure(report) => report.lane,
        DecryptWorkerEvent::DecryptFailure(_) => DecryptWorkerLane::Priority,
    }
}

fn decrypt_worker_event_backlog_high_event(
    event: &DecryptWorkerEvent,
) -> crate::perf_profile::Event {
    match event {
        DecryptWorkerEvent::AuthenticatedLink(_)
        | DecryptWorkerEvent::AuthenticatedLinkBatch(_)
        | DecryptWorkerEvent::AuthenticatedFmpReceive(_)
        | DecryptWorkerEvent::AuthenticatedSession(_)
        | DecryptWorkerEvent::AuthenticatedSessionBatch(_)
        | DecryptWorkerEvent::DirectSessionCommit(_)
        | DecryptWorkerEvent::DirectSessionCommitBatch(_)
        | DecryptWorkerEvent::DirectSessionData(_)
        | DecryptWorkerEvent::DirectSessionDataBatch(_) => {
            crate::perf_profile::Event::DecryptAuthenticatedBacklogHigh
        }
        DecryptWorkerEvent::FspDecryptFailure(_) | DecryptWorkerEvent::DecryptFailure(_) => {
            crate::perf_profile::Event::DecryptFallbackBacklogHigh
        }
    }
}

fn decrypt_worker_event_drop_event(
    event: &DecryptWorkerEvent,
    lane: DecryptWorkerLane,
) -> crate::perf_profile::Event {
    match event {
        DecryptWorkerEvent::AuthenticatedLink(_)
        | DecryptWorkerEvent::AuthenticatedLinkBatch(_)
        | DecryptWorkerEvent::AuthenticatedFmpReceive(_)
        | DecryptWorkerEvent::AuthenticatedSession(_)
        | DecryptWorkerEvent::AuthenticatedSessionBatch(_)
        | DecryptWorkerEvent::DirectSessionCommit(_)
        | DecryptWorkerEvent::DirectSessionCommitBatch(_)
        | DecryptWorkerEvent::DirectSessionData(_)
        | DecryptWorkerEvent::DirectSessionDataBatch(_) => match lane {
            DecryptWorkerLane::Priority => {
                crate::perf_profile::Event::DecryptAuthenticatedSessionPriorityDropped
            }
            DecryptWorkerLane::Bulk => {
                crate::perf_profile::Event::DecryptAuthenticatedSessionBulkDropped
            }
        },
        DecryptWorkerEvent::FspDecryptFailure(_)
        | DecryptWorkerEvent::DecryptFailure(_) => match lane {
            DecryptWorkerLane::Priority => {
                crate::perf_profile::Event::DecryptFallbackPriorityDropped
            }
            DecryptWorkerLane::Bulk => crate::perf_profile::Event::DecryptFallbackBulkDropped,
        },
    }
}
