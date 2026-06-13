#[derive(Clone)]
pub(crate) struct DecryptWorkerFallbackSender {
    priority: TokioSender<DecryptWorkerEvent>,
    bulk: TokioSender<DecryptWorkerEvent>,
    authenticated_bulk: TokioSender<DecryptWorkerEvent>,
    bulk_queued_packets: Arc<AtomicUsize>,
    authenticated_bulk_queued_packets: Arc<AtomicUsize>,
    bulk_packet_cap: usize,
}

pub(crate) struct DecryptWorkerFallbackReceivers {
    pub(crate) priority: TokioReceiver<DecryptWorkerEvent>,
    pub(crate) bulk: TokioReceiver<DecryptWorkerEvent>,
    pub(crate) authenticated_bulk: TokioReceiver<DecryptWorkerEvent>,
    bulk_queued_packets: Arc<AtomicUsize>,
    authenticated_bulk_queued_packets: Arc<AtomicUsize>,
}

pub(crate) fn decrypt_worker_fallback_channels()
-> (DecryptWorkerFallbackSender, DecryptWorkerFallbackReceivers) {
    decrypt_worker_fallback_channels_with_caps(
        fallback_priority_channel_cap(),
        fallback_bulk_channel_cap(),
    )
}

fn decrypt_worker_fallback_channels_with_caps(
    priority_cap: usize,
    bulk_cap: usize,
) -> (DecryptWorkerFallbackSender, DecryptWorkerFallbackReceivers) {
    let (priority_tx, priority_rx) = tokio::sync::mpsc::channel(priority_cap.max(1));
    let (bulk_tx, bulk_rx) = tokio::sync::mpsc::channel(bulk_cap.max(1));
    let (authenticated_bulk_tx, authenticated_bulk_rx) =
        tokio::sync::mpsc::channel(bulk_cap.max(1));
    let bulk_queued_packets = Arc::new(AtomicUsize::new(0));
    let authenticated_bulk_queued_packets = Arc::new(AtomicUsize::new(0));
    (
        DecryptWorkerFallbackSender {
            priority: priority_tx,
            bulk: bulk_tx,
            authenticated_bulk: authenticated_bulk_tx,
            bulk_queued_packets: Arc::clone(&bulk_queued_packets),
            authenticated_bulk_queued_packets: Arc::clone(&authenticated_bulk_queued_packets),
            bulk_packet_cap: bulk_cap.max(1),
        },
        DecryptWorkerFallbackReceivers {
            priority: priority_rx,
            bulk: bulk_rx,
            authenticated_bulk: authenticated_bulk_rx,
            bulk_queued_packets,
            authenticated_bulk_queued_packets,
        },
    )
}

impl DecryptWorkerFallbackSender {
    fn same_channels(&self, other: &Self) -> bool {
        self.priority.same_channel(&other.priority)
            && self.bulk.same_channel(&other.bulk)
            && self
                .authenticated_bulk
                .same_channel(&other.authenticated_bulk)
            && Arc::ptr_eq(&self.bulk_queued_packets, &other.bulk_queued_packets)
            && Arc::ptr_eq(
                &self.authenticated_bulk_queued_packets,
                &other.authenticated_bulk_queued_packets,
            )
            && self.bulk_packet_cap == other.bulk_packet_cap
    }

    fn send(&self, mut event: DecryptWorkerEvent) -> bool {
        let lane = decrypt_worker_event_lane(&event);
        event.set_trace_enqueued_at(crate::perf_profile::stamp());
        match lane {
            DecryptWorkerLane::Priority => self.send_priority_event(event),
            DecryptWorkerLane::Bulk => self.send_bulk_event(event),
        }
    }

    fn send_priority_event(&self, event: DecryptWorkerEvent) -> bool {
        match self.priority.try_send(event) {
            Ok(()) => true,
            // Worker completions are sent from decrypt OS threads. A full
            // priority return lane should slow those workers, not drop
            // control/rekey/liveness progress.
            Err(TokioTrySendError::Full(event)) => match self.priority.blocking_send(event) {
                Ok(()) => true,
                Err(_) => {
                    debug!("decrypt fallback receiver gone; dropping priority worker event");
                    false
                }
            },
            Err(TokioTrySendError::Closed(_)) => {
                debug!("decrypt fallback receiver gone; dropping priority worker event");
                false
            }
        }
    }

    fn send_bulk_event(&self, event: DecryptWorkerEvent) -> bool {
        let packet_count = event.packet_count();
        let drop_event = decrypt_worker_event_drop_event(&event, DecryptWorkerLane::Bulk);
        let bulk_lane = decrypt_worker_event_return_bulk_lane(&event);
        let queued_packets = self.return_bulk_queued_packets(bulk_lane);
        let Some(previous) = try_reserve_bulk_packets_with_previous(
            queued_packets,
            self.bulk_packet_cap,
            packet_count,
        ) else {
            record_decrypt_worker_return_drop_count(
                drop_event,
                DecryptWorkerLane::Bulk,
                packet_count,
            );
            return false;
        };
        let queued = previous.saturating_add(packet_count);
        if bulk_lane == DecryptWorkerReturnBulkLane::Fallback
            && previous < DECRYPT_FALLBACK_BACKLOG_HIGH_WATER
            && queued >= DECRYPT_FALLBACK_BACKLOG_HIGH_WATER
        {
            crate::perf_profile::record_event(
                crate::perf_profile::Event::DecryptFallbackBacklogHigh,
            );
        }

        let result = match bulk_lane {
            DecryptWorkerReturnBulkLane::Fallback => self.bulk.try_send(event),
            DecryptWorkerReturnBulkLane::Authenticated => self.authenticated_bulk.try_send(event),
        };
        match result {
            Ok(()) => true,
            Err(TokioTrySendError::Full(_)) => {
                release_bulk_packets(self.return_bulk_queued_packets(bulk_lane), packet_count);
                record_decrypt_worker_return_drop_count(
                    drop_event,
                    DecryptWorkerLane::Bulk,
                    packet_count,
                );
                false
            }
            Err(TokioTrySendError::Closed(_)) => {
                release_bulk_packets(self.return_bulk_queued_packets(bulk_lane), packet_count);
                debug!(
                    lane = ?DecryptWorkerLane::Bulk,
                    "decrypt fallback receiver gone; dropping worker event"
                );
                false
            }
        }
    }

    fn return_bulk_queued_packets(&self, lane: DecryptWorkerReturnBulkLane) -> &Arc<AtomicUsize> {
        match lane {
            DecryptWorkerReturnBulkLane::Fallback => &self.bulk_queued_packets,
            DecryptWorkerReturnBulkLane::Authenticated => &self.authenticated_bulk_queued_packets,
        }
    }
}

impl DecryptWorkerFallbackReceivers {
    pub(crate) fn release_dequeued_event(&self, event: &DecryptWorkerEvent) {
        if matches!(event.lane(), DecryptWorkerLane::Bulk) {
            let queued_packets =
                self.return_bulk_queued_packets(decrypt_worker_event_return_bulk_lane(event));
            release_bulk_packets(queued_packets, event.packet_count());
        }
    }

    pub(crate) fn bulk_queued_packets(&self) -> usize {
        self.bulk_queued_packets.load(Ordering::Relaxed)
    }

    #[cfg(test)]
    fn authenticated_bulk_queued_packets(&self) -> usize {
        self.authenticated_bulk_queued_packets
            .load(Ordering::Relaxed)
    }

    fn return_bulk_queued_packets(&self, lane: DecryptWorkerReturnBulkLane) -> &Arc<AtomicUsize> {
        match lane {
            DecryptWorkerReturnBulkLane::Fallback => &self.bulk_queued_packets,
            DecryptWorkerReturnBulkLane::Authenticated => &self.authenticated_bulk_queued_packets,
        }
    }
}

fn decrypt_worker_event_lane(event: &DecryptWorkerEvent) -> DecryptWorkerLane {
    match event {
        DecryptWorkerEvent::AuthenticatedFmpReceive(receive) => receive.lane,
        DecryptWorkerEvent::DirectFmpEndpointData(endpoint) => endpoint.lane,
        DecryptWorkerEvent::DirectFmpEndpointDataBatch(_) => DecryptWorkerLane::Bulk,
        DecryptWorkerEvent::Plaintext(fallback) => fallback.lane(),
        DecryptWorkerEvent::PlaintextBatch(_) => DecryptWorkerLane::Bulk,
        DecryptWorkerEvent::AuthenticatedSession(session) => session.lane,
        DecryptWorkerEvent::DirectSessionCommit(commit) => commit.lane,
        DecryptWorkerEvent::DirectSessionCommitBatch(_) => DecryptWorkerLane::Bulk,
        DecryptWorkerEvent::DirectSessionData(direct) => direct.lane,
        DecryptWorkerEvent::FspDecryptFailure(report) => report.lane,
        DecryptWorkerEvent::DecryptFailure(_) => DecryptWorkerLane::Priority,
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DecryptWorkerReturnBulkLane {
    Fallback,
    Authenticated,
}

fn decrypt_worker_event_return_bulk_lane(
    event: &DecryptWorkerEvent,
) -> DecryptWorkerReturnBulkLane {
    match event {
        DecryptWorkerEvent::AuthenticatedFmpReceive(_)
        | DecryptWorkerEvent::DirectFmpEndpointData(_)
        | DecryptWorkerEvent::DirectFmpEndpointDataBatch(_)
        | DecryptWorkerEvent::AuthenticatedSession(_)
        | DecryptWorkerEvent::DirectSessionCommit(_)
        | DecryptWorkerEvent::DirectSessionCommitBatch(_)
        | DecryptWorkerEvent::DirectSessionData(_) => DecryptWorkerReturnBulkLane::Authenticated,
        DecryptWorkerEvent::Plaintext(_)
        | DecryptWorkerEvent::PlaintextBatch(_)
        | DecryptWorkerEvent::FspDecryptFailure(_)
        | DecryptWorkerEvent::DecryptFailure(_) => DecryptWorkerReturnBulkLane::Fallback,
    }
}

fn decrypt_worker_event_drop_event(
    event: &DecryptWorkerEvent,
    lane: DecryptWorkerLane,
) -> crate::perf_profile::Event {
    match event {
        DecryptWorkerEvent::AuthenticatedFmpReceive(_)
        | DecryptWorkerEvent::DirectFmpEndpointData(_)
        | DecryptWorkerEvent::DirectFmpEndpointDataBatch(_)
        | DecryptWorkerEvent::AuthenticatedSession(_)
        | DecryptWorkerEvent::DirectSessionCommit(_)
        | DecryptWorkerEvent::DirectSessionCommitBatch(_)
        | DecryptWorkerEvent::DirectSessionData(_) => match lane {
            DecryptWorkerLane::Priority => {
                crate::perf_profile::Event::DecryptAuthenticatedSessionPriorityDropped
            }
            DecryptWorkerLane::Bulk => {
                crate::perf_profile::Event::DecryptAuthenticatedSessionBulkDropped
            }
        },
        DecryptWorkerEvent::Plaintext(_)
        | DecryptWorkerEvent::PlaintextBatch(_)
        | DecryptWorkerEvent::FspDecryptFailure(_)
        | DecryptWorkerEvent::DecryptFailure(_) => match lane {
            DecryptWorkerLane::Priority => {
                crate::perf_profile::Event::DecryptFallbackPriorityDropped
            }
            DecryptWorkerLane::Bulk => crate::perf_profile::Event::DecryptFallbackBulkDropped,
        },
    }
}
