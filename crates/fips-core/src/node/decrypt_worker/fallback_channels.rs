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
    #[cfg(test)]
    pub(crate) fn send_for_test(&self, event: DecryptWorkerEvent) -> bool {
        self.send(event)
    }

    fn send(&self, mut event: DecryptWorkerEvent) -> bool {
        let lane = decrypt_worker_event_lane(&event);
        let packet_count = event.packet_count();
        let drop_event = decrypt_worker_event_drop_event(&event, lane);
        let bulk_lane = if matches!(lane, DecryptWorkerLane::Bulk) {
            Some(decrypt_worker_event_return_bulk_lane(&event))
        } else {
            None
        };
        event.set_trace_enqueued_at(crate::perf_profile::stamp());
        if let Some(bulk_lane) = bulk_lane {
            let queued_packets = self.return_bulk_queued_packets(bulk_lane);
            let Some(previous) = try_reserve_bulk_packets_with_previous(
                queued_packets,
                self.bulk_packet_cap,
                packet_count,
            ) else {
                record_decrypt_worker_return_drop_count(drop_event, lane, packet_count);
                return false;
            };
            let queued = previous.saturating_add(packet_count);
            if previous < DECRYPT_FALLBACK_BACKLOG_HIGH_WATER
                && queued >= DECRYPT_FALLBACK_BACKLOG_HIGH_WATER
            {
                let event = match bulk_lane {
                    DecryptWorkerReturnBulkLane::Fallback => {
                        crate::perf_profile::Event::DecryptFallbackBacklogHigh
                    }
                    DecryptWorkerReturnBulkLane::Authenticated => {
                        crate::perf_profile::Event::DecryptAuthenticatedBacklogHigh
                    }
                };
                crate::perf_profile::record_event(event);
            }
        }
        let result = match lane {
            DecryptWorkerLane::Priority => self.priority.try_send(event),
            DecryptWorkerLane::Bulk => match bulk_lane.expect("bulk event has return bulk lane") {
                DecryptWorkerReturnBulkLane::Fallback => self.bulk.try_send(event),
                DecryptWorkerReturnBulkLane::Authenticated => {
                    self.authenticated_bulk.try_send(event)
                }
            },
        };
        match result {
            Ok(()) => true,
            Err(TokioTrySendError::Full(_)) => {
                if let Some(bulk_lane) = bulk_lane {
                    release_bulk_packets(self.return_bulk_queued_packets(bulk_lane), packet_count);
                }
                record_decrypt_worker_return_drop_count(drop_event, lane, packet_count);
                false
            }
            Err(TokioTrySendError::Closed(_)) => {
                if let Some(bulk_lane) = bulk_lane {
                    release_bulk_packets(self.return_bulk_queued_packets(bulk_lane), packet_count);
                }
                debug!(
                    ?lane,
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

    #[cfg(test)]
    pub(crate) fn bulk_queued_packets(&self) -> usize {
        self.bulk_queued_packets.load(Ordering::Relaxed)
    }

    #[cfg(test)]
    pub(crate) fn bulk_pressure_queued_packets(&self) -> usize {
        self.bulk_queued_packets()
            .saturating_add(self.authenticated_bulk_queued_packets())
    }

    #[cfg(test)]
    pub(crate) fn authenticated_bulk_queued_packets(&self) -> usize {
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
        DecryptWorkerEvent::Plaintext(fallback) => fallback.lane(),
        DecryptWorkerEvent::PlaintextBatch(_) => DecryptWorkerLane::Bulk,
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
        | DecryptWorkerEvent::AuthenticatedSession(_)
        | DecryptWorkerEvent::AuthenticatedSessionBatch(_)
        | DecryptWorkerEvent::DirectSessionCommit(_)
        | DecryptWorkerEvent::DirectSessionCommitBatch(_)
        | DecryptWorkerEvent::DirectSessionData(_)
        | DecryptWorkerEvent::DirectSessionDataBatch(_) => {
            DecryptWorkerReturnBulkLane::Authenticated
        }
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
