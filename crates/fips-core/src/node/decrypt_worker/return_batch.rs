use crate::packet_mover::{
    CommitBeforeOutputItems, OwnerRetireBatchSink, OwnerRetireBatchTypes, OwnerRetireOutputBatch,
};

struct DecryptWorkerReturnBatch {
    return_tx: DecryptWorkerReturnSender,
    output_batch: OwnerRetireOutputBatch<DecryptWorkerRetireBatchTypes>,
}

impl DecryptWorkerReturnBatch {
    fn new(return_tx: DecryptWorkerReturnSender) -> Self {
        let authenticated_batch_max = return_tx
            .authenticated_bulk_capacity()
            .clamp(1, DECRYPT_WORKER_BULK_BATCH_MAX);
        let endpoint_batch_max = return_tx
            .authenticated_bulk_capacity()
            .clamp(1, DECRYPT_WORKER_ENDPOINT_DELIVERY_BATCH_MAX);
        let direct_batch_max = return_tx
            .authenticated_bulk_capacity()
            .clamp(1, DECRYPT_WORKER_DIRECT_DELIVERY_BATCH_MAX);
        Self {
            return_tx,
            output_batch: OwnerRetireOutputBatch::new(
                authenticated_batch_max,
                endpoint_batch_max,
                direct_batch_max,
            ),
        }
    }

    fn push_output(&mut self, output: DecryptWorkerOutput) {
        if output.is_batchable_authenticated_link() {
            let DecryptWorkerOutput {
                event,
                direct_delivery,
            } = output;
            debug_assert!(direct_delivery.is_none());
            let DecryptWorkerEvent::AuthenticatedLink(link) = event else {
                unreachable!("checked batchable authenticated link output")
            };
            let sink = DecryptWorkerRetireBatchSink {
                return_tx: &self.return_tx,
            };
            self.output_batch.push_authenticated_link(link, &sink);
            return;
        }

        if output.is_batchable_authenticated_session() {
            let DecryptWorkerOutput {
                event,
                direct_delivery,
            } = output;
            debug_assert!(direct_delivery.is_none());
            let DecryptWorkerEvent::AuthenticatedSession(session) = event else {
                unreachable!("checked batchable authenticated session output")
            };
            let sink = DecryptWorkerRetireBatchSink {
                return_tx: &self.return_tx,
            };
            self.output_batch
                .push_authenticated_session(session, &sink);
            return;
        }

        if output.is_batchable_direct_endpoint() {
            let DecryptWorkerOutput {
                event,
                direct_delivery,
            } = output;
            let DecryptWorkerEvent::DirectSessionCommit(commit) = event else {
                unreachable!("checked batchable direct endpoint commit output")
            };
            let Some(direct_delivery) = direct_delivery else {
                unreachable!("checked batchable direct endpoint delivery")
            };
            let Ok((sink, delivery)) = direct_delivery.into_endpoint_data() else {
                unreachable!("checked batchable endpoint delivery")
            };
            let return_sink = DecryptWorkerRetireBatchSink {
                return_tx: &self.return_tx,
            };
            self.output_batch
                .push_direct_endpoint(sink, commit, delivery, &return_sink);
            return;
        }

        if output.is_batchable_direct_ipv6() {
            let DecryptWorkerOutput {
                event,
                direct_delivery,
            } = output;
            let DecryptWorkerEvent::DirectSessionCommit(commit) = event else {
                unreachable!("checked batchable direct IPv6 commit output")
            };
            let Some(direct_delivery) = direct_delivery else {
                unreachable!("checked batchable direct IPv6 delivery")
            };

            let sink = DecryptWorkerRetireBatchSink {
                return_tx: &self.return_tx,
            };
            self.output_batch
                .push_direct(commit, direct_delivery, &sink);
            return;
        }

        if output.is_batchable_direct_data() {
            let DecryptWorkerOutput {
                event,
                direct_delivery,
            } = output;
            debug_assert!(direct_delivery.is_none());
            let DecryptWorkerEvent::DirectSessionData(direct) = event else {
                unreachable!("checked batchable direct data output")
            };
            let sink = DecryptWorkerRetireBatchSink {
                return_tx: &self.return_tx,
            };
            self.output_batch.push_direct_data(direct, &sink);
            return;
        }

        self.flush();
        let _ = output.send(&self.return_tx);
    }

    fn flush(&mut self) {
        let sink = DecryptWorkerRetireBatchSink {
            return_tx: &self.return_tx,
        };
        self.output_batch.flush(&sink);
    }

    #[cfg(test)]
    fn is_empty(&self) -> bool {
        self.output_batch.is_empty()
    }
}

struct DecryptWorkerRetireBatchTypes;

impl OwnerRetireBatchTypes for DecryptWorkerRetireBatchTypes {
    type AuthenticatedLink = DecryptAuthenticatedLink;
    type AuthenticatedSession = DecryptAuthenticatedSession;
    type DirectCommit = DecryptDirectSessionCommit;
    type EndpointSink = DecryptDirectSessionDeliverySink;
    type EndpointDelivery = EndpointDataDelivery;
    type DirectDelivery = PendingDirectSessionDelivery;
    type DirectData = DecryptDirectSessionData;
}

struct DecryptWorkerRetireBatchSink<'a> {
    return_tx: &'a DecryptWorkerReturnSender,
}

impl OwnerRetireBatchSink<DecryptWorkerRetireBatchTypes> for DecryptWorkerRetireBatchSink<'_> {
    fn send_authenticated_links(
        &self,
        links: CommitBeforeOutputItems<DecryptAuthenticatedLink>,
    ) -> bool {
        let event = match links {
            CommitBeforeOutputItems::One(link) => DecryptWorkerEvent::AuthenticatedLink(link),
            CommitBeforeOutputItems::Many(links) => DecryptWorkerEvent::AuthenticatedLinkBatch(links),
        };
        self.return_tx.send(event)
    }

    fn send_authenticated_sessions(
        &self,
        sessions: CommitBeforeOutputItems<DecryptAuthenticatedSession>,
    ) -> bool {
        let event = match sessions {
            CommitBeforeOutputItems::One(session) => {
                DecryptWorkerEvent::AuthenticatedSession(session)
            }
            CommitBeforeOutputItems::Many(sessions) => {
                DecryptWorkerEvent::AuthenticatedSessionBatch(sessions)
            }
        };
        self.return_tx.send(event)
    }

    fn send_direct_commits(
        &self,
        commits: CommitBeforeOutputItems<DecryptDirectSessionCommit>,
    ) -> bool {
        let event = match commits {
            CommitBeforeOutputItems::One(commit) => DecryptWorkerEvent::DirectSessionCommit(commit),
            CommitBeforeOutputItems::Many(commits) => {
                DecryptWorkerEvent::DirectSessionCommitBatch(commits)
            }
        };
        self.return_tx.send(event)
    }

    fn send_direct_data(
        &self,
        direct_data: CommitBeforeOutputItems<DecryptDirectSessionData>,
    ) -> bool {
        let event = match direct_data {
            CommitBeforeOutputItems::One(direct) => DecryptWorkerEvent::DirectSessionData(direct),
            CommitBeforeOutputItems::Many(direct_data) => {
                DecryptWorkerEvent::DirectSessionDataBatch(direct_data)
            }
        };
        self.return_tx.send(event)
    }

    fn same_endpoint_sink(
        &self,
        current: &DecryptDirectSessionDeliverySink,
        next: &DecryptDirectSessionDeliverySink,
    ) -> bool {
        current.same_endpoint_event_channel(next)
    }

    fn endpoint_sink_ready(&self, sink: &DecryptDirectSessionDeliverySink) -> bool {
        sink.endpoint_event_sender().is_some()
    }

    fn deliver_endpoint(
        &self,
        sink: &DecryptDirectSessionDeliverySink,
        deliveries: CommitBeforeOutputItems<EndpointDataDelivery>,
    ) {
        let Some(endpoint_event_tx) = sink.endpoint_event_sender().cloned() else {
            return;
        };
        let count = deliveries.len();
        if count == 0 {
            return;
        }
        let queued_at = crate::perf_profile::stamp();
        let endpoint_event = match deliveries {
            CommitBeforeOutputItems::One(delivery) => NodeEndpointEvent::Data {
                source_peer: delivery.source_peer,
                payload: delivery.payload,
                queued_at,
            },
            CommitBeforeOutputItems::Many(messages) => {
                NodeEndpointEvent::DataBatch { messages, queued_at }
            }
        };
        let _t_deliver =
            crate::perf_profile::Timer::start(crate::perf_profile::Stage::EndpointDeliver);
        if let Err(error) = endpoint_event_tx.send(endpoint_event) {
            debug!(
                error = %error,
                messages = count,
                "Failed to deliver worker-decoded endpoint data batch"
            );
        }
    }

    fn deliver_direct(&self, deliveries: CommitBeforeOutputItems<PendingDirectSessionDelivery>) {
        match deliveries {
            CommitBeforeOutputItems::One(delivery) => delivery.deliver(),
            CommitBeforeOutputItems::Many(deliveries) => {
                for delivery in deliveries {
                    delivery.deliver();
                }
            }
        }
    }
}
