use crate::packet_mover::{CommitBeforeOutputBatch, CommitBeforeOutputItems};

struct DecryptWorkerReturnBatch {
    return_tx: DecryptWorkerReturnSender,
    fallbacks: Vec<DecryptFallback>,
    authenticated_links: Vec<DecryptAuthenticatedLink>,
    authenticated_sessions: Vec<DecryptAuthenticatedSession>,
    endpoint_sink: Option<DecryptDirectSessionDeliverySink>,
    endpoint_outputs: CommitBeforeOutputBatch<DecryptDirectSessionCommit, EndpointDataDelivery>,
    direct_outputs: CommitBeforeOutputBatch<DecryptDirectSessionCommit, PendingDirectSessionDelivery>,
    direct_data: Vec<DecryptDirectSessionData>,
}

impl DecryptWorkerReturnBatch {
    fn new(return_tx: DecryptWorkerReturnSender) -> Self {
        Self {
            return_tx,
            fallbacks: Vec::with_capacity(DECRYPT_WORKER_BULK_BATCH_MAX),
            authenticated_links: Vec::with_capacity(DECRYPT_WORKER_BULK_BATCH_MAX),
            authenticated_sessions: Vec::with_capacity(DECRYPT_WORKER_BULK_BATCH_MAX),
            endpoint_sink: None,
            endpoint_outputs: CommitBeforeOutputBatch::new(
                DECRYPT_WORKER_ENDPOINT_DELIVERY_BATCH_MAX,
            ),
            direct_outputs: CommitBeforeOutputBatch::new(DECRYPT_WORKER_DIRECT_DELIVERY_BATCH_MAX),
            direct_data: Vec::with_capacity(DECRYPT_WORKER_DIRECT_DELIVERY_BATCH_MAX),
        }
    }

    fn batch_max(&self) -> usize {
        self.return_tx
            .bulk_credits
            .capacity()
            .clamp(1, DECRYPT_WORKER_BULK_BATCH_MAX)
    }

    fn endpoint_batch_max(&self) -> usize {
        self.return_tx
            .authenticated_bulk_credits
            .capacity()
            .clamp(1, DECRYPT_WORKER_ENDPOINT_DELIVERY_BATCH_MAX)
    }

    fn direct_batch_max(&self) -> usize {
        self.return_tx
            .authenticated_bulk_credits
            .capacity()
            .clamp(1, DECRYPT_WORKER_DIRECT_DELIVERY_BATCH_MAX)
    }

    fn push_output(&mut self, output: DecryptWorkerOutput) {
        if output.is_batchable_bulk_plaintext() {
            self.flush_authenticated_links();
            self.flush_authenticated_sessions();
            self.flush_endpoint();
            self.flush_direct();
            self.flush_direct_data();
            let DecryptWorkerOutput {
                event,
                direct_delivery,
            } = output;
            debug_assert!(direct_delivery.is_none());
            let DecryptWorkerEvent::Plaintext(fallback) = event else {
                unreachable!("checked batchable plaintext output")
            };
            self.fallbacks.push(fallback);
            if self.fallbacks.len() >= self.batch_max() {
                self.flush_plaintext();
            }
            return;
        }

        if output.is_batchable_authenticated_link() {
            self.flush_plaintext();
            self.flush_authenticated_sessions();
            self.flush_endpoint();
            self.flush_direct();
            self.flush_direct_data();
            let DecryptWorkerOutput {
                event,
                direct_delivery,
            } = output;
            debug_assert!(direct_delivery.is_none());
            let DecryptWorkerEvent::AuthenticatedLink(link) = event else {
                unreachable!("checked batchable authenticated link output")
            };
            self.authenticated_links.push(link);
            if self.authenticated_links.len() >= self.batch_max() {
                self.flush_authenticated_links();
            }
            return;
        }

        if output.is_batchable_authenticated_session() {
            self.flush_plaintext();
            self.flush_authenticated_links();
            self.flush_endpoint();
            self.flush_direct();
            self.flush_direct_data();
            let DecryptWorkerOutput {
                event,
                direct_delivery,
            } = output;
            debug_assert!(direct_delivery.is_none());
            let DecryptWorkerEvent::AuthenticatedSession(session) = event else {
                unreachable!("checked batchable authenticated session output")
            };
            self.authenticated_sessions.push(session);
            if self.authenticated_sessions.len() >= self.batch_max() {
                self.flush_authenticated_sessions();
            }
            return;
        }

        if output.is_batchable_direct_endpoint() {
            self.flush_plaintext();
            self.flush_authenticated_links();
            self.flush_authenticated_sessions();
            self.flush_direct();
            self.flush_direct_data();
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

            if self
                .endpoint_sink
                .as_ref()
                .is_none_or(|current| current.same_endpoint_event_channel(&sink))
            {
                if self.endpoint_sink.is_none() {
                    self.endpoint_sink = Some(sink);
                }
            } else {
                self.flush_endpoint();
                self.endpoint_sink = Some(sink);
            }

            self.endpoint_outputs.push(commit, delivery);
            if self.endpoint_outputs.len() >= self.endpoint_batch_max() {
                self.flush_endpoint();
            }
            return;
        }

        if output.is_batchable_direct_ipv6() {
            self.flush_plaintext();
            self.flush_authenticated_links();
            self.flush_authenticated_sessions();
            self.flush_endpoint();
            self.flush_direct_data();
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

            self.direct_outputs.push(commit, direct_delivery);
            if self.direct_outputs.len() >= self.direct_batch_max() {
                self.flush_direct();
            }
            return;
        }

        if output.is_batchable_direct_data() {
            self.flush_plaintext();
            self.flush_authenticated_links();
            self.flush_authenticated_sessions();
            self.flush_endpoint();
            self.flush_direct();
            let DecryptWorkerOutput {
                event,
                direct_delivery,
            } = output;
            debug_assert!(direct_delivery.is_none());
            let DecryptWorkerEvent::DirectSessionData(direct) = event else {
                unreachable!("checked batchable direct data output")
            };
            self.direct_data.push(direct);
            if self.direct_data.len() >= self.direct_batch_max() {
                self.flush_direct_data();
            }
            return;
        }

        self.flush();
        let _ = output.send(&self.return_tx);
    }

    fn flush(&mut self) {
        self.flush_plaintext();
        self.flush_authenticated_links();
        self.flush_authenticated_sessions();
        self.flush_endpoint();
        self.flush_direct();
        self.flush_direct_data();
    }

    fn flush_plaintext(&mut self) {
        if self.fallbacks.is_empty() {
            return;
        }
        let _t_flush =
            crate::perf_profile::Timer::start(crate::perf_profile::Stage::DecryptWorkerOutputFlush);
        let event = if self.fallbacks.len() == 1 {
            DecryptWorkerEvent::Plaintext(self.fallbacks.pop().expect("checked single fallback"))
        } else {
            let fallbacks = std::mem::replace(
                &mut self.fallbacks,
                Vec::with_capacity(DECRYPT_WORKER_BULK_BATCH_MAX),
            );
            DecryptWorkerEvent::PlaintextBatch(fallbacks)
        };
        let _ = self.return_tx.send(event);
    }

    fn flush_authenticated_sessions(&mut self) {
        if self.authenticated_sessions.is_empty() {
            return;
        }
        let _t_flush =
            crate::perf_profile::Timer::start(crate::perf_profile::Stage::DecryptWorkerOutputFlush);
        let event = if self.authenticated_sessions.len() == 1 {
            DecryptWorkerEvent::AuthenticatedSession(
                self.authenticated_sessions
                    .pop()
                    .expect("checked single authenticated session"),
            )
        } else {
            let sessions = std::mem::replace(
                &mut self.authenticated_sessions,
                Vec::with_capacity(DECRYPT_WORKER_BULK_BATCH_MAX),
            );
            DecryptWorkerEvent::AuthenticatedSessionBatch(sessions)
        };
        let _ = self.return_tx.send(event);
    }

    fn flush_authenticated_links(&mut self) {
        if self.authenticated_links.is_empty() {
            return;
        }
        let _t_flush =
            crate::perf_profile::Timer::start(crate::perf_profile::Stage::DecryptWorkerOutputFlush);
        let event = if self.authenticated_links.len() == 1 {
            DecryptWorkerEvent::AuthenticatedLink(
                self.authenticated_links
                    .pop()
                    .expect("checked single authenticated link"),
            )
        } else {
            let links = std::mem::replace(
                &mut self.authenticated_links,
                Vec::with_capacity(DECRYPT_WORKER_BULK_BATCH_MAX),
            );
            DecryptWorkerEvent::AuthenticatedLinkBatch(links)
        };
        let _ = self.return_tx.send(event);
    }

    fn flush_endpoint(&mut self) {
        if self.endpoint_outputs.is_empty() {
            return;
        }
        let _t_flush =
            crate::perf_profile::Timer::start(crate::perf_profile::Stage::DecryptWorkerOutputFlush);
        let Some(sink) = self.endpoint_sink.take() else {
            self.endpoint_outputs.clear();
            return;
        };
        let Some(endpoint_event_tx) = sink.endpoint_event_sender().cloned() else {
            self.endpoint_outputs.clear();
            return;
        };

        let return_tx = self.return_tx.clone();
        let _ = self.endpoint_outputs.flush_commit_then_output(
            |commits| {
                let event = match commits {
                    CommitBeforeOutputItems::One(commit) => {
                        DecryptWorkerEvent::DirectSessionCommit(commit)
                    }
                    CommitBeforeOutputItems::Many(commits) => {
                        DecryptWorkerEvent::DirectSessionCommitBatch(commits)
                    }
                };
                return_tx.send(event)
            },
            |deliveries| {
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
        );
    }

    fn flush_direct(&mut self) {
        if self.direct_outputs.is_empty() {
            return;
        }
        let _t_flush =
            crate::perf_profile::Timer::start(crate::perf_profile::Stage::DecryptWorkerOutputFlush);

        let return_tx = self.return_tx.clone();
        let _ = self.direct_outputs.flush_commit_then_output(
            |commits| {
                let event = match commits {
                    CommitBeforeOutputItems::One(commit) => {
                        DecryptWorkerEvent::DirectSessionCommit(commit)
                    }
                    CommitBeforeOutputItems::Many(commits) => {
                        DecryptWorkerEvent::DirectSessionCommitBatch(commits)
                    }
                };
                return_tx.send(event)
            },
            |deliveries| match deliveries {
                CommitBeforeOutputItems::One(delivery) => delivery.deliver(),
                CommitBeforeOutputItems::Many(deliveries) => {
                    for delivery in deliveries {
                        delivery.deliver();
                    }
                }
            },
        );
    }

    fn flush_direct_data(&mut self) {
        if self.direct_data.is_empty() {
            return;
        }
        let _t_flush =
            crate::perf_profile::Timer::start(crate::perf_profile::Stage::DecryptWorkerOutputFlush);

        let event = if self.direct_data.len() == 1 {
            DecryptWorkerEvent::DirectSessionData(
                self.direct_data
                    .pop()
                    .expect("checked single direct data"),
            )
        } else {
            let direct_data = std::mem::replace(
                &mut self.direct_data,
                Vec::with_capacity(DECRYPT_WORKER_DIRECT_DELIVERY_BATCH_MAX),
            );
            DecryptWorkerEvent::DirectSessionDataBatch(direct_data)
        };

        let _ = self.return_tx.send(event);
    }
}
