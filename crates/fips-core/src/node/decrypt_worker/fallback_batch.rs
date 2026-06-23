struct DecryptPlaintextFallbackBatch {
    fallback_tx: DecryptWorkerFallbackSender,
    fallbacks: Vec<DecryptFallback>,
    authenticated_sessions: Vec<DecryptAuthenticatedSession>,
    endpoint_sink: Option<DecryptDirectSessionDeliverySink>,
    endpoint_commits: Vec<DecryptDirectSessionCommit>,
    endpoint_deliveries: Vec<EndpointDataDelivery>,
    direct_commits: Vec<DecryptDirectSessionCommit>,
    direct_deliveries: Vec<PendingDirectSessionDelivery>,
    direct_data: Vec<DecryptDirectSessionData>,
}

impl DecryptPlaintextFallbackBatch {
    fn new(fallback_tx: DecryptWorkerFallbackSender) -> Self {
        Self {
            fallback_tx,
            fallbacks: Vec::with_capacity(DECRYPT_WORKER_BULK_BATCH_MAX),
            authenticated_sessions: Vec::with_capacity(DECRYPT_WORKER_BULK_BATCH_MAX),
            endpoint_sink: None,
            endpoint_commits: Vec::with_capacity(DECRYPT_WORKER_ENDPOINT_DELIVERY_BATCH_MAX),
            endpoint_deliveries: Vec::with_capacity(DECRYPT_WORKER_ENDPOINT_DELIVERY_BATCH_MAX),
            direct_commits: Vec::with_capacity(DECRYPT_WORKER_DIRECT_DELIVERY_BATCH_MAX),
            direct_deliveries: Vec::with_capacity(DECRYPT_WORKER_DIRECT_DELIVERY_BATCH_MAX),
            direct_data: Vec::with_capacity(DECRYPT_WORKER_DIRECT_DELIVERY_BATCH_MAX),
        }
    }

    fn batch_max(&self) -> usize {
        self.fallback_tx
            .bulk_packet_cap
            .clamp(1, DECRYPT_WORKER_BULK_BATCH_MAX)
    }

    fn endpoint_batch_max(&self) -> usize {
        self.fallback_tx
            .bulk_packet_cap
            .clamp(1, DECRYPT_WORKER_ENDPOINT_DELIVERY_BATCH_MAX)
    }

    fn direct_batch_max(&self) -> usize {
        self.fallback_tx
            .bulk_packet_cap
            .clamp(1, DECRYPT_WORKER_DIRECT_DELIVERY_BATCH_MAX)
    }

    fn push_output(&mut self, output: DecryptWorkerOutput) {
        if output.is_batchable_bulk_plaintext() {
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

        if output.is_batchable_authenticated_session() {
            self.flush_plaintext();
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

            self.endpoint_commits.push(commit);
            self.endpoint_deliveries.push(delivery);
            if self.endpoint_commits.len() >= self.endpoint_batch_max() {
                self.flush_endpoint();
            }
            return;
        }

        if output.is_batchable_direct_ipv6() {
            self.flush_plaintext();
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

            self.direct_commits.push(commit);
            self.direct_deliveries.push(direct_delivery);
            if self.direct_commits.len() >= self.direct_batch_max() {
                self.flush_direct();
            }
            return;
        }

        if output.is_batchable_direct_data() {
            self.flush_plaintext();
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
        let _ = output.send(&self.fallback_tx);
    }

    fn flush(&mut self) {
        self.flush_plaintext();
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
        let _ = self.fallback_tx.send(event);
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
        let _ = self.fallback_tx.send(event);
    }

    fn flush_endpoint(&mut self) {
        if self.endpoint_commits.is_empty() {
            return;
        }
        let _t_flush =
            crate::perf_profile::Timer::start(crate::perf_profile::Stage::DecryptWorkerOutputFlush);
        let Some(sink) = self.endpoint_sink.take() else {
            self.endpoint_commits.clear();
            self.endpoint_deliveries.clear();
            return;
        };
        let Some(endpoint_event_tx) = sink.endpoint_event_sender().cloned() else {
            self.endpoint_commits.clear();
            self.endpoint_deliveries.clear();
            return;
        };

        let event = if self.endpoint_commits.len() == 1 {
            DecryptWorkerEvent::DirectSessionCommit(
                self.endpoint_commits
                    .pop()
                    .expect("checked single direct endpoint commit"),
            )
        } else {
            let commits = std::mem::replace(
                &mut self.endpoint_commits,
                Vec::with_capacity(DECRYPT_WORKER_ENDPOINT_DELIVERY_BATCH_MAX),
            );
            DecryptWorkerEvent::DirectSessionCommitBatch(commits)
        };

        if !self.fallback_tx.send(event) {
            self.endpoint_deliveries.clear();
            return;
        }

        let count = self.endpoint_deliveries.len();
        if count == 0 {
            return;
        }
        let queued_at = crate::perf_profile::stamp();
        let endpoint_event = if count == 1 {
            let delivery = self
                .endpoint_deliveries
                .pop()
                .expect("checked single endpoint delivery");
            NodeEndpointEvent::Data {
                source_peer: delivery.source_peer,
                payload: delivery.payload,
                queued_at,
            }
        } else {
            let messages = std::mem::replace(
                &mut self.endpoint_deliveries,
                Vec::with_capacity(DECRYPT_WORKER_ENDPOINT_DELIVERY_BATCH_MAX),
            );
            NodeEndpointEvent::DataBatch {
                messages,
                queued_at,
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

    fn flush_direct(&mut self) {
        if self.direct_commits.is_empty() {
            return;
        }
        let _t_flush =
            crate::perf_profile::Timer::start(crate::perf_profile::Stage::DecryptWorkerOutputFlush);

        let event = if self.direct_commits.len() == 1 {
            DecryptWorkerEvent::DirectSessionCommit(
                self.direct_commits
                    .pop()
                    .expect("checked single direct commit"),
            )
        } else {
            let commits = std::mem::replace(
                &mut self.direct_commits,
                Vec::with_capacity(DECRYPT_WORKER_DIRECT_DELIVERY_BATCH_MAX),
            );
            DecryptWorkerEvent::DirectSessionCommitBatch(commits)
        };

        if !self.fallback_tx.send(event) {
            self.direct_deliveries.clear();
            return;
        }

        for delivery in self.direct_deliveries.drain(..) {
            delivery.deliver();
        }
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

        let _ = self.fallback_tx.send(event);
    }
}
