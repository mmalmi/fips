struct DecryptPlaintextFallbackBatch {
    fallback_tx: Option<DecryptWorkerFallbackSender>,
    fallbacks: Vec<DecryptFallback>,
    authenticated_session_fallback_tx: Option<DecryptWorkerFallbackSender>,
    authenticated_sessions: Vec<DecryptAuthenticatedSession>,
    endpoint_fallback_tx: Option<DecryptWorkerFallbackSender>,
    endpoint_commits: Vec<DecryptDirectSessionCommit>,
    endpoint_deliveries: Vec<EndpointDataDelivery>,
    direct_fallback_tx: Option<DecryptWorkerFallbackSender>,
    direct_commits: Vec<DecryptDirectSessionCommit>,
    direct_deliveries: Vec<PendingDirectSessionDelivery>,
    direct_data_fallback_tx: Option<DecryptWorkerFallbackSender>,
    direct_data: Vec<DecryptDirectSessionData>,
}

impl DecryptPlaintextFallbackBatch {
    fn new() -> Self {
        Self {
            fallback_tx: None,
            fallbacks: Vec::with_capacity(DECRYPT_WORKER_BULK_BATCH_MAX),
            authenticated_session_fallback_tx: None,
            authenticated_sessions: Vec::with_capacity(DECRYPT_WORKER_BULK_BATCH_MAX),
            endpoint_fallback_tx: None,
            endpoint_commits: Vec::with_capacity(DECRYPT_WORKER_ENDPOINT_DELIVERY_BATCH_MAX),
            endpoint_deliveries: Vec::with_capacity(DECRYPT_WORKER_ENDPOINT_DELIVERY_BATCH_MAX),
            direct_fallback_tx: None,
            direct_commits: Vec::with_capacity(DECRYPT_WORKER_DIRECT_DELIVERY_BATCH_MAX),
            direct_deliveries: Vec::with_capacity(DECRYPT_WORKER_DIRECT_DELIVERY_BATCH_MAX),
            direct_data_fallback_tx: None,
            direct_data: Vec::with_capacity(DECRYPT_WORKER_DIRECT_DELIVERY_BATCH_MAX),
        }
    }

    fn batch_max_for(fallback_tx: &DecryptWorkerFallbackSender) -> usize {
        fallback_tx
            .bulk_packet_cap
            .clamp(1, DECRYPT_WORKER_BULK_BATCH_MAX)
    }

    fn endpoint_batch_max_for(fallback_tx: &DecryptWorkerFallbackSender) -> usize {
        fallback_tx
            .bulk_packet_cap
            .clamp(1, DECRYPT_WORKER_ENDPOINT_DELIVERY_BATCH_MAX)
    }

    fn direct_batch_max_for(fallback_tx: &DecryptWorkerFallbackSender) -> usize {
        fallback_tx
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
                fallback_tx,
                event,
                direct_delivery,
            } = output;
            debug_assert!(direct_delivery.is_none());
            let DecryptWorkerEvent::Plaintext(fallback) = event else {
                unreachable!("checked batchable plaintext output")
            };
            if self
                .fallback_tx
                .as_ref()
                .is_some_and(|current| !current.same_channels(&fallback_tx))
            {
                self.flush();
            }
            if self.fallback_tx.is_none() {
                self.fallback_tx = Some(fallback_tx);
            }
            let batch_max = Self::batch_max_for(
                self.fallback_tx
                    .as_ref()
                    .expect("fallback sender set before batching plaintext"),
            );
            self.fallbacks.push(fallback);
            if self.fallbacks.len() >= batch_max {
                self.flush();
            }
            return;
        }
        if output.is_batchable_authenticated_session() {
            self.flush_plaintext();
            self.flush_endpoint();
            self.flush_direct();
            self.flush_direct_data();
            let DecryptWorkerOutput {
                fallback_tx,
                event,
                direct_delivery,
            } = output;
            debug_assert!(direct_delivery.is_none());
            let DecryptWorkerEvent::AuthenticatedSession(session) = event else {
                unreachable!("checked batchable authenticated session output")
            };
            if self
                .authenticated_session_fallback_tx
                .as_ref()
                .is_some_and(|current| !current.same_channels(&fallback_tx))
            {
                self.flush_authenticated_sessions();
            }
            if self.authenticated_session_fallback_tx.is_none() {
                self.authenticated_session_fallback_tx = Some(fallback_tx);
            }
            let batch_max = Self::batch_max_for(
                self.authenticated_session_fallback_tx
                    .as_ref()
                    .expect("fallback sender set before batching authenticated sessions"),
            );
            self.authenticated_sessions.push(session);
            if self.authenticated_sessions.len() >= batch_max {
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
                fallback_tx,
                event,
                direct_delivery,
            } = output;
            let DecryptWorkerEvent::DirectSessionCommit(commit) = event else {
                unreachable!("checked batchable direct endpoint commit output")
            };
            let Some(direct_delivery) = direct_delivery else {
                unreachable!("checked batchable direct endpoint delivery")
            };
            let Ok((_sink, delivery)) = direct_delivery.into_endpoint_data() else {
                unreachable!("checked batchable endpoint delivery")
            };

            let same_fallback = self
                .endpoint_fallback_tx
                .as_ref()
                .is_none_or(|current| current.same_channels(&fallback_tx));
            if !same_fallback {
                self.flush_endpoint();
            }
            if self.endpoint_fallback_tx.is_none() {
                self.endpoint_fallback_tx = Some(fallback_tx);
            }
            let batch_max = Self::endpoint_batch_max_for(
                self.endpoint_fallback_tx
                    .as_ref()
                    .expect("fallback sender set before batching direct endpoint completions"),
            );
            self.endpoint_commits.push(commit);
            self.endpoint_deliveries.push(delivery);
            if self.endpoint_commits.len() >= batch_max {
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
                fallback_tx,
                event,
                direct_delivery,
            } = output;
            let DecryptWorkerEvent::DirectSessionCommit(commit) = event else {
                unreachable!("checked batchable direct IPv6 commit output")
            };
            let Some(direct_delivery) = direct_delivery else {
                unreachable!("checked batchable direct IPv6 delivery")
            };

            if self
                .direct_fallback_tx
                .as_ref()
                .is_some_and(|current| !current.same_channels(&fallback_tx))
            {
                self.flush_direct();
            }
            if self.direct_fallback_tx.is_none() {
                self.direct_fallback_tx = Some(fallback_tx);
            }
            let batch_max = Self::direct_batch_max_for(
                self.direct_fallback_tx
                    .as_ref()
                    .expect("fallback sender set before batching direct completions"),
            );
            self.direct_commits.push(commit);
            self.direct_deliveries.push(direct_delivery);
            if self.direct_commits.len() >= batch_max {
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
                fallback_tx,
                event,
                direct_delivery,
            } = output;
            debug_assert!(direct_delivery.is_none());
            let DecryptWorkerEvent::DirectSessionData(direct) = event else {
                unreachable!("checked batchable direct data output")
            };
            if self
                .direct_data_fallback_tx
                .as_ref()
                .is_some_and(|current| !current.same_channels(&fallback_tx))
            {
                self.flush_direct_data();
            }
            if self.direct_data_fallback_tx.is_none() {
                self.direct_data_fallback_tx = Some(fallback_tx);
            }
            let batch_max = Self::direct_batch_max_for(
                self.direct_data_fallback_tx
                    .as_ref()
                    .expect("fallback sender set before batching direct data"),
            );
            self.direct_data.push(direct);
            if self.direct_data.len() >= batch_max {
                self.flush_direct_data();
            }
            return;
        }
        self.flush();
        let _ = output.send();
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
        let Some(fallback_tx) = self.fallback_tx.take() else {
            return;
        };
        let event = if self.fallbacks.len() == 1 {
            DecryptWorkerEvent::Plaintext(self.fallbacks.pop().expect("checked single fallback"))
        } else {
            let fallbacks = std::mem::replace(
                &mut self.fallbacks,
                Vec::with_capacity(DECRYPT_WORKER_BULK_BATCH_MAX),
            );
            DecryptWorkerEvent::PlaintextBatch(fallbacks)
        };
        let _ = fallback_tx.send(event);
    }

    fn flush_authenticated_sessions(&mut self) {
        if self.authenticated_sessions.is_empty() {
            return;
        }
        let _t_flush =
            crate::perf_profile::Timer::start(crate::perf_profile::Stage::DecryptWorkerOutputFlush);
        let Some(fallback_tx) = self.authenticated_session_fallback_tx.take() else {
            self.authenticated_sessions.clear();
            return;
        };
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
        let _ = fallback_tx.send(event);
    }

    fn flush_endpoint(&mut self) {
        if self.endpoint_commits.is_empty() {
            return;
        }
        let _t_flush =
            crate::perf_profile::Timer::start(crate::perf_profile::Stage::DecryptWorkerOutputFlush);
        let Some(fallback_tx) = self.endpoint_fallback_tx.take() else {
            return;
        };
        let commits = std::mem::replace(
            &mut self.endpoint_commits,
            Vec::with_capacity(DECRYPT_WORKER_ENDPOINT_DELIVERY_BATCH_MAX),
        );
        let deliveries = std::mem::replace(
            &mut self.endpoint_deliveries,
            Vec::with_capacity(DECRYPT_WORKER_ENDPOINT_DELIVERY_BATCH_MAX),
        );
        let event =
            DecryptWorkerEvent::DirectEndpointBatch(DecryptDirectEndpointBatch::new(
                commits, deliveries,
            ));

        if !fallback_tx.send(event) {
            self.endpoint_deliveries.clear();
        }
    }

    fn flush_direct(&mut self) {
        if self.direct_commits.is_empty() {
            return;
        }
        let _t_flush =
            crate::perf_profile::Timer::start(crate::perf_profile::Stage::DecryptWorkerOutputFlush);
        let Some(fallback_tx) = self.direct_fallback_tx.take() else {
            self.direct_commits.clear();
            self.direct_deliveries.clear();
            return;
        };

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

        if !fallback_tx.send(event) {
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
        let Some(fallback_tx) = self.direct_data_fallback_tx.take() else {
            self.direct_data.clear();
            return;
        };

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

        let _ = fallback_tx.send(event);
    }
}
