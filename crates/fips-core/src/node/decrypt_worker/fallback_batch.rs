struct DecryptPlaintextFallbackBatch {
    fallback_tx: Option<DecryptWorkerFallbackSender>,
    fallbacks: Vec<DecryptFallback>,
    endpoint_fallback_tx: Option<DecryptWorkerFallbackSender>,
    endpoint_sink: Option<DecryptDirectSessionDeliverySink>,
    endpoint_commits: Vec<DecryptDirectSessionCommit>,
    endpoint_deliveries: Vec<EndpointDataDelivery>,
    direct_fmp_fallback_tx: Option<DecryptWorkerFallbackSender>,
    direct_fmp_endpoints: Vec<DecryptDirectFmpEndpointData>,
    direct_fallback_tx: Option<DecryptWorkerFallbackSender>,
    direct_commits: Vec<DecryptDirectSessionCommit>,
    direct_deliveries: Vec<PendingDirectSessionDelivery>,
}

impl DecryptPlaintextFallbackBatch {
    fn new() -> Self {
        Self {
            fallback_tx: None,
            fallbacks: Vec::with_capacity(DECRYPT_WORKER_BULK_BATCH_MAX),
            endpoint_fallback_tx: None,
            endpoint_sink: None,
            endpoint_commits: Vec::with_capacity(DECRYPT_WORKER_ENDPOINT_DELIVERY_BATCH_MAX),
            endpoint_deliveries: Vec::with_capacity(DECRYPT_WORKER_ENDPOINT_DELIVERY_BATCH_MAX),
            direct_fmp_fallback_tx: None,
            direct_fmp_endpoints: Vec::with_capacity(DECRYPT_WORKER_DIRECT_DELIVERY_BATCH_MAX),
            direct_fallback_tx: None,
            direct_commits: Vec::with_capacity(DECRYPT_WORKER_DIRECT_DELIVERY_BATCH_MAX),
            direct_deliveries: Vec::with_capacity(DECRYPT_WORKER_DIRECT_DELIVERY_BATCH_MAX),
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
            self.flush_endpoint();
            self.flush_direct_fmp();
            self.flush_direct();
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
        if output.is_batchable_direct_endpoint() {
            self.flush_plaintext();
            self.flush_direct_fmp();
            self.flush_direct();
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
            let Ok((sink, delivery)) = direct_delivery.into_endpoint_data() else {
                unreachable!("checked batchable endpoint delivery")
            };

            let same_fallback = self
                .endpoint_fallback_tx
                .as_ref()
                .is_none_or(|current| current.same_channels(&fallback_tx));
            let same_endpoint = self
                .endpoint_sink
                .as_ref()
                .is_none_or(|current| current.same_endpoint_event_channel(&sink));
            if !same_fallback || !same_endpoint {
                self.flush_endpoint();
            }
            if self.endpoint_fallback_tx.is_none() {
                self.endpoint_fallback_tx = Some(fallback_tx);
            }
            if self.endpoint_sink.is_none() {
                self.endpoint_sink = Some(sink);
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
        if output.is_batchable_direct_fmp_endpoint_data() {
            self.flush_plaintext();
            self.flush_endpoint();
            self.flush_direct();
            let DecryptWorkerOutput {
                fallback_tx,
                event,
                direct_delivery,
            } = output;
            debug_assert!(direct_delivery.is_none());
            let DecryptWorkerEvent::DirectFmpEndpointData(endpoint) = event else {
                unreachable!("checked batchable direct-FMP endpoint data output")
            };

            if self
                .direct_fmp_fallback_tx
                .as_ref()
                .is_some_and(|current| !current.same_channels(&fallback_tx))
            {
                self.flush_direct_fmp();
            }
            if self.direct_fmp_fallback_tx.is_none() {
                self.direct_fmp_fallback_tx = Some(fallback_tx);
            }
            let batch_max = Self::direct_batch_max_for(
                self.direct_fmp_fallback_tx
                    .as_ref()
                    .expect("fallback sender set before batching direct-FMP endpoint data"),
            );
            self.direct_fmp_endpoints.push(endpoint);
            if self.direct_fmp_endpoints.len() >= batch_max {
                self.flush_direct_fmp();
            }
            return;
        }
        if output.is_batchable_direct_ipv6() {
            self.flush_plaintext();
            self.flush_endpoint();
            self.flush_direct_fmp();
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
        self.flush();
        let _ = output.send();
    }

    fn push_fsp_job_fallback(&mut self, job: FspDecryptJob) {
        self.push_output(DecryptWorkerOutput {
            fallback_tx: job.fallback_tx,
            event: DecryptWorkerEvent::Plaintext(job.fallback),
            direct_delivery: None,
        });
    }

    fn flush(&mut self) {
        self.flush_plaintext();
        self.flush_endpoint();
        self.flush_direct_fmp();
        self.flush_direct();
    }

    fn flush_plaintext(&mut self) {
        if self.fallbacks.is_empty() {
            return;
        }
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

    fn flush_endpoint(&mut self) {
        if self.endpoint_commits.is_empty() {
            return;
        }
        let Some(fallback_tx) = self.endpoint_fallback_tx.take() else {
            return;
        };
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

        if !fallback_tx.send(event) {
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

    fn flush_direct_fmp(&mut self) {
        if self.direct_fmp_endpoints.is_empty() {
            return;
        }
        let Some(fallback_tx) = self.direct_fmp_fallback_tx.take() else {
            self.direct_fmp_endpoints.clear();
            return;
        };

        let event = if self.direct_fmp_endpoints.len() == 1 {
            DecryptWorkerEvent::DirectFmpEndpointData(
                self.direct_fmp_endpoints
                    .pop()
                    .expect("checked single direct-FMP endpoint data"),
            )
        } else {
            let endpoints = std::mem::replace(
                &mut self.direct_fmp_endpoints,
                Vec::with_capacity(DECRYPT_WORKER_DIRECT_DELIVERY_BATCH_MAX),
            );
            DecryptWorkerEvent::DirectFmpEndpointDataBatch(endpoints)
        };
        let _ = fallback_tx.send(event);
    }

    fn flush_direct(&mut self) {
        if self.direct_commits.is_empty() {
            return;
        }
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
}
