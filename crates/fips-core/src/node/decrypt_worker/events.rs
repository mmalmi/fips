/// Event emitted by the decrypt worker to the rx_loop.
pub(crate) enum DecryptWorkerEvent {
    Plaintext(DecryptFallback),
    PlaintextBatch(Vec<DecryptFallback>),
    AuthenticatedFmpReceive(DecryptAuthenticatedFmpReceive),
    DirectFmpEndpointData(DecryptDirectFmpEndpointData),
    DirectFmpEndpointDataBatch(Vec<DecryptDirectFmpEndpointData>),
    AuthenticatedSession(DecryptAuthenticatedSession),
    DirectSessionCommit(DecryptDirectSessionCommit),
    DirectSessionCommitBatch(Vec<DecryptDirectSessionCommit>),
    DirectSessionData(DecryptDirectSessionData),
    FspDecryptFailure(DecryptFspFailureReport),
    DecryptFailure(DecryptFailureReport),
}

impl DecryptWorkerEvent {
    fn lane(&self) -> DecryptWorkerLane {
        decrypt_worker_event_lane(self)
    }

    pub(crate) fn packet_count(&self) -> usize {
        match self {
            Self::Plaintext(_) | Self::DecryptFailure(_) => 1,
            Self::AuthenticatedFmpReceive(_) => 1,
            Self::DirectFmpEndpointData(_) => 1,
            Self::DirectFmpEndpointDataBatch(endpoints) => endpoints.len(),
            Self::AuthenticatedSession(_) => 1,
            Self::DirectSessionCommit(_) => 1,
            Self::DirectSessionCommitBatch(commits) => commits.len(),
            Self::DirectSessionData(_) => 1,
            Self::FspDecryptFailure(_) => 1,
            Self::PlaintextBatch(fallbacks) => fallbacks.len(),
        }
    }

    fn set_trace_enqueued_at(&mut self, queued_at: Option<crate::perf_profile::TraceStamp>) {
        match self {
            Self::Plaintext(fallback) => fallback.trace_enqueued_at = queued_at,
            Self::PlaintextBatch(fallbacks) => {
                for fallback in fallbacks {
                    fallback.trace_enqueued_at = queued_at;
                }
            }
            Self::AuthenticatedFmpReceive(receive) => receive.trace_enqueued_at = queued_at,
            Self::DirectFmpEndpointData(endpoint) => endpoint.trace_enqueued_at = queued_at,
            Self::DirectFmpEndpointDataBatch(endpoints) => {
                for endpoint in endpoints {
                    endpoint.trace_enqueued_at = queued_at;
                }
            }
            Self::AuthenticatedSession(session) => session.trace_enqueued_at = queued_at,
            Self::DirectSessionCommit(commit) => commit.trace_enqueued_at = queued_at,
            Self::DirectSessionCommitBatch(commits) => {
                for commit in commits {
                    commit.trace_enqueued_at = queued_at;
                }
            }
            Self::DirectSessionData(direct) => direct.trace_enqueued_at = queued_at,
            Self::FspDecryptFailure(report) => report.trace_enqueued_at = queued_at,
            Self::DecryptFailure(report) => report.trace_enqueued_at = queued_at,
        }
    }

    fn trace_enqueued_at(&self) -> Option<crate::perf_profile::TraceStamp> {
        match self {
            Self::Plaintext(fallback) => fallback.trace_enqueued_at,
            Self::PlaintextBatch(fallbacks) => fallbacks
                .first()
                .and_then(|fallback| fallback.trace_enqueued_at),
            Self::AuthenticatedFmpReceive(receive) => receive.trace_enqueued_at,
            Self::DirectFmpEndpointData(endpoint) => endpoint.trace_enqueued_at,
            Self::DirectFmpEndpointDataBatch(endpoints) => {
                endpoints.first().and_then(|endpoint| endpoint.trace_enqueued_at)
            }
            Self::AuthenticatedSession(session) => session.trace_enqueued_at,
            Self::DirectSessionCommit(commit) => commit.trace_enqueued_at,
            Self::DirectSessionCommitBatch(commits) => {
                commits.first().and_then(|commit| commit.trace_enqueued_at)
            }
            Self::DirectSessionData(direct) => direct.trace_enqueued_at,
            Self::FspDecryptFailure(report) => report.trace_enqueued_at,
            Self::DecryptFailure(report) => report.trace_enqueued_at,
        }
    }

    fn queue_wait_stages(
        &self,
    ) -> (
        crate::perf_profile::Stage,
        crate::perf_profile::Stage,
        crate::perf_profile::Stage,
    ) {
        match self {
            Self::AuthenticatedFmpReceive(_)
            | Self::DirectFmpEndpointData(_)
            | Self::DirectFmpEndpointDataBatch(_)
            | Self::AuthenticatedSession(_)
            | Self::DirectSessionCommit(_)
            | Self::DirectSessionCommitBatch(_)
            | Self::DirectSessionData(_) => (
                crate::perf_profile::Stage::DecryptAuthenticatedSessionWait,
                crate::perf_profile::Stage::DecryptAuthenticatedSessionPriorityWait,
                crate::perf_profile::Stage::DecryptAuthenticatedSessionBulkWait,
            ),
            Self::Plaintext(_)
            | Self::PlaintextBatch(_)
            | Self::FspDecryptFailure(_)
            | Self::DecryptFailure(_) => (
                crate::perf_profile::Stage::DecryptFallbackWait,
                crate::perf_profile::Stage::DecryptFallbackPriorityWait,
                crate::perf_profile::Stage::DecryptFallbackBulkWait,
            ),
        }
    }

    fn authenticated_return_kind_stage(&self) -> Option<crate::perf_profile::Stage> {
        match self {
            Self::AuthenticatedFmpReceive(_) => {
                Some(crate::perf_profile::Stage::DecryptAuthenticatedFmpReceiveWait)
            }
            Self::DirectFmpEndpointData(_) | Self::DirectFmpEndpointDataBatch(_) => {
                Some(crate::perf_profile::Stage::DecryptDirectFmpEndpointWait)
            }
            Self::AuthenticatedSession(_) => Some(
                crate::perf_profile::Stage::DecryptAuthenticatedSessionMessageWait,
            ),
            Self::DirectSessionCommit(_) | Self::DirectSessionCommitBatch(_) => {
                Some(crate::perf_profile::Stage::DecryptDirectSessionCommitWait)
            }
            Self::DirectSessionData(_) => {
                Some(crate::perf_profile::Stage::DecryptDirectSessionDataWait)
            }
            Self::Plaintext(_)
            | Self::PlaintextBatch(_)
            | Self::FspDecryptFailure(_)
            | Self::DecryptFailure(_) => None,
        }
    }

    pub(crate) fn record_queue_wait(&self) {
        let queued_at = self.trace_enqueued_at();
        if queued_at.is_none() {
            return;
        }
        let count = self.packet_count() as u64;
        let (priority_count, bulk_count) = match self.lane() {
            DecryptWorkerLane::Priority => (count, 0),
            DecryptWorkerLane::Bulk => (0, count),
        };
        let (total_stage, priority_stage, bulk_stage) = self.queue_wait_stages();
        crate::perf_profile::record_since_split_count(
            total_stage,
            priority_stage,
            bulk_stage,
            queued_at,
            count,
            priority_count,
            bulk_count,
        );
        if let Some(kind_stage) = self.authenticated_return_kind_stage() {
            crate::perf_profile::record_since_count(kind_stage, queued_at, count);
        }
    }
}
