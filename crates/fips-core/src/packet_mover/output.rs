use super::OwnerReservation;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum OutputTarget {
    Tun,
    Endpoint,
    Transport,
}

pub(crate) trait PacketOutputTarget {
    fn output_target(&self) -> Option<OutputTarget>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum OutputDropReason {
    AdmissionPressure,
    Replay,
    Aead,
    Malformed,
    StaleGeneration,
    RetirePressure,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct OutputDrop {
    pub(crate) reason: OutputDropReason,
    pub(crate) packet_count: usize,
    pub(crate) byte_count: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum RetireOutput<P> {
    Payload { target: OutputTarget, packet: P },
    Control,
    Drop(OutputDrop),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct RetiredPacket<P> {
    pub(crate) reservation: OwnerReservation,
    pub(crate) output: RetireOutput<P>,
}

pub(crate) trait PacketOutput<P> {
    fn push_output(&mut self, packet: RetiredPacket<P>) -> Result<(), OutputDrop>;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum CommitBeforeOutputItems<T> {
    One(T),
    Many(Vec<T>),
}

impl<T> CommitBeforeOutputItems<T> {
    pub(crate) fn len(&self) -> usize {
        match self {
            Self::One(_) => 1,
            Self::Many(items) => items.len(),
        }
    }
}

pub(crate) trait OwnerRetireBatchTypes {
    type AuthenticatedLink;
    type AuthenticatedSession;
    type DirectCommit;
    type EndpointSink;
    type EndpointDelivery;
    type DirectDelivery;
    type DirectData;
}

pub(crate) trait OwnerRetireBatchSink<T: OwnerRetireBatchTypes> {
    fn send_authenticated_links(
        &self,
        links: CommitBeforeOutputItems<T::AuthenticatedLink>,
    ) -> bool;

    fn send_authenticated_sessions(
        &self,
        sessions: CommitBeforeOutputItems<T::AuthenticatedSession>,
    ) -> bool;

    fn send_direct_commits(&self, commits: CommitBeforeOutputItems<T::DirectCommit>) -> bool;

    fn send_direct_data(&self, direct_data: CommitBeforeOutputItems<T::DirectData>) -> bool;

    fn same_endpoint_sink(&self, current: &T::EndpointSink, next: &T::EndpointSink) -> bool;

    fn endpoint_sink_ready(&self, _sink: &T::EndpointSink) -> bool {
        true
    }

    fn deliver_endpoint(
        &self,
        sink: &T::EndpointSink,
        deliveries: CommitBeforeOutputItems<T::EndpointDelivery>,
    );

    fn deliver_direct(&self, deliveries: CommitBeforeOutputItems<T::DirectDelivery>);
}

#[derive(Clone, Debug)]
pub(crate) struct OwnerRetireOutputBatch<T: OwnerRetireBatchTypes> {
    authenticated_links: Vec<T::AuthenticatedLink>,
    authenticated_sessions: Vec<T::AuthenticatedSession>,
    endpoint_sink: Option<T::EndpointSink>,
    endpoint_outputs: CommitBeforeOutputBatch<T::DirectCommit, T::EndpointDelivery>,
    direct_outputs: CommitBeforeOutputBatch<T::DirectCommit, T::DirectDelivery>,
    direct_data: Vec<T::DirectData>,
    authenticated_batch_capacity: usize,
    endpoint_batch_capacity: usize,
    direct_batch_capacity: usize,
}

pub(crate) enum OwnerRetireOutput<T: OwnerRetireBatchTypes, I> {
    AuthenticatedLink(T::AuthenticatedLink),
    AuthenticatedSession(T::AuthenticatedSession),
    DirectEndpoint {
        endpoint_sink: T::EndpointSink,
        commit: T::DirectCommit,
        delivery: T::EndpointDelivery,
    },
    Direct {
        commit: T::DirectCommit,
        delivery: T::DirectDelivery,
    },
    DirectData(T::DirectData),
    Immediate(I),
}

impl<T: OwnerRetireBatchTypes> OwnerRetireOutputBatch<T> {
    pub(crate) fn new(
        authenticated_batch_capacity: usize,
        endpoint_batch_capacity: usize,
        direct_batch_capacity: usize,
    ) -> Self {
        let authenticated_batch_capacity = authenticated_batch_capacity.max(1);
        let endpoint_batch_capacity = endpoint_batch_capacity.max(1);
        let direct_batch_capacity = direct_batch_capacity.max(1);
        Self {
            authenticated_links: Vec::with_capacity(authenticated_batch_capacity),
            authenticated_sessions: Vec::with_capacity(authenticated_batch_capacity),
            endpoint_sink: None,
            endpoint_outputs: CommitBeforeOutputBatch::new(endpoint_batch_capacity),
            direct_outputs: CommitBeforeOutputBatch::new(direct_batch_capacity),
            direct_data: Vec::with_capacity(direct_batch_capacity),
            authenticated_batch_capacity,
            endpoint_batch_capacity,
            direct_batch_capacity,
        }
    }

    pub(crate) fn push_authenticated_link<S>(&mut self, link: T::AuthenticatedLink, sink: &S)
    where
        S: OwnerRetireBatchSink<T>,
    {
        self.flush_authenticated_sessions(sink);
        self.flush_endpoint(sink);
        self.flush_direct(sink);
        self.flush_direct_data(sink);
        self.authenticated_links.push(link);
        if self.authenticated_links.len() >= self.authenticated_batch_capacity {
            self.flush_authenticated_links(sink);
        }
    }

    pub(crate) fn push_authenticated_session<S>(
        &mut self,
        session: T::AuthenticatedSession,
        sink: &S,
    ) where
        S: OwnerRetireBatchSink<T>,
    {
        self.flush_authenticated_links(sink);
        self.flush_endpoint(sink);
        self.flush_direct(sink);
        self.flush_direct_data(sink);
        self.authenticated_sessions.push(session);
        if self.authenticated_sessions.len() >= self.authenticated_batch_capacity {
            self.flush_authenticated_sessions(sink);
        }
    }

    pub(crate) fn push_direct_endpoint<S>(
        &mut self,
        endpoint_sink: T::EndpointSink,
        commit: T::DirectCommit,
        delivery: T::EndpointDelivery,
        sink: &S,
    ) where
        S: OwnerRetireBatchSink<T>,
    {
        self.flush_authenticated_links(sink);
        self.flush_authenticated_sessions(sink);
        self.flush_direct(sink);
        self.flush_direct_data(sink);

        if self
            .endpoint_sink
            .as_ref()
            .is_some_and(|current| !sink.same_endpoint_sink(current, &endpoint_sink))
        {
            self.flush_endpoint(sink);
        }

        if self.endpoint_sink.is_none() {
            self.endpoint_sink = Some(endpoint_sink);
        }

        self.endpoint_outputs.push(commit, delivery);
        if self.endpoint_outputs.len() >= self.endpoint_batch_capacity {
            self.flush_endpoint(sink);
        }
    }

    pub(crate) fn push_direct<S>(
        &mut self,
        commit: T::DirectCommit,
        delivery: T::DirectDelivery,
        sink: &S,
    ) where
        S: OwnerRetireBatchSink<T>,
    {
        self.flush_authenticated_links(sink);
        self.flush_authenticated_sessions(sink);
        self.flush_endpoint(sink);
        self.flush_direct_data(sink);
        self.direct_outputs.push(commit, delivery);
        if self.direct_outputs.len() >= self.direct_batch_capacity {
            self.flush_direct(sink);
        }
    }

    pub(crate) fn push_direct_data<S>(&mut self, direct: T::DirectData, sink: &S)
    where
        S: OwnerRetireBatchSink<T>,
    {
        self.flush_authenticated_links(sink);
        self.flush_authenticated_sessions(sink);
        self.flush_endpoint(sink);
        self.flush_direct(sink);
        self.direct_data.push(direct);
        if self.direct_data.len() >= self.direct_batch_capacity {
            self.flush_direct_data(sink);
        }
    }

    pub(crate) fn push_output<S, I>(
        &mut self,
        output: OwnerRetireOutput<T, I>,
        sink: &S,
        mut push_immediate: impl FnMut(I, &S),
    ) where
        S: OwnerRetireBatchSink<T>,
    {
        match output {
            OwnerRetireOutput::AuthenticatedLink(link) => {
                self.push_authenticated_link(link, sink);
            }
            OwnerRetireOutput::AuthenticatedSession(session) => {
                self.push_authenticated_session(session, sink);
            }
            OwnerRetireOutput::DirectEndpoint {
                endpoint_sink,
                commit,
                delivery,
            } => {
                self.push_direct_endpoint(endpoint_sink, commit, delivery, sink);
            }
            OwnerRetireOutput::Direct { commit, delivery } => {
                self.push_direct(commit, delivery, sink);
            }
            OwnerRetireOutput::DirectData(direct) => {
                self.push_direct_data(direct, sink);
            }
            OwnerRetireOutput::Immediate(output) => {
                self.flush(sink);
                push_immediate(output, sink);
            }
        }
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.authenticated_links.is_empty()
            && self.authenticated_sessions.is_empty()
            && self.endpoint_outputs.is_empty()
            && self.direct_outputs.is_empty()
            && self.direct_data.is_empty()
    }

    pub(crate) fn flush<S>(&mut self, sink: &S)
    where
        S: OwnerRetireBatchSink<T>,
    {
        self.flush_authenticated_links(sink);
        self.flush_authenticated_sessions(sink);
        self.flush_endpoint(sink);
        self.flush_direct(sink);
        self.flush_direct_data(sink);
    }

    fn flush_authenticated_links<S>(&mut self, sink: &S)
    where
        S: OwnerRetireBatchSink<T>,
    {
        if self.authenticated_links.is_empty() {
            return;
        }
        let _t_flush =
            crate::perf_profile::Timer::start(crate::perf_profile::Stage::DecryptWorkerOutputFlush);
        let links = take_items(
            &mut self.authenticated_links,
            self.authenticated_batch_capacity,
        );
        let _ = sink.send_authenticated_links(links);
    }

    fn flush_authenticated_sessions<S>(&mut self, sink: &S)
    where
        S: OwnerRetireBatchSink<T>,
    {
        if self.authenticated_sessions.is_empty() {
            return;
        }
        let _t_flush =
            crate::perf_profile::Timer::start(crate::perf_profile::Stage::DecryptWorkerOutputFlush);
        let sessions = take_items(
            &mut self.authenticated_sessions,
            self.authenticated_batch_capacity,
        );
        let _ = sink.send_authenticated_sessions(sessions);
    }

    fn flush_endpoint<S>(&mut self, sink: &S)
    where
        S: OwnerRetireBatchSink<T>,
    {
        if self.endpoint_outputs.is_empty() {
            return;
        }
        let _t_flush =
            crate::perf_profile::Timer::start(crate::perf_profile::Stage::DecryptWorkerOutputFlush);
        let Some(endpoint_sink) = self.endpoint_sink.take() else {
            self.endpoint_outputs.clear();
            return;
        };
        if !sink.endpoint_sink_ready(&endpoint_sink) {
            self.endpoint_outputs.clear();
            return;
        }
        let _ = self.endpoint_outputs.flush_commit_then_output(
            |commits| sink.send_direct_commits(commits),
            |deliveries| sink.deliver_endpoint(&endpoint_sink, deliveries),
        );
    }

    fn flush_direct<S>(&mut self, sink: &S)
    where
        S: OwnerRetireBatchSink<T>,
    {
        if self.direct_outputs.is_empty() {
            return;
        }
        let _t_flush =
            crate::perf_profile::Timer::start(crate::perf_profile::Stage::DecryptWorkerOutputFlush);
        let _ = self.direct_outputs.flush_commit_then_output(
            |commits| sink.send_direct_commits(commits),
            |deliveries| sink.deliver_direct(deliveries),
        );
    }

    fn flush_direct_data<S>(&mut self, sink: &S)
    where
        S: OwnerRetireBatchSink<T>,
    {
        if self.direct_data.is_empty() {
            return;
        }
        let _t_flush =
            crate::perf_profile::Timer::start(crate::perf_profile::Stage::DecryptWorkerOutputFlush);
        let direct_data = take_items(&mut self.direct_data, self.direct_batch_capacity);
        let _ = sink.send_direct_data(direct_data);
    }
}

#[derive(Clone, Debug)]
pub(crate) struct CommitBeforeOutputBatch<C, O> {
    commits: Vec<C>,
    outputs: Vec<O>,
    capacity: usize,
}

impl<C, O> CommitBeforeOutputBatch<C, O> {
    pub(crate) fn new(capacity: usize) -> Self {
        let capacity = capacity.max(1);
        Self {
            commits: Vec::with_capacity(capacity),
            outputs: Vec::with_capacity(capacity),
            capacity,
        }
    }

    pub(crate) fn push(&mut self, commit: C, output: O) {
        debug_assert_eq!(self.commits.len(), self.outputs.len());
        self.commits.push(commit);
        self.outputs.push(output);
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.commits.is_empty()
    }

    pub(crate) fn len(&self) -> usize {
        self.commits.len()
    }

    pub(crate) fn clear(&mut self) {
        self.commits.clear();
        self.outputs.clear();
    }

    pub(crate) fn flush_commit_then_output<Commit, Output>(
        &mut self,
        mut commit: Commit,
        mut output: Output,
    ) -> bool
    where
        Commit: FnMut(CommitBeforeOutputItems<C>) -> bool,
        Output: FnMut(CommitBeforeOutputItems<O>),
    {
        let Some((commits, outputs)) = self.take() else {
            return true;
        };
        debug_assert_eq!(commits.len(), outputs.len());
        if !commit(commits) {
            return false;
        }
        output(outputs);
        true
    }

    fn take(&mut self) -> Option<(CommitBeforeOutputItems<C>, CommitBeforeOutputItems<O>)> {
        debug_assert_eq!(self.commits.len(), self.outputs.len());
        if self.commits.is_empty() {
            return None;
        }
        Some((
            take_items(&mut self.commits, self.capacity),
            take_items(&mut self.outputs, self.capacity),
        ))
    }
}

fn take_items<T>(items: &mut Vec<T>, capacity: usize) -> CommitBeforeOutputItems<T> {
    if items.len() == 1 {
        CommitBeforeOutputItems::One(items.pop().expect("checked single item"))
    } else {
        CommitBeforeOutputItems::Many(std::mem::replace(
            items,
            Vec::with_capacity(capacity.max(1)),
        ))
    }
}

#[derive(Debug)]
pub(crate) struct VecOutputSink<P> {
    outputs: Vec<RetiredPacket<P>>,
}

impl<P> Default for VecOutputSink<P> {
    fn default() -> Self {
        Self {
            outputs: Vec::new(),
        }
    }
}

impl<P> VecOutputSink<P> {
    pub(crate) fn into_outputs(self) -> Vec<RetiredPacket<P>> {
        self.outputs
    }

    pub(crate) fn take_outputs(&mut self) -> Vec<RetiredPacket<P>> {
        std::mem::take(&mut self.outputs)
    }
}

impl<P> PacketOutput<P> for VecOutputSink<P> {
    fn push_output(&mut self, packet: RetiredPacket<P>) -> Result<(), OutputDrop> {
        self.outputs.push(packet);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn commit_before_output_delivers_only_after_commit_accepts() {
        let mut batch = CommitBeforeOutputBatch::new(4);
        batch.push("commit-1", "packet-1");
        batch.push("commit-2", "packet-2");

        let mut committed = Vec::new();
        let mut delivered = Vec::new();
        assert!(batch.flush_commit_then_output(
            |commits| {
                committed = match commits {
                    CommitBeforeOutputItems::One(commit) => vec![commit],
                    CommitBeforeOutputItems::Many(commits) => commits,
                };
                true
            },
            |outputs| {
                delivered = match outputs {
                    CommitBeforeOutputItems::One(output) => vec![output],
                    CommitBeforeOutputItems::Many(outputs) => outputs,
                };
            },
        ));

        assert_eq!(committed, vec!["commit-1", "commit-2"]);
        assert_eq!(delivered, vec!["packet-1", "packet-2"]);
        assert!(batch.is_empty());
    }

    #[test]
    fn commit_before_output_drops_payloads_when_commit_rejects() {
        let mut batch = CommitBeforeOutputBatch::new(2);
        batch.push("commit", "packet");

        let mut delivered = false;
        assert!(!batch.flush_commit_then_output(|_| false, |_| delivered = true,));

        assert!(!delivered);
        assert!(batch.is_empty());
    }

    struct TestBatchTypes;

    impl OwnerRetireBatchTypes for TestBatchTypes {
        type AuthenticatedLink = &'static str;
        type AuthenticatedSession = &'static str;
        type DirectCommit = &'static str;
        type EndpointSink = u8;
        type EndpointDelivery = &'static str;
        type DirectDelivery = &'static str;
        type DirectData = &'static str;
    }

    struct TestBatchSink {
        events: std::cell::RefCell<Vec<String>>,
        endpoint_ready: bool,
    }

    impl Default for TestBatchSink {
        fn default() -> Self {
            Self {
                events: std::cell::RefCell::new(Vec::new()),
                endpoint_ready: true,
            }
        }
    }

    impl OwnerRetireBatchSink<TestBatchTypes> for TestBatchSink {
        fn send_authenticated_links(&self, links: CommitBeforeOutputItems<&'static str>) -> bool {
            self.events
                .borrow_mut()
                .push(format!("links:{:?}", items_to_vec(links)));
            true
        }

        fn send_authenticated_sessions(
            &self,
            sessions: CommitBeforeOutputItems<&'static str>,
        ) -> bool {
            self.events
                .borrow_mut()
                .push(format!("sessions:{:?}", items_to_vec(sessions)));
            true
        }

        fn send_direct_commits(&self, commits: CommitBeforeOutputItems<&'static str>) -> bool {
            self.events
                .borrow_mut()
                .push(format!("commits:{:?}", items_to_vec(commits)));
            true
        }

        fn send_direct_data(&self, direct_data: CommitBeforeOutputItems<&'static str>) -> bool {
            self.events
                .borrow_mut()
                .push(format!("direct_data:{:?}", items_to_vec(direct_data)));
            true
        }

        fn same_endpoint_sink(&self, current: &u8, next: &u8) -> bool {
            current == next
        }

        fn endpoint_sink_ready(&self, _sink: &u8) -> bool {
            self.endpoint_ready
        }

        fn deliver_endpoint(&self, sink: &u8, deliveries: CommitBeforeOutputItems<&'static str>) {
            self.events
                .borrow_mut()
                .push(format!("endpoint-{sink}:{:?}", items_to_vec(deliveries)));
        }

        fn deliver_direct(&self, deliveries: CommitBeforeOutputItems<&'static str>) {
            self.events
                .borrow_mut()
                .push(format!("direct:{:?}", items_to_vec(deliveries)));
        }
    }

    fn items_to_vec<T>(items: CommitBeforeOutputItems<T>) -> Vec<T> {
        match items {
            CommitBeforeOutputItems::One(item) => vec![item],
            CommitBeforeOutputItems::Many(items) => items,
        }
    }

    #[test]
    fn owner_retire_output_batch_flushes_previous_class_before_next() {
        let sink = TestBatchSink::default();
        let mut batch = OwnerRetireOutputBatch::<TestBatchTypes>::new(4, 4, 4);

        batch.push_authenticated_link("link-1", &sink);
        batch.push_authenticated_session("session-1", &sink);
        batch.flush(&sink);

        assert_eq!(
            sink.events.into_inner(),
            vec![
                "links:[\"link-1\"]".to_string(),
                "sessions:[\"session-1\"]".to_string(),
            ]
        );
    }

    #[test]
    fn owner_retire_output_batch_push_output_flushes_before_immediate() {
        let sink = TestBatchSink::default();
        let mut batch = OwnerRetireOutputBatch::<TestBatchTypes>::new(4, 4, 4);

        batch.push_output(
            OwnerRetireOutput::AuthenticatedLink("link-1"),
            &sink,
            |immediate: &'static str, sink| {
                sink.events
                    .borrow_mut()
                    .push(format!("immediate:{immediate}"));
            },
        );
        batch.push_output(
            OwnerRetireOutput::Immediate("fallback"),
            &sink,
            |immediate: &'static str, sink| {
                sink.events
                    .borrow_mut()
                    .push(format!("immediate:{immediate}"));
            },
        );

        assert_eq!(
            sink.events.into_inner(),
            vec![
                "links:[\"link-1\"]".to_string(),
                "immediate:fallback".to_string(),
            ]
        );
    }

    #[test]
    fn owner_retire_output_batch_commits_before_endpoint_delivery() {
        let sink = TestBatchSink::default();
        let mut batch = OwnerRetireOutputBatch::<TestBatchTypes>::new(4, 2, 4);

        batch.push_direct_endpoint(7, "commit-1", "endpoint-1", &sink);
        batch.push_direct_endpoint(7, "commit-2", "endpoint-2", &sink);

        assert_eq!(
            sink.events.into_inner(),
            vec![
                "commits:[\"commit-1\", \"commit-2\"]".to_string(),
                "endpoint-7:[\"endpoint-1\", \"endpoint-2\"]".to_string(),
            ]
        );
    }

    #[test]
    fn owner_retire_output_batch_splits_endpoint_sinks() {
        let sink = TestBatchSink::default();
        let mut batch = OwnerRetireOutputBatch::<TestBatchTypes>::new(4, 4, 4);

        batch.push_direct_endpoint(1, "commit-1", "endpoint-1", &sink);
        batch.push_direct_endpoint(2, "commit-2", "endpoint-2", &sink);
        batch.flush(&sink);

        assert_eq!(
            sink.events.into_inner(),
            vec![
                "commits:[\"commit-1\"]".to_string(),
                "endpoint-1:[\"endpoint-1\"]".to_string(),
                "commits:[\"commit-2\"]".to_string(),
                "endpoint-2:[\"endpoint-2\"]".to_string(),
            ]
        );
    }

    #[test]
    fn owner_retire_output_batch_skips_commit_when_endpoint_sink_is_not_ready() {
        let sink = TestBatchSink {
            endpoint_ready: false,
            ..TestBatchSink::default()
        };
        let mut batch = OwnerRetireOutputBatch::<TestBatchTypes>::new(4, 4, 4);

        batch.push_direct_endpoint(7, "commit-1", "endpoint-1", &sink);
        batch.flush(&sink);

        assert!(sink.events.into_inner().is_empty());
    }
}
