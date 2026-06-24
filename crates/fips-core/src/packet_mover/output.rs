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
}
