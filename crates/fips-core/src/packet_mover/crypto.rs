use super::{OwnerKey, OwnerReservation};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct CryptoTicket {
    pub(crate) reservation: OwnerReservation,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct CryptoWork<W> {
    pub(crate) ticket: CryptoTicket,
    pub(crate) work: W,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct CryptoCompletion<W> {
    pub(crate) ticket: CryptoTicket,
    pub(crate) result: CryptoResult<W>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum CryptoResult<W> {
    Opened(W),
    Rejected(CryptoReject),
    Dropped,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CryptoReject {
    Replay,
    Aead,
    Malformed,
    StaleGeneration,
}

pub(crate) trait StatelessCryptoWorker<W> {
    fn execute(&mut self, work: CryptoWork<W>) -> CryptoCompletion<W>;
}

pub(crate) trait OwnerOrderedCompletion {
    fn owner_reservation(&self) -> OwnerReservation;
}

#[allow(clippy::large_enum_variant)]
pub(crate) enum OwnerCompletionBatch<C> {
    One(C),
    Many(Vec<C>),
}

impl<C> OwnerCompletionBatch<C> {
    pub(crate) fn one(completion: C) -> Self {
        Self::One(completion)
    }

    pub(crate) fn len(&self) -> usize {
        match self {
            Self::One(_) => 1,
            Self::Many(completions) => completions.len(),
        }
    }
}

impl<C: OwnerOrderedCompletion> OwnerCompletionBatch<C> {
    pub(crate) fn owner_order(&self) -> (OwnerKey, u64) {
        let reservation = match self {
            Self::One(completion) => completion.owner_reservation(),
            Self::Many(completions) => completions
                .first()
                .expect("owner completion batch must not be empty")
                .owner_reservation(),
        };
        (reservation.owner, reservation.order.receive_order_id)
    }

    pub(crate) fn can_push(&self, owner: OwnerKey, receive_order_id: u64, max_len: usize) -> bool {
        self.len() < max_len && self.owner_order() == (owner, receive_order_id)
    }

    pub(crate) fn push(&mut self, completion: C) {
        self.push_with_capacity(completion, DEFAULT_OWNER_COMPLETION_BATCH_CAPACITY);
    }

    pub(crate) fn push_with_capacity(&mut self, completion: C, capacity: usize) {
        let (owner, receive_order_id) = self.owner_order();
        let reservation = completion.owner_reservation();
        debug_assert_eq!(reservation.owner, owner);
        debug_assert_eq!(reservation.order.receive_order_id, receive_order_id);
        match self {
            Self::One(_) => {
                let Self::One(existing) =
                    std::mem::replace(self, Self::Many(Vec::with_capacity(capacity.max(2))))
                else {
                    unreachable!("replaced One with Many")
                };
                let Self::Many(completions) = self else {
                    unreachable!("batch was replaced with Many")
                };
                completions.push(existing);
                completions.push(completion);
            }
            Self::Many(completions) => completions.push(completion),
        }
    }
}

const DEFAULT_OWNER_COMPLETION_BATCH_CAPACITY: usize = 16;

#[derive(Default)]
pub(crate) struct NoopCryptoWorker;

impl<W> StatelessCryptoWorker<W> for NoopCryptoWorker {
    fn execute(&mut self, work: CryptoWork<W>) -> CryptoCompletion<W> {
        CryptoCompletion {
            ticket: work.ticket,
            result: CryptoResult::Opened(work.work),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::NodeAddr;
    use crate::packet_mover::{
        OrderSequence, OrderToken, OwnerGeneration, OwnerKey, OwnerReservation, PacketLane,
    };

    #[test]
    fn no_op_worker_returns_ticket_unchanged() {
        let reservation = OwnerReservation {
            owner: OwnerKey::Fmp {
                source_addr: NodeAddr::from_bytes([1; 16]),
            },
            generation: OwnerGeneration(9),
            order: OrderToken {
                receive_order_id: 4,
                sequence: OrderSequence(7),
            },
            lane: PacketLane::Bulk,
            packet_count: 1,
        };
        let mut worker = NoopCryptoWorker;
        let completion = worker.execute(CryptoWork {
            ticket: CryptoTicket { reservation },
            work: "payload",
        });

        assert_eq!(completion.ticket.reservation, reservation);
        assert_eq!(completion.result, CryptoResult::Opened("payload"));
    }

    #[derive(Clone, Debug, Eq, PartialEq)]
    struct TestCompletion {
        reservation: OwnerReservation,
        value: u8,
    }

    impl OwnerOrderedCompletion for TestCompletion {
        fn owner_reservation(&self) -> OwnerReservation {
            self.reservation
        }
    }

    fn completion(source: u8, receive_order_id: u64, sequence: u64) -> TestCompletion {
        TestCompletion {
            reservation: OwnerReservation {
                owner: OwnerKey::Fsp {
                    source_addr: NodeAddr::from_bytes([source; 16]),
                },
                generation: OwnerGeneration(1),
                order: OrderToken {
                    receive_order_id,
                    sequence: OrderSequence(sequence),
                },
                lane: PacketLane::Bulk,
                packet_count: 1,
            },
            value: source,
        }
    }

    #[test]
    fn owner_completion_batch_groups_same_owner_order() {
        let mut batch = OwnerCompletionBatch::one(completion(1, 7, 0));
        assert!(batch.can_push(
            OwnerKey::Fsp {
                source_addr: NodeAddr::from_bytes([1; 16])
            },
            7,
            2
        ));

        batch.push(completion(1, 7, 1));
        assert_eq!(batch.len(), 2);
        assert!(!batch.can_push(
            OwnerKey::Fsp {
                source_addr: NodeAddr::from_bytes([1; 16])
            },
            7,
            2
        ));
    }

    #[test]
    fn owner_completion_batch_rejects_different_owner_or_order() {
        let batch = OwnerCompletionBatch::one(completion(1, 7, 0));
        assert!(!batch.can_push(
            OwnerKey::Fsp {
                source_addr: NodeAddr::from_bytes([2; 16])
            },
            7,
            2
        ));
        assert!(!batch.can_push(
            OwnerKey::Fsp {
                source_addr: NodeAddr::from_bytes([1; 16])
            },
            8,
            2
        ));
    }
}
