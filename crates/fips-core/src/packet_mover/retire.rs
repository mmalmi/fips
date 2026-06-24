use super::{
    CryptoCompletion, CryptoReject, CryptoResult, OrderSequence, OutputDrop, OutputDropReason,
    OutputTarget, OwnerGeneration, OwnerKey, RetireOutput, RetiredPacket,
};
use std::collections::BTreeMap;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum OrderedRetireError {
    WrongOwner {
        expected: OwnerKey,
        actual: OwnerKey,
    },
    WrongGeneration {
        owner: OwnerKey,
        expected: OwnerGeneration,
        actual: OwnerGeneration,
    },
    WrongOrder {
        owner: OwnerKey,
        expected: u64,
        actual: u64,
    },
    WindowFull {
        owner: OwnerKey,
    },
}

#[derive(Debug)]
pub(crate) struct OrderedRetireBuffer<P> {
    owner: OwnerKey,
    generation: OwnerGeneration,
    receive_order_id: u64,
    next_ready: u64,
    pending_limit: usize,
    pending: BTreeMap<u64, RetiredPacket<P>>,
}

impl<P> OrderedRetireBuffer<P> {
    pub(crate) fn new(
        owner: OwnerKey,
        generation: OwnerGeneration,
        receive_order_id: u64,
        pending_limit: usize,
    ) -> Self {
        Self {
            owner,
            generation,
            receive_order_id,
            next_ready: 0,
            pending_limit: pending_limit.max(1),
            pending: BTreeMap::new(),
        }
    }

    pub(crate) fn complete_crypto(
        &mut self,
        completion: CryptoCompletion<P>,
        target: OutputTarget,
    ) -> Result<Vec<RetiredPacket<P>>, OrderedRetireError> {
        let reservation = completion.ticket.reservation;
        if reservation.owner != self.owner {
            return Err(OrderedRetireError::WrongOwner {
                expected: self.owner,
                actual: reservation.owner,
            });
        }
        if reservation.generation != self.generation {
            return Err(OrderedRetireError::WrongGeneration {
                owner: self.owner,
                expected: self.generation,
                actual: reservation.generation,
            });
        }
        if reservation.order.receive_order_id != self.receive_order_id {
            return Err(OrderedRetireError::WrongOrder {
                owner: self.owner,
                expected: self.receive_order_id,
                actual: reservation.order.receive_order_id,
            });
        }
        if self.pending.len() >= self.pending_limit {
            return Err(OrderedRetireError::WindowFull { owner: self.owner });
        }

        let sequence = reservation.order.sequence.0;
        let output = match completion.result {
            CryptoResult::Opened(packet) => RetireOutput::Payload { target, packet },
            CryptoResult::Rejected(reject) | CryptoResult::RejectedWith { reject, .. } => {
                RetireOutput::Drop(OutputDrop {
                    reason: output_drop_reason_for_reject(reject),
                    packet_count: reservation.packet_count,
                    byte_count: 0,
                })
            }
            CryptoResult::Dropped => RetireOutput::Drop(OutputDrop {
                reason: OutputDropReason::RetirePressure,
                packet_count: reservation.packet_count,
                byte_count: 0,
            }),
        };
        self.pending.insert(
            sequence,
            RetiredPacket {
                reservation,
                output,
            },
        );

        let mut ready = Vec::new();
        while let Some(packet) = self.pending.remove(&self.next_ready) {
            self.next_ready = self
                .next_ready
                .saturating_add(packet.reservation.packet_count as u64);
            ready.push(packet);
        }
        Ok(ready)
    }

    pub(crate) fn next_ready(&self) -> OrderSequence {
        OrderSequence(self.next_ready)
    }
}

fn output_drop_reason_for_reject(reject: CryptoReject) -> OutputDropReason {
    match reject {
        CryptoReject::Replay => OutputDropReason::Replay,
        CryptoReject::Aead => OutputDropReason::Aead,
        CryptoReject::Malformed => OutputDropReason::Malformed,
        CryptoReject::StaleGeneration => OutputDropReason::StaleGeneration,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::NodeAddr;
    use crate::packet_mover::{
        CryptoResult, CryptoTicket, OwnerReservation, PacketLane, StatelessCryptoWorker,
    };
    use crate::packet_mover::{NoopCryptoWorker, OrderToken};

    fn reservation(sequence: u64) -> OwnerReservation {
        OwnerReservation {
            owner: OwnerKey::Fsp {
                source_addr: NodeAddr::from_bytes([3; 16]),
            },
            generation: OwnerGeneration(1),
            order: OrderToken {
                receive_order_id: 10,
                sequence: OrderSequence(sequence),
            },
            lane: PacketLane::Bulk,
            packet_count: 1,
        }
    }

    #[test]
    fn ordered_retire_holds_later_completion_until_gap_arrives() {
        let mut retire = OrderedRetireBuffer::new(reservation(0).owner, OwnerGeneration(1), 10, 8);
        let mut worker = NoopCryptoWorker;
        let second = worker.execute(crate::packet_mover::CryptoWork {
            ticket: CryptoTicket {
                reservation: reservation(1),
            },
            work: "second",
        });
        let first = worker.execute(crate::packet_mover::CryptoWork {
            ticket: CryptoTicket {
                reservation: reservation(0),
            },
            work: "first",
        });

        assert!(
            retire
                .complete_crypto(second, OutputTarget::Tun)
                .expect("second")
                .is_empty()
        );
        let ready = retire
            .complete_crypto(first, OutputTarget::Tun)
            .expect("first");
        assert_eq!(ready.len(), 2);
        assert!(matches!(
            ready[0].output,
            RetireOutput::Payload {
                target: OutputTarget::Tun,
                packet: "first"
            }
        ));
        assert!(matches!(
            ready[1].output,
            RetireOutput::Payload {
                target: OutputTarget::Tun,
                packet: "second"
            }
        ));
        assert_eq!(retire.next_ready(), OrderSequence(2));
    }

    #[test]
    fn ordered_retire_turns_crypto_rejects_into_ordered_drops() {
        let mut retire = OrderedRetireBuffer::<&'static str>::new(
            reservation(0).owner,
            OwnerGeneration(1),
            10,
            8,
        );
        let ready = retire
            .complete_crypto(
                CryptoCompletion {
                    ticket: CryptoTicket {
                        reservation: reservation(0),
                    },
                    result: CryptoResult::Rejected(CryptoReject::Replay),
                },
                OutputTarget::Tun,
            )
            .expect("reject");

        assert_eq!(ready.len(), 1);
        assert!(matches!(
            ready[0].output,
            RetireOutput::Drop(OutputDrop {
                reason: OutputDropReason::Replay,
                packet_count: 1,
                byte_count: 0
            })
        ));
    }
}
