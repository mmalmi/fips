use super::OwnerReservation;

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
}
