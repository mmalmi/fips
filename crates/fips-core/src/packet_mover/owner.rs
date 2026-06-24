use super::PacketLane;
use crate::NodeAddr;
use std::collections::VecDeque;

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(crate) enum OwnerKey {
    Fmp { source_addr: NodeAddr },
    Fsp { source_addr: NodeAddr },
    Peer { node_addr: NodeAddr },
    Unknown,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct OwnerGeneration(pub(crate) u64);

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub(crate) struct OrderSequence(pub(crate) u64);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct OrderToken {
    pub(crate) receive_order_id: u64,
    pub(crate) sequence: OrderSequence,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct OwnerReservation {
    pub(crate) owner: OwnerKey,
    pub(crate) generation: OwnerGeneration,
    pub(crate) order: OrderToken,
    pub(crate) lane: PacketLane,
    pub(crate) packet_count: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum OwnerReserveError {
    WindowFull { owner: OwnerKey, lane: PacketLane },
    StaleGeneration { owner: OwnerKey },
    MissingOwner { owner: OwnerKey },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct OwnerReceiveTicket {
    pub(crate) sequence: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum OwnerCompletionError {
    Stale,
    Duplicate,
    WindowExceeded,
}

#[derive(Debug)]
struct OwnerCompletionBuffer<T> {
    next_ready: u64,
    pending: VecDeque<Option<T>>,
    pending_limit: usize,
}

#[derive(Debug)]
pub(crate) struct OwnerReceiveWindow<T> {
    next_ticket: u64,
    completions: OwnerCompletionBuffer<T>,
}

pub(crate) trait OwnerSequencer<P, W> {
    fn reserve(&mut self, packet: P) -> Result<W, OwnerReserveError>;
}

impl<T> OwnerCompletionBuffer<T> {
    fn new(pending_limit: usize) -> Self {
        Self {
            next_ready: 0,
            pending: VecDeque::new(),
            pending_limit: pending_limit.max(1),
        }
    }

    fn complete(
        &mut self,
        ticket: OwnerReceiveTicket,
        completion: T,
        mut on_ready: impl FnMut(OwnerReceiveTicket, T),
    ) -> Result<usize, OwnerCompletionError> {
        if ticket.sequence < self.next_ready {
            return Err(OwnerCompletionError::Stale);
        }

        let offset = (ticket.sequence - self.next_ready) as usize;
        if offset == 0 {
            on_ready(
                OwnerReceiveTicket {
                    sequence: self.next_ready,
                },
                completion,
            );
            self.next_ready = self.next_ready.saturating_add(1);
            if !self.pending.is_empty() {
                let _ = self.pending.pop_front();
            }

            let mut ready = 1;
            while matches!(self.pending.front(), Some(Some(_))) {
                let completion = self
                    .pending
                    .pop_front()
                    .and_then(|completion| completion)
                    .expect("checked ready pending completion");
                on_ready(
                    OwnerReceiveTicket {
                        sequence: self.next_ready,
                    },
                    completion,
                );
                self.next_ready = self.next_ready.saturating_add(1);
                ready += 1;
            }
            return Ok(ready);
        }

        if offset >= self.pending_limit {
            return Err(OwnerCompletionError::WindowExceeded);
        }

        if self.pending.len() <= offset {
            self.pending.resize_with(offset + 1, || None);
        }
        if self.pending[offset].is_some() {
            return Err(OwnerCompletionError::Duplicate);
        }
        self.pending[offset] = Some(completion);
        Ok(0)
    }

    fn next_ready(&self) -> u64 {
        self.next_ready
    }

    fn pending_limit(&self) -> usize {
        self.pending_limit
    }
}

impl<T> OwnerReceiveWindow<T> {
    pub(crate) fn new(pending_limit: usize) -> Self {
        Self {
            next_ticket: 0,
            completions: OwnerCompletionBuffer::new(pending_limit),
        }
    }

    pub(crate) fn issue(&mut self) -> Option<OwnerReceiveTicket> {
        self.issue_with_reserve(0)
    }

    pub(crate) fn issue_with_reserve(&mut self, reserve: usize) -> Option<OwnerReceiveTicket> {
        self.issue_batch_with_reserve(1, reserve)
            .map(|sequence| OwnerReceiveTicket { sequence })
    }

    pub(crate) fn issue_batch_with_reserve(&mut self, count: usize, reserve: usize) -> Option<u64> {
        if count == 0 {
            return Some(self.next_ticket);
        }
        let limit = self.completions.pending_limit().saturating_sub(reserve);
        if limit == 0 {
            return None;
        }
        let count = count as u64;
        let in_flight = self
            .next_ticket
            .saturating_sub(self.completions.next_ready());
        if in_flight.saturating_add(count) > limit as u64 {
            return None;
        }
        let first = self.next_ticket;
        self.next_ticket = self.next_ticket.saturating_add(count);
        Some(first)
    }

    pub(crate) fn next_ticket(&self) -> u64 {
        self.next_ticket
    }

    pub(crate) fn next_ready(&self) -> u64 {
        self.completions.next_ready()
    }

    pub(crate) fn advance_next_ticket_to(&mut self, next_ticket: u64) {
        self.next_ticket = self.next_ticket.max(next_ticket);
    }

    pub(crate) fn complete(
        &mut self,
        ticket: OwnerReceiveTicket,
        completion: T,
        on_ready: impl FnMut(OwnerReceiveTicket, T),
    ) -> Result<usize, OwnerCompletionError> {
        self.completions.complete(ticket, completion, on_ready)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct OwnerWindow {
    owner: OwnerKey,
    generation: OwnerGeneration,
    receive_order_id: u64,
    next_sequence: u64,
    in_flight: usize,
    in_flight_limit: usize,
}

impl OwnerWindow {
    pub(crate) fn new(
        owner: OwnerKey,
        generation: OwnerGeneration,
        receive_order_id: u64,
        in_flight_limit: usize,
    ) -> Self {
        Self {
            owner,
            generation,
            receive_order_id,
            next_sequence: 0,
            in_flight: 0,
            in_flight_limit: in_flight_limit.max(1),
        }
    }

    pub(crate) fn reserve(
        &mut self,
        lane: PacketLane,
        packet_count: usize,
    ) -> Result<OwnerReservation, OwnerReserveError> {
        let packet_count = packet_count.max(1);
        if self.in_flight.saturating_add(packet_count) > self.in_flight_limit {
            return Err(OwnerReserveError::WindowFull {
                owner: self.owner,
                lane,
            });
        }
        let sequence = self.next_sequence;
        self.next_sequence = self.next_sequence.saturating_add(packet_count as u64);
        self.in_flight += packet_count;
        Ok(OwnerReservation {
            owner: self.owner,
            generation: self.generation,
            order: OrderToken {
                receive_order_id: self.receive_order_id,
                sequence: OrderSequence(sequence),
            },
            lane,
            packet_count,
        })
    }

    pub(crate) fn release(&mut self, reservation: OwnerReservation) {
        debug_assert_eq!(reservation.owner, self.owner);
        debug_assert_eq!(reservation.generation, self.generation);
        self.in_flight = self.in_flight.saturating_sub(reservation.packet_count);
    }

    pub(crate) fn in_flight(&self) -> usize {
        self.in_flight
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn owner() -> OwnerKey {
        OwnerKey::Fsp {
            source_addr: NodeAddr::from_bytes([7; 16]),
        }
    }

    #[test]
    fn owner_window_reserves_order_before_dispatch() {
        let mut window = OwnerWindow::new(owner(), OwnerGeneration(3), 44, 4);
        let first = window.reserve(PacketLane::Bulk, 1).expect("first");
        let second = window.reserve(PacketLane::Bulk, 2).expect("second");

        assert_eq!(first.order.sequence, OrderSequence(0));
        assert_eq!(second.order.sequence, OrderSequence(1));
        assert_eq!(second.packet_count, 2);
        assert_eq!(window.in_flight(), 3);
    }

    #[test]
    fn owner_window_refuses_unbounded_in_flight_growth() {
        let mut window = OwnerWindow::new(owner(), OwnerGeneration(3), 44, 1);
        let reservation = window.reserve(PacketLane::Bulk, 1).expect("first");
        assert!(matches!(
            window.reserve(PacketLane::Bulk, 1),
            Err(OwnerReserveError::WindowFull { .. })
        ));

        window.release(reservation);
        assert!(window.reserve(PacketLane::Bulk, 1).is_ok());
    }

    #[test]
    fn owner_receive_window_buffers_until_oldest_completion_is_ready() {
        let mut window = OwnerReceiveWindow::new(4);
        let first = window.issue().expect("first ticket");
        let second = window.issue().expect("second ticket");
        let third = window.issue().expect("third ticket");

        let mut ready = Vec::new();
        assert_eq!(
            window
                .complete(second, "second", |ticket, completion| ready
                    .push((ticket.sequence, completion)))
                .expect("second completion should buffer"),
            0
        );
        assert_eq!(
            window
                .complete(third, "third", |ticket, completion| ready
                    .push((ticket.sequence, completion)))
                .expect("third completion should buffer"),
            0
        );
        assert!(ready.is_empty());

        assert_eq!(
            window
                .complete(first, "first", |ticket, completion| ready
                    .push((ticket.sequence, completion)))
                .expect("first completion should drain all ready completions"),
            3
        );
        assert_eq!(ready, vec![(0, "first"), (1, "second"), (2, "third")]);
        assert_eq!(window.next_ready(), 3);
    }

    #[test]
    fn owner_receive_window_bounds_in_flight_tickets_with_reserve() {
        let mut window = OwnerReceiveWindow::<&'static str>::new(4);
        assert_eq!(
            window
                .issue_batch_with_reserve(2, 2)
                .expect("bulk should fit before reserve"),
            0
        );
        assert!(window.issue_with_reserve(2).is_none());
        assert_eq!(window.issue().expect("reserved ticket").sequence, 2);
        assert_eq!(window.issue().expect("reserved ticket").sequence, 3);
        assert!(window.issue().is_none());
    }
}
