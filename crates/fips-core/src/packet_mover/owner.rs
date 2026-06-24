use super::PacketLane;
use crate::NodeAddr;

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

pub(crate) trait OwnerSequencer<P, W> {
    fn reserve(&mut self, packet: P) -> Result<W, OwnerReserveError>;
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
}
