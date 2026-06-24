use super::{
    AdmissionClass, BoundedLaneQueues, CryptoCompletion, CryptoTicket, CryptoWork,
    OrderedRetireBuffer, OrderedRetireError, OutputDrop, OutputTarget, OwnerGeneration, OwnerKey,
    OwnerReserveError, OwnerWindow, PacketOutput, QueueAdmission, QueueCaps, QueuedPacket,
    RetiredPacket, UdpIngress, VecOutputSink,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct CanonicalOwnerPacketMoverConfig {
    pub(crate) owner: OwnerKey,
    pub(crate) generation: OwnerGeneration,
    pub(crate) receive_order_id: u64,
    pub(crate) queue_caps: QueueCaps,
    pub(crate) in_flight_limit: usize,
    pub(crate) retire_pending_limit: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum PacketMoverDispatch<I> {
    Work(CryptoWork<UdpIngress<I>>),
    Dropped {
        packet: UdpIngress<I>,
        lane: super::PacketLane,
        packet_count: usize,
        byte_count: usize,
        error: OwnerReserveError,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum PacketMoverRetireError {
    Ordered(OrderedRetireError),
    Output(OutputDrop),
}

impl From<OrderedRetireError> for PacketMoverRetireError {
    fn from(error: OrderedRetireError) -> Self {
        Self::Ordered(error)
    }
}

impl From<OutputDrop> for PacketMoverRetireError {
    fn from(error: OutputDrop) -> Self {
        Self::Output(error)
    }
}

#[derive(Debug)]
pub(crate) struct CanonicalOwnerPacketMover<I, O> {
    queues: BoundedLaneQueues<UdpIngress<I>>,
    owner: OwnerWindow,
    retire: OrderedRetireBuffer<O>,
    output: VecOutputSink<O>,
}

impl<I, O> CanonicalOwnerPacketMover<I, O> {
    pub(crate) fn new(config: CanonicalOwnerPacketMoverConfig) -> Self {
        Self {
            queues: BoundedLaneQueues::new(config.queue_caps),
            owner: OwnerWindow::new(
                config.owner,
                config.generation,
                config.receive_order_id,
                config.in_flight_limit,
            ),
            retire: OrderedRetireBuffer::new(
                config.owner,
                config.generation,
                config.receive_order_id,
                config.retire_pending_limit,
            ),
            output: VecOutputSink::default(),
        }
    }

    pub(crate) fn admit_udp(
        &mut self,
        packet: UdpIngress<I>,
        class: AdmissionClass,
    ) -> QueueAdmission<UdpIngress<I>> {
        let lane = class.lane();
        let byte_count = packet.facts.packet_len;
        self.queues.push(packet, lane, 1, byte_count)
    }

    pub(crate) fn dispatch_next(&mut self) -> Option<PacketMoverDispatch<I>> {
        let packet = self.queues.pop()?;
        Some(match self.owner.reserve(packet.lane, packet.packet_count) {
            Ok(reservation) => PacketMoverDispatch::Work(CryptoWork {
                ticket: CryptoTicket { reservation },
                work: packet.item,
            }),
            Err(error) => dropped_dispatch(packet, error),
        })
    }

    pub(crate) fn retire_completion(
        &mut self,
        completion: CryptoCompletion<O>,
        target: OutputTarget,
    ) -> Result<usize, PacketMoverRetireError> {
        let ready = self.retire.complete_crypto(completion, target)?;
        let ready_count = ready.len();
        for packet in ready {
            self.owner.release(packet.reservation);
            self.output.push_output(packet)?;
        }
        Ok(ready_count)
    }

    pub(crate) fn drain_outputs(&mut self) -> Vec<RetiredPacket<O>> {
        self.output.take_outputs()
    }

    pub(crate) fn queued_packets(&self, lane: super::PacketLane) -> usize {
        self.queues.queued_packets(lane)
    }

    pub(crate) fn in_flight(&self) -> usize {
        self.owner.in_flight()
    }
}

fn dropped_dispatch<I>(
    packet: QueuedPacket<UdpIngress<I>>,
    error: OwnerReserveError,
) -> PacketMoverDispatch<I> {
    PacketMoverDispatch::Dropped {
        packet: packet.item,
        lane: packet.lane,
        packet_count: packet.packet_count,
        byte_count: packet.byte_count,
        error,
    }
}

#[cfg(test)]
fn completion_from_opened<I>(
    reservation: super::OwnerReservation,
    packet: I,
) -> CryptoCompletion<I> {
    CryptoCompletion {
        ticket: CryptoTicket { reservation },
        result: super::CryptoResult::Opened(packet),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::NodeAddr;
    use crate::packet_mover::{
        AdmissionDropReason, PacketFacts, PacketLane, QueueAdmission, RetireOutput,
    };
    use crate::transport::{TransportAddr, TransportId};

    fn owner() -> OwnerKey {
        OwnerKey::Fsp {
            source_addr: NodeAddr::from_bytes([9; 16]),
        }
    }

    fn config() -> CanonicalOwnerPacketMoverConfig {
        CanonicalOwnerPacketMoverConfig {
            owner: owner(),
            generation: OwnerGeneration(7),
            receive_order_id: 99,
            queue_caps: QueueCaps::new(4, 4),
            in_flight_limit: 4,
            retire_pending_limit: 4,
        }
    }

    fn ingress(packet: &'static str, len: usize) -> UdpIngress<&'static str> {
        UdpIngress::new(
            packet,
            PacketFacts {
                transport_id: TransportId::new(1),
                remote_addr: TransportAddr::from_string("udp 127.0.0.1:9"),
                packet_len: len,
                received_at_ms: 42,
            },
        )
    }

    fn dispatch_work(
        mover: &mut CanonicalOwnerPacketMover<&'static str, &'static str>,
    ) -> CryptoWork<UdpIngress<&'static str>> {
        match mover.dispatch_next().expect("dispatch") {
            PacketMoverDispatch::Work(work) => work,
            PacketMoverDispatch::Dropped { error, .. } => {
                panic!("unexpected owner drop: {error:?}")
            }
        }
    }

    #[test]
    fn canonical_pipeline_drains_priority_before_bulk() {
        let mut mover = CanonicalOwnerPacketMover::new(config());

        assert_eq!(
            mover.admit_udp(ingress("bulk", 1500), AdmissionClass::BulkData),
            QueueAdmission::Enqueued
        );
        assert_eq!(
            mover.admit_udp(ingress("priority", 64), AdmissionClass::Mmp),
            QueueAdmission::Enqueued
        );

        let first = dispatch_work(&mut mover);
        let second = dispatch_work(&mut mover);

        assert_eq!(first.work.packet, "priority");
        assert_eq!(second.work.packet, "bulk");
        assert_eq!(first.ticket.reservation.order.sequence.0, 0);
        assert_eq!(second.ticket.reservation.order.sequence.0, 1);
    }

    #[test]
    fn canonical_pipeline_keeps_later_completion_until_owner_order_is_ready() {
        let mut mover = CanonicalOwnerPacketMover::new(config());
        assert_eq!(
            mover.admit_udp(ingress("first", 1200), AdmissionClass::BulkData),
            QueueAdmission::Enqueued
        );
        assert_eq!(
            mover.admit_udp(ingress("second", 1200), AdmissionClass::BulkData),
            QueueAdmission::Enqueued
        );
        let first = dispatch_work(&mut mover);
        let second = dispatch_work(&mut mover);

        assert_eq!(
            mover
                .retire_completion(
                    completion_from_opened(second.ticket.reservation, "second-opened"),
                    OutputTarget::Tun,
                )
                .expect("second completion"),
            0
        );
        assert!(mover.drain_outputs().is_empty());
        assert_eq!(mover.in_flight(), 2);

        assert_eq!(
            mover
                .retire_completion(
                    completion_from_opened(first.ticket.reservation, "first-opened"),
                    OutputTarget::Tun,
                )
                .expect("first completion"),
            2
        );

        let outputs = mover.drain_outputs();
        assert_eq!(outputs.len(), 2);
        assert!(matches!(
            outputs[0].output,
            RetireOutput::Payload {
                target: OutputTarget::Tun,
                packet: "first-opened"
            }
        ));
        assert!(matches!(
            outputs[1].output,
            RetireOutput::Payload {
                target: OutputTarget::Tun,
                packet: "second-opened"
            }
        ));
        assert_eq!(mover.in_flight(), 0);
    }

    #[test]
    fn canonical_pipeline_reports_bulk_admission_pressure_without_side_path() {
        let mut config = config();
        config.queue_caps = QueueCaps::new(4, 1);
        let mut mover = CanonicalOwnerPacketMover::<&'static str, &'static str>::new(config);

        assert_eq!(
            mover.admit_udp(ingress("first", 1200), AdmissionClass::BulkData),
            QueueAdmission::Enqueued
        );
        let QueueAdmission::Dropped { item, drop } =
            mover.admit_udp(ingress("second", 1200), AdmissionClass::BulkData)
        else {
            panic!("second bulk packet must drop under pressure");
        };

        assert_eq!(item.packet, "second");
        assert_eq!(drop.reason, AdmissionDropReason::BulkPressure);
        assert_eq!(drop.lane, PacketLane::Bulk);
        assert_eq!(mover.queued_packets(PacketLane::Bulk), 1);
    }

    #[test]
    fn canonical_pipeline_reports_owner_pressure_without_side_path() {
        let mut config = config();
        config.in_flight_limit = 1;
        let mut mover = CanonicalOwnerPacketMover::<&'static str, &'static str>::new(config);
        assert_eq!(
            mover.admit_udp(ingress("first", 1200), AdmissionClass::BulkData),
            QueueAdmission::Enqueued
        );
        assert_eq!(
            mover.admit_udp(ingress("second", 1200), AdmissionClass::BulkData),
            QueueAdmission::Enqueued
        );

        let first = dispatch_work(&mut mover);
        let Some(PacketMoverDispatch::Dropped {
            packet,
            error,
            lane,
            ..
        }) = mover.dispatch_next()
        else {
            panic!("owner pressure must return an explicit dropped dispatch");
        };

        assert_eq!(packet.packet, "second");
        assert_eq!(lane, PacketLane::Bulk);
        assert!(matches!(
            error,
            OwnerReserveError::WindowFull {
                owner,
                lane: PacketLane::Bulk
            } if owner == self::owner()
        ));
        assert_eq!(mover.in_flight(), 1);

        assert_eq!(
            mover
                .retire_completion(
                    completion_from_opened(first.ticket.reservation, "first-opened"),
                    OutputTarget::Tun,
                )
                .expect("first completion"),
            1
        );
        assert_eq!(mover.in_flight(), 0);
    }
}
