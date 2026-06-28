use crate::node::{endpoint_payload_is_latency_sensitive, endpoint_payload_is_liveness_probe};
use tokio::sync::mpsc;

const TUN_OUTBOUND_PRIORITY_BURST_MAX: usize = 8;

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
enum TunOutboundLane {
    Priority,
    Bulk,
}

#[derive(Debug, Clone)]
pub struct TunOutboundTx {
    priority: mpsc::Sender<Vec<u8>>,
    bulk: mpsc::Sender<Vec<u8>>,
}

#[derive(Debug)]
pub struct TunOutboundRx {
    priority: mpsc::Receiver<Vec<u8>>,
    bulk: mpsc::Receiver<Vec<u8>>,
    priority_closed: bool,
    bulk_closed: bool,
    priority_burst: usize,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub(crate) enum TunOutboundAdmission {
    Enqueued,
    BulkDropped,
}

pub(crate) fn tun_outbound_channel(capacity: usize) -> (TunOutboundTx, TunOutboundRx) {
    let capacity = capacity.max(1);
    let (priority_tx, priority_rx) = mpsc::channel(capacity);
    let (bulk_tx, bulk_rx) = mpsc::channel(capacity);
    (
        TunOutboundTx {
            priority: priority_tx,
            bulk: bulk_tx,
        },
        TunOutboundRx {
            priority: priority_rx,
            bulk: bulk_rx,
            priority_closed: false,
            bulk_closed: false,
            priority_burst: 0,
        },
    )
}

impl TunOutboundTx {
    pub async fn send(&self, packet: Vec<u8>) -> Result<(), mpsc::error::SendError<Vec<u8>>> {
        match tun_outbound_lane(&packet) {
            TunOutboundLane::Priority => self.priority.send(packet).await,
            TunOutboundLane::Bulk => self.bulk.send(packet).await,
        }
    }

    pub fn blocking_send(&self, packet: Vec<u8>) -> Result<(), mpsc::error::SendError<Vec<u8>>> {
        match tun_outbound_lane(&packet) {
            TunOutboundLane::Priority => self.priority.blocking_send(packet),
            TunOutboundLane::Bulk => self.bulk.blocking_send(packet),
        }
    }

    pub fn try_send(&self, packet: Vec<u8>) -> Result<(), mpsc::error::TrySendError<Vec<u8>>> {
        match tun_outbound_lane(&packet) {
            TunOutboundLane::Priority => self.priority.try_send(packet),
            TunOutboundLane::Bulk => self.bulk.try_send(packet),
        }
    }

    pub(crate) fn admit_from_tun_reader(
        &self,
        packet: Vec<u8>,
    ) -> Result<TunOutboundAdmission, mpsc::error::SendError<Vec<u8>>> {
        match tun_outbound_lane(&packet) {
            TunOutboundLane::Priority => self
                .priority
                .blocking_send(packet)
                .map(|()| TunOutboundAdmission::Enqueued),
            TunOutboundLane::Bulk => match self.bulk.try_send(packet) {
                Ok(()) => Ok(TunOutboundAdmission::Enqueued),
                Err(mpsc::error::TrySendError::Full(packet)) => {
                    crate::perf_profile::record_event(
                        crate::perf_profile::Event::PendingTunPacketDropped,
                    );
                    tracing::debug!(
                        len = packet.len(),
                        "Dropping bulk TUN outbound packet because admission queue is full"
                    );
                    Ok(TunOutboundAdmission::BulkDropped)
                }
                Err(mpsc::error::TrySendError::Closed(packet)) => {
                    Err(mpsc::error::SendError(packet))
                }
            },
        }
    }
}

impl TunOutboundRx {
    pub(crate) async fn recv(&mut self) -> Option<Vec<u8>> {
        loop {
            match self.try_recv() {
                Ok(packet) => return Some(packet),
                Err(mpsc::error::TryRecvError::Disconnected) => return None,
                Err(mpsc::error::TryRecvError::Empty) => {}
            }

            if self.priority_burst >= TUN_OUTBOUND_PRIORITY_BURST_MAX {
                tokio::select! {
                    biased;

                    packet = self.bulk.recv(), if !self.bulk_closed => {
                        if let Some(packet) = self.note_bulk(packet) {
                            return Some(packet);
                        }
                    }
                    packet = self.priority.recv(), if !self.priority_closed => {
                        if let Some(packet) = self.note_priority(packet) {
                            return Some(packet);
                        }
                    }
                };
            } else {
                tokio::select! {
                    biased;

                    packet = self.priority.recv(), if !self.priority_closed => {
                        if let Some(packet) = self.note_priority(packet) {
                            return Some(packet);
                        }
                    }
                    packet = self.bulk.recv(), if !self.bulk_closed => {
                        if let Some(packet) = self.note_bulk(packet) {
                            return Some(packet);
                        }
                    }
                };
            }
        }
    }

    pub(crate) fn try_recv(&mut self) -> Result<Vec<u8>, mpsc::error::TryRecvError> {
        if self.priority_burst >= TUN_OUTBOUND_PRIORITY_BURST_MAX {
            if let Some(packet) = self.try_recv_bulk()? {
                return Ok(packet);
            }
            if let Some(packet) = self.try_recv_priority()? {
                return Ok(packet);
            }
        } else {
            if let Some(packet) = self.try_recv_priority()? {
                return Ok(packet);
            }
            if let Some(packet) = self.try_recv_bulk()? {
                return Ok(packet);
            }
        }

        if self.priority_closed && self.bulk_closed {
            Err(mpsc::error::TryRecvError::Disconnected)
        } else {
            Err(mpsc::error::TryRecvError::Empty)
        }
    }

    fn try_recv_priority(&mut self) -> Result<Option<Vec<u8>>, mpsc::error::TryRecvError> {
        if self.priority_closed {
            return Ok(None);
        }
        match self.priority.try_recv() {
            Ok(packet) => Ok(self.note_priority(Some(packet))),
            Err(mpsc::error::TryRecvError::Empty) => Ok(None),
            Err(mpsc::error::TryRecvError::Disconnected) => {
                self.priority_closed = true;
                Ok(None)
            }
        }
    }

    fn try_recv_bulk(&mut self) -> Result<Option<Vec<u8>>, mpsc::error::TryRecvError> {
        if self.bulk_closed {
            return Ok(None);
        }
        match self.bulk.try_recv() {
            Ok(packet) => Ok(self.note_bulk(Some(packet))),
            Err(mpsc::error::TryRecvError::Empty) => Ok(None),
            Err(mpsc::error::TryRecvError::Disconnected) => {
                self.bulk_closed = true;
                Ok(None)
            }
        }
    }

    fn note_priority(&mut self, packet: Option<Vec<u8>>) -> Option<Vec<u8>> {
        match packet {
            Some(packet) => {
                self.priority_burst = self
                    .priority_burst
                    .saturating_add(1)
                    .min(TUN_OUTBOUND_PRIORITY_BURST_MAX);
                Some(packet)
            }
            None => {
                self.priority_closed = true;
                None
            }
        }
    }

    fn note_bulk(&mut self, packet: Option<Vec<u8>>) -> Option<Vec<u8>> {
        match packet {
            Some(packet) => {
                self.priority_burst = 0;
                Some(packet)
            }
            None => {
                self.bulk_closed = true;
                None
            }
        }
    }
}

fn tun_outbound_lane(packet: &[u8]) -> TunOutboundLane {
    if endpoint_payload_is_liveness_probe(packet) || endpoint_payload_is_latency_sensitive(packet) {
        TunOutboundLane::Priority
    } else {
        TunOutboundLane::Bulk
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ipv4_packet(proto: u8, body_len: usize) -> Vec<u8> {
        let total_len = 20 + body_len;
        let mut packet = vec![0u8; total_len];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
        packet[9] = proto;
        packet
    }

    fn ipv4_tcp_bulk_packet() -> Vec<u8> {
        let mut packet = ipv4_packet(6, 20 + 300);
        let tcp_offset = 20;
        packet[tcp_offset + 12] = 5 << 4;
        packet[tcp_offset + 13] = 0x10;
        packet
    }

    fn ipv4_icmp_packet() -> Vec<u8> {
        ipv4_packet(1, 8)
    }

    fn packet_variant(mut packet: Vec<u8>, value: u8) -> Vec<u8> {
        if let Some(last) = packet.last_mut() {
            *last = value;
        }
        packet
    }

    #[tokio::test]
    async fn tun_outbound_recv_prefers_priority_over_queued_bulk() {
        let (tx, mut rx) = tun_outbound_channel(4);
        let bulk = ipv4_tcp_bulk_packet();
        let priority = ipv4_icmp_packet();

        tx.try_send(bulk.clone())
            .expect("bulk packet should enqueue");
        tx.try_send(priority.clone())
            .expect("priority packet should enqueue");

        assert_eq!(rx.recv().await, Some(priority));
        assert_eq!(rx.recv().await, Some(bulk));
    }

    #[test]
    fn tun_outbound_bulk_pressure_does_not_block_priority() {
        let (tx, mut rx) = tun_outbound_channel(1);
        let first_bulk = ipv4_tcp_bulk_packet();
        let second_bulk = ipv4_tcp_bulk_packet();
        let priority = ipv4_icmp_packet();

        tx.try_send(first_bulk.clone())
            .expect("first bulk packet should fit");
        assert!(
            tx.try_send(second_bulk).is_err(),
            "bulk lane should report its own pressure"
        );
        tx.try_send(priority.clone())
            .expect("priority packet should use reserved lane capacity");

        assert_eq!(rx.try_recv(), Ok(priority));
        assert_eq!(rx.try_recv(), Ok(first_bulk));
    }

    #[test]
    fn tun_reader_admission_sheds_bulk_but_keeps_priority_capacity() {
        let (tx, mut rx) = tun_outbound_channel(1);
        let first_bulk = ipv4_tcp_bulk_packet();
        let second_bulk = ipv4_tcp_bulk_packet();
        let priority = ipv4_icmp_packet();

        assert!(matches!(
            tx.admit_from_tun_reader(first_bulk.clone()),
            Ok(TunOutboundAdmission::Enqueued)
        ));
        assert!(matches!(
            tx.admit_from_tun_reader(second_bulk),
            Ok(TunOutboundAdmission::BulkDropped)
        ));
        assert!(matches!(
            tx.admit_from_tun_reader(priority.clone()),
            Ok(TunOutboundAdmission::Enqueued)
        ));

        assert_eq!(rx.try_recv(), Ok(priority));
        assert_eq!(rx.try_recv(), Ok(first_bulk));
    }

    #[test]
    fn tun_outbound_recv_gives_bulk_a_turn_after_priority_burst() {
        let (tx, mut rx) = tun_outbound_channel(TUN_OUTBOUND_PRIORITY_BURST_MAX + 1);
        let bulk = ipv4_tcp_bulk_packet();
        let overflow_priority = packet_variant(ipv4_icmp_packet(), 0xff);

        tx.try_send(bulk.clone())
            .expect("bulk packet should enqueue");
        for index in 0..TUN_OUTBOUND_PRIORITY_BURST_MAX {
            tx.try_send(packet_variant(ipv4_icmp_packet(), index as u8))
                .expect("priority burst packet should enqueue");
        }
        tx.try_send(overflow_priority.clone())
            .expect("overflow priority packet should enqueue");

        for index in 0..TUN_OUTBOUND_PRIORITY_BURST_MAX {
            assert_eq!(
                rx.try_recv(),
                Ok(packet_variant(ipv4_icmp_packet(), index as u8))
            );
        }
        assert_eq!(rx.try_recv(), Ok(bulk));
        assert_eq!(rx.try_recv(), Ok(overflow_priority));
    }
}
