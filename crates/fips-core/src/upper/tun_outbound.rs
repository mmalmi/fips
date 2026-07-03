use crate::transport::{PacketBuffer, PacketBufferPool};
use tokio::sync::mpsc;

pub(super) const TUN_OUTBOUND_PACKET_TAIL_RESERVE: usize = 128;

#[derive(Debug, Clone)]
pub struct TunOutboundTx {
    bulk: mpsc::Sender<QueuedTunOutboundPacket>,
    buffer_pool: PacketBufferPool,
}

#[derive(Debug)]
pub struct TunOutboundRx {
    bulk: mpsc::Receiver<QueuedTunOutboundPacket>,
    bulk_closed: bool,
}

#[derive(Debug)]
struct QueuedTunOutboundPacket {
    packet: PacketBuffer,
}

impl QueuedTunOutboundPacket {
    fn new(packet: impl Into<PacketBuffer>) -> Self {
        Self {
            packet: packet.into(),
        }
    }

    fn into_packet(self) -> PacketBuffer {
        self.packet
    }
}

#[cfg(any(test, target_os = "linux", target_os = "macos", windows))]
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub(crate) enum TunOutboundAdmission {
    Enqueued,
    BulkDropped,
}

pub(crate) fn tun_outbound_channel(capacity: usize) -> (TunOutboundTx, TunOutboundRx) {
    let capacity = capacity.max(1);
    let (bulk_tx, bulk_rx) = mpsc::channel(capacity);
    let buffer_pool = PacketBufferPool::new();
    (
        TunOutboundTx {
            bulk: bulk_tx,
            buffer_pool,
        },
        TunOutboundRx {
            bulk: bulk_rx,
            bulk_closed: false,
        },
    )
}

impl TunOutboundTx {
    pub async fn send(&self, packet: Vec<u8>) -> Result<(), mpsc::error::SendError<Vec<u8>>> {
        self.send_queued(QueuedTunOutboundPacket::new(packet)).await
    }

    async fn send_queued(
        &self,
        queued: QueuedTunOutboundPacket,
    ) -> Result<(), mpsc::error::SendError<Vec<u8>>> {
        self.bulk
            .send(queued)
            .await
            .map_err(|error| mpsc::error::SendError(error.0.into_packet().into_vec()))
    }

    pub fn blocking_send(&self, packet: Vec<u8>) -> Result<(), mpsc::error::SendError<Vec<u8>>> {
        self.blocking_send_queued(QueuedTunOutboundPacket::new(packet))
    }

    fn blocking_send_queued(
        &self,
        queued: QueuedTunOutboundPacket,
    ) -> Result<(), mpsc::error::SendError<Vec<u8>>> {
        self.bulk
            .blocking_send(queued)
            .map_err(|error| mpsc::error::SendError(error.0.into_packet().into_vec()))
    }

    pub fn try_send(&self, packet: Vec<u8>) -> Result<(), mpsc::error::TrySendError<Vec<u8>>> {
        self.try_send_queued(QueuedTunOutboundPacket::new(packet))
    }

    fn try_send_queued(
        &self,
        queued: QueuedTunOutboundPacket,
    ) -> Result<(), mpsc::error::TrySendError<Vec<u8>>> {
        self.bulk
            .try_send(queued)
            .map_err(map_queued_try_send_error)
    }

    #[cfg(any(test, target_os = "linux", target_os = "macos", windows))]
    pub(crate) fn admit_from_tun_reader(
        &self,
        packet: &[u8],
    ) -> Result<TunOutboundAdmission, mpsc::error::SendError<Vec<u8>>> {
        let queued = self.tun_reader_packet(packet);
        match self.bulk.try_send(queued) {
            Ok(()) => Ok(TunOutboundAdmission::Enqueued),
            Err(mpsc::error::TrySendError::Full(queued)) => {
                crate::perf_profile::record_event(
                    crate::perf_profile::Event::PendingTunPacketDropped,
                );
                tracing::debug!(
                    len = queued.packet.len(),
                    "Dropping TUN outbound packet because admission queue is full"
                );
                Ok(TunOutboundAdmission::BulkDropped)
            }
            Err(mpsc::error::TrySendError::Closed(queued)) => {
                Err(mpsc::error::SendError(queued.into_packet().into_vec()))
            }
        }
    }

    #[cfg(any(test, target_os = "linux", target_os = "macos", windows))]
    fn tun_reader_packet(&self, packet: &[u8]) -> QueuedTunOutboundPacket {
        let mut outbound = self.buffer_pool.take_empty(
            packet
                .len()
                .saturating_add(TUN_OUTBOUND_PACKET_TAIL_RESERVE),
        );
        outbound.extend_from_slice(packet);
        QueuedTunOutboundPacket::new(self.buffer_pool.packet_buffer(outbound))
    }
}

impl TunOutboundRx {
    pub(crate) async fn recv(&mut self) -> Option<PacketBuffer> {
        match self.bulk.recv().await {
            Some(packet) => Some(packet.into_packet()),
            None => {
                self.bulk_closed = true;
                None
            }
        }
    }

    pub(crate) fn try_recv(&mut self) -> Result<PacketBuffer, mpsc::error::TryRecvError> {
        match self.bulk.try_recv() {
            Ok(packet) => Ok(packet.into_packet()),
            Err(mpsc::error::TryRecvError::Empty) => Err(mpsc::error::TryRecvError::Empty),
            Err(mpsc::error::TryRecvError::Disconnected) => {
                self.bulk_closed = true;
                Err(mpsc::error::TryRecvError::Disconnected)
            }
        }
    }
}

fn map_queued_try_send_error(
    error: mpsc::error::TrySendError<QueuedTunOutboundPacket>,
) -> mpsc::error::TrySendError<Vec<u8>> {
    match error {
        mpsc::error::TrySendError::Full(packet) => {
            mpsc::error::TrySendError::Full(packet.into_packet().into_vec())
        }
        mpsc::error::TrySendError::Closed(packet) => {
            mpsc::error::TrySendError::Closed(packet.into_packet().into_vec())
        }
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

    #[tokio::test]
    async fn tun_outbound_recv_preserves_app_packet_order() {
        let (tx, mut rx) = tun_outbound_channel(4);
        let bulk = ipv4_tcp_bulk_packet();
        let icmp = ipv4_icmp_packet();

        tx.try_send(bulk.clone())
            .expect("first app packet should enqueue");
        tx.try_send(icmp.clone())
            .expect("second app packet should enqueue");

        assert_eq!(
            rx.recv()
                .await
                .expect("first app packet should dequeue")
                .as_slice(),
            bulk.as_slice()
        );
        assert_eq!(
            rx.recv()
                .await
                .expect("second app packet should dequeue")
                .as_slice(),
            icmp.as_slice()
        );
    }

    #[test]
    fn tun_outbound_capacity_applies_to_icmp_app_payload() {
        let (tx, mut rx) = tun_outbound_channel(1);
        let first_bulk = ipv4_tcp_bulk_packet();
        let icmp = ipv4_icmp_packet();

        tx.try_send(first_bulk.clone())
            .expect("first app packet should fit");
        assert!(
            tx.try_send(icmp).is_err(),
            "ICMP app payload should share bounded app packet capacity"
        );

        assert_eq!(
            rx.try_recv()
                .expect("first app packet should dequeue")
                .as_slice(),
            first_bulk.as_slice()
        );
    }

    #[test]
    fn tun_reader_admission_sheds_icmp_app_payload_when_full() {
        let (tx, mut rx) = tun_outbound_channel(1);
        let first_bulk = ipv4_tcp_bulk_packet();
        let icmp = ipv4_icmp_packet();

        assert!(matches!(
            tx.admit_from_tun_reader(&first_bulk),
            Ok(TunOutboundAdmission::Enqueued)
        ));
        assert!(matches!(
            tx.admit_from_tun_reader(&icmp),
            Ok(TunOutboundAdmission::BulkDropped)
        ));

        assert_eq!(
            rx.try_recv()
                .expect("first app packet should dequeue")
                .as_slice(),
            first_bulk.as_slice()
        );
    }

    #[test]
    fn tun_reader_admission_reserves_tail_room_for_dataplane_prepend() {
        let (tx, mut rx) = tun_outbound_channel(1);
        let packet = vec![0x42; 1280];

        assert!(matches!(
            tx.admit_from_tun_reader(&packet),
            Ok(TunOutboundAdmission::Enqueued)
        ));

        let outbound = rx
            .try_recv()
            .expect("TUN reader packet should be queued")
            .into_vec();
        assert_eq!(outbound, packet);
        assert!(
            outbound.capacity() >= packet.len() + TUN_OUTBOUND_PACKET_TAIL_RESERVE,
            "TUN outbound packets need spare tail room so IPv6 shim plus AEAD prepend can avoid a second hot-path allocation"
        );
    }
}
