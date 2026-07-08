use tokio::sync::mpsc;

#[derive(Debug, Clone)]
pub struct TunOutboundTx {
    bulk: mpsc::Sender<Vec<u8>>,
}

#[derive(Debug)]
pub struct TunOutboundRx {
    bulk: mpsc::Receiver<Vec<u8>>,
}

pub(crate) fn tun_outbound_channel(capacity: usize) -> (TunOutboundTx, TunOutboundRx) {
    let capacity = capacity.max(1);
    let (bulk_tx, bulk_rx) = mpsc::channel(capacity);
    (
        TunOutboundTx { bulk: bulk_tx },
        TunOutboundRx { bulk: bulk_rx },
    )
}

impl TunOutboundTx {
    pub async fn send(&self, packet: Vec<u8>) -> Result<(), mpsc::error::SendError<Vec<u8>>> {
        self.bulk.send(packet).await
    }

    pub fn blocking_send(&self, packet: Vec<u8>) -> Result<(), mpsc::error::SendError<Vec<u8>>> {
        self.bulk.blocking_send(packet)
    }

    pub fn try_send(&self, packet: Vec<u8>) -> Result<(), mpsc::error::TrySendError<Vec<u8>>> {
        self.bulk.try_send(packet)
    }

    #[cfg(any(test, target_os = "linux", target_os = "macos", windows))]
    pub(crate) fn admit_from_tun_reader(
        &self,
        packet: Vec<u8>,
    ) -> Result<(), mpsc::error::SendError<Vec<u8>>> {
        match self.bulk.try_send(packet) {
            Ok(()) => Ok(()),
            Err(mpsc::error::TrySendError::Full(packet)) => {
                crate::perf_profile::record_tun_outbound_admission_drop();
                tracing::debug!(
                    len = packet.len(),
                    "Dropping TUN outbound packet because admission queue is full"
                );
                Ok(())
            }
            Err(mpsc::error::TrySendError::Closed(packet)) => Err(mpsc::error::SendError(packet)),
        }
    }
}

impl TunOutboundRx {
    pub(crate) async fn recv(&mut self) -> Option<Vec<u8>> {
        self.bulk.recv().await
    }

    pub(crate) fn try_recv(&mut self) -> Result<Vec<u8>, mpsc::error::TryRecvError> {
        self.bulk.try_recv()
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

        assert_eq!(rx.recv().await, Some(bulk));
        assert_eq!(rx.recv().await, Some(icmp));
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

        assert_eq!(rx.try_recv(), Ok(first_bulk));
    }

    #[test]
    fn tun_reader_admission_sheds_icmp_app_payload_when_full() {
        let (tx, mut rx) = tun_outbound_channel(1);
        let first_bulk = ipv4_tcp_bulk_packet();
        let icmp = ipv4_icmp_packet();

        assert!(tx.admit_from_tun_reader(first_bulk.clone()).is_ok());
        assert!(tx.admit_from_tun_reader(icmp).is_ok());

        assert_eq!(rx.try_recv(), Ok(first_bulk));
        assert!(matches!(
            rx.try_recv(),
            Err(mpsc::error::TryRecvError::Empty)
        ));
    }
}
