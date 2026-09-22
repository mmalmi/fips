use super::TestNode;
use crate::node::wire::{CommonPrefix, PHASE_ESTABLISHED};
use crate::transport::{PacketRx, packet_channel};
use tokio::sync::oneshot;

/// Inspect copies of established UDP frames on one authenticated link.
/// The fixture decides which messages to keep; all other frames pass unchanged.
pub(super) struct WireTap {
    receiver: usize,
    stop: oneshot::Sender<()>,
    task: tokio::task::JoinHandle<PacketRx>,
}

impl WireTap {
    pub(super) fn start(
        nodes: &mut [TestNode],
        receiver: usize,
        sender: usize,
        mut keep: impl FnMut(&[u8], u64) -> bool + Send + 'static,
    ) -> Self {
        let remote = nodes[sender].addr.clone();
        let cipher = nodes[receiver]
            .node
            .get_peer(nodes[sender].node.node_addr())
            .unwrap()
            .noise_session()
            .unwrap()
            .recv_cipher_clone()
            .unwrap();
        let (tx, rx) = packet_channel(256);
        let mut inbound = std::mem::replace(&mut nodes[receiver].packet_rx, rx);
        let (stop, mut stopped) = oneshot::channel();
        let task = tokio::spawn(async move {
            loop {
                let packet = tokio::select! {
                    packet = inbound.recv() => match packet {
                        Some(packet) => packet,
                        None => break,
                    },
                    _ = &mut stopped => break,
                };
                let wire = packet.data.as_slice();
                if packet.remote_addr == remote
                    && CommonPrefix::parse(wire).unwrap().phase == PHASE_ESTABLISHED
                {
                    let header = crate::dataplane::FmpWireHeader::parse_encrypted(wire).unwrap();
                    let offset = usize::from(header.ciphertext_offset());
                    let mut nonce = [0u8; 12];
                    nonce[4..].copy_from_slice(&header.counter().to_le_bytes());
                    let mut ciphertext = wire[offset..].to_vec();
                    let plaintext = cipher
                        .open_in_place(
                            ring::aead::Nonce::assume_unique_for_key(nonce),
                            ring::aead::Aad::from(&wire[..offset]),
                            &mut ciphertext,
                        )
                        .unwrap();
                    // Skip the link header. Never advance live crypto/replay
                    // state, re-encrypt a frame, or expose key material.
                    if !keep(&plaintext[4..], packet.timestamp_ms) {
                        continue;
                    }
                }
                tx.send(packet)
                    .expect("tap preserves every unselected datagram");
            }
            inbound
        });
        Self {
            receiver,
            stop,
            task,
        }
    }

    pub(super) async fn restore(self, nodes: &mut [TestNode]) {
        let _ = self.stop.send(());
        nodes[self.receiver].packet_rx = self.task.await.unwrap();
    }
}
