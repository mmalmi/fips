//! Selected handshake state and authenticated delivery, not unrelated activity.
use super::*;
use crate::dataplane::FmpWireHeader;
use crate::node::session_wire::{FSP_PHASE_MSG1, FSP_PHASE_MSG2, FSP_PHASE_MSG3, FspCommonPrefix};
use crate::node::tests::spanning_tree::process_dataplane_packet_once;
use crate::protocol::LinkMessageType;
use crate::transport::{ReceivedPacket, packet_channel};
use ring::aead::{Aad, Nonce};

fn phase(stage: Stage) -> u8 {
    match stage {
        Stage::Setup => FSP_PHASE_MSG1,
        Stage::Ack => FSP_PHASE_MSG2,
        Stage::Msg3 | Stage::DuplicateAck => FSP_PHASE_MSG3,
    }
}

fn sent(node: &Node, peer: &NodeAddr, stage: Stage, rekey: bool) -> bool {
    node.get_session(peer)
        .is_some_and(|entry| match (stage, rekey) {
            (Stage::Ack, false) => entry.is_awaiting_msg3(),
            (Stage::Ack, true) => {
                entry.has_rekey_in_progress() && !entry.is_rekey_handshake_initiator()
            }
            (Stage::Msg3, false) => {
                entry.is_established()
                    && entry.handshake_payload().is_some_and(|payload| {
                        FspCommonPrefix::parse(payload)
                            .is_some_and(|prefix| prefix.phase == FSP_PHASE_MSG3)
                    })
            }
            (Stage::Msg3, true) => {
                entry.pending_new_session().is_some() && entry.rekey_msg3_payload().is_some()
            }
            _ => unreachable!("only the two driven reply stages have a readiness predicate"),
        })
}

async fn turn(node: &mut TestNode, peer: &NodeAddr, stage: Stage, rekey: bool) -> (usize, bool) {
    let activity = poll_available_packets(std::slice::from_mut(node)).await;
    (activity, sent(&node.node, peer, stage, rekey))
}

pub(super) async fn drive(node: &mut TestNode, peer: &NodeAddr, stage: Stage, rekey: bool) {
    loop {
        if turn(node, peer, stage, rekey).await.1 {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

pub(super) async fn wait_for_sent(node: &mut TestNode, peer: &NodeAddr, stage: Stage, rekey: bool) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    tokio::time::timeout_at(deadline, drive(node, peer, stage, rekey))
        .await
        .expect("selected reply must complete within the original two seconds");
    assert!(
        tokio::time::Instant::now() < deadline,
        "selected reply deadline"
    );
}

fn plaintext(node: &TestNode, source: &NodeAddr, packet: &ReceivedPacket) -> Option<Vec<u8>> {
    let header = FmpWireHeader::parse_encrypted(packet.data.as_slice()).ok()?;
    let peer = node.node.get_peer(source)?;
    if header.receiver_idx() != peer.our_index()?.as_u32() {
        return None;
    }
    let offset = usize::from(header.ciphertext_offset());
    let mut bytes = packet.data.as_slice()[offset..].to_vec();
    let mut nonce = [0; 12];
    nonce[4..].copy_from_slice(&header.counter().to_le_bytes());
    // Authenticate a copy: the original packet and production replay state remain intact.
    let plaintext = peer
        .noise_session()?
        .recv_cipher_clone()?
        .open_in_place(
            Nonce::assume_unique_for_key(nonce),
            Aad::from(&packet.data.as_slice()[..offset]),
            &mut bytes,
        )
        .ok()?;
    Some(plaintext.get(4..)?.to_vec())
}

pub(super) struct Delivery {
    packets: Vec<ReceivedPacket>,
    payload: Vec<u8>,
}

impl Delivery {
    pub(super) fn assert_retained(
        &self,
        sender: &Node,
        peer: &NodeAddr,
        stage: Stage,
        rekey: bool,
    ) {
        let entry = sender.get_session(peer).unwrap();
        let retained = if rekey && matches!(stage, Stage::Msg3) {
            entry.rekey_msg3_payload()
        } else {
            entry.handshake_payload()
        };
        assert_eq!(
            retained,
            Some(self.payload.as_slice()),
            "delivered packet must match the exact retained handshake"
        );
    }

    pub(super) async fn release(self, receiver: &mut TestNode) {
        // Admit every original packet once, in receive order, before polling
        // the receiver's remaining queue. Nothing is re-encrypted or replaced.
        for packet in self.packets {
            process_dataplane_packet_once(&mut receiver.node, packet).await;
        }
    }
}

pub(super) async fn capture(receiver: &mut TestNode, source: &NodeAddr, stage: Stage) -> Delivery {
    let mut packets = Vec::new();
    loop {
        let packet = receiver.packet_rx.recv().await.unwrap();
        let payload = plaintext(receiver, source, &packet).and_then(|bytes| {
            if bytes.first() != Some(&LinkMessageType::SessionDatagram.to_byte()) {
                return None;
            }
            let datagram = SessionDatagram::decode(&bytes[1..]).ok()?;
            (datagram.src_addr == *source
                && datagram.dest_addr == *receiver.node.node_addr()
                && FspCommonPrefix::parse(&datagram.payload)?.phase == phase(stage))
            .then_some(datagram.payload)
        });
        assert!(packets.len() < 64, "bounded selected-delivery capture");
        packets.push(packet);
        if let Some(payload) = payload {
            return Delivery { packets, payload };
        }
    }
}

#[test]
fn unrelated_activity_does_not_complete_withheld_handshake_setup() {
    run_large_stack_async_test("retention-held-setup", || async {
        let mut nodes = run_tree_test(2, &[(0, 1)], false).await;
        let result =
            futures::FutureExt::catch_unwind(std::panic::AssertUnwindSafe(held_setup(&mut nodes)))
                .await;
        cleanup_nodes(&mut nodes).await;
        if let Err(panic) = result {
            std::panic::resume_unwind(panic);
        }
    });
}

async fn held_setup(nodes: &mut [TestNode]) {
    populate_all_coord_caches(nodes);
    let source = *nodes[0].node.node_addr();
    let destination = *nodes[1].node.node_addr();
    let identity = PeerIdentity::from_pubkey_full(nodes[1].node.identity().pubkey_full());
    begin(&mut nodes[0].node, identity, false).await;
    let held = tokio::time::timeout(
        Duration::from_secs(2),
        capture(&mut nodes[1], &source, Stage::Setup),
    )
    .await
    .unwrap();
    held.assert_retained(&nodes[0].node, &destination, Stage::Setup, false);
    let heartbeat = [LinkMessageType::Heartbeat.to_byte()];
    nodes[0]
        .node
        .send_dataplane_fmp_link_plaintext(&destination, &heartbeat, false)
        .await
        .unwrap();
    let unrelated = tokio::time::timeout(Duration::from_secs(2), async {
        let mut packets = Vec::new();
        loop {
            let packet = nodes[1].packet_rx.recv().await.unwrap();
            let matched =
                plaintext(&nodes[1], &source, &packet).as_deref() == Some(heartbeat.as_slice());
            assert!(packets.len() < 64, "bounded heartbeat capture");
            packets.push(packet);
            if matched {
                return packets;
            }
        }
    })
    .await
    .unwrap();
    let (tx, rx) = packet_channel(128);
    let original_rx = std::mem::replace(&mut nodes[1].packet_rx, rx);
    for packet in unrelated {
        tx.send(packet).unwrap();
    }
    let (activity, ready) = tokio::time::timeout(
        Duration::from_secs(2),
        turn(&mut nodes[1], &source, Stage::Ack, false),
    )
    .await
    .unwrap();
    assert!(activity > 0, "real unrelated heartbeat must be admitted");
    assert!(
        !ready,
        "unrelated activity must not complete the withheld handshake setup"
    );
    for packet in held.packets {
        tx.send(packet).unwrap();
    }
    wait_for_sent(&mut nodes[1], &source, Stage::Ack, false).await;
    nodes[1].packet_rx = original_rx;
}
