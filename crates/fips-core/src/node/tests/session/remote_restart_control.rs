use super::*;
use crate::dataplane::FmpWireHeader;
use crate::node::tests::spanning_tree::process_dataplane_packet_once;
use crate::protocol::LinkMessageType;
use crate::transport::{ReceivedPacket, packet_channel};
use ring::aead::{Aad, Nonce};

async fn fresh_setup_turn(node: &mut TestNode, remote: &NodeAddr) -> (usize, bool) {
    // Activity on another frame is not completion of this particular setup.
    let activity = poll_available_packets(std::slice::from_mut(node)).await;
    let ready = node.node.get_session(remote).is_some_and(|entry| {
        entry.has_rekey_in_progress() && !entry.is_rekey_handshake_initiator()
    });
    (activity, ready)
}

pub(super) async fn wait_for_fresh_setup(node: &mut TestNode, remote: &NodeAddr) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    loop {
        assert!(
            tokio::time::Instant::now() < deadline,
            "fresh setup deadline"
        );
        let (_, ready) = tokio::time::timeout_at(deadline, fresh_setup_turn(node, remote))
            .await
            .expect("fresh setup turn must stay within the original two seconds");
        assert!(
            tokio::time::Instant::now() < deadline,
            "surviving responder must process the restarted peer's fresh setup"
        );
        if ready {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

#[test]
fn unrelated_packet_does_not_complete_withheld_restart_setup() {
    run_large_stack_async_test("fips-restart-held-setup", || async {
        restarted_initiator_reestablishes_with_surviving_responder(true).await;
    });
}

fn plaintext(node: &TestNode, remote: &NodeAddr, packet: &ReceivedPacket) -> Vec<u8> {
    let header = FmpWireHeader::parse_encrypted(packet.data.as_slice()).unwrap();
    let peer = node.node.get_peer(remote).unwrap();
    assert_eq!(header.receiver_idx(), peer.our_index().unwrap().as_u32());
    let offset = usize::from(header.ciphertext_offset());
    let mut bytes = packet.data.as_slice()[offset..].to_vec();
    let mut nonce = [0; 12];
    nonce[4..].copy_from_slice(&header.counter().to_le_bytes());
    // Read-only opening uses the real receiver key without consuming its replay counter.
    peer.noise_session()
        .unwrap()
        .recv_cipher_clone()
        .unwrap()
        .open_in_place(
            Nonce::assume_unique_for_key(nonce),
            Aad::from(&packet.data.as_slice()[..offset]),
            &mut bytes,
        )
        .unwrap()
        .get(4..)
        .expect("authenticated FMP plaintext includes its four-byte timestamp")
        .to_vec()
}

async fn receive_matching(
    node: &mut TestNode,
    remote: &NodeAddr,
    matches: impl Fn(&[u8]) -> bool,
) -> ReceivedPacket {
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            let packet = node.packet_rx.recv().await.unwrap();
            if matches(&plaintext(node, remote, &packet)) {
                return packet;
            }
            process_dataplane_packet_once(&mut node.node, packet).await;
        }
    })
    .await
    .expect("the real encrypted control packet must arrive")
}

pub(super) async fn withheld_setup(
    nodes: &mut [TestNode],
    restarted: &NodeAddr,
    survivor: &NodeAddr,
) {
    let expected = nodes[0]
        .node
        .get_session(survivor)
        .unwrap()
        .handshake_payload()
        .unwrap()
        .to_vec();
    let held = receive_matching(&mut nodes[1], restarted, |bytes| {
        bytes.first() == Some(&LinkMessageType::SessionDatagram.to_byte())
            && SessionDatagram::decode(&bytes[1..]).is_ok_and(|datagram| {
                datagram.src_addr == *restarted
                    && datagram.dest_addr == *survivor
                    && datagram.payload == expected
            })
    })
    .await;
    let heartbeat = [LinkMessageType::Heartbeat.to_byte()];
    nodes[0]
        .node
        .send_dataplane_fmp_link_plaintext(survivor, &heartbeat, false)
        .await
        .unwrap();
    let unrelated = receive_matching(&mut nodes[1], restarted, |bytes| bytes == heartbeat).await;
    assert!(
        !nodes[1]
            .node
            .get_session(restarted)
            .unwrap()
            .has_rekey_in_progress()
    );

    // Queue the real heartbeat while the exact authenticated setup stays withheld.
    let (tx, rx) = packet_channel(2);
    let original_rx = std::mem::replace(&mut nodes[1].packet_rx, rx);
    tx.send(unrelated).unwrap();
    assert_eq!(tx.reserved_packets_for_test(), 1);
    let (activity, ready) = tokio::time::timeout(
        Duration::from_secs(2),
        fresh_setup_turn(&mut nodes[1], restarted),
    )
    .await
    .expect("the real unrelated packet turn must finish");
    assert!(activity > 0, "the unrelated packet produced real activity");
    assert_eq!(
        tx.reserved_packets_for_test(),
        0,
        "the unrelated packet was consumed"
    );
    assert!(
        !ready,
        "unrelated packet activity must not satisfy fresh setup readiness"
    );
    tx.send(held).unwrap();
    wait_for_fresh_setup(&mut nodes[1], restarted).await;
    nodes[1].packet_rx = original_rx;
}
