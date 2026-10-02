//! A selected late Ack, rather than unrelated activity, must complete the exchange.
use super::*;
use crate::dataplane::FmpWireHeader;
use crate::node::tests::spanning_tree::process_dataplane_packet_once;
use crate::protocol::LinkMessageType;
use crate::transport::{ReceivedPacket, packet_channel};
use ring::aead::{Aad, Nonce};

const TURN_TIMEOUT: Duration = Duration::from_secs(2);

#[test]
fn unrelated_activity_cannot_complete_a_withheld_late_ack() {
    run_large_stack_async_test("fips-held-late-ack", || exercise(true));
}

async fn wait_state(node: &mut TestNode, remote: &NodeAddr, established: bool) {
    let deadline = tokio::time::Instant::now() + TURN_TIMEOUT;
    tokio::time::timeout_at(deadline, async {
        loop {
            assert!(tokio::time::Instant::now() < deadline);
            poll_available_packets(std::slice::from_mut(node)).await;
            assert!(tokio::time::Instant::now() < deadline);
            if node.node.get_session(remote).is_some_and(|entry| {
                if established {
                    entry.is_established()
                } else {
                    entry.is_awaiting_msg3()
                }
            }) {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("selected handshake state must arrive within the original two seconds");
}

fn plaintext(node: &TestNode, remote: &NodeAddr, packet: &ReceivedPacket) -> Vec<u8> {
    let header = FmpWireHeader::parse_encrypted(packet.data.as_slice()).unwrap();
    let peer = node.node.get_peer(remote).unwrap();
    assert_eq!(header.receiver_idx(), peer.our_index().unwrap().as_u32());
    let offset = usize::from(header.ciphertext_offset());
    let mut bytes = packet.data.as_slice()[offset..].to_vec();
    let mut nonce = [0; 12];
    nonce[4..].copy_from_slice(&header.counter().to_le_bytes());
    // Opening a copy authenticates the selection without consuming replay state.
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
        .expect("authenticated FMP timestamp prefix")
        .to_vec()
}

async fn capture(
    node: &mut TestNode,
    remote: &NodeAddr,
    timeout: Duration,
    matches: impl Fn(&[u8]) -> bool,
) -> ReceivedPacket {
    let deadline = tokio::time::Instant::now() + timeout;
    tokio::time::timeout_at(deadline, async {
        loop {
            assert!(tokio::time::Instant::now() < deadline);
            let packet = node.packet_rx.recv().await.unwrap();
            assert!(tokio::time::Instant::now() < deadline);
            if matches(&plaintext(node, remote, &packet)) {
                return packet;
            }
            process_dataplane_packet_once(&mut node.node, packet).await;
        }
    })
    .await
    .expect("the exact authenticated handshake packet must arrive")
}

fn selected_payload(bytes: &[u8], source: NodeAddr, dest: NodeAddr, payload: &[u8]) -> bool {
    bytes.first() == Some(&LinkMessageType::SessionDatagram.to_byte())
        && SessionDatagram::decode(&bytes[1..]).is_ok_and(|datagram| {
            datagram.src_addr == source && datagram.dest_addr == dest && datagram.payload == payload
        })
}

async fn exchange_turn(nodes: &mut [TestNode], initiator: &NodeAddr) -> (usize, bool) {
    let activity = poll_available_packets(nodes).await;
    let ready = nodes[1]
        .node
        .get_session(initiator)
        .is_some_and(|entry| entry.is_established());
    (activity, ready)
}

pub(super) async fn exercise(withhold_ack: bool) {
    let mut nodes = run_tree_test(2, &[(0, 1)], false).await;
    let result = futures::FutureExt::catch_unwind(std::panic::AssertUnwindSafe(late_ack(
        &mut nodes,
        withhold_ack,
    )))
    .await;
    cleanup_nodes(&mut nodes).await;
    if let Err(panic) = result {
        std::panic::resume_unwind(panic);
    }
}

async fn prepare_retained_msg3(nodes: &mut [TestNode]) -> (NodeAddr, NodeAddr) {
    verify_tree_convergence(nodes);
    populate_all_coord_caches(nodes);
    nodes[0].node.config.node.rate_limit.handshake_max_resends = 1;
    nodes[1].node.config.node.rate_limit.handshake_max_resends = 3;
    for node in nodes.iter_mut() {
        node.node
            .config
            .node
            .rate_limit
            .handshake_resend_interval_ms = 5;
    }
    let initiator = *nodes[0].node.node_addr();
    let responder = *nodes[1].node.node_addr();
    let pubkey = nodes[1].node.identity().pubkey_full();
    nodes[0]
        .node
        .initiate_session(responder, pubkey)
        .await
        .unwrap();
    wait_state(&mut nodes[1], &initiator, false).await;
    wait_state(&mut nodes[0], &responder, true).await;
    let msg3 = nodes[0]
        .node
        .get_session(&responder)
        .unwrap()
        .handshake_payload()
        .unwrap()
        .to_vec();
    // Drop this exact original Msg3, within the original twenty 10 ms waits.
    drop(
        capture(
            &mut nodes[1],
            &initiator,
            Duration::from_millis(200),
            |bytes| selected_payload(bytes, initiator, responder, &msg3),
        )
        .await,
    );
    assert!(
        nodes[1]
            .node
            .get_session(&initiator)
            .unwrap()
            .is_awaiting_msg3()
    );
    nodes[0]
        .node
        .sessions
        .get_mut(&responder)
        .unwrap()
        .record_resend(0);
    nodes[0]
        .node
        .resend_pending_session_handshakes(Node::now_ms())
        .await;
    assert_eq!(
        nodes[0]
            .node
            .get_session(&responder)
            .unwrap()
            .handshake_payload(),
        Some(msg3.as_slice()),
        "the final msg3 must remain available after proactive retries stop"
    );
    (initiator, responder)
}

async fn late_ack(nodes: &mut [TestNode], withhold_ack: bool) {
    let (initiator, responder) = prepare_retained_msg3(nodes).await;
    let ack = nodes[1]
        .node
        .get_session(&initiator)
        .unwrap()
        .handshake_payload()
        .unwrap()
        .to_vec();
    tokio::time::sleep(Duration::from_millis(10)).await;
    nodes[1]
        .node
        .resend_pending_session_handshakes(Node::now_ms())
        .await;
    let held = capture(&mut nodes[0], &responder, TURN_TIMEOUT, |bytes| {
        selected_payload(bytes, responder, initiator, &ack)
    })
    .await;

    deliver_ack(nodes, &initiator, &responder, held, withhold_ack).await;
}

async fn deliver_ack(
    nodes: &mut [TestNode],
    initiator: &NodeAddr,
    responder: &NodeAddr,
    held: ReceivedPacket,
    withhold_ack: bool,
) {
    let (tx, rx) = packet_channel(2);
    if withhold_ack {
        let heartbeat = [LinkMessageType::Heartbeat.to_byte()];
        nodes[1]
            .node
            .send_dataplane_fmp_link_plaintext(initiator, &heartbeat, false)
            .await
            .unwrap();
        let unrelated = capture(&mut nodes[0], responder, TURN_TIMEOUT, |bytes| {
            bytes == heartbeat
        })
        .await;
        tx.send(unrelated).unwrap();
    }
    let original_rx = std::mem::replace(&mut nodes[0].packet_rx, rx);
    if withhold_ack {
        let (activity, ready) = tokio::time::timeout(TURN_TIMEOUT, exchange_turn(nodes, initiator))
            .await
            .unwrap();
        assert!(
            activity > 0,
            "the real unrelated heartbeat must be processed"
        );
        assert_eq!(tx.reserved_packets_for_test(), 0);
        assert!(
            !ready,
            "unrelated activity must not complete the withheld late Ack"
        );
    }
    tx.send(held).unwrap();
    // No proactive handshake timer runs here: only the original late Ack can solicit Msg3.
    let deadline = tokio::time::Instant::now() + TURN_TIMEOUT;
    tokio::time::timeout_at(deadline, async {
        loop {
            assert!(tokio::time::Instant::now() < deadline);
            let ready = exchange_turn(nodes, initiator).await.1;
            assert!(tokio::time::Instant::now() < deadline);
            if ready {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }).await.expect("the initiator must answer the late Ack and establish the responder within the original two seconds");
    nodes[0].packet_rx = original_rx;
    assert!(
        nodes[1]
            .node
            .get_session(initiator)
            .unwrap()
            .is_established(),
        "the responder should establish after the solicited msg3 resend"
    );
    assert_eq!(
        nodes[0].node.get_session(responder).unwrap().resend_count(),
        1
    );
}
