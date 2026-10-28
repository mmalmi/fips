use super::*;
use crate::Identity;
use crate::dataplane::{
    DataplaneLiveNodeTurn, DataplaneLiveOutboundFirsts, DataplaneRawIngress, PacketProtocol,
};
use crate::node::SessionEntry;
use crate::node::session::EndToEndState;
use crate::noise::{HandshakeState, NoiseSession};
use crate::peer::{ActivePeer, ActivePeerSession};
use crate::test_allocations::{Counts, measure_future};
use crate::transport::{LinkId, LinkStats, PacketBuffer, TransportAddr, TransportId};
use crate::utils::index::SessionIndex;
use std::time::{Duration, Instant};

fn session_pair(initiator: &Identity, responder: &Identity) -> (NoiseSession, NoiseSession) {
    let mut a = HandshakeState::new_xk_initiator(initiator.keypair(), responder.pubkey_full());
    let mut b = HandshakeState::new_xk_responder(responder.keypair());
    a.set_local_epoch([1; 8]);
    b.set_local_epoch([2; 8]);
    b.read_xk_message_1(&a.write_xk_message_1().unwrap())
        .unwrap();
    a.read_xk_message_2(&b.write_xk_message_2().unwrap())
        .unwrap();
    b.read_xk_message_3(&a.write_xk_message_3().unwrap())
        .unwrap();
    (a.into_session().unwrap(), b.into_session().unwrap())
}

struct ReceiptFixture {
    node: Node,
    remote: NodeAddr,
    fmp: NoiseSession,
    fsp: NoiseSession,
    mixed_turns: usize,
}

impl ReceiptFixture {
    fn new() -> Self {
        let local = Identity::generate();
        let remote = Identity::generate();
        let (fmp, fmp_receive) = session_pair(&remote, &local);
        let (fsp, fsp_receive) = session_pair(&remote, &local);
        let mut node = Node::with_identity(local, crate::Config::new()).unwrap();
        node.config.node.mmp.mode = crate::mmp::MmpMode::Full;
        let address = *remote.node_addr();
        node.peers.insert_with_current_session_index(
            address,
            ActivePeer::with_session(
                PeerIdentity::from_pubkey_full(remote.pubkey_full()),
                LinkId::new(1),
                Node::now_ms(),
                ActivePeerSession {
                    session: fmp_receive,
                    our_index: SessionIndex::new(1),
                    their_index: SessionIndex::new(2),
                    transport_id: TransportId::new(1),
                    current_addr: TransportAddr::from_string("192.0.2.1:2121"),
                    link_stats: LinkStats::new(),
                    is_initiator: false,
                    remote_epoch: None,
                },
            ),
        );
        assert!(node.sync_dataplane_fmp_owner(&address));
        node.sessions.insert(
            address,
            SessionEntry::new(
                address,
                remote.pubkey_full(),
                EndToEndState::Established(fsp_receive),
                Node::now_ms(),
                false,
            ),
        );
        assert!(node.sync_dataplane_fsp_owner_from_current_session(&address, 0));
        Self {
            node,
            remote: address,
            fmp,
            fsp,
            mixed_turns: 0,
        }
    }

    fn raw_packet(&mut self) -> DataplaneRawIngress {
        let plaintext = crate::node::session_wire::fsp_prepend_inner_header(
            100,
            crate::protocol::SessionMessageType::EndpointData.to_byte(),
            0,
            b"receipt-qualified",
        );
        let header = crate::node::session_wire::build_fsp_header(
            self.fsp.current_send_counter(),
            0,
            plaintext.len().try_into().unwrap(),
        );
        let mut fsp = header.to_vec();
        fsp.extend(self.fsp.encrypt_with_aad(&plaintext, &header).unwrap());
        let datagram = crate::protocol::SessionDatagram::new(
            self.remote,
            *self.node.identity().node_addr(),
            fsp,
        )
        .with_ttl(8)
        .with_path_mtu(1280)
        .encode();
        let mut plaintext = 100_u32.to_le_bytes().to_vec();
        plaintext.extend(datagram);
        let mut wire = vec![0; crate::node::wire::ESTABLISHED_HEADER_SIZE];
        wire[0] = crate::node::wire::FMP_VERSION << 4;
        wire[2..4].copy_from_slice(&u16::try_from(plaintext.len()).unwrap().to_le_bytes());
        wire[4..8].copy_from_slice(&1_u32.to_le_bytes());
        wire[8..16].copy_from_slice(&self.fmp.current_send_counter().to_le_bytes());
        let ciphertext = self.fmp.encrypt_with_aad(&plaintext, &wire).unwrap();
        wire.extend(ciphertext);
        DataplaneRawIngress::from_live_received(
            PacketProtocol::Fmp,
            ReceivedPacket::with_timestamp(
                TransportId::new(1),
                TransportAddr::from_string("192.0.2.1:2121"),
                PacketBuffer::new(wire),
                Node::now_ms(),
            ),
        )
    }

    async fn pump(
        &mut self,
        raw: &mut std::collections::VecDeque<DataplaneRawIngress>,
    ) -> DataplaneLiveNodeTurn {
        let (endpoint_tx, _endpoint_events) = crate::node::EndpointEventSender::channel(8);
        let (_, mut endpoint_rx) = crate::node::endpoint_data_batch_channel(1);
        let (_, mut tun_rx) = crate::upper::tun::tun_outbound_channel(1);
        let turn = self
            .node
            .dataplane
            .pump_turn_with_firsts_and_transport_batch(
                None,
                raw,
                1,
                DataplaneLiveOutboundFirsts::default(),
                DataplaneLiveTurnIo {
                    endpoint_data_rx: Some(&mut endpoint_rx),
                    endpoint_limit: 0,
                    tun_outbound_rx: Some(&mut tun_rx),
                    tun_limit: 0,
                    endpoint_tx: &endpoint_tx,
                    transports: &self.node.transports,
                    crypto_limit: 1,
                    transport_send_batch_packets: 1,
                },
            )
            .await;
        assert!(
            !turn.has_failures(),
            "real authenticated ingress must remain accepted: {turn:?}"
        );
        turn
    }

    async fn receipt_turn(&mut self) -> DataplaneLiveNodeTurn {
        // A ready worker completion may share a turn with its FSP continuation.
        // Process those real mixed turns normally and report their frequency;
        // never manufacture a receipt-only report by stripping other work.
        for _ in 0..64 {
            let mut raw = std::collections::VecDeque::from([self.raw_packet()]);
            let deadline = Instant::now() + Duration::from_secs(2);
            loop {
                let mut turn = self.pump(&mut raw).await;
                if turn.has_only_fmp_ingress_receipts() {
                    return turn;
                }
                if turn.has_node_control_ingress() {
                    assert_eq!(turn.fsp_session_ingress_count(), 1);
                    let before = self.received();
                    assert_eq!(
                        self.node.process_dataplane_control_ingress(&mut turn).await,
                        2
                    );
                    assert_eq!(self.received(), before + 1);
                    assert!(!turn.has_node_control_ingress());
                    self.mixed_turns += 1;
                    break;
                }
                assert!(Instant::now() < deadline);
                tokio::task::yield_now().await;
            }
        }
        panic!("no genuine receipt-only turn in 64 packets; fixture cannot qualify this path");
    }

    async fn finish_payload(&mut self) {
        let mut raw = std::collections::VecDeque::new();
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            let mut turn = self.pump(&mut raw).await;
            let delivered =
                turn.fsp_session_ingress_count() > 0 || turn.endpoint_data_packet_count() > 0;
            self.node.process_dataplane_control_ingress(&mut turn).await;
            if delivered {
                return;
            }
            assert!(
                Instant::now() < deadline,
                "FSP payload must still complete after receipt bookkeeping"
            );
            tokio::task::yield_now().await;
        }
    }

    fn received(&self) -> u64 {
        self.node
            .dataplane
            .fmp_link_metrics(&self.remote, Instant::now())
            .unwrap()
            .rx_packets
    }

    async fn dispatch(
        &mut self,
        turn: &mut DataplaneLiveNodeTurn,
        baseline: bool,
    ) -> (usize, Counts, u128) {
        let started = Instant::now();
        let (processed, counts) = measure_future(async {
            if baseline {
                Box::pin(self.node.process_active_dataplane_control_ingress(turn)).await
            } else {
                self.node.process_dataplane_control_ingress(turn).await
            }
        })
        .await;
        (processed, counts, started.elapsed().as_nanos())
    }
}

#[tokio::test]
async fn receipt_only_turn_preserves_authenticated_bookkeeping_and_payload_completion() {
    let mut fixture = ReceiptFixture::new();
    for baseline in [true, false] {
        let mut turn = fixture.receipt_turn().await;
        let before = fixture.received();
        let (processed, _, _) = fixture.dispatch(&mut turn, baseline).await;
        assert_eq!(processed, 1);
        assert_eq!(fixture.received(), before + 1);
        assert!(!turn.has_node_control_ingress());
        assert_eq!(
            fixture
                .node
                .process_dataplane_control_ingress(&mut turn)
                .await,
            0
        );
        assert_eq!(
            fixture.received(),
            before + 1,
            "receipt is consumed exactly once"
        );
        fixture.finish_payload().await;
    }
}

#[tokio::test]
async fn receipt_only_turn_avoids_active_future_allocation() {
    assert_receipt_turn_allocation(false).await;
}

#[tokio::test]
#[ignore = "expected failure demonstrates pre-change active future allocation"]
async fn receipt_only_baseline_red() {
    assert_receipt_turn_allocation(true).await;
}

async fn assert_receipt_turn_allocation(baseline: bool) {
    let mut fixture = ReceiptFixture::new();
    let mut warmup = fixture.receipt_turn().await;
    fixture.dispatch(&mut warmup, baseline).await;
    fixture.finish_payload().await;
    let mut turn = fixture.receipt_turn().await;
    let active_bytes = std::mem::size_of_val(
        &fixture
            .node
            .process_active_dataplane_control_ingress(&mut turn),
    );
    let (processed, counts, _) = fixture.dispatch(&mut turn, baseline).await;
    assert_eq!(processed, 1);
    assert!(
        counts.bytes < active_bytes,
        "receipt-only turn must not allocate the active control future: {counts:?}, future={active_bytes}"
    );
    fixture.finish_payload().await;
}

#[tokio::test]
#[ignore = "bounded same-process allocation/latency qualification"]
async fn receipt_only_paired_allocation_benchmark() {
    let mut fixture = ReceiptFixture::new();
    let mut turn = fixture.receipt_turn().await;
    let active_bytes = std::mem::size_of_val(
        &fixture
            .node
            .process_active_dataplane_control_ingress(&mut turn),
    );
    let entry_bytes =
        std::mem::size_of_val(&fixture.node.process_dataplane_control_ingress(&mut turn));
    println!("TURN_FUTURE {{\"active_bytes\":{active_bytes},\"entry_bytes\":{entry_bytes}}}");
    fixture.dispatch(&mut turn, false).await;
    fixture.finish_payload().await;
    for baseline in [true, false] {
        for _ in 0..16 {
            let mut turn = fixture.receipt_turn().await;
            fixture.dispatch(&mut turn, baseline).await;
            fixture.finish_payload().await;
        }
    }
    for pair in 0..7 {
        let mut allocations = [0; 2];
        let mut bytes = [0; 2];
        for baseline in if pair % 2 == 0 {
            [true, false]
        } else {
            [false, true]
        } {
            let mut counts = Counts::default();
            let mut elapsed = 0;
            let mixed_before = fixture.mixed_turns;
            for _ in 0..256 {
                let mut turn = fixture.receipt_turn().await;
                let before = fixture.received();
                let (processed, sample, nanos) = fixture.dispatch(&mut turn, baseline).await;
                assert_eq!(processed, 1);
                assert_eq!(fixture.received(), before + 1);
                counts.allocations += sample.allocations;
                counts.bytes += sample.bytes;
                counts.frees += sample.frees;
                elapsed += nanos;
                fixture.finish_payload().await;
            }
            let index = usize::from(!baseline);
            allocations[index] = counts.allocations;
            bytes[index] = counts.bytes;
            let mixed_turns = fixture.mixed_turns - mixed_before;
            println!(
                "TURN_ALLOCATION {{\"case\":\"fmp_receipt\",\"pair\":{pair},\"baseline\":{baseline},\"turns\":256,\"mixed_turns_processed\":{mixed_turns},\"allocations\":{},\"bytes\":{},\"frees\":{},\"nanos\":{elapsed}}}",
                counts.allocations, counts.bytes, counts.frees
            );
        }
        assert_eq!(allocations[0], allocations[1] + 256);
        assert_eq!(bytes[0], bytes[1] + 256 * active_bytes);
    }
}
