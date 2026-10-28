use super::*;
use crate::test_allocations::{Counts, measure_future};
use std::time::{Duration, Instant};

#[test]
fn receipt_only_control_guard_rejects_mixed_controls_and_all_drop_classes() {
    let identity = crate::Identity::generate();
    let peer = crate::PeerIdentity::from_pubkey_full(identity.pubkey_full());
    let address = *peer.node_addr();
    let transport = TransportId::new(983);
    let remote = TransportAddr::from_string("192.0.2.1:2121");
    let receipt = DataplaneFmpIngressReceipt {
        source_addr: address,
        source_peer: peer,
        transport_id: transport,
        remote_addr: remote.clone(),
        packet_timestamp_ms: 100,
        packet_len: 64,
        fmp_counter: 1,
        fmp_flags: 0,
        inner_timestamp_ms: 100,
        elicits_report: true,
    };
    assert!(!DataplaneLiveNodeTurn::default().has_only_fmp_ingress_receipts());
    for case in 0..12 {
        let mut turn = DataplaneLiveNodeTurn {
            fmp_ingress_receipts: vec![receipt.clone()],
            ..Default::default()
        };
        assert!(turn.has_only_fmp_ingress_receipts());
        let packet = || {
            ReceivedPacket::with_timestamp(transport, remote.clone(), PacketBuffer::default(), 100)
        };
        let output =
            || transport_output(fmp_owner(983), 1, 1, transport, remote.clone(), vec![0; 32]);
        match case {
            0 => turn
                .fmp_control_ingress
                .push(DataplaneFmpControlIngress::new(packet())),
            1 => turn
                .fmp_link_ingress
                .push(DataplaneFmpLinkIngress::from_output(
                    output(),
                    receipt.clone(),
                )),
            2 => turn
                .fsp_coord_warmups
                .push(DataplaneFspCoordWarmup::default()),
            3 => turn
                .fsp_local_session_ingress
                .push(DataplaneFspLocalSessionIngress::new(
                    address,
                    address,
                    false,
                    1280,
                    PacketBuffer::default(),
                )),
            4 => turn
                .fsp_authenticated_ingress
                .runs
                .push(DataplaneFspAuthenticatedIngressRun::Sessions { count: 1 }),
            5 => turn.tun_outbound_drops.push(DataplaneTunOutboundDrop::new(
                vec![],
                DataplaneTunOutboundDropReason::InvalidPacket,
            )),
            6 => turn.drops.push(PacketDrop {
                owner: fmp_owner(983),
                counter: Some(1),
                send_token: None,
                reason: PacketDropReason::CryptoFailed,
                crypto_failure: Some(CryptoFailureKind::Open),
                wire_flags: Some(0),
                authenticated_counter_highest: None,
            }),
            7 => turn
                .raw_ingress_drops
                .push(DataplaneRawIngressDrop::from_packet(
                    DataplaneRawIngress::from_live_received(PacketProtocol::Fmp, packet()),
                    DataplaneRawIngressDropReason::Unrouted,
                )),
            8 => turn.endpoint_data_drops.push(DataplaneEndpointDataDrop {
                dest_addr: address,
                payload_len: 1,
                reason: DataplaneEndpointDataDropReason::StaleQueuedBatch,
            }),
            9 => turn.output_drops.push(DataplaneOutputDrop::from_output(
                &output(),
                DataplaneOutputError::NoRoute,
            )),
            10 => turn.transport_dropped = 1,
            11 => turn.summary.inbound_dropped = 1,
            _ => unreachable!(),
        }
        assert!(
            !turn.has_only_fmp_ingress_receipts(),
            "mixed control/failure case {case} must keep full processing"
        );
        assert_eq!(
            turn.take_fmp_ingress_receipts(),
            [receipt.clone()],
            "guard must not consume bookkeeping"
        );
    }
}

// Exact pre-change ownership transfer, for paired measurements in one binary.
fn baseline_groups(output: &mut DataplaneTransportSendGroups) -> Vec<DataplaneTransportPlanGroup> {
    if output.groups.is_empty() {
        return Vec::new();
    }
    let capacity = output.groups.capacity();
    std::mem::replace(&mut output.groups, Vec::with_capacity(capacity))
}

async fn dispatch(
    output: &mut DataplaneTransportSendGroups,
    transports: &HashMap<TransportId, TransportHandle>,
    drops: &mut Vec<DataplaneOutputDrop>,
    receipts: &mut Vec<DataplaneTransportSentReceipt>,
    baseline: bool,
) -> usize {
    if baseline {
        send_dataplane_transport_groups(
            transports,
            baseline_groups(output),
            drops,
            1,
            Some(receipts),
        )
        .await
    } else {
        send_dataplane_transport_groups(transports, output.drain_groups(), drops, 1, Some(receipts))
            .await
    }
}

struct UdpTurns {
    listener: tokio::net::UdpSocket,
    transports: HashMap<TransportId, TransportHandle>,
    output: DataplaneTransportSendGroups,
    remote: TransportAddr,
    drops: Vec<DataplaneOutputDrop>,
    receipts: Vec<DataplaneTransportSentReceipt>,
}

impl UdpTurns {
    async fn new() -> Self {
        let listener = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let remote = TransportAddr::from_string(&listener.local_addr().unwrap().to_string());
        let id = TransportId::new(981);
        let mut transport = unstarted_udp_transport(id);
        transport.start().await.unwrap();
        Self {
            listener,
            remote,
            transports: HashMap::from([(id, transport)]),
            output: DataplaneTransportSendGroups::new(),
            drops: Vec::new(),
            receipts: Vec::with_capacity(4),
        }
    }

    fn prepare(&mut self, groups: usize, sequence: u64) {
        assert!(self.output.groups.is_empty());
        self.drops.clear();
        self.receipts.clear();
        for index in 0..groups {
            let counter = sequence * 4 + index as u64;
            let id = TransportId::new(981);
            // Separate live groups preserve each owner's packet order.
            self.output.groups.push(DataplaneTransportPlanGroup::new(
                id,
                self.remote.clone(),
                transport_output(
                    fmp_owner(981 + index as u64),
                    counter,
                    counter,
                    id,
                    self.remote.clone(),
                    counter.to_le_bytes().to_vec(),
                ),
            ));
        }
    }

    async fn send(&mut self, baseline: bool) -> (usize, Counts, u128) {
        let start = Instant::now();
        let (sent, counts) = measure_future(dispatch(
            &mut self.output,
            &self.transports,
            &mut self.drops,
            &mut self.receipts,
            baseline,
        ))
        .await;
        (sent, counts, start.elapsed().as_nanos())
    }

    async fn verify(&self, groups: usize, sequence: u64) {
        assert!(self.output.groups.is_empty());
        assert!(self.drops.is_empty());
        assert_eq!(self.receipts.len(), groups);
        for (index, receipt) in self.receipts.iter().enumerate() {
            let counter = sequence * 4 + index as u64;
            assert_eq!(receipt.counter, counter);
            let mut received = [0; 16];
            let bytes =
                tokio::time::timeout(Duration::from_secs(1), self.listener.recv(&mut received))
                    .await
                    .unwrap()
                    .unwrap();
            assert_eq!(&received[..bytes], &counter.to_le_bytes());
        }
    }

    async fn stop(mut self) {
        self.transports
            .get_mut(&TransportId::new(981))
            .unwrap()
            .stop()
            .await
            .unwrap();
    }
}

#[tokio::test]
async fn transport_turn_reuses_buffer_with_real_one_packet_and_multigroup_sends() {
    assert_live_buffer_reused(false).await;
}

#[tokio::test]
#[ignore = "expected failure demonstrates the pre-change buffer replacement"]
async fn transport_turn_baseline_red() {
    assert_live_buffer_reused(true).await;
}

async fn assert_live_buffer_reused(baseline: bool) {
    let mut fixture = UdpTurns::new().await;
    for groups in [1, 4] {
        for sequence in 0..3 {
            fixture.prepare(groups, sequence);
            let pointer = fixture.output.groups.as_ptr();
            let capacity = fixture.output.groups.capacity();
            let (sent, _, _) = fixture.send(baseline).await;
            assert_eq!(sent, groups);
            assert_eq!(
                fixture.output.groups.as_ptr(),
                pointer,
                "nonempty turn must retain its buffer"
            );
            assert_eq!(fixture.output.groups.capacity(), capacity);
            fixture.verify(groups, sequence).await;
        }
    }
    let pointer = fixture.output.groups.as_ptr();
    let (sent, counts, _) = fixture.send(false).await;
    assert_eq!(sent, 0);
    assert_eq!(
        counts.allocations, 0,
        "empty output turns remain allocation-free"
    );
    assert_eq!(fixture.output.groups.as_ptr(), pointer);
    fixture.stop().await;
}

#[tokio::test]
async fn transport_turn_cancellation_consumes_remaining_groups_without_replay() {
    use tokio::io::AsyncReadExt;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let remote = TransportAddr::from_string(&listener.local_addr().unwrap().to_string());
    let id = TransportId::new(982);
    let (tx, _rx) = crate::transport::packet_channel(4);
    let mut transport = TransportHandle::Tcp(crate::transport::tcp::TcpTransport::new(
        id,
        None,
        crate::config::TcpConfig::default(),
        tx,
    ));
    transport.start().await.unwrap();
    transport.send(&remote, &[0; 32]).await.unwrap();
    let (mut stream, _) = listener.accept().await.unwrap();
    let mut primer = [0; 32];
    stream.read_exact(&mut primer).await.unwrap();
    let mut blocked = Box::pin(match &transport {
        TransportHandle::Tcp(tcp) => tcp.test_block_writes(&remote),
        _ => unreachable!(),
    });
    assert!(futures::poll!(blocked.as_mut()).is_pending());
    let mut transports = HashMap::from([(id, transport)]);
    let mut output = DataplaneTransportSendGroups::new();
    for counter in 0..3 {
        output.groups.push(DataplaneTransportPlanGroup::new(
            id,
            remote.clone(),
            transport_output(
                fmp_owner(982),
                counter,
                counter,
                id,
                remote.clone(),
                vec![0; 32],
            ),
        ));
    }
    let pointer = output.groups.as_ptr();
    let capacity = output.groups.capacity();
    let mut drops = Vec::new();
    let mut receipts = Vec::new();
    let mut send = Box::pin(dispatch(
        &mut output,
        &transports,
        &mut drops,
        &mut receipts,
        false,
    ));
    assert!(futures::poll!(send.as_mut()).is_pending());
    drop(send);
    assert!(output.groups.is_empty());
    assert_eq!(output.groups.as_ptr(), pointer);
    assert_eq!(output.groups.capacity(), capacity);
    assert!(drops.is_empty());
    assert!(
        receipts.is_empty(),
        "cancelled send must not invent terminal success"
    );
    drop(blocked);

    let mut fresh = vec![0; 32];
    fresh[8] = 99;
    output.push_transport(
        id,
        remote.clone(),
        transport_output(fmp_owner(982), 99, 99, id, remote.clone(), fresh.clone()),
    );
    assert_eq!(
        dispatch(&mut output, &transports, &mut drops, &mut receipts, false).await,
        1
    );
    let mut received = [0; 32];
    tokio::time::timeout(Duration::from_secs(1), stream.read_exact(&mut received))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        received.as_slice(),
        fresh.as_slice(),
        "only the new turn may reach the stream"
    );
    assert_eq!(receipts.len(), 1);
    assert_eq!(receipts[0].counter, 99);
    assert!(drops.is_empty());
    transports.get_mut(&id).unwrap().stop().await.unwrap();
}

#[tokio::test]
#[ignore = "bounded same-process allocation/latency qualification"]
async fn transport_turn_paired_allocation_benchmark() {
    let mut fixture = UdpTurns::new().await;
    for groups in [1, 4] {
        for baseline in [true, false] {
            for sequence in 0..16 {
                fixture.prepare(groups, sequence);
                fixture.send(baseline).await;
                fixture.verify(groups, sequence).await;
            }
        }
        for pair in 0..7 {
            let mut allocations = [0; 2];
            for baseline in if pair % 2 == 0 {
                [true, false]
            } else {
                [false, true]
            } {
                let mut counts = Counts::default();
                let mut elapsed = 0;
                for sequence in 0..256 {
                    fixture.prepare(groups, sequence);
                    let (sent, sample, nanos) = fixture.send(baseline).await;
                    assert_eq!(sent, groups);
                    counts.allocations += sample.allocations;
                    counts.bytes += sample.bytes;
                    counts.frees += sample.frees;
                    elapsed += nanos;
                    fixture.verify(groups, sequence).await;
                }
                allocations[usize::from(!baseline)] = counts.allocations;
                println!(
                    "TURN_ALLOCATION {{\"case\":\"udp_output\",\"groups\":{groups},\"pair\":{pair},\"baseline\":{baseline},\"turns\":256,\"allocations\":{},\"bytes\":{},\"frees\":{},\"nanos\":{elapsed}}}",
                    counts.allocations, counts.bytes, counts.frees
                );
            }
            assert_eq!(
                allocations[0],
                allocations[1] + 256,
                "one outer allocation removed per nonempty turn"
            );
        }
    }
    fixture.stop().await;
}
