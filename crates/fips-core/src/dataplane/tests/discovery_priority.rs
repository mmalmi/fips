use super::*;
use crate::proto::stp::TreeCoordinate;
use crate::protocol::{LookupRequest, LookupResponse};
use sha2::Digest;

const KEY: u8 = 42;
const RECEIVER: u32 = 5050;

fn messages() -> Vec<Vec<u8>> {
    let target = test_node_addr(50);
    let origin = test_node_addr(51);
    let secp = secp256k1::Secp256k1::new();
    let secret = secp256k1::SecretKey::from_byte_array(&[1; 32]).unwrap();
    let keypair = secp256k1::Keypair::from_secret_key(&secp, &secret);
    [1, 6]
        .into_iter()
        .flat_map(|depth| {
            let coords =
                TreeCoordinate::from_addrs((0..depth).map(|i| test_node_addr(50 + i)).collect())
                    .unwrap();
            let proof: [u8; 32] =
                sha2::Sha256::digest(LookupResponse::proof_bytes(999, &target, &coords)).into();
            [
                LookupRequest::new(999, target, origin, coords.clone(), 5, 1386).encode(),
                LookupResponse::new(999, target, coords, secp.sign_schnorr(&proof, &keypair))
                    .encode(),
            ]
        })
        .collect()
}

// Exercise the sender's actual timestamp prefix and AEAD, not a hand-built header.
fn sealed(message: &[u8]) -> Vec<u8> {
    let owner = fmp_owner(50);
    let mut sender = mover();
    sender.register_owner(
        owner,
        OwnerConfig::new(13, 8)
            .with_next_send_counter(5000)
            .with_fmp_session_start_ms(1000),
    );
    sender
        .owner_mut(owner)
        .unwrap()
        .set_crypto_keys(OwnerCryptoKeys::new(test_key(KEY), test_key(KEY)));
    sender
        .submit_outbound_packet(
            OutboundPacket::fmp(
                owner,
                13,
                PacketClass::Control,
                RECEIVER,
                0,
                PacketBuffer::new(message.to_vec()),
            )
            .with_activity_tick(ActivityTick::new(1234)),
        )
        .unwrap();
    let turn = run_aead_available(&mut sender, 8);
    assert!(turn.drops().is_empty());
    let output = turn.outputs()[0];
    assert_eq!(output.fmp_timestamp_ms, Some(234));
    let mut plaintext = 234u32.to_le_bytes().to_vec();
    plaintext.extend_from_slice(message);
    assert_eq!(open_sealed_output(output, KEY), plaintext);
    output.payload.as_slice().to_vec()
}

fn received(wire: Vec<u8>) -> ReceivedPacket {
    ReceivedPacket::with_timestamp(
        TransportId::new(50),
        TransportAddr::from_string("198.51.100.50:9000"),
        PacketBuffer::new(wire),
        50_000,
    )
}

fn routes() -> DataplaneLiveRouteTable {
    let mut routes = DataplaneLiveRouteTable::default();
    routes.register_fmp(
        TransportId::new(50),
        RECEIVER,
        DataplaneIngressRoute::new(fmp_owner(50), 13, OutputTarget::Transport)
            .with_class(PacketClass::Bulk),
    );
    routes
}

fn assert_authenticated_priority(packet: SocketPacket, message: &[u8], forged: bool) {
    assert_eq!(packet.class, PacketClass::Control);
    assert_eq!(packet.lane(), Lane::Priority);
    let owner = fmp_owner(50);
    let mut receiver = Dataplane::new(AdmissionConfig::new(1, 1));
    receiver.register_owner(owner, OwnerConfig::new(13, 8));
    receiver
        .owner_mut(owner)
        .unwrap()
        .set_crypto_keys(OwnerCryptoKeys::new(test_key(KEY), test_key(KEY)));
    receiver
        .submit_socket_packet(encrypted_fmp_packet(
            owner,
            13,
            5001,
            PacketClass::Bulk,
            OutputTarget::Transport,
            KEY,
        ))
        .unwrap();
    // Bulk capacity is already exhausted; control still admits and runs first.
    receiver.submit_socket_packet(packet).unwrap();
    let turn = run_aead_available(&mut receiver, 1);
    if forged {
        assert!(turn.outputs().is_empty());
        assert_eq!(turn.drops()[0].reason, PacketDropReason::CryptoFailed);
    } else {
        assert!(turn.drops().is_empty());
        assert_eq!(turn.outputs().len(), 1);
        let output = turn.outputs()[0];
        assert_eq!(output.counter, 5000);
        let mut plaintext = 234u32.to_le_bytes().to_vec();
        plaintext.extend_from_slice(message);
        assert_eq!(
            &output.payload.as_slice()[usize::from(output.opened_payload_offset)..],
            plaintext,
        );
    }
}

#[test]
fn scalar_transport_preserves_real_discovery_when_bulk_is_full() {
    for message in messages() {
        let wire = sealed(&message);
        let (tx, mut rx) = crate::transport::packet_channel(1);
        tx.send(received(vec![0xff; 512])).unwrap();
        tx.send(received(wire.clone())).unwrap();
        assert_eq!(rx.priority_ready_packets(), 1);
        assert_eq!(rx.try_recv().unwrap().data.as_slice(), wire);
        assert_eq!(rx.try_recv().unwrap().data.as_slice(), vec![0xff; 512]);
        assert!(rx.try_recv().is_err());
    }
}

#[test]
fn scalar_raw_discovery_keeps_priority_and_requires_authentication() {
    for message in messages() {
        for forged in [false, true] {
            let mut wire = sealed(&message);
            if forged {
                *wire.last_mut().unwrap() ^= 1;
            }
            let mut drops = Vec::new();
            let packet = DataplaneTurnDriver::raw_ingress_socket_packet(
                DataplaneRawIngress::from_live_received(PacketProtocol::Fmp, received(wire)),
                &mut routes(),
                &mut DataplaneRuntimeSummary::default(),
                &mut drops,
                &mut std::collections::VecDeque::new(),
                None,
            )
            .unwrap();
            assert!(drops.is_empty());
            assert_authenticated_priority(packet, &message, forged);
        }
    }
}

#[test]
fn batch_discovery_keeps_priority_and_requires_authentication() {
    for message in messages() {
        for forged in [false, true] {
            let mut wire = sealed(&message);
            if forged {
                *wire.last_mut().unwrap() ^= 1;
            }
            let (sink, mut rx) = DataplaneEstablishedFastIngressSink::channel(
                routes().established_fast_ingress_snapshot(),
                4,
            );
            let mut packets = vec![received(wire)];
            assert_eq!(sink.try_ingest_batch(&mut packets), 1);
            let mut runs = rx.try_recv().unwrap().into_runs();
            let (_, lane, mut packets) = runs.pop().unwrap().into_parts();
            assert_eq!(lane, Lane::Priority);
            assert_authenticated_priority(packets.pop().unwrap(), &message, forged);
        }
    }
}

#[test]
fn discovery_wire_shape_requires_timestamp_and_nonempty_coordinates() {
    for length in [46 + 16, 93 + 16, 50, 97, 50 + 15, 97 + 2] {
        let header = build_fmp_established_header(RECEIVER, 5000, 0, length);
        assert_ne!(
            FmpWireHeader::parse(&header)
                .unwrap()
                .visible_priority_class(),
            Some(PacketClass::Control),
            "invalid discovery plaintext length {length}",
        );
    }
}
