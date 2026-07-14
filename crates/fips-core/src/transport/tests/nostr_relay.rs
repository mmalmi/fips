use crate::config::NostrRelayConfig;
use crate::transport::nostr_relay::{NOSTR_RELAY_DATAGRAM_KIND, NostrRelayTransport};
use crate::transport::{PacketRx, TransportAddr, TransportId, packet_channel};
use crate::{Identity, Transport, encode_npub};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use nostr::{EventBuilder, Kind, PublicKey, Tag};

async fn recv_packet(rx: &mut PacketRx) -> crate::ReceivedPacket {
    rx.recv().await.expect("Nostr relay transport packet")
}

#[tokio::test]
async fn encrypted_fips_datagram_roundtrips_as_targeted_ephemeral_event() {
    let alice = Identity::generate();
    let bob = Identity::generate();
    let (alice_tx, _alice_rx) = packet_channel(8);
    let (bob_tx, mut bob_rx) = packet_channel(8);
    let mut alice_transport = NostrRelayTransport::new(
        TransportId::new(1),
        None,
        NostrRelayConfig::default(),
        alice_tx,
        &alice,
    )
    .expect("alice Nostr relay transport");
    let mut bob_transport = NostrRelayTransport::new(
        TransportId::new(2),
        None,
        NostrRelayConfig::default(),
        bob_tx,
        &bob,
    )
    .expect("bob Nostr relay transport");
    alice_transport.start().expect("start alice transport");
    bob_transport.start().expect("start bob transport");

    let bob_npub = encode_npub(&bob.pubkey());
    let ciphertext = vec![0x01, 0x80, 0xff, 0x00, 0x42];
    alice_transport
        .send(&TransportAddr::from(bob_npub), &ciphertext)
        .expect("queue relay datagram");

    let events = alice_transport.drain_outbound_events(8);
    assert_eq!(events.len(), 1);
    let event = &events[0];
    assert_eq!(u16::from(event.kind), NOSTR_RELAY_DATAGRAM_KIND);
    let bob_nostr_pubkey =
        nostr::PublicKey::from_slice(&bob.pubkey().serialize()).expect("bob Nostr public key");
    assert!(
        event
            .tags
            .public_keys()
            .any(|pubkey| pubkey == &bob_nostr_pubkey)
    );
    assert!(!event.content.contains('='), "wire content is unpadded");

    assert!(
        bob_transport
            .ingest_event(event.clone())
            .expect("ingest event")
    );
    let packet = recv_packet(&mut bob_rx).await;
    assert_eq!(packet.transport_id, TransportId::new(2));
    let alice_hex = hex::encode(alice.pubkey().serialize());
    assert_eq!(packet.remote_addr.as_str(), Some(alice_hex.as_str()));
    assert_eq!(packet.data.as_slice(), ciphertext);
}

#[test]
fn relay_datagram_rejects_events_for_another_recipient() {
    let alice = Identity::generate();
    let bob = Identity::generate();
    let carol = Identity::generate();
    let (alice_tx, _alice_rx) = packet_channel(8);
    let (bob_tx, _bob_rx) = packet_channel(8);
    let mut alice_transport = NostrRelayTransport::new(
        TransportId::new(1),
        None,
        NostrRelayConfig::default(),
        alice_tx,
        &alice,
    )
    .expect("alice Nostr relay transport");
    let mut bob_transport = NostrRelayTransport::new(
        TransportId::new(2),
        None,
        NostrRelayConfig::default(),
        bob_tx,
        &bob,
    )
    .expect("bob Nostr relay transport");
    alice_transport.start().expect("start alice transport");
    bob_transport.start().expect("start bob transport");

    alice_transport
        .send(
            &TransportAddr::from(hex::encode(carol.pubkey().serialize())),
            &[0x13, 0x37],
        )
        .expect("queue event for carol");
    let event = alice_transport
        .drain_outbound_events(1)
        .pop()
        .expect("outbound event");
    assert!(!bob_transport.ingest_event(event).expect("reject event"));
}

#[test]
fn relay_datagram_requires_exactly_one_recipient() {
    let alice = Identity::generate();
    let bob = Identity::generate();
    let carol = Identity::generate();
    let (bob_tx, _bob_rx) = packet_channel(8);
    let mut bob_transport = NostrRelayTransport::new(
        TransportId::new(2),
        None,
        NostrRelayConfig::default(),
        bob_tx,
        &bob,
    )
    .expect("bob Nostr relay transport");
    bob_transport.start().expect("start bob transport");

    let alice_keys =
        nostr::Keys::parse(&hex::encode(alice.keypair().secret_bytes())).expect("alice Nostr keys");
    let bob_pubkey = PublicKey::from_slice(&bob.pubkey().serialize()).expect("bob public key");
    let carol_pubkey =
        PublicKey::from_slice(&carol.pubkey().serialize()).expect("carol public key");
    let event = EventBuilder::new(
        Kind::Custom(NOSTR_RELAY_DATAGRAM_KIND),
        URL_SAFE_NO_PAD.encode([0x13, 0x37]),
    )
    .tags([Tag::public_key(bob_pubkey), Tag::public_key(carol_pubkey)])
    .sign_with_keys(&alice_keys)
    .expect("signed multi-recipient event");

    assert!(!bob_transport.ingest_event(event).expect("reject event"));
}

#[test]
fn relay_datagram_rejects_stale_invalid_and_oversized_content() {
    let alice = Identity::generate();
    let bob = Identity::generate();
    let (bob_tx, _bob_rx) = packet_channel(8);
    let mut bob_transport = NostrRelayTransport::new(
        TransportId::new(2),
        None,
        NostrRelayConfig {
            mtu: Some(4),
            ..Default::default()
        },
        bob_tx,
        &bob,
    )
    .expect("bob Nostr relay transport");
    bob_transport.start().expect("start bob transport");

    let alice_keys =
        nostr::Keys::parse(&hex::encode(alice.keypair().secret_bytes())).expect("alice Nostr keys");
    let bob_pubkey = PublicKey::from_slice(&bob.pubkey().serialize()).expect("bob public key");
    let stale = EventBuilder::new(
        Kind::Custom(NOSTR_RELAY_DATAGRAM_KIND),
        URL_SAFE_NO_PAD.encode([1, 2, 3, 4]),
    )
    .tag(Tag::public_key(bob_pubkey))
    .custom_created_at(nostr::Timestamp::from(
        nostr::Timestamp::now().as_secs().saturating_sub(61),
    ))
    .sign_with_keys(&alice_keys)
    .expect("signed stale event");
    assert!(!bob_transport.ingest_event(stale).expect("reject stale"));

    let invalid_content = EventBuilder::new(Kind::Custom(NOSTR_RELAY_DATAGRAM_KIND), "***")
        .tag(Tag::public_key(bob_pubkey))
        .sign_with_keys(&alice_keys)
        .expect("signed invalid content event");
    assert!(bob_transport.ingest_event(invalid_content).is_err());

    let oversized = EventBuilder::new(
        Kind::Custom(NOSTR_RELAY_DATAGRAM_KIND),
        URL_SAFE_NO_PAD.encode([1, 2, 3, 4, 5]),
    )
    .tag(Tag::public_key(bob_pubkey))
    .sign_with_keys(&alice_keys)
    .expect("signed oversized event");
    assert!(
        !bob_transport
            .ingest_event(oversized)
            .expect("reject oversized")
    );
}
