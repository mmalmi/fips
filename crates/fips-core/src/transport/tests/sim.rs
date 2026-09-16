use super::super::*;
use crate::config::SimTransportConfig;
use crate::{SimNetwork, SimTransport, register_sim_network, unregister_sim_network};

#[tokio::test(start_paused = true)]
async fn directional_sim_impairments_preserve_reverse_delivery_and_can_be_removed() {
    let name = format!("directional-sim-{}", std::process::id());
    let network = SimNetwork::new(7);
    register_sim_network(name.clone(), network.clone());
    let mut endpoints = Vec::new();
    for (id, addr) in [(1, "a"), (2, "b")] {
        let (tx, rx) = packet_channel(4);
        let mut transport = SimTransport::new(
            TransportId::new(id),
            None,
            SimTransportConfig {
                network: Some(name.clone()),
                addr: Some(addr.into()),
                ..Default::default()
            },
            tx,
        );
        transport.start_async().await.unwrap();
        endpoints.push((transport, rx));
    }
    let (left, right) = endpoints.split_at_mut(1);
    let ((a, a_rx), (b, b_rx)) = (&mut left[0], &mut right[0]);
    let a_addr = TransportAddr::from_string("a");
    let b_addr = TransportAddr::from_string("b");
    network.set_directed_link(
        "a",
        "b",
        Some(crate::SimLink {
            latency_ms: 100,
            ..Default::default()
        }),
    );
    let start = tokio::time::Instant::now();
    a.send_async(&b_addr, b"slow").await.unwrap();
    b.send_async(&a_addr, b"fast").await.unwrap();
    assert_eq!(a_rx.recv().await.unwrap().data.as_slice(), b"fast");
    assert!(start.elapsed() < Duration::from_millis(100));
    assert_eq!(b_rx.recv().await.unwrap().data.as_slice(), b"slow");
    assert!(start.elapsed() >= Duration::from_millis(100));

    network.set_directed_link(
        "a",
        "b",
        Some(crate::SimLink {
            loss_probability: 1.0,
            ..Default::default()
        }),
    );
    a.send_async(&b_addr, b"lost").await.unwrap();
    b.send_async(&a_addr, b"return").await.unwrap();
    assert_eq!(a_rx.recv().await.unwrap().data.as_slice(), b"return");
    assert!(b_rx.try_recv().is_err());
    assert_eq!(network.stats().packets_dropped_loss, 1);

    network.set_directed_link("a", "b", None);
    a.send_async(&b_addr, b"restored").await.unwrap();
    assert_eq!(b_rx.recv().await.unwrap().data.as_slice(), b"restored");
    a.stop_async().await.unwrap();
    b.stop_async().await.unwrap();
    unregister_sim_network(&name);
}

#[tokio::test]
async fn duplicate_sim_endpoint_registration_fails_without_replacing_owner() {
    let network_name = format!("duplicate-sim-endpoint-{}", std::process::id());
    register_sim_network(network_name.clone(), SimNetwork::new(1));

    let make_transport = |id: u32, addr: &str, packet_tx: PacketTx| {
        SimTransport::new(
            TransportId::new(id),
            None,
            SimTransportConfig {
                network: Some(network_name.clone()),
                addr: Some(addr.to_string()),
                ..Default::default()
            },
            packet_tx,
        )
    };
    let (first_tx, mut first_rx) = packet_channel(4);
    let (duplicate_tx, mut duplicate_rx) = packet_channel(4);
    let (sender_tx, _sender_rx) = packet_channel(4);
    let mut first = make_transport(1, "shared", first_tx);
    let mut duplicate = make_transport(2, "shared", duplicate_tx);
    let mut sender = make_transport(3, "sender", sender_tx);

    first.start_async().await.unwrap();
    let error = duplicate.start_async().await.unwrap_err();
    assert!(
        matches!(error, TransportError::StartFailed(message) if message.contains("already registered"))
    );
    sender.start_async().await.unwrap();
    sender
        .send_async(&TransportAddr::from_string("shared"), b"original")
        .await
        .unwrap();

    let packet = tokio::time::timeout(Duration::from_secs(1), first_rx.recv())
        .await
        .expect("original endpoint should receive")
        .expect("original endpoint channel should remain open");
    assert_eq!(packet.data.as_slice(), b"original");
    assert!(duplicate_rx.try_recv().is_err());

    sender.stop_async().await.unwrap();
    first.stop_async().await.unwrap();
    unregister_sim_network(&network_name);
}
