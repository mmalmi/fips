use super::super::*;
use crate::config::SimTransportConfig;
use crate::{SimNetwork, SimTransport, register_sim_network, unregister_sim_network};

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
