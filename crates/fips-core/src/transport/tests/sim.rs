use super::super::*;
use crate::config::SimTransportConfig;
use crate::{SimNetwork, SimTransport, register_sim_network, unregister_sim_network};

async fn discovering_transport(
    network: &str,
    addr: &str,
    id: u32,
    pubkey: Option<secp256k1::XOnlyPublicKey>,
) -> (SimTransport, PacketRx) {
    let (tx, rx) = packet_channel(4);
    let mut transport = SimTransport::new(
        TransportId::new(id),
        None,
        SimTransportConfig {
            network: Some(network.to_string()),
            addr: Some(addr.to_string()),
            ..Default::default()
        },
        tx,
    );
    if let Some(pubkey) = pubkey {
        transport.set_local_pubkey(pubkey);
    }
    transport.start_async().await.unwrap();
    (transport, rx)
}

fn discovery_addresses(transport: &SimTransport) -> Vec<String> {
    transport
        .discover()
        .unwrap()
        .iter()
        .map(|peer| peer.addr.as_str().unwrap().to_string())
        .collect()
}

#[tokio::test]
async fn sim_discovery_excludes_indirect_down_unregistered_and_unidentified_endpoints() {
    let name = format!("visible-sim-discovery-{}", std::process::id());
    let network = SimNetwork::new(2);
    network.set_default_link(crate::SimLink {
        up: false,
        ..Default::default()
    });
    for (a, b) in [
        ("a", "b"),
        ("b", "c"),
        ("a", "anonymous"),
        ("a", "unregistered"),
    ] {
        network.set_link(a, b, crate::SimLink::default());
    }
    register_sim_network(name.clone(), network.clone());
    let mut nodes = Vec::new();
    let identities = (0..4)
        .map(|_| crate::Identity::generate())
        .collect::<Vec<_>>();
    for (i, addr) in ["a", "b", "c", "down"].into_iter().enumerate() {
        nodes.push(
            discovering_transport(&name, addr, i as u32 + 1, Some(identities[i].pubkey())).await,
        );
    }
    nodes.push(discovering_transport(&name, "anonymous", 5, None).await);
    let peers = nodes[0].0.discover().unwrap();
    assert_eq!(peers.len(), 1);
    assert_eq!(peers[0].addr.as_str(), Some("b"));
    assert_eq!(peers[0].transport_id, nodes[0].0.transport_id());
    assert_eq!(peers[0].pubkey_hint, Some(identities[1].pubkey()));
    network.set_link_up("a", "b", false);
    assert!(nodes[0].0.discover().unwrap().is_empty());
    network.set_link_up("a", "b", true);
    assert_eq!(discovery_addresses(&nodes[0].0), ["b"]);
    network.set_node_up("b", false);
    assert!(nodes[0].0.discover().unwrap().is_empty());
    network.set_node_up("b", true);
    network.set_node_up("a", false);
    assert!(nodes[0].0.discover().unwrap().is_empty());
    network.set_node_up("a", true);
    nodes[1].0.stop_async().await.unwrap();
    assert!(nodes[0].0.discover().unwrap().is_empty());
    for (transport, _) in &mut nodes {
        if transport.state().is_operational() {
            transport.stop_async().await.unwrap();
        }
        assert!(transport.discover().unwrap().is_empty());
    }
    unregister_sim_network(&name);
}

#[tokio::test]
async fn sim_discovery_uses_incoming_visibility_without_stochastic_draws_or_packet_accounting() {
    let name = format!("directed-sim-discovery-{}", std::process::id());
    let network = SimNetwork::new(3);
    register_sim_network(name.clone(), network.clone());
    let (mut a, _a_rx) =
        discovering_transport(&name, "a", 1, Some(crate::Identity::generate().pubkey())).await;
    let (mut b, _b_rx) =
        discovering_transport(&name, "b", 2, Some(crate::Identity::generate().pubkey())).await;
    network.set_directed_link(
        "a",
        "b",
        Some(crate::SimLink {
            up: false,
            ..Default::default()
        }),
    );
    assert_eq!(
        discovery_addresses(&a),
        ["b"],
        "hearing a neighbor does not prove a return path"
    );
    assert!(b.discover().unwrap().is_empty());
    network.set_directed_link(
        "b",
        "a",
        Some(crate::SimLink {
            loss_probability: 1.0,
            ..Default::default()
        }),
    );
    assert!(a.discover().unwrap().is_empty());
    network.set_directed_link(
        "b",
        "a",
        Some(crate::SimLink {
            loss_probability: 0.99,
            ..Default::default()
        }),
    );
    network.set_node_egress_loss("a", 1.0);
    for _ in 0..20 {
        assert_eq!(
            discovery_addresses(&a),
            ["b"],
            "fractional loss models eventual visibility"
        );
    }
    network.set_node_egress_loss("b", 1.0);
    assert!(a.discover().unwrap().is_empty());
    network.set_node_egress_loss("b", 0.5);
    assert_eq!(discovery_addresses(&a), ["b"]);
    assert_eq!(network.stats().packets_sent, 0);
    assert_eq!(network.stats().bytes_sent, 0);
    a.stop_async().await.unwrap();
    b.stop_async().await.unwrap();
    unregister_sim_network(&name);
}

#[tokio::test]
async fn sim_discovery_rotates_bounded_sorted_batches_without_starving_late_addresses() {
    use crate::transport::sim::MAX_DISCOVERED_PEERS_PER_POLL as CAP;

    let name = format!("bounded-sim-discovery-{}", std::process::id());
    register_sim_network(name.clone(), SimNetwork::new(4));
    let (mut local, _rx) = discovering_transport(
        &name,
        "local",
        1,
        Some(crate::Identity::generate().pubkey()),
    )
    .await;
    let key = crate::Identity::generate().pubkey();
    let mut neighbors = Vec::new();
    for i in (0..CAP + 5).rev() {
        neighbors.push(
            discovering_transport(&name, &format!("peer-{i:03}"), i as u32 + 2, Some(key)).await,
        );
    }
    let first = discovery_addresses(&local);
    let second = discovery_addresses(&local);
    assert_eq!(
        first,
        (0..CAP).map(|i| format!("peer-{i:03}")).collect::<Vec<_>>()
    );
    assert_eq!(second.len(), CAP);
    assert_eq!(
        &second[..5],
        (CAP..CAP + 5)
            .map(|i| format!("peer-{i:03}"))
            .collect::<Vec<_>>()
    );
    assert_eq!(
        first
            .iter()
            .chain(&second)
            .collect::<std::collections::BTreeSet<_>>()
            .len(),
        CAP + 5
    );
    local.stop_async().await.unwrap();
    for (neighbor, _) in &mut neighbors {
        neighbor.stop_async().await.unwrap();
    }
    unregister_sim_network(&name);
}

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
