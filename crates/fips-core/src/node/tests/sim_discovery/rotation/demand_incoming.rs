//! Queued first contact also wakes when the destination initiates the link.
use super::*;

#[test]
fn incoming_destination_wakes_endpoint_without_periodic_maintenance() {
    run_incoming(false);
}

#[test]
fn incoming_destination_wakes_tun_without_periodic_maintenance() {
    run_incoming(true);
}

fn run_incoming(tun: bool) {
    run_large_stack_async_test("incoming-queued-demand", move || async move {
        let _guard = spanning_tree::lock_large_network_test().await;
        let name = format!("incoming-queued-demand-{}-{tun}", std::process::id());
        let network = SimNetwork::new(98);
        network.set_default_link(SimLink {
            up: false,
            ..Default::default()
        });
        register_sim_network(name.clone(), network.clone());
        let mut nodes = vec![
            discovering_node(&name, "sender", false).await,
            discovering_node(&name, "destination", true).await,
        ];
        let result = AssertUnwindSafe(exercise_incoming(&mut nodes, &network, tun))
            .catch_unwind()
            .await;
        cleanup_nodes(&mut nodes).await;
        unregister_sim_network(&name);
        if let Err(panic) = result {
            std::panic::resume_unwind(panic);
        }
    });
}

async fn exercise_incoming(nodes: &mut [TestNode], network: &SimNetwork, tun: bool) {
    let source = *nodes[0].node.node_addr();
    let remote = PeerIdentity::from_pubkey_full(nodes[1].node.identity().pubkey_full());
    let destination = *remote.node_addr();
    let _source_endpoint = nodes[0].node.attach_endpoint_data_io(8).unwrap();
    let mut receiver = nodes[1].node.attach_endpoint_data_io(8).unwrap();
    let (tun_tx, tun_rx) = crate::upper::tun::write_channel();
    nodes[1].node.tun_tx = Some(tun_tx);
    let payload = if tun {
        nodes[0]
            .node
            .register_identity(destination, remote.pubkey_full());
        build_ipv6_packet(
            &crate::FipsAddress::from_node_addr(&source),
            &crate::FipsAddress::from_node_addr(&destination),
            PAYLOAD,
        )
    } else {
        PAYLOAD.to_vec()
    };
    if tun {
        send_tun_packet_via_dataplane(nodes, 0, payload.clone()).await;
    } else {
        send_endpoint_data_via_dataplane(&mut nodes[0].node, remote, payload.clone())
            .await
            .unwrap();
    }
    assert_eq!(queued(&nodes[0].node, &destination, tun), 1);
    assert!(nodes[0].node.pending_lookups.contains_key(&destination));
    assert!(nodes[0].node.get_session(&destination).is_none());
    network.set_link("sender", "destination", SimLink::default());
    nodes[1].node.poll_transport_discovery().await;
    assert_eq!(nodes[0].node.connection_count(), 0);
    assert!(
        nodes[1]
            .node
            .peers
            .connection_values()
            .next()
            .unwrap()
            .is_outbound()
    );
    let offered = Instant::now();
    while !receive(&mut receiver, &tun_rx, tun, &source, &payload) {
        events_only(nodes, None).await;
        assert!(
            offered.elapsed() < Duration::from_secs(5),
            "incoming queued delivery"
        );
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    assert!(reciprocal_direct(nodes, 1));
    assert_eq!(queued(&nodes[0].node, &destination, tun), 0);
    assert!(!nodes[0].node.pending_lookups.contains_key(&destination));
    assert_eq!(nodes[0].node.stats().discovery.req_initiated, 0);
    let duplicate_deadline = Instant::now() + Duration::from_millis(200);
    while Instant::now() < duplicate_deadline {
        events_only(nodes, None).await;
        assert!(!receive(&mut receiver, &tun_rx, tun, &source, &payload));
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    eprintln!(
        "incoming queued delivery: {}",
        serde_json::json!({
            "tun":tun, "periodic_maintenance":0, "lookup_requests":0, "delivered":1
        })
    );
}
