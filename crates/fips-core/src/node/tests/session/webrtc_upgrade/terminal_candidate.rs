//! A terminal direct carrier must release its Noise candidate, not the WSS/FSP fallback.
use super::*;
use futures::FutureExt;
use std::panic::AssertUnwindSafe;

#[test]
fn remotely_closed_webrtc_handshake_retries_without_waiting_for_noise_timeout() {
    run(false);
}

#[test]
fn locally_closed_webrtc_handshake_retries_without_waiting_for_noise_timeout() {
    run(true);
}

fn run(local_close: bool) {
    run_large_stack_async_test("terminal-webrtc-handshake", move || async move {
        let mut nodes = vec![
            make_dual_transport_node(fixed_identity(6, 0x03)).await,
            make_dual_transport_node(fixed_identity(1, 0x02)).await,
        ];
        let result = AssertUnwindSafe(exercise(&mut nodes, local_close))
            .catch_unwind()
            .await;
        cleanup_nodes(&mut nodes).await;
        if let Err(panic) = result {
            std::panic::resume_unwind(panic);
        }
    });
}

async fn exercise(nodes: &mut [TestNode], local_close: bool) {
    configure_fallback_and_direct_paths(nodes).await;
    establish_websocket_adjacency(nodes).await;
    let identity_b = PeerIdentity::from_pubkey_full(nodes[1].node.identity().pubkey_full());
    let addr_a = identity_transport_addr(nodes[0].node.identity());
    let addr_b = identity_transport_addr(nodes[1].node.identity());
    let rtc_id = TransportId::new(WEBRTC_TRANSPORT_NUMBER);
    let mut endpoint_b = nodes[1].node.attach_endpoint_data_io(8).unwrap();
    send_endpoint_data_via_dataplane(&mut nodes[0].node, identity_b, b"before-close".to_vec())
        .await
        .unwrap();
    let _ = recv_endpoint_event_while_draining(
        nodes,
        &mut endpoint_b.event_rx,
        Duration::from_secs(5),
        "established WSS/FSP fallback",
    )
    .await;
    let fallback = nodes[0]
        .node
        .get_peer(identity_b.node_addr())
        .unwrap()
        .link_id();
    let session_created = nodes[0]
        .node
        .get_session(identity_b.node_addr())
        .unwrap()
        .created_at();
    let mut configured = nodes[0].node.config.peers.clone();
    configured[0].auto_reconnect = true;
    configured[0].connect_policy = ConnectPolicy::AutoConnect;
    nodes[0].node.update_peers(configured).await.unwrap();
    nodes[0]
        .node
        .initiate_connection(rtc_id, addr_b.clone(), identity_b)
        .await
        .unwrap();
    let recovered = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            drive_webrtc_negotiation(nodes).await;
            if physical_path_is_connected(&nodes[0].node, &addr_b)
                && physical_path_is_connected(&nodes[1].node, &addr_a)
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
    })
    .await;
    recovered.expect("actual loopback RTC channel opens over encrypted WSS signaling");
    nodes[0].node.poll_pending_connects().await;
    let (candidate, index) = nodes[0]
        .node
        .peers
        .connection_iter()
        .find(|(_, conn)| conn.transport_id() == Some(rtc_id))
        .map(|(link, conn)| {
            assert_eq!(
                conn.handshake_state(),
                crate::peer::HandshakeState::SentMsg1
            );
            (*link, conn.our_index().unwrap().as_u32())
        })
        .expect("real Noise Msg1 has been sent on RTC, without processing remote Msg2");
    let allocated = nodes[0].node.index_allocator.count();
    nodes[0].node.check_timeouts().await;
    assert!(
        nodes[0].node.peers.get_connection(&candidate).is_some(),
        "live carrier stays owned"
    );
    let (side, remote) = if local_close {
        (0, &addr_b)
    } else {
        (1, &addr_a)
    };
    nodes[side]
        .node
        .transports
        .get(&rtc_id)
        .unwrap()
        .close_connection(remote)
        .await;
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            let state = nodes[0]
                .node
                .transports
                .get(&rtc_id)
                .unwrap()
                .connection_state(&addr_b);
            if matches!(state, ConnectionState::None | ConnectionState::Failed(_)) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
    })
    .await
    .expect("checker observes actual terminal carrier state");
    nodes[0].node.check_timeouts().await;
    assert!(
        nodes[0].node.peers.get_connection(&candidate).is_none(),
        "terminal carrier releases candidate before 30-second Noise timeout"
    );
    assert!(!nodes[0].node.links.contains_key(&candidate));
    assert!(
        !nodes[0]
            .node
            .pending_outbound
            .contains_key(&(rtc_id, index))
    );
    assert_eq!(nodes[0].node.index_allocator.count(), allocated - 1);
    assert!(
        !nodes[0]
            .node
            .is_connecting_to_peer_on_path(identity_b.node_addr(), rtc_id, &addr_b)
    );
    assert_eq!(
        nodes[0]
            .node
            .get_peer(identity_b.node_addr())
            .unwrap()
            .link_id(),
        fallback
    );
    assert_eq!(
        nodes[0]
            .node
            .get_session(identity_b.node_addr())
            .unwrap()
            .created_at(),
        session_created
    );
    let retry_at = nodes[0]
        .node
        .retry_pending
        .get(identity_b.node_addr())
        .expect("existing direct-refresh retry policy is scheduled")
        .retry_after_ms;
    // Service that policy at its existing deadline; do not widen any timeout or cap.
    let delay = retry_at.saturating_sub(Node::now_ms());
    tokio::time::sleep(Duration::from_millis(delay)).await;
    nodes[0].node.process_pending_retries(Node::now_ms()).await;
    let recovered = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            drive_webrtc_negotiation(nodes).await;
            for node in nodes.iter_mut() {
                node.node.check_timeouts().await;
                node.node.poll_pending_connects().await;
                node.node.process_pending_retries(Node::now_ms()).await;
            }
            process_available_packets(nodes).await;
            if active_path_is_webrtc(&nodes[0].node, identity_b.node_addr(), &addr_b) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
    })
    .await;
    assert!(
        recovered.is_ok(),
        "fresh RTC Noise authentication completes through normal retry: left={}, right={}",
        upgrade_diagnostic(&nodes[0].node, identity_b.node_addr(), &addr_b),
        upgrade_diagnostic(&nodes[1].node, nodes[0].node.node_addr(), &addr_a)
    );
    assert_eq!(
        nodes[0]
            .node
            .get_session(identity_b.node_addr())
            .unwrap()
            .created_at(),
        session_created
    );
    send_endpoint_data_via_dataplane(&mut nodes[0].node, identity_b, b"after-close".to_vec())
        .await
        .unwrap();
    let event = recv_endpoint_event_while_draining(
        nodes,
        &mut endpoint_b.event_rx,
        Duration::from_secs(5),
        "FSP data after direct-carrier recovery",
    )
    .await;
    assert_eq!(
        expect_single_endpoint_data_event(event).payload.as_slice(),
        b"after-close"
    );
}
