use super::*;
use crate::node::wire::{Msg1Header, build_msg1};
use futures::SinkExt;
use spanning_tree::process_dataplane_packet;
use tokio_tungstenite::tungstenite::Message;

#[tokio::test]
async fn captured_msg1_on_a_fresh_carrier_cannot_displace_usable_keys() {
    let server = make_websocket_node(WebSocketConfig {
        bind_addr: Some("127.0.0.1:0".into()),
        ..Default::default()
    })
    .await;
    let client = make_websocket_node(WebSocketConfig {
        seed_urls: vec![server.addr.to_string()],
        ..Default::default()
    })
    .await;
    let mut nodes = vec![server, client];
    let server_addr = *nodes[0].node.node_addr();
    let client_addr = *nodes[1].node.node_addr();
    let mut captured = None;

    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            for node in &mut nodes {
                node.node.poll_transport_discovery().await;
            }
            run_synthetic_node_work(&mut nodes).await;
            while let Ok(packet) = nodes[0].packet_rx.try_recv() {
                if captured.is_none() && Msg1Header::parse(packet.data.as_slice()).is_some() {
                    captured = Some(packet.data.as_slice().to_vec());
                }
                process_dataplane_packet(&mut nodes[0], packet).await;
            }
            process_available_packets(&mut nodes[1..]).await;
            if nodes[1].node.get_peer(&server_addr).is_some()
                && nodes[0]
                    .node
                    .dataplane_fmp_link_metrics(&client_addr, std::time::Instant::now())
                    .is_some_and(|metrics| metrics.current_epoch_authenticated)
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("the original carrier must carry authenticated current-epoch traffic");

    let original = captured.expect("capture the genuine initial Noise Msg1");
    let header = Msg1Header::parse(&original).unwrap();
    let peer = nodes[0].node.get_peer(&client_addr).unwrap();
    assert!(peer.is_healthy());
    let retained = (
        peer.link_id(),
        peer.our_index(),
        peer.their_index(),
        peer.current_addr().cloned(),
    );

    // Neither a byte-for-byte retransmission nor an altered unauthenticated
    // sender index proves that the holder of captured Msg1 knows its keys.
    for sender_index in [
        header.sender_idx,
        SessionIndex::new(header.sender_idx.as_u32().wrapping_add(1).max(1)),
    ] {
        let replay = build_msg1(sender_index, header.noise_msg1(&original));
        let (mut carrier, _) = tokio_tungstenite::connect_async(nodes[0].addr.to_string())
            .await
            .unwrap();
        carrier
            .send(Message::Binary(replay.clone().into()))
            .await
            .unwrap();
        tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                let packet = nodes[0].packet_rx.recv().await.unwrap();
                let is_replay = packet.data.as_slice() == replay.as_slice();
                if is_replay {
                    assert_ne!(Some(&packet.remote_addr), retained.3.as_ref());
                }
                process_dataplane_packet(&mut nodes[0], packet).await;
                if is_replay {
                    break;
                }
            }
        })
        .await
        .expect("the fresh physical carrier must deliver the replay to the real receive path");
        let peer = nodes[0].node.get_peer(&client_addr).unwrap();
        assert_eq!(
            (
                peer.link_id(),
                peer.our_index(),
                peer.their_index(),
                peer.current_addr().cloned()
            ),
            retained,
            "captured Noise Msg1 with sender index {sender_index} must preserve the usable owner"
        );
        assert!(peer.pending_new_session().is_none());
        carrier.close(None).await.unwrap();
    }

    populate_all_coord_caches(&mut nodes);
    let mut endpoints = nodes
        .iter_mut()
        .map(|node| node.node.attach_endpoint_data_io(8).unwrap())
        .collect::<Vec<_>>();
    for sender in 0..2 {
        let receiver = 1 - sender;
        let identity =
            PeerIdentity::from_pubkey_full(nodes[receiver].node.identity().pubkey_full());
        let payload = vec![sender as u8, 0xA5];
        super::super::session::send_endpoint_data_via_dataplane(
            &mut nodes[sender].node,
            identity,
            payload.clone(),
        )
        .await
        .unwrap();
        let event = super::super::session::recv_endpoint_event_while_draining(
            &mut nodes,
            &mut endpoints[receiver].event_rx,
            Duration::from_secs(2),
            "the original carrier must remain usable after captured Msg1 replay",
        )
        .await;
        assert_eq!(
            super::super::session::expect_single_endpoint_data_event(event)
                .payload
                .as_slice(),
            payload
        );
    }
    cleanup_nodes(&mut nodes).await;
}
