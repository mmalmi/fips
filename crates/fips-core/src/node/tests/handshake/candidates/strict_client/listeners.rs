use super::*;
use crate::config::UdpConfig;
use crate::transport::{TransportHandle, udp::UdpTransport};

#[test]
fn authenticated_local_listener_hint_excludes_nonaccepting_sockets_and_expires_on_restart() {
    crate::node::tests::session::run_large_stack_async_test("local-listener-wire", || async {
        let mut node = node(true).await;
        node.node.config.node.discovery.local.enabled = true;
        let id = TransportId::new(2);
        let (tx, _rx) = crate::transport::packet_channel(8);
        let mut closed = UdpTransport::new(
            id,
            None,
            UdpConfig {
                bind_addr: Some("127.0.0.1:0".into()),
                accept_connections: Some(false),
                ..Default::default()
            },
            tx,
        );
        closed.start_async().await.unwrap();
        let rejected_port = closed.local_addr().unwrap().port();
        node.node
            .transports
            .insert(id, TransportHandle::Udp(closed));
        let remote = make_node();
        let (socket, mut peer) = attach(&mut node, &remote).await;
        send(
            &mut node,
            &socket,
            &mut peer,
            &[LinkMessageType::ClientSupport.to_byte()],
        )
        .await;
        let _ = frames(&socket, &mut peer).await;
        node.node
            .send_local_udp_listeners(remote.node_addr())
            .await
            .unwrap();
        let observed = frames(&socket, &mut peer).await;
        let hint = observed
            .iter()
            .find(|body| body[0] == LinkMessageType::LocalUdpListeners.to_byte())
            .expect("authenticated listener advertisement");
        assert_eq!(hint[1], 1);
        let accepting_port = u16::from_le_bytes([hint[2], hint[3]]);
        assert_ne!(accepting_port, rejected_port);
        assert_eq!(
            node.node.bound_udp_listener_snapshot()[0].port(),
            accepting_port
        );

        let hint = [LinkMessageType::LocalUdpListeners.to_byte(), 1, 0x34, 0x12];
        send(&mut node, &socket, &mut peer, &hint).await;
        let expected = vec!["127.0.0.1:4660".parse::<std::net::SocketAddr>().unwrap()];
        assert_eq!(
            node.node
                .authenticated_local_udp_listeners(remote.node_addr()),
            expected
        );
        for invalid in [vec![0x54, 1, 0], vec![0x54, 1, 0, 0], vec![0x54, 17]] {
            send(&mut node, &socket, &mut peer, &invalid).await;
            assert_eq!(
                node.node
                    .authenticated_local_udp_listeners(remote.node_addr()),
                expected
            );
        }
        node.node
            .reset_peer_routing_after_restart(remote.node_addr());
        assert!(
            node.node
                .authenticated_local_udp_listeners(remote.node_addr())
                .is_empty()
        );
        cleanup_nodes(&mut [node]).await;
    });
}
