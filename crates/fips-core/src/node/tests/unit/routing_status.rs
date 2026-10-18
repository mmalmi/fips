use super::*;

async fn routing_status(node: &mut Node) -> crate::FipsEndpointRoutingStatus {
    let (response_tx, response_rx) = tokio::sync::oneshot::channel();
    node.handle_endpoint_control(NodeEndpointControlCommand::RoutingStatus { response_tx })
        .await;
    response_rx.await.expect("routing status response")
}

#[tokio::test]
async fn endpoint_routing_status_distinguishes_requested_role_from_legacy_fallback() {
    let mut config = Config::new();
    config.node.leaf_only = true;
    let mut node = Node::new(config).expect("client node");
    let remote = Identity::generate();
    let address = *remote.node_addr();
    node.peers.insert(
        address,
        ActivePeer::new(
            PeerIdentity::from_pubkey_full(remote.pubkey_full()),
            LinkId::new(1),
            0,
        ),
    );
    node.refresh_client_role();
    assert_eq!(
        routing_status(&mut node).await,
        crate::FipsEndpointRoutingStatus {
            client_only_requested: true,
            client_only: false,
            connected_peers: 1,
            peers_without_client_support: 1,
        }
    );

    node.peers.get_mut(&address).unwrap().client_only_supported = true;
    node.refresh_client_role();
    let supported = routing_status(&mut node).await;
    assert!(supported.client_only_requested && supported.client_only);
    assert_eq!(
        (
            supported.connected_peers,
            supported.peers_without_client_support
        ),
        (1, 0)
    );

    let peer = node.peers.get_mut(&address).unwrap();
    peer.client_only_supported = false;
    peer.mark_disconnected();
    node.refresh_client_role();
    let disconnected = routing_status(&mut node).await;
    assert!(disconnected.client_only);
    assert_eq!(disconnected.connected_peers, 0);
    assert_eq!(disconnected.peers_without_client_support, 0);

    node.config.node.leaf_only = false;
    node.refresh_client_role();
    let router = routing_status(&mut node).await;
    assert!(!router.client_only_requested && !router.client_only);
    assert_eq!(
        (router.connected_peers, router.peers_without_client_support),
        (0, 0)
    );
}
