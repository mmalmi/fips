use super::*;
use crate::protocol::{LookupRequest, LookupResponse, SessionDatagram, SessionSetup};

#[test]
fn strict_client_never_exports_private_parent_in_lookup_or_session_setup() {
    crate::node::tests::session::run_large_stack_async_test("strict-coordinate-wire", || async {
        let mut node = node(true).await;
        let mut remotes = vec![make_node(), make_node()];
        remotes.sort_by_key(|peer| *peer.node_addr());
        let public = remotes.pop().unwrap();
        let contact = remotes.pop().unwrap();
        let (contact_socket, mut contact_peer) = attach(&mut node, &contact).await;
        send(
            &mut node,
            &contact_socket,
            &mut contact_peer,
            &[LinkMessageType::ClientSupport.to_byte()],
        )
        .await;
        let announce = TreeAnnounce::new(
            contact.tree_state.my_declaration().clone(),
            contact.tree_state.my_coords().clone(),
        )
        .encode()
        .unwrap();
        send(&mut node, &contact_socket, &mut contact_peer, &announce).await;
        let _ = frames(&contact_socket, &mut contact_peer).await;
        assert!(
            node.node
                .tree_state
                .my_coords()
                .node_addrs()
                .any(|addr| addr == contact.node_addr()),
            "fixture must learn private ancestry from an actual authenticated peer"
        );

        let (socket, mut peer) = attach(&mut node, &public).await;
        send(
            &mut node,
            &socket,
            &mut peer,
            &[LinkMessageType::ClientSupport.to_byte()],
        )
        .await;
        let _ = frames(&socket, &mut peer).await;
        let request = LookupRequest::generate(
            *node.node.node_addr(),
            *public.node_addr(),
            public.tree_state.my_coords().clone(),
            2,
            0,
        );
        send(&mut node, &socket, &mut peer, &request.encode()).await;
        let replies = frames(&socket, &mut peer).await;
        let response = replies
            .iter()
            .find(|body| body[0] == LinkMessageType::LookupResponse.to_byte())
            .expect("actual lookup response");
        let response = LookupResponse::decode(&response[1..]).unwrap();
        assert_eq!(
            response
                .target_coords
                .node_addrs()
                .copied()
                .collect::<Vec<_>>(),
            vec![*node.node.node_addr()]
        );

        node.node
            .initiate_session(*public.node_addr(), public.identity.pubkey_full())
            .await
            .unwrap();
        let replies = frames(&socket, &mut peer).await;
        let datagram = replies
            .iter()
            .find(|body| body[0] == LinkMessageType::SessionDatagram.to_byte())
            .expect("actual first-contact FSP frame");
        let datagram = SessionDatagram::decode(&datagram[1..]).unwrap();
        let setup = SessionSetup::decode(&datagram.payload[4..]).unwrap();
        assert_eq!(
            setup.src_coords.node_addrs().copied().collect::<Vec<_>>(),
            vec![*node.node.node_addr()]
        );
        assert_eq!(
            setup.dest_coords.node_addrs().copied().collect::<Vec<_>>(),
            vec![*public.node_addr()]
        );
        cleanup_nodes(&mut [node]).await;
    });
}
