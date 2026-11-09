#[tokio::test]
async fn session_capabilities_require_established_peer_valid_envelope_and_port() {
    let local = Identity::generate();
    let peer = Identity::generate();
    let peer_addr = *peer.node_addr();
    let mut node = Node::with_identity(local, crate::config::Config::new()).unwrap();
    let reply = SessionCapabilities::local(false).encode();
    node.handle_session_capabilities(&peer_addr, SESSION_CAPABILITY_PORT, &reply)
        .await;
    assert!(node.sessions.get(&peer_addr).is_none());

    node.sessions
        .insert(peer_addr, initiating_entry(&node.identity, &peer));
    node.handle_session_capabilities(&peer_addr, SESSION_CAPABILITY_PORT, &reply)
        .await;
    assert!(
        !node
            .sessions
            .get(&peer_addr)
            .unwrap()
            .remote_supports_direct_fsp_transport()
    );

    node.sessions
        .insert(peer_addr, established_entry(&node.identity, &peer));
    node.handle_session_capabilities(&peer_addr, 258, &reply)
        .await;
    node.handle_session_capabilities(&peer_addr, SESSION_CAPABILITY_PORT, &reply[..11])
        .await;
    let mut unknown = reply;
    unknown[10] = 2;
    node.handle_session_capabilities(&peer_addr, SESSION_CAPABILITY_PORT, &unknown)
        .await;
    assert!(
        !node
            .sessions
            .get(&peer_addr)
            .unwrap()
            .remote_supports_direct_fsp_transport()
    );

    // A response is sufficient positive evidence and requires no reply.
    node.handle_session_capabilities(&peer_addr, SESSION_CAPABILITY_PORT, &reply)
        .await;
    assert!(
        node.sessions
            .get(&peer_addr)
            .unwrap()
            .remote_supports_direct_fsp_transport()
    );
}

#[test]
fn capability_service_is_internal_without_optional_webrtc() {
    let peer = Identity::generate();
    let mut body = Vec::new();
    body.extend_from_slice(&SESSION_CAPABILITY_PORT.to_le_bytes());
    body.extend_from_slice(&SESSION_CAPABILITY_PORT.to_le_bytes());
    body.extend_from_slice(&SessionCapabilities::local(true).encode());
    let plaintext = fsp_prepend_inner_header(0, SessionMessageType::DataPacket.to_byte(), 0, &body);
    let message = AuthenticatedSessionMessage::new(
        PeerIdentity::from_pubkey_full(peer.pubkey_full()),
        PacketBuffer::new(plaintext),
        SessionMessageType::DataPacket.to_byte(),
    );
    let dispatch =
        AuthenticatedSessionDispatch::new(*peer.node_addr(), *peer.node_addr(), false, message);
    assert!(
        !dispatch.is_service_data_packet(),
        "capabilities must not leak to application service listeners"
    );
}
