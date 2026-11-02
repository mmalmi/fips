use super::*;

#[tokio::test]
async fn truncated_coordinate_records_cannot_warm_routes_or_panic() {
    let mut node = make_node();
    let src = make_node_addr(0x21);
    let dest = make_node_addr(0x22);
    let header = build_fsp_header(0, FSP_FLAG_CP, 0);
    for len in 4..header.len() {
        let encoded = SessionDatagram::new(src, dest, header[..len].to_vec()).encode();
        node.handle_session_datagram(authenticated_session_datagram(&encoded[1..], false))
            .await;
    }
    assert!(node.coord_cache().get(&src, Node::now_ms()).is_none());
}

#[tokio::test]
async fn test_coord_cache_warming_encrypted_msg_with_coords() {
    let mut node = make_node();
    let src_addr = make_node_addr(0x01);
    let dest_addr = make_node_addr(0x02);
    let root_addr = *node.tree_state().my_coords().root_id();

    let src_coords = TreeCoordinate::from_addrs(vec![src_addr, root_addr]).unwrap();
    let dest_coords = TreeCoordinate::from_addrs(vec![dest_addr, root_addr]).unwrap();

    // Build FSP encrypted message with CP flag: header(12) + coords + fake_ciphertext
    let header = build_fsp_header(0, FSP_FLAG_CP, 20);
    let mut data_payload = Vec::new();
    data_payload.extend_from_slice(&header);
    encode_coords(&src_coords, &mut data_payload);
    encode_coords(&dest_coords, &mut data_payload);
    data_payload.extend_from_slice(&[0xCC; 36]); // fake ciphertext (20 payload + 16 tag)

    let dg = SessionDatagram::new(src_addr, dest_addr, data_payload);
    let encoded = dg.encode();

    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;

    assert!(node.coord_cache().get(&src_addr, now_ms).is_none());
    assert!(node.coord_cache().get(&dest_addr, now_ms).is_none());

    node.handle_session_datagram(authenticated_session_datagram(&encoded[1..], false))
        .await;

    assert!(
        node.coord_cache().get(&src_addr, now_ms).is_some(),
        "src coords not cached from encrypted message"
    );
    assert!(
        node.coord_cache().get(&dest_addr, now_ms).is_some(),
        "dest coords not cached from encrypted message"
    );
}

#[tokio::test]
async fn test_coord_cache_warming_encrypted_msg_no_coords() {
    let mut node = make_node();
    let src_addr = make_node_addr(0x01);
    let dest_addr = make_node_addr(0x02);

    // Build FSP encrypted message without CP flag: header(12) + fake_ciphertext
    let header = build_fsp_header(0, 0, 20);
    let mut data_payload = Vec::new();
    data_payload.extend_from_slice(&header);
    data_payload.extend_from_slice(&[0xCC; 36]); // fake ciphertext (20 payload + 16 tag)

    let dg = SessionDatagram::new(src_addr, dest_addr, data_payload);
    let encoded = dg.encode();

    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;

    node.handle_session_datagram(authenticated_session_datagram(&encoded[1..], false))
        .await;

    assert!(
        node.coord_cache().get(&src_addr, now_ms).is_none(),
        "Should not cache coords from message without CP flag"
    );
    assert!(
        node.coord_cache().get(&dest_addr, now_ms).is_none(),
        "Should not cache coords from message without CP flag"
    );
}
