use super::*;

fn insert_awaiting_msg3_session(node: &mut Node, peer: &Identity) {
    let mut handshake = crate::noise::HandshakeState::new_xk_responder(node.identity().keypair());
    handshake.set_local_epoch([1; 8]);
    let entry = crate::node::session::SessionEntry::new(
        *peer.node_addr(),
        peer.pubkey_full(),
        EndToEndState::AwaitingMsg3(handshake),
        1_000,
        false,
    );
    node.sessions.insert(*peer.node_addr(), entry);
}

#[test]
fn existing_session_is_admitted_when_table_is_full() {
    let mut config = Config::new();
    config.node.limits.max_sessions = 1;
    let mut node = Node::new(config).unwrap();
    let peer = Identity::generate();
    insert_initiating_session(&mut node, &peer);

    assert!(node.admit_new_session(peer.node_addr()));
    assert_eq!(node.stats().sessions.table_full, 0);
}

#[test]
fn new_session_is_refused_when_table_is_full() {
    let mut config = Config::new();
    config.node.limits.max_sessions = 1;
    let mut node = Node::new(config).unwrap();
    let present = Identity::generate();
    let stranger = Identity::generate();
    insert_initiating_session(&mut node, &present);

    assert!(!node.admit_new_session(stranger.node_addr()));
    assert_eq!(node.stats().sessions.table_full, 1);
    assert_eq!(node.stats().sessions.half_open_full, 0);
}

#[test]
fn half_open_sessions_cannot_occupy_more_than_half_the_table() {
    let mut config = Config::new();
    config.node.limits.max_sessions = 4;
    let mut node = Node::new(config).unwrap();
    insert_awaiting_msg3_session(&mut node, &Identity::generate());
    insert_awaiting_msg3_session(&mut node, &Identity::generate());

    assert!(!node.admit_new_session(Identity::generate().node_addr()));
    assert_eq!(node.stats().sessions.table_full, 0);
    assert_eq!(node.stats().sessions.half_open_full, 1);
}

#[test]
fn zero_session_limit_preserves_unlimited_behavior() {
    let mut config = Config::new();
    config.node.limits.max_sessions = 0;
    let mut node = Node::new(config).unwrap();
    for _ in 0..8 {
        insert_awaiting_msg3_session(&mut node, &Identity::generate());
    }

    assert!(node.admit_new_session(Identity::generate().node_addr()));
    assert_eq!(node.stats().sessions.table_full, 0);
    assert_eq!(node.stats().sessions.half_open_full, 0);
}

fn setup_body_for(initiator: &Identity, responder: &Node) -> Vec<u8> {
    let mut handshake = crate::noise::HandshakeState::new_xk_initiator(
        initiator.keypair(),
        responder.identity().pubkey_full(),
    );
    handshake.set_local_epoch([0x44; 8]);
    let msg1 = handshake.write_xk_message_1().expect("msg1");
    let encoded = SessionSetup::new(
        TreeCoordinate::root(*initiator.node_addr()),
        responder.tree_state().my_coords().clone(),
    )
    .with_handshake(msg1)
    .encode();
    encoded[FSP_COMMON_PREFIX_SIZE..].to_vec()
}

#[tokio::test]
async fn routed_setup_budget_is_keyed_on_authenticated_previous_hop() {
    let mut config = Config::new();
    config.node.rate_limit.session_setup_burst = 1;
    config.node.rate_limit.session_setup_rate = 0.001;
    let mut node = Node::new(config).expect("node");
    let first = Identity::generate();
    let second = Identity::generate();
    let previous_hop = make_node_addr(0xEE);
    let first_body = setup_body_for(&first, &node);
    let second_body = setup_body_for(&second, &node);

    node.handle_session_setup(first.node_addr(), &previous_hop, &first_body)
        .await;
    node.handle_session_setup(second.node_addr(), &previous_hop, &second_body)
        .await;

    assert_eq!(node.stats().sessions.setup_rate_limited, 1);
}
