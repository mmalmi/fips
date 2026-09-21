//! Policy/ownership controls; real packet-only Endpoint/TUN tests live in
//! sim_discovery::rotation::demand. These fixtures attach no transport.
use super::*;
use crate::Identity;
use crate::node::EndpointDataPayload;
use crate::node::session::{EndToEndState, SessionEntry};
use crate::node::tests::{make_completed_connection_for_identity, make_node};
use crate::noise::HandshakeState;
use crate::transport::TransportId;

const PAYLOAD: &[u8] = b"retain this original queued payload";

fn add_peer(node: &mut Node, identity: &Identity, number: u64) -> PeerIdentity {
    let link = LinkId::new(number);
    let now = Node::now_ms();
    let (connection, peer) = make_completed_connection_for_identity(
        node,
        link,
        TransportId::new(number as u32),
        now,
        identity,
    );
    node.add_connection(connection).unwrap();
    node.promote_connection(link, peer, now).unwrap();
    assert!(node.sync_dataplane_fmp_owner(peer.node_addr()));
    assert!(node.get_peer(peer.node_addr()).unwrap().can_send());
    peer
}

fn fixture() -> (Node, Identity) {
    let mut node = make_node();
    let remote = Identity::generate();
    add_peer(&mut node, &remote, 1);
    assert!(node.transports.is_empty());
    (node, remote)
}

fn queue(node: &mut Node, destination: NodeAddr) -> u64 {
    let now = Node::now_ms();
    let result = node
        .pending_session_traffic
        .push_endpoint_data_batch_with_enqueued_at_ms(
            destination,
            vec![EndpointDataPayload::from_packet_payload(PAYLOAD.to_vec()).unwrap()],
            4,
            4,
            now,
        );
    assert!(!result.destination_dropped() && !result.dropped_oldest());
    node.pending_lookups.insert_new(destination, now);
    now
}

fn lookup(node: &Node, destination: &NodeAddr) -> Option<(u64, u64, u8, bool)> {
    node.pending_lookups.get(destination).map(|pending| {
        (
            pending.initiated_ms,
            pending.last_sent_ms,
            pending.attempt,
            pending.awaiting_first_request(),
        )
    })
}

/// Inspect the exact retained record only after the operation under test.
fn assert_original_queue(node: &mut Node, destination: &NodeAddr, enqueued: u64) {
    assert!(node.pending_session_traffic.has_traffic_for(destination));
    let queue = node
        .pending_session_traffic
        .take_endpoint_data(destination)
        .unwrap();
    assert_eq!(queue.len(), 1);
    let mut batches = queue.into_pending_payloads();
    assert_eq!(batches.len(), 1);
    let batch = batches.pop_front().unwrap();
    assert_eq!(
        batch.enqueued_at_ms(),
        enqueued,
        "original expiry authority"
    );
    assert_eq!(
        batch.into_payloads(),
        vec![EndpointDataPayload::from_packet_payload(PAYLOAD.to_vec()).unwrap()]
    );
}

fn install_existing(node: &mut Node, remote: &Identity, established: bool) {
    let now = Node::now_ms();
    let mut initiator =
        HandshakeState::new_xk_initiator(node.identity().keypair(), remote.pubkey_full());
    initiator.set_local_epoch(node.startup_epoch);
    let msg1 = initiator.write_xk_message_1().unwrap();
    let state = if established {
        let mut responder = HandshakeState::new_xk_responder(remote.keypair());
        responder.set_local_epoch([0x49; 8]);
        responder.read_xk_message_1(&msg1).unwrap();
        initiator
            .read_xk_message_2(&responder.write_xk_message_2().unwrap())
            .unwrap();
        responder
            .read_xk_message_3(&initiator.write_xk_message_3().unwrap())
            .unwrap();
        EndToEndState::Established(initiator.into_session().unwrap())
    } else {
        EndToEndState::Initiating(initiator)
    };
    let mut entry = SessionEntry::new(*remote.node_addr(), remote.pubkey_full(), state, now, true);
    if established {
        entry.mark_established(now);
    } else {
        entry.set_handshake_payload(msg1, now.saturating_add(1_000));
    }
    node.sessions.insert(*remote.node_addr(), entry);
    if established {
        assert!(node.sync_dataplane_fsp_owner_from_current_session(remote.node_addr(), 0));
    }
}

#[tokio::test]
async fn no_queue_does_not_start_session_or_clear_lookup() {
    let (mut node, remote) = fixture();
    let destination = *remote.node_addr();
    node.pending_lookups.insert_new(destination, Node::now_ms());
    let original = lookup(&node, &destination);
    node.resume_queued_direct_session(&destination).await;
    assert_eq!(node.session_count(), 0);
    assert!(!node.dataplane_has_fsp_owner(&destination));
    assert_eq!(lookup(&node, &destination), original);
    assert!(!node.pending_session_traffic.has_traffic_for(&destination));
    assert_eq!(
        node.get_peer(&destination)
            .unwrap()
            .link_stats()
            .packets_sent,
        0
    );
}

#[tokio::test]
async fn existing_initiating_and_established_sessions_keep_their_ownership() {
    for established in [false, true] {
        let (mut node, remote) = fixture();
        let destination = *remote.node_addr();
        install_existing(&mut node, &remote, established);
        let enqueued = queue(&mut node, destination);
        let pending = lookup(&node, &destination);
        let entry = node.get_session(&destination).unwrap();
        let original_entry = entry as *const SessionEntry;
        let original = (
            entry.created_at(),
            entry.session_start_ms(),
            entry.next_resend_at_ms(),
            entry.handshake_payload().map(<[u8]>::to_vec),
            entry.handshake_hash().copied(),
        );
        let owner = node.dataplane_has_fsp_owner(&destination);
        node.resume_queued_direct_session(&destination).await;
        let entry = node.get_session(&destination).unwrap();
        assert!(std::ptr::eq(entry, original_entry));
        assert_eq!(entry.is_established(), established);
        assert_eq!(entry.is_initiating(), !established);
        assert_eq!(
            (
                entry.created_at(),
                entry.session_start_ms(),
                entry.next_resend_at_ms(),
                entry.handshake_payload().map(<[u8]>::to_vec),
                entry.handshake_hash().copied()
            ),
            original
        );
        assert_eq!(node.dataplane_has_fsp_owner(&destination), owner);
        assert_eq!(lookup(&node, &destination), pending);
        assert_eq!(
            node.get_peer(&destination)
                .unwrap()
                .link_stats()
                .packets_sent,
            0
        );
        assert_original_queue(&mut node, &destination, enqueued);
    }
}

#[tokio::test]
async fn selected_other_carrier_and_unavailable_binding_preserve_queue_lookup() {
    for unavailable in [false, true] {
        let (mut node, remote) = fixture();
        let destination = *remote.node_addr();
        let other = add_peer(&mut node, &Identity::generate(), 2);
        node.set_endpoint_source_route(
            PeerIdentity::from_pubkey_full(remote.pubkey_full()),
            Some(other),
        )
        .unwrap();
        if unavailable {
            node.peers
                .get_mut(other.node_addr())
                .unwrap()
                .mark_disconnected();
        }
        assert_eq!(
            node.find_next_hop(&destination)
                .map(|peer| *peer.node_addr()),
            (!unavailable).then_some(*other.node_addr())
        );
        let enqueued = queue(&mut node, destination);
        let pending = lookup(&node, &destination);
        node.resume_queued_direct_session(&destination).await;
        assert_eq!(node.session_count(), 0);
        assert_eq!(
            node.source_routes.get(&destination),
            Some(other.node_addr())
        );
        assert_eq!(lookup(&node, &destination), pending);
        assert_eq!(
            node.get_peer(&destination)
                .unwrap()
                .link_stats()
                .packets_sent,
            0
        );
        assert_original_queue(&mut node, &destination, enqueued);
    }
}

#[tokio::test]
async fn session_admission_error_keeps_original_lookup_and_queue() {
    let mut config = crate::config::Config::new();
    config.node.limits.max_sessions = 1;
    let mut node = Node::new(config).unwrap();
    let remote = Identity::generate();
    add_peer(&mut node, &remote, 1);
    let other = Identity::generate();
    install_existing(&mut node, &other, false);
    let original_entry = node.get_session(other.node_addr()).unwrap() as *const SessionEntry;
    let destination = *remote.node_addr();
    let enqueued = queue(&mut node, destination);
    let pending = lookup(&node, &destination);
    node.resume_queued_direct_session(&destination).await;
    assert!(node.get_session(&destination).is_none());
    assert_eq!(node.session_count(), 1);
    assert!(std::ptr::eq(
        node.get_session(other.node_addr()).unwrap(),
        original_entry
    ));
    assert_eq!(
        node.stats().sessions.table_full,
        1,
        "real pre-install admission refusal"
    );
    assert_eq!(lookup(&node, &destination), pending);
    assert_original_queue(&mut node, &destination, enqueued);
}

#[tokio::test]
async fn installed_but_unsent_session_takes_lookup_ownership_without_requeue() {
    let (mut node, remote) = fixture();
    let destination = *remote.node_addr();
    assert_eq!(
        node.find_next_hop(&destination).unwrap().node_addr(),
        &destination
    );
    let enqueued = queue(&mut node, destination);
    // The authenticated fixture peer has no attached transport. The route is
    // selected normally, but no transport can accept the real SessionSetup.
    node.resume_queued_direct_session(&destination).await;
    let entry = node
        .get_session(&destination)
        .expect("retain installed generation after failed send");
    assert!(entry.is_initiating());
    assert!(entry.handshake_payload().is_some());
    assert!(entry.next_resend_at_ms() > 0);
    let original = (
        entry.created_at(),
        entry.next_resend_at_ms(),
        entry.handshake_payload().unwrap().to_vec(),
    );
    assert!(lookup(&node, &destination).is_none());
    assert!(node.transports.is_empty());
    assert_eq!(
        node.get_peer(&destination)
            .unwrap()
            .link_stats()
            .packets_sent,
        0
    );
    node.resume_queued_direct_session(&destination).await;
    let entry = node.get_session(&destination).unwrap();
    assert_eq!(
        (
            entry.created_at(),
            entry.next_resend_at_ms(),
            entry.handshake_payload().unwrap().to_vec()
        ),
        original
    );
    assert_eq!(node.session_count(), 1);
    assert_original_queue(&mut node, &destination, enqueued);
}
