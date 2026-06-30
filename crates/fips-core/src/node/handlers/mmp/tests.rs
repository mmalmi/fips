use super::*;

use crate::node::PeerLifecycleRegistry;
use crate::noise::{HandshakeState as NoiseHandshakeState, NoiseSession};
use crate::peer::ActivePeer;
use crate::transport::{LinkId, LinkStats, TransportAddr, TransportId};
use crate::utils::index::SessionIndex;
use crate::{Identity, PeerIdentity};
use std::time::{Duration, Instant};

fn link_mmp_quiet_for(now: Instant, peer: &ActivePeer) -> Duration {
    now.duration_since(peer.session_start())
}

fn make_fmp_session_pair(
    initiator: &Identity,
    responder: &Identity,
) -> (NoiseSession, NoiseSession) {
    let mut initiator_hs =
        NoiseHandshakeState::new_initiator(initiator.keypair(), responder.pubkey_full());
    let mut responder_hs = NoiseHandshakeState::new_responder(responder.keypair());
    initiator_hs.set_local_epoch([1u8; 8]);
    responder_hs.set_local_epoch([2u8; 8]);

    let msg1 = initiator_hs.write_message_1().unwrap();
    responder_hs.read_message_1(&msg1).unwrap();
    let msg2 = responder_hs.write_message_2().unwrap();
    initiator_hs.read_message_2(&msg2).unwrap();

    (
        initiator_hs.into_session().unwrap(),
        responder_hs.into_session().unwrap(),
    )
}

fn active_fmp_peer(local: &Identity, peer: &Identity, tag: u32) -> ActivePeer {
    let peer_identity = PeerIdentity::from_pubkey_full(peer.pubkey_full());
    let (session, _) = make_fmp_session_pair(local, peer);
    ActivePeer::with_session(
        peer_identity,
        LinkId::new(tag.into()),
        1_000,
        session,
        SessionIndex::new(tag * 10 + 1),
        SessionIndex::new(tag * 10 + 2),
        TransportId::new(tag),
        TransportAddr::from_string(&format!("127.0.0.1:{}", 4_000 + tag)),
        LinkStats::new(),
        true,
        &crate::mmp::MmpConfig::default(),
        Some([2u8; 8]),
    )
}

#[test]
fn peer_lifecycle_registry_owns_link_heartbeat_planning_and_sent_bookkeeping() {
    let local = Identity::generate();
    let peer_id = Identity::generate();
    let peer_addr = *peer_id.node_addr();
    let now = Instant::now();
    let mut peers = PeerLifecycleRegistry::default();
    peers.insert(peer_addr, active_fmp_peer(&local, &peer_id, 6));

    let initial = peers.plan_link_heartbeat_tick(
        now,
        Duration::from_secs(10),
        3,
        false,
        |_| Duration::from_secs(30),
        |_, peer| link_mmp_quiet_for(now, peer),
    );
    assert_eq!(initial.heartbeats, vec![peer_addr]);
    assert!(initial.dead_peers.is_empty());
    assert!(initial.deferred_dead_peers.is_empty());

    assert!(peers.record_link_heartbeat_sent(&peer_addr, now));
    let quiet = peers.plan_link_heartbeat_tick(
        now + Duration::from_secs(5),
        Duration::from_secs(10),
        3,
        false,
        |_| Duration::from_secs(30),
        |_, peer| link_mmp_quiet_for(now + Duration::from_secs(5), peer),
    );
    assert!(quiet.heartbeats.is_empty());
    assert!(quiet.dead_peers.is_empty());

    let due = peers.plan_link_heartbeat_tick(
        now + Duration::from_secs(10),
        Duration::from_secs(10),
        3,
        false,
        |_| Duration::from_secs(30),
        |_, peer| link_mmp_quiet_for(now + Duration::from_secs(10), peer),
    );
    assert_eq!(due.heartbeats, vec![peer_addr]);
}

#[test]
fn peer_lifecycle_registry_owns_link_dead_and_deferred_heartbeat_planning() {
    let local = Identity::generate();
    let peer_id = Identity::generate();
    let peer_addr = *peer_id.node_addr();
    let now = Instant::now();
    let peer = active_fmp_peer(&local, &peer_id, 7);

    let mut peers = PeerLifecycleRegistry::default();
    peers.insert(peer_addr, peer);

    let dead = peers.plan_link_heartbeat_tick(
        now,
        Duration::from_secs(10),
        3,
        false,
        |_| Duration::from_secs(30),
        |_, _| Duration::from_secs(31),
    );
    assert!(dead.heartbeats.is_empty());
    assert_eq!(
        dead.dead_peers,
        vec![LinkDeadPeerPlan {
            node_addr: peer_addr,
            effective_dead_timeout: Duration::from_secs(30)
        }]
    );
    assert!(dead.deferred_dead_peers.is_empty());

    let deferred = peers.plan_link_heartbeat_tick(
        now,
        Duration::from_secs(10),
        3,
        true,
        |_| Duration::from_secs(30),
        |_, _| Duration::from_secs(31),
    );
    assert_eq!(deferred.heartbeats, vec![peer_addr]);
    assert!(deferred.dead_peers.is_empty());
    assert_eq!(
        deferred.deferred_dead_peers,
        vec![LinkDeadPeerPlan {
            node_addr: peer_addr,
            effective_dead_timeout: Duration::from_secs(30)
        }]
    );
}
