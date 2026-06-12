use super::*;

use crate::node::session::{EndToEndState, SessionEntry};
use crate::node::{PeerLifecycleRegistry, SessionRegistry};
use crate::noise::{HandshakeState as NoiseHandshakeState, NoiseSession};
use crate::peer::ActivePeer;
use crate::transport::{LinkId, LinkStats, TransportAddr, TransportId};
use crate::utils::index::SessionIndex;
use crate::{Identity, NodeAddr, PeerIdentity};
use std::time::{Duration, Instant};

fn node_addr(byte: u8) -> NodeAddr {
    let mut bytes = [0u8; 16];
    bytes[0] = byte;
    NodeAddr::from_bytes(bytes)
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
    active_fmp_peer_with_mmp_config(local, peer, tag, &crate::mmp::MmpConfig::default())
}

fn active_fmp_peer_with_mmp_config(
    local: &Identity,
    peer: &Identity,
    tag: u32,
    mmp_config: &crate::mmp::MmpConfig,
) -> ActivePeer {
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
        mmp_config,
        Some([2u8; 8]),
    )
}

fn make_xk_session_pair(
    initiator: &Identity,
    responder: &Identity,
) -> (NoiseSession, NoiseSession) {
    let mut initiator_hs =
        NoiseHandshakeState::new_xk_initiator(initiator.keypair(), responder.pubkey_full());
    let mut responder_hs = NoiseHandshakeState::new_xk_responder(responder.keypair());
    initiator_hs.set_local_epoch([1u8; 8]);
    responder_hs.set_local_epoch([2u8; 8]);

    let msg1 = initiator_hs.write_xk_message_1().unwrap();
    responder_hs.read_xk_message_1(&msg1).unwrap();
    let msg2 = responder_hs.write_xk_message_2().unwrap();
    initiator_hs.read_xk_message_2(&msg2).unwrap();
    let msg3 = initiator_hs.write_xk_message_3().unwrap();
    responder_hs.read_xk_message_3(&msg3).unwrap();

    (
        initiator_hs.into_session().unwrap(),
        responder_hs.into_session().unwrap(),
    )
}

fn session_entry_with_mmp_config(
    local: &Identity,
    peer: &Identity,
    config: &crate::config::SessionMmpConfig,
) -> SessionEntry {
    let (session, _) = make_xk_session_pair(local, peer);
    let mut entry = SessionEntry::new(
        *peer.node_addr(),
        peer.pubkey_full(),
        EndToEndState::Established(session),
        1_000,
        true,
    );
    entry.mark_established(1_000);
    entry.init_mmp(config);
    entry
}

fn sample_receiver_report(timestamp_echo: u32) -> ReceiverReport {
    ReceiverReport {
        highest_counter: 10,
        cumulative_packets_recv: 10,
        cumulative_bytes_recv: 1_200,
        timestamp_echo,
        dwell_time: 0,
        max_burst_loss: 0,
        mean_burst_loss: 0,
        jitter: 123,
        ecn_ce_count: 0,
        owd_trend: 0,
        burst_loss_count: 0,
        cumulative_reorder_count: 0,
        interval_packets_recv: 10,
        interval_bytes_recv: 1_200,
    }
}

#[test]
fn session_registry_owns_due_session_mmp_report_collection() {
    let local = Identity::generate();
    let peer = Identity::generate();
    let peer_addr = *peer.node_addr();
    let now = Instant::now();
    let mut entry =
        session_entry_with_mmp_config(&local, &peer, &crate::config::SessionMmpConfig::default());

    {
        let mmp = entry.mmp_mut().expect("session MMP enabled");
        mmp.sender.record_sent(12, 3, 512);
        mmp.receiver.record_recv(12, 3, 512, false, now);
        mmp.path_mtu.observe_incoming_mtu(1234);
    }

    let mut sessions = SessionRegistry::default();
    assert!(sessions.insert(peer_addr, entry).is_none());

    let batch = sessions.collect_due_session_mmp_reports(now + Duration::from_millis(1));
    assert_eq!(batch.reports.len(), 3);
    assert!(
        batch.reports.iter().any(|report| {
            report.dest_addr == peer_addr
                && report.msg_type == SessionMessageType::SenderReport.to_byte()
        }),
        "full mode should emit a session SenderReport"
    );
    assert!(
        batch.reports.iter().any(|report| {
            report.dest_addr == peer_addr
                && report.msg_type == SessionMessageType::ReceiverReport.to_byte()
        }),
        "full mode should emit a session ReceiverReport"
    );
    assert!(
        batch.reports.iter().any(|report| {
            report.dest_addr == peer_addr
                && report.msg_type == SessionMessageType::PathMtuNotification.to_byte()
        }),
        "observed path MTU should emit a session PathMtuNotification"
    );
    assert_eq!(batch.metric_logs.len(), 1);
    assert_eq!(batch.metric_logs[0].dest_addr, peer_addr);
    assert!(!batch.metric_logs[0].fallback_session_name.is_empty());
    assert_eq!(batch.metric_logs[0].observed_mtu, 1234);
    assert_eq!(batch.metric_logs[0].tx_packets, 1);
    assert_eq!(batch.metric_logs[0].rx_packets, 1);

    let second = sessions.collect_due_session_mmp_reports(now + Duration::from_millis(2));
    assert!(second.reports.is_empty());
    assert!(second.metric_logs.is_empty());
}

#[test]
fn session_registry_session_mmp_report_collection_respects_modes() {
    let local = Identity::generate();
    let lightweight_peer = Identity::generate();
    let minimal_peer = Identity::generate();
    let now = Instant::now();

    let lightweight_config = crate::config::SessionMmpConfig {
        mode: MmpMode::Lightweight,
        ..Default::default()
    };
    let mut lightweight =
        session_entry_with_mmp_config(&local, &lightweight_peer, &lightweight_config);
    {
        let mmp = lightweight.mmp_mut().expect("session MMP enabled");
        mmp.sender.record_sent(1, 1, 100);
        mmp.receiver.record_recv(1, 1, 100, false, now);
    }

    let minimal_config = crate::config::SessionMmpConfig {
        mode: MmpMode::Minimal,
        ..Default::default()
    };
    let mut minimal = session_entry_with_mmp_config(&local, &minimal_peer, &minimal_config);
    {
        let mmp = minimal.mmp_mut().expect("session MMP enabled");
        mmp.sender.record_sent(1, 1, 100);
        mmp.receiver.record_recv(1, 1, 100, false, now);
    }

    let mut sessions = SessionRegistry::default();
    assert!(
        sessions
            .insert(*lightweight_peer.node_addr(), lightweight)
            .is_none()
    );
    assert!(
        sessions
            .insert(*minimal_peer.node_addr(), minimal)
            .is_none()
    );

    let batch = sessions.collect_due_session_mmp_reports(now + Duration::from_millis(1));

    assert_eq!(batch.reports.len(), 1);
    assert_eq!(batch.reports[0].dest_addr, *lightweight_peer.node_addr());
    assert_eq!(
        batch.reports[0].msg_type,
        SessionMessageType::ReceiverReport.to_byte()
    );
    assert_eq!(batch.metric_logs.len(), 2);
    assert!(
        batch
            .metric_logs
            .iter()
            .any(|metrics| metrics.dest_addr == *lightweight_peer.node_addr())
    );
    assert!(
        batch
            .metric_logs
            .iter()
            .any(|metrics| metrics.dest_addr == *minimal_peer.node_addr())
    );
}

#[test]
fn session_registry_owns_session_mmp_send_result_accounting() {
    let local = Identity::generate();
    let peer = Identity::generate();
    let peer_addr = *peer.node_addr();
    let entry =
        session_entry_with_mmp_config(&local, &peer, &crate::config::SessionMmpConfig::default());
    let mut sessions = SessionRegistry::default();
    assert!(sessions.insert(peer_addr, entry).is_none());

    for expected_failures in 1..=4 {
        let resumed = sessions.record_session_mmp_send_results([SessionMmpSendResult {
            dest_addr: peer_addr,
            success: false,
        }]);
        assert!(resumed.is_empty());
        assert_eq!(
            sessions
                .get(&peer_addr)
                .and_then(|entry| entry.mmp())
                .expect("session MMP")
                .sender
                .consecutive_send_failures(),
            expected_failures
        );
    }

    let resumed = sessions.record_session_mmp_send_results([
        SessionMmpSendResult {
            dest_addr: peer_addr,
            success: false,
        },
        SessionMmpSendResult {
            dest_addr: peer_addr,
            success: true,
        },
    ]);
    assert_eq!(
        resumed,
        vec![SessionMmpReportingResumed {
            dest_addr: peer_addr,
            consecutive_failures: 4
        }]
    );
    assert_eq!(
        sessions
            .get(&peer_addr)
            .and_then(|entry| entry.mmp())
            .expect("session MMP")
            .sender
            .consecutive_send_failures(),
        0
    );

    let resumed = sessions.record_session_mmp_send_results([
        SessionMmpSendResult {
            dest_addr: peer_addr,
            success: false,
        },
        SessionMmpSendResult {
            dest_addr: peer_addr,
            success: false,
        },
    ]);
    assert!(resumed.is_empty());
    assert_eq!(
        sessions
            .get(&peer_addr)
            .and_then(|entry| entry.mmp())
            .expect("session MMP")
            .sender
            .consecutive_send_failures(),
        1,
        "all failed reports for one destination should count as one failed tick"
    );
}

#[test]
fn peer_lifecycle_registry_owns_mmp_receiver_report_processing() {
    let local = Identity::generate();
    let peer_id = Identity::generate();
    let mut peer = active_fmp_peer(&local, &peer_id, 1);

    {
        let mmp = peer.mmp_mut().expect("MMP enabled");
        mmp.receiver
            .record_recv(10, 1, 1_200, false, Instant::now());
    }

    let mut peers = PeerLifecycleRegistry::default();
    peers.insert(*peer_id.node_addr(), peer);

    std::thread::sleep(Duration::from_millis(20));
    let outcome = peers
        .process_mmp_receiver_report(
            peer_id.node_addr(),
            &sample_receiver_report(1),
            Instant::now(),
        )
        .expect("receiver report should process");

    assert!(outcome.first_rtt);
    assert!(outcome.srtt_ms.is_some());
    assert_eq!(outcome.loss_rate, 0.0);
    assert_eq!(outcome.etx, 1.0);

    let peer = peers.get(peer_id.node_addr()).expect("peer retained");
    let mmp = peer.mmp().expect("MMP retained");
    assert_eq!(mmp.metrics.srtt_ms(), outcome.srtt_ms);
    assert!(peer.has_srtt());
    assert_eq!(mmp.receiver.cumulative_packets_recv(), 1);
    assert_eq!(mmp.receiver.highest_counter(), 10);
}

#[test]
fn peer_lifecycle_registry_owns_mmp_receiver_report_skip_paths() {
    let mut peers = PeerLifecycleRegistry::default();
    let rr = sample_receiver_report(0);

    assert_eq!(
        peers.process_mmp_receiver_report(&node_addr(0x77), &rr, Instant::now()),
        Err(MmpReceiverReportSkip::UnknownPeer)
    );

    let no_mmp_identity = Identity::generate();
    let no_mmp_peer = ActivePeer::new(
        PeerIdentity::from_pubkey_full(no_mmp_identity.pubkey_full()),
        LinkId::new(9),
        1_000,
    );
    peers.insert(*no_mmp_identity.node_addr(), no_mmp_peer);

    assert_eq!(
        peers.process_mmp_receiver_report(no_mmp_identity.node_addr(), &rr, Instant::now()),
        Err(MmpReceiverReportSkip::MmpDisabled)
    );
}

#[test]
fn peer_lifecycle_registry_owns_due_mmp_link_report_collection() {
    let local = Identity::generate();
    let peer_id = Identity::generate();
    let mut peer = active_fmp_peer(&local, &peer_id, 2);
    let now = Instant::now();

    {
        let mmp = peer.mmp_mut().expect("MMP enabled");
        mmp.sender.record_sent(12, 3, 512);
        mmp.receiver.record_recv(12, 3, 512, false, now);
    }

    let mut peers = PeerLifecycleRegistry::default();
    peers.insert(*peer_id.node_addr(), peer);

    let batch = peers.collect_due_mmp_link_reports(now + Duration::from_millis(1));
    assert_eq!(batch.sender_reports.len(), 1);
    assert_eq!(batch.receiver_reports.len(), 1);
    assert_eq!(batch.metric_logs.len(), 1);
    assert_eq!(batch.sender_reports[0].node_addr, *peer_id.node_addr());
    assert_eq!(batch.sender_reports[0].encoded[0], 0x01);
    assert_eq!(batch.receiver_reports[0].node_addr, *peer_id.node_addr());
    assert_eq!(batch.receiver_reports[0].encoded[0], 0x02);
    assert_eq!(batch.metric_logs[0].node_addr, *peer_id.node_addr());
    assert_eq!(batch.metric_logs[0].tx_packets, 1);
    assert_eq!(batch.metric_logs[0].rx_packets, 1);

    let second = peers.collect_due_mmp_link_reports(now + Duration::from_millis(2));
    assert!(second.sender_reports.is_empty());
    assert!(second.receiver_reports.is_empty());
    assert!(second.metric_logs.is_empty());
}

#[test]
fn peer_lifecycle_registry_mmp_link_report_collection_respects_modes() {
    let local = Identity::generate();
    let lightweight_peer = Identity::generate();
    let minimal_peer = Identity::generate();
    let no_mmp_peer = Identity::generate();
    let now = Instant::now();

    let lightweight_config = crate::mmp::MmpConfig {
        mode: MmpMode::Lightweight,
        ..Default::default()
    };
    let mut lightweight =
        active_fmp_peer_with_mmp_config(&local, &lightweight_peer, 3, &lightweight_config);
    {
        let mmp = lightweight.mmp_mut().expect("MMP enabled");
        mmp.sender.record_sent(1, 1, 100);
        mmp.receiver.record_recv(1, 1, 100, false, now);
    }

    let minimal_config = crate::mmp::MmpConfig {
        mode: MmpMode::Minimal,
        ..Default::default()
    };
    let mut minimal = active_fmp_peer_with_mmp_config(&local, &minimal_peer, 4, &minimal_config);
    {
        let mmp = minimal.mmp_mut().expect("MMP enabled");
        mmp.sender.record_sent(1, 1, 100);
        mmp.receiver.record_recv(1, 1, 100, false, now);
    }

    let no_mmp = ActivePeer::new(
        PeerIdentity::from_pubkey_full(no_mmp_peer.pubkey_full()),
        LinkId::new(5),
        1_000,
    );

    let mut peers = PeerLifecycleRegistry::default();
    peers.insert(*lightweight_peer.node_addr(), lightweight);
    peers.insert(*minimal_peer.node_addr(), minimal);
    peers.insert(*no_mmp_peer.node_addr(), no_mmp);

    let batch = peers.collect_due_mmp_link_reports(now + Duration::from_millis(1));

    assert!(batch.sender_reports.is_empty());
    assert_eq!(batch.receiver_reports.len(), 1);
    assert_eq!(
        batch.receiver_reports[0].node_addr,
        *lightweight_peer.node_addr()
    );
    assert_eq!(batch.receiver_reports[0].encoded[0], 0x02);
    assert_eq!(batch.metric_logs.len(), 2);
    assert!(
        batch
            .metric_logs
            .iter()
            .any(|metrics| metrics.node_addr == *lightweight_peer.node_addr())
    );
    assert!(
        batch
            .metric_logs
            .iter()
            .any(|metrics| metrics.node_addr == *minimal_peer.node_addr())
    );
}

#[test]
fn peer_lifecycle_registry_owns_link_heartbeat_planning_and_sent_bookkeeping() {
    let local = Identity::generate();
    let peer_id = Identity::generate();
    let peer_addr = *peer_id.node_addr();
    let now = Instant::now();
    let mut peers = PeerLifecycleRegistry::default();
    peers.insert(peer_addr, active_fmp_peer(&local, &peer_id, 6));

    let initial = peers.plan_link_heartbeat_tick(now, Duration::from_secs(10), 3, false, |_| {
        Duration::from_secs(30)
    });
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
    );
    assert!(quiet.heartbeats.is_empty());
    assert!(quiet.dead_peers.is_empty());

    let due = peers.plan_link_heartbeat_tick(
        now + Duration::from_secs(10),
        Duration::from_secs(10),
        3,
        false,
        |_| Duration::from_secs(30),
    );
    assert_eq!(due.heartbeats, vec![peer_addr]);
}

#[test]
fn peer_lifecycle_registry_owns_link_dead_and_deferred_heartbeat_planning() {
    let local = Identity::generate();
    let peer_id = Identity::generate();
    let peer_addr = *peer_id.node_addr();
    let now = Instant::now();
    let mut peer = active_fmp_peer(&local, &peer_id, 7);
    peer.mmp_mut().expect("MMP enabled").receiver.record_recv(
        1,
        1,
        64,
        false,
        now - Duration::from_secs(31),
    );

    let mut peers = PeerLifecycleRegistry::default();
    peers.insert(peer_addr, peer);

    let dead = peers.plan_link_heartbeat_tick(now, Duration::from_secs(10), 3, false, |_| {
        Duration::from_secs(30)
    });
    assert!(dead.heartbeats.is_empty());
    assert_eq!(
        dead.dead_peers,
        vec![LinkDeadPeerPlan {
            node_addr: peer_addr,
            effective_dead_timeout: Duration::from_secs(30)
        }]
    );
    assert!(dead.deferred_dead_peers.is_empty());

    let deferred = peers.plan_link_heartbeat_tick(now, Duration::from_secs(10), 3, true, |_| {
        Duration::from_secs(30)
    });
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
