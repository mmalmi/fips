//! Successful key recovery must not repeatedly repair an old unanswered burst.
use super::*;
use crate::node::{
    ForwardingOutcome, OriginatedSessionAdmission, OriginatedSessionIntent,
    OriginatedSessionObserver, OriginatedSessionRequest,
};
use futures::FutureExt;
use std::panic::AssertUnwindSafe;
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

#[derive(Debug, Default)]
struct NoReturnData(AtomicUsize);

impl OriginatedSessionObserver for NoReturnData {
    fn prepare(&self, _: &OriginatedSessionIntent) -> OriginatedSessionAdmission {
        self.0.fetch_add(1, Ordering::Relaxed);
        OriginatedSessionAdmission::Reject
    }

    fn observe(&self, _: &OriginatedSessionRequest<'_>) -> Option<u64> {
        None
    }

    fn complete(&self, _: u64, _: ForwardingOutcome) {
        panic!("no accounting reservation was made");
    }
}

#[test]
#[ignore = "observes the production 45-second drain"]
fn recovered_unanswered_burst_waits_for_new_application_traffic() {
    run_large_stack_async_test("fips-idle-recovery", || async {
        let subscriber = tracing_subscriber::fmt()
            .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
            .with_ansi(false)
            .with_test_writer()
            .finish();
        let _logging = tracing::subscriber::set_default(subscriber);
        let mut nodes = run_tree_test(3, &[(0, 1), (1, 2)], false).await;
        let result = AssertUnwindSafe(exercise(&mut nodes)).catch_unwind().await;
        cleanup_nodes(&mut nodes).await;
        if let Err(panic) = result {
            std::panic::resume_unwind(panic);
        }
    });
}

async fn tick(nodes: &mut [TestNode]) {
    process_available_packets(nodes).await;
    run_session_retransmit_work(nodes).await;
    for node in nodes {
        node.node.check_link_heartbeats().await;
        node.node.check_session_mmp_reports().await;
        node.node.check_session_rekey().await;
    }
    tokio::time::sleep(Duration::from_millis(20)).await;
}

async fn recover(nodes: &mut [TestNode], previous: [u8; 32]) -> [u8; 32] {
    let destination = *nodes[2].node.node_addr();
    tokio::time::timeout(Duration::from_secs(16), async {
        loop {
            tick(nodes).await;
            let hash = *nodes[0]
                .node
                .get_session(&destination)
                .unwrap()
                .handshake_hash()
                .unwrap();
            if hash != previous {
                return hash;
            }
        }
    })
    .await
    .expect("one unanswered request must still recover its keys")
}

async fn exercise(nodes: &mut [TestNode]) {
    populate_all_coord_caches(nodes);
    let identities = nodes
        .iter()
        .map(|node| PeerIdentity::from_pubkey_full(node.node.identity().pubkey_full()))
        .collect::<Vec<_>>();
    let mut endpoint = nodes[2].node.attach_endpoint_data_io(8).unwrap();
    for node in nodes.iter_mut() {
        node.node.config.node.heartbeat_interval_secs = 1;
        node.node.config.node.rekey.after_secs = u64::MAX;
        node.node.config.node.rekey.after_messages = u64::MAX;
    }
    // Only established reverse records are rejected. Ordinary Noise setup and
    // the payload-free confirmation retain their production control path.
    let reverse = Arc::new(NoReturnData::default());
    nodes[2]
        .node
        .set_originated_session_observer(Some(reverse.clone()));
    nodes[0]
        .node
        .initiate_session(*identities[2].node_addr(), identities[2].pubkey_full())
        .await
        .unwrap();
    for (index, other) in [(0, 2), (2, 0)] {
        wait_for_session_established(
            nodes,
            index,
            identities[other].node_addr(),
            Duration::from_secs(5),
            "idle recovery baseline",
        )
        .await;
    }
    settle_session_handshake_retransmits(
        nodes,
        0,
        identities[2].node_addr(),
        2,
        identities[0].node_addr(),
    );
    let initial = *nodes[0]
        .node
        .get_session(identities[2].node_addr())
        .unwrap()
        .handshake_hash()
        .unwrap();
    send_endpoint_data_via_dataplane(&mut nodes[0].node, identities[2], b"unanswered".to_vec())
        .await
        .unwrap();
    let event = recv_endpoint_event_while_draining(
        nodes,
        &mut endpoint.event_rx,
        Duration::from_secs(5),
        "initial one-way payload",
    )
    .await;
    assert_eq!(
        expect_single_endpoint_data_event(event).payload.as_slice(),
        b"unanswered"
    );
    let recovered = recover(nodes, initial).await;
    assert!(
        reverse.0.load(Ordering::Relaxed) > 0,
        "receiver reports must be rejected"
    );

    // Retain old-key traffic for the full production drain window before
    // checking whether the recovered but unanswered session stays idle.
    tokio::time::timeout(Duration::from_secs(50), async {
        while [(0, 2), (2, 0)].iter().any(|&(index, other)| {
            nodes[index]
                .node
                .get_session(identities[other].node_addr())
                .unwrap()
                .is_draining()
        }) {
            tick(nodes).await;
        }
    })
    .await
    .expect("the recovered epoch must finish its drain");
    nodes[0]
        .node
        .send_dataplane_fsp_coords_warmup(identities[2].node_addr())
        .await
        .unwrap();
    let until = tokio::time::Instant::now() + Duration::from_secs(7);
    while tokio::time::Instant::now() < until {
        tick(nodes).await;
        let entry = nodes[0]
            .node
            .get_session(identities[2].node_addr())
            .unwrap();
        assert!(
            entry.handshake_hash() == Some(&recovered)
                && !entry.has_rekey_in_progress()
                && entry.pending_new_session().is_none(),
            "idle session started another recovery without new application data: hash_changed={}, pending={}, initiator={}, {}; source_activity={:?}; recipient_activity={:?}",
            entry.handshake_hash() != Some(&recovered),
            entry.pending_new_session().is_some(),
            entry.is_rekey_handshake_initiator(),
            session_wait_snapshot(nodes, 0, identities[2].node_addr()),
            nodes[0]
                .node
                .dataplane
                .fsp_owner_activity(identities[2].node_addr()),
            nodes[2]
                .node
                .dataplane
                .fsp_owner_activity(identities[0].node_addr())
        );
    }
    let activity = nodes[0]
        .node
        .dataplane
        .fsp_owner_activity(identities[2].node_addr())
        .unwrap();
    assert!(
        activity.has_unacknowledged_outbound_from(
            &activity.last_outbound_next_hop().unwrap(),
            Node::now_ms(),
            5_000
        ),
        "key confirmation must not acknowledge application delivery"
    );

    // Healthy carrier heartbeats cannot repair a recipient that lost its keys.
    nodes[2]
        .node
        .remove_dataplane_fsp_owner(identities[0].node_addr());
    nodes[2]
        .node
        .remove_session(identities[0].node_addr())
        .unwrap();
    send_endpoint_data_via_dataplane(&mut nodes[0].node, identities[2], b"new request".to_vec())
        .await
        .unwrap();
    recover(nodes, recovered).await;
    send_endpoint_data_via_dataplane(&mut nodes[0].node, identities[2], b"usable again".to_vec())
        .await
        .unwrap();
    let event = recv_endpoint_event_while_draining(
        nodes,
        &mut endpoint.event_rx,
        Duration::from_secs(5),
        "delivery after renewed demand",
    )
    .await;
    assert_eq!(
        expect_single_endpoint_data_event(event).payload.as_slice(),
        b"usable again"
    );
}
