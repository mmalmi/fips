use super::*;
use fips_core::{
    Config,
    config::{PeerConfig, TransportInstances, UdpConfig},
};

fn config() -> Config {
    let mut config = Config::new();
    config.node.discovery.nostr.enabled = false;
    config.node.discovery.lan.enabled = false;
    config.node.discovery.local.enabled = false;
    config.transports.udp = TransportInstances::Single(UdpConfig {
        bind_addr: Some("127.0.0.1:0".into()),
        advertise_on_nostr: Some(false),
        ..UdpConfig::default()
    });
    config
}

async fn attach(entry: &Arc<FipsEndpoint>) -> Arc<FipsEndpoint> {
    let mut config = config();
    let address = entry.bound_udp_listen_addrs().await.unwrap()[0];
    config
        .peers
        .push(PeerConfig::new(entry.npub(), "udp", address.to_string()));
    Arc::new(
        FipsEndpoint::builder()
            .config(config)
            .identity_nsec("42".repeat(32))
            .without_system_tun()
            .bind()
            .await
            .unwrap(),
    )
}

async fn connected(entry: &FipsEndpoint, peer: PeerIdentity, expected: bool) {
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let active = entry
                .peers()
                .await
                .unwrap()
                .iter()
                .any(|p| p.connected && p.node_addr == *peer.node_addr());
            if active == expected {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn existing_permits_recheck_adjacency_and_reconnect_keeps_identity_budgets() {
    tokio::time::timeout(Duration::from_secs(30), async {
        let entry = Arc::new(
            FipsEndpoint::builder()
                .config(config())
                .without_system_tun()
                .bind()
                .await
                .unwrap(),
        );
        let remote = attach(&entry).await;
        let peer = PeerIdentity::from_npub(remote.npub()).unwrap();
        connected(&entry, peer, true).await;
        let admission = ControlAdmission::new(
            entry.clone(),
            vec![],
            None,
            NeighborAdmission::AuthenticatedAdjacent,
        )
        .unwrap();
        admission
            .bind_obligations(ControlObligations::for_test(
                *entry.node_addr(),
                [*peer.node_addr()],
            ))
            .unwrap();
        let incoming = admission.admit(peer, false).await.unwrap();
        let queued = admission.admit(peer, true).await.unwrap();
        incoming.recheck().await.unwrap();
        queued.recheck().await.unwrap();
        assert_eq!(admission.unconfigured.available_permits(), 8);
        assert_eq!(admission.obligation_slots.available_permits(), 6);
        remote.shutdown().await.unwrap();
        connected(&entry, peer, false).await;
        // These are the same guards invoked before an unsent connection and
        // before dispatching a fully received record to the financial handler.
        assert!(incoming.recheck().await.is_err());
        assert!(queued.recheck().await.is_err());
        let replacement = attach(&entry).await;
        assert_eq!(replacement.npub(), remote.npub());
        connected(&entry, peer, true).await;
        incoming.recheck().await.unwrap();
        queued.recheck().await.unwrap();
        {
            let state = admission.state.lock().unwrap();
            assert_eq!(state.peers.len(), 1);
            let saved = &state.peers[peer.node_addr()];
            assert_eq!(saved.incoming.tokens, ADMISSION_BURST - 1);
            assert_eq!(saved.outgoing.tokens, ADMISSION_BURST - 1);
            assert_eq!(saved.active, 2);
        }
        drop((incoming, queued));
        assert_eq!(admission.unconfigured.available_permits(), 8);
        assert_eq!(admission.obligation_slots.available_permits(), 8);
        assert_eq!(
            admission.state.lock().unwrap().peers[peer.node_addr()].active,
            0
        );
        replacement.shutdown().await.unwrap();
        entry.shutdown().await.unwrap();
    })
    .await
    .expect("admission reconnect deadline");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn verified_obligations_have_bounded_capacity_even_when_newcomer_resources_are_full() {
    let entry = Arc::new(
        FipsEndpoint::builder()
            .config(config())
            .without_system_tun()
            .bind()
            .await
            .unwrap(),
    );
    let remote = attach(&entry).await;
    let peer = PeerIdentity::from_npub(remote.npub()).unwrap();
    connected(&entry, peer, true).await;
    let admission = ControlAdmission::new(
        entry.clone(),
        vec![],
        None,
        NeighborAdmission::AuthenticatedAdjacent,
    )
    .unwrap();
    let newcomers = admission
        .unconfigured
        .clone()
        .acquire_many_owned(8)
        .await
        .unwrap();
    {
        let mut state = admission.state.lock().unwrap();
        let now = Instant::now();
        for _ in 0..AGGREGATE_BURST {
            assert!(state.aggregate.allow(now));
        }
        state.aggregate.updated = now + Duration::from_secs(10);
        for n in 1..=64u8 {
            let id = super::tests::peer(n);
            assert_ne!(id, *peer.node_addr());
            assert!(state.admit_peer(id, false, now, false));
        }
    }
    assert!(admission.admit(peer, false).await.is_err());
    admission
        .bind_obligations(ControlObligations::for_test(
            *entry.node_addr(),
            [*peer.node_addr()],
        ))
        .unwrap();
    let mut held = Vec::new();
    for outgoing in [false, true, false, true] {
        held.push(admission.admit(peer, outgoing).await.unwrap());
    }
    assert_eq!(admission.obligation_slots.available_permits(), 4);
    assert!(admission.admit(peer, false).await.is_err());
    assert!(admission.admit(peer, true).await.is_err());
    let tokens = {
        let state = admission.state.lock().unwrap();
        let budget = &state.peers[peer.node_addr()];
        assert_eq!(state.peers.len(), 65);
        (budget.incoming.tokens, budget.outgoing.tokens)
    };
    // Rebinding after a controller reload only changes the authoritative view.
    admission
        .bind_obligations(ControlObligations::for_test(
            *entry.node_addr(),
            [*peer.node_addr()],
        ))
        .unwrap();
    {
        let state = admission.state.lock().unwrap();
        let budget = &state.peers[peer.node_addr()];
        assert_eq!((budget.incoming.tokens, budget.outgoing.tokens), tokens);
        assert_eq!(budget.active, 4);
    }
    drop(held);
    assert_eq!(admission.obligation_slots.available_permits(), 8);
    admission
        .bind_obligations(ControlObligations::for_test(*entry.node_addr(), []))
        .unwrap();
    assert!(
        admission.admit(peer, false).await.is_err(),
        "retired obligations cannot bypass the full ordinary pool"
    );
    drop(newcomers);
    assert!(
        admission
            .admit(peer, false)
            .await
            .err()
            .unwrap()
            .contains("request budget")
    );
    admission
        .bind_obligations(ControlObligations::for_test(
            *entry.node_addr(),
            [*peer.node_addr()],
        ))
        .unwrap();
    drop(admission.admit(peer, false).await.unwrap());
    {
        let mut state = admission.state.lock().unwrap();
        state.obligation_aggregate.tokens = 0;
        state.obligation_aggregate.updated = Instant::now() + Duration::from_secs(10);
    }
    assert!(
        admission
            .admit(peer, false)
            .await
            .err()
            .unwrap()
            .contains("request budget")
    );
    remote.shutdown().await.unwrap();
    entry.shutdown().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn financial_protection_does_not_authorize_outbound_customer_control() {
    let entry = Arc::new(
        FipsEndpoint::builder()
            .config(config())
            .without_system_tun()
            .bind()
            .await
            .unwrap(),
    );
    let remote = attach(&entry).await;
    let peer = PeerIdentity::from_npub(remote.npub()).unwrap();
    connected(&entry, peer, true).await;
    let admission = ControlAdmission::new(
        entry.clone(),
        vec![],
        Some("127.0.0.0/8".parse().unwrap()),
        NeighborAdmission::AuthenticatedAdjacent,
    )
    .unwrap();
    assert!(
        admission
            .bind_obligations(ControlObligations::for_test(*remote.node_addr(), []))
            .is_err()
    );
    admission
        .bind_obligations(ControlObligations::for_test(
            *entry.node_addr(),
            [*peer.node_addr()],
        ))
        .unwrap();
    assert!(admission.admit(peer, true).await.is_err());
    let permit = admission.admit(peer, false).await.unwrap();
    permit.recheck().await.unwrap();
    assert_eq!(admission.obligation_slots.available_permits(), 7);
    drop(permit);
    remote.shutdown().await.unwrap();
    entry.shutdown().await.unwrap();
}
