use std::time::Duration;

use peer_discovery::{
    backends::in_memory::InMemoryHub, DiscoverySet, LocalPeer, PeerEvent, ServiceAd, ServiceAddr,
};
use tokio::time::timeout;

fn peer(id_byte: u8, services: Vec<ServiceAd>) -> LocalPeer {
    LocalPeer {
        id: [id_byte; 32],
        services,
        display_name: Some(format!("peer-{id_byte}")),
    }
}

#[tokio::test(flavor = "current_thread")]
async fn two_peers_see_each_other_via_shared_hub() {
    let hub = InMemoryHub::new();

    // Peer A advertises fips-fmp; Peer B advertises hashtree.
    let a_local = peer(
        1,
        vec![ServiceAd::new("fips-fmp")
            .with_addr(ServiceAddr::Udp("127.0.0.1:5555".parse().unwrap()))],
    );
    let b_local = peer(
        2,
        vec![ServiceAd::new("hashtree").with_txt("repo", "demo")],
    );

    let (mut a_events, _a_handle) = DiscoverySet::new()
        .register(hub.discovery())
        .start(a_local, vec!["hashtree".into()])
        .await
        .expect("start A");

    let (mut b_events, _b_handle) = DiscoverySet::new()
        .register(hub.discovery())
        .start(b_local, vec!["fips-fmp".into()])
        .await
        .expect("start B");

    let a_saw = timeout(Duration::from_millis(500), a_events.recv())
        .await
        .expect("A timed out")
        .expect("A channel closed");
    match a_saw {
        PeerEvent::Up(p) => {
            assert_eq!(p.id, [2u8; 32]);
            assert_eq!(p.services.len(), 1);
            assert_eq!(p.services[0].tag, "hashtree");
            assert_eq!(p.services[0].txt.get("repo").map(String::as_str), Some("demo"));
        }
        other => panic!("expected Up, got {other:?}"),
    }

    let b_saw = timeout(Duration::from_millis(500), b_events.recv())
        .await
        .expect("B timed out")
        .expect("B channel closed");
    match b_saw {
        PeerEvent::Up(p) => {
            assert_eq!(p.id, [1u8; 32]);
            assert_eq!(p.services.len(), 1);
            assert_eq!(p.services[0].tag, "fips-fmp");
        }
        other => panic!("expected Up, got {other:?}"),
    }
}

#[tokio::test(flavor = "current_thread")]
async fn empty_watch_means_match_everything() {
    let hub = InMemoryHub::new();
    let a_local = peer(10, vec![ServiceAd::new("anything")]);
    let b_local = peer(11, vec![ServiceAd::new("else")]);

    let (mut a_events, _a) = DiscoverySet::new()
        .register(hub.discovery())
        .start(a_local, vec![])
        .await
        .unwrap();
    let (_b_events, _b) = DiscoverySet::new()
        .register(hub.discovery())
        .start(b_local, vec![])
        .await
        .unwrap();

    let ev = timeout(Duration::from_millis(500), a_events.recv())
        .await
        .unwrap()
        .unwrap();
    match ev {
        PeerEvent::Up(p) => assert_eq!(p.id, [11u8; 32]),
        other => panic!("expected Up, got {other:?}"),
    }
}

#[tokio::test(flavor = "current_thread")]
async fn drop_handle_emits_down() {
    let hub = InMemoryHub::new();
    let a_local = peer(20, vec![ServiceAd::new("svc")]);
    let b_local = peer(21, vec![ServiceAd::new("svc")]);

    let (mut a_events, _a) = DiscoverySet::new()
        .register(hub.discovery())
        .start(a_local, vec!["svc".into()])
        .await
        .unwrap();
    let (_b_events, b_handle) = DiscoverySet::new()
        .register(hub.discovery())
        .start(b_local, vec!["svc".into()])
        .await
        .unwrap();

    // First event from A is the Up for B.
    let _ = timeout(Duration::from_millis(500), a_events.recv())
        .await
        .unwrap()
        .unwrap();

    drop(b_handle);

    let ev = timeout(Duration::from_millis(500), a_events.recv())
        .await
        .expect("expected Down")
        .unwrap();
    match ev {
        PeerEvent::Down { id, source } => {
            assert_eq!(id, [21u8; 32]);
            assert_eq!(source, "in-memory");
        }
        other => panic!("expected Down, got {other:?}"),
    }
}
