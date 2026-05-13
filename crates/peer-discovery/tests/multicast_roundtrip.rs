#![cfg(feature = "multicast")]

//! Two `MulticastDiscovery` instances on the same host send periodic UDP
//! multicast announcements, see each other, then time out into `Down` after
//! one peer stops announcing.
//!
//! Marked `#[ignore]` because it joins a real multicast group; run with
//! `cargo test -p peer-discovery --features multicast -- --ignored`.

use std::time::Duration;

use peer_discovery::{
    backends::multicast::{MulticastConfig, MulticastDiscovery},
    DiscoverySet, LocalPeer, PeerEvent, ServiceAd,
};
use tokio::time::timeout;

fn local_peer(id_byte: u8, tag: &'static str) -> LocalPeer {
    LocalPeer {
        id: [id_byte; 32],
        services: vec![ServiceAd::new(tag).with_txt("k", "v")],
        display_name: Some(format!("peer-{id_byte}")),
    }
}

fn cfg(port: u16, announce_every_ms: u64, stale_after_ms: u64) -> MulticastConfig {
    MulticastConfig {
        port,
        announce_every: Duration::from_millis(announce_every_ms),
        stale_after: Duration::from_millis(stale_after_ms),
        ..MulticastConfig::default()
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore]
async fn two_peers_see_each_other_then_one_goes_stale() {
    // Unique port per run to avoid collisions with other test invocations
    // and lingering sockets.
    let port = 39_000
        + (std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u16
            % 1000);

    let a_local = local_peer(0xA1, "fips-fmp");
    let b_local = local_peer(0xB2, "fips-fmp");

    let (mut a_events, _a) = DiscoverySet::new()
        .register(MulticastDiscovery::new(cfg(port, 200, 1500)))
        .start(a_local, vec!["fips-fmp".into()])
        .await
        .expect("start A");

    let (_b_events, b_handle) = DiscoverySet::new()
        .register(MulticastDiscovery::new(cfg(port, 200, 1500)))
        .start(b_local, vec!["fips-fmp".into()])
        .await
        .expect("start B");

    // A sees B come up.
    let saw = timeout(Duration::from_secs(3), wait_for_up(&mut a_events, [0xB2; 32]))
        .await
        .expect("A did not see B in time");
    assert_eq!(saw.id, [0xB2; 32]);
    assert_eq!(saw.services[0].tag, "fips-fmp");
    assert_eq!(saw.services[0].txt.get("k").map(String::as_str), Some("v"));
    assert_eq!(saw.display_name.as_deref(), Some("peer-178"));

    // B stops announcing; A should report Down within ~stale_after.
    drop(b_handle);
    let down = timeout(
        Duration::from_secs(5),
        wait_for_down(&mut a_events, [0xB2; 32]),
    )
    .await
    .expect("A did not stale-out B in time");
    assert_eq!(down, [0xB2; 32]);
}

async fn wait_for_up(
    rx: &mut tokio::sync::mpsc::Receiver<PeerEvent>,
    want_id: [u8; 32],
) -> peer_discovery::DiscoveredPeer {
    loop {
        match rx.recv().await.expect("channel closed") {
            PeerEvent::Up(p) if p.id == want_id => return p,
            _ => continue,
        }
    }
}

async fn wait_for_down(
    rx: &mut tokio::sync::mpsc::Receiver<PeerEvent>,
    want_id: [u8; 32],
) -> [u8; 32] {
    loop {
        match rx.recv().await.expect("channel closed") {
            PeerEvent::Down { id, .. } if id == want_id => return id,
            _ => continue,
        }
    }
}
