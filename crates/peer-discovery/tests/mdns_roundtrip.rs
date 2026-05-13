#![cfg(feature = "mdns")]

//! End-to-end mDNS roundtrip. Two `MdnsDiscovery` instances in the same
//! process advertise distinct services and watch each other's tags. The test
//! is `#[ignore]`d by default because it joins the real mDNS multicast group
//! and is sensitive to sandbox/firewall policy; run with
//! `cargo test -p peer-discovery --features mdns -- --ignored`.

use std::net::SocketAddr;
use std::time::Duration;

use peer_discovery::{
    backends::mdns::{MdnsConfig, MdnsDiscovery},
    DiscoverySet, LocalPeer, PeerEvent, ServiceAd, ServiceAddr,
};
use tokio::time::timeout;

fn local_peer(id_byte: u8, tag: &'static str, port: u16) -> LocalPeer {
    LocalPeer {
        id: [id_byte; 32],
        services: vec![ServiceAd::new(tag).with_addr(ServiceAddr::Udp(
            SocketAddr::from(([127, 0, 0, 1], port)),
        ))],
        display_name: Some(format!("peer-{id_byte}")),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore]
async fn two_mdns_peers_see_each_other() {
    // Unique tags per run so concurrent test invocations / lingering caches
    // don't bleed observations across runs.
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let tag_a: &'static str = Box::leak(format!("pdtesta{nonce}").into_boxed_str());
    let tag_b: &'static str = Box::leak(format!("pdtestb{nonce}").into_boxed_str());

    let a_local = local_peer(0xA1, tag_a, 51001);
    let b_local = local_peer(0xB2, tag_b, 51002);

    let (mut a_events, _a) = DiscoverySet::new()
        .register(MdnsDiscovery::new(MdnsConfig::default()))
        .start(a_local, vec![tag_b.into()])
        .await
        .expect("start A");

    let (mut b_events, _b) = DiscoverySet::new()
        .register(MdnsDiscovery::new(MdnsConfig::default()))
        .start(b_local, vec![tag_a.into()])
        .await
        .expect("start B");

    let saw_b = timeout(Duration::from_secs(5), wait_for_up(&mut a_events, [0xB2; 32]))
        .await
        .expect("A timed out");
    assert_eq!(saw_b.id, [0xB2; 32]);
    assert!(!saw_b.services.is_empty());
    assert_eq!(saw_b.services[0].tag, tag_b);

    let saw_a = timeout(Duration::from_secs(5), wait_for_up(&mut b_events, [0xA1; 32]))
        .await
        .expect("B timed out");
    assert_eq!(saw_a.id, [0xA1; 32]);
    assert_eq!(saw_a.services[0].tag, tag_a);
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
