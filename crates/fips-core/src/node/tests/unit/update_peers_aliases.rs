use super::*;

#[tokio::test]
async fn update_peers_moves_alias_acl_and_retains_hosts_overrides() {
    use crate::node::acl::{PeerAclDecision, PeerAclReloader};
    use crate::upper::hosts::HostMap;

    let mut node = make_node();
    let old = Identity::generate();
    let new = Identity::generate();
    let override_id = Identity::generate();
    let mut original = auto_connect_peer(old.npub(), "127.0.0.1:9");
    original.alias = Some("blocked".into());
    node.update_peers(vec![original.clone()]).await.unwrap();

    let dir = tempfile::tempdir().unwrap();
    let allow = dir.path().join("peers.allow");
    let deny = dir.path().join("peers.deny");
    let hosts = dir.path().join("hosts");
    std::fs::write(&deny, "blocked\n").unwrap();
    std::fs::write(&hosts, format!("override {}\n", override_id.npub())).unwrap();
    node.peer_acl = PeerAclReloader::with_alias_sources(
        allow,
        deny,
        HostMap::from_peer_configs(&[original]),
        hosts,
    );
    let old_peer = PeerIdentity::from_npub(&old.npub()).unwrap();
    let new_peer = PeerIdentity::from_npub(&new.npub()).unwrap();
    assert_eq!(
        node.peer_acl.acl().check(&old_peer),
        PeerAclDecision::DenyList
    );

    let mut moved = auto_connect_peer(new.npub(), "127.0.0.1:9");
    moved.alias = Some("blocked".into());
    let mut overridden = auto_connect_peer(old.npub(), "127.0.0.1:10");
    overridden.alias = Some("override".into());
    node.update_peers(vec![moved, overridden]).await.unwrap();

    assert_eq!(
        node.peer_acl.acl().check(&new_peer),
        PeerAclDecision::DenyList
    );
    assert_eq!(
        node.peer_acl.acl().check(&old_peer),
        PeerAclDecision::DefaultAllow
    );
    assert_eq!(
        node.host_map.lookup_npub("blocked"),
        Some(new.npub().as_str())
    );
    assert_eq!(
        node.host_map.lookup_npub("override"),
        Some(override_id.npub().as_str())
    );
    assert!(
        !node.reload_peer_acl(),
        "unchanged inputs must not rebuild on each tick"
    );

    node.update_peers(Vec::new()).await.unwrap();
    assert_eq!(node.host_map.lookup_npub("blocked"), None);
    assert_eq!(
        node.host_map.lookup_npub("override"),
        Some(override_id.npub().as_str())
    );
}

#[tokio::test]
async fn update_peers_refreshes_running_dns_answers() {
    use crate::upper::hosts::{HostMap, HostMapReloader};
    use simple_dns::{CLASS, Name, Packet, QCLASS, QTYPE, Question, TYPE, rdata::RData};

    for file_backed in [false, true] {
        let mut node = make_node();
        let old = Identity::generate();
        let new = Identity::generate();
        let dir = tempfile::tempdir().unwrap();
        let hosts = dir.path().join("hosts");
        std::fs::write(&hosts, format!("pinned {}\n", old.npub())).unwrap();
        let reloader = if file_backed {
            HostMapReloader::new(HostMap::new(), hosts)
        } else {
            HostMapReloader::memory_only(HostMap::new())
        };
        let (alias_tx, alias_rx) = tokio::sync::watch::channel(HostMap::new());
        node.dns_alias_tx = Some(alias_tx);
        let server = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let address = server.local_addr().unwrap();
        let (identity_tx, _identity_rx) = tokio::sync::mpsc::channel(16);
        let task = tokio::spawn(crate::upper::dns::run_dns_responder(
            server,
            identity_tx,
            300,
            reloader.with_base_updates(alias_rx),
            None,
        ));
        let client = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();

        let mut original = auto_connect_peer(old.npub(), "127.0.0.1:9");
        original.alias = Some("service".into());
        let mut moved = auto_connect_peer(new.npub(), "127.0.0.1:9");
        moved.alias = Some("service".into());
        let removed_alias = auto_connect_peer(new.npub(), "127.0.0.1:9");

        for (peers, expected) in [
            (vec![original], Some(old.address().to_ipv6())),
            (vec![moved], Some(new.address().to_ipv6())),
            (vec![removed_alias], None),
            (Vec::new(), None),
        ] {
            node.update_peers(peers).await.unwrap();
            for (name, expected) in [
                ("service.fips", expected),
                ("pinned.fips", file_backed.then(|| old.address().to_ipv6())),
            ] {
                let mut query = Packet::new_query(0x1234);
                query.questions.push(Question::new(
                    Name::new_unchecked(name).into_owned(),
                    QTYPE::TYPE(TYPE::AAAA),
                    QCLASS::CLASS(CLASS::IN),
                    false,
                ));
                client
                    .send_to(&query.build_bytes_vec().unwrap(), address)
                    .await
                    .unwrap();
                let mut buf = [0; 512];
                let (len, _) =
                    tokio::time::timeout(Duration::from_secs(2), client.recv_from(&mut buf))
                        .await
                        .unwrap()
                        .unwrap();
                let response = Packet::parse(&buf[..len]).unwrap();
                let actual = response
                    .answers
                    .iter()
                    .find_map(|answer| match &answer.rdata {
                        RData::AAAA(aaaa) => Some(std::net::Ipv6Addr::from(aaaa.address)),
                        _ => None,
                    });
                assert_eq!(actual, expected, "{name}, file_backed={file_backed}");
            }
        }
        task.abort();
        let _ = task.await;
    }
}
