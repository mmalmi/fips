use fips_core::{
    Config, FipsEndpoint, PeerIdentity,
    config::{PeerConfig, TransportInstances, UdpConfig},
};
use fips_relay::{
    control_transport::ControlTransport,
    ledger::ChannelTerms,
    route_quotes::{QuotePolicy, QuoteRequest, QuoteResponse, QuoteServer, RouteQuotes},
};
use std::{sync::Arc, time::Duration};

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn prices_follow_native_next_hops_and_accumulate_over_neighbor_control() {
    tokio::time::timeout(Duration::from_secs(50), async {
        let mut nodes = Vec::new();
        let mut addresses = Vec::new();
        for _ in 0..5 {
            let mut config = Config::new();
            config.node.control.enabled = false;
            config.node.discovery.nostr.enabled = false;
            config.node.discovery.lan.enabled = false;
            config.node.discovery.local.enabled = false;
            config.transports.udp = TransportInstances::Single(UdpConfig {
                bind_addr: Some("127.0.0.1:0".into()),
                advertise_on_nostr: Some(false),
                ..UdpConfig::default()
            });
            let node = Arc::new(
                FipsEndpoint::builder()
                    .config(config)
                    .without_system_tun()
                    .bind()
                    .await
                    .unwrap(),
            );
            addresses.push(node.bound_udp_listen_addrs().await.unwrap()[0]);
            nodes.push(node);
        }
        let peers: Vec<_> = nodes
            .iter()
            .map(|n| PeerIdentity::from_npub(n.npub()).unwrap())
            .collect();
        for (i, node) in nodes.iter().enumerate() {
            node.update_peers(
                peers
                    .iter()
                    .enumerate()
                    .filter(|(j, _)| i.abs_diff(*j) == 1)
                    .map(|(j, _)| PeerConfig::new(nodes[j].npub(), "udp", addresses[j].to_string()))
                    .collect(),
            )
            .await
            .unwrap();
        }
        let mut quotes = Vec::new();
        let mut servers = Vec::new();
        for (i, node) in nodes.iter().enumerate() {
            let neighbors = peers
                .iter()
                .enumerate()
                .filter(|(j, _)| i.abs_diff(*j) == 1)
                .map(|(_, p)| *p)
                .collect();
            let (control, incoming) =
                ControlTransport::start(node.clone(), 44_730, neighbors, i as u64 + 20)
                    .await
                    .unwrap();
            let service = Arc::new(
                RouteQuotes::new(
                    node.clone(),
                    Arc::new(control),
                    QuotePolicy {
                        destination_fees: Default::default(),
                        billing: Default::default(),
                        mint_url: "http://test.invalid".into(),
                        receiver_pubkey_hex: "02".to_owned() + &"11".repeat(32),
                        fee_msat_per_kib: 1_024,
                        max_rate_msat_per_kib: 8_192,
                        lifetime_secs: 120,
                        max_units: 20_000,
                        capacity_sat: 32,
                        grace_msat: 16_384,
                    },
                )
                .unwrap(),
            );
            servers.push(QuoteServer::start(service.clone(), incoming));
            quotes.push(service);
        }
        tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                let mut connected = 0;
                for n in &nodes {
                    connected += n
                        .peers()
                        .await
                        .unwrap()
                        .iter()
                        .filter(|p| p.connected)
                        .count();
                }
                if connected == 8 {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .unwrap();
        // Start both directions together to exercise nested quote requests while
        // each node is also receiving another neighbor's request.
        let (forward, reverse) = tokio::join!(
            quotes[0].request_route(peers[4]),
            quotes[4].request_route(peers[0])
        );
        for (source, destination, offer) in
            [(0usize, 4usize, forward.unwrap()), (4, 0, reverse.unwrap())]
        {
            assert_eq!(offer.buyer, *peers[source].node_addr());
            assert_eq!(offer.destination, peers[destination]);
            assert_eq!(offer.price.msat, 3_072);
            assert_eq!(offer.price.per_bytes, 1_024);
            assert_eq!(
                offer.path.len(),
                4,
                "three paid routers and final destination"
            );
            let expected: Vec<_> = if source == 0 {
                (1..=4).collect()
            } else {
                (0..4).rev().collect()
            };
            assert_eq!(
                offer.path,
                expected
                    .iter()
                    .map(|i| *peers[*i].node_addr())
                    .collect::<Vec<_>>()
            );
            let provider = if source == 0 { 1 } else { 3 };
            if source == 0 {
                for _ in 0..32 {
                    let refreshed = quotes[source]
                        .refresh_route(peers[destination])
                        .await
                        .unwrap();
                    assert_eq!(
                        refreshed, offer,
                        "monitoring must reuse unchanged quotes past the per-buyer offer limit"
                    );
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
                assert_ne!(
                    quotes[source]
                        .request_route(peers[destination])
                        .await
                        .unwrap()
                        .id,
                    offer.id,
                    "an explicit fresh purchase still gets a fresh offer"
                );
            }
            let retained = quotes[provider]
                .retained_offer(peers[source], &offer.id)
                .unwrap();
            assert_eq!(retained, offer);
            assert!(
                quotes[provider]
                    .retained_offer(peers[destination], &offer.id)
                    .is_err()
            );
            let downstream = quotes[provider]
                .downstream_offer(peers[source], &offer.id)
                .unwrap()
                .unwrap();
            assert_eq!(downstream.price.msat, 2_048);
            assert!(downstream.expires_unix >= offer.expires_unix);
            assert!(quotes[provider].route_still_matches(&offer).await.unwrap());
            let channel = ChannelTerms {
                id: format!("test-channel-{source}"),
                buyer: *peers[source].node_addr(),
                mint_url: offer.mint_url.clone(),
                expires_unix: offer.expires_unix + 60,
                capacity_sat: offer.capacity_sat,
                grace_msat: offer.grace_msat,
            };
            let bound = quotes[provider]
                .bind_offer(peers[source], &offer.id, &channel)
                .unwrap();
            assert_eq!(bound.price, offer.price);
            assert_eq!(bound.next_hop, offer.next_hop);
            assert_eq!(
                bound,
                quotes[provider]
                    .bind_offer(peers[source], &offer.id, &channel)
                    .unwrap()
            );
            let mut changed = channel;
            changed.grace_msat += 1;
            assert!(
                quotes[provider]
                    .bind_offer(peers[source], &offer.id, &changed)
                    .is_err()
            );
            let mut changed = offer.clone();
            changed.price.msat += 1;
            assert!(
                !quotes[provider]
                    .route_still_matches(&changed)
                    .await
                    .unwrap()
            );
        }
        let deadline_unix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 10;
        let invalid = QuoteRequest {
            destination: peers[4],
            ancestors: vec![*peers[1].node_addr(), *peers[0].node_addr()],
            deadline_unix,
            reuse_unchanged: false,
            requested_max_units: None,
        };
        assert!(matches!(
            quotes[1]
                .handle(peers[0], &serde_json::to_vec(&invalid).unwrap())
                .await,
            QuoteResponse::Rejected
        ));
        for (i, node) in nodes.iter().enumerate() {
            for peer in node.peers().await.unwrap().iter().filter(|p| p.connected) {
                assert!(
                    peers
                        .iter()
                        .enumerate()
                        .any(|(j, p)| i.abs_diff(j) == 1 && p.node_addr() == &peer.node_addr)
                );
            }
        }
        for server in servers {
            server.stop().await;
        }
        drop(quotes);
        for node in nodes {
            node.shutdown().await.unwrap();
        }
    })
    .await
    .expect("bounded native quote test");
}
