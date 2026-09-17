use fips_core::{
    Config, FipsEndpoint, PeerIdentity,
    config::{PeerConfig, TransportInstances, UdpConfig},
};
use fips_relay::control_transport::ControlTransport;
use std::{sync::Arc, time::Duration};

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

async fn pair() -> (Arc<FipsEndpoint>, Arc<FipsEndpoint>) {
    let a = Arc::new(
        FipsEndpoint::builder()
            .config(config())
            .without_system_tun()
            .bind()
            .await
            .unwrap(),
    );
    let b = attach(&a).await;
    (a, b)
}

async fn attach(a: &Arc<FipsEndpoint>) -> Arc<FipsEndpoint> {
    let addr = a.bound_udp_listen_addrs().await.unwrap()[0];
    let mut b_config = config();
    b_config
        .peers
        .push(PeerConfig::new(a.npub(), "udp", addr.to_string()));
    let b = Arc::new(
        FipsEndpoint::builder()
            .config(b_config)
            .without_system_tun()
            .bind()
            .await
            .unwrap(),
    );
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if b.peers()
                .await
                .unwrap()
                .iter()
                .any(|p| p.connected && p.npub == a.npub())
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    b
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn full_neighbor_slots_do_not_block_other_peers_or_fail_queued_control() {
    tokio::time::timeout(Duration::from_secs(20), async {
        let (a, b) = pair().await;
        let c = attach(&a).await;
        let alice = PeerIdentity::from_npub(a.npub()).unwrap();
        let bob = PeerIdentity::from_npub(b.npub()).unwrap();
        let charlie = PeerIdentity::from_npub(c.npub()).unwrap();
        let (first, _a_requests) =
            ControlTransport::start(a.clone(), 44_710, vec![bob, charlie], 1)
                .await
                .unwrap();
        let (second, mut b_requests) = ControlTransport::start(b.clone(), 44_710, vec![alice], 2)
            .await
            .unwrap();
        let (third, mut c_requests) = ControlTransport::start(c.clone(), 44_710, vec![alice], 3)
            .await
            .unwrap();
        let first = Arc::new(first);
        let request = |peer, byte| {
            let client = first.clone();
            tokio::spawn(async move { client.request(peer, vec![byte]).await })
        };
        let mut jobs = Vec::new();
        let mut held = Vec::new();
        for byte in 0..4 {
            jobs.push(request(bob, byte));
            held.push(b_requests.recv().await.unwrap());
        }
        let mut canceled = request(bob, 4);
        assert!(
            tokio::time::timeout(Duration::from_millis(200), &mut canceled)
                .await
                .is_err(),
            "a full neighbor must queue before connecting, not fail the request"
        );
        canceled.abort();
        assert!(canceled.await.unwrap_err().is_cancelled());
        let queued = request(bob, 5);
        let healthy = request(charlie, 6);
        let answer = tokio::time::timeout(Duration::from_secs(2), c_requests.recv())
            .await
            .unwrap()
            .unwrap();
        answer.respond.send(answer.body).unwrap();
        assert_eq!(healthy.await.unwrap().unwrap(), vec![6]);
        assert_eq!(second.statistics().snapshot().requests_received, 4);
        let released = held.remove(0);
        released.respond.send(released.body).unwrap();
        let answer = tokio::time::timeout(Duration::from_secs(2), b_requests.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            answer.body,
            vec![5],
            "the canceled queued request must never be sent"
        );
        answer.respond.send(answer.body).unwrap();
        assert_eq!(queued.await.unwrap().unwrap(), vec![5]);
        for request in held {
            request.respond.send(request.body).unwrap();
        }
        for (byte, job) in jobs.into_iter().enumerate() {
            assert_eq!(job.await.unwrap().unwrap(), vec![byte as u8]);
        }
        assert_eq!(first.statistics().snapshot().requests_started, 6);
        drop((first, second, third));
        a.shutdown().await.unwrap();
        b.shutdown().await.unwrap();
        c.shutdown().await.unwrap();
    })
    .await
    .expect("closing streams must release slots within the bounded request deadline");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn authenticated_neighbor_control_carries_large_records_and_isolates_rejections() {
    tokio::time::timeout(Duration::from_secs(40), async {
        let (a, b) = pair().await;
        let alice = PeerIdentity::from_npub(a.npub()).unwrap();
        let bob = PeerIdentity::from_npub(b.npub()).unwrap();
        let (first, mut first_incoming) = ControlTransport::start(a.clone(), 44_710, vec![bob], 1)
            .await
            .unwrap();
        let (second, mut second_incoming) =
            ControlTransport::start(b.clone(), 44_710, vec![alice], 2)
                .await
                .unwrap();
        let responder = tokio::spawn(async move {
            let request = second_incoming.recv().await.unwrap();
            assert_eq!(request.peer, alice);
            assert_eq!(request.body, vec![42; 24_000]);
            request.respond.send(vec![51; 20_000]).unwrap();
            // Dropping the next responder must release only its own stream.
            drop(second_incoming.recv().await.unwrap());
            let next = second_incoming.recv().await.unwrap();
            next.respond.send(b"recovered".to_vec()).unwrap();
        });
        let reply = first.request(bob, vec![42; 24_000]).await.unwrap();
        assert_eq!(reply, vec![51; 20_000]);
        let first_sample = first.statistics().snapshot();
        let second_sample = second.statistics().snapshot();
        assert_eq!(first_sample.stream_bytes_sent, 24_004);
        assert_eq!(first_sample.stream_bytes_received, 20_004);
        assert_eq!(second_sample.stream_bytes_sent, 20_004);
        assert_eq!(second_sample.stream_bytes_received, 24_004);
        assert_eq!(first_sample.requests_started, 1);
        assert_eq!(second_sample.requests_received, 1);
        assert!(first.request(bob, vec![0; 65_537]).await.is_err());
        assert_eq!(
            first.statistics().snapshot(),
            first_sample,
            "rejected oversized records consume no stream bytes"
        );
        assert!(first.request(bob, b"cancel".to_vec()).await.is_err());
        assert_eq!(
            first.request(bob, b"retry".to_vec()).await.unwrap(),
            b"recovered"
        );
        responder.await.unwrap();
        let reverse = tokio::spawn(async move {
            let request = first_incoming.recv().await.unwrap();
            assert_eq!(request.peer, bob);
            request.respond.send(b"reverse".to_vec()).unwrap();
        });
        assert_eq!(
            second.request(alice, b"back".to_vec()).await.unwrap(),
            b"reverse"
        );
        reverse.await.unwrap();
        drop(first);
        drop(second);
        a.shutdown().await.unwrap();
        b.shutdown().await.unwrap();
    })
    .await
    .expect("control record deadline");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn control_service_rejects_an_identity_outside_its_configured_neighbors() {
    tokio::time::timeout(Duration::from_secs(15), async {
        let (a, b) = pair().await;
        let alice = PeerIdentity::from_npub(a.npub()).unwrap();
        let (first, mut incoming) = ControlTransport::start(a.clone(), 44_711, vec![], 3)
            .await
            .unwrap();
        let (second, _unused) = ControlTransport::start(b.clone(), 44_711, vec![alice], 4)
            .await
            .unwrap();
        assert!(second.request(alice, b"uninvited".to_vec()).await.is_err());
        assert!(incoming.try_recv().is_err());
        assert!(
            first
                .request(alice, b"not-neighbor".to_vec())
                .await
                .is_err()
        );
        drop(first);
        drop(second);
        a.shutdown().await.unwrap();
        b.shutdown().await.unwrap();
    })
    .await
    .expect("rejection deadline");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn customer_entry_accepts_authenticated_local_udp_without_authorizing_outbound_purchases() {
    tokio::time::timeout(Duration::from_secs(20), async {
        let (entry, customer) = pair().await;
        let provider = PeerIdentity::from_npub(entry.npub()).unwrap();
        let payer = PeerIdentity::from_npub(customer.npub()).unwrap();
        let (server, mut incoming) = ControlTransport::start_with_customers(
            entry.clone(),
            44_712,
            vec![],
            Some("127.0.0.1/32".parse().unwrap()),
            5,
        )
        .await
        .unwrap();
        let (client, _unused) =
            ControlTransport::start(customer.clone(), 44_712, vec![provider], 6)
                .await
                .unwrap();
        let response = tokio::spawn(async move {
            let request = incoming.recv().await.unwrap();
            assert_eq!(
                request.peer, payer,
                "payer identity comes from FIPS authentication"
            );
            assert_eq!(request.body, b"customer quote");
            request.respond.send(b"terms".to_vec()).unwrap();
        });
        assert_eq!(
            client
                .request(provider, b"customer quote".to_vec())
                .await
                .unwrap(),
            b"terms"
        );
        response.await.unwrap();
        assert!(server.request(payer, b"buy onward".to_vec()).await.is_err());
        assert_eq!(server.statistics().snapshot().requests_started, 0);
        drop(client);
        drop(server);
        customer.shutdown().await.unwrap();
        entry.shutdown().await.unwrap();
    })
    .await
    .expect("public customer control deadline");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn customer_network_restriction_preserves_explicit_neighbor_access() {
    tokio::time::timeout(Duration::from_secs(20), async {
        let (entry, customer) = pair().await;
        let provider = PeerIdentity::from_npub(entry.npub()).unwrap();
        let payer = PeerIdentity::from_npub(customer.npub()).unwrap();
        let network = Some("127.0.0.2/32".parse().unwrap());
        let (server, mut incoming) =
            ControlTransport::start_with_customers(entry.clone(), 44_713, vec![], network, 7)
                .await
                .unwrap();
        let (client, _unused) =
            ControlTransport::start(customer.clone(), 44_713, vec![provider], 8)
                .await
                .unwrap();
        assert!(
            client
                .request(provider, b"outside customer network".to_vec())
                .await
                .is_err()
        );
        assert!(incoming.try_recv().is_err());
        let (trusted, mut trusted_incoming) =
            ControlTransport::start_with_customers(entry.clone(), 44_714, vec![payer], network, 9)
                .await
                .unwrap();
        let (neighbor, _unused) =
            ControlTransport::start(customer.clone(), 44_714, vec![provider], 10)
                .await
                .unwrap();
        let responder = tokio::spawn(async move {
            trusted_incoming
                .recv()
                .await
                .unwrap()
                .respond
                .send(b"neighbor".to_vec())
                .unwrap();
        });
        assert_eq!(
            neighbor.request(provider, vec![]).await.unwrap(),
            b"neighbor"
        );
        responder.await.unwrap();
        drop(neighbor);
        drop(trusted);
        drop(client);
        drop(server);
        customer.shutdown().await.unwrap();
        entry.shutdown().await.unwrap();
    })
    .await
    .expect("customer network restriction deadline");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn customer_entry_does_not_admit_a_remote_session_as_a_direct_customer() {
    tokio::time::timeout(Duration::from_secs(40), async {
        let (entry, relay) = pair().await;
        let remote = attach(&relay).await;
        let provider = PeerIdentity::from_npub(entry.npub()).unwrap();
        let payer = PeerIdentity::from_npub(remote.npub()).unwrap();
        let (proof, mut proof_incoming) =
            ControlTransport::start(entry.clone(), 44_715, vec![payer], 11)
                .await
                .unwrap();
        let (proof_client, _unused) =
            ControlTransport::start(remote.clone(), 44_715, vec![provider], 12)
                .await
                .unwrap();
        let responder = tokio::spawn(async move {
            proof_incoming
                .recv()
                .await
                .unwrap()
                .respond
                .send(b"routed".to_vec())
                .unwrap();
        });
        assert_eq!(
            proof_client.request(provider, vec![]).await.unwrap(),
            b"routed",
            "prove the remote session reaches the entry through the middle node"
        );
        responder.await.unwrap();
        assert!(
            !entry
                .peers()
                .await
                .unwrap()
                .iter()
                .any(|p| p.connected && p.node_addr == *payer.node_addr())
        );
        let (server, mut incoming) = ControlTransport::start_with_customers(
            entry.clone(),
            44_716,
            vec![],
            Some("127.0.0.0/8".parse().unwrap()),
            13,
        )
        .await
        .unwrap();
        let (client, _unused) = ControlTransport::start(remote.clone(), 44_716, vec![provider], 14)
            .await
            .unwrap();
        assert!(
            client
                .request(provider, b"remote customer".to_vec())
                .await
                .is_err()
        );
        assert!(incoming.try_recv().is_err());
        drop(client);
        drop(server);
        drop(proof_client);
        drop(proof);
        remote.shutdown().await.unwrap();
        relay.shutdown().await.unwrap();
        entry.shutdown().await.unwrap();
    })
    .await
    .expect("indirect customer rejection deadline");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn customer_connection_limit_leaves_room_for_configured_neighbor_control() {
    tokio::time::timeout(Duration::from_secs(40), async {
        let (entry, first) = pair().await;
        let endpoints = vec![
            first,
            attach(&entry).await,
            attach(&entry).await,
            attach(&entry).await,
        ];
        let provider = PeerIdentity::from_npub(entry.npub()).unwrap();
        let neighbor = PeerIdentity::from_npub(endpoints[3].npub()).unwrap();
        let (server, mut incoming) = ControlTransport::start_with_customers(
            entry.clone(),
            44_717,
            vec![neighbor],
            Some("127.0.0.1/32".parse().unwrap()),
            15,
        )
        .await
        .unwrap();
        let mut clients = Vec::new();
        for (i, endpoint) in endpoints.iter().enumerate() {
            let (client, _) =
                ControlTransport::start(endpoint.clone(), 44_717, vec![provider], i as u64 + 16)
                    .await
                    .unwrap();
            clients.push(Arc::new(client));
        }
        let mut jobs = Vec::new();
        for (index, count) in [3, 3, 2].into_iter().enumerate() {
            for _ in 0..count {
                let client = clients[index].clone();
                jobs.push(tokio::spawn(async move {
                    client.request(provider, b"hold".to_vec()).await
                }));
            }
        }
        let mut held = Vec::new();
        for _ in 0..8 {
            held.push(incoming.recv().await.unwrap());
        }
        assert!(
            clients[2]
                .request(provider, b"over capacity".to_vec())
                .await
                .is_err()
        );
        assert!(incoming.try_recv().is_err());
        let trusted = clients[3].clone();
        let trusted_job =
            tokio::spawn(async move { trusted.request(provider, b"neighbor".to_vec()).await });
        let request = incoming.recv().await.unwrap();
        assert_eq!(request.peer, neighbor);
        request.respond.send(b"available".to_vec()).unwrap();
        assert_eq!(trusted_job.await.unwrap().unwrap(), b"available");
        for request in held {
            request.respond.send(b"done".to_vec()).unwrap();
        }
        for job in jobs {
            assert_eq!(job.await.unwrap().unwrap(), b"done");
        }
        drop(clients);
        drop(server);
        for endpoint in endpoints {
            endpoint.shutdown().await.unwrap();
        }
        entry.shutdown().await.unwrap();
    })
    .await
    .expect("bounded customer capacity deadline");
}

#[path = "control_transport/dynamic.rs"]
mod dynamic;
