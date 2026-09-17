use super::*;
use fips_relay::control_transport::{ControlAdmission, NeighborAdmission};

fn admission(endpoint: &Arc<FipsEndpoint>) -> Arc<ControlAdmission> {
    ControlAdmission::new(
        endpoint.clone(),
        vec![],
        None,
        NeighborAdmission::AuthenticatedAdjacent,
    )
    .unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn adjacent_control_works_in_both_directions_without_a_control_roster() {
    tokio::time::timeout(Duration::from_secs(20), async {
        let (a, b) = pair().await;
        let alice = PeerIdentity::from_npub(a.npub()).unwrap();
        let bob = PeerIdentity::from_npub(b.npub()).unwrap();
        let shared_a = admission(&a);
        assert!(
            ControlTransport::start_with_admission(b.clone(), 44_720, shared_a.clone(), 1)
                .await
                .is_err()
        );
        let (first, mut incoming_a) =
            ControlTransport::start_with_admission(a.clone(), 44_720, shared_a, 1)
                .await
                .unwrap();
        let (second, mut incoming_b) =
            ControlTransport::start_with_admission(b.clone(), 44_720, admission(&b), 2)
                .await
                .unwrap();
        let answer = tokio::spawn(async move {
            let request = incoming_b.recv().await.unwrap();
            assert_eq!(request.peer, alice);
            request.respond.send(request.body).unwrap();
        });
        assert_eq!(
            first.request(bob, b"forward".to_vec()).await.unwrap(),
            b"forward"
        );
        answer.await.unwrap();
        let answer = tokio::spawn(async move {
            let request = incoming_a.recv().await.unwrap();
            assert_eq!(request.peer, bob);
            request.respond.send(request.body).unwrap();
        });
        assert_eq!(
            second.request(alice, b"back".to_vec()).await.unwrap(),
            b"back"
        );
        answer.await.unwrap();
        drop((first, second));
        a.shutdown().await.unwrap();
        b.shutdown().await.unwrap();
    })
    .await
    .expect("dynamic adjacency deadline");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn adjacent_mode_keeps_customer_subnet_inbound_only() {
    tokio::time::timeout(Duration::from_secs(20), async {
        let (entry, customer) = pair().await;
        let provider = PeerIdentity::from_npub(entry.npub()).unwrap();
        let payer = PeerIdentity::from_npub(customer.npub()).unwrap();
        let shared = ControlAdmission::new(
            entry.clone(),
            vec![],
            Some("127.0.0.0/8".parse().unwrap()),
            NeighborAdmission::AuthenticatedAdjacent,
        )
        .unwrap();
        let (server, mut incoming) =
            ControlTransport::start_with_admission(entry.clone(), 44_721, shared, 3)
                .await
                .unwrap();
        let (client, _) = ControlTransport::start(customer.clone(), 44_721, vec![provider], 4)
            .await
            .unwrap();
        let answer = tokio::spawn(async move {
            let request = incoming.recv().await.unwrap();
            assert_eq!(request.peer, payer);
            request.respond.send(b"quote".to_vec()).unwrap();
        });
        assert_eq!(client.request(provider, vec![]).await.unwrap(), b"quote");
        answer.await.unwrap();
        assert!(server.request(payer, b"onward".to_vec()).await.is_err());
        assert_eq!(server.statistics().snapshot().requests_started, 0);
        drop((server, client));
        customer.shutdown().await.unwrap();
        entry.shutdown().await.unwrap();
    })
    .await
    .expect("dynamic customer classification deadline");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn adjacent_mode_rejects_a_reachable_remote_session() {
    tokio::time::timeout(Duration::from_secs(45), async {
        let (entry, middle) = pair().await;
        let remote = attach(&middle).await;
        let provider = PeerIdentity::from_npub(entry.npub()).unwrap();
        let caller = PeerIdentity::from_npub(remote.npub()).unwrap();
        let (proof, mut proof_incoming) =
            ControlTransport::start(entry.clone(), 44_722, vec![caller], 5)
                .await
                .unwrap();
        let (proof_client, _) = ControlTransport::start(remote.clone(), 44_722, vec![provider], 6)
            .await
            .unwrap();
        let answer = tokio::spawn(async move {
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
            b"routed"
        );
        answer.await.unwrap();
        assert!(
            !entry
                .peers()
                .await
                .unwrap()
                .iter()
                .any(|p| p.connected && p.node_addr == *caller.node_addr())
        );
        let (server, mut incoming) =
            ControlTransport::start_with_admission(entry.clone(), 44_723, admission(&entry), 7)
                .await
                .unwrap();
        let (client, _) = ControlTransport::start(remote.clone(), 44_723, vec![provider], 8)
            .await
            .unwrap();
        assert!(client.request(provider, b"remote".to_vec()).await.is_err());
        assert!(incoming.try_recv().is_err());
        assert_eq!(server.statistics().snapshot().requests_received, 0);
        assert!(server.request(caller, b"outbound".to_vec()).await.is_err());
        assert_eq!(server.statistics().snapshot().requests_started, 0);
        drop((server, client, proof, proof_client));
        remote.shutdown().await.unwrap();
        middle.shutdown().await.unwrap();
        entry.shutdown().await.unwrap();
    })
    .await
    .expect("remote adjacency rejection deadline");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn three_ports_share_capacity_without_one_peer_monopolizing_it() {
    tokio::time::timeout(Duration::from_secs(45), async {
        let (entry, caller) = pair().await;
        let second_caller = attach(&entry).await;
        let healthy = attach(&entry).await;
        let provider = PeerIdentity::from_npub(entry.npub()).unwrap();
        let shared = admission(&entry);
        let mut servers = Vec::new();
        let mut clients = [Vec::new(), Vec::new()];
        let mut incoming = Vec::new();
        for port in 44_724..44_727 {
            let (server, receive) = ControlTransport::start_with_admission(
                entry.clone(),
                port,
                shared.clone(),
                u64::from(port),
            )
            .await
            .unwrap();
            for (index, endpoint) in [&caller, &second_caller].into_iter().enumerate() {
                let (client, _) = ControlTransport::start(
                    endpoint.clone(),
                    port,
                    vec![provider],
                    u64::from(port) + 10,
                )
                .await
                .unwrap();
                clients[index].push(Arc::new(client));
            }
            servers.push(server);
            incoming.push(receive);
        }
        let (healthy_client, _) =
            ControlTransport::start(healthy.clone(), 44_726, vec![provider], 100)
                .await
                .unwrap();
        let healthy_client = Arc::new(healthy_client);
        let mut jobs = Vec::new();
        let mut held = Vec::new();
        for (peer_index, peer_clients) in clients.iter().enumerate() {
            for index in [0, 0, 1, 2] {
                let client = peer_clients[index].clone();
                jobs.push(tokio::spawn(async move {
                    client.request(provider, b"held".to_vec()).await
                }));
                held.push(incoming[index].recv().await.unwrap());
            }
            assert!(
                peer_clients[2]
                    .request(provider, b"fifth".to_vec())
                    .await
                    .is_err()
            );
            assert!(incoming[2].try_recv().is_err());
            if peer_index == 0 {
                // The first unresponsive peer fills its quota across all ports,
                // but a different authenticated neighbor can still complete.
                let client = healthy_client.clone();
                let job =
                    tokio::spawn(
                        async move { client.request(provider, b"healthy".to_vec()).await },
                    );
                let request = incoming[2].recv().await.unwrap();
                assert_eq!(request.body, b"healthy");
                request.respond.send(request.body).unwrap();
                assert_eq!(job.await.unwrap().unwrap(), b"healthy");
            }
        }
        assert!(
            healthy_client
                .request(provider, b"ninth".to_vec())
                .await
                .is_err()
        );
        assert!(incoming[2].try_recv().is_err());
        let canceled = jobs.pop().unwrap();
        canceled.abort();
        assert!(canceled.await.unwrap_err().is_cancelled());
        drop(held.pop().unwrap());
        let client = clients[1][2].clone();
        let replacement = tokio::spawn(async move {
            tokio::time::timeout(Duration::from_secs(3), async {
                loop {
                    match client.request(provider, b"replacement".to_vec()).await {
                        Ok(body) => break body,
                        Err(_) => tokio::time::sleep(Duration::from_millis(20)).await,
                    }
                }
            })
            .await
            .unwrap()
        });
        let request = incoming[2].recv().await.unwrap();
        assert_eq!(request.body, b"replacement");
        request.respond.send(request.body).unwrap();
        assert_eq!(replacement.await.unwrap(), b"replacement");
        for request in held {
            request.respond.send(b"done".to_vec()).unwrap();
        }
        for job in jobs {
            assert_eq!(job.await.unwrap().unwrap(), b"done");
        }
        drop((servers, clients, healthy_client));
        healthy.shutdown().await.unwrap();
        second_caller.shutdown().await.unwrap();
        caller.shutdown().await.unwrap();
        entry.shutdown().await.unwrap();
    })
    .await
    .expect("shared admission capacity deadline");
}
