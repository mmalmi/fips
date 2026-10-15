//! A queued record remains work even when the idle deadline has elapsed.
use super::*;
use fips_core::config::{PeerConfig, TransportInstances, UdpConfig};

async fn pump(tcp: &mut FipsTcpEndpoint, started: Instant) {
    let now = started.elapsed().as_millis() as u64;
    tokio::select! {
        result = tcp.receive_report(now) => { result.unwrap(); }
        _ = tokio::time::sleep(Duration::from_millis(1)) => {
            tcp.poll(now).await.unwrap();
        }
    }
}

struct Pair {
    a: Arc<FipsEndpoint>,
    b: Arc<FipsEndpoint>,
    client: FipsTcpEndpoint,
    server: FipsTcpEndpoint,
    outgoing: ConnectionId,
    incoming: ConnectionId,
    started: Instant,
}

async fn connected() -> Pair {
    let mut config = fips_core::Config::new();
    config.node.discovery.nostr.enabled = false;
    config.node.discovery.lan.enabled = false;
    config.node.discovery.local.enabled = false;
    config.transports.udp = TransportInstances::Single(UdpConfig {
        bind_addr: Some("127.0.0.1:0".into()),
        advertise_on_nostr: Some(false),
        ..Default::default()
    });
    let a = Arc::new(
        FipsEndpoint::builder()
            .config(config.clone())
            .without_system_tun()
            .bind()
            .await
            .unwrap(),
    );
    config.peers.push(PeerConfig::new(
        a.npub(),
        "udp",
        a.bound_udp_listen_addrs().await.unwrap()[0].to_string(),
    ));
    let b = Arc::new(
        FipsEndpoint::builder()
            .config(config)
            .without_system_tun()
            .bind()
            .await
            .unwrap(),
    );
    while !b
        .peers()
        .await
        .unwrap()
        .iter()
        .any(|p| p.connected && p.npub == a.npub())
    {
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let bob = PeerIdentity::from_npub(b.npub()).unwrap();
    let mut client = FipsTcpEndpoint::bind(a.clone(), 44_722, Config::default(), 1)
        .await
        .unwrap();
    let mut server = FipsTcpEndpoint::bind(b.clone(), 44_722, Config::default(), 2)
        .await
        .unwrap();
    let started = Instant::now();
    let now = || started.elapsed().as_millis() as u64;
    let outgoing = client.connect(bob, now()).await.unwrap();
    let incoming = loop {
        tokio::join!(pump(&mut client, started), pump(&mut server, started));
        if let Some(id) = server.accept() {
            break id;
        }
    };
    Pair {
        a,
        b,
        client,
        server,
        outgoing,
        incoming,
        started,
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn queued_record_takes_precedence_over_idle_expiry() {
    tokio::time::timeout(Duration::from_secs(10), async {
        let Pair {
            a,
            b,
            mut client,
            mut server,
            outgoing,
            incoming,
            started,
        } = connected().await;
        let now = || started.elapsed().as_millis() as u64;
        let alice = PeerIdentity::from_npub(a.npub()).unwrap();
        let admission = ControlAdmission::new(
            b.clone(),
            vec![alice],
            None,
            NeighborAdmission::ConfiguredOnly,
        )
        .unwrap();
        let statistics = ControlStatistics::default();
        let mut idle = IdleStreams::default();
        idle.park(&mut server, incoming, alice, false, now()).await;
        assert_eq!(
            client
                .write(outgoing, &[0, 0, 0, 1, 42], now())
                .await
                .unwrap(),
            5
        );
        server.receive_report(now()).await.unwrap();
        // Advance only the pool's idle age after TCP has accepted the record.
        // Include connection pressure in that same service turn; neither it
        // nor a delayed service poll may discard an already accepted record.
        idle.streams.get_mut(&incoming).unwrap().since = Instant::now() - IDLE_TIMEOUT;
        let mut ready = idle
            .ready(&mut server, admission.clone(), now(), &statistics, true)
            .await;
        assert_eq!(
            ready.len(),
            1,
            "idle pressure discarded an already queued request"
        );
        let (id, mut exchange) = ready.pop().unwrap();
        assert_eq!(id, incoming);
        let (send, mut receive) = mpsc::channel(1);
        let request = loop {
            assert!(
                drive(&mut server, id, &mut exchange, &send, now(), &statistics)
                    .await
                    .unwrap()
            );
            if let Ok(request) = receive.try_recv() {
                break request;
            }
            tokio::task::yield_now().await;
        };
        assert_eq!(request.body, [42]);
        request.respond.send(vec![43]).unwrap();
        assert!(
            !drive(&mut server, id, &mut exchange, &send, now(), &statistics)
                .await
                .unwrap()
        );
        assert_eq!(statistics.snapshot().requests_received, 1);
        let mut reply = Vec::new();
        while reply.len() < 5 {
            pump(&mut client, started).await;
            reply.extend(client.read(outgoing, 5 - reply.len(), now()).await.unwrap());
        }
        assert_eq!(reply, [0, 0, 0, 1, 43]);
        drop(exchange);
        idle.park(&mut server, id, alice, false, now()).await;
        idle.streams.get_mut(&id).unwrap().since = Instant::now() - IDLE_TIMEOUT;
        assert!(
            idle.ready(&mut server, admission.clone(), now(), &statistics, false)
                .await
                .is_empty()
        );
        assert_eq!(
            idle.streams.len(),
            1,
            "responder awaits the requester's FIN"
        );
        let bob = PeerIdentity::from_npub(b.npub()).unwrap();
        let requester_admission = ControlAdmission::new(
            a.clone(),
            vec![bob],
            None,
            NeighborAdmission::ConfiguredOnly,
        )
        .unwrap();
        let mut requester_idle = IdleStreams::default();
        requester_idle
            .park(&mut client, outgoing, bob, true, now())
            .await;
        requester_idle.streams.get_mut(&outgoing).unwrap().since = Instant::now() - IDLE_TIMEOUT;
        assert!(
            requester_idle
                .ready(&mut client, requester_admission, now(), &statistics, false)
                .await
                .is_empty()
        );
        assert!(
            requester_idle.streams.is_empty(),
            "quiet expired requester streams must still close"
        );
        while !server.is_read_closed(id) {
            tokio::join!(pump(&mut client, started), pump(&mut server, started));
        }
        assert!(
            idle.ready(&mut server, admission, now(), &statistics, false)
                .await
                .is_empty()
        );
        assert!(
            idle.streams.is_empty(),
            "peer FIN releases the responder stream"
        );
        assert_ne!(server.state(id), Some(State::Established));
        drop((client, server));
        a.shutdown().await.unwrap();
        b.shutdown().await.unwrap();
    })
    .await
    .expect("bounded idle expiry regression");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn requester_owns_idle_expiry_until_its_next_record() {
    tokio::time::timeout(Duration::from_secs(10), async {
        let Pair {
            a,
            b,
            mut client,
            mut server,
            outgoing,
            incoming,
            started,
        } = connected().await;
        let now = || started.elapsed().as_millis() as u64;
        let alice = PeerIdentity::from_npub(a.npub()).unwrap();
        let bob = PeerIdentity::from_npub(b.npub()).unwrap();
        let admission = |endpoint, peer| {
            ControlAdmission::new(
                endpoint,
                vec![peer],
                None,
                NeighborAdmission::ConfiguredOnly,
            )
            .unwrap()
        };
        let client_admission = admission(a.clone(), bob);
        let server_admission = admission(b.clone(), alice);
        let statistics = ControlStatistics::default();
        let mut client_idle = IdleStreams::default();
        let mut server_idle = IdleStreams::default();

        // Finish one real record. The responder parks before the requester has
        // received the reply, so its independent idle deadline is earlier.
        client
            .write(outgoing, &[0, 0, 0, 1, 42], now())
            .await
            .unwrap();
        let mut request = Vec::new();
        while request.len() < 5 {
            pump(&mut server, started).await;
            request.extend(
                server
                    .read(incoming, 5 - request.len(), now())
                    .await
                    .unwrap(),
            );
        }
        assert_eq!(request, [0, 0, 0, 1, 42]);
        server
            .write(incoming, &[0, 0, 0, 1, 43], now())
            .await
            .unwrap();
        server_idle
            .park(&mut server, incoming, alice, false, now())
            .await;
        let mut reply = Vec::new();
        while reply.len() < 5 {
            pump(&mut client, started).await;
            reply.extend(client.read(outgoing, 5 - reply.len(), now()).await.unwrap());
        }
        assert_eq!(reply, [0, 0, 0, 1, 43]);
        client_idle
            .park(&mut client, outgoing, bob, true, now())
            .await;
        server_idle.streams.get_mut(&incoming).unwrap().since = Instant::now() - IDLE_TIMEOUT;
        assert!(
            server_idle
                .ready(
                    &mut server,
                    server_admission.clone(),
                    now(),
                    &statistics,
                    false
                )
                .await
                .is_empty()
        );
        assert_eq!(client_idle.take(&client, bob), Some(outgoing));

        // Select the still-reusable client stream before it receives a server
        // FIN. Generic control records must never be replayed to hide it.
        let (response, mut received) = oneshot::channel();
        let command = Command {
            peer: bob,
            body: Some(vec![44]),
            response,
            retry_at: Instant::now(),
        };
        let mut client_exchange =
            Exchange::client(command, AdmissionCheck::start(client_admission, bob, true));
        let mut server_exchange = None;
        let (send, mut requests) = mpsc::channel(1);
        loop {
            let pending = drive(
                &mut client,
                outgoing,
                &mut client_exchange,
                &send,
                now(),
                &statistics,
            )
            .await
            .expect("responder idle expiry interrupted a still-reusable request");
            if !pending {
                assert_eq!(received.try_recv().unwrap().unwrap(), [45]);
                break;
            }
            tokio::join!(pump(&mut client, started), pump(&mut server, started));
            for (id, exchange) in server_idle
                .ready(
                    &mut server,
                    server_admission.clone(),
                    now(),
                    &statistics,
                    false,
                )
                .await
            {
                assert_eq!(id, incoming);
                assert!(server_exchange.replace(exchange).is_none());
            }
            if let Some(exchange) = server_exchange.as_mut()
                && !drive(&mut server, incoming, exchange, &send, now(), &statistics)
                    .await
                    .unwrap()
            {
                server_exchange = None;
                server_idle
                    .park(&mut server, incoming, alice, false, now())
                    .await;
            }
            if let Ok(request) = requests.try_recv() {
                assert_eq!(request.body, [44]);
                request.respond.send(vec![45]).unwrap();
            }
        }
        assert_eq!(statistics.snapshot().requests_received, 1);
        drop((client_exchange, server_exchange, client, server));
        a.shutdown().await.unwrap();
        b.shutdown().await.unwrap();
    })
    .await
    .expect("bounded idle half-close regression");
}
