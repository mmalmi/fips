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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn queued_record_takes_precedence_over_idle_expiry() {
    tokio::time::timeout(Duration::from_secs(10), async {
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
        let alice = PeerIdentity::from_npub(a.npub()).unwrap();
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
        // This reproduces a delayed service poll without a five-second sleep.
        idle.streams.get_mut(&incoming).unwrap().since = Instant::now() - IDLE_TIMEOUT;
        let mut ready = idle
            .ready(&mut server, admission.clone(), now(), &statistics)
            .await;
        assert_eq!(ready.len(), 1, "expiry discarded an already queued request");
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
            idle.ready(&mut server, admission, now(), &statistics)
                .await
                .is_empty()
        );
        assert!(
            idle.streams.is_empty(),
            "quiet expired streams must still close"
        );
        assert_ne!(server.state(id), Some(State::Established));
        drop((client, server));
        a.shutdown().await.unwrap();
        b.shutdown().await.unwrap();
    })
    .await
    .expect("bounded idle expiry regression");
}
