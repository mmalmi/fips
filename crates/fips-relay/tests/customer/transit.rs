//! The phone's actual customer lifecycle can host a paid intermediate relay.
use super::*;
use fips_relay::{
    control_transport::NeighborAdmission, probe::stream::StreamProbe, service::native_request,
};
use std::net::{Ipv4Addr, SocketAddr, UdpSocket};

async fn duplex(
    configs: &[ServiceConfig],
    npubs: &[String],
    bytes: u64,
    duration: u64,
) -> Vec<Result<Value, String>> {
    let run = |source: usize, destination: usize| {
        let config = configs[source].clone();
        let probe = StreamProbe {
            peer: npubs[destination].clone(),
            stream_id: "75".repeat(16),
            bytes,
            bytes_per_second: 64 * 1024,
            duration_secs: duration,
            connect: source == 0,
        };
        async move { request(&config, &AdminRequest::StreamProbe { probe }).await }
    };
    let (left, right) = tokio::join!(run(0, 2), run(2, 0));
    vec![left, right]
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn customer_relays_paid_duplex_for_an_unconfigured_adjacent_peer() {
    tokio::time::timeout(Duration::from_secs(120), async {
        let root = tempfile::tempdir().unwrap();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let network = PaymentNetwork::new(175, 0, Arc::new(VirtualClock::new(now)));
        let mint = LocalMint::start(
            root.path(),
            network.clone(),
            "phone-transit",
            IssuerMode::ClosedLoop,
        )
        .await
        .unwrap();
        let directory = root.path().join("phone");
        let mut configs = vec![
            config(&root.path().join("left"), mint.url()),
            config(&directory, mint.url()),
            config(&root.path().join("right"), mint.url()),
        ];
        let mut reservations = Vec::new();
        let mut npubs = vec![String::new(); 3];
        for node in [0, 2] {
            let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
            configs[node].transports = udp_transports(socket.local_addr().unwrap());
            configs[node].neighbor_admission = NeighborAdmission::AuthenticatedAdjacent;
            configs[node].terms.billing = BillingBasis::ForwardingData;
            configs[node].terms.fee_msat_per_kib = 1;
            configs[node].terms.quote_max_units = 1024 * 1024;
            reservations.push(socket);
            std::fs::create_dir_all(configs[node].state_directory.parent().unwrap()).unwrap();
            npubs[node] = RelayService::initialize(configs[node].clone())
                .await
                .unwrap();
            fund(
                &configs[node].state_directory.join("wallet"),
                mint.url(),
                &network,
                128,
            )
            .await;
        }
        let mut policy = profile(
            &npubs[0],
            udp_bind(&configs[0]).to_string(),
            &npubs[2],
            mint.url(),
        );
        policy.billing = BillingBasis::ForwardingData;
        policy.neighbor_admission = NeighborAdmission::AuthenticatedAdjacent;
        let mut client = CustomerClient::open(&directory).unwrap();
        let setup = client
            .execute(Action::Setup {
                profile: policy.clone(),
            })
            .await
            .unwrap();
        npubs[1] = setup["npub"].as_str().unwrap().into();
        fund(
            &configs[1].state_directory.join("wallet"),
            mint.url(),
            &network,
            128,
        )
        .await;
        let mut changed = policy.clone();
        changed.neighbor_admission = NeighborAdmission::ConfiguredOnly;
        assert!(
            client
                .execute(Action::Setup { profile: changed })
                .await
                .is_err()
        );
        let paths = [
            root.path().join("left.json"),
            root.path().join("right.json"),
        ];
        std::fs::write(&paths[0], serde_json::to_vec(&configs[0]).unwrap()).unwrap();
        drop(reservations);
        let mut children = vec![process_support::start(&paths[0]).await];
        // CustomerClient starts the same service used by Android, with only its
        // configured entry. The other endpoint must establish a new adjacency.
        client.execute(Action::Start).await.unwrap();
        let report = native_request(&configs[1], &json!({"command":"show_transports"}))
            .await
            .unwrap();
        let mut address: SocketAddr = report["data"]["transports"][0]["local_addr"]
            .as_str()
            .unwrap()
            .parse()
            .unwrap();
        assert_ne!(address.port(), 0);
        address.set_ip(Ipv4Addr::LOCALHOST.into());
        configs[2].neighbors = vec![PeerConfig::new(&npubs[1], "udp", address.to_string())];
        std::fs::write(&paths[1], serde_json::to_vec(&configs[2]).unwrap()).unwrap();
        children.push(process_support::start(&paths[1]).await);
        tokio::time::timeout(Duration::from_secs(15), async {
            loop {
                let mut ready = true;
                for (node, config) in configs.iter().enumerate() {
                    ready &= request(config, &AdminRequest::Status)
                        .await
                        .is_ok_and(|state| process_support::has_line_peers(&state, &npubs, node));
                }
                if ready {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
        })
        .await
        .expect("only the two phone adjacencies must form");
        let denied = duplex(&configs, &npubs, 1024, 2).await;
        let unpaid = request(&configs[1], &AdminRequest::Status).await.unwrap();
        for (source, destination) in [(0, 2), (2, 0)] {
            request(
                &configs[source],
                &AdminRequest::Buy {
                    destination: npubs[destination].clone(),
                },
            )
            .await
            .unwrap();
        }
        let before = client.execute(Action::Status).await.unwrap();
        let delivery = duplex(&configs, &npubs, 128 * 1024, 6).await;
        let after = client.execute(Action::Status).await.unwrap();
        eprintln!("phone transit stream results: {delivery:?}");
        // Retain the measured outcome before closing and reconciling accounts.
        for config in &configs {
            request(config, &AdminRequest::Settle).await.unwrap();
        }
        let settled = client.execute(Action::Status).await.unwrap();
        client.execute(Action::Stop).await.unwrap();
        for child in &mut children {
            process_support::stop(child).await;
        }
        let mut total = 0;
        for config in &configs {
            total += load_mint_balance(&config.state_directory.join("wallet"), mint.url())
                .await
                .unwrap()
                .balance_sat;
        }
        assert_eq!(total, 384);
        assert!(network.accounting().unwrap().is_conserved());
        assert_eq!(settled["relay"]["funding_budget"]["locked_sat"], 0);
        assert_eq!(
            settled["relay"]["funding_budget"]["pending_reserved_sat"],
            0
        );
        assert!(denied.iter().all(Result::is_err));
        assert_eq!(unpaid["funding_budget"]["wallet_debited_sat"], 0);
        assert_eq!(before["profile"], after["profile"]);
        assert_eq!(
            before["relay"]["funding_budget"],
            after["relay"]["funding_budget"]
        );
        let reports: Vec<_> = delivery
            .into_iter()
            .map(|r| r.unwrap()["probe"].clone())
            .collect();
        for report in &reports {
            for field in ["accepted_bytes", "received_bytes", "acknowledged_bytes"] {
                assert_eq!(report[field], 128 * 1024);
            }
        }
        assert_eq!(reports[0]["received_sha256"], reports[1]["received_sha256"]);
        // Positive provider credit and onward evidence establish actual paid
        // transit, independently of native packet counters or mere adjacency.
        let ledger: Value = serde_json::from_slice(
            &std::fs::read(configs[1].state_directory.join("seller/ledger.json")).unwrap(),
        )
        .unwrap();
        let channels = ledger["ledger"]["channels"].as_array().unwrap();
        assert_eq!(channels.len(), 2);
        assert!(
            channels
                .iter()
                .all(|row| row["usage"]["submitted_msat"].as_u64().unwrap() > 0
                    && row["usage"]["paid_msat"].as_u64().unwrap() > 0)
        );
        let progress = after["relay"]["payment_progress"].as_object().unwrap();
        assert_eq!(progress.len(), 2);
        assert!(
            progress
                .values()
                .all(|p| p["evidence_msat"].as_u64().unwrap() > 0)
        );
        assert_eq!(after["relay"]["received"]["packets"], 0);
    })
    .await
    .expect("phone lifecycle transit and settlement deadline");
}
