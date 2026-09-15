//! Composes native FMP transit, authenticated TCP/FIPS payment control,
//! durable accounting, and real local-mint redemption. Route approvals and
//! buyer scheduling are explicit fixture inputs, not autonomous route buying.

use cashu::{
    Token,
    nuts::{CurrencyUnit, Proof},
};
use cashu_service::{
    CashuSpilmanPayment, FileSpilmanPaymentReceiver, FileSpilmanPaymentReceiverConfig,
    FileSpilmanPaymentSigner, StreamingRouteOpenCashuSpilmanChannelFromWalletRequest,
    create_topup_quote, load_mint_balance, load_wallet_overview,
    open_streaming_route_cashu_spilman_channel_from_wallet, receive_payment_token,
    restore_streaming_route_cashu_spilman_refund, send_payment_token,
    simulation::{IssuerMode, LocalMint, PaymentNetwork, VirtualClock},
};
use fips_core::{
    Config, FipsEndpoint, Identity, PeerIdentity,
    config::{PeerConfig, TransportInstances, UdpConfig},
    encode_nsec,
    node::{ForwardingOutcome, ForwardingPolicy, ForwardingRequest},
};
use fips_relay::{
    buyer::{BuyerAuthorizer, BuyerError, PaidForwarder},
    control_transport::ControlTransport,
    durable::DurableRelay,
    ledger::{BytePrice, ChannelTerms, ChannelUsage, Contract, Limits},
    payment_control::{
        ApprovedAgreement, PaymentControl, PaymentRequest, PaymentResponse, PaymentServer,
    },
};
use std::{
    path::PathBuf,
    sync::{Arc, Mutex},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

const SERVICE: u16 = 44_720;
const DATA: u16 = 44_721;

struct Link {
    buyer: usize,
    seller: usize,
    channel: ChannelTerms,
    opening: CashuSpilmanPayment,
}

#[derive(Debug)]
struct AuditedPolicy {
    forwarding: PaidForwarder,
    peers: Vec<PeerIdentity>,
    denied: Mutex<Vec<String>>,
}

impl ForwardingPolicy for AuditedPolicy {
    fn admit(&self, request: &ForwardingRequest<'_>) -> Option<u64> {
        let token = self.forwarding.admit(request);
        if token.is_none() {
            let mut denied = self.denied.lock().unwrap();
            if denied.len() < 8 {
                let node = |address: &fips_core::NodeAddr| {
                    self.peers
                        .iter()
                        .position(|peer| peer.node_addr() == address)
                };
                denied.push(format!(
                    "buyer={:?} source={:?} destination={:?} next={:?} bytes={}",
                    node(request.ingress.node_addr()),
                    node(&request.source),
                    node(&request.destination),
                    node(&request.next_hop),
                    request.session_payload.len()
                ));
            }
        }
        token
    }
    fn complete(&self, token: u64, outcome: ForwardingOutcome) {
        self.forwarding.complete(token, outcome);
    }
}

async fn request(
    control: &ControlTransport,
    seller: PeerIdentity,
    value: PaymentRequest,
) -> PaymentResponse {
    let bytes = control
        .request(seller, serde_json::to_vec(&value).unwrap())
        .await
        .unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

fn status(response: PaymentResponse) -> ChannelUsage {
    match response {
        PaymentResponse::Status { usage, .. } => usage,
        PaymentResponse::Rejected => panic!("approved request rejected"),
    }
}

async fn pay_usage(
    controls: &[ControlTransport],
    identities: &[PeerIdentity],
    wallets: &[PathBuf],
    links: &[Link],
    buyers: &[Arc<BuyerAuthorizer>],
) {
    for link in links {
        let usage = status(
            request(
                &controls[link.buyer],
                identities[link.seller],
                PaymentRequest::Usage {
                    channel_id: link.channel.id.clone(),
                },
            )
            .await,
        );
        let due = usage.submitted_msat.div_ceil(1_000);
        let signer = FileSpilmanPaymentSigner::load(&wallets[link.buyer]).unwrap();
        let buyer = &buyers[link.buyer];
        let evidence = buyer.evidence_msat(&link.channel.id).unwrap();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        assert!(
            matches!(
                buyer.sign_claim(
                    &signer,
                    *identities[link.seller].node_addr(),
                    &link.channel.id,
                    evidence + 1,
                    now
                ),
                Err(BuyerError::UnearnedClaim)
            ),
            "a provider cannot turn spare funded capacity into permission to charge"
        );
        let payment = buyer
            .sign_claim(
                &signer,
                *identities[link.seller].node_addr(),
                &link.channel.id,
                usage.submitted_msat,
                now,
            )
            .unwrap_or_else(|error| {
                panic!(
                    "buyer {} provider {} evidence={evidence} claim={} error={error}",
                    link.buyer, link.seller, usage.submitted_msat
                )
            });
        let result = status(
            request(
                &controls[link.buyer],
                identities[link.seller],
                PaymentRequest::Update {
                    channel_id: link.channel.id.clone(),
                    payment,
                },
            )
            .await,
        );
        assert_eq!(result.paid_msat, due * 1_000);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn three_native_transit_routers_redeem_both_directions_through_neighbor_control() {
    if let Ok(filter) = std::env::var("FIPS_RELAY_TRACE") {
        let _ = tracing_subscriber::fmt()
            .with_env_filter(filter)
            .with_ansi(false)
            .try_init();
    }
    tokio::time::timeout(Duration::from_secs(120), async {
        let root = tempfile::tempdir().unwrap();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let network = PaymentNetwork::new(92, 0, Arc::new(VirtualClock::new(now)));
        let mint = LocalMint::start(
            root.path(),
            network.clone(),
            "native-relay-test",
            IssuerMode::ClosedLoop,
        )
        .await
        .unwrap();
        let identities: Vec<_> = (1..=5)
            .map(|i| Identity::from_secret_bytes(&[i; 32]).unwrap())
            .collect();
        let peers: Vec<_> = identities
            .iter()
            .map(|id| PeerIdentity::from_pubkey_full(id.pubkey_full()))
            .collect();
        let mut nodes = Vec::new();
        let mut addresses = Vec::new();
        let mut ledgers = Vec::new();
        let mut buyers = Vec::new();
        let mut audits = Vec::new();
        let mut data = Vec::new();
        let wallets: Vec<_> = (0..5)
            .map(|i| root.path().join(format!("wallet-{i}")))
            .collect();
        for (i, identity) in identities.iter().enumerate() {
            let buyer = Arc::new(BuyerAuthorizer::create(&root.path().join(format!("buyer-{i}")), *peers[i].node_addr(), 64, Limits::default()).unwrap());
            let ledger = Arc::new(
                DurableRelay::create(
                    &root.path().join(format!("ledger-{i}")),
                    Limits::default(),
                    16_384,
                )
                .unwrap(),
            );
            let mut config = Config::new();
            config.node.identity.nsec = Some(encode_nsec(&identity.keypair().secret_key()));
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
                    .forwarding_policy({
                        let audit = Arc::new(AuditedPolicy { forwarding: PaidForwarder::new(ledger.clone(), buyer.clone()), peers: peers.clone(), denied: Mutex::new(Vec::new()) });
                        audits.push(audit.clone());
                        audit
                    })
                    .originated_session_observer(buyer.clone())
                    .without_system_tun()
                    .bind()
                    .await
                    .unwrap(),
            );
            addresses.push(node.bound_udp_listen_addrs().await.unwrap()[0]);
            data.push(node.register_service_receiver(DATA).await.unwrap());
            nodes.push(node);
            ledgers.push(ledger);
            buyers.push(buyer);
            let funding = create_topup_quote(&wallets[i], mint.url(), 128)
                .await
                .unwrap();
            network
                .orchestrator_funding()
                .settle_external(&funding.payment_request)
                .unwrap();
            assert!(
                load_wallet_overview(&wallets[i], true)
                    .await
                    .unwrap()
                    .warnings
                    .is_empty()
            );
        }
        for (i, node) in nodes.iter().enumerate() {
            node.update_peers(
                nodes
                    .iter()
                    .enumerate()
                    .filter(|(j, _)| i.abs_diff(*j) == 1)
                    .map(|(j, other)| {
                        PeerConfig::new(other.npub(), "udp", addresses[j].to_string())
                    })
                    .collect(),
            )
            .await
            .unwrap();
        }
        tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                let mut connected = 0;
                for node in &nodes {
                    connected += node
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
        .expect("linear native adjacencies");
        let mut receivers = Vec::new();
        for i in 0..5 {
            receivers.push(
                FileSpilmanPaymentReceiver::load_with_keyset_refresh(
                    &root.path().join(format!("receiver-{i}")),
                    FileSpilmanPaymentReceiverConfig::new([mint.url().to_string()]),
                )
                .await
                .unwrap(),
            );
        }
        let mut approvals: Vec<Vec<ApprovedAgreement>> = (0..5).map(|_| Vec::new()).collect();
        let mut links = Vec::new();
        for (buyer, seller, destination, next, rate) in [
            (0, 1, 4, 2, 3),
            (1, 2, 4, 3, 2),
            (2, 3, 4, 4, 1),
            (4, 3, 0, 2, 3),
            (3, 2, 0, 1, 2),
            (2, 1, 0, 0, 1),
        ] {
            let opened = open_streaming_route_cashu_spilman_channel_from_wallet(
                &wallets[buyer],
                StreamingRouteOpenCashuSpilmanChannelFromWalletRequest {
                    mint_url: mint.url().to_string(),
                    receiver_pubkey_hex: receivers[seller].receiver_pubkey_hex().to_string(),
                    capacity_sat: 32,
                    expiry_unix: now + 600,
                    max_amount_per_output: 0,
                    unit: "sat".into(),
                    opening_paid_msat: 0,
                    keyset_id: None,
                    keyset_info_json: None,
                    client_request_id: Some(format!("native-{buyer}-{seller}")),
                    route_created_at_unix: Some(now),
                },
            )
            .await
            .unwrap();
            let channel = ChannelTerms {
                id: opened.channel.channel_id,
                buyer: *peers[buyer].node_addr(),
                mint_url: mint.url().to_string(),
                expires_unix: now + 540,
                capacity_sat: 32,
                grace_msat: rate * 4_096,
            };
            let quote = Contract {
                id: format!("native-{buyer}-{seller}"),
                channel_id: channel.id.clone(),
                destination: *peers[destination].node_addr(),
                next_hop: *peers[next].node_addr(),
                expires_unix: now + 300,
                price: BytePrice {
                    msat: rate,
                    per_bytes: 1,
                },
                max_units: 20_000,
            };
            approvals[seller].push(ApprovedAgreement {
                channel: channel.clone(),
                quotes: vec![quote.clone()],
            });
            buyers[buyer].accept_channel(*peers[seller].node_addr(), channel.clone(), 0).unwrap();
            buyers[buyer].accept_quote(quote).unwrap();
            links.push(Link {
                buyer,
                seller,
                channel,
                opening: opened.channel.payment,
            });
        }
        let mut controls = Vec::new();
        let mut servers = Vec::new();
        for (i, receiver) in receivers.into_iter().enumerate() {
            let neighbors = peers
                .iter()
                .enumerate()
                .filter(|(j, _)| i.abs_diff(*j) == 1)
                .map(|(_, id)| *id)
                .collect();
            let (control, incoming) =
                ControlTransport::start(nodes[i].clone(), SERVICE, neighbors, i as u64 + 1)
                    .await
                    .unwrap();
            servers.push(PaymentServer::start(
                PaymentControl::new(
                    receiver,
                    ledgers[i].clone(),
                    std::mem::take(&mut approvals[i]),
                )
                .unwrap(),
                incoming,
            ));
            controls.push(control);
        }
        let mut forged = links[0].opening.clone();
        forged.balance += 1;
        assert!(matches!(
            request(
                &controls[0],
                peers[1],
                PaymentRequest::Open {
                    channel_id: links[0].channel.id.clone(),
                    payment: forged
                }
            )
            .await,
            PaymentResponse::Rejected
        ));
        assert!(ledgers[1].channel_usage(&links[0].channel.id).is_none());
        for link in &links {
            let result = status(
                request(
                    &controls[link.buyer],
                    peers[link.seller],
                    PaymentRequest::Open {
                        channel_id: link.channel.id.clone(),
                        payment: link.opening.clone(),
                    },
                )
                .await,
            );
            assert_eq!(result.paid_msat, 0);
        }
        assert!(matches!(
            request(
                &controls[2],
                peers[1],
                PaymentRequest::Usage {
                    channel_id: links[0].channel.id.clone()
                }
            )
            .await,
            PaymentResponse::Rejected
        ));
        for round in 0..4 {
            for (source, destination) in [(0, 4), (4, 0)] {
                // Leave room for routed FIPS/session/service headers on the
                // default 1280-byte path. Oversized service datagrams are not
                // application-fragmented by the endpoint send API.
                let mut payload = vec![round as u8; 1_000];
                payload[0] = source as u8;
                nodes[source]
                    .send_datagram(peers[destination], DATA, DATA, payload.clone())
                    .await
                    .unwrap();
                let mut received = Vec::new();
                tokio::time::timeout(
                    Duration::from_secs(10),
                    data[destination].recv_batch_into(&mut received, 8),
                )
                .await
                .unwrap_or_else(|_| panic!("paid native delivery {source}->{destination}, round {round}; usage={:?}; denied={:?}",
                    links.iter().map(|link| (link.buyer, link.seller, ledgers[link.seller].channel_usage(&link.channel.id))).collect::<Vec<_>>(),
                    audits.iter().map(|audit| audit.denied.lock().unwrap().clone()).collect::<Vec<_>>()))
                .unwrap();
                assert!(
                    received
                        .iter()
                        .any(|message| message.source_peer == peers[source]
                            && message.data.as_slice() == payload)
                );
            }
            pay_usage(&controls, &peers, &wallets, &links, &buyers).await;
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        for link in &links {
            let usage = status(
                request(
                    &controls[link.buyer],
                    peers[link.seller],
                    PaymentRequest::StopForwarding {
                        channel_id: link.channel.id.clone(),
                    },
                )
                .await,
            );
            assert!(
                usage.submitted_msat > 0,
                "every forwarder must submit native traffic"
            );
            assert_eq!(usage.lost_msat, 0);
            assert!(ledgers[link.seller].usage(&format!("native-{}-{}", link.buyer, link.seller)).unwrap().submitted_units >= 4_000);
        }
        for (i, node) in nodes.iter().enumerate() {
            for connected in node.peers().await.unwrap().iter().filter(|peer| peer.connected) {
                assert!(peers.iter().enumerate().any(|(j, peer)| i.abs_diff(j) == 1 && peer.node_addr() == &connected.node_addr), "native data cannot create a shortcut around the paid chain");
            }
        }
        pay_usage(&controls, &peers, &wallets, &links, &buyers).await;
        // An exhausted/closed middle path cannot silently bypass native gates.
        nodes[0]
            .send_datagram(peers[4], DATA, DATA, b"blocked".to_vec())
            .await
            .unwrap();
        let mut received = Vec::new();
        assert!(
            tokio::time::timeout(
                Duration::from_millis(200),
                data[4].recv_batch_into(&mut received, 8)
            )
            .await
            .is_err()
        );
        let mut expected = [128i64; 5];
        for link in &links {
            let paid = ledgers[link.seller]
                .channel_usage(&link.channel.id)
                .unwrap()
                .paid_msat
                / 1_000;
            expected[link.buyer] -= paid as i64;
            expected[link.seller] += paid as i64;
        }
        assert!(
            expected[1..4].iter().all(|balance| *balance > 128),
            "all three relays retain a margin after buying downstream"
        );
        for server in servers {
            server.stop().await;
        }
        drop(controls);
        for node in &nodes {
            node.shutdown().await.unwrap();
        }
        for link in &links {
            let receiver = FileSpilmanPaymentReceiver::load_with_keyset_refresh(
                &root.path().join(format!("receiver-{}", link.seller)),
                FileSpilmanPaymentReceiverConfig::new([mint.url().to_string()]),
            )
            .await
            .unwrap();
            let closed = receiver
                .close_cashu_spilman_channel(&link.channel.id)
                .await
                .unwrap();
            assert_eq!(
                closed.receiver_sum * 1_000,
                ledgers[link.seller]
                    .channel_usage(&link.channel.id)
                    .unwrap()
                    .paid_msat
            );
            let proofs: Vec<Proof> = serde_json::from_str(&closed.receiver_proofs_json).unwrap();
            let token = Token::new(mint.url().parse().unwrap(), proofs, None, CurrencyUnit::Sat)
                .to_string();
            receive_payment_token(&wallets[link.seller], &token)
                .await
                .unwrap();
            assert!(
                restore_streaming_route_cashu_spilman_refund(
                    &wallets[link.buyer],
                    &link.channel.id
                )
                .await
                .unwrap()
                .complete
            );
        }
        for (wallet, balance) in wallets.iter().zip(expected) {
            assert_eq!(
                load_mint_balance(wallet, mint.url())
                    .await
                    .unwrap()
                    .balance_sat,
                balance as u64
            );
            let spent = send_payment_token(wallet, mint.url(), balance as u64)
                .await
                .unwrap();
            receive_payment_token(&root.path().join("collector"), &spent.token)
                .await
                .unwrap();
        }
        assert_eq!(
            load_mint_balance(&root.path().join("collector"), mint.url())
                .await
                .unwrap()
                .balance_sat,
            640
        );
        assert!(network.accounting().unwrap().is_conserved());
    })
    .await
    .expect("native forwarding/payment/settlement deadline");
}
