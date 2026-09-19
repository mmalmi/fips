//! Real TCP/FIPS segments and encryption over the existing impaired SimTransport.
use super::*;
use fips_core::{
    Identity, SimLink, SimNetwork,
    config::SimTransportConfig,
    endpoint::{ServiceCarrierDiagnostics, ServiceCarrierSnapshot},
};
use fips_tcp::{MarkerStatus, State};
use fips_tcp_endpoint::FipsTcpEndpoint;

const PORT: u16 = 44_743;

struct Network(String);

impl Drop for Network {
    fn drop(&mut self) {
        fips_core::unregister_sim_network(&self.0);
    }
}

async fn simulated_pair(name: &str) -> (Arc<FipsEndpoint>, Arc<FipsEndpoint>) {
    let mut nodes = Vec::new();
    for address in ["sender", "receiver"] {
        let mut cfg = config();
        cfg.node.identity.persistent = false;
        cfg.node.control.enabled = false;
        cfg.transports = Default::default();
        cfg.transports.sim = TransportInstances::Single(SimTransportConfig {
            network: Some(name.into()),
            addr: Some(address.into()),
            auto_connect: Some(false),
            accept_connections: Some(true),
            ..Default::default()
        });
        nodes.push(Arc::new(
            FipsEndpoint::builder()
                .config(cfg)
                .without_system_tun()
                .bind()
                .await
                .unwrap(),
        ));
    }
    let receiver = nodes.pop().unwrap();
    let sender = nodes.pop().unwrap();
    sender
        .update_peers(vec![PeerConfig::new(receiver.npub(), "sim", "receiver")])
        .await
        .unwrap();
    while !sender
        .peers()
        .await
        .unwrap()
        .iter()
        .any(|peer| peer.connected && peer.npub == receiver.npub())
    {
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    (sender, receiver)
}

fn submitted(snapshot: &ServiceCarrierSnapshot) -> (u64, u64) {
    assert_eq!(snapshot.service_port, PORT);
    assert_eq!(snapshot.ambiguous_port_datagrams, 0);
    assert_eq!(snapshot.discarded_outputs, 0);
    for carrier in &snapshot.transports {
        assert_eq!(carrier.ethernet_framing_bytes, 0);
        if carrier.transport != "sim" {
            assert_eq!(carrier.submitted_packets, 0);
            assert_eq!(carrier.fips_payload_bytes, 0);
        }
    }
    let sim = snapshot
        .transports
        .iter()
        .find(|carrier| carrier.transport == "sim")
        .unwrap();
    (sim.submitted_packets, sim.fips_payload_bytes)
}

async fn after_submissions(handle: &ServiceCarrierDiagnostics, packets: u64) -> (u64, u64) {
    loop {
        let sample = submitted(&handle.snapshot());
        if sample.0 >= packets {
            assert_eq!(sample.0, packets, "unexpected TCP service transmission");
            // Snapshot fields are separate atomics; wait for the final byte
            // increment as well as the packet increment before comparing.
            tokio::time::sleep(Duration::from_millis(1)).await;
            if submitted(&handle.snapshot()) == sample {
                return sample;
            }
        }
        tokio::time::sleep(Duration::from_millis(1)).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn service_carrier_counts_actual_tcp_retransmission_without_unrelated_traffic() {
    tokio::time::timeout(Duration::from_secs(20), async {
        let network = SimNetwork::new(743);
        let registration = Network(format!("tcp-carrier-{}", Identity::generate().node_addr()));
        fips_core::register_sim_network(registration.0.clone(), network.clone());
        let (a, b) = simulated_pair(&registration.0).await;
        let bob = PeerIdentity::from_npub(b.npub()).unwrap();
        let measured = a.enable_service_carrier_diagnostics(PORT).unwrap();
        let server_measured = b.enable_service_carrier_diagnostics(PORT).unwrap();
        let same_handle = a.enable_service_carrier_diagnostics(PORT).unwrap();
        assert_eq!(
            measured, same_handle,
            "registration preserves the counter epoch"
        );
        let mut client = FipsTcpEndpoint::bind(a.clone(), PORT, fips_tcp::Config::default(), 1)
            .await
            .unwrap();
        let mut server = FipsTcpEndpoint::bind(b.clone(), PORT, fips_tcp::Config::default(), 2)
            .await
            .unwrap();
        let outgoing = client.connect(bob, 0).await.unwrap();
        server.receive(10).await.unwrap(); // SYN -> SYN/ACK
        client.receive(20).await.unwrap(); // SYN/ACK -> ACK
        server.receive(30).await.unwrap();
        let incoming = server.accept().unwrap();
        assert_eq!(client.state(outgoing), Some(State::Established));
        assert_eq!(server.state(incoming), Some(State::Established));
        let before = after_submissions(&measured, 2).await;
        let server_before = after_submissions(&server_measured, 1).await;

        // Lose the one submitted data segment after encryption. SimTransport
        // still accepts its bytes, as a real lossy carrier would. Drive TCP's
        // clock explicitly so no second application write causes the retry.
        network.set_directed_link(
            "sender",
            "receiver",
            Some(SimLink {
                loss_probability: 1.0,
                ..Default::default()
            }),
        );
        let network_before = network.stats();
        let body = vec![42; 128];
        let mut record = (body.len() as u32).to_be_bytes().to_vec();
        record.extend_from_slice(&body);
        let (accepted, marker) = client
            .write_with_marker(outgoing, &record, 100)
            .await
            .unwrap();
        assert_eq!(accepted, record.len());
        let lost = after_submissions(&measured, before.0 + 1).await;
        let segment_bytes = lost.1 - before.1;
        assert!(
            segment_bytes > record.len() as u64,
            "includes TCP/FIPS headers"
        );
        assert!(
            network
                .stats()
                .delta_since(&network_before)
                .packets_dropped_loss
                >= 1
        );
        assert_eq!(client.marker_status(&marker), MarkerStatus::Pending);
        assert!(
            tokio::time::timeout(Duration::from_millis(20), server.receive(110))
                .await
                .is_err(),
            "the first submitted segment never reached TCP"
        );

        network.set_directed_link("sender", "receiver", None);
        client.poll(2_000).await.unwrap();
        let retried = after_submissions(&measured, before.0 + 2).await;
        assert_eq!(retried.1 - before.1, 2 * segment_bytes);
        server.receive(2_010).await.unwrap();
        client.receive(2_020).await.unwrap();
        assert_eq!(client.marker_status(&marker), MarkerStatus::Acked);
        assert_eq!(server.read(incoming, 1024, 2_030).await.unwrap(), record);
        assert!(server.read(incoming, 1024, 2_030).await.unwrap().is_empty());
        client.receive(2_040).await.unwrap(); // Receive-window update from read.
        assert_eq!(submitted(&same_handle.snapshot()), retried);
        let server_after = after_submissions(&server_measured, 3).await;
        assert!(
            server_after.0 > server_before.0,
            "TCP ACKs are attributed too"
        );
        assert!(server_after.1 > server_before.1);

        // A completed unrelated TCP exchange must leave both measured handles
        // unchanged, despite using the same endpoints and encrypted sessions.
        let baseline_a = measured.snapshot();
        let baseline_b = server_measured.snapshot();
        let (unrelated, _) = ControlTransport::start(a.clone(), PORT + 1, vec![bob], 3)
            .await
            .unwrap();
        let alice = PeerIdentity::from_npub(a.npub()).unwrap();
        let (responder, mut requests) =
            ControlTransport::start(b.clone(), PORT + 1, vec![alice], 4)
                .await
                .unwrap();
        let response = tokio::spawn(async move {
            let request = requests.recv().await.unwrap();
            request.respond.send(request.body).unwrap();
        });
        assert_eq!(unrelated.request(bob, body.clone()).await.unwrap(), body);
        response.await.unwrap();
        let application = unrelated.statistics().snapshot();
        assert_eq!(application.requests_started, 1);
        assert_eq!(application.stream_bytes_sent, record.len() as u64);
        assert_eq!(application.stream_bytes_received, record.len() as u64);
        assert_eq!(measured.snapshot(), baseline_a);
        assert_eq!(server_measured.snapshot(), baseline_b);
        drop((unrelated, responder, client, server));
        a.shutdown().await.unwrap();
        b.shutdown().await.unwrap();
    })
    .await
    .expect("controlled TCP retransmission deadline");
}
