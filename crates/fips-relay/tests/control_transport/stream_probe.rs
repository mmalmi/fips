//! Drive the optional device diagnostic through real encrypted native endpoints.
use super::*;
use fips_relay::probe::stream::{self, StreamProbe, StreamReport};
use std::sync::Mutex;
use tokio::sync::watch;

type Progress = Arc<Mutex<Option<StreamReport>>>;

fn shape(peer: &FipsEndpoint, connect: bool) -> StreamProbe {
    StreamProbe {
        peer: peer.npub().into(),
        stream_id: "102030405060708090a0b0c0d0e0f000".into(),
        bytes: 512 * 1024,
        bytes_per_second: 1024 * 1024,
        duration_secs: 6,
        connect,
    }
}

async fn observed(progress: &Progress, check: impl Fn(&StreamReport) -> bool) {
    tokio::time::timeout(Duration::from_secs(4), async {
        loop {
            if progress.lock().unwrap().as_ref().is_some_and(&check) {
                return;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("stream diagnostic progress deadline");
}

fn start(
    endpoint: Arc<FipsEndpoint>,
    shape: StreamProbe,
    progress: Progress,
    stop: watch::Receiver<bool>,
) -> tokio::task::JoinHandle<Result<StreamReport, String>> {
    tokio::spawn(async move { stream::run(endpoint, shape, &progress, stop).await })
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn stream_probe_recovers_duplex_bytes_and_partial_writes_without_replay() {
    let network = SimNetwork::new(744);
    let registration = Network(format!("stream-probe-{}", Identity::generate().node_addr()));
    fips_core::register_sim_network(registration.0.clone(), network.clone());
    let (a, b) = simulated_pair(&registration.0).await;
    let (stop, receive_stop) = watch::channel(false);
    let first = Arc::new(Mutex::new(None));
    let second = Arc::new(Mutex::new(None));
    let server = start(
        b.clone(),
        shape(&a, false),
        second.clone(),
        receive_stop.clone(),
    );
    observed(&second, |p| p.ready).await;
    let client = start(a.clone(), shape(&b, true), first.clone(), receive_stop);
    observed(&first, |p| p.connected).await;
    observed(&second, |p| p.connected).await;
    network.set_directed_link(
        "sender",
        "receiver",
        Some(SimLink {
            loss_probability: 1.0,
            ..Default::default()
        }),
    );
    let before = network.stats();
    tokio::time::sleep(Duration::from_secs(2)).await;
    network.set_directed_link("sender", "receiver", None);
    let (sent, received) = tokio::join!(client, server);
    let reports = [sent.unwrap().unwrap(), received.unwrap().unwrap()];
    assert!(network.stats().delta_since(&before).packets_dropped_loss > 0);
    assert!(
        reports.iter().any(|p| p.partial_writes > 0),
        "exercise accepted-prefix cursors under backpressure"
    );
    for p in &reports {
        assert_eq!(p.accepted_bytes, 512 * 1024);
        assert_eq!(p.received_bytes, p.accepted_bytes);
        assert_eq!(p.acknowledged_bytes, p.accepted_bytes);
        assert!(p.finished && p.completed_us.is_some() && p.stopped_reason.is_none());
        assert!(
            p.elapsed_us >= 6_000_000,
            "keep servicing the peer through the drain window"
        );
    }
    assert_eq!(reports[0].received_sha256, reports[1].received_sha256);
    drop(stop);
    a.shutdown().await.unwrap();
    b.shutdown().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn stream_probe_bounds_cancellation_rebind_and_authenticated_peer_admission() {
    let (a, b) = pair().await;
    let progress = Arc::new(Mutex::new(None));
    let (stop, receive_stop) = watch::channel(false);
    let mut request = shape(&a, false);
    request.bytes = u64::MAX;
    assert!(
        stream::run(b.clone(), request, &progress, receive_stop.clone())
            .await
            .is_err()
    );
    assert!(
        progress.lock().unwrap().is_none(),
        "invalid input cannot arm a receiver"
    );
    let mut request = shape(&a, false);
    request.duration_secs = 300;
    let server = start(b.clone(), request, progress.clone(), receive_stop);
    observed(&progress, |p| p.ready).await;
    stop.send_replace(true);
    let error = tokio::time::timeout(Duration::from_secs(1), server)
        .await
        .unwrap()
        .unwrap()
        .unwrap_err();
    assert!(error.contains("cancelled"));
    assert!(progress.lock().unwrap().as_ref().unwrap().finished);

    // Reuse the same bounded service port after native cleanup. The real peer
    // may send SYNs but cannot allocate TCP state for another armed identity.
    let (stop, receive_stop) = watch::channel(false);
    let progress = Arc::new(Mutex::new(None));
    let mut request = shape(&a, false);
    request.peer = PeerIdentity::from_pubkey_full(Identity::generate().pubkey_full()).npub();
    request.duration_secs = 4;
    let server = start(b.clone(), request, progress.clone(), receive_stop);
    observed(&progress, |p| p.ready).await;
    let mut stranger =
        FipsTcpEndpoint::bind(a.clone(), stream::PORT, fips_tcp::Config::default(), 5)
            .await
            .unwrap();
    stranger
        .connect(PeerIdentity::from_npub(b.npub()).unwrap(), 0)
        .await
        .unwrap();
    observed(&progress, |p| p.rejected_datagrams > 0).await;
    assert!(server.await.unwrap().unwrap_err().contains("deadline"));
    let final_report = progress.lock().unwrap().clone().unwrap();
    assert!(!final_report.connected);
    assert_eq!(final_report.received_bytes, 0);
    assert!(final_report.completed_us.is_none());
    drop((stop, stranger));
    a.shutdown().await.unwrap();
    b.shutdown().await.unwrap();
}
