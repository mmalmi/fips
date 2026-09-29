//! Real TCP/FIPS records while only the native node's status loop is paused.
use super::*;
use fips_core::Config;
use std::sync::mpsc as sync_channel;

struct NodeRuntime {
    resume: Option<sync_channel::Sender<()>>,
    stop: Option<oneshot::Sender<()>>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl Drop for NodeRuntime {
    fn drop(&mut self) {
        if let Some(resume) = self.resume.take() {
            let _ = resume.send(());
        }
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        if let Some(thread) = self.thread.take() {
            let result = thread.join();
            if !std::thread::panicking() {
                result.expect("native endpoint owner exited cleanly");
            }
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn slow_adjacency_lookup_does_not_block_configured_control() {
    tokio::time::timeout(Duration::from_secs(10), scenario())
        .await
        .expect("bounded control isolation check");
}

async fn scenario() {
    let (endpoint_tx, endpoint_rx) = oneshot::channel();
    let (pause, pause_rx) = oneshot::channel();
    let (paused_tx, paused) = oneshot::channel();
    let (resume, resume_rx) = sync_channel::channel();
    let (stop, stop_rx) = oneshot::channel();
    let thread = std::thread::spawn(move || {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(async move {
                let mut config = Config::new();
                config.node.discovery.nostr.enabled = false;
                config.node.discovery.lan.enabled = false;
                config.node.discovery.local.enabled = false;
                let endpoint = Arc::new(
                    FipsEndpoint::builder()
                        .config(config)
                        .without_system_tun()
                        .bind()
                        .await
                        .unwrap(),
                );
                assert!(endpoint_tx.send(endpoint.clone()).is_ok());
                pause_rx.await.unwrap();
                paused_tx.send(()).unwrap();
                // The control transport runs on the test runtime. Local FSP
                // delivery remains synchronous; node-status commands must wait.
                resume_rx.recv_timeout(Duration::from_secs(10)).unwrap();
                let _ = stop_rx.await;
                endpoint.shutdown().await.unwrap();
            });
    });
    let mut owner = NodeRuntime {
        resume: Some(resume),
        stop: Some(stop),
        thread: Some(thread),
    };
    let endpoint = endpoint_rx.await.unwrap();
    let local = PeerIdentity::from_npub(endpoint.npub()).unwrap();
    let unknown = PeerIdentity::from_pubkey_full(fips_core::Identity::generate().pubkey_full());
    let admission = ControlAdmission::new(
        endpoint.clone(),
        vec![local],
        None,
        NeighborAdmission::AuthenticatedAdjacent,
    )
    .unwrap();
    let (transport, mut incoming) =
        ControlTransport::start_with_admission(endpoint, 44_719, admission, 1)
            .await
            .unwrap();
    let transport = Arc::new(transport);
    let echo = tokio::spawn(async move {
        while let Some(request) = incoming.recv().await {
            let _ = request.respond.send(request.body);
        }
    });
    pause.send(()).unwrap();
    paused.await.unwrap();
    assert_eq!(
        tokio::time::timeout(
            Duration::from_millis(250),
            transport.request(local, b"baseline".to_vec()),
        )
        .await
        .unwrap()
        .unwrap(),
        b"baseline"
    );
    // Let the baseline's TCP closing tuples expire before opening another pair.
    tokio::time::sleep(Duration::from_millis(300)).await;
    let client = transport.clone();
    let checking = tokio::spawn(async move { client.request(unknown, vec![0]).await });
    tokio::time::timeout(Duration::from_millis(250), async {
        while transport.outbound_slots.available_permits() != QUEUE_SIZE - 1
            || transport.commands.capacity() != QUEUE_SIZE
        {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("unknown request reached admission while native status is paused");
    assert!(!checking.is_finished());
    let healthy = tokio::time::timeout(
        Duration::from_millis(250),
        transport.request(local, b"healthy".to_vec()),
    )
    .await;
    let stayed_available = matches!(healthy, Ok(Ok(ref body)) if body == b"healthy");
    let lookup_stayed_pending = !checking.is_finished();
    owner.resume.take().unwrap().send(()).unwrap();
    assert!(checking.await.unwrap().is_err());
    assert_eq!(
        tokio::time::timeout(
            Duration::from_secs(2),
            transport.request(local, b"recovered".to_vec()),
        )
        .await
        .unwrap()
        .unwrap(),
        b"recovered"
    );
    drop(transport);
    echo.await.unwrap();
    drop(owner);
    assert!(
        lookup_stayed_pending,
        "lookup remained held through the healthy exchange"
    );
    assert!(
        stayed_available,
        "adjacency lookup must not block configured control traffic"
    );
}
