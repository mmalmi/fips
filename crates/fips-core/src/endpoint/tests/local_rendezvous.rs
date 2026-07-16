use super::*;
use crate::config::RoutingMode;
use crate::discovery::local::{
    LocalInstanceAdvertisement, LocalInstanceCapability, select_capability_provider,
};
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, UdpSocket};
use std::process::Stdio;

const SERVICE_CAPABILITY: &str = "hashtree.blob/1";
const SERVICE_PORT: u16 = 39_019;
const CONSUMER_PORT: u16 = 49_019;
const CONVERGENCE_TIMEOUT: Duration = Duration::from_secs(20);
const LOCAL_PROVIDER_CHILD: &str = "FIPS_LOCAL_PROVIDER_CHILD";
const LOCAL_PROVIDER_ADDR: &str = "FIPS_LOCAL_PROVIDER_ADDR";
const LOCAL_PROVIDER_READY: &str = "FIPS_LOCAL_PROVIDER_READY";
const LOCAL_PROVIDER_STOP: &str = "FIPS_LOCAL_PROVIDER_STOP";
const LOCAL_CAPABILITY_REPLAY_CHILD: &str = "FIPS_LOCAL_CAPABILITY_REPLAY_CHILD";

fn reserve_rendezvous_addr() -> SocketAddrV4 {
    let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("reserve loopback UDP port");
    let SocketAddr::V4(addr) = socket.local_addr().expect("reserved loopback UDP address") else {
        panic!("IPv4 loopback bind returned an IPv6 address");
    };
    drop(socket);
    addr
}

fn local_config(rendezvous_addr: SocketAddrV4) -> Config {
    let mut config = Config::new();
    config.node.routing.mode = RoutingMode::ReplyLearned;
    config.node.discovery.local.enabled = true;
    config.node.discovery.local.rendezvous_addr = rendezvous_addr;
    config.node.discovery.local.retry_interval_ms = 20;
    config.node.discovery.lan.enabled = false;
    config.node.discovery.nostr.enabled = false;
    config
}

async fn bind_local(rendezvous_addr: SocketAddrV4) -> FipsEndpoint {
    FipsEndpoint::builder()
        .config(local_config(rendezvous_addr))
        .local_rendezvous()
        .without_system_tun()
        .bind()
        .await
        .expect("bind local FIPS endpoint")
}

async fn registered_capability_before_local_link() {
    let rendezvous_addr = reserve_rendezvous_addr();
    let anchor = bind_local(rendezvous_addr).await;
    let provider = bind_local(rendezvous_addr).await;
    let provider_npub = provider.npub().to_string();
    let provider_service = provider
        .register_service_receiver_with_capability(LocalInstanceCapability::service(
            SERVICE_CAPABILITY,
            SERVICE_PORT,
        ))
        .await
        .expect("register service capability before authentication");
    let consumer = bind_local(rendezvous_addr).await;

    wait_for_connected_peer(&provider, anchor.npub()).await;
    wait_for_connected_peer(&consumer, anchor.npub()).await;
    wait_for_capability(&consumer, SERVICE_CAPABILITY, &provider_npub).await;

    drop(provider_service);
    consumer.shutdown().await.expect("consumer shutdown");
    provider.shutdown().await.expect("provider shutdown");
    anchor.shutdown().await.expect("anchor shutdown");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn registered_capability_replays_after_authentication_without_slow_maintenance() {
    if std::env::var_os(LOCAL_CAPABILITY_REPLAY_CHILD).is_some() {
        registered_capability_before_local_link().await;
        return;
    }

    let status = tokio::time::timeout(
        CONVERGENCE_TIMEOUT,
        tokio::process::Command::new(std::env::current_exe().expect("test binary"))
            .arg("registered_capability_replays_after_authentication_without_slow_maintenance")
            .arg("--nocapture")
            .arg("--test-threads=1")
            .env(LOCAL_CAPABILITY_REPLAY_CHILD, "1")
            .env("FIPS_FAULT_INJECT_RX_LOOP_SLOW_MAINTENANCE_MS", "5000")
            .stdin(Stdio::null())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .status(),
    )
    .await
    .expect("isolated capability replay test timed out")
    .expect("run isolated capability replay test");
    assert!(status.success(), "isolated capability replay test failed");
}

async fn wait_for_connected_peer(endpoint: &FipsEndpoint, npub: &str) -> FipsEndpointPeer {
    tokio::time::timeout(CONVERGENCE_TIMEOUT, async {
        loop {
            if let Some(peer) = endpoint
                .peers()
                .await
                .expect("peer snapshot")
                .into_iter()
                .find(|peer| peer.npub == npub && peer.connected)
            {
                break peer;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("endpoint did not authenticate {npub}"))
}

async fn wait_for_capability(
    endpoint: &FipsEndpoint,
    name: &str,
    expected_npub: &str,
) -> LocalInstanceAdvertisement {
    tokio::time::timeout(CONVERGENCE_TIMEOUT, async {
        loop {
            let adverts = endpoint
                .local_instance_advertisements()
                .expect("local capability snapshot");
            if let Some(selected) = select_capability_provider(&adverts, name)
                && selected.npub == expected_npub
            {
                break selected.clone();
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("local capability {name} did not appear"))
}

async fn wait_for_capability_removal(endpoint: &FipsEndpoint, name: &str) {
    tokio::time::timeout(CONVERGENCE_TIMEOUT, async {
        loop {
            let adverts = endpoint
                .local_instance_advertisements()
                .expect("local capability snapshot");
            if select_capability_provider(&adverts, name).is_none() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("local capability {name} was not withdrawn"));
}

async fn wait_for_capability_removal_within(
    endpoint: &FipsEndpoint,
    name: &str,
    deadline: Duration,
) {
    let removed = tokio::time::timeout(deadline, async {
        loop {
            let adverts = endpoint
                .local_instance_advertisements()
                .expect("local capability snapshot");
            if select_capability_provider(&adverts, name).is_none() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await;
    if removed.is_err() {
        let adverts = endpoint
            .local_instance_advertisements()
            .expect("local capability snapshot after timeout");
        let peers = endpoint.peers().await.expect("peer snapshot after timeout");
        panic!(
            "local capability {name} survived provider process exit; adverts={adverts:?}; peers={peers:?}"
        );
    }
}

async fn run_local_provider_child() {
    let rendezvous_addr = std::env::var(LOCAL_PROVIDER_ADDR)
        .expect("child rendezvous address")
        .parse()
        .expect("valid child rendezvous address");
    let ready = std::env::var_os(LOCAL_PROVIDER_READY).expect("child ready path");
    let stop = std::env::var_os(LOCAL_PROVIDER_STOP).expect("child stop path");
    let provider = bind_local(rendezvous_addr).await;
    let service = provider
        .register_service_receiver_with_capability(LocalInstanceCapability::service(
            SERVICE_CAPABILITY,
            SERVICE_PORT,
        ))
        .await
        .expect("register child provider capability");
    std::fs::write(&ready, provider.npub()).expect("publish child provider identity");

    while !std::path::Path::new(&stop).exists() {
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    drop(service);
    provider.shutdown().await.expect("child provider shutdown");
}

#[derive(Clone, Copy)]
enum ProviderExit {
    Graceful,
    Forced,
}

async fn cross_process_provider_exit(exit: ProviderExit) {
    let rendezvous_addr = reserve_rendezvous_addr();
    let consumer = bind_local(rendezvous_addr).await;
    let ready_dir = tempfile::tempdir().expect("provider ready directory");
    let ready = ready_dir.path().join("provider-npub");
    let stop = ready_dir.path().join("stop");
    let mut child = tokio::process::Command::new(std::env::current_exe().expect("test binary"))
        .arg("cross_process_provider_capabilities_expire_after_exit")
        .arg("--nocapture")
        .arg("--test-threads=1")
        .env(LOCAL_PROVIDER_CHILD, "1")
        .env(LOCAL_PROVIDER_ADDR, rendezvous_addr.to_string())
        .env(LOCAL_PROVIDER_READY, &ready)
        .env(LOCAL_PROVIDER_STOP, &stop)
        .stdin(Stdio::null())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("spawn local provider child");

    let provider_npub = tokio::time::timeout(CONVERGENCE_TIMEOUT, async {
        loop {
            if let Ok(npub) = std::fs::read_to_string(&ready) {
                break npub;
            }
            assert!(
                child.try_wait().expect("provider child status").is_none(),
                "provider child exited before advertising"
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("provider child did not start");
    wait_for_capability(&consumer, SERVICE_CAPABILITY, &provider_npub).await;

    match exit {
        ProviderExit::Graceful => {
            std::fs::write(&stop, b"stop").expect("signal graceful provider shutdown");
            let status = tokio::time::timeout(CONVERGENCE_TIMEOUT, child.wait())
                .await
                .expect("provider child graceful exit timed out")
                .expect("provider child status");
            assert!(status.success(), "provider child failed: {status}");
        }
        ProviderExit::Forced => {
            child.kill().await.expect("kill provider child");
            let _ = child.wait().await;
        }
    }

    wait_for_capability_removal_within(&consumer, SERVICE_CAPABILITY, Duration::from_secs(10))
        .await;
    consumer.shutdown().await.expect("consumer shutdown");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cross_process_provider_capabilities_expire_after_exit() {
    if std::env::var_os(LOCAL_PROVIDER_CHILD).is_some() {
        run_local_provider_child().await;
        return;
    }
    cross_process_provider_exit(ProviderExit::Graceful).await;
    cross_process_provider_exit(ProviderExit::Forced).await;
}

async fn receive_service_datagram(
    receiver: &FipsEndpointServiceReceiver,
    expected: &[u8],
) -> FipsEndpointServiceDatagram {
    tokio::time::timeout(CONVERGENCE_TIMEOUT, async {
        loop {
            let mut datagrams = Vec::new();
            receiver
                .recv_batch_into(&mut datagrams, 8)
                .await
                .unwrap_or_else(|| panic!("service receiver closed before {expected:?}"));
            if let Some(datagram) = datagrams
                .into_iter()
                .find(|datagram| datagram.data.as_slice() == expected)
            {
                break datagram;
            }
        }
    })
    .await
    .unwrap_or_else(|_| panic!("timed out waiting for {expected:?}"))
}

fn assert_loopback_udp(peer: &FipsEndpointPeer) {
    assert_eq!(peer.transport_type.as_deref(), Some("udp"));
    let addr = peer
        .transport_addr
        .as_deref()
        .expect("authenticated peer transport address")
        .parse::<SocketAddr>()
        .expect("UDP transport address");
    assert!(addr.ip().is_loopback());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn fixed_loopback_rendezvous_authenticates_capabilities_and_survives_anchor_exit() {
    let rendezvous_addr = reserve_rendezvous_addr();

    // The first exclusive binder is only a rendezvous anchor. Its lower
    // service priority must not affect ownership of the fixed socket.
    let anchor = bind_local(rendezvous_addr).await;
    let anchor_npub = anchor.npub().to_string();
    let _anchor_service = anchor
        .register_service_receiver_with_capability(
            LocalInstanceCapability::service(SERVICE_CAPABILITY, SERVICE_PORT).with_priority(1),
        )
        .await
        .expect("register anchor service capability");

    let provider = bind_local(rendezvous_addr).await;
    let provider_npub = provider.npub().to_string();
    let provider_service = provider
        .register_service_receiver_with_capability(
            LocalInstanceCapability::service(SERVICE_CAPABILITY, SERVICE_PORT).with_priority(10),
        )
        .await
        .expect("register preferred service capability");

    let consumer = bind_local(rendezvous_addr).await;
    let consumer_npub = consumer.npub().to_string();

    assert_loopback_udp(&wait_for_connected_peer(&provider, &anchor_npub).await);
    assert_loopback_udp(&wait_for_connected_peer(&consumer, &anchor_npub).await);
    assert_loopback_udp(&wait_for_connected_peer(&anchor, &provider_npub).await);
    assert_loopback_udp(&wait_for_connected_peer(&anchor, &consumer_npub).await);
    assert!(
        consumer
            .peers()
            .await
            .expect("consumer peer snapshot")
            .iter()
            .all(|peer| peer.npub != provider_npub || !peer.connected),
        "clients should initially use the authenticated rendezvous star"
    );

    let selected = wait_for_capability(&consumer, SERVICE_CAPABILITY, &provider_npub).await;
    assert_eq!(selected.npub, provider_npub);
    let capability = selected
        .capability(SERVICE_CAPABILITY)
        .expect("selected service capability");
    assert_eq!(capability.priority, 10);
    assert_eq!(capability.fsp_port, Some(SERVICE_PORT));

    consumer
        .send_datagram(
            PeerIdentity::from_npub(&provider_npub).expect("provider identity"),
            CONSUMER_PORT,
            SERVICE_PORT,
            b"through-anchor".to_vec(),
        )
        .await
        .expect("send through authenticated rendezvous star");
    let request = receive_service_datagram(&provider_service, b"through-anchor").await;
    assert_eq!(request.source_peer.npub(), consumer_npub);
    assert_eq!(request.data.as_slice(), b"through-anchor");

    // Releasing the exclusive bind lets either survivor become the next
    // anchor. They must authenticate again with ordinary Noise IK, then
    // rebuild the same FSP capability directory.
    anchor.shutdown().await.expect("anchor shutdown");
    assert_loopback_udp(&wait_for_connected_peer(&consumer, &provider_npub).await);
    assert_eq!(
        wait_for_capability(&consumer, SERVICE_CAPABILITY, &provider_npub)
            .await
            .npub,
        provider_npub
    );

    consumer
        .send_datagram(
            PeerIdentity::from_npub(&provider_npub).expect("provider identity"),
            CONSUMER_PORT,
            SERVICE_PORT,
            b"after-anchor-exit".to_vec(),
        )
        .await
        .expect("send after rendezvous failover");
    let request = receive_service_datagram(&provider_service, b"after-anchor-exit").await;
    assert_eq!(request.source_peer.npub(), consumer_npub);
    assert_eq!(request.data.as_slice(), b"after-anchor-exit");

    provider.shutdown().await.expect("provider shutdown");
    wait_for_capability_removal(&consumer, SERVICE_CAPABILITY).await;
    consumer.shutdown().await.expect("consumer shutdown");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn fixed_loopback_rendezvous_survives_abrupt_anchor_task_abort() {
    let rendezvous_addr = reserve_rendezvous_addr();
    let anchor = bind_local(rendezvous_addr).await;
    let provider = bind_local(rendezvous_addr).await;
    let provider_npub = provider.npub().to_string();
    let provider_service = provider
        .register_service_receiver_with_capability(LocalInstanceCapability::service(
            SERVICE_CAPABILITY,
            SERVICE_PORT,
        ))
        .await
        .expect("register service capability");
    let consumer = bind_local(rendezvous_addr).await;
    let consumer_npub = consumer.npub().to_string();

    wait_for_connected_peer(&provider, anchor.npub()).await;
    wait_for_connected_peer(&consumer, anchor.npub()).await;
    wait_for_capability(&consumer, SERVICE_CAPABILITY, &provider_npub).await;
    consumer
        .send_datagram(
            PeerIdentity::from_npub(&provider_npub).expect("provider identity"),
            CONSUMER_PORT,
            SERVICE_PORT,
            b"before-abort".to_vec(),
        )
        .await
        .expect("send before anchor abort");
    receive_service_datagram(&provider_service, b"before-abort").await;

    let anchor_task = anchor
        .task
        .lock()
        .expect("anchor task lock")
        .take()
        .expect("running anchor task");
    anchor_task.abort();
    assert!(
        anchor_task
            .await
            .expect_err("anchor task should abort")
            .is_cancelled()
    );

    assert_loopback_udp(&wait_for_connected_peer(&provider, &consumer_npub).await);
    assert_loopback_udp(&wait_for_connected_peer(&consumer, &provider_npub).await);
    wait_for_capability(&consumer, SERVICE_CAPABILITY, &provider_npub).await;
    consumer
        .send_datagram(
            PeerIdentity::from_npub(&provider_npub).expect("provider identity"),
            CONSUMER_PORT,
            SERVICE_PORT,
            b"after-abort".to_vec(),
        )
        .await
        .expect("send after anchor abort");
    receive_service_datagram(&provider_service, b"after-abort").await;

    provider.shutdown().await.expect("provider shutdown");
    consumer.shutdown().await.expect("consumer shutdown");
}
