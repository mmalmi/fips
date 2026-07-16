use std::net::{SocketAddr, SocketAddrV4};
use std::sync::Arc;
use std::time::Duration;

use fips_core::config::{RoutingMode, TransportInstances};
use fips_core::{Config, FipsEndpoint, UdpConfig};
use tokio::time::timeout;

const CONVERGENCE_TIMEOUT: Duration = Duration::from_secs(10);
const ROUTE_WORKER_STACK_BYTES: usize = 7 * 256 * 1024;

#[test]
fn local_route_handshake_fits_below_the_default_tokio_worker_stack() {
    // Tokio workers default to a 2 MiB stack. Keep a real endpoint handshake
    // below that ceiling with guard room so nested debug poll frames cannot
    // silently consume the whole production worker stack again.
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .thread_stack_size(ROUTE_WORKER_STACK_BYTES)
        .enable_all()
        .build()
        .expect("route regression runtime");
    runtime.block_on(async {
        let rendezvous = rendezvous_addr();
        let first = endpoint(rendezvous, "default-stack-route-regression").await;
        let second = endpoint(rendezvous, "default-stack-route-regression").await;

        timeout(CONVERGENCE_TIMEOUT, async {
            loop {
                let first_connected = first
                    .peers()
                    .await
                    .expect("first peer query")
                    .iter()
                    .any(|peer| peer.npub == second.npub() && peer.connected);
                let second_connected = second
                    .peers()
                    .await
                    .expect("second peer query")
                    .iter()
                    .any(|peer| peer.npub == first.npub() && peer.connected);
                if first_connected && second_connected {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("authenticated local route handshake");

        second.shutdown().await.expect("second endpoint shutdown");
        first.shutdown().await.expect("first endpoint shutdown");
    });
}

async fn endpoint(rendezvous_addr: SocketAddrV4, discovery_scope: &str) -> Arc<FipsEndpoint> {
    let mut config = Config::new();
    config.node.discovery.nostr.enabled = false;
    config.node.discovery.lan.enabled = false;
    config.node.discovery.local.rendezvous_addr = rendezvous_addr;
    config.node.routing.mode = RoutingMode::ReplyLearned;
    config.transports.udp = TransportInstances::Single(UdpConfig {
        bind_addr: Some("127.0.0.1:0".to_string()),
        advertise_on_nostr: Some(false),
        public: Some(false),
        ..UdpConfig::default()
    });
    Arc::new(
        FipsEndpoint::builder()
            .config(config)
            .discovery_scope(discovery_scope)
            .local_rendezvous()
            .without_system_tun()
            .bind()
            .await
            .expect("local endpoint"),
    )
}

fn rendezvous_addr() -> SocketAddrV4 {
    let socket = std::net::UdpSocket::bind("127.0.0.1:0").expect("ephemeral rendezvous socket");
    match socket.local_addr().expect("rendezvous address") {
        SocketAddr::V4(addr) => addr,
        SocketAddr::V6(_) => unreachable!("IPv4 bind returned an IPv6 address"),
    }
}
