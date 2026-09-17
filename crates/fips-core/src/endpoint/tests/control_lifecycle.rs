use super::*;
use std::{io::ErrorKind, path::Path};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;

async fn status(socket: &Path) -> serde_json::Value {
    tokio::time::timeout(Duration::from_secs(3), async {
        let mut stream = loop {
            match UnixStream::connect(socket).await {
                Ok(stream) => break stream,
                Err(error)
                    if matches!(
                        error.kind(),
                        ErrorKind::NotFound | ErrorKind::ConnectionRefused
                    ) =>
                {
                    tokio::task::yield_now().await;
                }
                Err(error) => panic!("control connection failed: {error}"),
            }
        };
        stream
            .write_all(b"{\"command\":\"show_status\"}\n")
            .await
            .unwrap();
        let mut response = String::new();
        BufReader::new(stream)
            .read_line(&mut response)
            .await
            .unwrap();
        serde_json::from_str(&response).unwrap()
    })
    .await
    .expect("native control response deadline")
}

#[tokio::test]
async fn shutdown_releases_control_socket_before_rebinding() {
    tokio::time::timeout(Duration::from_secs(15), async {
        let directory = tempfile::tempdir().unwrap();
        let socket = directory.path().join("native.sock");
        let mut config = Config::new();
        config.node.identity.persistent = false;
        config.node.discovery.nostr.enabled = false;
        config.node.discovery.lan.enabled = false;
        config.node.discovery.local.enabled = false;
        config.node.control.enabled = true;
        config.node.control.socket_path = socket.to_str().unwrap().to_owned();
        config.transports.udp = TransportInstances::Single(UdpConfig {
            bind_addr: Some("127.0.0.1:0".into()),
            ..Default::default()
        });
        let mut previous_identity = None;
        for _ in 0..3 {
            let endpoint = FipsEndpoint::builder()
                .config(config.clone())
                .without_system_tun()
                .bind()
                .await
                .unwrap();
            let report = status(&socket).await;
            assert_eq!(report["status"], "ok", "{report}");
            assert_eq!(report["data"]["npub"], endpoint.npub());
            assert_ne!(previous_identity.as_deref(), Some(endpoint.npub()));
            previous_identity = Some(endpoint.npub().to_owned());

            endpoint.shutdown().await.unwrap();
            assert!(
                !socket.exists(),
                "shutdown must join the listener's socket cleanup"
            );
            assert!(UnixStream::connect(&socket).await.is_err());
        }
    })
    .await
    .expect("repeated native control shutdown deadline");
}
