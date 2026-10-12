use super::*;
use crate::config::UdpConfig;
use crate::transport::udp::UdpTransport;
use crate::transport::{Transport, TransportAddr, TransportId, TransportState, packet_channel};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[derive(Debug)]
struct FixtureNetwork {
    address: SocketAddr,
    denied: bool,
    protected: AtomicUsize,
    resolved: AtomicUsize,
}

impl HostNetwork for FixtureNetwork {
    fn protect_socket(&self, socket: &socket2::SockRef<'_>) -> io::Result<()> {
        if socket.r#type()? == socket2::Type::STREAM {
            assert_eq!(socket.local_addr()?.as_socket().unwrap().port(), 0);
        }
        self.protected.fetch_add(1, Ordering::SeqCst);
        if self.denied {
            Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "host policy denied socket",
            ))
        } else {
            Ok(())
        }
    }

    fn resolve<'a>(
        &'a self,
        address: &'a str,
    ) -> Pin<Box<dyn Future<Output = io::Result<Vec<SocketAddr>>> + Send + Sync + 'a>> {
        Box::pin(async move {
            assert_eq!(address, "carrier.invalid:1234");
            self.resolved.fetch_add(1, Ordering::SeqCst);
            Ok(vec![self.address])
        })
    }
}

#[tokio::test]
async fn denied_carrier_socket_never_contacts_listener_or_claims_a_port() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let policy = FixtureNetwork {
        address,
        denied: true,
        protected: AtomicUsize::new(0),
        resolved: AtomicUsize::new(0),
    };
    assert_eq!(
        connect_tcp(Some(&policy), address)
            .await
            .unwrap_err()
            .kind(),
        io::ErrorKind::PermissionDenied,
    );
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(50), listener.accept())
            .await
            .is_err()
    );
    assert_eq!(
        listen_tcp(Some(&policy), address).await.unwrap_err().kind(),
        io::ErrorKind::PermissionDenied,
        "protection is checked before a bind can fail with address-in-use",
    );
    assert_eq!(policy.protected.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn host_resolver_and_protected_tcp_preserve_bidirectional_streams() {
    let policy = Arc::new(FixtureNetwork {
        address: "127.0.0.1:0".parse().unwrap(),
        denied: false,
        protected: AtomicUsize::new(0),
        resolved: AtomicUsize::new(0),
    });
    let listener = listen_tcp(Some(&*policy), policy.address).await.unwrap();
    let address = listener.local_addr().unwrap();
    let client = connect_tcp(Some(&*policy), address);
    let (mut client, (mut accepted, _)) = tokio::try_join!(client, listener.accept()).unwrap();
    client.write_all(b"carrier").await.unwrap();
    let mut message = [0; 7];
    accepted.read_exact(&mut message).await.unwrap();
    assert_eq!(&message, b"carrier");
    accepted.write_all(b"reply").await.unwrap();
    let mut reply = [0; 5];
    client.read_exact(&mut reply).await.unwrap();
    assert_eq!(&reply, b"reply");
    assert_eq!(policy.protected.load(Ordering::SeqCst), 2);

    assert_eq!(
        resolve(Some(&*policy), "carrier.invalid:1234")
            .await
            .unwrap(),
        vec![policy.address]
    );
    assert_eq!(
        resolve(Some(&*policy), &address.to_string()).await.unwrap(),
        vec![address]
    );
    assert_eq!(
        policy.resolved.load(Ordering::SeqCst),
        1,
        "numeric addresses bypass DNS"
    );
}

#[tokio::test]
async fn udp_policy_covers_normal_exclusive_and_adopted_socket_start() {
    let policy = Arc::new(FixtureNetwork {
        address: "127.0.0.1:1234".parse().unwrap(),
        denied: true,
        protected: AtomicUsize::new(0),
        resolved: AtomicUsize::new(0),
    });
    for mode in 0..3 {
        let (packets, _received) = packet_channel(8);
        let mut transport = UdpTransport::new(
            TransportId::new(1),
            None,
            UdpConfig {
                bind_addr: Some("127.0.0.1:0".into()),
                ..Default::default()
            },
            packets,
        )
        .with_host_network(Some(policy.clone()));
        let result = match mode {
            0 => transport.start_async().await,
            1 => transport.start_exclusive_async().await,
            _ => {
                transport
                    .adopt_socket_async(std::net::UdpSocket::bind("127.0.0.1:0").unwrap())
                    .await
            }
        };
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("host policy denied socket")
        );
        assert_eq!(transport.state(), TransportState::Failed);
        assert!(transport.local_addr().is_none());
    }
    assert_eq!(policy.protected.load(Ordering::SeqCst), 3);
}

#[tokio::test]
async fn udp_carrier_uses_host_dns_and_reprotects_rebuilt_sockets() {
    let receiver = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let policy = Arc::new(FixtureNetwork {
        address: receiver.local_addr().unwrap(),
        denied: false,
        protected: AtomicUsize::new(0),
        resolved: AtomicUsize::new(0),
    });
    let (packets, _received) = packet_channel(8);
    let mut transport = UdpTransport::new(
        TransportId::new(1),
        None,
        UdpConfig {
            bind_addr: Some("127.0.0.1:0".into()),
            ..Default::default()
        },
        packets,
    )
    .with_host_network(Some(policy.clone()));
    transport.start_async().await.unwrap();
    let target = TransportAddr::from_string("carrier.invalid:1234");
    for generation in 0..2 {
        transport
            .send_async(&target, b"protected carrier")
            .await
            .unwrap();
        let mut packet = [0; 64];
        let (length, _) = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            receiver.recv_from(&mut packet),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(&packet[..length], b"protected carrier");
        if generation == 0 {
            transport
                .network_rebind_probe(None)
                .unwrap()
                .unwrap()
                .prepare()
                .await
                .unwrap();
            assert!(
                transport
                    .rebind_after_prepared_network_change(None)
                    .await
                    .unwrap()
            );
        }
    }
    assert_eq!(
        policy.protected.load(Ordering::SeqCst),
        3,
        "initial, preparation, and rebuilt socket"
    );
    assert!(policy.resolved.load(Ordering::SeqCst) >= 1);
    transport.stop_async().await.unwrap();
}

#[tokio::test]
async fn protected_websocket_preserves_original_host_and_path() {
    use futures::{SinkExt, StreamExt};
    use tokio_tungstenite::tungstenite::Message;
    use tokio_tungstenite::tungstenite::handshake::server::{
        Callback, ErrorResponse, Request, Response,
    };

    struct OriginalRequest;
    impl Callback for OriginalRequest {
        fn on_request(
            self,
            request: &Request,
            response: Response,
        ) -> std::result::Result<Response, ErrorResponse> {
            assert_eq!(
                request.uri().path_and_query().unwrap().as_str(),
                "/carrier?scope=fixture"
            );
            assert_eq!(request.headers()["host"], "carrier.invalid:1234");
            Ok(response)
        }
    }

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let policy = FixtureNetwork {
        address: listener.local_addr().unwrap(),
        denied: false,
        protected: AtomicUsize::new(0),
        resolved: AtomicUsize::new(0),
    };
    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut websocket = tokio_tungstenite::accept_hdr_async(stream, OriginalRequest)
            .await
            .unwrap();
        let message = websocket.next().await.unwrap().unwrap();
        assert_eq!(message, Message::Text("protected".into()));
        websocket.send(message).await.unwrap();
    });
    let (mut websocket, _) = connect_websocket(
        Some(&policy),
        "ws://carrier.invalid:1234/carrier?scope=fixture",
        None,
        None,
    )
    .await
    .unwrap();
    websocket
        .send(Message::Text("protected".into()))
        .await
        .unwrap();
    assert_eq!(
        websocket.next().await.unwrap().unwrap(),
        Message::Text("protected".into())
    );
    server.await.unwrap();
    assert_eq!(policy.protected.load(Ordering::SeqCst), 1);
    assert_eq!(policy.resolved.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn nostr_carrier_preserves_messages_and_proxy_remote_dns() {
    use async_wsocket::{ConnectionMode, Message};
    use futures::{SinkExt, StreamExt};
    use nostr_sdk::pool::transport::websocket::WebSocketTransport;
    use tokio_tungstenite::tungstenite::Message as WireMessage;

    for proxy in [false, true] {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let policy = Arc::new(FixtureNetwork {
            address,
            denied: false,
            protected: AtomicUsize::new(0),
            resolved: AtomicUsize::new(0),
        });
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            if proxy {
                let mut greeting = [0; 3];
                stream.read_exact(&mut greeting).await.unwrap();
                assert_eq!(greeting, [5, 1, 0]);
                stream.write_all(&[5, 0]).await.unwrap();
                let mut header = [0; 5];
                stream.read_exact(&mut header).await.unwrap();
                assert_eq!(&header[..4], &[5, 1, 0, 3]);
                let mut hostname = vec![0; usize::from(header[4])];
                stream.read_exact(&mut hostname).await.unwrap();
                assert_eq!(hostname, b"carrier.invalid");
                assert_eq!(stream.read_u16().await.unwrap(), 1234);
                stream
                    .write_all(&[5, 0, 0, 1, 127, 0, 0, 1, 4, 210])
                    .await
                    .unwrap();
            }
            let mut websocket = tokio_tungstenite::accept_async(stream).await.unwrap();
            assert_eq!(
                websocket.next().await.unwrap().unwrap(),
                WireMessage::Text("[\"REQ\",\"fixture\",{}]".into())
            );
            websocket
                .send(WireMessage::Binary(vec![0, 1, 255].into()))
                .await
                .unwrap();
            assert_eq!(
                websocket.next().await.unwrap().unwrap(),
                WireMessage::Ping(vec![7].into())
            );
            // Reading the next message flushes tungstenite's automatic Pong.
            let WireMessage::Close(Some(close)) = websocket.next().await.unwrap().unwrap() else {
                panic!("close frame missing")
            };
            assert_eq!(u16::from(close.code), 1000);
            assert_eq!(close.reason.as_str(), "finished");
            websocket.flush().await.unwrap();
        });
        let transport = NostrHostTransport(policy.clone());
        assert!(transport.support_ping());
        let url = ::nostr::Url::parse("ws://carrier.invalid:1234/").unwrap();
        let mode = if proxy {
            ConnectionMode::Proxy(address)
        } else {
            ConnectionMode::Direct
        };
        let (mut sink, mut stream) = transport
            .connect(&url, &mode, std::time::Duration::from_secs(2))
            .await
            .unwrap();
        sink.send(Message::Text("[\"REQ\",\"fixture\",{}]".into()))
            .await
            .unwrap();
        assert_eq!(
            stream.next().await.unwrap().unwrap(),
            Message::Binary(vec![0, 1, 255])
        );
        sink.send(Message::Ping(vec![7])).await.unwrap();
        assert_eq!(
            stream.next().await.unwrap().unwrap(),
            Message::Pong(vec![7])
        );
        sink.send(Message::Close(Some(async_wsocket::message::CloseFrame {
            code: 1000,
            reason: "finished".into(),
        })))
        .await
        .unwrap();
        assert!(matches!(
            stream.next().await.unwrap().unwrap(),
            Message::Close(_)
        ));
        server.await.unwrap();
        assert_eq!(policy.protected.load(Ordering::SeqCst), 1);
        assert_eq!(policy.resolved.load(Ordering::SeqCst), usize::from(!proxy));
    }
}

#[cfg(feature = "webrtc-transport")]
#[tokio::test]
async fn protected_webrtc_native_network_resolves_and_exchanges_udp_without_fallback() {
    let destination = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let policy = Arc::new(FixtureNetwork {
        address: destination.local_addr().unwrap(),
        denied: false,
        protected: AtomicUsize::new(0),
        resolved: AtomicUsize::new(0),
    });
    let network = native_network(policy.clone()).unwrap();
    let socket = network.dial(true, "carrier.invalid:1234").await.unwrap();
    socket.send(b"carrier").await.unwrap();
    let mut bytes = [0; 32];
    let (length, peer) = destination.recv_from(&mut bytes).await.unwrap();
    assert_eq!(&bytes[..length], b"carrier");
    destination.send_to(b"reply", peer).await.unwrap();
    let length = socket.recv(&mut bytes).await.unwrap();
    assert_eq!(&bytes[..length], b"reply");
    assert_eq!(policy.resolved.load(Ordering::SeqCst), 1);
    assert_eq!(policy.protected.load(Ordering::SeqCst), 1);
    let denied = Arc::new(FixtureNetwork {
        address: destination.local_addr().unwrap(),
        denied: true,
        protected: AtomicUsize::new(0),
        resolved: AtomicUsize::new(0),
    });
    let network = native_network(denied.clone()).unwrap();
    assert!(
        network
            .bind(destination.local_addr().unwrap())
            .await
            .is_err()
    );
    assert!(network.dial(true, "carrier.invalid:1234").await.is_err());
    assert_eq!(denied.protected.load(Ordering::SeqCst), 2);
}

#[test]
fn protected_mdns_daemon_rejects_denied_socket_before_startup() {
    let denied = Arc::new(FixtureNetwork {
        address: "127.0.0.1:1234".parse().unwrap(),
        denied: true,
        protected: AtomicUsize::new(0),
        resolved: AtomicUsize::new(0),
    });
    let policy: Arc<dyn HostNetwork> = denied.clone();
    let error = mdns_daemon(Some(&policy))
        .err()
        .expect("socket must be denied");
    assert!(error.to_string().contains("host policy denied socket"));
    assert_eq!(denied.protected.load(Ordering::SeqCst), 1);
    assert_eq!(denied.resolved.load(Ordering::SeqCst), 0);
}
