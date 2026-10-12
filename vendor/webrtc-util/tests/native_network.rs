use std::io;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::net::UdpSocket;
use upstream::vnet::interface::Interface;
use upstream::Result;
use webrtc_util::vnet::net::{Connection, NativeNet, Net, NetFuture};

struct HostNetwork {
    destination: SocketAddr,
    deny: bool,
    calls: Mutex<Vec<&'static str>>,
}

impl NativeNet for HostNetwork {
    fn interfaces(&self) -> Vec<Interface> {
        Vec::new()
    }

    fn resolve_addr<'a>(&'a self, use_ipv4: bool, address: &'a str) -> NetFuture<'a, SocketAddr> {
        Box::pin(async move {
            self.calls.lock().unwrap().push("resolve");
            assert!(use_ipv4);
            assert_eq!(address, "host-network.invalid:12345");
            Ok(self.destination)
        })
    }

    fn bind(&self, address: SocketAddr) -> NetFuture<'_, Connection> {
        Box::pin(async move {
            self.calls.lock().unwrap().push("bind");
            if self.deny {
                return Err(io::Error::new(io::ErrorKind::PermissionDenied, "host denial").into());
            }
            Ok(Arc::new(UdpSocket::bind(address).await?) as Connection)
        })
    }

    fn dial<'a>(&'a self, use_ipv4: bool, address: &'a str) -> NetFuture<'a, Connection> {
        Box::pin(async move {
            self.calls.lock().unwrap().push("dial");
            let destination = self.resolve_addr(use_ipv4, address).await?;
            let connection = self.bind("127.0.0.1:0".parse().unwrap()).await?;
            connection.connect(destination).await?;
            Ok(connection)
        })
    }
}

#[tokio::test]
async fn protected_network_uses_host_resolution_and_upstream_connection_types() -> Result<()> {
    let server = UdpSocket::bind("127.0.0.1:0").await?;
    let host = Arc::new(HostNetwork {
        destination: server.local_addr()?,
        deny: false,
        calls: Mutex::new(Vec::new()),
    });
    let network = Net::new_native(host.clone());
    assert_eq!(
        network
            .resolve_addr(true, "host-network.invalid:12345")
            .await?,
        server.local_addr()?
    );
    // This upstream trait identity is shared by unmodified DTLS/STUN/SCTP crates.
    let connection: Arc<dyn upstream::Conn + Send + Sync> =
        network.dial(true, "host-network.invalid:12345").await?;
    assert_eq!(connection.send(b"hello").await?, 5);
    let mut bytes = [0; 32];
    let (length, sender) =
        tokio::time::timeout(Duration::from_secs(2), server.recv_from(&mut bytes))
            .await
            .expect("native packet arrived")?;
    assert_eq!(&bytes[..length], b"hello");
    server.send_to(b"reply", sender).await?;
    let length = tokio::time::timeout(Duration::from_secs(2), connection.recv(&mut bytes))
        .await
        .expect("native reply arrived")?;
    assert_eq!(&bytes[..length], b"reply");
    assert_eq!(
        *host.calls.lock().unwrap(),
        ["resolve", "dial", "resolve", "bind"]
    );
    Ok(())
}

#[tokio::test]
async fn denied_native_socket_does_not_fall_back_to_an_ordinary_socket() -> Result<()> {
    let server = UdpSocket::bind("127.0.0.1:0").await?;
    let host = Arc::new(HostNetwork {
        destination: server.local_addr()?,
        deny: true,
        calls: Mutex::new(Vec::new()),
    });
    let network = Net::new_native(host.clone());
    let error = match network.dial(true, "host-network.invalid:12345").await {
        Ok(_) => panic!("denied native socket was created"),
        Err(error) => error,
    };
    assert!(error.to_string().contains("host denial"));
    assert!(network.bind("127.0.0.1:0".parse().unwrap()).await.is_err());
    assert_eq!(
        *host.calls.lock().unwrap(),
        ["dial", "resolve", "bind", "bind"]
    );
    Ok(())
}
