use super::*;
use ::webrtc::util::vnet::interface::Interface;
use ::webrtc::util::vnet::net::{Connection, NativeNet, Net, NetFuture};
use std::sync::Arc;

pub(crate) fn native_network(policy: Arc<dyn HostNetwork>) -> io::Result<Arc<Net>> {
    let Net::Ifs(interfaces) = Net::new(None) else {
        return Err(io::Error::other(
            "WebRTC native interface enumeration unavailable",
        ));
    };
    Ok(Arc::new(Net::new_native(Arc::new(ProtectedNet {
        policy,
        interfaces,
    }))))
}

struct ProtectedNet {
    policy: Arc<dyn HostNetwork>,
    interfaces: Vec<Interface>,
}

impl NativeNet for ProtectedNet {
    fn interfaces(&self) -> Vec<Interface> {
        self.interfaces.clone()
    }

    fn resolve_addr<'a>(&'a self, use_ipv4: bool, address: &'a str) -> NetFuture<'a, SocketAddr> {
        Box::pin(async move {
            resolve(Some(&*self.policy), address)
                .await?
                .into_iter()
                .find(|address| address.is_ipv4() == use_ipv4)
                .ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::NotFound,
                        "carrier resolver has no address of the requested family",
                    )
                    .into()
                })
        })
    }

    fn bind(&self, address: SocketAddr) -> NetFuture<'_, Connection> {
        Box::pin(async move {
            let socket = socket2::Socket::new(
                socket2::Domain::for_address(address),
                socket2::Type::DGRAM,
                Some(socket2::Protocol::UDP),
            )?;
            socket.set_nonblocking(true)?;
            self.policy
                .protect_socket(&socket2::SockRef::from(&socket))?;
            socket.bind(&address.into())?;
            let socket = tokio::net::UdpSocket::from_std(socket.into())?;
            Ok(Arc::new(socket) as Connection)
        })
    }

    fn dial<'a>(&'a self, use_ipv4: bool, address: &'a str) -> NetFuture<'a, Connection> {
        Box::pin(async move {
            let destination = self.resolve_addr(use_ipv4, address).await?;
            let wildcard = if use_ipv4 { "0.0.0.0:0" } else { "[::]:0" }
                .parse()
                .expect("constant UDP wildcard");
            let socket = self.bind(wildcard).await?;
            socket.connect(destination).await?;
            Ok(socket)
        })
    }
}
