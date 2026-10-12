//! Native socket policy injection without changing virtual-network behavior.

use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;

use tokio::sync::Mutex;
use upstream::vnet::interface::Interface;
use upstream::vnet::router::Nic;
use upstream::{Conn, Error, Result};

pub use upstream::vnet::net::{NetConfig, VNet};

pub type NetFuture<'a, T> = Pin<Box<dyn Future<Output = Result<T>> + Send + 'a>>;
pub type Connection = Arc<dyn Conn + Send + Sync>;

/// Host-owned native network access for every ICE socket and name lookup.
///
/// Implementations must protect sockets before they can send packets, including
/// connected UDP sockets. A denial is final: the stack never retries through the
/// ordinary native network. Connections retain the upstream `Conn` identity.
pub trait NativeNet: Send + Sync {
    fn interfaces(&self) -> Vec<Interface>;
    fn resolve_addr<'a>(&'a self, use_ipv4: bool, address: &'a str) -> NetFuture<'a, SocketAddr>;
    fn bind(&self, address: SocketAddr) -> NetFuture<'_, Connection>;
    fn dial<'a>(&'a self, use_ipv4: bool, address: &'a str) -> NetFuture<'a, Connection>;
}

/// The original virtual/native networks plus an explicitly protected backend.
pub enum Net {
    VNet(Arc<Mutex<VNet>>),
    Ifs(Vec<Interface>),
    Native(Arc<dyn NativeNet>),
}

impl Net {
    pub fn new(config: Option<NetConfig>) -> Self {
        match upstream::vnet::net::Net::new(config) {
            upstream::vnet::net::Net::VNet(net) => Self::VNet(net),
            upstream::vnet::net::Net::Ifs(interfaces) => Self::Ifs(interfaces),
        }
    }

    pub fn new_native(network: Arc<dyn NativeNet>) -> Self {
        Self::Native(network)
    }

    pub async fn get_interfaces(&self) -> Vec<Interface> {
        match self {
            Self::VNet(net) => {
                upstream::vnet::net::Net::VNet(Arc::clone(net))
                    .get_interfaces()
                    .await
            }
            Self::Ifs(interfaces) => interfaces.clone(),
            Self::Native(network) => network.interfaces(),
        }
    }

    pub async fn get_interface(&self, name: &str) -> Option<Interface> {
        match self {
            Self::VNet(net) => {
                upstream::vnet::net::Net::VNet(Arc::clone(net))
                    .get_interface(name)
                    .await
            }
            Self::Ifs(interfaces) => interfaces.iter().find(|i| i.name() == name).cloned(),
            Self::Native(network) => network.interfaces().into_iter().find(|i| i.name() == name),
        }
    }

    pub fn is_virtual(&self) -> bool {
        matches!(self, Self::VNet(_))
    }

    pub async fn resolve_addr(&self, use_ipv4: bool, address: &str) -> Result<SocketAddr> {
        match self {
            Self::VNet(net) => {
                upstream::vnet::net::Net::VNet(Arc::clone(net))
                    .resolve_addr(use_ipv4, address)
                    .await
            }
            Self::Ifs(interfaces) => {
                upstream::vnet::net::Net::Ifs(interfaces.clone())
                    .resolve_addr(use_ipv4, address)
                    .await
            }
            Self::Native(network) => network.resolve_addr(use_ipv4, address).await,
        }
    }

    pub async fn bind(&self, address: SocketAddr) -> Result<Connection> {
        match self {
            Self::VNet(net) => {
                upstream::vnet::net::Net::VNet(Arc::clone(net))
                    .bind(address)
                    .await
            }
            Self::Ifs(interfaces) => {
                upstream::vnet::net::Net::Ifs(interfaces.clone())
                    .bind(address)
                    .await
            }
            Self::Native(network) => network.bind(address).await,
        }
    }

    pub async fn dial(&self, use_ipv4: bool, address: &str) -> Result<Connection> {
        match self {
            Self::VNet(net) => {
                upstream::vnet::net::Net::VNet(Arc::clone(net))
                    .dial(use_ipv4, address)
                    .await
            }
            Self::Ifs(interfaces) => {
                upstream::vnet::net::Net::Ifs(interfaces.clone())
                    .dial(use_ipv4, address)
                    .await
            }
            Self::Native(network) => network.dial(use_ipv4, address).await,
        }
    }

    pub fn get_nic(&self) -> Result<Arc<Mutex<dyn Nic + Send + Sync>>> {
        match self {
            Self::VNet(net) => upstream::vnet::net::Net::VNet(Arc::clone(net)).get_nic(),
            Self::Ifs(_) | Self::Native(_) => Err(Error::ErrVnetDisabled),
        }
    }
}
