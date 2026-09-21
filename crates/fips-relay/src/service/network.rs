//! The relay uses native FIPS transports with an explicitly tested adapter scope.
use super::{Identity, PeerIdentity, ServiceConfig};
use crate::control_transport::NeighborAdmission;
use fips_core::{
    Config,
    config::{TransportInstances, UdpConfig, WebSocketConfig},
};
use std::{
    collections::HashSet,
    net::{IpAddr, SocketAddr},
};

impl ServiceConfig {
    pub(super) fn validate_network(&self) -> Result<(), String> {
        let counts: Vec<_> = self.transports.instance_counts().collect();
        if counts.is_empty() || counts.iter().map(|(_, count)| count).sum::<usize>() > 4 {
            return Err("configure between one and four native transport instances".into());
        }
        for (kind, _) in counts {
            if !matches!(kind, "udp" | "tcp" | "ethernet" | "websocket") {
                return Err(format!("paid relay does not yet support transport {kind}"));
            }
        }
        let mut udp_binds = Vec::new();
        for (_, udp) in self.transports.udp.iter() {
            // Validate the supplied address even when outbound-only mode changes
            // the effective bind; a typo must not silently change address family.
            if let Some(raw) = &udp.bind_addr {
                socket_address(raw, false)?;
            }
            let bind = socket_address(udp.bind_addr(), false)?;
            if let Some(interface) = &udp.bind_interface {
                validate_interface(interface)?;
            }
            udp_binds.push((bind, udp.accept_connections() && !udp.outbound_only()));
        }
        for (_, tcp) in self.transports.tcp.iter() {
            if let Some(bind) = &tcp.bind_addr {
                socket_address(bind, false)?;
            }
        }
        for (_, websocket) in self.transports.websocket.iter() {
            if let Some(bind) = &websocket.bind_addr {
                socket_address(bind, false)?;
            }
        }
        let mut interfaces = HashSet::new();
        for (_, ethernet) in self.transports.ethernet.iter() {
            validate_interface(&ethernet.interface)?;
            if !interfaces.insert(ethernet.interface.as_str()) {
                return Err("repeated native Ethernet interface".into());
            }
        }
        if let Some(network) = self.customer_network
            && (network.prefix_len() == 0
                || network.network().is_unspecified()
                || invalid_ip(network.network())
                || !udp_binds.iter().any(|(bind, accepts)| {
                    *accepts && !bind.ip().is_unspecified() && network.contains(&bind.ip())
                }))
        {
            return Err("customer entry requires an accepting UDP listener bound to a specific address inside its customer network".into());
        }
        if self.neighbors.len() > 8 {
            return Err("too many configured neighbors".into());
        }
        let mut peers = HashSet::new();
        for peer in &self.neighbors {
            let identity =
                PeerIdentity::from_npub(&peer.npub).map_err(|_| "invalid neighbor npub")?;
            if !peers.insert(*identity.node_addr())
                || peer.addresses.is_empty()
                || peer.addresses.len() > 4
            {
                return Err("invalid or repeated neighbor".into());
            }
            for address in &peer.addresses {
                match address.transport.as_str() {
                    "udp" if !udp_binds.is_empty() => {
                        let remote = socket_address(&address.addr, true)?;
                        if !udp_binds
                            .iter()
                            .any(|(bind, _)| bind.is_ipv4() == remote.is_ipv4())
                        {
                            return Err(
                                "neighbor UDP address has no configured socket family".into()
                            );
                        }
                    }
                    "tcp" if !self.transports.tcp.is_empty() => {
                        socket_address(&address.addr, true)?;
                    }
                    "websocket" if !self.transports.websocket.is_empty() => {
                        WebSocketConfig {
                            seed_urls: vec![address.addr.clone()],
                            ..Default::default()
                        }
                        .validate()?;
                    }
                    "ethernet" => {
                        let (interface, mac) = address
                            .addr
                            .split_once('/')
                            .ok_or("neighbor Ethernet address requires interface/MAC")?;
                        if !interfaces.contains(interface) {
                            return Err("neighbor uses an unconfigured Ethernet interface".into());
                        }
                        validate_mac(mac)?;
                    }
                    _ => return Err("neighbor uses an unconfigured transport".into()),
                }
            }
        }
        self.network_settings(false)
            .validate()
            .map_err(|e| e.to_string())
    }

    pub(super) fn network(&self, identity: &Identity, initializing: bool) -> Config {
        let mut config = self.network_settings(initializing);
        config.node.identity.nsec = Some(fips_core::encode_nsec(&identity.keypair().secret_key()));
        config
    }

    fn network_settings(&self, initializing: bool) -> Config {
        let mut config = Config::new();
        config.node.control.enabled = !initializing;
        config.node.control.socket_path = self
            .state_directory
            .join("native.sock")
            .to_string_lossy()
            .into_owned();
        config.node.discovery.nostr.enabled = false;
        config.node.discovery.lan.enabled = false;
        config.node.discovery.local.enabled = false;
        if self.customer_network.is_some()
            || self.neighbor_admission == NeighborAdmission::AuthenticatedAdjacent
        {
            config.node.limits.max_peers = self.neighbors.len() + 16;
            config.node.limits.max_connections = config.node.limits.max_peers * 2;
            config.node.limits.max_links = config.node.limits.max_peers * 2;
            config.node.limits.max_pending_inbound = 16;
            config.node.limits.max_sessions = 128;
        }
        if initializing {
            config.transports.udp = TransportInstances::Single(UdpConfig {
                bind_addr: Some("127.0.0.1:0".into()),
                advertise_on_nostr: Some(false),
                ..Default::default()
            });
        } else {
            config.transports = self.transports.clone();
            config.peers = self.neighbors.clone();
        }
        config
    }
}

fn invalid_ip(ip: IpAddr) -> bool {
    ip.is_multicast() || matches!(ip, IpAddr::V4(v4) if v4.is_broadcast())
}

fn socket_address(raw: &str, remote: bool) -> Result<SocketAddr, String> {
    let address: SocketAddr = raw
        .parse()
        .map_err(|_| "native socket address must be numeric")?;
    if invalid_ip(address.ip())
        || (remote && (address.port() == 0 || address.ip().is_unspecified()))
    {
        return Err("invalid native socket address".into());
    }
    Ok(address)
}

fn validate_interface(interface: &str) -> Result<(), String> {
    if interface.is_empty()
        || interface.len() > 15
        || !interface
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || b"_.-".contains(&c))
    {
        return Err("invalid native interface".into());
    }
    Ok(())
}

fn validate_mac(raw: &str) -> Result<(), String> {
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        let mac =
            fips_core::transport::ethernet::parse_mac_string(raw).map_err(|e| e.to_string())?;
        if mac == [0; 6] || mac[0] & 1 != 0 {
            return Err("neighbor Ethernet address must be nonzero unicast".into());
        }
        Ok(())
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = raw;
        Err("native Ethernet is unavailable on this platform".into())
    }
}
