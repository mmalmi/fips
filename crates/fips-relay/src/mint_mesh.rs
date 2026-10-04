//! Optional mint HTTP transport over authenticated FIPS streams.
mod bridge;
pub use bridge::MeshMintBridge;

use fips_core::PeerIdentity;
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, SocketAddr};

/// Immutable alongside the wallet's mint URL. The URL names a local adapter;
/// this identity selects its sole remote mint. No direct-network fallback exists.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MintMesh {
    pub npub: String,
    pub service_port: u16,
}

impl MintMesh {
    pub(crate) fn target(&self, mint_url: &str) -> Result<(PeerIdentity, SocketAddr), String> {
        bridge::validate_port(self.service_port)?;
        let peer = PeerIdentity::from_npub(&self.npub).map_err(|_| "invalid mesh mint identity")?;
        let url = url::Url::parse(mint_url).map_err(|_| "invalid mesh mint URL")?;
        let ip = match url.host() {
            Some(url::Host::Ipv4(ip)) => IpAddr::V4(ip),
            Some(url::Host::Ipv6(ip)) => IpAddr::V6(ip),
            _ => return Err("mesh mint URL requires a numeric loopback address".into()),
        };
        if !ip.is_loopback()
            || url.scheme() != "http"
            || !url.username().is_empty()
            || url.password().is_some()
            || url.path() != "/"
            || url.query().is_some()
            || url.fragment().is_some()
        {
            return Err("mesh mint URL must name only its fixed loopback HTTP listener".into());
        }
        let port = url
            .port_or_known_default()
            .filter(|port| *port != 0)
            .ok_or("mesh mint URL requires a nonzero port")?;
        Ok((peer, SocketAddr::new(ip, port)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn adapter_target_requires_a_pinned_identity_and_fixed_loopback_url() {
        let mut mesh = MintMesh {
            npub: fips_core::Identity::generate().npub(),
            service_port: 44_745,
        };
        assert_eq!(
            mesh.target("http://127.0.0.1:3338").unwrap().1,
            "127.0.0.1:3338".parse::<SocketAddr>().unwrap()
        );
        for url in [
            "http://localhost:3338",
            "http://192.0.2.1:3338",
            "https://127.0.0.1:3338",
            "http://user@127.0.0.1:3338",
            "http://127.0.0.1:3338/mint",
            "http://127.0.0.1:3338?fallback=1",
            "http://127.0.0.1:0",
        ] {
            assert!(mesh.target(url).is_err(), "{url}");
        }
        mesh.service_port = 44_741;
        assert!(mesh.target("http://127.0.0.1:3338").is_err());
        mesh.service_port = 44_745;
        mesh.npub = "unverified-mint".into();
        assert!(mesh.target("http://127.0.0.1:3338").is_err());
    }
}
