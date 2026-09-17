//! An explicit, immutable test-customer purchase policy.
use super::*;
use crate::{
    controller::{ControllerPolicy, RenewalPolicy},
    ledger::BillingBasis,
    service::ServiceTerms,
};
use fips_core::{
    PeerIdentity,
    config::{PeerConfig, TransportInstances, TransportsConfig, UdpConfig},
};
use std::net::{IpAddr, SocketAddr};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CustomerProfile {
    pub version: u16,
    pub test_only: bool,
    pub entry_npub: String,
    pub entry_address: SocketAddr,
    pub destination_npub: String,
    pub mint_url: String,
    pub budget_sat: u64,
    pub channel_capacity_sat: u64,
    pub max_rate_msat_per_kib: u64,
}

fn local_address(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v) => v.is_private() || v.is_loopback() || v.is_link_local(),
        IpAddr::V6(v) => v.is_unique_local() || v.is_loopback() || v.is_unicast_link_local(),
    }
}

impl CustomerProfile {
    pub fn validate(&self) -> Result<(), String> {
        let entry =
            PeerIdentity::from_npub(&self.entry_npub).map_err(|_| "invalid entry identity")?;
        let destination = PeerIdentity::from_npub(&self.destination_npub)
            .map_err(|_| "invalid destination identity")?;
        if self.version != 1
            || !self.test_only
            || entry == destination
            || self.budget_sat == 0
            || self.budget_sat > 512
            || !(8..=128).contains(&self.channel_capacity_sat)
            || self.channel_capacity_sat > self.budget_sat
            || !(1..=8192).contains(&self.max_rate_msat_per_kib)
            || !local_address(self.entry_address.ip())
            || self.entry_address.port() == 0
        {
            return Err("invalid test profile identities, local entry or spending limits".into());
        }
        let mint = url::Url::parse(&self.mint_url).map_err(|_| "invalid test mint URL")?;
        let ip = match mint.host() {
            Some(url::Host::Ipv4(ip)) => IpAddr::V4(ip),
            Some(url::Host::Ipv6(ip)) => IpAddr::V6(ip),
            _ => return Err("test mint must use a numeric local address".into()),
        };
        if self.mint_url.len() > 512
            || !local_address(ip)
            || mint.scheme() != "http"
            || !mint.username().is_empty()
            || mint.password().is_some()
            || mint.query().is_some()
            || mint.fragment().is_some()
            || mint.path() != "/"
        {
            return Err("test mint must be an explicit local HTTP mint".into());
        }
        Ok(())
    }

    pub(super) fn config(&self, root: &Path) -> ServiceConfig {
        ServiceConfig {
            state_directory: root.join("state"),
            transports: TransportsConfig {
                udp: TransportInstances::Single(UdpConfig {
                    bind_addr: Some(
                        if self.entry_address.is_ipv4() {
                            "0.0.0.0:0"
                        } else {
                            "[::]:0"
                        }
                        .into(),
                    ),
                    advertise_on_nostr: Some(false),
                    ..Default::default()
                }),
                ..Default::default()
            },
            customer_network: None,
            neighbor_admission: Default::default(),
            destination_fees: Default::default(),
            return_allowance: false,
            price_selection: None,
            payment_cadence: Default::default(),
            neighbors: vec![PeerConfig::new(
                &self.entry_npub,
                "udp",
                self.entry_address.to_string(),
            )],
            terms: ServiceTerms {
                billing: BillingBasis::ForwardingAttempt,
                controller: ControllerPolicy {
                    mint_url: self.mint_url.clone(),
                    channel_capacity_sat: self.channel_capacity_sat,
                    max_locked_sat: self.channel_capacity_sat * 2,
                    max_funding_overhead_sat: 0,
                    max_wallet_spend_sat: self.budget_sat,
                    channel_lifetime_secs: 7200,
                    renewal: Some(RenewalPolicy {
                        at_capacity_percent: 80,
                        before_expiry_secs: 30,
                    }),
                },
                buyer_budget_sat: self.budget_sat,
                window_msat: 4000,
                grace_msat: 8000,
                fee_msat_per_kib: 1,
                max_rate_msat_per_kib: self.max_rate_msat_per_kib,
                quote_lifetime_secs: 1800,
                quote_max_units: 128 * 1024 * 1024,
            },
        }
    }
}
