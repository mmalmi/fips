//! Validate network configuration and require intact saved account state.
use super::*;
use crate::controller::PaymentCadence;
use ipnet::IpNet;

// These files must already exist before any library that can lazily initialize
// state is called. The explicit init command creates them in a fresh directory.
pub(super) const REQUIRED: &[&str] = &[
    "identity.key",
    "seller/ledger.json",
    "buyer/buyer.json",
    "controller/controller.json",
    "receiver/spilman-receiver-key.json",
    "receiver/spilman-receiver.sqlite",
    "wallet/cashu/seed.json",
    "wallet/cashu/wallet.sqlite",
    "wallet/spilman-sender-key.json",
];

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServiceTerms {
    #[serde(default, skip_serializing_if = "BillingBasis::is_legacy")]
    pub billing: BillingBasis,
    pub controller: ControllerPolicy,
    pub buyer_budget_sat: u64,
    pub window_msat: u64,
    pub grace_msat: u64,
    pub fee_msat_per_kib: u64,
    pub max_rate_msat_per_kib: u64,
    pub quote_lifetime_secs: u64,
    pub quote_max_units: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServiceConfig {
    pub state_directory: PathBuf,
    pub udp_bind: Option<SocketAddr>,
    /// Opt-in inbound payment control for authenticated direct UDP peers in
    /// this network. It does not authorize Internet access or onward purchases.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub customer_network: Option<IpNet>,
    pub ethernet_interfaces: Vec<String>,
    pub neighbors: Vec<PeerConfig>,
    pub terms: ServiceTerms,
    /// Local timing only; does not change saved financial terms or authority.
    #[serde(default, skip_serializing_if = "PaymentCadence::is_default")]
    pub payment_cadence: PaymentCadence,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Manifest {
    pub(super) version: u16,
    pub(super) npub: String,
    pub(super) receiver_pubkey: String,
    pub(super) terms: ServiceTerms,
}

pub(crate) fn read_json<T: serde::de::DeserializeOwned>(path: &Path) -> Result<T, String> {
    let mut bytes = Vec::new();
    File::open(path)
        .map_err(|e| e.to_string())?
        .take(MAX_CONFIG + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| e.to_string())?;
    if bytes.len() as u64 > MAX_CONFIG {
        return Err("configuration too large".into());
    }
    serde_json::from_slice(&bytes).map_err(|e| format!("invalid configuration: {e}"))
}

impl ServiceConfig {
    pub fn read(path: &Path) -> Result<Self, String> {
        let value: Self = read_json(path)?;
        value.validate()?;
        Ok(value)
    }

    pub fn socket_path(&self) -> PathBuf {
        self.state_directory.join("control.sock")
    }

    pub(super) fn validate(&self) -> Result<(), String> {
        self.payment_cadence.validate()?;
        if !self.state_directory.is_absolute() || self.socket_path().as_os_str().len() > 100 {
            return Err(
                "state directory must be absolute and control socket path at most 100 bytes".into(),
            );
        }
        if self.udp_bind.is_none() && self.ethernet_interfaces.is_empty() {
            return Err("configure an explicit UDP socket or native Ethernet interface".into());
        }
        if let Some(network) = self.customer_network {
            let bind = self
                .udp_bind
                .ok_or("customer entry requires an explicit UDP socket")?;
            if bind.ip().is_unspecified()
                || bind.ip().is_multicast()
                || network.prefix_len() == 0
                || network.network().is_unspecified()
                || network.network().is_multicast()
                || !network.contains(&bind.ip())
            {
                return Err(
                    "customer UDP socket must bind a specific address inside its customer network"
                        .into(),
                );
            }
        }
        if self.neighbors.len() > 8 || self.ethernet_interfaces.len() > 4 {
            return Err("too many peers or interfaces".into());
        }
        let mut interfaces = HashSet::new();
        for interface in &self.ethernet_interfaces {
            if interface.is_empty()
                || interface.len() > 15
                || !interface
                    .bytes()
                    .all(|c| c.is_ascii_alphanumeric() || b"_.-".contains(&c))
                || !interfaces.insert(interface)
            {
                return Err("invalid or repeated native interface".into());
            }
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
                    "udp" if self.udp_bind.is_some() => {
                        let addr: SocketAddr = address
                            .addr
                            .parse()
                            .map_err(|_| "neighbor UDP address must be numeric")?;
                        if addr.port() == 0
                            || addr.ip().is_unspecified()
                            || addr.ip().is_multicast()
                        {
                            return Err("invalid neighbor UDP address".into());
                        }
                    }
                    "ethernet"
                        if address
                            .addr
                            .split_once('/')
                            .is_some_and(|(iface, _)| interfaces.contains(&iface.to_string())) => {}
                    _ => return Err("neighbor uses an unconfigured transport/interface".into()),
                }
            }
        }
        let t = &self.terms;
        Controller::validate_policy(&t.controller)?;
        let cap = t
            .controller
            .channel_capacity_sat
            .checked_mul(1_000)
            .ok_or("capacity overflow")?;
        if t.buyer_budget_sat == 0
            || t.window_msat == 0
            || t.window_msat > t.grace_msat
            || t.grace_msat > cap
            || t.fee_msat_per_kib == 0
            || t.fee_msat_per_kib > t.max_rate_msat_per_kib
            || t.quote_lifetime_secs == 0
            || t.quote_lifetime_secs > 3_600
            || t.quote_max_units == 0
            || t.controller
                .renewal
                .as_ref()
                .is_some_and(|r| r.before_expiry_secs >= t.quote_lifetime_secs)
        {
            return Err("invalid service spending, exposure or price limits".into());
        }
        Ok(())
    }

    pub(super) fn network(&self, identity: &Identity, initializing: bool) -> Config {
        let mut config = Config::new();
        config.node.identity.nsec = Some(fips_core::encode_nsec(&identity.keypair().secret_key()));
        config.node.control.enabled = !initializing;
        config.node.control.socket_path = self
            .state_directory
            .join("native.sock")
            .to_string_lossy()
            .into_owned();
        config.node.discovery.nostr.enabled = false;
        config.node.discovery.lan.enabled = false;
        config.node.discovery.local.enabled = false;
        if self.customer_network.is_some() {
            config.node.limits.max_peers = self.neighbors.len() + 16;
            config.node.limits.max_connections = config.node.limits.max_peers * 2;
            config.node.limits.max_links = config.node.limits.max_peers * 2;
            config.node.limits.max_pending_inbound = 16;
            config.node.limits.max_sessions = 128;
        }
        let bind = if initializing {
            Some("127.0.0.1:0".parse::<SocketAddr>().unwrap())
        } else {
            self.udp_bind
        };
        if let Some(bind) = bind {
            config.transports.udp = TransportInstances::Single(UdpConfig {
                bind_addr: Some(bind.to_string()),
                advertise_on_nostr: Some(false),
                ..UdpConfig::default()
            });
        }
        if !initializing {
            if !self.ethernet_interfaces.is_empty() {
                config.transports.ethernet = TransportInstances::Named(
                    self.ethernet_interfaces
                        .iter()
                        .map(|interface| {
                            (
                                interface.clone(),
                                EthernetConfig {
                                    interface: interface.clone(),
                                    discovery: Some(false),
                                    announce: Some(false),
                                    auto_connect: Some(false),
                                    accept_connections: Some(true),
                                    ..EthernetConfig::default()
                                },
                            )
                        })
                        .collect(),
                );
            }
            config.peers = self.neighbors.clone();
        }
        config
    }
}

pub(super) fn check_state(root: &Path) -> Result<(), String> {
    let mut required = REQUIRED.to_vec();
    // Cashu creates its sender channel store only at first funding. Once a
    // funding intent exists, losing that store must never look like a new buyer.
    let file = File::open(root.join("controller/controller.json")).map_err(|e| e.to_string())?;
    if file.metadata().map_err(|e| e.to_string())?.len() > crate::durable::MAX_JOURNAL_BYTES {
        return Err("controller journal too large".into());
    }
    let journal: Value = serde_json::from_reader(file).map_err(|_| "invalid controller journal")?;
    let funding = journal["funding"]
        .as_object()
        .ok_or("missing funding history")?;
    if !funding.is_empty() || root.join("wallet/spilman-client.json").exists() {
        required.push("wallet/spilman-client.json");
    }
    for relative in required {
        let metadata = std::fs::symlink_metadata(root.join(relative))
            .map_err(|_| format!("required state missing: {relative}"))?;
        if !metadata.is_file() || metadata.len() == 0 || metadata.permissions().mode() & 0o077 != 0
        {
            return Err(format!(
                "required state must be a nonempty private regular file: {relative}"
            ));
        }
    }
    Ok(())
}
