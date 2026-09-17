//! Validate network configuration and require intact saved account state.
use super::*;
use crate::control_transport::NeighborAdmission;
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
    pub transports: fips_core::config::TransportsConfig,
    /// Opt-in inbound payment control for authenticated direct UDP peers in
    /// this network. It does not authorize Internet access or onward purchases.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub customer_network: Option<IpNet>,
    /// Permit bounded control with authenticated adjacent peers. Link discovery
    /// is configured separately; neither grants purchase authority.
    #[serde(default)]
    pub neighbor_admission: NeighborAdmission,
    pub neighbors: Vec<PeerConfig>,
    /// Local fees for future offers; existing financial agreements stay intact.
    #[serde(
        default,
        skip_serializing_if = "crate::destination_pricing::DestinationFees::is_empty"
    )]
    pub destination_fees: crate::destination_pricing::DestinationFees,
    /// Optional bounded opaque replies on the reverse of an admitted path.
    #[serde(default)]
    pub return_allowance: bool,
    /// Opt-in source offer comparison and native quality-based path trials.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub price_selection: Option<crate::route_quotes::PriceSelectionPolicy>,
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
        if let Some(policy) = &self.price_selection {
            policy.validate()?;
            if !self.terms.billing.has_free_handshakes() {
                return Err("price selection requires forwarding-data billing".into());
            }
        }
        self.payment_cadence.validate()?;
        if !self.state_directory.is_absolute() || self.socket_path().as_os_str().len() > 100 {
            return Err(
                "state directory must be absolute and control socket path at most 100 bytes".into(),
            );
        }
        self.validate_network()?;
        let t = &self.terms;
        if self.return_allowance && !t.billing.has_free_handshakes() {
            return Err("return allowance requires forwarding-data billing".into());
        }
        self.destination_fees
            .resolve(t.max_rate_msat_per_kib, t.billing.has_free_handshakes())?;
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
            || (t.fee_msat_per_kib == 0 && !t.billing.has_free_handshakes())
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
