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
    /// Optional pinned FIPS transport for the immutable loopback mint URL.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mint_mesh: Option<crate::mint_mesh::MintMesh>,
    /// Logical wallet bytes, including completion reservations; not filesystem space.
    /// Set only before initialization. Omission preserves an unconfigured wallet.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wallet_capacity_bytes: Option<u64>,
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
    /// Export one fixed local mint HTTP listener over this endpoint.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mint_export: Option<crate::mint_mesh::MintExport>,
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
    /// Optional rate limits for earned replies; omission keeps the small default.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub return_bandwidth: Option<crate::free_routes::FreeBandwidthPolicy>,
    /// Optional local rate limits for already negotiated free-data forwarding.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub free_bandwidth: Option<crate::free_routes::FreeBandwidthPolicy>,
    /// Opt-in source offer comparison and native quality-based path trials.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub price_selection: Option<crate::route_quotes::PriceSelectionPolicy>,
    pub terms: ServiceTerms,
    /// Local timing only; does not change saved financial terms or authority.
    #[serde(default, skip_serializing_if = "PaymentCadence::is_default")]
    pub payment_cadence: PaymentCadence,
    /// Optional local CDK HTTP pacing for wallet-backed channel opening.
    /// Omission retains CDK defaults; use only within the mint operator's limits.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub funding_request_budget: Option<crate::controller::FundingRequestBudget>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Manifest {
    pub(super) version: u16,
    pub(super) npub: String,
    pub(super) receiver_pubkey: String,
    pub(super) sender_pubkey: String,
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
    pub(super) fn quote_policy(&self, receiver_pubkey_hex: String) -> Result<QuotePolicy, String> {
        let t = &self.terms;
        Ok(QuotePolicy {
            destination_fees: self
                .destination_fees
                .resolve(t.max_rate_msat_per_kib, t.billing.has_free_handshakes())?,
            billing: t.billing,
            mint_url: t.controller.mint_url.clone(),
            receiver_pubkey_hex,
            fee_msat_per_kib: t.fee_msat_per_kib,
            max_rate_msat_per_kib: t.max_rate_msat_per_kib,
            lifetime_secs: t.quote_lifetime_secs,
            max_units: t.quote_max_units,
            capacity_sat: t.controller.channel_capacity_sat,
            grace_msat: t.grace_msat,
        })
    }

    pub fn read(path: &Path) -> Result<Self, String> {
        let value: Self = read_json(path)?;
        value.validate()?;
        Ok(value)
    }

    pub fn socket_path(&self) -> PathBuf {
        self.state_directory.join("control.sock")
    }

    pub(crate) fn validate(&self) -> Result<(), String> {
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
        if let Some(export) = &self.mint_export {
            export.validate()?;
            if t.mint_mesh.is_some() || !t.billing.has_free_handshakes() {
                return Err(
                    "mint export requires forwarding-data billing and no client adapter".into(),
                );
            }
        }
        if let Some(mesh) = &t.mint_mesh {
            mesh.target(&t.controller.mint_url)?;
            if !t.billing.has_free_handshakes() {
                return Err("mesh mint access requires forwarding-data billing".into());
            }
        }
        if let Some(policy) = &self.free_bandwidth {
            policy.validate()?;
            if !t.billing.has_free_handshakes() {
                return Err("free bandwidth requires forwarding-data billing".into());
            }
        }
        if self.return_allowance && !t.billing.has_free_handshakes() {
            return Err("return allowance requires forwarding-data billing".into());
        }
        if let Some(policy) = &self.return_bandwidth {
            policy.validate()?;
            if !self.return_allowance {
                return Err("return bandwidth requires return allowance".into());
            }
        }
        self.destination_fees
            .resolve(t.max_rate_msat_per_kib, t.billing.has_free_handshakes())?;
        Controller::validate_policy(&t.controller)?;
        let cap = t
            .controller
            .channel_capacity_sat
            .checked_mul(1_000)
            .ok_or("capacity overflow")?;
        if t.wallet_capacity_bytes
            .is_some_and(|maximum| maximum == 0 || maximum > i64::MAX as u64)
        {
            return Err("wallet storage maximum is out of range".into());
        }
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
    // funding intent exists, losing that store must never look like a new buyer,
    // including after completed funding entries retire into lifetime totals.
    let file = File::open(root.join("controller/controller.json")).map_err(|e| e.to_string())?;
    if file.metadata().map_err(|e| e.to_string())?.len() > crate::durable::MAX_JOURNAL_BYTES {
        return Err("controller journal too large".into());
    }
    let journal: Value = serde_json::from_reader(file).map_err(|_| "invalid controller journal")?;
    let funding = journal["funding"]
        .as_object()
        .ok_or("missing funding history")?;
    let next_funding = journal["next_funding"]
        .as_u64()
        .filter(|next| *next > 0)
        .ok_or("invalid funding sequence")?;
    if next_funding > 1 || !funding.is_empty() || root.join("wallet/spilman-client.json").exists() {
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
