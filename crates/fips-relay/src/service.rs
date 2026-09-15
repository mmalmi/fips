//! Unix service assembly. Init is explicit; run never creates missing accounts.

use crate::{
    buyer::{BuyerAuthorizer, PaidForwarder},
    control_transport::ControlTransport,
    controller::{Controller, ControllerPolicy, ControllerServices, ControllerTasks},
    durable::{DurableRelay, acquire_owner},
    ledger::Limits,
    payment_control::{PaymentControl, PaymentServer},
    route_quotes::{QuotePolicy, QuoteServer, RouteQuotes},
};
use cashu_service::{
    FileSpilmanPaymentReceiver, FileSpilmanPaymentReceiverConfig, FileSpilmanPaymentSigner,
    load_mint_balance,
};
use fips_core::{
    Config, FipsEndpoint, Identity, PeerIdentity,
    config::{EthernetConfig, PeerConfig, TransportInstances, UdpConfig},
    node::{ForwardingOutcome, ForwardingPolicy, ForwardingRequest},
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, HashSet},
    fs::{File, OpenOptions},
    io::{Read, Write},
    net::SocketAddr,
    os::unix::fs::{DirBuilderExt, FileTypeExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{UnixListener, UnixStream},
    task::JoinSet,
};

const MAX_CONFIG: u64 = 64 * 1024;
const MAX_REQUEST: usize = 16 * 1024;
const DATA_PORT: u16 = 44_740;
// These files must already exist before any library that can lazily initialize
// state is called. The explicit init command creates them in a fresh directory.
const REQUIRED: &[&str] = &[
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
    pub ethernet_interfaces: Vec<String>,
    pub neighbors: Vec<PeerConfig>,
    pub terms: ServiceTerms,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    version: u16,
    npub: String,
    receiver_pubkey: String,
    terms: ServiceTerms,
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

    fn validate(&self) -> Result<(), String> {
        if !self.state_directory.is_absolute() || self.socket_path().as_os_str().len() > 100 {
            return Err(
                "state directory must be absolute and control socket path at most 100 bytes".into(),
            );
        }
        if self.udp_bind.is_none() && self.ethernet_interfaces.is_empty() {
            return Err("configure an explicit UDP socket or native Ethernet interface".into());
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

    fn network(&self, identity: &Identity, initializing: bool) -> Config {
        let mut config = Config::new();
        config.node.identity.nsec = Some(fips_core::encode_nsec(&identity.keypair().secret_key()));
        config.node.control.enabled = false;
        config.node.discovery.nostr.enabled = false;
        config.node.discovery.lan.enabled = false;
        config.node.discovery.local.enabled = false;
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

fn check_state(root: &Path) -> Result<(), String> {
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

#[derive(Default, Clone, Serialize)]
struct Received {
    packets: u64,
    bytes: u64,
    last_sha256: Option<String>,
}

#[derive(Debug)]
struct ServiceForwarder {
    relay: PaidForwarder,
    ready: AtomicBool,
}

impl ForwardingPolicy for ServiceForwarder {
    fn admit(&self, request: &ForwardingRequest<'_>) -> Option<u64> {
        if !self.ready.load(Ordering::Acquire) {
            return None;
        }
        self.relay.admit(request)
    }

    fn complete(&self, token: u64, outcome: ForwardingOutcome) {
        self.relay.complete(token, outcome);
    }
}

pub struct RelayService {
    config: ServiceConfig,
    endpoint: Arc<FipsEndpoint>,
    controller: Arc<Controller>,
    seller: Arc<DurableRelay>,
    buyer: Arc<BuyerAuthorizer>,
    tasks: ControllerTasks,
    payment_server: PaymentServer,
    quote_server: QuoteServer,
    received: Arc<Mutex<Received>>,
    receive_task: tokio::task::JoinHandle<()>,
    receiver_pubkey: String,
    forwarding: Arc<ServiceForwarder>,
    _owner: File,
}

impl RelayService {
    pub async fn initialize(config: ServiceConfig) -> Result<String, String> {
        config.validate()?;
        std::fs::DirBuilder::new().mode(0o700).create(&config.state_directory)
            .map_err(|_| "init requires a new state directory; existing or partial state is never replaced")?;
        let identity = Identity::generate();
        fips_core::config::write_key_file(
            &config.state_directory.join("identity.key"),
            &fips_core::encode_nsec(&identity.keypair().secret_key()),
        )
        .map_err(|e| e.to_string())?;
        let service = Self::assemble(config.clone(), identity, None).await?;
        let manifest = Manifest {
            version: 1,
            npub: service.endpoint.npub().to_string(),
            receiver_pubkey: service.receiver_pubkey.clone(),
            terms: config.terms,
        };
        service.shutdown().await?;
        for relative in REQUIRED {
            let path = config.state_directory.join(relative);
            if !std::fs::symlink_metadata(&path)
                .map_err(|_| format!("initial state missing: {relative}"))?
                .is_file()
            {
                return Err(format!("initial state is not a regular file: {relative}"));
            }
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
                .map_err(|e| e.to_string())?;
        }
        check_state(&config.state_directory)?;
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(config.state_directory.join("service.json"))
            .map_err(|e| e.to_string())?;
        file.write_all(&serde_json::to_vec(&manifest).map_err(|e| e.to_string())?)
            .map_err(|e| e.to_string())?;
        file.sync_all().map_err(|e| e.to_string())?;
        File::open(&config.state_directory)
            .and_then(|f| f.sync_all())
            .map_err(|e| e.to_string())?;
        Ok(manifest.npub)
    }

    pub async fn load(config: ServiceConfig) -> Result<Self, String> {
        let (identity, manifest) = Self::stored_state(&config)?;
        Self::assemble(config, identity, Some(&manifest)).await
    }

    pub(crate) fn validate_stored_state(config: &ServiceConfig) -> Result<(), String> {
        Self::stored_state(config).map(|_| ())
    }

    fn stored_state(config: &ServiceConfig) -> Result<(Identity, Manifest), String> {
        config.validate()?;
        let manifest: Manifest = read_json(&config.state_directory.join("service.json"))?;
        if manifest.version != 1 || manifest.terms != config.terms {
            return Err(
                "configuration differs from saved terms; explicit reconciliation required".into(),
            );
        }
        check_state(&config.state_directory)?;
        let secret = fips_core::config::read_key_file(&config.state_directory.join("identity.key"))
            .map_err(|e| e.to_string())?;
        let identity = Identity::from_secret_str(&secret).map_err(|_| "invalid stored identity")?;
        if identity.npub() != manifest.npub {
            return Err("stored identity changed".into());
        }
        Ok((identity, manifest))
    }

    async fn assemble(
        config: ServiceConfig,
        identity: Identity,
        manifest: Option<&Manifest>,
    ) -> Result<Self, String> {
        let create = manifest.is_none();
        let owner = acquire_owner(&config.state_directory).map_err(|e| e.to_string())?;
        let root = &config.state_directory;
        let seller = Arc::new(
            if create {
                DurableRelay::create(
                    &root.join("seller"),
                    Limits::default(),
                    config.terms.window_msat,
                )
            } else {
                DurableRelay::load(&root.join("seller"))
            }
            .map_err(|e| e.to_string())?,
        );
        let buyer = Arc::new(
            if create {
                BuyerAuthorizer::create(
                    &root.join("buyer"),
                    *identity.node_addr(),
                    config.terms.buyer_budget_sat,
                    Limits::default(),
                )
            } else {
                BuyerAuthorizer::load(&root.join("buyer"))
            }
            .map_err(|e| e.to_string())?,
        );
        if create {
            load_mint_balance(&root.join("wallet"), &config.terms.controller.mint_url)
                .await
                .map_err(|e| e.to_string())?;
            drop(FileSpilmanPaymentSigner::load(&root.join("wallet"))?);
        }
        let receiver = FileSpilmanPaymentReceiver::load_with_keyset_refresh(
            &root.join("receiver"),
            FileSpilmanPaymentReceiverConfig::new([config.terms.controller.mint_url.clone()]),
        )
        .await?;
        let receiver_pubkey = receiver.receiver_pubkey_hex().to_string();
        if manifest.is_some_and(|m| m.receiver_pubkey != receiver_pubkey) {
            return Err("stored payment receiver identity changed".into());
        }
        let forwarding = Arc::new(ServiceForwarder {
            relay: PaidForwarder::new(seller.clone(), buyer.clone()),
            ready: AtomicBool::new(false),
        });
        let endpoint = Arc::new(
            FipsEndpoint::builder()
                .config(config.network(&identity, create))
                .forwarding_policy(forwarding.clone())
                .originated_session_observer(buyer.clone())
                .without_system_tun()
                .bind()
                .await
                .map_err(|e| e.to_string())?,
        );
        let neighbors: Vec<_> = config
            .neighbors
            .iter()
            .map(|p| PeerIdentity::from_npub(&p.npub).unwrap())
            .collect();
        let entropy = Identity::generate();
        let seed = u64::from_le_bytes(entropy.node_addr().as_bytes()[..8].try_into().unwrap());
        let (quote_transport, quote_incoming) =
            ControlTransport::start(endpoint.clone(), 44_741, neighbors.clone(), seed).await?;
        let t = &config.terms;
        let quotes = Arc::new(RouteQuotes::new(
            endpoint.clone(),
            Arc::new(quote_transport),
            QuotePolicy {
                mint_url: t.controller.mint_url.clone(),
                receiver_pubkey_hex: receiver.receiver_pubkey_hex().to_string(),
                fee_msat_per_kib: t.fee_msat_per_kib,
                max_rate_msat_per_kib: t.max_rate_msat_per_kib,
                lifetime_secs: t.quote_lifetime_secs,
                max_units: t.quote_max_units,
                capacity_sat: t.controller.channel_capacity_sat,
                grace_msat: t.grace_msat,
            },
        )?);
        let quote_server = QuoteServer::start(quotes.clone(), quote_incoming);
        let (acceptance, incoming) = ControlTransport::start(
            endpoint.clone(),
            44_742,
            neighbors.clone(),
            seed.wrapping_add(1),
        )
        .await?;
        let (payments, payment_incoming) =
            ControlTransport::start(endpoint.clone(), 44_743, neighbors, seed.wrapping_add(2))
                .await?;
        let payment_control = Arc::new(PaymentControl::new(receiver, seller.clone(), vec![])?);
        let payment_server = PaymentServer::start_shared(payment_control.clone(), payment_incoming);
        let services = ControllerServices {
            endpoint: endpoint.clone(),
            quotes,
            acceptance: Arc::new(acceptance),
            payments: Arc::new(payments),
            payment_control,
            seller: seller.clone(),
            buyer: buyer.clone(),
            wallet_directory: root.join("wallet"),
        };
        let controller = Arc::new(if create {
            Controller::create(&root.join("controller"), t.controller.clone(), services)
        } else {
            Controller::load(&root.join("controller"), t.controller.clone(), services)
        }?);
        let tasks = ControllerTasks::start(controller.clone(), incoming);
        let received = Arc::new(Mutex::new(Received::default()));
        let destination = received.clone();
        let input = endpoint
            .register_service_receiver(DATA_PORT)
            .await
            .map_err(|e| e.to_string())?;
        let receive_task = tokio::spawn(async move {
            let mut batch = Vec::new();
            while input.recv_batch_into(&mut batch, 32).await.is_some() {
                let mut totals = destination.lock().unwrap();
                for packet in &batch {
                    totals.packets = totals.packets.saturating_add(1);
                    totals.bytes = totals.bytes.saturating_add(packet.data.len() as u64);
                    totals.last_sha256 = Some(format!("{:x}", Sha256::digest(&packet.data)));
                }
            }
        });
        // Native startup needs an endpoint to construct the controller. Keep
        // restored data admission closed until every component loaded and
        // validated; corrupt controller state must not briefly permit transit.
        forwarding.ready.store(true, Ordering::Release);
        Ok(Self {
            config,
            endpoint,
            controller,
            seller,
            buyer,
            tasks,
            payment_server,
            quote_server,
            received,
            receive_task,
            receiver_pubkey,
            forwarding,
            _owner: owner,
        })
    }

    pub async fn shutdown(self) -> Result<(), String> {
        let Self {
            endpoint,
            controller,
            seller,
            buyer,
            tasks,
            payment_server,
            quote_server,
            receive_task,
            forwarding,
            _owner,
            ..
        } = self;
        forwarding.ready.store(false, Ordering::Release);
        tasks.stop().await;
        payment_server.stop().await;
        drop(quote_server);
        endpoint.shutdown().await.map_err(|e| e.to_string())?;
        receive_task.abort();
        let _ = receive_task.await;
        // No more transport callbacks or payment writers can race final state.
        let result = tokio::task::spawn_blocking(move || {
            seller.suspend().map_err(|e| e.to_string())?;
            buyer.checkpoint().map_err(|e| e.to_string())
        })
        .await
        .map_err(|e| e.to_string())?;
        drop(controller);
        drop(endpoint);
        drop(_owner);
        result
    }

    async fn handle(&self, request: AdminRequest) -> Result<Value, String> {
        match request {
            AdminRequest::Status => {
                let peers = self.endpoint.peers().await.map_err(|e| e.to_string())?;
                Ok(
                    json!({"npub": self.endpoint.npub(), "peers": peers.iter().map(|p| json!({
                    "npub": p.npub, "connected": p.connected, "transport": p.transport_type,
                    "address": p.transport_addr, "sent_bytes": p.bytes_sent, "received_bytes": p.bytes_recv,
                    "srtt_ms": p.srtt_ms })).collect::<Vec<_>>(),
                    "purchases": self.controller.purchases().await?,
                    "watched_routes": self.controller.watched_routes().await?,
                    "history": self.controller.purchase_history().await?,
                    "locked_sat": self.controller.locked_capital_sat().await?,
                    "remaining_budget_sat": self.buyer.remaining_budget_sat(),
                    "received": self.received.lock().unwrap().clone(),
                    "last_error": self.controller.last_error()}),
                )
            }
            AdminRequest::Buy { destination } => {
                let peer = PeerIdentity::from_npub(&destination)
                    .map_err(|_| "invalid destination npub")?;
                Ok(json!({"purchase": self.controller.buy_route(peer).await?}))
            }
            AdminRequest::Watch {
                destination,
                max_rate_msat_per_kib,
            } => {
                let peer = PeerIdentity::from_npub(&destination)
                    .map_err(|_| "invalid destination npub")?;
                Ok(
                    json!({"purchase": self.controller.watch_route(peer, max_rate_msat_per_kib).await?}),
                )
            }
            AdminRequest::PauseRouteRefresh => {
                self.controller.pause_route_refresh().await?;
                Ok(json!({"paused": true}))
            }
            AdminRequest::Send {
                destination,
                payload,
            } => {
                if payload.is_empty() || payload.len() > 1_000 {
                    return Err("payload must contain 1..1000 bytes".into());
                }
                let peer = PeerIdentity::from_npub(&destination)
                    .map_err(|_| "invalid destination npub")?;
                self.endpoint
                    .send_datagram(peer, DATA_PORT, DATA_PORT, payload.into_bytes())
                    .await
                    .map_err(|e| e.to_string())?;
                Ok(json!({"queued": true}))
            }
            AdminRequest::Settle => Ok(json!({"settlements": self.controller.settle_all().await?})),
            AdminRequest::PauseRenewals => {
                self.controller.pause_renewals().await?;
                Ok(json!({"paused": true}))
            }
            AdminRequest::ResumeRenewals => {
                self.controller.resume_renewals().await?;
                Ok(json!({"paused": false}))
            }
        }
    }

    pub async fn serve(self, stop: impl Future<Output = ()>) -> Result<(), String> {
        let socket = self.config.socket_path();
        if let Ok(metadata) = std::fs::symlink_metadata(&socket) {
            if !metadata.file_type().is_socket() {
                return Err("control path is not a socket".into());
            }
            // This service owns the exclusive state lock; only its stale socket can remain.
            std::fs::remove_file(&socket).map_err(|e| e.to_string())?;
        }
        let listener = UnixListener::bind(&socket).map_err(|e| e.to_string())?;
        std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o600))
            .map_err(|e| e.to_string())?;
        let service = Arc::new(self);
        let mut jobs = JoinSet::new();
        tokio::pin!(stop);
        loop {
            tokio::select! {
                _ = &mut stop => break,
                connection = listener.accept(), if jobs.len() < 4 => {
                    let (mut stream, _) = connection.map_err(|e| e.to_string())?;
                    let service = service.clone();
                    jobs.spawn(async move {
                        let request = tokio::time::timeout(Duration::from_secs(5), read_record(&mut stream, MAX_REQUEST)).await;
                        let response = match request {
                            Ok(Ok(bytes)) => match serde_json::from_slice(&bytes) {
                                Ok(request) => service.handle(request).await,
                                Err(_) => Err("invalid control request".into()),
                            },
                            _ => Err("control request timed out or exceeded its limit".into()),
                        };
                        let value = match response { Ok(v) => json!({"ok": v}), Err(e) => json!({"error": e}) };
                        let _ = tokio::time::timeout(Duration::from_secs(5), write_record(&mut stream, &serde_json::to_vec(&value).unwrap())).await;
                    });
                }
                _ = jobs.join_next(), if !jobs.is_empty() => {}
            }
        }
        drop(listener);
        while jobs.join_next().await.is_some() {}
        std::fs::remove_file(&socket).map_err(|e| e.to_string())?;
        let service = Arc::try_unwrap(service).map_err(|_| "service still borrowed")?;
        service.shutdown().await
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum AdminRequest {
    Status,
    Buy {
        destination: String,
    },
    Watch {
        destination: String,
        max_rate_msat_per_kib: u64,
    },
    PauseRouteRefresh,
    Send {
        destination: String,
        payload: String,
    },
    Settle,
    PauseRenewals,
    ResumeRenewals,
}

pub(crate) async fn read_record(stream: &mut UnixStream, limit: usize) -> Result<Vec<u8>, String> {
    let size = stream.read_u32().await.map_err(|e| e.to_string())? as usize;
    if size == 0 || size > limit {
        return Err("invalid control record size".into());
    }
    let mut bytes = vec![0; size];
    stream
        .read_exact(&mut bytes)
        .await
        .map_err(|e| e.to_string())?;
    Ok(bytes)
}

pub(crate) async fn write_record(stream: &mut UnixStream, bytes: &[u8]) -> Result<(), String> {
    stream
        .write_u32(u32::try_from(bytes.len()).map_err(|_| "control record too large")?)
        .await
        .map_err(|e| e.to_string())?;
    stream.write_all(bytes).await.map_err(|e| e.to_string())
}

pub async fn request(config: &ServiceConfig, request: &AdminRequest) -> Result<Value, String> {
    let mut stream = UnixStream::connect(config.socket_path())
        .await
        .map_err(|e| e.to_string())?;
    write_record(
        &mut stream,
        &serde_json::to_vec(request).map_err(|e| e.to_string())?,
    )
    .await?;
    let response = read_record(&mut stream, 1024 * 1024).await?;
    let mut value: BTreeMap<String, Value> =
        serde_json::from_slice(&response).map_err(|e| e.to_string())?;
    if let Some(error) = value.remove("error") {
        return Err(error.as_str().unwrap_or("control failed").into());
    }
    value.remove("ok").ok_or("invalid control response".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn restored_allowance_is_inaccessible_until_service_startup_finishes() {
        use crate::ledger::{BytePrice, ChannelTerms, Contract};
        let directory = tempfile::tempdir().unwrap();
        let ingress = PeerIdentity::from_pubkey_full(Identity::generate().pubkey_full());
        let destination = *Identity::generate().node_addr();
        let local = *Identity::generate().node_addr();
        let seller = Arc::new(
            DurableRelay::create(&directory.path().join("seller"), Limits::default(), 100).unwrap(),
        );
        let buyer = Arc::new(
            BuyerAuthorizer::create(&directory.path().join("buyer"), local, 1, Limits::default())
                .unwrap(),
        );
        let expires = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 60;
        seller
            .open_channel_verified(
                ChannelTerms {
                    id: "channel".into(),
                    buyer: *ingress.node_addr(),
                    mint_url: "http://test.invalid".into(),
                    capacity_sat: 1,
                    grace_msat: 100,
                    expires_unix: expires,
                },
                0,
            )
            .unwrap();
        seller
            .add_contract(Contract {
                id: "route".into(),
                channel_id: "channel".into(),
                destination,
                next_hop: destination,
                price: BytePrice {
                    msat: 1,
                    per_bytes: 1,
                },
                max_units: 100,
                expires_unix: expires,
            })
            .unwrap();
        let forwarding = ServiceForwarder {
            relay: PaidForwarder::new(seller.clone(), buyer),
            ready: AtomicBool::new(false),
        };
        let request = ForwardingRequest {
            ingress,
            source: *ingress.node_addr(),
            destination,
            next_hop: destination,
            session_payload: &[1, 2, 3, 4],
        };
        assert!(forwarding.admit(&request).is_none());
        assert_eq!(seller.channel_usage("channel").unwrap().reserved_msat, 0);
        forwarding.ready.store(true, Ordering::Release);
        let token = forwarding
            .admit(&request)
            .expect("validated startup exposes the existing allowance");
        forwarding.complete(token, ForwardingOutcome::Submitted);
        assert_eq!(seller.channel_usage("channel").unwrap().submitted_msat, 4);
    }

    #[test]
    fn native_interface_configuration_has_no_implicit_udp_or_discovery_shortcut() {
        let config = ServiceConfig {
            state_directory: "/tmp/fips-relay-example".into(),
            udp_bind: None,
            ethernet_interfaces: vec!["mesh0".into()],
            neighbors: vec![],
            terms: ServiceTerms {
                controller: ControllerPolicy {
                    mint_url: "http://127.0.0.1:3338".into(),
                    channel_capacity_sat: 32,
                    max_locked_sat: 64,
                    channel_lifetime_secs: 600,
                    renewal: None,
                },
                buyer_budget_sat: 64,
                window_msat: 4_000,
                grace_msat: 8_000,
                fee_msat_per_kib: 1_024,
                max_rate_msat_per_kib: 8_192,
                quote_lifetime_secs: 300,
                quote_max_units: 30_000,
            },
        };
        config.validate().unwrap();
        let native = config.network(&Identity::generate(), false);
        assert!(native.transports.udp.is_empty());
        assert!(native.transports.tcp.is_empty());
        assert!(!native.node.discovery.nostr.enabled);
        assert!(!native.node.discovery.lan.enabled);
        assert!(!native.node.discovery.local.enabled);
        let TransportInstances::Named(interfaces) = native.transports.ethernet else {
            panic!("explicit interfaces");
        };
        assert_eq!(interfaces.len(), 1);
        assert_eq!(interfaces["mesh0"].interface, "mesh0");
        assert_eq!(interfaces["mesh0"].ethertype(), 0x2121);
        assert_eq!(interfaces["mesh0"].discovery, Some(false));
        assert_eq!(interfaces["mesh0"].auto_connect, Some(false));
        let mut invalid = config;
        invalid.neighbors.push(PeerConfig::new(
            Identity::generate().npub(),
            "udp",
            "127.0.0.1:2121",
        ));
        assert!(
            invalid.validate().is_err(),
            "unconfigured transport cannot become a fallback"
        );
    }
}
