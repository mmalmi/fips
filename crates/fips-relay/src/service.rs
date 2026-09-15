//! Unix service assembly. Init is explicit; run never creates missing accounts.

mod config;
mod control;
pub(crate) use config::read_json;
use config::{Manifest, REQUIRED, check_state};
pub use config::{ServiceConfig, ServiceTerms};
pub use control::{AdminRequest, native_request, request};
#[cfg(feature = "testbench")]
pub(crate) use control::{read_record, write_record};

use crate::{
    buyer::{BuyerAuthorizer, PaidForwarder},
    control_transport::{ControlStatistics, ControlTransport},
    controller::{Controller, ControllerPolicy, ControllerServices, ControllerTasks},
    durable::{DurableRelay, acquire_owner},
    ledger::{BillingBasis, Limits},
    payment_control::{PaymentControl, PaymentServer},
    probe::{self, ProbeReceiver, ReceiveProbe, SendProbe},
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
    io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader},
    net::{UnixListener, UnixStream},
    task::JoinSet,
};

const MAX_CONFIG: u64 = 64 * 1024;
const MAX_REQUEST: usize = 16 * 1024;
const DATA_PORT: u16 = 44_740;
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
    probe_receiver: Arc<Mutex<Option<ProbeReceiver>>>,
    probe_sender: tokio::sync::Semaphore,
    control_statistics: Vec<(u16, Arc<ControlStatistics>)>,
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
        if !create {
            let native_socket = root.join("native.sock");
            if let Ok(metadata) = std::fs::symlink_metadata(&native_socket)
                && !metadata.file_type().is_socket()
            {
                return Err("native control path is not a socket".into());
            }
        }
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
        let (quote_transport, quote_incoming) = ControlTransport::start_with_customers(
            endpoint.clone(),
            44_741,
            neighbors.clone(),
            config.customer_network,
            seed,
        )
        .await?;
        let mut control_statistics = vec![(44_741, quote_transport.statistics())];
        let t = &config.terms;
        let quotes = Arc::new(RouteQuotes::new(
            endpoint.clone(),
            Arc::new(quote_transport),
            QuotePolicy {
                billing: t.billing,
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
        let (acceptance, incoming) = ControlTransport::start_with_customers(
            endpoint.clone(),
            44_742,
            neighbors.clone(),
            config.customer_network,
            seed.wrapping_add(1),
        )
        .await?;
        let (payments, payment_incoming) = ControlTransport::start_with_customers(
            endpoint.clone(),
            44_743,
            neighbors,
            config.customer_network,
            seed.wrapping_add(2),
        )
        .await?;
        control_statistics.push((44_742, acceptance.statistics()));
        control_statistics.push((44_743, payments.statistics()));
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
        let probe_receiver: Arc<Mutex<Option<ProbeReceiver>>> = Arc::new(Mutex::new(None));
        let diagnostic = probe_receiver.clone();
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
                    if let Some(probe) = diagnostic.lock().unwrap().as_mut() {
                        probe.record(
                            packet.source_peer,
                            packet.data.as_ref(),
                            probe::unix_micros(),
                        );
                    }
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
            probe_receiver,
            probe_sender: tokio::sync::Semaphore::new(1),
            control_statistics,
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
}

#[cfg(test)]
mod tests;
