//! Keep the same mesh identity available while the exclusive wallet is offline.
use super::*;
use crate::{free_routes::FreeRoutes, mint_mesh::MeshMintBridge};
use fips_core::node::{
    OriginatedSessionAdmission, OriginatedSessionIntent, OriginatedSessionObserver,
    OriginatedSessionRequest,
};
use tokio::net::TcpListener;

pub(super) async fn attach(
    config: &ServiceConfig,
    endpoint: Arc<FipsEndpoint>,
    quotes: Arc<RouteQuotes>,
) -> Result<Option<MeshMintBridge>, String> {
    let Some(mesh) = &config.terms.mint_mesh else {
        return Ok(None);
    };
    let (mint, address) = mesh.target(&config.terms.controller.mint_url)?;
    if mint.node_addr() == endpoint.node_addr() {
        return Err("mesh mint must use a distinct remote identity".into());
    }
    let listener = TcpListener::bind(address)
        .await
        .map_err(|e| e.to_string())?;
    MeshMintBridge::connect_quoted(endpoint, mesh.service_port, mint, listener, quotes)
        .await
        .map(Some)
}

#[derive(Debug)]
struct OfflinePolicy(Arc<FreeRoutes>);

impl ForwardingPolicy for OfflinePolicy {
    fn admit(&self, _: &ForwardingRequest<'_>) -> Option<u64> {
        None
    }
    fn complete(&self, _: u64, _: ForwardingOutcome) {}
}

impl OriginatedSessionObserver for OfflinePolicy {
    fn prepare(&self, intent: &OriginatedSessionIntent) -> OriginatedSessionAdmission {
        if intent.next_hop == intent.destination
            || self
                .0
                .prepare_onward(intent.next_hop, intent.destination, intent.session_bytes)
                == Some(true)
        {
            OriginatedSessionAdmission::Untracked
        } else {
            OriginatedSessionAdmission::Reject
        }
    }
    fn observe(&self, _: &OriginatedSessionRequest<'_>) -> Option<u64> {
        None
    }
    fn complete(&self, _: u64, _: ForwardingOutcome) {}
}

pub(crate) struct OfflineMint {
    bridge: Option<MeshMintBridge>,
    quotes: Arc<RouteQuotes>,
    endpoint: Arc<FipsEndpoint>,
}

impl OfflineMint {
    /// Caller retains the service's exclusive root lock throughout this lifetime.
    /// No buyer, seller, payment worker or wallet is opened by this network.
    pub(crate) async fn start(config: &ServiceConfig) -> Result<Option<Self>, String> {
        if config.terms.mint_mesh.is_none() {
            return Ok(None);
        }
        let (identity, manifest) = RelayService::stored_state(config)?;
        let free = Arc::new(FreeRoutes::default());
        let policy = Arc::new(OfflinePolicy(free.clone()));
        let endpoint = Arc::new(
            FipsEndpoint::builder()
                .config(config.network(&identity, false))
                .forwarding_policy(policy.clone())
                .originated_session_observer(policy)
                .without_system_tun()
                .bind()
                .await
                .map_err(|e| e.to_string())?,
        );
        let initialized = async {
            transport_startup::verify(config).await?;
            let neighbors = config
                .neighbors
                .iter()
                .map(|p| PeerIdentity::from_npub(&p.npub).map_err(|e| e.to_string()))
                .collect::<Result<Vec<_>, _>>()?;
            let admission = ControlAdmission::new(
                endpoint.clone(),
                neighbors,
                config.customer_network,
                config.neighbor_admission,
            )?;
            let entropy = Identity::generate();
            let seed = u64::from_le_bytes(entropy.node_addr().as_bytes()[..8].try_into().unwrap());
            let (transport, incoming) =
                ControlTransport::start_with_admission(endpoint.clone(), 44_741, admission, seed)
                    .await?;
            // The stopped wallet is an endpoint only; it never offers transit.
            drop(incoming);
            let quotes = Arc::new(RouteQuotes::with_free_routes(
                endpoint.clone(),
                Arc::new(transport),
                config.quote_policy(manifest.receiver_pubkey)?,
                free,
            )?);
            let bridge = attach(config, endpoint.clone(), quotes.clone()).await?;
            Ok::<_, String>((bridge, quotes))
        }
        .await;
        match initialized {
            Ok((bridge, quotes)) => Ok(Some(Self {
                bridge,
                quotes,
                endpoint,
            })),
            Err(error) => {
                let _ = endpoint.shutdown().await;
                Err(error)
            }
        }
    }

    pub(crate) async fn shutdown(self) -> Result<(), String> {
        let Self {
            bridge,
            quotes,
            endpoint,
        } = self;
        let bridge_result = match bridge {
            Some(bridge) => bridge.shutdown().await,
            None => Ok(()),
        };
        drop(quotes);
        let endpoint_result = endpoint.shutdown().await.map_err(|e| e.to_string());
        bridge_result.and(endpoint_result)
    }
}
