//! Small application-side bridge for the FIPS Nostr relay transport.
//!
//! This is used by standalone FIPS tools. Larger applications should normally
//! share their existing configured Nostr relay connections instead.

use std::sync::Arc;
use std::time::Duration;

use fips_core::transport::nostr_relay::NOSTR_RELAY_DATAGRAM_KIND;
use fips_core::{FipsEndpoint, FipsEndpointError, NostrRelayIo};
use nostr_sdk::Event;
use nostr_sdk::prelude::{Client, Filter, Keys, Kind, PublicKey, RelayPoolNotification};
use tokio::sync::{Semaphore, oneshot};
use tokio::task::JoinHandle;

/// Direct relay bridge for signed kind 21060 FIPS datagrams.
pub struct NostrRelayAdapter {
    client: Client,
    shutdown: Option<oneshot::Sender<()>>,
    task: JoinHandle<()>,
}

#[derive(Clone)]
enum RelayEventIo {
    Endpoint(Arc<FipsEndpoint>),
    Node(NostrRelayIo),
}

impl RelayEventIo {
    fn npub(&self) -> &str {
        match self {
            Self::Endpoint(endpoint) => endpoint.npub(),
            Self::Node(io) => io.npub(),
        }
    }

    async fn drain_events(&self, limit: usize) -> Result<Vec<Event>, FipsEndpointError> {
        match self {
            Self::Endpoint(endpoint) => endpoint.drain_nostr_relay_events(limit).await,
            Self::Node(io) => io.drain_events(limit).await,
        }
    }

    async fn ingest_event(&self, event: Event) -> Result<bool, FipsEndpointError> {
        match self {
            Self::Endpoint(endpoint) => endpoint.ingest_nostr_event(event).await,
            Self::Node(io) => io.ingest_event(event).await,
        }
    }
}

impl NostrRelayAdapter {
    /// Connect to the application-provided relays and bridge targeted events.
    pub async fn start(
        endpoint: Arc<FipsEndpoint>,
        relays: &[String],
    ) -> Result<Option<Self>, String> {
        Self::start_with_io(RelayEventIo::Endpoint(endpoint), relays).await
    }

    /// Connect a direct [`fips_core::Node`] through its attached relay I/O.
    pub async fn start_for_node(
        io: NostrRelayIo,
        relays: &[String],
    ) -> Result<Option<Self>, String> {
        Self::start_with_io(RelayEventIo::Node(io), relays).await
    }

    async fn start_with_io(io: RelayEventIo, relays: &[String]) -> Result<Option<Self>, String> {
        if relays.is_empty() {
            return Ok(None);
        }

        let local_pubkey = PublicKey::parse(io.npub())
            .map_err(|error| format!("invalid FIPS endpoint identity: {error}"))?;
        let client = Client::new(Keys::generate());
        for relay in relays {
            client
                .add_relay(relay)
                .await
                .map_err(|error| format!("failed to add Nostr relay {relay}: {error}"))?;
        }
        let mut notifications = client.notifications();
        client.connect().await;
        client
            .subscribe(
                Filter::new()
                    .kind(Kind::Custom(NOSTR_RELAY_DATAGRAM_KIND))
                    .pubkey(local_pubkey),
                None,
            )
            .await
            .map_err(|error| format!("failed to subscribe to FIPS relay datagrams: {error}"))?;

        let task_client = client.clone();
        let publish_slots = Arc::new(Semaphore::new(32));
        let (shutdown_tx, mut shutdown_rx) = oneshot::channel();
        let task = tokio::spawn(async move {
            let mut outbound_tick = tokio::time::interval(Duration::from_millis(10));
            outbound_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                tokio::select! {
                    _ = &mut shutdown_rx => break,
                    _ = outbound_tick.tick() => {
                        match io.drain_events(64).await {
                            Ok(events) => {
                                for event in events {
                                    let Ok(permit) = Arc::clone(&publish_slots).try_acquire_owned() else {
                                        tracing::debug!(event_id = %event.id, "FIPS relay publish queue is saturated");
                                        continue;
                                    };
                                    let client = task_client.clone();
                                    tokio::spawn(async move {
                                        let _permit = permit;
                                        if let Err(error) = client.send_event(&event).await {
                                            tracing::debug!(%error, event_id = %event.id, "failed to publish FIPS relay datagram");
                                        }
                                    });
                                }
                            }
                            Err(error) => tracing::debug!(%error, "failed to drain FIPS relay datagrams"),
                        }
                    }
                    notification = notifications.recv() => {
                        match notification {
                            Ok(RelayPoolNotification::Event { event, .. })
                                if event.kind == Kind::Custom(NOSTR_RELAY_DATAGRAM_KIND) =>
                            {
                                if let Err(error) = io.ingest_event((*event).clone()).await {
                                    tracing::debug!(%error, "failed to ingest FIPS relay datagram");
                                }
                            }
                            Ok(_) => {}
                            Err(tokio::sync::broadcast::error::RecvError::Lagged(skipped)) => {
                                tracing::debug!(skipped, "FIPS relay notification receiver lagged");
                            }
                            Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                        }
                    }
                }
            }
        });

        Ok(Some(Self {
            client,
            shutdown: Some(shutdown_tx),
            task,
        }))
    }

    pub async fn stop(mut self) {
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
        let _ = (&mut self.task).await;
        self.client.shutdown().await;
    }
}

impl Drop for NostrRelayAdapter {
    fn drop(&mut self) {
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
        self.task.abort();
    }
}
