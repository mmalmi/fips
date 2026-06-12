use super::{IncomingSignal, SIGNAL_TTL_MS, WEBRTC_PROTOCOL, WebRtcSignal, now_ms};
use crate::discovery::nostr::{SIGNAL_KIND, build_signal_event, unwrap_signal_event};
use crate::transport::TransportError;
use nostr::prelude::{EventBuilder, Filter, Kind, PublicKey, Timestamp};
use nostr_sdk::{Client, ClientOptions, prelude::RelayPoolNotification};
use std::collections::HashSet;
use tokio::sync::{broadcast, mpsc};
use tokio::task::JoinHandle;
use tracing::{debug, warn};

#[derive(Clone)]
pub(super) struct NostrSignalSender {
    client: Client,
    keys: nostr::Keys,
    local_pubkey: PublicKey,
}

impl NostrSignalSender {
    pub(super) async fn send_signal(
        &self,
        relays: &[String],
        receiver: PublicKey,
        signal: &WebRtcSignal,
    ) -> Result<(), TransportError> {
        let rumor = EventBuilder::private_msg_rumor(
            receiver,
            serde_json::to_string(signal).map_err(|e| TransportError::SendFailed(e.to_string()))?,
        )
        .build(self.local_pubkey);
        let event = build_signal_event(
            &self.keys,
            receiver,
            rumor,
            Timestamp::from((now_ms() + SIGNAL_TTL_MS) / 1000),
        )
        .await
        .map_err(|e| TransportError::SendFailed(e.to_string()))?;
        self.client
            .send_event_to(relays.to_vec(), &event)
            .await
            .map_err(|e| TransportError::SendFailed(e.to_string()))?;
        debug!(
            receiver = %receiver,
            relays = relays.len(),
            event = %event.id,
            kind = ?signal.kind,
            session = %signal.session_id,
            "WebRTC signal published"
        );
        Ok(())
    }
}

pub(super) struct NostrWebRtcSignaling {
    sender: NostrSignalSender,
    relays: Vec<String>,
    signal_tx: mpsc::UnboundedSender<IncomingSignal>,
    notify_task: Option<JoinHandle<()>>,
    connect_task: Option<JoinHandle<()>>,
}

impl NostrWebRtcSignaling {
    pub(super) fn new(
        keys: nostr::Keys,
        relays: Vec<String>,
        signal_tx: mpsc::UnboundedSender<IncomingSignal>,
    ) -> Self {
        let client = Client::builder()
            .signer(keys.clone())
            .opts(ClientOptions::new().autoconnect(false))
            .build();
        let local_pubkey = keys.public_key();
        Self {
            sender: NostrSignalSender {
                client,
                keys,
                local_pubkey,
            },
            relays,
            signal_tx,
            notify_task: None,
            connect_task: None,
        }
    }

    pub(super) fn sender(&self) -> NostrSignalSender {
        self.sender.clone()
    }

    pub(super) async fn start(&mut self, local_pubkey: PublicKey) -> Result<(), TransportError> {
        let mut unique_relays = HashSet::new();
        for relay in &self.relays {
            if unique_relays.insert(relay.clone()) {
                self.sender
                    .client
                    .add_relay(relay)
                    .await
                    .map_err(|e| TransportError::StartFailed(e.to_string()))?;
            }
        }
        let notifications = self.sender.client.notifications();
        let keys = self.sender.keys.clone();
        let signal_tx = self.signal_tx.clone();
        self.notify_task = Some(spawn_notify_loop(keys, notifications, signal_tx));

        for relay in &self.relays {
            if let Err(error) = self.sender.client.connect_relay(relay.clone()).await {
                warn!(relay = %relay, error = %error, "failed to connect WebRTC signal relay");
            }
        }
        self.sender
            .client
            .subscribe_to(
                self.relays.clone(),
                Filter::new()
                    .kind(Kind::Custom(SIGNAL_KIND))
                    .pubkey(local_pubkey)
                    .limit(100),
                None,
            )
            .await
            .map_err(|e| TransportError::StartFailed(e.to_string()))?;
        let client = self.sender.client.clone();
        self.connect_task = Some(tokio::spawn(async move {
            client.connect().await;
        }));
        Ok(())
    }

    pub(super) async fn stop(&mut self) {
        if let Some(task) = self.notify_task.take() {
            task.abort();
        }
        if let Some(task) = self.connect_task.take() {
            task.abort();
        }
    }
}

fn spawn_notify_loop(
    keys: nostr::Keys,
    mut notifications: broadcast::Receiver<RelayPoolNotification>,
    signal_tx: mpsc::UnboundedSender<IncomingSignal>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            let notification = match notifications.recv().await {
                Ok(notification) => notification,
                Err(broadcast::error::RecvError::Lagged(skipped)) => {
                    warn!(skipped, "WebRTC Nostr signal notifications lagged");
                    continue;
                }
                Err(broadcast::error::RecvError::Closed) => break,
            };
            let RelayPoolNotification::Event { event, .. } = notification else {
                continue;
            };
            if event.kind != Kind::Custom(SIGNAL_KIND) {
                continue;
            }
            let unwrapped = match unwrap_signal_event(&keys, &event).await {
                Ok(unwrapped) => unwrapped,
                Err(err) => {
                    debug!(error = %err, event = %event.id, "failed to unwrap WebRTC signal");
                    continue;
                }
            };
            let signal = match serde_json::from_str::<WebRtcSignal>(&unwrapped.rumor.content) {
                Ok(signal) if signal.protocol == WEBRTC_PROTOCOL => signal,
                Ok(_) => continue,
                Err(err) => {
                    debug!(error = %err, event = %event.id, "failed to parse WebRTC signal");
                    continue;
                }
            };
            let _ = signal_tx.send(IncomingSignal {
                signal,
                sender: unwrapped.sender,
            });
        }
    })
}
