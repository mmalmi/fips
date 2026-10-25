//! Framing and discovery for a registered WebSocket connection.
use super::*;
use tokio::time::Instant;

pub(super) async fn run<S>(
    runtime: &Runtime,
    addr: &TransportAddr,
    websocket: WebSocketStream<S>,
    rx: mpsc::Receiver<Vec<u8>>,
    request_key_hint: bool,
    generation: u64,
) -> Result<(), TransportError>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let (sink, stream) = websocket.split();
    let nonce = request_key_hint.then(|| rand::rng().random::<u64>());
    let deadlines = Deadlines::new(&runtime.config, request_key_hint);
    // Control replies must not wait for space in the bulk queue. Flooding this
    // small reserve closes the connection rather than blocking its reader.
    let (replies, reply_rx) = mpsc::channel(8);
    tokio::select! {
        result = read(runtime, addr, stream, replies, nonce, generation, &deadlines) => {
            crate::marked_carrier_diagnostic::terminal(runtime.transport_id, addr,
                if result.is_err() { "read_error" } else { "read_end" });
            result
        },
        result = write(runtime, addr, sink, rx, reply_rx, nonce) => {
            crate::marked_carrier_diagnostic::terminal(runtime.transport_id, addr,
                if result.is_err() { "write_error" } else { "write_end" });
            result
        },
        reason = deadlines.expired() => {
            crate::marked_carrier_diagnostic::terminal(runtime.transport_id, addr, reason);
            Err(TransportError::Timeout)
        },
    }
}

async fn write<S>(
    runtime: &Runtime,
    addr: &TransportAddr,
    mut sink: S,
    mut rx: mpsc::Receiver<Vec<u8>>,
    mut replies: mpsc::Receiver<Message>,
    nonce: Option<u64>,
) -> Result<(), TransportError>
where
    S: futures::Sink<Message, Error = tokio_tungstenite::tungstenite::Error> + Unpin,
{
    if let Some(nonce) = nonce {
        sink.send(Message::Binary(
            LocalKeyHint::Request { nonce }.encode().into(),
        ))
        .await
        .map_err(|error| TransportError::SendFailed(error.to_string()))?;
    }
    let ping_secs = runtime.config.ping_interval_secs();
    let mut ping = tokio::time::interval(if ping_secs == 0 {
        Duration::from_secs(24 * 60 * 60)
    } else {
        Duration::from_secs(ping_secs)
    });
    ping.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        let (message, data_len) = tokio::select! {
            reply = replies.recv() => {
                let Some(reply) = reply else {
                    crate::marked_carrier_diagnostic::terminal(runtime.transport_id, addr, "reply_queue_closed");
                    return Ok(());
                };
                (reply, None)
            }
            outbound = rx.recv() => {
                let Some(data) = outbound else {
                    crate::marked_carrier_diagnostic::terminal(runtime.transport_id, addr, "output_queue_closed");
                    return Ok(());
                };
                let len = data.len();
                (Message::Binary(data.into()), Some(len))
            }
            _ = ping.tick(), if ping_secs > 0 => (Message::Ping(Bytes::new()), None),
        };
        let marked_write = if let Message::Binary(data) = &message {
            crate::marked_carrier_diagnostic::msg2_write(runtime.transport_id, addr, data)
        } else {
            None
        };
        let sent = sink.send(message).await;
        if let Some(marked_write) = marked_write {
            marked_write.finish(if sent.is_ok() { "sent" } else { "error" });
        }
        sent.map_err(|error| TransportError::SendFailed(error.to_string()))?;
        if let Some(len) = data_len {
            runtime.stats.frames_sent.fetch_add(1, Ordering::Relaxed);
            runtime
                .stats
                .bytes_sent
                .fetch_add(len as u64, Ordering::Relaxed);
        }
    }
}

async fn read<S>(
    runtime: &Runtime,
    addr: &TransportAddr,
    mut stream: S,
    replies: mpsc::Sender<Message>,
    mut pending_nonce: Option<u64>,
    generation: u64,
    deadlines: &Deadlines,
) -> Result<(), TransportError>
where
    S: futures::Stream<Item = Result<Message, tokio_tungstenite::tungstenite::Error>> + Unpin,
{
    let mut ready_frames = 0;
    loop {
        let reply = match stream.next().await {
            Some(Ok(Message::Binary(data))) => {
                deadlines.received();
                if let Some(hint) = LocalKeyHint::decode(&data) {
                    match hint {
                        LocalKeyHint::Request { nonce } => Some(Message::Binary(
                            LocalKeyHint::Response {
                                nonce,
                                pubkey: runtime.local_pubkey,
                            }
                            .encode()
                            .into(),
                        )),
                        LocalKeyHint::Response { nonce, pubkey }
                            if pending_nonce == Some(nonce) =>
                        {
                            pending_nonce = None;
                            deadlines.complete_hint();
                            if pubkey != runtime.local_pubkey
                                && let Ok(pubkey) = XOnlyPublicKey::from_slice(&pubkey)
                                && let Some(connection) = runtime
                                    .connections()
                                    .get_mut(addr)
                                    .filter(|connection| connection.generation == generation)
                            {
                                connection.pending_hint = Some(pubkey);
                            }
                            None
                        }
                        LocalKeyHint::Response { .. } => None,
                    }
                } else {
                    if data.len() > runtime.config.max_frame_bytes()
                        || validate_websocket_record(&data).is_err()
                    {
                        runtime.stats.invalid_frames.fetch_add(1, Ordering::Relaxed);
                        crate::marked_carrier_diagnostic::terminal(
                            runtime.transport_id,
                            addr,
                            "invalid_record",
                        );
                        return Err(TransportError::RecvFailed(
                            "invalid WebSocket FIPS physical record".into(),
                        ));
                    }
                    let mut msg1_read = crate::msg1_ingress_diagnostic::websocket_read(&data);
                    let marked_read = crate::marked_carrier_diagnostic::msg1_read(
                        runtime.transport_id,
                        addr,
                        &data,
                    );
                    let len = data.len();
                    let packet = ReceivedPacket::with_timestamp(
                        runtime.transport_id,
                        addr.clone(),
                        PacketBuffer::new(data.to_vec()),
                        now_ms(),
                    );
                    if let Some(msg1_read) = msg1_read.as_mut() {
                        msg1_read.begin_admission();
                    }
                    let admitted = runtime
                        .packet_tx
                        .send_stream_packet(packet, marked_read.as_ref())
                        .await;
                    if let Some(marked_read) = marked_read {
                        marked_read.finish(if admitted.is_ok() {
                            "admitted"
                        } else {
                            "channel_closed"
                        });
                    }
                    admitted.map_err(|_| {
                        crate::marked_carrier_diagnostic::terminal(
                            runtime.transport_id,
                            addr,
                            "node_channel_closed",
                        );
                        TransportError::RecvFailed("node packet channel closed".into())
                    })?;
                    if let Some(msg1_read) = msg1_read {
                        msg1_read.admitted();
                    }
                    runtime
                        .stats
                        .frames_received
                        .fetch_add(1, Ordering::Relaxed);
                    runtime
                        .stats
                        .bytes_received
                        .fetch_add(len as u64, Ordering::Relaxed);
                    None
                }
            }
            Some(Ok(Message::Ping(payload))) => {
                deadlines.received();
                Some(Message::Pong(payload))
            }
            Some(Ok(Message::Pong(_))) => {
                deadlines.received();
                None
            }
            Some(Ok(Message::Close(_))) => {
                crate::marked_carrier_diagnostic::terminal(
                    runtime.transport_id,
                    addr,
                    "peer_close",
                );
                return Ok(());
            }
            None => {
                crate::marked_carrier_diagnostic::terminal(runtime.transport_id, addr, "peer_eof");
                return Ok(());
            }
            Some(Ok(Message::Text(_) | Message::Frame(_))) => {
                runtime.stats.invalid_frames.fetch_add(1, Ordering::Relaxed);
                crate::marked_carrier_diagnostic::terminal(
                    runtime.transport_id,
                    addr,
                    "non_binary",
                );
                return Err(TransportError::RecvFailed(
                    "WebSocket transport accepts binary messages only".into(),
                ));
            }
            Some(Err(error)) => {
                use tokio_tungstenite::tungstenite::{Error, error::ProtocolError};
                let reason = match &error {
                    Error::Protocol(ProtocolError::ResetWithoutClosingHandshake) => "peer_reset",
                    Error::Protocol(_) => "read_protocol",
                    Error::Io(_) => "read_io",
                    _ => "read_error",
                };
                crate::marked_carrier_diagnostic::terminal(runtime.transport_id, addr, reason);
                return Err(TransportError::RecvFailed(error.to_string()));
            }
        };
        if let Some(reply) = reply {
            replies.try_send(reply).map_err(|error| {
                crate::marked_carrier_diagnostic::terminal(
                    runtime.transport_id,
                    addr,
                    if matches!(error, mpsc::error::TrySendError::Full(_)) {
                        "reply_queue_full"
                    } else {
                        "reply_queue_closed"
                    },
                );
                TransportError::SendFailed("WebSocket control reply queue unavailable".into())
            })?;
        }
        // One socket read can leave hundreds of complete frames buffered.
        // Bulk admission and control admission with available space don't
        // yield. Give the node and other connections a turn even then.
        ready_frames += 1;
        if ready_frames == 32 {
            ready_frames = 0;
            tokio::task::yield_now().await;
        }
    }
}

#[cfg(test)]
mod diagnostic_tests;

// Read progress can extend an idle deadline while a write is pending. Deadlines
// only move later or disappear, so the timer rechecks after its earlier wakeup.
// Expiry or local cancellation drops both halves, including any partial write.
struct Deadlines {
    idle_after: Option<Duration>,
    activity: StdMutex<Activity>,
}

struct Activity {
    hint: Option<Instant>,
    received: Instant,
}

impl Deadlines {
    fn new(config: &WebSocketConfig, request_key_hint: bool) -> Self {
        let now = Instant::now();
        Self {
            idle_after: (config.idle_timeout_secs() > 0)
                .then(|| Duration::from_secs(config.idle_timeout_secs())),
            activity: StdMutex::new(Activity {
                hint: request_key_hint
                    .then(|| now.checked_add(Duration::from_millis(config.key_hint_timeout_ms())))
                    .flatten(),
                received: now,
            }),
        }
    }

    fn activity(&self) -> MutexGuard<'_, Activity> {
        self.activity
            .lock()
            .unwrap_or_else(|error| error.into_inner())
    }

    fn received(&self) {
        self.activity().received = Instant::now();
    }

    fn complete_hint(&self) {
        self.activity().hint = None;
    }

    async fn expired(&self) -> &'static str {
        loop {
            let deadline = {
                let activity = self.activity();
                activity
                    .hint
                    .into_iter()
                    .map(|deadline| (deadline, "hint_timeout"))
                    .chain(
                        self.idle_after
                            .and_then(|idle| activity.received.checked_add(idle))
                            .map(|deadline| (deadline, "idle_timeout")),
                    )
                    .min_by_key(|(deadline, _)| *deadline)
            };
            match deadline {
                Some((deadline, reason)) if deadline <= Instant::now() => return reason,
                Some((deadline, _)) => tokio::time::sleep_until(deadline).await,
                None => std::future::pending().await,
            }
        }
    }
}
