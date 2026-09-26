//! Framing and discovery for a registered WebSocket connection.
use super::*;
use tokio::time::Instant;

pub(super) async fn run<S>(
    runtime: &Runtime,
    addr: &TransportAddr,
    websocket: WebSocketStream<S>,
    mut rx: mpsc::Receiver<Vec<u8>>,
    request_key_hint: bool,
    generation: u64,
) -> Result<(), TransportError>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let (mut sink, mut stream) = websocket.split();
    let mut pending_nonce = request_key_hint.then(|| rand::rng().random::<u64>());
    let mut deadlines = Deadlines::new(&runtime.config, request_key_hint);
    if let Some(nonce) = pending_nonce {
        deadlines
            .send(
                &mut sink,
                Message::Binary(LocalKeyHint::Request { nonce }.encode().into()),
            )
            .await?;
    }

    let ping_secs = runtime.config.ping_interval_secs();
    let mut ping = tokio::time::interval(if ping_secs == 0 {
        Duration::from_secs(24 * 60 * 60)
    } else {
        Duration::from_secs(ping_secs)
    });
    ping.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    enum Event {
        Outbound(Option<Vec<u8>>),
        Inbound(Option<Result<Message, tokio_tungstenite::tungstenite::Error>>),
        Ping,
        Expired,
    }

    loop {
        let event = tokio::select! {
            outbound = rx.recv() => Event::Outbound(outbound),
            inbound = stream.next() => Event::Inbound(inbound),
            _ = ping.tick(), if ping_secs > 0 => Event::Ping,
            _ = deadlines.expired() => Event::Expired,
        };
        match event {
            Event::Outbound(Some(data)) => {
                let len = data.len();
                deadlines
                    .send(&mut sink, Message::Binary(data.into()))
                    .await?;
                runtime.stats.frames_sent.fetch_add(1, Ordering::Relaxed);
                runtime
                    .stats
                    .bytes_sent
                    .fetch_add(len as u64, Ordering::Relaxed);
            }
            Event::Outbound(None) => break Ok(()),
            Event::Inbound(Some(Ok(Message::Binary(data)))) => {
                deadlines.received = Instant::now();
                if let Some(hint) = LocalKeyHint::decode(&data) {
                    match hint {
                        LocalKeyHint::Request { nonce } => {
                            let reply = LocalKeyHint::Response {
                                nonce,
                                pubkey: runtime.local_pubkey,
                            };
                            deadlines
                                .send(&mut sink, Message::Binary(reply.encode().into()))
                                .await?;
                        }
                        LocalKeyHint::Response { nonce, pubkey }
                            if pending_nonce == Some(nonce) =>
                        {
                            pending_nonce = None;
                            deadlines.hint = None;
                            if pubkey != runtime.local_pubkey
                                && let Ok(pubkey) = XOnlyPublicKey::from_slice(&pubkey)
                                && let Some(connection) = runtime
                                    .connections()
                                    .get_mut(addr)
                                    .filter(|connection| connection.generation == generation)
                            {
                                connection.pending_hint = Some(pubkey);
                            }
                        }
                        LocalKeyHint::Response { .. } => {}
                    }
                    continue;
                }
                if data.len() > runtime.config.max_frame_bytes()
                    || validate_websocket_record(&data).is_err()
                {
                    runtime.stats.invalid_frames.fetch_add(1, Ordering::Relaxed);
                    break Err(TransportError::RecvFailed(
                        "invalid WebSocket FIPS physical record".into(),
                    ));
                }
                let len = data.len();
                let packet = ReceivedPacket::with_timestamp(
                    runtime.transport_id,
                    addr.clone(),
                    PacketBuffer::new(data.to_vec()),
                    now_ms(),
                );
                if runtime.packet_tx.send(packet).is_err() {
                    break Err(TransportError::RecvFailed(
                        "node packet channel closed".into(),
                    ));
                }
                runtime
                    .stats
                    .frames_received
                    .fetch_add(1, Ordering::Relaxed);
                runtime
                    .stats
                    .bytes_received
                    .fetch_add(len as u64, Ordering::Relaxed);
            }
            Event::Inbound(Some(Ok(Message::Ping(payload)))) => {
                deadlines.received = Instant::now();
                deadlines.send(&mut sink, Message::Pong(payload)).await?;
            }
            Event::Inbound(Some(Ok(Message::Pong(_)))) => {
                deadlines.received = Instant::now();
            }
            Event::Inbound(Some(Ok(Message::Close(_))) | None) => break Ok(()),
            Event::Inbound(Some(Ok(Message::Text(_) | Message::Frame(_)))) => {
                runtime.stats.invalid_frames.fetch_add(1, Ordering::Relaxed);
                break Err(TransportError::RecvFailed(
                    "WebSocket transport accepts binary messages only".into(),
                ));
            }
            Event::Inbound(Some(Err(error))) => {
                break Err(TransportError::RecvFailed(error.to_string()));
            }
            Event::Ping => {
                deadlines
                    .send(&mut sink, Message::Ping(Bytes::new()))
                    .await?;
            }
            Event::Expired => break Err(TransportError::Timeout),
        }
    }
}

// The same deadlines cover waiting for input and writing any frame, including
// the initial hint. A partial timed-out write closes the whole stream; it is
// never resumed on a replacement connection.
struct Deadlines {
    hint: Option<Instant>,
    idle_after: Option<Duration>,
    received: Instant,
}

impl Deadlines {
    fn new(config: &WebSocketConfig, request_key_hint: bool) -> Self {
        let now = Instant::now();
        Self {
            hint: request_key_hint
                .then(|| now.checked_add(Duration::from_millis(config.key_hint_timeout_ms())))
                .flatten(),
            idle_after: (config.idle_timeout_secs() > 0)
                .then(|| Duration::from_secs(config.idle_timeout_secs())),
            received: now,
        }
    }

    async fn expired(&self) {
        let deadline = self
            .hint
            .into_iter()
            .chain(
                self.idle_after
                    .and_then(|idle| self.received.checked_add(idle)),
            )
            .min();
        match deadline {
            Some(deadline) => tokio::time::sleep_until(deadline).await,
            None => std::future::pending().await,
        }
    }

    async fn send<S>(&self, sink: &mut S, message: Message) -> Result<(), TransportError>
    where
        S: futures::Sink<Message, Error = tokio_tungstenite::tungstenite::Error> + Unpin,
    {
        tokio::select! {
            biased;
            _ = self.expired() => Err(TransportError::Timeout),
            result = sink.send(message) => result.map_err(|error| TransportError::SendFailed(error.to_string())),
        }
    }
}
