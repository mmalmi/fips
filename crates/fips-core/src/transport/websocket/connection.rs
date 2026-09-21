//! Framing and discovery for a registered WebSocket connection.
use super::*;

pub(super) async fn run<S>(
    runtime: &Runtime,
    addr: &TransportAddr,
    websocket: WebSocketStream<S>,
    mut rx: mpsc::Receiver<Vec<u8>>,
    request_key_hint: bool,
) -> Result<(), TransportError>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let (mut sink, mut stream) = websocket.split();
    let mut pending_nonce = request_key_hint.then(|| rand::rng().random::<u64>());
    if let Some(nonce) = pending_nonce {
        sink.send(Message::Binary(
            LocalKeyHint::Request { nonce }.encode().into(),
        ))
        .await
        .map_err(|error| TransportError::SendFailed(error.to_string()))?;
    }

    let started = tokio::time::Instant::now();
    let mut last_received = started;
    let ping_secs = runtime.config.ping_interval_secs();
    let idle_secs = runtime.config.idle_timeout_secs();
    let mut ping = tokio::time::interval(if ping_secs == 0 {
        Duration::from_secs(24 * 60 * 60)
    } else {
        Duration::from_secs(ping_secs)
    });
    ping.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut check = tokio::time::interval(Duration::from_secs(1));
    check.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    enum Event {
        Outbound(Option<Vec<u8>>),
        Inbound(Option<Result<Message, tokio_tungstenite::tungstenite::Error>>),
        Ping,
        Check,
    }

    loop {
        let event = tokio::select! {
            outbound = rx.recv() => Event::Outbound(outbound),
            inbound = stream.next() => Event::Inbound(inbound),
            _ = ping.tick(), if ping_secs > 0 => Event::Ping,
            _ = check.tick() => Event::Check,
        };
        match event {
            Event::Outbound(Some(data)) => {
                let len = data.len();
                if let Err(error) = sink.send(Message::Binary(data.into())).await {
                    break Err(TransportError::SendFailed(error.to_string()));
                }
                runtime.stats.frames_sent.fetch_add(1, Ordering::Relaxed);
                runtime
                    .stats
                    .bytes_sent
                    .fetch_add(len as u64, Ordering::Relaxed);
            }
            Event::Outbound(None) => break Ok(()),
            Event::Inbound(Some(Ok(Message::Binary(data)))) => {
                last_received = tokio::time::Instant::now();
                if let Some(hint) = LocalKeyHint::decode(&data) {
                    match hint {
                        LocalKeyHint::Request { nonce } => {
                            let reply = LocalKeyHint::Response {
                                nonce,
                                pubkey: runtime.local_pubkey,
                            };
                            if let Err(error) =
                                sink.send(Message::Binary(reply.encode().into())).await
                            {
                                break Err(TransportError::SendFailed(error.to_string()));
                            }
                        }
                        LocalKeyHint::Response { nonce, pubkey }
                            if pending_nonce == Some(nonce) =>
                        {
                            pending_nonce = None;
                            if pubkey != runtime.local_pubkey
                                && let Ok(pubkey) = XOnlyPublicKey::from_slice(&pubkey)
                            {
                                runtime
                                    .discoveries
                                    .lock()
                                    .unwrap_or_else(|error| error.into_inner())
                                    .push_back(DiscoveredPeer::with_hint(
                                        runtime.transport_id,
                                        addr.clone(),
                                        pubkey,
                                    ));
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
                last_received = tokio::time::Instant::now();
                if let Err(error) = sink.send(Message::Pong(payload)).await {
                    break Err(TransportError::SendFailed(error.to_string()));
                }
            }
            Event::Inbound(Some(Ok(Message::Pong(_)))) => {
                last_received = tokio::time::Instant::now();
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
                if let Err(error) = sink.send(Message::Ping(Bytes::new())).await {
                    break Err(TransportError::SendFailed(error.to_string()));
                }
            }
            Event::Check => {
                if pending_nonce.is_some()
                    && started.elapsed()
                        >= Duration::from_millis(runtime.config.key_hint_timeout_ms())
                {
                    break Err(TransportError::Timeout);
                }
                if idle_secs > 0 && last_received.elapsed() >= Duration::from_secs(idle_secs) {
                    break Err(TransportError::Timeout);
                }
            }
        }
    }
}
