//! Private local operator requests and bounded control framing.
use super::*;

impl RelayService {
    async fn handle(&self, request: AdminRequest) -> Result<Value, String> {
        match request {
            AdminRequest::Status => {
                let peers = self.endpoint.peers().await.map_err(|e| e.to_string())?;
                let probe = self
                    .probe_receiver
                    .lock()
                    .unwrap()
                    .as_ref()
                    .map(ProbeReceiver::report);
                let funding_budget = self.controller.funding_budget().await?;
                // Sample progress before cost counters: an exchange completing
                // during status must not certify an earlier counter boundary.
                #[cfg(feature = "measurements")]
                let payment_progress = self.controller.payment_progress().await?;
                let status = json!({"npub": self.endpoint.npub(), "peers": peers.iter().map(|p| json!({
                    "npub": p.npub, "connected": p.connected, "transport": p.transport_type,
                    "address": p.transport_addr, "link_id": p.link_id,
                    "sent_bytes": p.bytes_sent, "received_bytes": p.bytes_recv,
                    "sent_packets": p.packets_sent, "received_packets": p.packets_recv,
                    "srtt_ms": p.srtt_ms })).collect::<Vec<_>>(),
                    "purchases": self.controller.purchases().await?,
                    "watched_routes": self.controller.watched_routes().await?,
                    "history": self.controller.purchase_history().await?,
                    "locked_sat": funding_budget.locked_sat,
                    "funding_budget": funding_budget,
                    "remaining_budget_sat": self.buyer.remaining_budget_sat(),
                    "bootstrap": self.forwarding.relay.bootstrap_stats(),
                    "return_allowance": self.forwarding.relay.return_stats(),
                    "free_routes": self.free.stats(),
                    "measurements": crate::measurements::snapshot(),
                    "received": self.received.lock().unwrap().clone(),
                    "probe": probe,
                    "control_traffic": self.control_statistics.iter().map(|(port, stats)| json!({
                        "service_port": port, "counters": stats.snapshot()
                    })).collect::<Vec<_>>(),
                    "last_error": self.controller.last_error()});
                #[cfg(feature = "measurements")]
                let status = {
                    let mut status = status;
                    status["payment_progress"] = serde_json::to_value(payment_progress)
                        .map_err(|error| error.to_string())?;
                    status
                };
                Ok(status)
            }
            AdminRequest::Buy { destination } => {
                let peer = PeerIdentity::from_npub(&destination)
                    .map_err(|_| "invalid destination npub")?;
                Ok(json!(self.controller.open_route(peer).await?))
            }
            AdminRequest::Watch {
                destination,
                max_rate_msat_per_kib,
            } => {
                let peer = PeerIdentity::from_npub(&destination)
                    .map_err(|_| "invalid destination npub")?;
                Ok(json!(
                    self.controller
                        .watch_route(peer, max_rate_msat_per_kib)
                        .await?
                ))
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
            AdminRequest::ReceiveProbe { probe } => {
                let _permit = self
                    .probe_sender
                    .try_acquire()
                    .map_err(|_| "a probe sender is already running")?;
                let receiver = ProbeReceiver::new(probe)?;
                let report = receiver.report();
                *self.probe_receiver.lock().unwrap() = Some(receiver);
                Ok(json!({"probe": report}))
            }
            AdminRequest::SendProbe { probe } => {
                let _permit = self
                    .probe_sender
                    .try_acquire()
                    .map_err(|_| "a probe sender is already running")?;
                Ok(
                    json!({"probe": probe::send(&self.endpoint, probe, &self.probe_receiver).await?}),
                )
            }
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
    ReceiveProbe {
        probe: ReceiveProbe,
    },
    SendProbe {
        probe: SendProbe,
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

/// Access the existing native node operator API inside the private account.
/// This is never the public customer gateway or a payment authorization API.
pub async fn native_request(config: &ServiceConfig, request: &Value) -> Result<Value, String> {
    let mut bytes = serde_json::to_vec(request).map_err(|e| e.to_string())?;
    if bytes.len() > MAX_REQUEST {
        return Err("native control request too large".into());
    }
    bytes.push(b'\n');
    tokio::time::timeout(Duration::from_secs(30), async {
        let mut socket = UnixStream::connect(config.state_directory.join("native.sock"))
            .await
            .map_err(|e| e.to_string())?;
        socket.write_all(&bytes).await.map_err(|e| e.to_string())?;
        let mut reply = Vec::new();
        BufReader::new(socket.take(1024 * 1024 + 1))
            .read_until(b'\n', &mut reply)
            .await
            .map_err(|e| e.to_string())?;
        if reply.len() > 1024 * 1024 || !reply.ends_with(b"\n") {
            return Err("invalid native control response size or framing".into());
        }
        serde_json::from_slice(&reply).map_err(|_| "invalid native control response".into())
    })
    .await
    .map_err(|_| "native control request timed out".to_string())?
}
