//! Bounded command/event bridge for platform-owned BLE APIs.

use super::{
    addr::BleAddr,
    bootstrap::BleBootstrap,
    io::{BleAcceptor, BleCandidate, BleIo, BleScanner, BleStream},
};
use crate::transport::TransportError;
use std::collections::{HashMap, VecDeque};
use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
};
use tokio::sync::{Mutex, mpsc, oneshot};

const REQUEST_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);
const MAX_HOST_CHUNK: usize = u16::MAX as usize + 6;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HostBleCommand {
    Listen {
        request_id: u64,
        preferred_psm: u16,
    },
    StopListening,
    StartAdvertising {
        request_id: u64,
        bootstrap: Vec<u8>,
    },
    StopAdvertising {
        request_id: u64,
    },
    StartScanning {
        request_id: u64,
    },
    StopScanning,
    Connect {
        request_id: u64,
        peer_token: String,
        psm: u16,
    },
    Write {
        request_id: u64,
        connection_id: u64,
        bytes: Vec<u8>,
    },
    Close {
        connection_id: u64,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HostBleEvent {
    Listening {
        request_id: u64,
        psm: u16,
    },
    AdvertisingStarted {
        request_id: u64,
    },
    AdvertisingStopped {
        request_id: u64,
    },
    ScanningStarted {
        request_id: u64,
    },
    PeerDiscovered {
        peer_token: String,
        bootstrap: Vec<u8>,
    },
    Connected {
        request_id: u64,
        connection_id: u64,
        peer_token: String,
        send_segment_mtu: u16,
        receive_segment_mtu: u16,
    },
    IncomingConnection {
        connection_id: u64,
        peer_token: String,
        send_segment_mtu: u16,
        receive_segment_mtu: u16,
    },
    BytesReceived {
        connection_id: u64,
        bytes: Vec<u8>,
    },
    WriteCompleted {
        request_id: u64,
    },
    Disconnected {
        connection_id: u64,
        reason: Option<String>,
    },
    Failed {
        request_id: u64,
        message: String,
    },
}

/// Platform-facing half of the BLE bridge.
pub struct HostBleAdapter {
    command_rx: Mutex<mpsc::Receiver<HostBleCommand>>,
    event_tx: mpsc::Sender<HostBleEvent>,
}

impl HostBleAdapter {
    pub async fn next_command(&self) -> Option<HostBleCommand> {
        self.command_rx.lock().await.recv().await
    }

    pub async fn emit(&self, event: HostBleEvent) -> Result<(), TransportError> {
        self.event_tx
            .send(event)
            .await
            .map_err(|_| TransportError::RecvFailed("host BLE event channel closed".into()))
    }

    pub fn try_emit(&self, event: HostBleEvent) -> Result<(), TransportError> {
        self.event_tx.try_send(event).map_err(|error| {
            TransportError::RecvFailed(format!("host BLE event rejected: {error}"))
        })
    }
}

/// Rust-facing BLE I/O implementation driven by a platform adapter.
pub struct HostBleIo {
    adapter_name: String,
    local_addr: BleAddr,
    shared: Arc<HostShared>,
    accept_rx: std::sync::Mutex<Option<mpsc::Receiver<HostBleStream>>>,
    scan_rx: std::sync::Mutex<Option<mpsc::Receiver<BleCandidate>>>,
}

struct HostShared {
    adapter_name: String,
    command_tx: mpsc::Sender<HostBleCommand>,
    pending: Mutex<HashMap<u64, oneshot::Sender<Result<HostResponse, String>>>>,
    connections: Mutex<HashMap<u64, mpsc::Sender<HostStreamSignal>>>,
    accept_tx: mpsc::Sender<HostBleStream>,
    scan_tx: mpsc::Sender<BleCandidate>,
    next_request_id: AtomicU64,
    stream_queue_capacity: usize,
}

enum HostResponse {
    Listening(u16),
    Connected(HostBleStream),
    Complete,
}

enum HostStreamSignal {
    Bytes(Vec<u8>),
    Disconnected(Option<String>),
}

impl HostBleIo {
    pub fn channel(
        adapter_name: impl Into<String>,
        local_peer_token: impl Into<String>,
        queue_capacity: usize,
    ) -> Result<(Self, HostBleAdapter), TransportError> {
        let adapter_name = adapter_name.into();
        let local_addr = BleAddr::from_opaque(&adapter_name, local_peer_token.into())?;
        let capacity = queue_capacity.max(1);
        let (command_tx, command_rx) = mpsc::channel(capacity);
        let (event_tx, event_rx) = mpsc::channel(capacity);
        let (accept_tx, accept_rx) = mpsc::channel(capacity);
        let (scan_tx, scan_rx) = mpsc::channel(capacity);
        let shared = Arc::new(HostShared {
            adapter_name: adapter_name.clone(),
            command_tx,
            pending: Mutex::new(HashMap::new()),
            connections: Mutex::new(HashMap::new()),
            accept_tx,
            scan_tx,
            next_request_id: AtomicU64::new(1),
            stream_queue_capacity: capacity,
        });
        tokio::spawn(dispatch_events(Arc::clone(&shared), event_rx));

        Ok((
            Self {
                adapter_name,
                local_addr,
                shared,
                accept_rx: std::sync::Mutex::new(Some(accept_rx)),
                scan_rx: std::sync::Mutex::new(Some(scan_rx)),
            },
            HostBleAdapter {
                command_rx: Mutex::new(command_rx),
                event_tx,
            },
        ))
    }
}

impl HostShared {
    async fn request(
        &self,
        build: impl FnOnce(u64) -> HostBleCommand,
    ) -> Result<HostResponse, TransportError> {
        let request_id = self.next_request_id.fetch_add(1, Ordering::Relaxed);
        let (response_tx, response_rx) = oneshot::channel();
        self.pending.lock().await.insert(request_id, response_tx);
        if self.command_tx.send(build(request_id)).await.is_err() {
            self.pending.lock().await.remove(&request_id);
            return Err(TransportError::SendFailed(
                "host BLE command channel closed".into(),
            ));
        }

        match tokio::time::timeout(REQUEST_TIMEOUT, response_rx).await {
            Ok(Ok(Ok(response))) => Ok(response),
            Ok(Ok(Err(message))) => Err(TransportError::LinkFailed(message)),
            Ok(Err(_)) => Err(TransportError::RecvFailed(
                "host BLE response channel closed".into(),
            )),
            Err(_) => {
                self.pending.lock().await.remove(&request_id);
                Err(TransportError::Timeout)
            }
        }
    }

    async fn complete(&self, request_id: u64, result: Result<HostResponse, String>) {
        if let Some(sender) = self.pending.lock().await.remove(&request_id) {
            let _ = sender.send(result);
        }
    }

    async fn register_stream(
        self: &Arc<Self>,
        connection_id: u64,
        peer_token: String,
        send_segment_mtu: u16,
        receive_segment_mtu: u16,
    ) -> Result<HostBleStream, String> {
        if send_segment_mtu == 0 || receive_segment_mtu == 0 {
            return Err("host BLE connection reported a zero segment MTU".into());
        }
        let addr = BleAddr::from_opaque(&self.adapter_name, peer_token)
            .map_err(|error| error.to_string())?;
        let (signal_tx, signal_rx) = mpsc::channel(self.stream_queue_capacity);
        if self
            .connections
            .lock()
            .await
            .insert(connection_id, signal_tx)
            .is_some()
        {
            return Err(format!("duplicate host BLE connection id {connection_id}"));
        }
        Ok(HostBleStream {
            connection_id,
            addr,
            send_segment_mtu,
            receive_segment_mtu,
            shared: Arc::clone(self),
            receive: Mutex::new(HostReceiveState {
                signal_rx,
                pending: VecDeque::new(),
            }),
        })
    }

    fn close_without_waiting(&self, connection_id: u64) {
        let _ = self
            .command_tx
            .try_send(HostBleCommand::Close { connection_id });
    }
}

async fn dispatch_events(shared: Arc<HostShared>, mut event_rx: mpsc::Receiver<HostBleEvent>) {
    while let Some(event) = event_rx.recv().await {
        match event {
            HostBleEvent::Listening { request_id, psm } => {
                if psm == 0 {
                    shared
                        .complete(request_id, Err("platform assigned zero BLE PSM".into()))
                        .await;
                } else {
                    shared
                        .complete(request_id, Ok(HostResponse::Listening(psm)))
                        .await;
                }
            }
            HostBleEvent::AdvertisingStarted { request_id }
            | HostBleEvent::AdvertisingStopped { request_id }
            | HostBleEvent::ScanningStarted { request_id }
            | HostBleEvent::WriteCompleted { request_id } => {
                shared
                    .complete(request_id, Ok(HostResponse::Complete))
                    .await;
            }
            HostBleEvent::PeerDiscovered {
                peer_token,
                bootstrap,
            } => {
                let Ok(addr) = BleAddr::from_opaque(&shared.adapter_name, peer_token) else {
                    continue;
                };
                let Ok(bootstrap) = BleBootstrap::decode(&bootstrap) else {
                    continue;
                };
                let _ = shared.scan_tx.try_send(BleCandidate { addr, bootstrap });
            }
            HostBleEvent::Connected {
                request_id,
                connection_id,
                peer_token,
                send_segment_mtu,
                receive_segment_mtu,
            } => {
                let Some(sender) = shared.pending.lock().await.remove(&request_id) else {
                    shared.close_without_waiting(connection_id);
                    continue;
                };
                if sender.is_closed() {
                    shared.close_without_waiting(connection_id);
                    continue;
                }
                let result = shared
                    .register_stream(
                        connection_id,
                        peer_token,
                        send_segment_mtu,
                        receive_segment_mtu,
                    )
                    .await
                    .map(HostResponse::Connected);
                let _ = sender.send(result);
            }
            HostBleEvent::IncomingConnection {
                connection_id,
                peer_token,
                send_segment_mtu,
                receive_segment_mtu,
            } => {
                match shared
                    .register_stream(
                        connection_id,
                        peer_token,
                        send_segment_mtu,
                        receive_segment_mtu,
                    )
                    .await
                {
                    Ok(stream) => {
                        if shared.accept_tx.try_send(stream).is_err() {
                            shared.close_without_waiting(connection_id);
                        }
                    }
                    Err(_) => shared.close_without_waiting(connection_id),
                }
            }
            HostBleEvent::BytesReceived {
                connection_id,
                bytes,
            } => {
                if bytes.is_empty() || bytes.len() > MAX_HOST_CHUNK {
                    shared.close_without_waiting(connection_id);
                    continue;
                }
                let sender = shared.connections.lock().await.get(&connection_id).cloned();
                if sender
                    .is_none_or(|sender| sender.try_send(HostStreamSignal::Bytes(bytes)).is_err())
                {
                    shared.close_without_waiting(connection_id);
                }
            }
            HostBleEvent::Disconnected {
                connection_id,
                reason,
            } => {
                if let Some(sender) = shared.connections.lock().await.remove(&connection_id) {
                    let _ = sender.try_send(HostStreamSignal::Disconnected(reason));
                }
            }
            HostBleEvent::Failed {
                request_id,
                message,
            } => shared.complete(request_id, Err(message)).await,
        }
    }

    for (_, sender) in shared.pending.lock().await.drain() {
        let _ = sender.send(Err("host BLE adapter stopped".into()));
    }
    for (_, sender) in shared.connections.lock().await.drain() {
        let _ = sender.try_send(HostStreamSignal::Disconnected(Some(
            "host BLE adapter stopped".into(),
        )));
    }
}

pub struct HostBleAcceptor {
    psm: u16,
    rx: mpsc::Receiver<HostBleStream>,
    command_tx: mpsc::Sender<HostBleCommand>,
}

impl BleAcceptor for HostBleAcceptor {
    type Stream = HostBleStream;

    async fn accept(&mut self) -> Result<Self::Stream, TransportError> {
        self.rx
            .recv()
            .await
            .ok_or_else(|| TransportError::RecvFailed("host BLE acceptor closed".into()))
    }

    fn psm(&self) -> u16 {
        self.psm
    }
}

impl Drop for HostBleAcceptor {
    fn drop(&mut self) {
        let _ = self.command_tx.try_send(HostBleCommand::StopListening);
    }
}

pub struct HostBleScanner {
    rx: mpsc::Receiver<BleCandidate>,
    command_tx: mpsc::Sender<HostBleCommand>,
}

impl BleScanner for HostBleScanner {
    async fn next(&mut self) -> Option<BleCandidate> {
        self.rx.recv().await
    }
}

impl Drop for HostBleScanner {
    fn drop(&mut self) {
        let _ = self.command_tx.try_send(HostBleCommand::StopScanning);
    }
}

pub struct HostBleStream {
    connection_id: u64,
    addr: BleAddr,
    send_segment_mtu: u16,
    receive_segment_mtu: u16,
    shared: Arc<HostShared>,
    receive: Mutex<HostReceiveState>,
}

struct HostReceiveState {
    signal_rx: mpsc::Receiver<HostStreamSignal>,
    pending: VecDeque<u8>,
}

impl BleStream for HostBleStream {
    async fn send(&self, data: &[u8]) -> Result<(), TransportError> {
        if data.is_empty() || data.len() > usize::from(self.send_segment_mtu) {
            return Err(TransportError::MtuExceeded {
                packet_size: data.len(),
                mtu: self.send_segment_mtu,
            });
        }
        match self
            .shared
            .request(|request_id| HostBleCommand::Write {
                request_id,
                connection_id: self.connection_id,
                bytes: data.to_vec(),
            })
            .await?
        {
            HostResponse::Complete => Ok(()),
            _ => Err(TransportError::SendFailed(
                "unexpected host BLE write response".into(),
            )),
        }
    }

    async fn recv(&self, output: &mut [u8]) -> Result<usize, TransportError> {
        let mut state = self.receive.lock().await;
        if !state.pending.is_empty() {
            return Ok(drain_pending(&mut state.pending, output));
        }
        match state.signal_rx.recv().await {
            Some(HostStreamSignal::Bytes(bytes)) => {
                state.pending.extend(bytes);
                Ok(drain_pending(&mut state.pending, output))
            }
            Some(HostStreamSignal::Disconnected(None)) | None => Ok(0),
            Some(HostStreamSignal::Disconnected(Some(reason))) => {
                Err(TransportError::RecvFailed(reason))
            }
        }
    }

    fn send_mtu(&self) -> u16 {
        self.send_segment_mtu
    }

    fn recv_mtu(&self) -> u16 {
        self.receive_segment_mtu
    }

    fn remote_addr(&self) -> &BleAddr {
        &self.addr
    }
}

impl Drop for HostBleStream {
    fn drop(&mut self) {
        self.shared.close_without_waiting(self.connection_id);
    }
}

fn drain_pending(pending: &mut VecDeque<u8>, output: &mut [u8]) -> usize {
    let count = pending.len().min(output.len());
    for slot in &mut output[..count] {
        *slot = pending.pop_front().expect("pending length was checked");
    }
    count
}

impl BleIo for HostBleIo {
    type Stream = HostBleStream;
    type Acceptor = HostBleAcceptor;
    type Scanner = HostBleScanner;

    async fn listen(&self, preferred_psm: u16) -> Result<Self::Acceptor, TransportError> {
        let psm = match self
            .shared
            .request(|request_id| HostBleCommand::Listen {
                request_id,
                preferred_psm,
            })
            .await?
        {
            HostResponse::Listening(psm) => psm,
            _ => {
                return Err(TransportError::StartFailed(
                    "unexpected host BLE listener response".into(),
                ));
            }
        };
        let rx = self
            .accept_rx
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .take()
            .ok_or_else(|| {
                TransportError::NotSupported("host BLE acceptor already taken".into())
            })?;
        Ok(HostBleAcceptor {
            psm,
            rx,
            command_tx: self.shared.command_tx.clone(),
        })
    }

    async fn connect(&self, addr: &BleAddr, psm: u16) -> Result<Self::Stream, TransportError> {
        match self
            .shared
            .request(|request_id| HostBleCommand::Connect {
                request_id,
                peer_token: addr.peer_token(),
                psm,
            })
            .await?
        {
            HostResponse::Connected(stream) => Ok(stream),
            _ => Err(TransportError::ConnectionRefused),
        }
    }

    async fn start_advertising(&self, bootstrap: BleBootstrap) -> Result<(), TransportError> {
        match self
            .shared
            .request(|request_id| HostBleCommand::StartAdvertising {
                request_id,
                bootstrap: bootstrap.encode().to_vec(),
            })
            .await?
        {
            HostResponse::Complete => Ok(()),
            _ => Err(TransportError::StartFailed(
                "unexpected host BLE advertiser response".into(),
            )),
        }
    }

    async fn stop_advertising(&self) -> Result<(), TransportError> {
        match self
            .shared
            .request(|request_id| HostBleCommand::StopAdvertising { request_id })
            .await?
        {
            HostResponse::Complete => Ok(()),
            _ => Err(TransportError::ShutdownFailed(
                "unexpected host BLE advertiser stop response".into(),
            )),
        }
    }

    async fn start_scanning(&self) -> Result<Self::Scanner, TransportError> {
        match self
            .shared
            .request(|request_id| HostBleCommand::StartScanning { request_id })
            .await?
        {
            HostResponse::Complete => {}
            _ => {
                return Err(TransportError::StartFailed(
                    "unexpected host BLE scanner response".into(),
                ));
            }
        }
        let rx = self
            .scan_rx
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .take()
            .ok_or_else(|| TransportError::NotSupported("host BLE scanner already taken".into()))?;
        Ok(HostBleScanner {
            rx,
            command_tx: self.shared.command_tx.clone(),
        })
    }

    fn local_addr(&self) -> Result<BleAddr, TransportError> {
        Ok(self.local_addr.clone())
    }

    fn adapter_name(&self) -> &str {
        &self.adapter_name
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn platform_assigned_psm_and_bootstrap_flow_to_scanner() {
        let (io, adapter) = HostBleIo::channel("ios", "local-device", 8).unwrap();
        let platform = tokio::spawn(async move {
            let HostBleCommand::Listen {
                request_id,
                preferred_psm,
            } = adapter.next_command().await.unwrap()
            else {
                panic!("expected listener command");
            };
            assert_eq!(preferred_psm, 0x0085);
            adapter
                .emit(HostBleEvent::Listening {
                    request_id,
                    psm: 0x0091,
                })
                .await
                .unwrap();

            let HostBleCommand::StartAdvertising {
                request_id,
                bootstrap,
            } = adapter.next_command().await.unwrap()
            else {
                panic!("expected advertising command");
            };
            assert_eq!(BleBootstrap::decode(&bootstrap).unwrap().psm, 0x0091);
            adapter
                .emit(HostBleEvent::AdvertisingStarted { request_id })
                .await
                .unwrap();

            let HostBleCommand::StartScanning { request_id } =
                adapter.next_command().await.unwrap()
            else {
                panic!("expected scanning command");
            };
            adapter
                .emit(HostBleEvent::ScanningStarted { request_id })
                .await
                .unwrap();
            adapter
                .emit(HostBleEvent::PeerDiscovered {
                    peer_token: "remote-device".into(),
                    bootstrap: BleBootstrap::new(0x0092, 1024).unwrap().encode().to_vec(),
                })
                .await
                .unwrap();
        });

        let acceptor = io.listen(0x0085).await.unwrap();
        assert_eq!(acceptor.psm(), 0x0091);
        io.start_advertising(BleBootstrap::new(0x0091, 2048).unwrap())
            .await
            .unwrap();
        let mut scanner = io.start_scanning().await.unwrap();
        let candidate = scanner.next().await.unwrap();
        assert_eq!(candidate.addr.to_string_repr(), "ios/remote-device");
        assert_eq!(candidate.bootstrap.psm, 0x0092);
        assert_eq!(candidate.bootstrap.max_packet, 1024);
        platform.await.unwrap();
    }

    #[tokio::test]
    async fn connection_write_completion_and_received_bytes_roundtrip() {
        let (io, adapter) = HostBleIo::channel("android", "local-device", 8).unwrap();
        let platform = tokio::spawn(async move {
            let HostBleCommand::Connect {
                request_id,
                peer_token,
                psm,
            } = adapter.next_command().await.unwrap()
            else {
                panic!("expected connect command");
            };
            assert_eq!(peer_token, "remote-device");
            assert_eq!(psm, 0x0092);
            adapter
                .emit(HostBleEvent::Connected {
                    request_id,
                    connection_id: 7,
                    peer_token,
                    send_segment_mtu: 64,
                    receive_segment_mtu: 64,
                })
                .await
                .unwrap();

            let HostBleCommand::Write {
                request_id,
                connection_id,
                bytes,
            } = adapter.next_command().await.unwrap()
            else {
                panic!("expected write command");
            };
            assert_eq!(connection_id, 7);
            assert_eq!(bytes, b"ping");
            adapter
                .emit(HostBleEvent::WriteCompleted { request_id })
                .await
                .unwrap();
            adapter
                .emit(HostBleEvent::BytesReceived {
                    connection_id,
                    bytes: b"pong".to_vec(),
                })
                .await
                .unwrap();
        });

        let addr = BleAddr::from_opaque("android", "remote-device").unwrap();
        let stream = io.connect(&addr, 0x0092).await.unwrap();
        stream.send(b"ping").await.unwrap();
        let mut output = [0u8; 16];
        let received = stream.recv(&mut output).await.unwrap();
        assert_eq!(&output[..received], b"pong");
        platform.await.unwrap();
    }

    #[tokio::test]
    async fn late_connection_after_cancel_is_closed_without_becoming_a_stream() {
        let (io, adapter) = HostBleIo::channel("android", "local-device", 8).unwrap();
        let addr = BleAddr::from_opaque("android", "remote-device").unwrap();
        let connect = tokio::spawn(async move { io.connect(&addr, 0x0092).await });
        let HostBleCommand::Connect {
            request_id,
            peer_token,
            ..
        } = adapter.next_command().await.unwrap()
        else {
            panic!("expected connect command");
        };

        connect.abort();
        let _ = connect.await;
        adapter
            .emit(HostBleEvent::Connected {
                request_id,
                connection_id: 12,
                peer_token,
                send_segment_mtu: 64,
                receive_segment_mtu: 64,
            })
            .await
            .unwrap();

        assert_eq!(
            tokio::time::timeout(std::time::Duration::from_secs(1), adapter.next_command())
                .await
                .unwrap(),
            Some(HostBleCommand::Close { connection_id: 12 })
        );
    }
}
