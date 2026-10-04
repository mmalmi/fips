//! Fixed loopback mint sockets carried as ordinary TCP/FIPS data. This adapter
//! grants no forwarding permission and never retries an HTTP request.
use crate::route_quotes::RouteQuotes;
use fips_core::{FipsEndpoint, Identity, PeerIdentity};
use fips_tcp::{Config, ConnectionId, StackError, State};
use fips_tcp_endpoint::{AdapterError, FipsTcpEndpoint};
use std::{
    collections::{HashMap, VecDeque},
    io,
    net::SocketAddr,
    sync::Arc,
    time::Duration,
};
use tokio::{
    io::AsyncWriteExt,
    net::{TcpListener, TcpStream},
    task::{JoinHandle, JoinSet},
    time::{Instant, MissedTickBehavior},
};

const CONNECTIONS: usize = 8;
const BUFFER: usize = 16 * 1024;
const LIFETIME: Duration = Duration::from_secs(45);

pub(super) fn validate_port(port: u16) -> Result<(), String> {
    if port == 0 || (44_740..=44_744).contains(&port) {
        return Err("mint requires a distinct nonzero FIPS service port".into());
    }
    Ok(())
}

pub struct MeshMintBridge {
    task: JoinHandle<Result<(), String>>,
}

impl MeshMintBridge {
    /// Export only the mint's fixed loopback HTTP listener, never its funding
    /// control socket or a destination supplied by the remote client.
    pub async fn serve(
        endpoint: Arc<FipsEndpoint>,
        port: u16,
        backend: SocketAddr,
    ) -> Result<Self, String> {
        loopback(backend)?;
        Self::start(endpoint, port, Mode::Server(backend)).await
    }

    /// The caller owns the immutable mint URL and authenticated server identity.
    /// Refuse non-loopback listeners; this is not a LAN or Internet proxy.
    pub async fn connect(
        endpoint: Arc<FipsEndpoint>,
        port: u16,
        mint: PeerIdentity,
        listener: TcpListener,
    ) -> Result<Self, String> {
        loopback(listener.local_addr().map_err(|e| e.to_string())?)?;
        Self::start(
            endpoint,
            port,
            Mode::Client {
                mint,
                listener,
                quotes: None,
            },
        )
        .await
    }

    pub(crate) async fn connect_quoted(
        endpoint: Arc<FipsEndpoint>,
        port: u16,
        mint: PeerIdentity,
        listener: TcpListener,
        quotes: Arc<RouteQuotes>,
    ) -> Result<Self, String> {
        loopback(listener.local_addr().map_err(|e| e.to_string())?)?;
        Self::start(
            endpoint,
            port,
            Mode::Client {
                mint,
                listener,
                quotes: Some(quotes),
            },
        )
        .await
    }

    async fn start(endpoint: Arc<FipsEndpoint>, port: u16, mode: Mode) -> Result<Self, String> {
        validate_port(port)?;
        let seed = u64::from_le_bytes(
            Identity::generate().node_addr().as_bytes()[..8]
                .try_into()
                .unwrap(),
        );
        let config = Config {
            receive_buffer: BUFFER,
            send_buffer: BUFFER,
            max_connections: CONNECTIONS,
            max_connections_per_peer: 4,
            fin_wait_2_ms: 1_000,
            time_wait_ms: 1_000,
            ..Config::default()
        };
        let tcp = FipsTcpEndpoint::bind(endpoint, port, config, seed)
            .await
            .map_err(|e| e.to_string())?;
        Ok(Self {
            task: tokio::spawn(drive(tcp, mode)),
        })
    }

    pub async fn shutdown(mut self) -> Result<(), String> {
        self.task.abort();
        match (&mut self.task).await {
            Ok(result) => result,
            Err(error) if error.is_cancelled() => Ok(()),
            Err(error) => Err(error.to_string()),
        }
    }
}

impl Drop for MeshMintBridge {
    fn drop(&mut self) {
        self.task.abort();
    }
}

fn loopback(address: SocketAddr) -> Result<(), String> {
    if !address.ip().is_loopback() || address.port() == 0 {
        return Err("mesh mint adapter requires a fixed loopback socket".into());
    }
    Ok(())
}

enum Mode {
    Client {
        mint: PeerIdentity,
        listener: TcpListener,
        quotes: Option<Arc<RouteQuotes>>,
    },
    Server(SocketAddr),
}

struct Connection {
    socket: TcpStream,
    started: Instant,
    to_mesh: Vec<u8>,
    to_socket: Vec<u8>,
    read_closed: bool,
    write_closed: bool,
    fin_sent: bool,
}

impl Connection {
    fn new(socket: TcpStream, started: Instant) -> Self {
        Self {
            socket,
            started,
            to_mesh: Vec::new(),
            to_socket: Vec::new(),
            read_closed: false,
            write_closed: false,
            fin_sent: false,
        }
    }

    async fn step(
        &mut self,
        tcp: &mut FipsTcpEndpoint,
        id: ConnectionId,
        now: u64,
    ) -> Result<bool, String> {
        if self.started.elapsed() >= LIFETIME || tcp.state(id).is_none() {
            return Ok(false);
        }
        if !matches!(
            tcp.state(id),
            Some(
                State::Established
                    | State::CloseWait
                    | State::FinWait1
                    | State::FinWait2
                    | State::Closing
                    | State::TimeWait
            )
        ) {
            return Ok(true);
        }
        if self.to_mesh.is_empty() && !self.read_closed {
            let mut buffer = [0; BUFFER];
            match self.socket.try_read(&mut buffer) {
                Ok(0) => self.read_closed = true,
                Ok(count) => self.to_mesh.extend_from_slice(&buffer[..count]),
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
                Err(e) => return Err(e.to_string()),
            }
        }
        if !self.to_mesh.is_empty() {
            let count = tcp
                .write(id, &self.to_mesh, now)
                .await
                .map_err(|e| e.to_string())?;
            self.to_mesh.drain(..count);
        }
        if self.to_socket.is_empty() && !self.write_closed {
            self.to_socket = tcp.read(id, BUFFER, now).await.map_err(|e| e.to_string())?;
            if self.to_socket.is_empty() && tcp.is_read_closed(id) {
                self.socket.shutdown().await.map_err(|e| e.to_string())?;
                self.write_closed = true;
            }
        }
        if !self.to_socket.is_empty() {
            match self.socket.try_write(&self.to_socket) {
                Ok(0) => return Err("mint socket closed during write".into()),
                Ok(count) => {
                    self.to_socket.drain(..count);
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
                Err(e) => return Err(e.to_string()),
            }
        }
        // Propagate EOF once without discarding the opposite direction. TCP
        // keeps accepted bytes ahead of FIN, including after a partial write.
        if self.read_closed && !self.fin_sent && self.to_mesh.is_empty() {
            tcp.close(id, now).await.map_err(|e| e.to_string())?;
            self.fin_sent = true;
        }
        Ok(true)
    }
}

async fn drive(mut tcp: FipsTcpEndpoint, mode: Mode) -> Result<(), String> {
    let mut connections = HashMap::<ConnectionId, Connection>::new();
    let mut waiting = VecDeque::new();
    let mut pending = JoinSet::new();
    let mut preparing = JoinSet::new();
    let started = Instant::now();
    let mut tick = tokio::time::interval(Duration::from_millis(10));
    tick.set_missed_tick_behavior(MissedTickBehavior::Skip);
    loop {
        let now = started.elapsed().as_millis() as u64;
        tokio::select! {
            result = tcp.receive_report_filtered(now, |peer| match &mode {
                Mode::Client { mint, .. } => peer.pubkey() == mint.pubkey(),
                Mode::Server(_) => true,
            }) => { result.map_err(|e| e.to_string())?; },
            _ = tick.tick() => {
                tcp.poll(started.elapsed().as_millis() as u64).await.map_err(|e| e.to_string())?;
            }
            socket = async {
                match &mode {
                    Mode::Client { listener, .. } => listener.accept().await,
                    Mode::Server(_) => std::future::pending().await,
                }
            }, if connections.len() + pending.len() + waiting.len() + preparing.len() < CONNECTIONS => {
                let (socket, _) = socket.map_err(|e| e.to_string())?;
                let accepted = Instant::now();
                if let Mode::Client { mint, quotes: Some(quotes), .. } = &mode {
                    let (mint, quotes) = (*mint, quotes.clone());
                    preparing.spawn(async move {
                        let ready = quotes.require_free_route(mint).await;
                        (socket, accepted, ready)
                    });
                } else {
                    waiting.push_back((socket, accepted, accepted));
                }
            }
            Some(result) = preparing.join_next(), if !preparing.is_empty() => {
                let (socket, accepted, ready) = result.map_err(|e| e.to_string())?;
                match ready {
                    Ok(()) => waiting.push_back((socket, accepted, Instant::now())),
                    Err(error) => tracing::debug!(%error, "mesh mint bootstrap route unavailable"),
                }
            }
            Some(result) = pending.join_next(), if !pending.is_empty() => {
                let (id, socket) = result.map_err(|e| e.to_string())?;
                if let Ok(Ok(socket)) = socket {
                    connections.insert(id, Connection::new(socket, Instant::now()));
                } else { let _ = tcp.abort(id).await; }
            }
        }
        let now = started.elapsed().as_millis() as u64;
        // A wallet can open several short HTTP connections while earlier TCP
        // entries finish closing. Wait before reading any request bytes; never
        // recreate a connection that already accepted application data.
        if let Mode::Client { mint, .. } = &mode {
            while let Some((socket, accepted, queued)) = waiting.pop_front() {
                if queued.elapsed() >= Duration::from_secs(3) || accepted.elapsed() >= LIFETIME {
                    continue;
                }
                match tcp.connect(*mint, now).await {
                    Ok(id) => {
                        connections.insert(id, Connection::new(socket, accepted));
                    }
                    Err(AdapterError::Tcp(
                        StackError::ConnectionLimit | StackError::NoEphemeralPort,
                    )) => {
                        waiting.push_front((socket, accepted, queued));
                        break;
                    }
                    Err(error) => {
                        tracing::debug!(%error, "mesh mint connection failed");
                    }
                }
            }
        }
        while let Some(id) = tcp.accept() {
            if let Mode::Server(backend) = mode
                && connections.len() + pending.len() < CONNECTIONS
            {
                pending.spawn(async move {
                    (
                        id,
                        tokio::time::timeout(Duration::from_secs(3), TcpStream::connect(backend))
                            .await,
                    )
                });
            } else {
                let _ = tcp.abort(id).await;
            }
        }
        let mut closed = Vec::new();
        for (&id, connection) in &mut connections {
            match connection.step(&mut tcp, id, now).await {
                Ok(true) => {}
                Ok(false) => closed.push(id),
                Err(error) => {
                    tracing::debug!(%error, "mesh mint stream failed");
                    closed.push(id);
                }
            }
        }
        for id in closed {
            connections.remove(&id);
            let _ = tcp.abort(id).await;
        }
    }
}
