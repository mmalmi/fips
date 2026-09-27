//! Bounded loopback carrier interruption, shared by WS and TLS process checks.
use std::{
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite},
    net::{TcpListener, TcpStream},
    sync::{mpsc, oneshot, watch},
    task::{JoinHandle, JoinSet},
};
use tokio_rustls::TlsAcceptor;

pub struct StreamProxy {
    pub address: SocketAddr,
    connections: Arc<AtomicUsize>,
    interrupt: mpsc::Sender<oneshot::Sender<usize>>,
    task: JoinHandle<()>,
    blackhole: watch::Sender<u64>,
    loss: Arc<Loss>,
}

#[derive(Default)]
struct Loss {
    activated: AtomicUsize,
    bytes: AtomicUsize,
}

impl StreamProxy {
    pub async fn start(backend: SocketAddr, acceptor: Option<TlsAcceptor>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let connections = Arc::new(AtomicUsize::new(0));
        let (interrupt, mut requests) = mpsc::channel::<oneshot::Sender<usize>>(1);
        let accepted = connections.clone();
        let (blackhole, _) = watch::channel(0);
        let faults = blackhole.clone();
        let loss = Arc::new(Loss::default());
        let dropped = loss.clone();
        let task = tokio::spawn(async move {
            let mut sessions = JoinSet::new();
            loop {
                tokio::select! {
                    Some(reply) = requests.recv() => {
                        let count = sessions.len();
                        sessions.abort_all();
                        while let Some(result) = sessions.join_next().await {
                            if let Err(error) = result {
                                assert!(error.is_cancelled(), "proxy session panicked: {error}");
                            }
                        }
                        // Acknowledge after both halves of every stream have closed.
                        reply.send(count).unwrap();
                    }
                    stream = listener.accept(), if sessions.len() < 16 => {
                        let (stream, _) = stream.unwrap();
                        let acceptor = acceptor.clone();
                        let accepted = accepted.clone();
                        let mut fault = faults.subscribe();
                        fault.borrow_and_update();
                        let loss = dropped.clone();
                        sessions.spawn(async move {
                            if let Some(acceptor) = acceptor {
                                if let Ok(Ok(stream)) = tokio::time::timeout(
                                    Duration::from_secs(5), acceptor.accept(stream),
                                ).await {
                                    forward(stream, backend, accepted, fault, loss).await;
                                }
                            } else {
                                forward(stream, backend, accepted, fault, loss).await;
                            }
                        });
                    }
                    Some(result) = sessions.join_next(), if !sessions.is_empty() => {
                        result.unwrap();
                    }
                }
            }
        });
        Self {
            address,
            connections,
            interrupt,
            task,
            blackhole,
            loss,
        }
    }

    pub fn connections(&self) -> usize {
        self.connections.load(Ordering::SeqCst)
    }

    pub fn dropped_bytes(&self) -> usize {
        self.loss.bytes.load(Ordering::SeqCst)
    }

    /// Lose traffic on existing streams while retaining both TCP sockets.
    /// New connections subscribe after the fault and forward normally.
    pub async fn blackhole(&self) {
        let before = self.loss.activated.load(Ordering::SeqCst);
        self.blackhole.send_modify(|generation| *generation += 1);
        tokio::time::timeout(Duration::from_secs(2), async {
            while self.loss.activated.load(Ordering::SeqCst) == before {
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        })
        .await
        .expect("a live proxy stream must enter silent loss");
    }

    pub async fn interrupt(&self) -> usize {
        let (reply, received) = oneshot::channel();
        self.interrupt.send(reply).await.unwrap();
        received.await.unwrap()
    }
}

impl Drop for StreamProxy {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn forward<S: AsyncRead + AsyncWrite + Unpin>(
    mut stream: S,
    backend: SocketAddr,
    accepted: Arc<AtomicUsize>,
    mut fault: watch::Receiver<u64>,
    loss: Arc<Loss>,
) {
    let Ok(mut upstream) = TcpStream::connect(backend).await else {
        return;
    };
    accepted.fetch_add(1, Ordering::SeqCst);
    tokio::select! {
        _ = tokio::io::copy_bidirectional(&mut stream, &mut upstream) => {}
        changed = fault.changed() => {
            assert!(changed.is_ok());
            loss.activated.fetch_add(1, Ordering::SeqCst);
            // Drain without forwarding, flushing, replying or locally closing.
            // The daemons must detect loss and retire their own connections.
            let _ = tokio::try_join!(discard(&mut stream, &loss), discard(&mut upstream, &loss));
        }
    }
}

async fn discard<R: AsyncRead + Unpin>(reader: &mut R, loss: &Loss) -> std::io::Result<()> {
    let mut buffer = [0; 8192];
    loop {
        let read = reader.read(&mut buffer).await?;
        if read == 0 {
            return Ok(());
        }
        loss.bytes.fetch_add(read, Ordering::SeqCst);
    }
}
